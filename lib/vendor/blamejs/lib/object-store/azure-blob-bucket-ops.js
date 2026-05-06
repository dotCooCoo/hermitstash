"use strict";
/**
 * azure-blob-bucket-ops — container-level operations for Azure Blob.
 *
 * Per-blob ops (put / get / list / delete) live in
 * `lib/object-store/azure-blob.js` and are bound to a single container
 * at create() time. Container lifecycle ops are at a different level —
 * a service-scoped client that addresses arbitrary containers — so
 * they get their own factory.
 *
 *   create(name, opts?)        async; PUT  /{container}?restype=container
 *   delete(name)               async; DELETE /{container}?restype=container
 *   list(opts?)                async; GET  /?comp=list
 *                              -> [{ name, lastModified, etag,
 *                                    leaseStatus, leaseState, publicAccess }]
 *   setCorsRules(rules)        async; PUT  /?restype=service&comp=properties
 *                              account-level CORS — Azure has no
 *                              per-container CORS.
 *
 * Shared Key auth via `lib/object-store/azure-blob.js`'s `signRequest`
 * helper. Not implemented here:
 *
 *   setLifecycle(name, rules) — Azure Storage lifecycle management
 *     policies live on Azure Resource Manager
 *     (`management.azure.com`), not the Blob service endpoint. ARM
 *     requires an Azure AD bearer token (Service Principal flow), a
 *     different auth scheme entirely. Operators wiring lifecycle do
 *     so via Terraform / Bicep / az CLI; the framework documents the
 *     gap rather than half-implementing one auth path.
 */
var azureBlob = require("./azure-blob");
var C = require("../constants");
var httpClient = require("../http-client");
var requestHelpers = require("../request-helpers");
var safeUrl = require("../safe-url");
var { ObjectStoreError } = require("../framework-error");

var _err = ObjectStoreError.factory;

// HTTP status constants used in the bucket-ops expectStatus arrays.
// OK / NOT_FOUND / CONFLICT come from the framework's HTTP_STATUS table;
// CREATED (201) and ACCEPTED (202) are not in the table, so they're
// named locally with their RFC 7231 values.
var HTTP_OK         = requestHelpers.HTTP_STATUS.OK;
var HTTP_NOT_FOUND  = requestHelpers.HTTP_STATUS.NOT_FOUND;
var HTTP_CONFLICT   = requestHelpers.HTTP_STATUS.CONFLICT;
var HTTP_CREATED    = 201;   // RFC 7231 §6.3.2
var HTTP_ACCEPTED   = 202;   // RFC 7231 §6.3.3

// Internal URL builder — endpoint + path string from validated config.
// Routes through safeUrl.parse so the protocol allowlist + length cap
// apply uniformly.
function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

// Maximum length for a tag passed into the framework-internal XML
// extractor. The XML payloads come back from Azure (server-controlled)
// but the tag name is framework-supplied; cap it explicitly so the
// open/close substrings used for indexOf walks can't be driven against
// an oversize pattern.
var MAX_XML_TAG_LENGTH = 128;

// Azure container names: 3-63 chars, lowercase alphanumeric + hyphens,
// no consecutive hyphens, must start and end with letter or digit.
var CONTAINER_NAME_RE = /^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$/;

function _validateContainerName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw _err("BUCKET_INVALID_NAME",
      "azure-blob bucketOps: container name must be a non-empty string", true);
  }
  if (name.length < 3 || name.length > 63) {
    throw _err("BUCKET_INVALID_NAME",
      "azure-blob bucketOps: container name must be 3-63 chars (got " +
      name.length + ")", true);
  }
  // Length is bounded above (3..63) before the regex runs so the
  // pattern can't be driven against an unbounded input.
  if (name.length > 63 || !CONTAINER_NAME_RE.test(name)) {
    throw _err("BUCKET_INVALID_NAME",
      "azure-blob bucketOps: container name '" + name + "' is invalid; " +
      "lowercase letters / digits / hyphens only, no consecutive hyphens, " +
      "must start and end with letter or digit", true);
  }
}

function _validateCorsRule(rule, idx) {
  function bad(msg) {
    throw _err("INVALID_CORS_RULE",
      "azure-blob bucketOps: setCorsRules: rule[" + idx + "]: " + msg, true);
  }
  if (!rule || typeof rule !== "object") bad("must be an object");
  if (!Array.isArray(rule.allowedOrigins) || rule.allowedOrigins.length === 0) {
    bad("allowedOrigins must be a non-empty array");
  }
  if (!Array.isArray(rule.allowedMethods) || rule.allowedMethods.length === 0) {
    bad("allowedMethods must be a non-empty array");
  }
  for (var i = 0; i < rule.allowedMethods.length; i++) {
    var m = rule.allowedMethods[i];
    if (["GET", "PUT", "POST", "DELETE", "HEAD", "MERGE", "OPTIONS"].indexOf(m) === -1) {
      bad("allowedMethods[" + i + "] = " + JSON.stringify(m) +
          " (must be one of GET/PUT/POST/DELETE/HEAD/MERGE/OPTIONS)");
    }
  }
  if (rule.allowedHeaders !== undefined && !Array.isArray(rule.allowedHeaders)) {
    bad("allowedHeaders, if present, must be an array");
  }
  if (rule.exposedHeaders !== undefined && !Array.isArray(rule.exposedHeaders)) {
    bad("exposedHeaders, if present, must be an array");
  }
  if (rule.maxAgeInSeconds !== undefined &&
      (typeof rule.maxAgeInSeconds !== "number" || rule.maxAgeInSeconds < 0 ||
       !Number.isFinite(rule.maxAgeInSeconds))) {
    bad("maxAgeInSeconds, if present, must be a non-negative finite number");
  }
}

function _xmlEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function _buildCorsXml(rules) {
  var inner = rules.map(function (rule) {
    var parts = [
      "<CorsRule>",
      "<AllowedOrigins>" + _xmlEscape(rule.allowedOrigins.join(",")) + "</AllowedOrigins>",
      "<AllowedMethods>" + rule.allowedMethods.join(",") + "</AllowedMethods>",
      "<AllowedHeaders>" + _xmlEscape((rule.allowedHeaders || []).join(",")) + "</AllowedHeaders>",
      "<ExposedHeaders>" + _xmlEscape((rule.exposedHeaders || []).join(",")) + "</ExposedHeaders>",
      "<MaxAgeInSeconds>" +
        (rule.maxAgeInSeconds == null ? 0 : Math.floor(rule.maxAgeInSeconds)) +
        "</MaxAgeInSeconds>",
      "</CorsRule>",
    ];
    return parts.join("");
  }).join("");
  return '<?xml version="1.0" encoding="utf-8"?>' +
         "<StorageServiceProperties><Cors>" + inner + "</Cors></StorageServiceProperties>";
}

// Tiny XML extractor — pulls every occurrence of <Tag>value</Tag>
// and returns an array of value strings. Sufficient for the limited
// shapes we read (Containers list, container metadata). The tag is
// framework-supplied (call sites pass hardcoded tag names such as
// "Container", "Name", "Last-Modified") but cap the length explicitly
// so the open/close substrings used for indexOf walks can't be driven
// against an oversize pattern under any future call shape.
function _validateTag(tag) {
  if (typeof tag !== "string" || tag.length === 0 || tag.length > MAX_XML_TAG_LENGTH) {
    throw _err("BUCKET_INVALID_NAME",
      "azure-blob bucketOps: XML tag must be a non-empty string of length " +
      "<= " + MAX_XML_TAG_LENGTH, true);
  }
  if (!/^[A-Za-z][A-Za-z0-9_.-]*$/.test(tag)) {
    throw _err("BUCKET_INVALID_NAME",
      "azure-blob bucketOps: XML tag '" + tag + "' has invalid characters", true);
  }
}

function _extractAll(xml, tag) {
  _validateTag(tag);
  var open = "<" + tag + ">";
  var close = "</" + tag + ">";
  var out = [];
  var i = 0;
  while (true) {
    var s = xml.indexOf(open, i);
    if (s === -1) break;
    var e = xml.indexOf(close, s + open.length);
    if (e === -1) break;
    out.push(xml.slice(s + open.length, e));
    i = e + close.length;
  }
  return out;
}

function _extractBlocks(xml, tag) {
  _validateTag(tag);
  var open = "<" + tag + ">";
  var close = "</" + tag + ">";
  var blocks = [];
  var i = 0;
  while (true) {
    var s = xml.indexOf(open, i);
    if (s === -1) break;
    var e = xml.indexOf(close, s + open.length);
    if (e === -1) break;
    blocks.push(xml.slice(s + open.length, e));
    i = e + close.length;
  }
  return blocks;
}

function create(config) {
  if (!config) throw _err("BAD_OPT", "azure-blob bucketOps: config required", true);
  if (!config.accountName) throw _err("BAD_OPT", "azure-blob bucketOps: accountName required", true);
  if (!config.accountKey)  throw _err("BAD_OPT", "azure-blob bucketOps: accountKey required", true);

  var endpoint = config.endpoint ||
                 ("https://" + config.accountName + ".blob.core.windows.net");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var apiVersion = config.apiVersion || azureBlob.DEFAULT_API_VERSION;
  var timeoutMs = config.timeoutMs;
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal = config.allowInternal != null ? config.allowInternal : null;

  function _sign(method, url, headers) {
    return azureBlob.signRequest({
      method:      method,
      url:         url,
      headers:     headers || {},
      accountName: config.accountName,
      accountKey:  config.accountKey,
      apiVersion:  apiVersion,
    }).headers;
  }

  function _request(method, url, headers, body, expectStatus) {
    var reqOpts = {
      method:           method,
      url:              url,
      headers:          headers,
      body:             body,
      idleTimeoutMs:    timeoutMs,
      allowedProtocols: allowedProtocols,
      errorClass:       ObjectStoreError,
    };
    if (allowInternal !== null) reqOpts.allowInternal = allowInternal;
    // http-client rejects on any 4xx/5xx by default. The bucket-ops API
    // semantically accepts certain non-2xx codes (404 for "missing on
    // delete", 409 for "container already exists"), so we catch those
    // and surface them as the wrapped response object instead.
    return httpClient.request(reqOpts).then(function (res) {
      if (expectStatus && expectStatus.indexOf(res.statusCode) === -1) {
        throw _err("UNEXPECTED_STATUS",
          "azure-blob bucketOps: " + method + " " + url +
          " returned HTTP " + res.statusCode, true);
      }
      return res;
    }, function (e) {
      var sc = e && e.statusCode;
      if (sc && expectStatus && expectStatus.indexOf(sc) !== -1) {
        return { statusCode: sc, headers: {}, body: Buffer.alloc(0) };
      }
      throw e;
    });
  }

  async function createContainer(name, opts) {
    _validateContainerName(name);
    opts = opts || {};
    var url = _internalUrl(endpoint + "/" + name + "?restype=container", allowedProtocols);
    var headers = { "Content-Length": "0" };
    if (opts.publicAccess) {
      if (opts.publicAccess !== "blob" && opts.publicAccess !== "container") {
        throw _err("BAD_OPT",
          "azure-blob bucketOps: createContainer: publicAccess must be " +
          "'blob' or 'container' (got " + JSON.stringify(opts.publicAccess) + ")", true);
      }
      headers["x-ms-blob-public-access"] = opts.publicAccess;
    }
    var signed = _sign("PUT", url, headers);
    var res = await _request("PUT", url, signed, null, [HTTP_CREATED, HTTP_CONFLICT]);
    if (res.statusCode === HTTP_CONFLICT) {
      throw _err("BUCKET_ALREADY_OWNED",
        "azure-blob bucketOps: container '" + name +
        "' already exists or was recently deleted", true);
    }
    return { name: name };
  }

  async function deleteContainer(name) {
    _validateContainerName(name);
    var url = _internalUrl(endpoint + "/" + name + "?restype=container", allowedProtocols);
    var signed = _sign("DELETE", url, {});
    var res = await _request("DELETE", url, signed, null, [HTTP_ACCEPTED, HTTP_NOT_FOUND]);
    return res.statusCode === HTTP_ACCEPTED;
  }

  async function listContainers(opts) {
    opts = opts || {};
    var url = _internalUrl(endpoint + "/?comp=list", allowedProtocols);
    if (opts.prefix)  url.searchParams.set("prefix", opts.prefix);
    if (opts.maxResults != null) url.searchParams.set("maxresults", String(opts.maxResults));
    var signed = _sign("GET", url, {});
    var res = await _request("GET", url, signed, null, [HTTP_OK]);
    var xml = Buffer.isBuffer(res.body) ? res.body.toString("utf8") :
              typeof res.body === "string" ? res.body :
              "";
    var blocks = _extractBlocks(xml, "Container");
    return blocks.map(function (block) {
      return {
        name:          (_extractAll(block, "Name")[0] || "").trim(),
        lastModified:  (_extractAll(block, "Last-Modified")[0] || null),
        etag:          (_extractAll(block, "Etag")[0] || null),
        leaseStatus:   (_extractAll(block, "LeaseStatus")[0] || null),
        leaseState:    (_extractAll(block, "LeaseState")[0] || null),
        publicAccess:  (_extractAll(block, "PublicAccess")[0] || null),
      };
    });
  }

  async function setCorsRules(rules) {
    if (!Array.isArray(rules)) {
      throw _err("INVALID_CORS_RULE",
        "azure-blob bucketOps: setCorsRules: rules must be an array", true);
    }
    rules.forEach(_validateCorsRule);
    var xml = _buildCorsXml(rules);
    var bodyBuf = Buffer.from(xml, "utf8");
    var url = _internalUrl(endpoint + "/?restype=service&comp=properties", allowedProtocols);
    var headers = {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
    };
    var signed = _sign("PUT", url, headers);
    await _request("PUT", url, signed, bodyBuf, [HTTP_ACCEPTED]);
    return { rulesApplied: rules.length };
  }

  return {
    protocol:     "azure-blob",
    create:       createContainer,
    delete:       deleteContainer,
    list:         listContainers,
    setCorsRules: setCorsRules,
    setLifecycle: function () {
      throw _err("NOT_SUPPORTED",
        "azure-blob bucketOps: setLifecycle is not implemented because " +
        "Azure Storage lifecycle management policies live on Azure Resource " +
        "Manager (management.azure.com) and require Azure AD bearer token " +
        "auth, not Shared Key. Configure lifecycle via Terraform / Bicep / " +
        "az CLI.", true);
    },
  };
}

module.exports = { create: create };
