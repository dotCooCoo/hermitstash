"use strict";
/**
 * gcs-bucket-ops — bucket-level operations for Google Cloud Storage.
 *
 * Per-object ops (put / get / list / delete) live in
 * `lib/object-store/gcs.js` and are bound to a single bucket at
 * create() time. Bucket lifecycle ops are at a different level — a
 * project-scoped client that addresses arbitrary buckets — so they
 * get their own factory.
 *
 *   create(name, opts?)         async; POST /storage/v1/b?project={projectId}
 *                               opts: location ('US' / 'EU' / region) +
 *                                     storageClass + iamConfiguration
 *   delete(name)                async; DELETE /storage/v1/b/{name}
 *   list()                      async; GET  /storage/v1/b?project={projectId}
 *                               -> [{ name, location, storageClass,
 *                                     timeCreated, updated }]
 *   setLifecycle(name, rules)   async; PATCH /storage/v1/b/{name}
 *                               -> body { lifecycle: { rule: [...] } }
 *   setCorsRules(name, rules)   async; PATCH /storage/v1/b/{name}
 *                               -> body { cors: [...] }
 *
 * Auth: same service-account JSON / RSA-SHA256-signed JWT exchanged
 * for an OAuth2 access token as `lib/object-store/gcs.js`.
 */
var gcs = require("./gcs");
var authHeader = require("../auth-header");
var httpClient = require("../http-client");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var C = require("../constants");
var atomicFile = require("../atomic-file");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");

var _err = ObjectStoreError.factory;

// HTTP status constants used in the bucket-ops expectStatus arrays.
var HTTP_OK         = requestHelpers.HTTP_STATUS.OK;
var HTTP_NO_CONTENT = requestHelpers.HTTP_STATUS.NO_CONTENT;
var HTTP_NOT_FOUND  = requestHelpers.HTTP_STATUS.NOT_FOUND;
var HTTP_CONFLICT   = requestHelpers.HTTP_STATUS.CONFLICT;

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

// GCS bucket names: 3-63 chars, lowercase letters / digits / hyphens /
// underscores / dots; can't start or end with hyphen; can't contain '..'
// or 'goog' prefix; can't be IP address. Most violations the API will
// reject for us — we sanity-check the basics.
var BUCKET_NAME_RE = /^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$/;

function _validateBucketName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw _err("BUCKET_INVALID_NAME",
      "gcs bucketOps: bucket name must be a non-empty string", true);
  }
  if (name.length < 3 || name.length > 63) {
    throw _err("BUCKET_INVALID_NAME",
      "gcs bucketOps: bucket name must be 3-63 chars (got " + name.length + ")", true);
  }
  // Length is bounded above (3..63) before the regex runs so the
  // pattern can't be driven against an unbounded input.
  if (name.length > 63 || !BUCKET_NAME_RE.test(name)) {
    throw _err("BUCKET_INVALID_NAME",
      "gcs bucketOps: bucket name '" + name + "' is invalid; lowercase " +
      "letters / digits / hyphens / underscores / dots only, must start " +
      "and end with letter or digit", true);
  }
  if (name.indexOf("..") !== -1) {
    throw _err("BUCKET_INVALID_NAME",
      "gcs bucketOps: bucket name '" + name + "' contains '..'", true);
  }
  if (name.indexOf("goog") === 0) {
    throw _err("BUCKET_INVALID_NAME",
      "gcs bucketOps: bucket name '" + name + "' starts with 'goog' " +
      "(reserved by Google)", true);
  }
}

// GCS lifecycle rules: { action: { type: "Delete"|"SetStorageClass", storageClass? },
//                        condition: { age, createdBefore, ...} }
function _validateLifecycleRule(rule, idx) {
  function bad(msg) {
    throw _err("INVALID_LIFECYCLE",
      "gcs bucketOps: setLifecycle: rule[" + idx + "]: " + msg, true);
  }
  if (!rule || typeof rule !== "object") bad("must be an object");
  if (!rule.action || typeof rule.action !== "object") {
    bad("action object is required");
  }
  if (!rule.action.type) bad("action.type is required");
  if (rule.action.type !== "Delete" && rule.action.type !== "SetStorageClass" &&
      rule.action.type !== "AbortIncompleteMultipartUpload") {
    bad("action.type must be 'Delete' / 'SetStorageClass' / " +
        "'AbortIncompleteMultipartUpload' (got " +
        JSON.stringify(rule.action.type) + ")");
  }
  if (rule.action.type === "SetStorageClass" && !rule.action.storageClass) {
    bad("action.storageClass required when action.type='SetStorageClass'");
  }
  if (!rule.condition || typeof rule.condition !== "object") {
    bad("condition object is required");
  }
}

function _validateCorsRule(rule, idx) {
  function bad(msg) {
    throw _err("INVALID_CORS_RULE",
      "gcs bucketOps: setCorsRules: rule[" + idx + "]: " + msg, true);
  }
  if (!rule || typeof rule !== "object") bad("must be an object");
  if (!Array.isArray(rule.origin) || rule.origin.length === 0) {
    bad("origin must be a non-empty array");
  }
  if (rule.method !== undefined && !Array.isArray(rule.method)) {
    bad("method, if present, must be an array");
  }
  if (rule.responseHeader !== undefined && !Array.isArray(rule.responseHeader)) {
    bad("responseHeader, if present, must be an array");
  }
  if (rule.maxAgeSeconds !== undefined &&
      (typeof rule.maxAgeSeconds !== "number" || rule.maxAgeSeconds < 0)) {
    bad("maxAgeSeconds, if present, must be a non-negative number");
  }
}

function create(config) {
  if (!config) throw _err("BAD_OPT", "gcs bucketOps: config required", true);

  var serviceAccount = config.serviceAccount;
  if (!serviceAccount && config.serviceAccountFile) {
    try {
      // Cap + fd-bound read of the GCS service-account JSON (private_key). NO
      // refuseSymlink: commonly a k8s projected-secret mount (symlink).
      serviceAccount = safeJson.parse(atomicFile.fdSafeReadSync(config.serviceAccountFile, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }));
    } catch (e) {
      throw _err("BAD_OPT", "gcs bucketOps: failed to read serviceAccountFile '" +
        config.serviceAccountFile + "': " + ((e && e.message) || String(e)), true);
    }
  }
  if (!serviceAccount || !serviceAccount.client_email || !serviceAccount.private_key) {
    throw _err("BAD_OPT",
      "gcs bucketOps: serviceAccount with { client_email, private_key } required " +
      "(or serviceAccountFile pointing to one)", true);
  }
  var projectId = config.projectId || serviceAccount.project_id;
  if (!projectId) {
    throw _err("BAD_OPT",
      "gcs bucketOps: projectId required (either config.projectId or " +
      "serviceAccount.project_id)", true);
  }

  var endpoint = config.endpoint || gcs.DEFAULT_ENDPOINT;
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var tokenEndpoint = config.tokenEndpoint || "https://oauth2.googleapis.com/token";
  // Bucket-level admin needs the full-control scope — list-buckets +
  // create + delete + lifecycle + CORS are all admin operations beyond
  // the per-object read_write scope used by gcs.js's per-blob client.
  var scope = config.scope || "https://www.googleapis.com/auth/devstorage.full_control";
  var timeoutMs = config.timeoutMs;
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal = config.allowInternal != null ? config.allowInternal : null;

  // Token cache — same shape as gcs.js's per-blob client, scoped to
  // this factory instance so a parallel per-blob client doesn't share
  // the admin-scoped token (different scope).
  var cachedToken = null;
  var TOKEN_REFRESH_BUFFER = C.TIME.minutes(5);

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
    return httpClient.request(reqOpts).then(function (res) {
      if (expectStatus && expectStatus.indexOf(res.statusCode) === -1) {
        var bodyText = res.body ?
          (Buffer.isBuffer(res.body) ? res.body.toString("utf8") : String(res.body)) : "";
        throw _err("UNEXPECTED_STATUS",
          "gcs bucketOps: " + method + " " + url + " returned HTTP " +
          res.statusCode + (bodyText ? " — " + bodyText.slice(0, 500) : ""), true);
      }
      return res;
    }, function (e) {
      // http-client rejects on 4xx/5xx; if the caller marked the
      // status as semantically acceptable (404 on delete, 409 on
      // create) surface it as a normal response.
      var sc = e && e.statusCode;
      if (sc && expectStatus && expectStatus.indexOf(sc) !== -1) {
        return { statusCode: sc, headers: {}, body: Buffer.alloc(0) };
      }
      throw e;
    });
  }

  async function _ensureToken() {
    if (cachedToken && Date.now() < cachedToken.expiresAt - TOKEN_REFRESH_BUFFER) {
      return cachedToken.accessToken;
    }
    var assertion = gcs._signJwt(serviceAccount, scope, tokenEndpoint);
    var bodyStr = "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") +
                  "&assertion=" + encodeURIComponent(assertion);
    var bodyBuf = Buffer.from(bodyStr, "utf8");
    var res = await _request("POST", _internalUrl(tokenEndpoint, allowedProtocols), {
      "Content-Type":   "application/x-www-form-urlencoded",
      "Content-Length": String(bodyBuf.length),
    }, bodyBuf, [HTTP_OK]);
    var tokenResp = safeJson.parse(res.body);
    if (!tokenResp.access_token) {
      throw _err("AUTH_FAILED",
        "gcs bucketOps: token endpoint returned no access_token: " +
        (res.body ? res.body.toString("utf8") : ""), true);
    }
    var expiresInMs = C.TIME.seconds(tokenResp.expires_in || 3600);
    cachedToken = {
      accessToken: tokenResp.access_token,
      expiresAt:   Date.now() + expiresInMs,
    };
    return cachedToken.accessToken;
  }

  // Returns a parsed URL ready for `.searchParams` mutation. The bucket
  // base path is "/storage/v1/b"; suffix (e.g., "/" + bucket name) is
  // appended before parsing so safeUrl.parse owns every URL we hand to
  // httpClient.
  function _bucketBaseUrl(suffix) {
    return _internalUrl(endpoint + "/storage/v1/b" + (suffix || ""), allowedProtocols);
  }

  async function createBucket(name, opts) {
    _validateBucketName(name);
    opts = opts || {};
    var token = await _ensureToken();
    var url = _bucketBaseUrl();
    url.searchParams.set("project", projectId);
    var bodyObj = { name: name };
    if (opts.location)     bodyObj.location     = opts.location;
    if (opts.storageClass) bodyObj.storageClass = opts.storageClass;
    if (opts.iamConfiguration) bodyObj.iamConfiguration = opts.iamConfiguration;
    var bodyBuf = Buffer.from(JSON.stringify(bodyObj), "utf8");
    var headers = Object.assign(authHeader.bearer(token), {
      "Content-Type":   "application/json",
      "Content-Length": String(bodyBuf.length),
    });
    var res = await _request("POST", url, headers, bodyBuf, [HTTP_OK, HTTP_CONFLICT]);
    if (res.statusCode === HTTP_CONFLICT) {
      throw _err("BUCKET_ALREADY_OWNED",
        "gcs bucketOps: bucket '" + name + "' already exists", true);
    }
    var parsed = safeJson.parse(res.body);
    return {
      name:         parsed.name,
      location:     parsed.location || null,
      storageClass: parsed.storageClass || null,
    };
  }

  async function deleteBucket(name) {
    _validateBucketName(name);
    var token = await _ensureToken();
    var url = _bucketBaseUrl("/" + encodeURIComponent(name));
    var headers = authHeader.bearer(token);
    var res = await _request("DELETE", url, headers, null, [HTTP_NO_CONTENT, HTTP_NOT_FOUND]);
    return res.statusCode === HTTP_NO_CONTENT;
  }

  async function listBuckets(opts) {
    opts = opts || {};
    var token = await _ensureToken();
    var url = _bucketBaseUrl();
    url.searchParams.set("project", projectId);
    if (opts.prefix)     url.searchParams.set("prefix", opts.prefix);
    if (opts.maxResults) url.searchParams.set("maxResults", String(opts.maxResults));
    if (opts.pageToken)  url.searchParams.set("pageToken", opts.pageToken);
    var headers = authHeader.bearer(token);
    var res = await _request("GET", url, headers, null, [HTTP_OK]);
    var parsed = safeJson.parse(res.body);
    var items = Array.isArray(parsed.items) ? parsed.items : [];
    return items.map(function (item) {
      return {
        name:         item.name,
        location:     item.location || null,
        storageClass: item.storageClass || null,
        timeCreated:  item.timeCreated || null,
        updated:      item.updated || null,
      };
    });
  }

  async function setLifecycle(name, rules) {
    _validateBucketName(name);
    if (!Array.isArray(rules)) {
      throw _err("INVALID_LIFECYCLE",
        "gcs bucketOps: setLifecycle: rules must be an array", true);
    }
    rules.forEach(_validateLifecycleRule);
    var token = await _ensureToken();
    var url = _bucketBaseUrl("/" + encodeURIComponent(name));
    var bodyObj = { lifecycle: { rule: rules } };
    var bodyBuf = Buffer.from(JSON.stringify(bodyObj), "utf8");
    var headers = Object.assign(authHeader.bearer(token), {
      "Content-Type":   "application/json",
      "Content-Length": String(bodyBuf.length),
    });
    await _request("PATCH", url, headers, bodyBuf, [HTTP_OK]);
    return { rulesApplied: rules.length };
  }

  async function setCorsRules(name, rules) {
    _validateBucketName(name);
    if (!Array.isArray(rules)) {
      throw _err("INVALID_CORS_RULE",
        "gcs bucketOps: setCorsRules: rules must be an array", true);
    }
    rules.forEach(_validateCorsRule);
    var token = await _ensureToken();
    var url = _bucketBaseUrl("/" + encodeURIComponent(name));
    var bodyObj = { cors: rules };
    var bodyBuf = Buffer.from(JSON.stringify(bodyObj), "utf8");
    var headers = Object.assign(authHeader.bearer(token), {
      "Content-Type":   "application/json",
      "Content-Length": String(bodyBuf.length),
    });
    await _request("PATCH", url, headers, bodyBuf, [HTTP_OK]);
    return { rulesApplied: rules.length };
  }

  return {
    protocol:     "gcs",
    create:       createBucket,
    delete:       deleteBucket,
    list:         listBuckets,
    setLifecycle: setLifecycle,
    setCorsRules: setCorsRules,
  };
}

module.exports = { create: create };
