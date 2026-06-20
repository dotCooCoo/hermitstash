"use strict";
/**
 * Azure Blob Storage protocol adapter — Shared Key auth (account-level).
 *
 * Auth: HMAC-SHA256 over a canonicalized string-to-sign (different format
 *       from AWS SigV4 — Azure has its own signing scheme). Signature is
 *       base64-encoded; Authorization header: "SharedKey <account>:<sig>".
 *
 * Endpoint: https://<account>.blob.core.windows.net (override via
 * config.endpoint for Azurite emulator / Azure Stack / private endpoints).
 *
 * Config:
 *   {
 *     accountName:  'mystorage'              // required
 *     accountKey:   '<base64 storage key>'    // required (REST shared key)
 *     container:    'my-container'            // required
 *     endpoint:     'https://...'             // optional override
 *     pathStyle:    true                       // optional; account as the first
 *                                              // URL path segment (Azurite / Azure
 *                                              // Stack / private endpoints).
 *                                              // Default false = host-based
 *                                              // (<account>.blob.core.windows.net).
 *     apiVersion:   '2024-08-04'              // x-ms-version header
 *     timeoutMs:    C.TIME.seconds(30)
 *   }
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
 *   https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api
 *
 * Scope notes:
 *   - Auth: Shared Key only. SAS tokens (Shared Access Signatures) and
 *     Azure AD OAuth2 are not implemented; this covers the common
 *     server-to-storage case with rotated keys.
 *   - PutBlock + PutBlockList (multipart for >256MB blobs) is not
 *     implemented; uploads above that ceiling will fail at the API.
 */
var nodeCrypto = require("node:crypto");
var { URL } = require("node:url");
var { Readable } = require("node:stream");
var safeXml = require("../parsers/safe-xml");
var sharedRequest = require("./http-request");
var sigv4 = require("./sigv4");
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var time = require("../time");
var safeUrl = require("../safe-url");

// Azure Blob list responses are commonly multi-thousand-key paginated
// payloads — well above the parser's default 1 MiB / 10K element ceilings.
var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: C.BYTES.bytes(50000),
};

// Internal URL builder — endpoint + path string from validated config.
// Routes through safeUrl.parse so the protocol allowlist + length cap
// apply uniformly. Cap is generous since SAS-presigned URLs carry many
// query params.
function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

function _arrayify(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

// Percent-encode a hierarchical blob name for use in a URL path. Azure
// blob names are `/`-delimited virtual directories, so each segment is
// RFC 3986 percent-encoded (via the family-shared encoder used by the
// S3 / GCS backends) while the `/` separators are preserved. Without
// this, a key containing `?`, `#`, a space, or other reserved chars is
// interpolated raw into the request URL — `?`/`#` start the query /
// fragment (so the blob path is truncated, hitting the wrong object or
// the container root), and spaces / control bytes corrupt the request
// line (CWE-20 improper input → request-smuggling-adjacent). A null
// byte is refused outright (it can't appear in a valid blob name and
// indicates a malformed / hostile key), matching the S3 / GCS guards.
function _encodeBlobKey(key) {
  if (key.indexOf("\0") !== -1) {
    throw _err("INVALID_KEY", "null byte in blob key", true);
  }
  return key.split("/").map(function (s) {
    return sigv4.awsUriEncode(s, true);
  }).join("/");
}

var DEFAULT_API_VERSION = "2024-08-04";

var _err = ObjectStoreError.factory;

var _httpRequest = sharedRequest;

// ---- Shared Key signing ----
//
// StringToSign for Blob (Shared Key):
//   VERB + "\n" +
//   Content-Encoding + "\n" +
//   Content-Language + "\n" +
//   Content-Length + "\n" +
//   Content-MD5 + "\n" +
//   Content-Type + "\n" +
//   Date + "\n" +
//   If-Modified-Since + "\n" +
//   If-Match + "\n" +
//   If-None-Match + "\n" +
//   If-Unmodified-Since + "\n" +
//   Range + "\n" +
//   CanonicalizedHeaders +
//   CanonicalizedResource
//
// CanonicalizedHeaders: x-ms-* headers, lowercased, sorted, "key:value\n"
// CanonicalizedResource: "/<account>/<container>/<blob>" + sorted query
//                         params each on their own line as "param:value\n"

function buildStringToSign(opts) {
  var headers = opts.headers || {};
  var url = opts.url instanceof URL ? opts.url : _internalUrl(opts.url);

  var canonicalHeaders = (function () {
    var pairs = [];
    Object.keys(headers).forEach(function (k) {
      var lk = k.toLowerCase();
      if (lk.indexOf("x-ms-") === 0) {
        pairs.push([lk, String(headers[k]).trim().replace(/\s+/g, " ")]);
      }
    });
    pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    return pairs.map(function (p) { return p[0] + ":" + p[1]; }).join("\n");
  })();

  var canonicalResource = (function () {
    // /<account>/<rest of path>
    // Plus sorted query params, each "name:value\n"
    // Canonicalized resource per the Shared Key spec: "/" + account + the
    // request's absolute path + sorted query. Host-based endpoints
    // (production <account>.blob.core.windows.net) have url.pathname
    // "/<container>/<blob>", giving "/<account>/<container>/<blob>".
    // Path-style endpoints (Azurite / Azure Stack / private) already carry
    // "/<account>" as the first path segment, so the account appears twice
    // ("/<account>/<account>/<container>/<blob>") — which is exactly what a
    // path-style server expects: it prepends the account to the full request
    // path it received. Verified against Azurite — the doubled form is the
    // one that authenticates; the URL itself must carry the account in its
    // path (see pathPrefix in create()).
    var resourcePath = "/" + opts.accountName + url.pathname;
    var paramPairs = [];
    url.searchParams.forEach(function (v, k) {
      paramPairs.push([k.toLowerCase(), v]);
    });
    paramPairs.sort(function (a, b) {
      if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
      return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    });
    // Group by name; multiple values comma-separated per Azure rules
    var grouped = {};
    paramPairs.forEach(function (p) {
      if (!grouped[p[0]]) grouped[p[0]] = [];
      grouped[p[0]].push(p[1]);
    });
    // Azure Shared Key canonicalized resource: sorted query param names,
    // each on its own line as `name:value` — Azure-spec, not JSON
    // canonicalization.
    var groupedKeys = [];
    for (var gk in grouped) groupedKeys.push(gk);
    groupedKeys.sort();
    var queryLines = groupedKeys.map(function (name) {
      return "\n" + name + ":" + grouped[name].join(",");
    }).join("");
    return resourcePath + queryLines;
  })();

  return [
    opts.method.toUpperCase(),
    headers["Content-Encoding"]      || "",
    headers["Content-Language"]      || "",
    headers["Content-Length"] && headers["Content-Length"] !== "0"
      ? headers["Content-Length"] : "",       // "0" → empty (Azure quirk)
    headers["Content-MD5"]           || "",
    headers["Content-Type"]          || "",
    "",                                       // Date line — empty when x-ms-date is set
    headers["If-Modified-Since"]     || "",
    headers["If-Match"]              || "",
    headers["If-None-Match"]         || "",
    headers["If-Unmodified-Since"]   || "",
    headers["Range"]                 || "",
    canonicalHeaders,
    canonicalResource,
  ].join("\n");
}

function signRequest(opts) {
  var headers = Object.assign({}, opts.headers || {});
  if (!headers["x-ms-version"]) headers["x-ms-version"] = opts.apiVersion || DEFAULT_API_VERSION;
  if (!headers["x-ms-date"])    headers["x-ms-date"]    = new Date().toUTCString();

  var url = opts.url instanceof URL ? opts.url : _internalUrl(opts.url);
  if (!headers["host"])         headers["host"]         = url.host;

  var sts = buildStringToSign({
    method:      opts.method,
    url:         url,
    headers:     headers,
    accountName: opts.accountName,
  });
  var keyBytes = Buffer.from(opts.accountKey, "base64");
  var signature = nodeCrypto.createHmac("sha256", keyBytes).update(sts, "utf8").digest("base64");
  headers["Authorization"] = "SharedKey " + opts.accountName + ":" + signature;

  return { headers: headers, stringToSign: sts, signature: signature };
}

// ---- Public adapter factory ----

function create(config) {
  if (!config) throw new Error("azure-blob protocol requires config");
  if (!config.accountName) throw new Error("azure-blob: accountName is required");
  if (!config.accountKey)  throw new Error("azure-blob: accountKey is required");
  if (!config.container)   throw new Error("azure-blob: container is required");

  var endpoint = config.endpoint || ("https://" + config.accountName + ".blob.core.windows.net");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var apiVersion = config.apiVersion || DEFAULT_API_VERSION;
  var timeoutMs = config.timeoutMs;
  // HTTPS-only by default — real Azure is always HTTPS. Operators with
  // an Azurite emulator endpoint opt in via config.allowedProtocols.
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  // Account placement. Default host-based — production Azure is
  // https://<account>.blob.core.windows.net/<container>/<blob> (account in the
  // host). Path-style endpoints (Azurite / Azure Stack / private) carry the
  // account as the first PATH segment instead —
  // https://<host>/<account>/<container>/<blob> — opt in with
  // config.pathStyle:true. Default false keeps the host-based wire shape
  // unchanged for existing deployments (no silent breaking change). The signed
  // canonicalized resource is always "/" + account + url.pathname, so for a
  // path-style URL the account appears twice — which is exactly what a
  // path-style server expects (see buildStringToSign).
  var pathStyle = config.pathStyle === true;
  var pathPrefix = pathStyle ? ("/" + config.accountName) : "";
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function _blobUrl(key, params) {
    var u = _internalUrl(endpoint + pathPrefix + "/" + config.container + "/" + _encodeBlobKey(key),
                         allowedProtocols);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _containerUrl(params) {
    var u = _internalUrl(endpoint + pathPrefix + "/" + config.container, allowedProtocols);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _signed(method, url, headers) {
    var s = signRequest({
      method:      method,
      url:         url,
      headers:     headers || {},
      accountName: config.accountName,
      accountKey:  config.accountKey,
      apiVersion:  apiVersion,
    });
    return s.headers;
  }

  function put(key, body, opts) {
    var url = _blobUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var headers = _signed("PUT", url, {
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
      "x-ms-blob-type": "BlockBlob",
    });
    return _httpRequest("PUT", url, headers, buf, reqOpts).then(function (res) {
      return { size: buf.length, etag: res.headers.etag };
    });
  }

  // get(key, opts?) — opts forwarded to Azure as conditional / range
  // headers (Range / x-ms-range, If-None-Match, If-Match,
  // If-Modified-Since, If-Unmodified-Since). Returns the body buffer;
  // operators wanting status + response headers call getResponse().
  function get(key, opts) {
    return getResponse(key, opts).then(function (r) { return r.body; });
  }

  function getStream(key, opts) { return Readable.from(get(key, opts)); }

  function getResponse(key, opts) {
    opts = opts || {};
    var url = _blobUrl(key);
    var extraHeaders = sharedRequest.applyConditionalGetHeaders({}, opts, "x-ms-range");
    var headers = _signed("GET", url, extraHeaders);
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      return sharedRequest.mapGetResponse(res);
    }, function (err) {
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return sharedRequest.notModifiedGetResult();
      }
      throw err;
    });
  }

  function head(key) {
    var url = _blobUrl(key);
    var headers = _signed("HEAD", url, {});
    return _httpRequest("HEAD", url, headers, null, reqOpts).then(function (res) {
      return sharedRequest.mapHeadResponse(res);
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    // Versioned erasure (opts.versionId) is the S3 Object-Lock workflow and is
    // sigv4-only today. Refuse loudly rather than silently delete the current
    // blob — a silent drop on an erasure path would let a caller believe a
    // specific version was shredded when it was not.
    if (opts.versionId) {
      throw _err("VERSIONID_UNSUPPORTED",
        "deleteKey: versioned delete (opts.versionId) is S3/sigv4-only; the Azure " +
        "Blob backend has no version surface here. Use a sigv4 backend for " +
        "Object-Lock version erasure.", true);
    }
    var url = _blobUrl(key);
    var headers = _signed("DELETE", url, {});
    return _httpRequest("DELETE", url, headers, null, reqOpts).then(
      function () { return true; },
      function (e) { if (e.statusCode === 404) return false; throw e; }
    );
  }

  function list(prefix, opts) {
    opts = opts || {};
    var params = { restype: "container", comp: "list" };
    if (prefix)                   params.prefix = prefix;
    if (opts.maxResults)          params.maxresults = String(opts.maxResults);
    if (opts.continuationToken)   params.marker = opts.continuationToken;
    var url = _containerUrl(params);
    var headers = _signed("GET", url, {});
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      var doc = safeXml.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.EnumerationResults || {};
      var blobsContainer = result.Blobs || {};
      var blobs = _arrayify(blobsContainer.Blob);
      var items = blobs.map(function (b) {
        var props = b.Properties || {};
        var size = props["Content-Length"];
        var lm = props["Last-Modified"];
        return {
          key:          b.Name,
          size:         size != null ? parseInt(size, 10) : null,
          lastModified: lm ? Date.parse(lm) : null,
        };
      }).filter(function (it) { return it.key; });
      // <NextMarker/> (self-closing) parses to "" — falsy. A real token
      // is a non-empty string, which is truthy.
      var marker = (typeof result.NextMarker === "string") ? result.NextMarker : "";
      return {
        items:             items,
        truncated:         marker.length > 0,
        continuationToken: marker.length > 0 ? marker : null,
      };
    });
  }

  // Service SAS (Shared Access Signature) generator for blob endpoints.
  // The string-to-sign layout is fixed by API version — see Azure docs
  // "Create a service SAS". We sign with the account key (HMAC-SHA256
  // over the canonical string) and emit the token as URL query params.
  function _buildSasToken(permissions, opts) {
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presigned URL", "");
    var nowDate = opts.date || new Date();
    var expiry = new Date(nowDate.getTime() + C.TIME.seconds(expiresIn));
    // Azure accepts ISO 8601 with second precision; strip ms.
    var signedExpiry = time.toIso8601NoMs(expiry);
    var signedStart  = "";  // omitted = SAS valid immediately
    var signedVersion = apiVersion;
    var signedResource = "b";  // blob
    var signedProtocol = "https";
    var canonicalizedResource = "/blob/" + config.accountName + "/" +
                                config.container + "/" + opts.key;
    var signedContentType = opts.contentType || "";

    // String-to-sign layout for Service SAS (blob), API version 2018-11-09+:
    //   signedPermissions \n signedStart \n signedExpiry \n
    //   canonicalizedResource \n signedIdentifier \n signedIP \n
    //   signedProtocol \n signedVersion \n signedResource \n
    //   signedSnapshotTime \n signedEncryptionScope \n
    //   rscc \n rscd \n rsce \n rscl \n rsct
    var stringToSign = [
      permissions,
      signedStart,
      signedExpiry,
      canonicalizedResource,
      "",                    // signedIdentifier
      "",                    // signedIP
      signedProtocol,
      signedVersion,
      signedResource,
      "",                    // signedSnapshotTime
      "",                    // signedEncryptionScope
      "",                    // rscc — Cache-Control
      "",                    // rscd — Content-Disposition
      "",                    // rsce — Content-Encoding
      "",                    // rscl — Content-Language
      signedContentType,     // rsct — Content-Type (signed when supplied)
    ].join("\n");

    var keyBuf = Buffer.from(config.accountKey, "base64");
    var signature = nodeCrypto.createHmac("sha256", keyBuf)
      .update(stringToSign, "utf8").digest("base64");

    var sas = new URLSearchParams();
    sas.set("sv",  signedVersion);
    sas.set("sr",  signedResource);
    sas.set("sp",  permissions);
    sas.set("se",  signedExpiry);
    sas.set("spr", signedProtocol);
    if (signedContentType) sas.set("rsct", signedContentType);
    sas.set("sig", signature);

    return { sas: sas.toString(), expiresAt: expiry.getTime() };
  }

  function _presign(method, permissions, opts) {
    opts = opts || {};
    if (!opts.key || typeof opts.key !== "string") {
      throw _err("INVALID_KEY", "presigned URL: key is required", true);
    }
    if (opts.key.indexOf("\0") !== -1) {
      throw _err("INVALID_KEY", "null byte in key", true);
    }

    // _buildSasToken signs the canonicalized resource with the RAW
    // (decoded) blob name per the Azure SAS spec; the URL PATH carries the
    // percent-encoded key so a key with reserved chars (`?` / `#` / space)
    // doesn't truncate the path or corrupt the request line.
    var token = _buildSasToken(permissions, opts);
    var url = _internalUrl(endpoint + pathPrefix + "/" + config.container + "/" + _encodeBlobKey(opts.key) + "?" + token.sas, allowedProtocols);

    var clientHeaders = {};
    if (opts.contentType) clientHeaders["Content-Type"] = opts.contentType;
    if (method === "PUT") clientHeaders["x-ms-blob-type"] = "BlockBlob";

    return {
      url:       url.toString(),
      method:    method,
      headers:   clientHeaders,
      expiresAt: token.expiresAt,
    };
  }

  function presignedUploadUrl(opts)   { return _presign("PUT", "cw", opts); }
  function presignedDownloadUrl(opts) { return _presign("GET", "r",  opts); }

  // Azure SAS has no equivalent of S3 / GCS POST policy with a
  // content-length-range constraint — the SAS spec carries permissions
  // / start / expiry / IP / protocol / resource-content-headers but
  // no body-size cap. Returning a PUT URL under the POST-policy name
  // would be a silent shape mismatch (operators wiring an HTML form
  // expecting multipart fields get a PUT URL with no fields), so the
  // azure-blob backend refuses cleanly.
  //
  // For strict server-side body-size enforcement on Azure: use
  // presignedUploadUrl + a server-side post-upload HEAD that deletes
  // and 4xxs the requester if Content-Length > limit.
  function presignedUploadPolicy(_opts) {
    throw _err("PRESIGN_NOT_SUPPORTED",
      "azure-blob backend does not support presigned upload policies — " +
      "Azure SAS has no body-size cap. Use presignedUploadUrl + a server-side " +
      "HEAD-and-delete check, or switch to an S3 / GCS-compatible backend.",
      true);
  }

  return {
    protocol:    "azure-blob",
    endpoint:    endpoint,
    container:   config.container,
    accountName: config.accountName,
    put:         put,
    get:         get,
    getStream:   getStream,
    getResponse: getResponse,
    head:        head,
    delete:      deleteKey,
    list:        list,
    presignedUploadUrl:    presignedUploadUrl,
    presignedDownloadUrl:  presignedDownloadUrl,
    presignedUploadPolicy: presignedUploadPolicy,
  };
}

module.exports = {
  create:             create,
  signRequest:        signRequest,
  buildStringToSign:  buildStringToSign,
  DEFAULT_API_VERSION: DEFAULT_API_VERSION,
};
