"use strict";
/**
 * Google Cloud Storage (GCS) protocol adapter — native JSON API.
 *
 * Auth: service-account JSON (RSA-SHA256 signed JWT exchanged for an
 *       OAuth2 access token; tokens cached until ~5 min before expiry).
 *
 * Endpoint: https://storage.googleapis.com (override via config.endpoint
 * for emulators / private endpoints).
 *
 * Config:
 *   {
 *     bucket:         'my-bucket'                        // required
 *     serviceAccount: { client_email, private_key, ... } // OR
 *     serviceAccountFile: '/path/to/sa.json'             // OR
 *     scope:          'https://www.googleapis.com/auth/devstorage.read_write'
 *     endpoint:       'https://storage.googleapis.com'
 *     timeoutMs:      C.TIME.seconds(30)
 *   }
 *
 * Reference:
 *   https://cloud.google.com/storage/docs/json_api/v1
 *   https://developers.google.com/identity/protocols/oauth2/service-account
 */
var nodeFs = require("fs");
var nodeCrypto = require("crypto");
var { Readable } = require("stream");
var safeJson = require("../safe-json");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");
var sharedRequest = require("./http-request");
var authHeader = require("../auth-header");
var sigv4 = require("./sigv4");

// Internal URL builder — endpoint + path string from validated config.
// Routes through safeUrl.parse so the protocol allowlist + length cap
// apply uniformly. Cap is generous since presigned URLs can carry many
// query params.
function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

// V4 query-string presigning. GCS uses the same canonical-request
// shape as AWS SigV4, differing only in:
//   - algorithm:        GOOG4-RSA-SHA256 (RSA service-account signing)
//   - service:          storage
//   - region:           auto (single global region for V4 presigning)
//   - credential scope: {date}/{region}/storage/goog4_request
//   - param prefix:     X-Goog-* instead of X-Amz-*
//   - credential value: client_email instead of accessKeyId
var GCS_V4_ALGORITHM = "GOOG4-RSA-SHA256";
var GCS_V4_SERVICE   = "storage";
var GCS_V4_REGION    = "auto";

// Same expiry bounds as SigV4 — V4 presigning shares the spec's 7-day cap.
var PRESIGN_DEFAULT_EXPIRES_SECONDS = C.TIME.minutes(15) / C.TIME.seconds(1);
var PRESIGN_MAX_EXPIRES_SECONDS     = C.TIME.days(7)     / C.TIME.seconds(1);
var PRESIGN_MIN_EXPIRES_SECONDS     = 1;

var SERVICE_ACCOUNT_SCHEMA = {
  type: "object",
  required: ["client_email", "private_key"],
  properties: {
    client_email: { type: "string" },
    private_key:  { type: "string" },
    token_uri:    { type: "string" },
    project_id:   { type: "string" },
  },
};

var DEFAULT_ENDPOINT     = "https://storage.googleapis.com";
var TOKEN_ENDPOINT       = "https://oauth2.googleapis.com/token";
var DEFAULT_SCOPE        = "https://www.googleapis.com/auth/devstorage.read_write";
var TOKEN_REFRESH_BUFFER = C.TIME.minutes(5); // refresh 5 min before expiry

var _err = ObjectStoreError.factory;

// ---- Generic HTTP helper (separate from sigv4's; no signing here) ----

var _httpRequest = sharedRequest;

// ---- JWT signing for service-account auth ----

function _base64UrlEncode(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function _signJwt(serviceAccount, scope, audience) {
  var nowSec = Math.floor(Date.now() / C.TIME.seconds(1));
  var header = { alg: "RS256", typ: "JWT" };
  var claim = {
    iss:   serviceAccount.client_email,
    scope: scope,
    aud:   audience || TOKEN_ENDPOINT,
    iat:   nowSec,
    exp:   nowSec + (C.TIME.hours(1) / C.TIME.seconds(1)),
  };
  var headerB64 = _base64UrlEncode(JSON.stringify(header));
  var claimB64  = _base64UrlEncode(JSON.stringify(claim));
  var signingInput = headerB64 + "." + claimB64;

  var signer = nodeCrypto.createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  var signature = signer.sign(serviceAccount.private_key);
  return signingInput + "." + _base64UrlEncode(signature);
}

// ---- Public adapter factory ----

function create(config) {
  if (!config) throw new Error("gcs protocol requires config");
  if (!config.bucket) throw new Error("gcs: bucket is required");

  var serviceAccount = config.serviceAccount;
  if (!serviceAccount && config.serviceAccountFile) {
    try {
      serviceAccount = safeJson.parse(nodeFs.readFileSync(config.serviceAccountFile), { schema: SERVICE_ACCOUNT_SCHEMA });
    } catch (e) {
      throw new Error("gcs: failed to read serviceAccountFile '" + config.serviceAccountFile + "': " + e.message);
    }
  } else if (serviceAccount && (!serviceAccount.client_email || !serviceAccount.private_key)) {
    throw new Error("gcs: serviceAccount with { client_email, private_key } is required (or serviceAccountFile pointing to one)");
  }
  if (!serviceAccount) {
    throw new Error("gcs: serviceAccount with { client_email, private_key } is required (or serviceAccountFile pointing to one)");
  }

  var endpoint = config.endpoint || DEFAULT_ENDPOINT;
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var tokenEndpoint = config.tokenEndpoint || TOKEN_ENDPOINT;
  var bucket    = config.bucket;
  var scope     = config.scope || DEFAULT_SCOPE;
  var timeoutMs = config.timeoutMs;
  // HTTPS-only by default — google APIs are always HTTPS. Operators with
  // an emulator / private fake-GCS endpoint opt in via config.allowedProtocols.
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint,      { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  safeUrl.parse(tokenEndpoint, { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  // ---- Token cache ----
  var cachedToken = null;       // { accessToken, expiresAt }

  async function _ensureToken() {
    if (cachedToken && Date.now() < cachedToken.expiresAt - TOKEN_REFRESH_BUFFER) {
      return cachedToken.accessToken;
    }
    var assertion = _signJwt(serviceAccount, scope, tokenEndpoint);
    var bodyStr = "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") +
                  "&assertion=" + encodeURIComponent(assertion);
    var bodyBuf = Buffer.from(bodyStr, "utf8");
    var res = await _httpRequest(
      "POST",
      _internalUrl(tokenEndpoint, allowedProtocols),
      {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": String(bodyBuf.length),
      },
      bodyBuf,
      reqOpts
    );
    var tokenResp = safeJson.parse(res.body);
    if (!tokenResp.access_token) {
      throw _err("AUTH_FAILED", "GCS token endpoint returned no access_token: " + res.body.toString("utf8"), true);
    }
    var expiresInMs = C.TIME.seconds(tokenResp.expires_in || 3600);
    cachedToken = {
      accessToken: tokenResp.access_token,
      expiresAt:   Date.now() + expiresInMs,
    };
    return cachedToken.accessToken;
  }

  function _objectUrl(key, params) {
    var u = _internalUrl(endpoint + "/storage/v1/b/" + encodeURIComponent(bucket) +
                    "/o/" + encodeURIComponent(key), allowedProtocols);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _uploadUrl(key) {
    var u = _internalUrl(endpoint + "/upload/storage/v1/b/" + encodeURIComponent(bucket) + "/o", allowedProtocols);
    u.searchParams.set("uploadType", "media");
    u.searchParams.set("name", key);
    return u;
  }

  function _listUrl(prefix, opts) {
    var u = _internalUrl(endpoint + "/storage/v1/b/" + encodeURIComponent(bucket) + "/o", allowedProtocols);
    if (prefix)                      u.searchParams.set("prefix", prefix);
    if (opts && opts.maxResults)     u.searchParams.set("maxResults", String(opts.maxResults));
    if (opts && opts.pageToken)      u.searchParams.set("pageToken", opts.pageToken);
    return u;
  }

  // ---- Operations ----

  async function put(key, body, opts) {
    var token = await _ensureToken();
    var url = _uploadUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var res = await _httpRequest("POST", url, Object.assign(
      authHeader.bearer(token),
      { "Content-Type":   contentType,
        "Content-Length": String(buf.length) }
    ), buf, reqOpts);
    var meta = safeJson.parse(res.body);
    return { size: parseInt(meta.size || buf.length, 10), etag: meta.etag };
  }

  // get(key, opts?) — opts forwarded to GCS as conditional / range
  // headers (Range, If-None-Match, If-Match, If-Modified-Since,
  // If-Unmodified-Since). Returns the body buffer for backwards compat;
  // operators wanting full status + response headers call getResponse().
  async function get(key, opts) {
    var r = await getResponse(key, opts);
    return r.body;
  }

  function getStream(key, opts) {
    return Readable.from(get(key, opts));
  }

  async function getResponse(key, opts) {
    opts = opts || {};
    var token = await _ensureToken();
    var url = _objectUrl(key, { alt: "media" });
    var headers = authHeader.bearer(token);
    if (opts.range) {
      headers["Range"] = "bytes=" + opts.range.start + "-" + opts.range.end;
    }
    if (opts.ifNoneMatch)       headers["If-None-Match"]       = opts.ifNoneMatch;
    if (opts.ifMatch)           headers["If-Match"]            = opts.ifMatch;
    if (opts.ifModifiedSince)   headers["If-Modified-Since"]   = opts.ifModifiedSince;
    if (opts.ifUnmodifiedSince) headers["If-Unmodified-Since"] = opts.ifUnmodifiedSince;
    try {
      var res = await _httpRequest("GET", url, headers, null, reqOpts);
      return {
        statusCode:   res.statusCode,
        body:         res.body,
        etag:         res.headers && res.headers.etag,
        lastModified: res.headers && res.headers["last-modified"]
                      ? Date.parse(res.headers["last-modified"]) : null,
        contentRange: res.headers && res.headers["content-range"] || null,
        size:         res.headers && res.headers["content-length"]
                      ? parseInt(res.headers["content-length"], 10) : null,
        contentType:  res.headers && res.headers["content-type"] || null,
      };
    } catch (err) {
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return {
          statusCode: requestHelpers.HTTP_STATUS.NOT_MODIFIED,
          body: null, etag: null, lastModified: null,
        };
      }
      throw err;
    }
  }

  async function head(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key);
    var res = await _httpRequest("GET", url, authHeader.bearer(token), null, reqOpts);
    var meta = safeJson.parse(res.body);
    return {
      size:         parseInt(meta.size, 10),
      etag:         meta.etag,
      lastModified: meta.updated ? Date.parse(meta.updated) : null,
    };
  }

  async function deleteKey(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key);
    try {
      await _httpRequest("DELETE", url, authHeader.bearer(token), null, reqOpts);
      return true;
    } catch (e) {
      if (e.statusCode === 404) return false;
      throw e;
    }
  }

  async function list(prefix, opts) {
    opts = opts || {};
    var token = await _ensureToken();
    var url = _listUrl(prefix, { maxResults: opts.maxResults, pageToken: opts.continuationToken });
    var res = await _httpRequest("GET", url, authHeader.bearer(token), null, reqOpts);
    var listResp = safeJson.parse(res.body);
    var items = (listResp.items || []).map(function (item) {
      return {
        key:          item.name,
        size:         parseInt(item.size, 10),
        lastModified: item.updated ? Date.parse(item.updated) : null,
      };
    });
    return {
      items:             items,
      truncated:         !!listResp.nextPageToken,
      continuationToken: listResp.nextPageToken || null,
    };
  }

  function _v4Presign(method, opts) {
    opts = opts || {};
    if (!opts.key || typeof opts.key !== "string") {
      throw _err("INVALID_KEY", "presigned URL: key is required", true);
    }
    if (opts.key.indexOf("\0") !== -1) {
      throw _err("INVALID_KEY", "null byte in key", true);
    }
    var expiresIn = opts.expiresIn != null ? opts.expiresIn : PRESIGN_DEFAULT_EXPIRES_SECONDS;
    if (typeof expiresIn !== "number" ||
        expiresIn < PRESIGN_MIN_EXPIRES_SECONDS ||
        expiresIn > PRESIGN_MAX_EXPIRES_SECONDS) {
      throw _err("INVALID_EXPIRES",
        "presigned URL: expiresIn must be a number of seconds between " +
        PRESIGN_MIN_EXPIRES_SECONDS + " and " + PRESIGN_MAX_EXPIRES_SECONDS +
        " (7 days, V4 hard cap)", true);
    }

    // V4 presigned URLs target the XML API path-style endpoint
    // (storage.googleapis.com/{bucket}/{key}), not the JSON API used
    // for the in-process put/get methods. The XML endpoint is what
    // honors the V4 signature.
    var encodedKey = opts.key.split("/")
      .map(function (s) { return sigv4.awsUriEncode(s, true); })
      .join("/");
    var url = _internalUrl(endpoint + "/" + encodeURIComponent(bucket) + "/" + encodedKey, allowedProtocols);

    var date = opts.date || new Date();
    // Reuse SigV4's date formatters — the wire format is identical.
    var amzDate = sigv4.formatAmzDate(date);
    var dateStamp = sigv4.formatDateStamp(date);
    var credentialScope = dateStamp + "/" + GCS_V4_REGION + "/" +
                          GCS_V4_SERVICE + "/goog4_request";

    var headers = { host: url.host };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    // GCS V4 SignedHeaders: lowercase, semicolon-joined, AWS-spec order.
    var signedHeaderKeys = [];
    for (var hk in headers) signedHeaderKeys.push(hk);
    signedHeaderKeys.sort();
    var signedHeadersStr = signedHeaderKeys.join(";");

    url.searchParams.set("X-Goog-Algorithm",     GCS_V4_ALGORITHM);
    url.searchParams.set("X-Goog-Credential",    serviceAccount.client_email + "/" + credentialScope);
    url.searchParams.set("X-Goog-Date",          amzDate);
    url.searchParams.set("X-Goog-Expires",       String(expiresIn));
    url.searchParams.set("X-Goog-SignedHeaders", signedHeadersStr);

    // Build the canonical request — identical shape to SigV4. The
    // sigv4 export gives us the formatter so this stays in lockstep
    // with the AWS implementation.
    var canon = sigv4.canonicalRequest(method, url, headers, "UNSIGNED-PAYLOAD");
    var stringToSign = [
      GCS_V4_ALGORITHM,
      amzDate,
      credentialScope,
      sigv4.sha256Hex(canon),
    ].join("\n");

    // GCS V4 signs the stringToSign with the service-account's RSA
    // private key (RSA-SHA256). Hex-encoded signature goes back into
    // the URL.
    var signer = nodeCrypto.createSign("RSA-SHA256");
    signer.update(stringToSign);
    signer.end();
    var signature = signer.sign(serviceAccount.private_key).toString("hex");

    url.searchParams.set("X-Goog-Signature", signature);

    var clientHeaders = {};
    if (opts.contentType) clientHeaders["Content-Type"] = opts.contentType;

    return {
      url:       url.toString(),
      method:    method,
      headers:   clientHeaders,
      expiresAt: date.getTime() + C.TIME.seconds(expiresIn),
    };
  }

  function presignedUploadUrl(opts)   { return _v4Presign("PUT", opts); }
  function presignedDownloadUrl(opts) { return _v4Presign("GET", opts); }

  // GCS V4 POST policy presigning. Same shape as SigV4 POST policy
  // (operator-uploaded multipart/form-data with policy + signature
  // fields), but signed with the service account's RSA private key
  // instead of an HMAC chain. The content-length-range condition is
  // server-side enforced by GCS — clients sending bodies outside the
  // declared range get a 403 from the bucket itself.
  function presignedUploadPolicy(opts) {
    opts = opts || {};
    if (!opts.key || typeof opts.key !== "string") {
      throw _err("INVALID_KEY", "presignedUploadPolicy: key is required", true);
    }
    if (opts.key.indexOf("\0") !== -1) {
      throw _err("INVALID_KEY", "null byte in key", true);
    }
    if (typeof opts.maxBytes !== "number" || !Number.isFinite(opts.maxBytes) ||
        opts.maxBytes <= 0) {
      throw _err("INVALID_MAX_BYTES",
        "presignedUploadPolicy: maxBytes (positive number of bytes) is required — " +
        "POST-form policy enforces body size via the content-length-range condition; " +
        "use presignedUploadUrl if size enforcement is not needed", true);
    }
    if (opts.minBytes !== undefined && !numericBounds.isNonNegativeFiniteInt(opts.minBytes)) {
      throw _err("INVALID_MIN_BYTES",
        "presignedUploadPolicy: minBytes must be a non-negative finite integer; got " +
        numericBounds.shape(opts.minBytes), true);
    }
    var minBytes = opts.minBytes !== undefined ? opts.minBytes : 0;
    var expiresIn = opts.expiresIn != null ? opts.expiresIn : PRESIGN_DEFAULT_EXPIRES_SECONDS;
    if (typeof expiresIn !== "number" ||
        expiresIn < PRESIGN_MIN_EXPIRES_SECONDS ||
        expiresIn > PRESIGN_MAX_EXPIRES_SECONDS) {
      throw _err("INVALID_EXPIRES",
        "presignedUploadPolicy: expiresIn must be a number of seconds between " +
        PRESIGN_MIN_EXPIRES_SECONDS + " and " + PRESIGN_MAX_EXPIRES_SECONDS +
        " (7 days, V4 hard cap)", true);
    }

    var date = opts.date || new Date();
    var amzDate = sigv4.formatAmzDate(date);
    var dateStamp = sigv4.formatDateStamp(date);
    var credentialScope = dateStamp + "/" + GCS_V4_REGION + "/" +
                          GCS_V4_SERVICE + "/goog4_request";
    var credential = serviceAccount.client_email + "/" + credentialScope;
    var expirationIso = new Date(date.getTime() + C.TIME.seconds(expiresIn)).toISOString();

    var conditions = [
      { "bucket":            bucket },
      { "key":               opts.key },
      { "x-goog-algorithm":  GCS_V4_ALGORITHM },
      { "x-goog-credential": credential },
      { "x-goog-date":       amzDate },
      ["content-length-range", minBytes, opts.maxBytes],
    ];
    if (opts.contentType) {
      conditions.push({ "content-type": opts.contentType });
    }

    var policy = { expiration: expirationIso, conditions: conditions };
    var policyJson = JSON.stringify(policy);
    var policyB64 = Buffer.from(policyJson, "utf8").toString("base64");

    // GCS V4: signature is hex(RSA-SHA256(privateKey, policyB64)).
    var signer = nodeCrypto.createSign("RSA-SHA256");
    signer.update(policyB64);
    signer.end();
    var signature = signer.sign(serviceAccount.private_key).toString("hex");

    var fields = {
      "key":               opts.key,
      "x-goog-algorithm":  GCS_V4_ALGORITHM,
      "x-goog-credential": credential,
      "x-goog-date":       amzDate,
      "policy":            policyB64,
      "x-goog-signature":  signature,
    };
    if (opts.contentType) fields["content-type"] = opts.contentType;

    var url = _internalUrl(endpoint + "/" + encodeURIComponent(bucket) + "/", allowedProtocols);

    return {
      url:         url.toString(),
      method:      "POST",
      fields:      fields,
      expiresAt:   date.getTime() + C.TIME.seconds(expiresIn),
      maxBytes:    opts.maxBytes,
      enforcement: "content-length-range",
    };
  }

  return {
    protocol:  "gcs",
    endpoint:  endpoint,
    bucket:    bucket,
    put:       put,
    get:       get,
    getStream: getStream,
    getResponse: getResponse,
    head:      head,
    delete:    deleteKey,
    list:      list,
    presignedUploadUrl:    presignedUploadUrl,
    presignedDownloadUrl:  presignedDownloadUrl,
    presignedUploadPolicy: presignedUploadPolicy,
    // Internal accessors for tests
    _ensureToken: _ensureToken,
    _signJwt:     function () { return _signJwt(serviceAccount, scope, TOKEN_ENDPOINT); },
  };
}

module.exports = {
  create:                create,
  _signJwt:              _signJwt,
  _base64UrlEncode:      _base64UrlEncode,
  DEFAULT_ENDPOINT:      DEFAULT_ENDPOINT,
  TOKEN_ENDPOINT:        TOKEN_ENDPOINT,
  DEFAULT_SCOPE:         DEFAULT_SCOPE,
};
