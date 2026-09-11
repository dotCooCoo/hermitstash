// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var bCrypto = require("../crypto");
var safeJson = require("../safe-json");
var C = require("../constants");
var atomicFile = require("../atomic-file");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");
var sharedRequest = require("./http-request");
var authHeader = require("../auth-header");
var sigv4 = require("./sigv4");

function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

var GCS_V4_ALGORITHM = "GOOG4-RSA-SHA256";
var GCS_V4_SERVICE   = "storage";
var GCS_V4_REGION    = "auto";

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
var TOKEN_REFRESH_BUFFER = C.TIME.minutes(5);

var _err = ObjectStoreError.factory;

var _httpRequest = sharedRequest;

function _base64UrlEncode(buf) { return bCrypto.toBase64Url(buf); }

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

function create(config) {
  if (!config) throw new Error("gcs protocol requires config");
  if (!config.bucket) throw new Error("gcs: bucket is required");

  var serviceAccount = config.serviceAccount;
  if (!serviceAccount && config.serviceAccountFile) {
    try {
      serviceAccount = safeJson.parse(atomicFile.fdSafeReadSync(config.serviceAccountFile, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }), { schema: SERVICE_ACCOUNT_SCHEMA });
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
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint,      { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  safeUrl.parse(tokenEndpoint, { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  var cachedToken = null;

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
      throw _err("objectstore/auth-failed", "GCS token endpoint returned no access_token: " + res.body.toString("utf8"), true);
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

  async function get(key, opts) {
    var r = await getResponse(key, opts);
    return r.body;
  }

  function getStream(key, opts) {
    return sharedRequest.promiseToStream(get(key, opts));
  }

  async function getResponse(key, opts) {
    opts = opts || {};
    var token = await _ensureToken();
    var url = _objectUrl(key, { alt: "media" });
    var headers = authHeader.bearer(token);
    sharedRequest.applyConditionalGetHeaders(headers, opts, "Range");
    try {
      var res = await _httpRequest("GET", url, headers, null, reqOpts);
      return sharedRequest.mapGetResponse(res);
    } catch (err) {
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return sharedRequest.notModifiedGetResult();
      }
      return sharedRequest.rethrowObjectError(err, key);
    }
  }

  async function head(key) {
    var token = await _ensureToken();
    var url = _objectUrl(key);
    var res;
    try {
      res = await _httpRequest("GET", url, authHeader.bearer(token), null, reqOpts);
    } catch (err) {
      return sharedRequest.rethrowObjectError(err, key);
    }
    var meta = safeJson.parse(res.body);
    return {
      size:         parseInt(meta.size, 10),
      etag:         meta.etag,
      lastModified: meta.updated ? Date.parse(meta.updated) : null,
    };
  }

  async function deleteKey(key, opts) {
    opts = opts || {};
    if (opts.versionId) {
      throw _err("objectstore/versionid-unsupported",
        "deleteKey: versioned delete (opts.versionId) is S3/sigv4-only; the GCS " +
        "backend has no version surface here. Use a sigv4 backend for Object-Lock " +
        "version erasure.", true);
    }
    var token = await _ensureToken();
    var url = _objectUrl(key);
    try {
      await _httpRequest("DELETE", url, authHeader.bearer(token), null, reqOpts);
      return true;
    } catch (e) {
      if (e.statusCode === C.HTTP.STATUS.NOT_FOUND) return false;
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
    sharedRequest.requirePresignKey(opts, "presigned URL");
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presigned URL", "V4");

    var encodedKey = opts.key.split("/")
      .map(function (s) { return sigv4.awsUriEncode(s, true); })
      .join("/");
    var url = _internalUrl(endpoint + "/" + encodeURIComponent(bucket) + "/" + encodedKey, allowedProtocols);

    var date = opts.date || new Date();
    var amzDate = sigv4.formatAmzDate(date);
    var dateStamp = sigv4.formatDateStamp(date);
    var credentialScope = dateStamp + "/" + GCS_V4_REGION + "/" +
                          GCS_V4_SERVICE + "/goog4_request";

    var headers = { host: url.host };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    var signedHeaderKeys = [];
    for (var hk in headers) signedHeaderKeys.push(hk);
    signedHeaderKeys.sort();
    var signedHeadersStr = signedHeaderKeys.join(";");

    url.searchParams.set("X-Goog-Algorithm",     GCS_V4_ALGORITHM);
    url.searchParams.set("X-Goog-Credential",    serviceAccount.client_email + "/" + credentialScope);
    url.searchParams.set("X-Goog-Date",          amzDate);
    url.searchParams.set("X-Goog-Expires",       String(expiresIn));
    url.searchParams.set("X-Goog-SignedHeaders", signedHeadersStr);

    var canon = sigv4.canonicalRequest(method, url, headers, "UNSIGNED-PAYLOAD", false);
    var stringToSign = [
      GCS_V4_ALGORITHM,
      amzDate,
      credentialScope,
      sigv4.sha256Hex(canon),
    ].join("\n");

    var signer = nodeCrypto.createSign("RSA-SHA256");
    signer.update(stringToSign);
    signer.end();
    var signature = signer.sign(serviceAccount.private_key).toString("hex");

    url.searchParams.set("X-Goog-Signature", signature);

    sigv4.alignWireQueryToSigV4(url);

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

  function presignedUploadPolicy(opts) {
    opts = opts || {};
    sharedRequest.requirePresignKey(opts, "presignedUploadPolicy");
    var minBytes = sharedRequest.resolvePresignUploadMinBytes(opts);
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presignedUploadPolicy", "V4");

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
