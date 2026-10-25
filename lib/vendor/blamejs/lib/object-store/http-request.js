// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var { PassThrough } = require("node:stream");
var httpClient = require("../http-client");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");

var _err = ObjectStoreError.factory;

function resolveTransport(configuredProtocols, configuredAllowInternal, urls, timeoutMs) {
  var allowedProtocols = configuredProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = configuredAllowInternal != null ? configuredAllowInternal : null;
  for (var i = 0; i < urls.length; i += 1) {
    safeUrl.parse(urls[i], {
      allowedProtocols: allowedProtocols,
      errorClass:       ObjectStoreError,
    });
  }
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;
  return {
    allowedProtocols: allowedProtocols,
    allowInternal:    allowInternal,
    reqOpts:          reqOpts,
  };
}

function request(method, url, headers, body, opts) {
  opts = opts || {};
  var req = {
    method:           method,
    url:              url,
    headers:          headers,
    body:             body,
    timeoutMs:        opts.timeoutMs,
    idleTimeoutMs:    opts.timeoutMs,
    errorClass:       opts.errorClass || ObjectStoreError,
    allowedProtocols: opts.allowedProtocols,
    responseMode:     opts.responseMode,
  };
  if (opts.maxResponseBytes !== undefined) req.maxResponseBytes = opts.maxResponseBytes;
  if (opts.allowInternal !== undefined) req.allowInternal = opts.allowInternal;
  return httpClient.request(req);
}

var PRESIGN_DEFAULT_EXPIRES_SECONDS = C.TIME.minutes(15) / C.TIME.seconds(1);
var PRESIGN_MAX_EXPIRES_SECONDS     = C.TIME.days(7)     / C.TIME.seconds(1);
var PRESIGN_MIN_EXPIRES_SECONDS     = 1;

function requirePresignKey(opts, msgPrefix) {
  if (!opts.key || typeof opts.key !== "string") {
    throw _err("objectstore/invalid-key", msgPrefix + ": key is required", true);
  }
  if (opts.key.indexOf("\0") !== -1) {
    throw _err("objectstore/invalid-key", "null byte in key", true);
  }
}

function resolvePresignExpires(opts, msgPrefix, hardCapLabel) {
  var expiresIn = opts.expiresIn != null ? opts.expiresIn : PRESIGN_DEFAULT_EXPIRES_SECONDS;
  if (typeof expiresIn !== "number" || !Number.isInteger(expiresIn) ||
      expiresIn < PRESIGN_MIN_EXPIRES_SECONDS ||
      expiresIn > PRESIGN_MAX_EXPIRES_SECONDS) {
    var capTail = hardCapLabel ? " (7 days, " + hardCapLabel + " hard cap)" : " (7 days)";
    throw _err("objectstore/invalid-expires",
      msgPrefix + ": expiresIn must be an integer number of seconds between " +
      PRESIGN_MIN_EXPIRES_SECONDS + " and " + PRESIGN_MAX_EXPIRES_SECONDS +
      capTail, true);
  }
  return expiresIn;
}

function assertSafeContentType(contentType, msgPrefix) {
  if (contentType === undefined || contentType === null) return;
  if (typeof contentType !== "string" || /[\r\n\0]/.test(contentType)) {
    throw _err("objectstore/invalid-content-type",
      msgPrefix + ": contentType must be a string with no CR, LF, or NUL byte", true);
  }
}

function resolvePresignUploadMinBytes(opts) {
  if (typeof opts.maxBytes !== "number" || !Number.isFinite(opts.maxBytes) ||
      opts.maxBytes <= 0) {
    throw _err("objectstore/invalid-max-bytes",
      "presignedUploadPolicy: maxBytes (positive number of bytes) is required — " +
      "POST-form policy enforces body size via the content-length-range condition; " +
      "use presignedUploadUrl if size enforcement is not needed", true);
  }
  if (opts.minBytes !== undefined && !numericBounds.isNonNegativeFiniteInt(opts.minBytes)) {
    throw _err("objectstore/invalid-min-bytes",
      "presignedUploadPolicy: minBytes must be a non-negative finite integer; got " +
      numericBounds.shape(opts.minBytes), true);
  }
  return opts.minBytes !== undefined ? opts.minBytes : 0;
}

function applyConditionalGetHeaders(target, opts, rangeHeaderName) {
  if (opts.range) {
    var r = opts.range;
    var start = Array.isArray(r) ? r[0] : r.start;
    var end   = Array.isArray(r) ? r[1] : r.end;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start) {
      throw _err("objectstore/invalid-range",
        "range must be [start, end] (or { start, end }) with 0 <= start <= end, got " +
        JSON.stringify(r), true);
    }
    target[rangeHeaderName] = "bytes=" + start + "-" + end;
  }
  if (opts.ifNoneMatch)       target["If-None-Match"]       = opts.ifNoneMatch;
  if (opts.ifMatch)           target["If-Match"]            = opts.ifMatch;
  if (opts.ifModifiedSince)   target["If-Modified-Since"]   = opts.ifModifiedSince;
  if (opts.ifUnmodifiedSince) target["If-Unmodified-Since"] = opts.ifUnmodifiedSince;
  return target;
}

function mapGetResponse(res) {
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
}

function mapHeadResponse(res) {
  return {
    size:         res.headers["content-length"] ? parseInt(res.headers["content-length"], 10) : null,
    etag:         res.headers.etag,
    lastModified: res.headers["last-modified"] ? Date.parse(res.headers["last-modified"]) : null,
  };
}

function rethrowObjectError(err, key) {
  if (err && err.statusCode === C.HTTP.STATUS.NOT_FOUND) {
    var mapped = _err("objectstore/not-found", "key not found: " + key, true);
    mapped.statusCode = C.HTTP.STATUS.NOT_FOUND;
    throw mapped;
  }
  throw err;
}

function notModifiedGetResult() {
  return {
    statusCode: requestHelpers.HTTP_STATUS.NOT_MODIFIED,
    body: null, etag: null, lastModified: null,
  };
}

function assertOkStatus(res) {
  var status = res && res.statusCode;
  if (typeof status === "number" && (status < 200 || status >= 300) &&
      status !== requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
    var body = res && res.body;
    if (body && typeof body.destroy === "function") {
      try { body.destroy(); } catch (_e) { /* best-effort */ }
    }
    var err = _err("objectstore/http-error",
      "object store returned HTTP " + status);
    err.statusCode = status;
    throw err;
  }
  return res;
}

function streamObject(responsePromise, key) {
  return responseToStream(
    responsePromise
      .then(assertOkStatus)
      .catch(function (err) { return rethrowObjectError(err, key); }));
}

function responseToStream(promise) {
  var out = new PassThrough();
  var upstream = null;
  var consumerClosed = false;
  out.on("close", function () {
    consumerClosed = true;
    if (upstream && typeof upstream.destroy === "function") {
      try { upstream.destroy(); } catch (_e) { /* best-effort */ }
    }
  });
  (async function () {
    var res;
    try { res = await promise; }
    catch (err) { out.destroy(err); return; }
    var src = (res && typeof res === "object" && !Buffer.isBuffer(res) && "body" in res)
      ? res.body : res;
    if (!src || typeof src.pipe !== "function") {
      if (!consumerClosed) out.end(src == null ? undefined : src);
      return;
    }
    upstream = src;
    if (consumerClosed) {
      try { src.destroy(); } catch (_e) { /* best-effort */ }
      return;
    }
    src.on("error", function (e) { out.destroy(e); });
    var declared = httpClient._bodyLengthOf(res, "GET");
    if (declared !== null) {
      var seen = 0;
      src.on("data", function (c) { seen += c.length; });
      src.on("end", function () {
        if (seen === declared) return;
        var short = _err("objectstore/truncated-body",
          "object body ended after " + seen + " of " + declared + " bytes");
        short.permanent = false;
        short.transient = true;
        out.destroy(short);
      });
    }
    src.pipe(out);
  })();
  return out;
}

module.exports = request;
module.exports.applyConditionalGetHeaders = applyConditionalGetHeaders;
module.exports.responseToStream = responseToStream;
module.exports.streamObject = streamObject;
module.exports.mapGetResponse = mapGetResponse;
module.exports.mapHeadResponse = mapHeadResponse;
module.exports.notModifiedGetResult = notModifiedGetResult;
module.exports.rethrowObjectError = rethrowObjectError;
module.exports.PRESIGN_DEFAULT_EXPIRES_SECONDS = PRESIGN_DEFAULT_EXPIRES_SECONDS;
module.exports.PRESIGN_MAX_EXPIRES_SECONDS = PRESIGN_MAX_EXPIRES_SECONDS;
module.exports.PRESIGN_MIN_EXPIRES_SECONDS = PRESIGN_MIN_EXPIRES_SECONDS;
module.exports.requirePresignKey = requirePresignKey;
module.exports.resolvePresignExpires = resolvePresignExpires;
module.exports.resolvePresignUploadMinBytes = resolvePresignUploadMinBytes;
module.exports.assertSafeContentType = assertSafeContentType;
module.exports.resolveTransport = resolveTransport;
