// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var { Readable } = require("node:stream");
var httpClient = require("../http-client");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");

var _err = ObjectStoreError.factory;

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
  if (typeof expiresIn !== "number" ||
      expiresIn < PRESIGN_MIN_EXPIRES_SECONDS ||
      expiresIn > PRESIGN_MAX_EXPIRES_SECONDS) {
    var capTail = hardCapLabel ? " (7 days, " + hardCapLabel + " hard cap)" : " (7 days)";
    throw _err("objectstore/invalid-expires",
      msgPrefix + ": expiresIn must be a number of seconds between " +
      PRESIGN_MIN_EXPIRES_SECONDS + " and " + PRESIGN_MAX_EXPIRES_SECONDS +
      capTail, true);
  }
  return expiresIn;
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

function promiseToStream(promise) {
  return Readable.from((async function* () { yield await promise; })());
}

module.exports = request;
module.exports.applyConditionalGetHeaders = applyConditionalGetHeaders;
module.exports.promiseToStream = promiseToStream;
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
