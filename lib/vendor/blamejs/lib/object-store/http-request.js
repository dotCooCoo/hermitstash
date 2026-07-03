// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared HTTP-request helper for object-store backends.
 *
 * Every protocol backend (azure-blob / gcs / sigv4 / http-put)
 * previously rolled an identical wrapper around httpClient.request that
 * threaded the same five opts: idleTimeoutMs / maxResponseBytes /
 * errorClass / allowedProtocols / allowInternal. Centralized here so a
 * future change to the call shape (new opt, different error class
 * default, etc.) is a one-file change.
 *
 *   var sharedRequest = require("./http-request");
 *   sharedRequest("PUT", url, headers, body, { timeoutMs: 5000 });
 *
 * The errorClass defaults to ObjectStoreError; backends that need a
 * different class pass `errorClass: SomeError` in opts.
 */

var { Readable } = require("node:stream");
var httpClient = require("../http-client");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");

// Same code-first error factory the object-store backends use; the bare
// cloud-provider-style codes (INVALID_KEY / INVALID_EXPIRES / ...) are the
// existing object-store convention, swept to namespace/kebab-case for the
// whole family in the v1.0 error-code pass.
var _err = ObjectStoreError.factory;

function request(method, url, headers, body, opts) {
  opts = opts || {};
  var req = {
    method:           method,
    url:              url,
    headers:          headers,
    body:             body,
    // Both caps from the operator's configured timeout: timeoutMs bounds the
    // whole request (no slow-trickle hold-open), idleTimeoutMs the zero-progress
    // window. Undefined leaves httpClient's defaults unchanged.
    timeoutMs:        opts.timeoutMs,
    idleTimeoutMs:    opts.timeoutMs,
    errorClass:       opts.errorClass || ObjectStoreError,
    allowedProtocols: opts.allowedProtocols,
  };
  if (opts.maxResponseBytes !== undefined) req.maxResponseBytes = opts.maxResponseBytes;
  if (opts.allowInternal !== undefined) req.allowInternal = opts.allowInternal;
  return httpClient.request(req);
}

// ---- Shared presign opts validation (gcs / sigv4) ----
// Every presigning entry point (presigned GET/PUT URLs and the POST-form
// upload policy) opened with the same key + expiry bounds checks, varying
// only in the message prefix and the signature-version label in the
// hard-cap text. Centralized so the bounds are enforced identically and a
// future change (a new cap, a different default) is one edit.
var PRESIGN_DEFAULT_EXPIRES_SECONDS = C.TIME.minutes(15) / C.TIME.seconds(1);   // 15 minutes
var PRESIGN_MAX_EXPIRES_SECONDS     = C.TIME.days(7)     / C.TIME.seconds(1);   // 7 days
var PRESIGN_MIN_EXPIRES_SECONDS     = 1;

function requirePresignKey(opts, msgPrefix) {
  if (!opts.key || typeof opts.key !== "string") {
    throw _err("INVALID_KEY", msgPrefix + ": key is required", true);
  }
  if (opts.key.indexOf("\0") !== -1) {
    throw _err("INVALID_KEY", "null byte in key", true);
  }
}

// hardCapLabel names the signing version in the cap text ("V4" / "SigV4"
// → "(7 days, V4 hard cap)"); an empty / omitted label yields the plain
// "(7 days)" tail used by the Azure SAS path, whose cap is the same 7 days
// but is not a SigV4 family limit.
function resolvePresignExpires(opts, msgPrefix, hardCapLabel) {
  var expiresIn = opts.expiresIn != null ? opts.expiresIn : PRESIGN_DEFAULT_EXPIRES_SECONDS;
  if (typeof expiresIn !== "number" ||
      expiresIn < PRESIGN_MIN_EXPIRES_SECONDS ||
      expiresIn > PRESIGN_MAX_EXPIRES_SECONDS) {
    var capTail = hardCapLabel ? " (7 days, " + hardCapLabel + " hard cap)" : " (7 days)";
    throw _err("INVALID_EXPIRES",
      msgPrefix + ": expiresIn must be a number of seconds between " +
      PRESIGN_MIN_EXPIRES_SECONDS + " and " + PRESIGN_MAX_EXPIRES_SECONDS +
      capTail, true);
  }
  return expiresIn;
}

// POST-form upload policy size bounds — returns the resolved minBytes
// (defaulting to 0). maxBytes is validated here but consumed by the
// caller (it becomes the content-length-range upper bound).
function resolvePresignUploadMinBytes(opts) {
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
  return opts.minBytes !== undefined ? opts.minBytes : 0;
}

// ---- Shared conditional-GET request + response mapping (gcs / sigv4 / azure) ----
// Every backend's getResponse() set the same RFC 7232/7233 conditional
// headers (Range + If-Match family), mapped the HTTP response into the same
// { statusCode, body, etag, lastModified, contentRange, size, contentType }
// shape, and turned a 304 into the same short-circuit result. Only the Range
// header NAME differs (S3/GCS "Range" vs Azure "x-ms-range"), so it is a
// parameter; the rest is identical.
function applyConditionalGetHeaders(target, opts, rangeHeaderName) {
  if (opts.range) {
    // The documented + shipped contract is an array [start, end] (see
    // b.archive.adapters.objectStore and b.backup). Reading .start/.end off an
    // array yields undefined → "bytes=undefined-undefined", which every store
    // IGNORES — silently returning the FULL object instead of the byte range
    // (over-fetch + wrong data for a partial read). Accept the array form (and
    // {start,end} for compatibility) and validate, so a malformed range fails
    // loudly rather than emitting a garbage header.
    var r = opts.range;
    var start = Array.isArray(r) ? r[0] : r.start;
    var end   = Array.isArray(r) ? r[1] : r.end;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start) {
      throw _err("INVALID_RANGE",
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

// HEAD response projection — { size, etag, lastModified } from the response
// headers. Shared by the header-driven backends (azure / sigv4 / http-put);
// gcs.head is NOT a member (it reads a JSON metadata body, not headers).
function mapHeadResponse(res) {
  return {
    size:         res.headers["content-length"] ? parseInt(res.headers["content-length"], 10) : null,
    etag:         res.headers.etag,
    lastModified: res.headers["last-modified"] ? Date.parse(res.headers["last-modified"]) : null,
  };
}

// The structured result a conditional GET returns when the server answers
// 304 Not Modified (httpClient surfaces it as a non-2xx error each backend
// catches and maps here).
function notModifiedGetResult() {
  return {
    statusCode: requestHelpers.HTTP_STATUS.NOT_MODIFIED,
    body: null, etag: null, lastModified: null,
  };
}

// Wrap a Promise<Buffer|string> as a Readable WITHOUT awaiting it first, so a
// backend's getStream() stays synchronous (the dispatcher hands the returned
// Readable straight to the consumer). A bare `Readable.from(promise)` throws
// ERR_INVALID_ARG_TYPE — Readable.from needs an (async-)iterable, not a Promise
// — which broke getStream on every remote backend. The async generator defers
// the await to the first read; a rejection surfaces as the stream's 'error'
// event, matching the dispatcher's "the Readable surfaces its own errors"
// contract.
function promiseToStream(promise) {
  return Readable.from((async function* () { yield await promise; })());
}

module.exports = request;
module.exports.applyConditionalGetHeaders = applyConditionalGetHeaders;
module.exports.promiseToStream = promiseToStream;
module.exports.mapGetResponse = mapGetResponse;
module.exports.mapHeadResponse = mapHeadResponse;
module.exports.notModifiedGetResult = notModifiedGetResult;
module.exports.PRESIGN_DEFAULT_EXPIRES_SECONDS = PRESIGN_DEFAULT_EXPIRES_SECONDS;
module.exports.PRESIGN_MAX_EXPIRES_SECONDS = PRESIGN_MAX_EXPIRES_SECONDS;
module.exports.PRESIGN_MIN_EXPIRES_SECONDS = PRESIGN_MIN_EXPIRES_SECONDS;
module.exports.requirePresignKey = requirePresignKey;
module.exports.resolvePresignExpires = resolvePresignExpires;
module.exports.resolvePresignUploadMinBytes = resolvePresignUploadMinBytes;
