// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var networkByteQuota = require("../network-byte-quota");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var requestHelpers = lazyRequire(function () { return require("../request-helpers"); });

var DailyByteQuotaError = defineClass("DailyByteQuotaError", { alwaysPermanent: true });

function _defaultGetKey(req) {
  return requestHelpers().clientIp(req, { trustProxy: false });
}

/**
 * @primitive b.middleware.dailyByteQuota
 * @signature b.middleware.dailyByteQuota(opts)
 * @since     0.1.0
 * @related   b.middleware.rateLimit
 *
 * Per-IP rolling 24-hour byte budget. Tracks request + response
 * bytes per peer key (default: client IP). When a peer exceeds the
 * configured quota, further requests are refused with HTTP 429 +
 * `Retry-After`. The window slides per-second — a peer can't reset
 * by waiting past midnight. Composes `b.network.byteQuota`; handlers
 * that already know the byte cost of an op can call
 * `b.network.byteQuota.check`/`record` directly. Fails open (request
 * proceeds, audit emitted) when the backing cache is unreachable.
 *
 * @opts
 *   {
 *     bytesPerDay: number,                            // required, positive, finite
 *     getKey:      function(req): string|null,        // default: req client IP
 *     cache:       object,                            // null = in-memory single-node
 *     onDeny:      function(req, res, info): void,    // own the 429; info = { status, reason, quota, total, retryAfterSec }
 *     onExceeded:  function(req, res, info): void,    // legacy alias for onDeny
 *     problemDetails: boolean,                        // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *     skipPaths:   string[],
 *     now:         function(): number,
 *     audit:       boolean,                           // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.dailyByteQuota({
 *     bytesPerDay: b.constants.BYTES.gib(2),
 *     skipPaths:   ["/healthz"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "bytesPerDay", "cache", "getKey", "audit",
    "onDeny", "onExceeded", "problemDetails", "skipPaths", "now",
  ], "middleware.dailyByteQuota");

  if (typeof opts.bytesPerDay !== "number" || !isFinite(opts.bytesPerDay) || opts.bytesPerDay <= 0) {
    throw new DailyByteQuotaError("daily-byte-quota/bad-quota",
      "middleware.dailyByteQuota: opts.bytesPerDay must be a positive finite number; " +
      "use b.constants.BYTES.gib(N) / mib(N) for readable values");
  }
  var bytesPerDay = opts.bytesPerDay;
  var getKey = typeof opts.getKey === "function" ? opts.getKey : _defaultGetKey;
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny
    : (typeof opts.onExceeded === "function" ? opts.onExceeded : null);
  var problemMode = opts.problemDetails === true;
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  var quota = networkByteQuota.create({
    bytesPerDay: bytesPerDay,
    cache:       opts.cache || null,
    audit:       false,
    now:         now,
  });
  var backend = quota._backend;

  var _shouldSkip = requestHelpers().makeSkipMatcher(
    { skipPaths: skipPaths, exact: true }, "middleware.dailyByteQuota");

  var _emitAudit = audit().namespaced("middleware.daily_byte_quota", opts.audit);

  var _emitMetric = observability().namespaced("middleware.daily_byte_quota");

  return async function dailyByteQuotaMiddleware(req, res, next) {
    if (_shouldSkip(req)) return next();
    var key;
    try { key = getKey(req); }
    catch (e) {
      _emitAudit("get_key_failed", "failure", { error: (e && e.message) || String(e) });
      return next();
    }
    if (!key) return next();

    var nowMs = now();
    var total;
    try { total = await backend.total(key, nowMs); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "total", error: (e && e.message) || String(e) });
      return next();
    }
    if (total >= bytesPerDay) {
      _emitMetric("refused", 1, { reason: "quota-exceeded" });
      _emitAudit("refused", "denied", { key: key, total: total, quota: bytesPerDay });
      var info = {
        status:          C.HTTP.STATUS.TOO_MANY_REQUESTS,
        reason:          "quota-exceeded",
        quota:           bytesPerDay,
        total:           total,
        retryAfterSec:   Math.ceil(C.TIME.hours(1) / C.TIME.seconds(1)),
      };
      denyResponse(req, res, {
        onDeny:        onDeny,
        problem:       problemMode,
        status:        C.HTTP.STATUS.TOO_MANY_REQUESTS,
        info:          info,
        problemCode:   "daily-byte-quota-exceeded",
        problemTitle:  "Too Many Requests",
        problemDetail: "Daily byte quota exceeded; retry after the indicated interval.",
        problemExt:    { quota: bytesPerDay, total: total, retryAfter: info.retryAfterSec },
        headers:       {
          "Retry-After":   String(info.retryAfterSec),
          "Cache-Control": "no-store",
        },
        contentType:   "application/json; charset=utf-8",
        body:          JSON.stringify({ error: "quota-exceeded", quota: bytesPerDay, total: total }),
        onThrow:       function (e) { _emitAudit("on_exceeded_threw", "failure", { error: (e && e.message) || String(e) }); },
      });
      return;
    }

    var inboundBytes = 0;
    if (req.headers && typeof req.headers === "object") {
      var keys = Object.keys(req.headers);
      for (var hi = 0; hi < keys.length; hi++) {
        var v = req.headers[keys[hi]];
        inboundBytes += Buffer.byteLength(keys[hi], "utf8") + 2 +
          (typeof v === "string" ? Buffer.byteLength(v, "utf8") : 0) + 2;
      }
    }
    if (req.headers && req.headers["content-length"]) {
      var clen = parseInt(req.headers["content-length"], 10);
      if (isFinite(clen) && clen > 0) inboundBytes += clen;
    }

    var outboundBytes = 0;
    var origWrite = res.write.bind(res);
    var origEnd = res.end.bind(res);
    res.write = function (chunk, encoding, cb) {
      if (chunk) {
        outboundBytes += Buffer.isBuffer(chunk) ? chunk.length :
          Buffer.byteLength(chunk, typeof encoding === "string" ? encoding : "utf8");
      }
      return origWrite(chunk, encoding, cb);
    };
    res.end = function (chunk, encoding, cb) {
      if (chunk) {
        outboundBytes += Buffer.isBuffer(chunk) ? chunk.length :
          Buffer.byteLength(chunk, typeof encoding === "string" ? encoding : "utf8");
      }
      backend.account(key, inboundBytes + outboundBytes, now())
        .catch(function (e) { _emitAudit("backend_error", "failure", { phase: "account", error: (e && e.message) || String(e) }); });
      return origEnd(chunk, encoding, cb);
    };

    return next();
  };
}

module.exports = {
  create:                 create,
  DailyByteQuotaError:    DailyByteQuotaError,
  BINS_PER_DAY:           networkByteQuota.BINS_PER_DAY,
  _memoryBackend:         networkByteQuota._memoryBackend,
};
