"use strict";
/**
 * dailyByteQuota middleware — per-IP rolling 24-hour byte budget.
 *
 * Tracks request + response bytes per peer IP across a rolling 24-hour
 * window. When a peer exceeds the operator-configured quota, further
 * requests are rejected with 429 + Retry-After. The window slides per-
 * second so a peer that hammers the framework for 23 hours and 59
 * minutes can't reset by waiting an instant past midnight.
 *
 *   var quota = b.middleware.dailyByteQuota({
 *     bytesPerDay:    b.constants.BYTES.gib(2),  // 2 GiB / IP / day
 *     getKey:         function (req) {
 *       // default: req.ip — operator overrides for tenant-id / api-key
 *       return req.ip;
 *     },
 *     cache:          null,                       // single-node memory by default
 *     audit:          b.audit,
 *     onExceeded:     function (req, res, info) {
 *       res.setHeader("Retry-After", info.retryAfterSec);
 *       res.statusCode = 429;
 *       res.end(JSON.stringify({ error: "quota-exceeded", info: info }));
 *     },
 *   });
 *   router.use(quota);
 *
 * The middleware composes b.network.byteQuota — handlers that already
 * know the byte cost of an op call b.network.byteQuota.check / record
 * directly without going through the middleware lifecycle.
 *
 * Failure modes:
 *   - cache backend unreachable → fail-open (count drops, request
 *     proceeds), audit emitted to operator alerting; the alternative
 *     fail-closed would let a flaky cache take down the framework
 *   - peer key resolution returns null → request bypasses the quota
 *     (operator's getKey decided this IP is out-of-scope)
 */

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

// Default getKey — req.ip OR the trusted-proxy-resolved peer address
// when the operator wired b.middleware.requestId or similar earlier in
// the chain. We don't try to be clever here: req.ip is the canonical
// shape every other middleware reads.
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
  // onDeny is the canonical hook across the deny-path middleware
  // family; onExceeded is the original name kept working as an alias.
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny
    : (typeof opts.onExceeded === "function" ? opts.onExceeded : null);
  var problemMode = opts.problemDetails === true;
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  // Compose the standalone primitive — the middleware drives the same
  // counter store the operator-facing b.network.byteQuota.check /
  // record API exposes. No parallel byte-counter implementation.
  var quota = networkByteQuota.create({
    bytesPerDay: bytesPerDay,
    cache:       opts.cache || null,
    audit:       false,                                                                // middleware emits its own per-rejection audits
    now:         now,
  });
  var backend = quota._backend;

  // exact:true preserves this guard's whole-path skip semantics (no descendant
  // match); makeSkipMatcher strips the query + resolves url || originalUrl.
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
      return next();                                                                     // fail-open on operator-supplied key resolution
    }
    if (!key) return next();

    var nowMs = now();
    var total;
    try { total = await backend.total(key, nowMs); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "total", error: (e && e.message) || String(e) });
      return next();                                                                     // fail-open on cache miss
    }
    if (total >= bytesPerDay) {
      _emitMetric("refused", 1, { reason: "quota-exceeded" });
      _emitAudit("refused", "denied", { key: key, total: total, quota: bytesPerDay });
      var info = {
        status:          429,
        reason:          "quota-exceeded",
        quota:           bytesPerDay,
        total:           total,
        retryAfterSec:   Math.ceil(C.TIME.hours(1) / C.TIME.seconds(1)),
      };
      denyResponse(req, res, {
        onDeny:        onDeny,
        problem:       problemMode,
        status:        429,
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

    // Account both inbound + outbound bytes. Inbound is roughly the
    // header bytes (we don't proxy the body buffer to count). Outbound
    // is observed via writableLength as res.write / res.end fire.
    var inboundBytes = 0;
    if (req.headers && typeof req.headers === "object") {
      // Approximate: each header line is "Name: Value\r\n". Sum the
      // string lengths; the actual byte count differs only on multi-
      // byte UTF-8, which is uncommon in standard headers.
      var keys = Object.keys(req.headers);
      for (var hi = 0; hi < keys.length; hi++) {
        var v = req.headers[keys[hi]];
        inboundBytes += keys[hi].length + 2 + (typeof v === "string" ? v.length : 0) + 2;        // ": " + "\r\n" overhead
      }
    }
    if (req.headers && req.headers["content-length"]) {
      var clen = parseInt(req.headers["content-length"], 10);
      if (isFinite(clen) && clen > 0) inboundBytes += clen;
    }

    // Patch res.write / res.end to account outbound bytes.
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
      // Account on response end so a slow long-poll doesn't block the
      // accounting until the client drops.
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
  // Backward-compat re-export for tests that mocked the in-process backend.
  _memoryBackend:         networkByteQuota._memoryBackend,
};
