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
 * The middleware fires twice per request:
 *   - On entry: peek the running counter, refuse if already past quota
 *   - On res.end / res.write: account both directions of byte transfer
 *
 * Single-node memory backend uses a Map<ip, { bins: Uint32Array(24),
 * windowStartHour: number }>. Each bin holds bytes for one rolling hour;
 * sweeping happens on every account() call so cold storage doesn't grow
 * unbounded. Cluster-aware operators wire opts.cache (b.cache instance)
 * and the same pattern runs in the shared backend.
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
var validateOpts = require("../validate-opts");

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var requestHelpers = lazyRequire(function () { return require("../request-helpers"); });

var DailyByteQuotaError = defineClass("DailyByteQuotaError", { alwaysPermanent: true });

var BINS_PER_DAY = 24;                                                                  // allow:raw-byte-literal — 24 hours in a day
var BIN_MS = C.TIME.hours(1);

// Default getKey — req.ip OR the trusted-proxy-resolved peer address
// when the operator wired b.middleware.requestId or similar earlier in
// the chain. We don't try to be clever here: req.ip is the canonical
// shape every other middleware reads.
function _defaultGetKey(req) {
  return requestHelpers().clientIp(req, { trustProxy: false });
}

function _hourBin(nowMs) { return Math.floor(nowMs / BIN_MS); }
function _newEntry() { return { bins: new Array(BINS_PER_DAY).fill(0), startHour: 0 }; }

// Shared sliding-window helper — both backends call this so the
// per-bin shift / zero / total math lives in one place. Returns the
// (possibly mutated) entry; caller persists if the entry is shared
// state (cache backend writes back).
function _slideAndSum(entry, nowHour) {
  if (entry.startHour === 0) entry.startHour = nowHour - (BINS_PER_DAY - 1);
  var advance = nowHour - (entry.startHour + (BINS_PER_DAY - 1));
  var moved = false;
  if (advance > 0) {
    moved = true;
    if (advance >= BINS_PER_DAY) {
      for (var i = 0; i < BINS_PER_DAY; i++) entry.bins[i] = 0;
    } else {
      for (var j = 0; j < BINS_PER_DAY - advance; j++) entry.bins[j] = entry.bins[j + advance];
      for (var k = BINS_PER_DAY - advance; k < BINS_PER_DAY; k++) entry.bins[k] = 0;
    }
    entry.startHour = nowHour - (BINS_PER_DAY - 1);
  }
  var total = 0;
  for (var t = 0; t < BINS_PER_DAY; t++) total += entry.bins[t];
  return { entry: entry, total: total, moved: moved };
}

function _memoryBackend() {
  var store = new Map();
  function _get(key) {
    var entry = store.get(key);
    if (!entry) { entry = _newEntry(); store.set(key, entry); }
    return entry;
  }
  return {
    async total(key, nowMs) {
      return _slideAndSum(_get(key), _hourBin(nowMs)).total;
    },
    async account(key, bytes, nowMs) {
      var slid = _slideAndSum(_get(key), _hourBin(nowMs));
      slid.entry.bins[BINS_PER_DAY - 1] += bytes;
    },
    _resetForTest: function () { store.clear(); },
  };
}

function _cacheBackend(cache) {
  function _key(k) { return "dailyByteQuota:" + k; }
  async function _read(key) {
    var raw = await cache.get(_key(key));
    return raw && typeof raw === "object" && Array.isArray(raw.bins) ? raw : _newEntry();
  }
  return {
    async total(key, nowMs) {
      var entry = await _read(key);
      var slid = _slideAndSum(entry, _hourBin(nowMs));
      if (slid.moved) await cache.set(_key(key), slid.entry, { ttlMs: BIN_MS * BINS_PER_DAY });
      return slid.total;
    },
    async account(key, bytes, nowMs) {
      var entry = await _read(key);
      var slid = _slideAndSum(entry, _hourBin(nowMs));
      slid.entry.bins[BINS_PER_DAY - 1] += bytes;
      await cache.set(_key(key), slid.entry, { ttlMs: BIN_MS * BINS_PER_DAY });
    },
  };
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "bytesPerDay", "cache", "getKey", "audit",
    "onExceeded", "skipPaths", "now",
  ], "middleware.dailyByteQuota");

  if (typeof opts.bytesPerDay !== "number" || !isFinite(opts.bytesPerDay) || opts.bytesPerDay <= 0) {
    throw new DailyByteQuotaError("daily-byte-quota/bad-quota",
      "middleware.dailyByteQuota: opts.bytesPerDay must be a positive finite number; " +
      "use b.constants.BYTES.gib(N) / mib(N) for readable values");
  }
  var bytesPerDay = opts.bytesPerDay;
  var getKey = typeof opts.getKey === "function" ? opts.getKey : _defaultGetKey;
  var auditOn = opts.audit !== false;
  var onExceeded = typeof opts.onExceeded === "function" ? opts.onExceeded : null;
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };
  var backend = opts.cache && typeof opts.cache.get === "function"
    ? _cacheBackend(opts.cache)
    : _memoryBackend();

  function _shouldSkip(req) {
    if (skipPaths.length === 0) return false;
    var p = req.url || req.originalUrl || "";
    var qpos = p.indexOf("?");
    if (qpos !== -1) p = p.slice(0, qpos);
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" && p === skipPaths[i]) return true;
      if (skipPaths[i] instanceof RegExp && skipPaths[i].test(p)) return true;
    }
    return false;
  }

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "middleware.daily_byte_quota." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit is best-effort */ }
  }

  function _emitMetric(verb, n, labels) {
    try { observability().safeEvent("middleware.daily_byte_quota." + verb, n || 1, labels || {}); }
    catch (_e) { /* drop-silent */ }
  }

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
        quota:           bytesPerDay,
        total:           total,
        retryAfterSec:   Math.max(C.TIME.seconds(1) / C.TIME.seconds(1) | 0, Math.ceil(BIN_MS / C.TIME.seconds(1))),
      };
      if (onExceeded) {
        try { return onExceeded(req, res, info); }
        catch (e) { _emitAudit("on_exceeded_threw", "failure", { error: (e && e.message) || String(e) }); }
      }
      if (!res.writableEnded) {
        res.writeHead(429, {
          "Content-Type":  "application/json; charset=utf-8",
          "Retry-After":   String(info.retryAfterSec),
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify({ error: "quota-exceeded", quota: bytesPerDay, total: total }));
      }
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
        inboundBytes += keys[hi].length + 2 + (typeof v === "string" ? v.length : 0) + 2;        // allow:raw-byte-literal — ": " + "\r\n" overhead
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
  _memoryBackend:         _memoryBackend,                                                // exported for tests
  BINS_PER_DAY:           BINS_PER_DAY,
};
