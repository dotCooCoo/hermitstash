"use strict";
/**
 * b.network.byteQuota — per-key rolling 24-hour byte budget primitive.
 *
 * Provides a callable preflight + record surface used by handlers that
 * already know the byte cost of an operation BEFORE accepting it (e.g.
 * a multipart upload whose Content-Length is known at headers-parsed
 * time, an SSE feed whose payload size is computed by the originator,
 * a webhook whose body size is asserted via signed manifest):
 *
 *   var quota = b.network.byteQuota.create({
 *     bytesPerDay: b.constants.BYTES.gib(2),
 *     audit:       b.audit,
 *   });
 *
 *   // Preflight — returns { allowed, remaining, total, quota } without
 *   // mutating the counter. Refusal emits network.byte_quota.exceeded.
 *   var verdict = await quota.check(req.ip, fileSize);
 *   if (!verdict.allowed) return res.writeHead(429).end();
 *
 *   // Commit — mutates the counter for the rolling-window slot.
 *   await quota.record(req.ip, fileSize);
 *
 *   // Operator helpers
 *   await quota.reset(req.ip);
 *   var snap = await quota.snapshot();          // [{ key, total, quota, remaining }]
 *
 * The middleware in lib/middleware/daily-byte-quota.js composes this
 * primitive — there's no parallel byte-counter store.
 *
 * Failure modes:
 *   - cache backend unreachable → fail-open on check (verdict.allowed
 *     true with verdict.degraded = true) so a flaky cache can't take
 *     down the framework; record swallows the error after audit so the
 *     handler that already accepted the bytes isn't punished. Both
 *     paths emit network.byte_quota.backend_error.
 *   - bytesPerDay <= 0 / non-finite at create() throws. Per-call byte
 *     counts <0 / non-finite at check/record throw NetworkError.
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var auditFwk = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var ByteQuotaError = defineClass("ByteQuotaError", { alwaysPermanent: true });

var BINS_PER_DAY = 24;                                                                  // allow:raw-byte-literal — 24 hours in a day
var BIN_MS = C.TIME.hours(1);

function _hourBin(nowMs) { return Math.floor(nowMs / BIN_MS); }
function _newEntry()    { return { bins: new Array(BINS_PER_DAY).fill(0), startHour: 0 }; }

// Shared sliding-window helper — both backends call this so the per-bin
// shift / zero / total math lives in one place. Caller persists the
// returned entry when it's shared state (cache backend writes back).
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
    async reset(key) {
      store.delete(key);
    },
    async snapshot(nowMs) {
      var nowHour = _hourBin(nowMs);
      var out = [];
      for (var key of store.keys()) {
        var slid = _slideAndSum(_get(key), nowHour);
        out.push({ key: key, total: slid.total });
      }
      return out;
    },
    _resetForTest: function () { store.clear(); },
  };
}

function _cacheBackend(cache) {
  function _key(k) { return "byteQuota:" + k; }
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
    async reset(key) {
      if (typeof cache.delete === "function") await cache.delete(_key(key));
      else if (typeof cache.del === "function") await cache.del(_key(key));
      else await cache.set(_key(key), _newEntry(), { ttlMs: 1 });
    },
    // Cache backends don't enumerate by prefix portably — snapshot()
    // returns an empty list when wired with a cache backend. Operators
    // that need cluster-wide enumeration query the cache directly with
    // their backend's idiomatic scan op.
    async snapshot(_nowMs) { return []; },
  };
}

function _requirePositiveBytes(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-quota",
      "network.byteQuota: " + name + " must be a positive finite number; " +
      "use b.constants.BYTES.gib(N) / mib(N) for readable values"
    );
  }
}

function _requireNonNegativeBytes(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-bytes",
      "network.byteQuota: " + name + " must be a non-negative finite number, got " + JSON.stringify(value)
    );
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw new ByteQuotaError(
      "byte-quota/bad-key",
      "network.byteQuota: key must be a non-empty string, got " + JSON.stringify(key)
    );
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["bytesPerDay", "cache", "audit", "now"], "network.byteQuota");
  _requirePositiveBytes("bytesPerDay", opts.bytesPerDay);
  var bytesPerDay = opts.bytesPerDay;
  var auditOn = opts.audit !== false;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };
  var backend = opts.cache && typeof opts.cache.get === "function"
    ? _cacheBackend(opts.cache)
    : _memoryBackend();

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      auditFwk().safeEmit({
        action:   "network.byte_quota." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit is best-effort */ }
  }

  function _emitMetric(verb, n, labels) {
    try { observability().safeEvent("network.byte_quota." + verb, n || 1, labels || {}); }
    catch (_e) { /* drop-silent */ }
  }

  // check(key, bytes) — preflight without mutation. Returns
  //   { allowed, total, remaining, quota, retryAfterSec, degraded }
  // `degraded: true` indicates a backend error caused the verdict to
  // fail-open; operators that want fail-closed inspect this flag.
  async function check(key, bytes) {
    _requireKey(key);
    _requireNonNegativeBytes("bytes", bytes);
    var nowMs = now();
    var total;
    try { total = await backend.total(key, nowMs); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "check", error: (e && e.message) || String(e) });
      return {
        allowed:   true,
        total:     0,
        remaining: bytesPerDay,
        quota:     bytesPerDay,
        retryAfterSec: 0,
        degraded:  true,
      };
    }
    var projected = total + bytes;
    var remaining = Math.max(0, bytesPerDay - total);
    if (projected > bytesPerDay) {
      _emitMetric("refused", 1, { reason: "quota-exceeded" });
      _emitAudit("exceeded", "denied", { key: key, total: total, requested: bytes, quota: bytesPerDay });
      return {
        allowed:   false,
        total:     total,
        remaining: remaining,
        quota:     bytesPerDay,
        retryAfterSec: Math.ceil(BIN_MS / C.TIME.seconds(1)),
        degraded:  false,
      };
    }
    return {
      allowed:   true,
      total:     total,
      remaining: Math.max(0, bytesPerDay - projected),
      quota:     bytesPerDay,
      retryAfterSec: 0,
      degraded:  false,
    };
  }

  // record(key, bytes) — commit the mutation. Used after the operation
  // succeeded (or for in-flight middleware accounting via the rolling-
  // counter middleware wrapper).
  async function record(key, bytes) {
    _requireKey(key);
    _requireNonNegativeBytes("bytes", bytes);
    if (bytes === 0) return;
    var nowMs = now();
    try { await backend.account(key, bytes, nowMs); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "record", key: key, bytes: bytes, error: (e && e.message) || String(e) });
      // Drop-silent after audit — the operation already succeeded; the
      // alternative throw would punish the handler that already accepted bytes.
      return;
    }
    _emitMetric("recorded", bytes, {});
  }

  async function reset(key) {
    _requireKey(key);
    try { await backend.reset(key); }
    catch (e) {
      _emitAudit("backend_error", "failure", { phase: "reset", error: (e && e.message) || String(e) });
    }
  }

  async function snapshot() {
    var nowMs = now();
    try {
      var rows = await backend.snapshot(nowMs);
      return rows.map(function (r) {
        return {
          key:       r.key,
          total:     r.total,
          quota:     bytesPerDay,
          remaining: Math.max(0, bytesPerDay - r.total),
        };
      });
    } catch (e) {
      _emitAudit("backend_error", "failure", { phase: "snapshot", error: (e && e.message) || String(e) });
      return [];
    }
  }

  return {
    check:    check,
    record:   record,
    reset:    reset,
    snapshot: snapshot,
    // Internals exposed for the middleware composition seam — same
    // backend instance can serve both APIs (so middleware account()
    // and standalone record() agree on the counter state).
    _backend: backend,
    _bytesPerDay: bytesPerDay,
    _now: now,
  };
}

module.exports = {
  create:           create,
  ByteQuotaError:   ByteQuotaError,
  BINS_PER_DAY:     BINS_PER_DAY,
  // Internals exposed for tests + the middleware composition seam.
  _memoryBackend:   _memoryBackend,
  _cacheBackend:    _cacheBackend,
  _slideAndSum:     _slideAndSum,
};
