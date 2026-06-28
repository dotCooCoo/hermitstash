"use strict";
/**
 * Flag-evaluation cache — per-targetingKey TTL'd cache wrapping a
 * downstream provider so a high-traffic request path does not hit
 * the provider on every flag read.
 *
 *   var raw = b.flag.providers.localFile({ path: "./flags.json", watch: true });
 *   var cached = b.flag.cache(raw, { ttlMs: 60_000, maxEntries: 10000 });
 *
 *   var flag = b.flag.create({ provider: cached });
 *
 * Cache key: `${targetingKey}::${flagKey}`. Entries TTL out after
 * `ttlMs` (default 30 s). When the cache hits its `maxEntries` cap,
 * oldest entries are evicted (insertion-order via a Map).
 *
 * Cache is bypassed for evaluation contexts without a `targetingKey`
 * (flag value depends on every attribute, not a stable key).
 *
 * Operators with a hot-reload need pass `bustOn: "flag-reload"` and
 * call `cached.bust()` from their reload handler — clears the entire
 * map.
 */

var validateOpts = require("./validate-opts");
var lazyRequire  = require("./lazy-require");
var C            = require("./constants");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

function cache(downstream, opts) {
  opts = opts || {};
  validateOpts(opts, ["ttlMs", "maxEntries", "audit"], "flag.cache");
  if (!downstream || typeof downstream.evaluate !== "function") {
    throw new FlagError("flag/bad-cache",
      "cache: downstream provider must implement .evaluate()");
  }
  // A present ttlMs / maxEntries must be a positive finite integer — Infinity
  // would pass a bare `typeof === "number" && > 0` check and give a
  // never-expiring entry (ttlMs) or an unbounded cache (maxEntries).
  numericBounds.requirePositiveFiniteIntIfPresent(opts.ttlMs, "flag.cache: opts.ttlMs", FlagError, "flag/bad-cache");
  var ttlMs = (typeof opts.ttlMs === "number") ? opts.ttlMs : C.TIME.seconds(30);
  if (ttlMs < C.TIME.seconds(1)) {
    throw new FlagError("flag/bad-cache",
      "cache: ttlMs must be >= 1000ms - got " + ttlMs);
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxEntries, "flag.cache: opts.maxEntries", FlagError, "flag/bad-cache");
  var maxEntries = (typeof opts.maxEntries === "number") ? opts.maxEntries : 10000;   // entry-count default
  var auditOn = opts.audit === true;            // off by default — too chatty
  var entries = new Map();
  var hits   = 0;
  var misses = 0;
  var evictions = 0;

  function _evictExpired(nowMs) {
    var iter = entries.entries();
    var step = iter.next();
    while (!step.done) {
      if (step.value[1].expiresAt <= nowMs) {
        entries.delete(step.value[0]);
        evictions += 1;
      }
      step = iter.next();
    }
  }

  function _evictOldest() {
    var first = entries.keys().next();
    if (!first.done) {
      entries.delete(first.value);
      evictions += 1;
    }
  }

  return {
    kind: "cache:" + (downstream.kind || "unknown"),
    list: typeof downstream.list === "function"
      ? function () { return downstream.list(); }
      : function () { return []; },
    evaluate: function (flagKey, ctx) {
      var tk = (ctx && typeof ctx.targetingKey === "string") ? ctx.targetingKey : null;
      if (!tk) {
        misses += 1;
        return downstream.evaluate(flagKey, ctx);
      }
      var key = tk + "::" + flagKey;
      var now = Date.now();
      var entry = entries.get(key);
      if (entry && entry.expiresAt > now) {
        hits += 1;
        return entry.value;
      }
      if (entry) entries.delete(key);
      var freshResult = downstream.evaluate(flagKey, ctx);
      misses += 1;
      // Don't cache flag-not-found — operator might add it later.
      if (freshResult && freshResult.reason !== "flag_not_found") {
        if (entries.size >= maxEntries) _evictOldest();
        entries.set(key, { value: freshResult, expiresAt: now + ttlMs });
      }
      // Periodic sweep — evict expired on every 100th miss.
      if (misses % 100 === 0) _evictExpired(now);
      return freshResult;
    },
    bust: function () {
      var prevSize = entries.size;
      entries.clear();
      if (auditOn) {
        try {
          audit().safeEmit({
            action:   "flag.cache.bust",
            outcome:  "success",
            actor:    null,
            metadata: { prevSize: prevSize },
          });
        } catch (_e) { /* drop-silent */ }
      }
      return prevSize;
    },
    stats: function () {
      return {
        size:      entries.size,
        hits:      hits,
        misses:    misses,
        evictions: evictions,
        hitRatio:  (hits + misses) === 0 ? 0 : hits / (hits + misses),
        ttlMs:     ttlMs,
        maxEntries: maxEntries,
      };
    },
  };
}

module.exports = { cache: cache, FlagError: FlagError };
