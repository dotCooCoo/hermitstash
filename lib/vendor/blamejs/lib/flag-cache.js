// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.flag.cache
 * @nav        Tools
 * @title      Flag cache
 * @order      102
 *
 * @intro
 *   A short-lived cache in front of a flag provider, keyed by the evaluation
 *   context the decision was made against.
 *
 * @card
 *   Wrap a flag provider in a TTL cache keyed by the whole evaluation
 *   context, so one principal's decision is never served to another.
 */

var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var lazyRequire  = require("./lazy-require");
var C            = require("./constants");
var numericBounds = require("./numeric-bounds");
var canonicalJson = require("./canonical-json");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

function _contextKey(targetingKey, flagKey, ctx) {
  var canonical;
  try { canonical = canonicalJson.stringify(ctx && typeof ctx === "object" ? ctx : {}); }
  catch (_e) { return null; }
  if (typeof canonical !== "string") return null;
  var digest = nodeCrypto.createHash("sha3-512").update(canonical).digest("hex");
  return targetingKey.length + ":" + targetingKey + "::" +
         flagKey.length + ":" + flagKey + "::" + digest;
}

/**
 * @primitive b.flag.cache
 * @signature b.flag.cache(downstream, opts?)
 * @since     0.7.111
 * @status    stable
 * @related   b.flag.create, b.flag.context.fromRequest
 *
 * Wrap a flag provider in a TTL cache. Returns a provider of the same shape,
 * `{ kind, list, evaluate, bust, stats }`, so it goes wherever the wrapped one
 * went.
 *
 * The cache key is the flag key, the context's `targetingKey`, and a SHA3-512
 * digest of the whole evaluation context. A targeting rule reads any path
 * through that context, so every field it could decide on is part of the key
 * and one principal's decision is never answered for another's context. The
 * digest keeps the key a fixed length, since a context carries values a client
 * chooses, such as the agent string. A context that cannot be canonicalized,
 * and one carrying no `targetingKey`, are passed straight to the wrapped
 * provider rather than cached.
 *
 * A `flag_not_found` result is not stored. `bust()` clears every entry and
 * answers how many it held. Entries expire on read, the oldest is dropped when
 * `maxEntries` is reached, and expired ones are swept every hundredth miss.
 *
 * @opts
 *   ttlMs:      number,    // entry lifetime, at least 1000; default 30000
 *   maxEntries: number,    // ceiling on entries held; default 10000
 *   audit:      boolean,   // emit flag.cache.bust through b.audit
 *
 * @example
 *   var b = require("blamejs");
 *   var provider = b.flag.providers.memory({
 *     flags: { beta: { default: "off", variants: { on: true, off: false } } },
 *   });
 *   var cached = b.flag.cache(provider, { ttlMs: b.constants.TIME.seconds(5) });
 *   cached.evaluate("beta", { targetingKey: "alice" });
 *   cached.evaluate("beta", { targetingKey: "alice" });
 *   cached.stats().hits;   // → 1
 *   cached.kind;           // → "cache:memory"
 */
function cache(downstream, opts) {
  opts = opts || {};
  validateOpts(opts, ["ttlMs", "maxEntries", "audit"], "flag.cache");
  if (!downstream || typeof downstream.evaluate !== "function") {
    throw new FlagError("flag/bad-cache",
      "cache: downstream provider must implement .evaluate()");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.ttlMs, "flag.cache: opts.ttlMs", FlagError, "flag/bad-cache");
  var ttlMs = (typeof opts.ttlMs === "number") ? opts.ttlMs : C.TIME.seconds(30);
  if (ttlMs < C.TIME.seconds(1)) {
    throw new FlagError("flag/bad-cache",
      "cache: ttlMs must be >= 1000ms - got " + ttlMs);
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxEntries, "flag.cache: opts.maxEntries", FlagError, "flag/bad-cache");
  var maxEntries = (typeof opts.maxEntries === "number") ? opts.maxEntries : 10000;
  var auditOn = opts.audit === true;
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
      var key = _contextKey(tk, flagKey, ctx);
      if (key === null) {
        misses += 1;
        return downstream.evaluate(flagKey, ctx);
      }
      var now = Date.now();
      var entry = entries.get(key);
      if (entry && entry.expiresAt > now) {
        hits += 1;
        return entry.value;
      }
      if (entry) entries.delete(key);
      var freshResult = downstream.evaluate(flagKey, ctx);
      misses += 1;
      if (freshResult && freshResult.reason !== "flag_not_found") {
        if (entries.size >= maxEntries) _evictOldest();
        entries.set(key, { value: freshResult, expiresAt: now + ttlMs });
      }
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
