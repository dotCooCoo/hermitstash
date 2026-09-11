// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.cache
 * @nav    Data
 * @title  Cache
 *
 * @intro
 *   LRU + TTL cache with operator-supplied namespacing, drop-silent
 *   key validation on hot-path observability, and pluggable backends
 *   that share semantics across single-process and clustered nodes.
 *
 *   Three first-class backends ship in the box:
 *
 *     - "memory" (default) — Map + LRU eviction (maxEntries) + bytes
 *       eviction (maxBytes) + periodic sweep. Single-process accuracy.
 *     - "cluster" — _blamejs_cache table via cluster-storage. One
 *       table serves every CacheInstance via "<namespace>:<key>"
 *       composite key; ON CONFLICT UPSERT for atomic set.
 *     - "redis" — cache-redis client; sliding TTL via EXPIRE; tag
 *       wipes via SCAN+DEL on a per-namespace prefix.
 *
 *   A `{ get, set, del, clear, size, close }` operator-supplied
 *   object is the custom-backend escape hatch (Memcached, in-memory
 *   harnesses, anything else with the same async surface).
 *
 *   Hot-path validation policy:
 *
 *     - create() opts             → throw at boot (config-time)
 *     - key arg on get/set/del    → throw at call site (programming bug)
 *     - per-call ttlMs override   → throw at call site (silent footgun
 *                                   if accepted)
 *     - audit / observability     → drop silent (hot-path sink)
 *     - method-after-close        → throw BAD_STATE
 *
 *   Security defaults that are NOT opt-in:
 *
 *     - auditClear: true     mass purges are operator-action shaped
 *     - auditFailures: true  backend errors are signal
 *     - hot-path get/set/hit/miss/eviction → observability only
 *       (the audit chain would drown at any reasonable QPS)
 *
 *   Returned `CacheInstance` shape:
 *
 *     get(key) → value | undefined
 *     set(key, value, opts?) → void          (opts: { ttlMs, tags, seal })
 *     del(key) → boolean
 *     has(key) → boolean                     (does NOT bump LRU recency)
 *     clear(opts?) → number                  (opts: { req, context })
 *     size() → number
 *     bytes() → number                       (memory backend only)
 *     wrap(key, fn, opts?) → fn's return     (opts: { ttlMs, singleFlight })
 *     invalidateTag(tag, opts?) → number     (opts: { req, context })
 *     getTags(key) → string[] | null
 *     close() → void
 *
 *   Stale-while-revalidate, single-flight wrap (concurrent calls
 *   collapse to one compute), tag-based bulk invalidation (memory +
 *   cluster), and cross-node invalidation via b.pubsub are all built
 *   in — operator opts in via the `staleWhileRevalidate` /
 *   `invalidationPubsub` opts.
 *
 *   What is NOT in the box: maxBytes on the cluster backend (would
 *   require an aggregate query per set; operator prunes the shared
 *   table on their own schedule) and per-entry exact slidingTtl on
 *   the cluster backend (sliding extends by the cache's defaultTtlMs;
 *   operators with mixed-TTL writes wanting strict per-entry sliding
 *   use the memory backend or extend at the application layer).
 *
 * @card
 *   LRU + TTL cache with operator-supplied namespacing, drop-silent key validation on hot-path observability, and pluggable backends that share semantics across single-process and clustered nodes.
 */

var boundedMap = require("./bounded-map");
var cacheRedis = require("./cache-redis");
var redisClient = require("./redis-client");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var frameworkSchema = require("./framework-schema");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var numericChecks = require("./numeric-checks");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var { CacheError } = require("./framework-error");

var CACHE_TABLE      = "_blamejs_cache";        // allow:hand-rolled-sql — canonical logical table-name declaration
var CACHE_TAGS_TABLE = "_blamejs_cache_tags";   // allow:hand-rolled-sql — canonical logical table-name declaration
function _cacheSqlTable() { return frameworkSchema.tableName(CACHE_TABLE); }
function _cacheTagsSqlTable() { return frameworkSchema.tableName(CACHE_TAGS_TABLE); }
function _cacheSqlOpts() { return { dialect: clusterStorage.dialect() }; }

var log = boot("cache");
var observability = lazyRequire(function () { return require("./observability"); });
// Opt-in vault seal for cluster-backend cache values. Lazy so
// vault-not-initialized in tests with a memory cache doesn't crash
// at module load.
var vault = lazyRequire(function () { return require("./vault"); });
var CACHE_SEAL_PREFIX = "blamejs:cache.sealed:";

var _err = CacheError.factory;

var DEFAULTS = Object.freeze({
  backend:                 "memory",
  ttlMs:                   C.TIME.minutes(5),
  maxEntries:              C.BYTES.bytes(10000),
  maxBytes:                Infinity,
  sweepIntervalMs:         C.TIME.minutes(1),
  staleWhileRevalidate:    false,
  slidingTtl:              false,
  auditFailures:           true,
  auditClear:              true,
});

var _isFiniteNonNegative = numericChecks.isFiniteNonNegative;
var _isPositiveInt       = numericChecks.isPositiveInt;

function _validateTtl(name, value) {
  if (value === Infinity) return;
  if (typeof value !== "number" || isNaN(value) || !isFinite(value) || value < 0) {
    throw _err("cache/bad-opt", name + " must be a non-negative finite number or Infinity, got " +
      (typeof value) + " " + JSON.stringify(value));
  }
}

function _validateMaxEntries(value) {
  if (value === Infinity) return;
  if (!_isPositiveInt(value)) {
    throw _err("cache/bad-opt", "cache.create: maxEntries must be a positive integer or Infinity, got " +
      JSON.stringify(value));
  }
}

function _validateMaxBytes(value) {
  if (value === Infinity) return;
  if (!_isFiniteNonNegative(value) || value < 1) {
    throw _err("cache/bad-opt", "cache.create: maxBytes must be a positive finite number or Infinity, got " +
      JSON.stringify(value));
  }
}

function _defaultSizeOf(value) {
  if (value === null || value === undefined) return 0;
  if (Buffer.isBuffer(value)) return value.length;
  if (typeof value === "string") return Buffer.byteLength(value, "utf8");
  if (typeof value === "number" || typeof value === "boolean") return C.BYTES.bytes(8);
  try { return Buffer.byteLength(JSON.stringify(value), "utf8"); }
  catch (_e) { return 0; }
}

function _validateBackendObject(backend) {
  validateOpts.requireMethods(backend, ["get", "set", "del", "clear", "size", "close"],
    "cache.create: custom backend", CacheError, "cache/bad-opt");
}

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "cache.create", CacheError);
  validateOpts.requireNonEmptyString(opts.namespace, "cache.create: namespace", CacheError, "cache/bad-opt");
  if (opts.namespace.indexOf(":") !== -1) {
    throw _err("cache/bad-opt", "cache.create: namespace must not contain ':' (used as cluster-key separator), got " +
      JSON.stringify(opts.namespace));
  }
  if (opts.backend !== undefined) {
    if (typeof opts.backend === "string") {
      if (opts.backend !== "memory" && opts.backend !== "cluster" && opts.backend !== "redis") {
        throw _err("cache/bad-opt", "cache.create: backend string must be 'memory' | 'cluster' | 'redis', got " +
          JSON.stringify(opts.backend));
      }
      if (opts.backend === "redis") {
        if (typeof opts.redisUrl !== "string" || opts.redisUrl.length === 0) {
          throw _err("cache/bad-opt", "cache.create: backend='redis' requires opts.redisUrl (e.g. redis://localhost:6379/0)");
        }
      }
    } else {
      _validateBackendObject(opts.backend);
    }
  }
  if (opts.ttlMs !== undefined) _validateTtl("cache.create: ttlMs", opts.ttlMs);
  if (opts.maxEntries !== undefined) _validateMaxEntries(opts.maxEntries);
  if (opts.maxBytes !== undefined) _validateMaxBytes(opts.maxBytes);
  validateOpts.optionalFunction(opts.sizeOf, "cache.create: sizeOf", CacheError);
  validateOpts.optionalBoolean(opts.slidingTtl, "cache.create: slidingTtl", CacheError);
  if (opts.sweepIntervalMs !== undefined) {
    validateOpts.optionalFiniteNonNegative(opts.sweepIntervalMs, "cache.create: sweepIntervalMs", CacheError);
    if (opts.sweepIntervalMs < C.TIME.seconds(1)) {
      throw _err("cache/bad-opt", "cache.create: sweepIntervalMs must be >= 1000ms, got " +
        JSON.stringify(opts.sweepIntervalMs));
    }
  }
  validateOpts.optionalBoolean(opts.staleWhileRevalidate, "cache.create: staleWhileRevalidate", CacheError);
  validateOpts.optionalBoolean(opts.auditFailures, "cache.create: auditFailures", CacheError);
  validateOpts.optionalBoolean(opts.auditClear, "cache.create: auditClear", CacheError);
  validateOpts.auditShape(opts.audit, "cache.create", CacheError);
  validateOpts.observabilityShape(opts.observability, "cache.create", CacheError);
  validateOpts.optionalFunction(opts.clock, "cache.create: clock", CacheError);
}

function _validateKey(key, ctx) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("cache/bad-key", ctx + ": key must be a non-empty string, got " +
      (typeof key) + " " + JSON.stringify(key));
  }
}

function _memoryBackend(cfg) {
  var entries = new Map();
  var maxEntries = cfg.maxEntries;
  var maxBytes   = cfg.maxBytes;
  var sizeOf     = cfg.sizeOf;
  var slidingTtl = cfg.slidingTtl;
  var clock      = cfg.clock;
  var emitObs    = cfg.emitObs;
  var namespace  = cfg.namespace;
  var sweepTimer = null;
  var totalBytes = 0;

  var tagIndex = new Map();

  function _isExpired(entry, now) {
    return entry.expiresAt !== Infinity && entry.expiresAt <= now;
  }

  function _untrack(key, entry) {
    if (!entry) return;
    totalBytes -= entry.bytes || 0;
    if (totalBytes < 0) totalBytes = 0;
    if (entry.tags && entry.tags.length > 0) {
      for (var i = 0; i < entry.tags.length; i++) {
        var s = tagIndex.get(entry.tags[i]);
        if (s) {
          s.delete(key);
          if (s.size === 0) tagIndex.delete(entry.tags[i]);
        }
      }
    }
  }

  function _evictByCounts() {
    while (maxEntries !== Infinity && entries.size > maxEntries) {
      var oldest = entries.keys().next().value;
      var e = entries.get(oldest);
      _untrack(oldest, e);
      entries.delete(oldest);
      emitObs("cache.eviction.size", { namespace: namespace });
    }
    while (maxBytes !== Infinity && totalBytes > maxBytes && entries.size > 0) {
      var oldestB = entries.keys().next().value;
      var eb = entries.get(oldestB);
      _untrack(oldestB, eb);
      entries.delete(oldestB);
      emitObs("cache.eviction.bytes", { namespace: namespace });
    }
  }

  async function get(key) {
    var now = clock();
    var entry = entries.get(key);
    if (!entry) return undefined;
    if (_isExpired(entry, now)) {
      _untrack(key, entry);
      entries.delete(key);
      emitObs("cache.eviction.expired", { namespace: namespace });
      return undefined;
    }
    if (slidingTtl && entry.ttlMs !== Infinity && typeof entry.ttlMs === "number") {
      entry.expiresAt = now + entry.ttlMs;
    }
    entries.delete(key);
    entries.set(key, entry);
    return entry.value;
  }

  async function set(key, value, expiresAt, meta) {
    var prior = entries.get(key);
    if (prior) {
      _untrack(key, prior);
      entries.delete(key);
    }
    var bytes = sizeOf(value) || 0;
    var ttlMs = meta && typeof meta.ttlMs === "number" ? meta.ttlMs : null;
    var tags  = (meta && Array.isArray(meta.tags)) ? meta.tags.slice() : null;
    entries.set(key, {
      value:     value,
      expiresAt: expiresAt,
      ttlMs:     ttlMs,
      bytes:     bytes,
      tags:      tags,
    });
    totalBytes += bytes;
    if (tags && tags.length > 0) {
      for (var i = 0; i < tags.length; i++) {
        var s = boundedMap.getOrInsert(tagIndex, tags[i], function () { return new Set(); });
        s.add(key);
      }
    }
    _evictByCounts();
  }

  async function del(key) {
    var entry = entries.get(key);
    if (!entry) return false;
    _untrack(key, entry);
    entries.delete(key);
    return true;
  }

  async function _updateEntry(key, mutatorFn, expiresAt, meta) {
    var now = clock();
    var entry = entries.get(key);
    var current = (entry && !_isExpired(entry, now)) ? entry.value : null;
    var decision = mutatorFn(current);
    if (decision && decision.abort !== undefined) return { aborted: decision.abort };
    if (decision && decision.delete === true) {
      if (entry) { _untrack(key, entry); entries.delete(key); }
      return { updated: true, deleted: true };
    }
    var effExpires = (decision.ttlMs !== undefined) ? now + decision.ttlMs
      : (decision.expiresAt !== undefined ? decision.expiresAt : expiresAt);
    await set(key, decision.value, effExpires, meta);
    return { updated: true, value: decision.value };
  }

  async function has(key) {
    var entry = entries.get(key);
    if (!entry) return false;
    if (_isExpired(entry, clock())) {
      _untrack(key, entry);
      entries.delete(key);
      emitObs("cache.eviction.expired", { namespace: namespace });
      return false;
    }
    return true;
  }

  async function clear() {
    var n = entries.size;
    entries.clear();
    tagIndex.clear();
    totalBytes = 0;
    return n;
  }

  async function size() {
    var now = clock();
    var live = 0;
    for (var entry of entries.values()) {
      if (!_isExpired(entry, now)) live++;
    }
    return live;
  }

  async function invalidateTag(tag) {
    var keys = tagIndex.get(tag);
    if (!keys || keys.size === 0) return 0;
    var purged = 0;
    var toDelete = Array.from(keys);
    for (var i = 0; i < toDelete.length; i++) {
      var k = toDelete[i];
      var entry = entries.get(k);
      if (entry) {
        _untrack(k, entry);
        entries.delete(k);
        purged++;
      }
    }
    return purged;
  }

  async function getTags(key) {
    var entry = entries.get(key);
    if (!entry) return null;
    return entry.tags ? entry.tags.slice() : [];
  }

  async function bytes() {
    return totalBytes;
  }

  function _sweep() {
    var now = clock();
    var purged = 0;
    for (var k of Array.from(entries.keys())) {
      var e = entries.get(k);
      if (_isExpired(e, now)) {
        _untrack(k, e);
        entries.delete(k);
        purged++;
      }
    }
    if (purged > 0) {
      for (var i = 0; i < purged; i++) emitObs("cache.eviction.expired", { namespace: namespace });
    }
  }

  function _startSweep(intervalMs) {
    if (sweepTimer) return;
    sweepTimer = safeAsync.repeating(_sweep, intervalMs, { name: "cache-sweep" });
  }

  async function close() {
    if (sweepTimer) { sweepTimer.stop(); sweepTimer = null; }
    entries.clear();
    tagIndex.clear();
    totalBytes = 0;
  }

  return {
    name:           "memory",
    get:            get,
    set:            set,
    update:         _updateEntry,
    del:            del,
    has:            has,
    clear:          clear,
    size:           size,
    bytes:          bytes,
    invalidateTag:  invalidateTag,
    getTags:        getTags,
    close:          close,
    _startSweep:    _startSweep,
    _entries:       entries,
  };
}

function _clusterBackend(cfg) {
  var namespace      = cfg.namespace;
  var clock          = cfg.clock;
  var emitObs        = cfg.emitObs;
  var slidingTtl     = cfg.slidingTtl;
  var defaultTtlMs   = cfg.defaultTtlMs;

  function _composedKey(key) { return namespace + ":" + key; }

  async function get(key) {
    var now = clock();
    var getBuilt = sql.select(_cacheSqlTable(), _cacheSqlOpts())
      .columns(["valueJson", "expiresAt"])
      .where("cacheKey", _composedKey(key))
      .toSql();
    var result = await clusterStorage.execute(getBuilt.sql, getBuilt.params);
    if (!result || !result.rows || result.rows.length === 0) return undefined;
    var row = result.rows[0];
    if (row.expiresAt <= now) {
      try {
        var delBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
          .where("cacheKey", _composedKey(key))
          .where("expiresAt", "<=", now)
          .toSql();
        await clusterStorage.execute(delBuilt.sql, delBuilt.params);
      } catch (_e) { /* sweeper will catch it next pass */ }
      emitObs("cache.eviction.expired", { namespace: namespace });
      return undefined;
    }
    if (slidingTtl && defaultTtlMs !== Infinity && typeof defaultTtlMs === "number") {
      var newExpires = now + defaultTtlMs;
      var slideBuilt = sql.update(_cacheSqlTable(), _cacheSqlOpts())
        .set({ expiresAt: newExpires, updatedAt: now })
        .where("cacheKey", _composedKey(key))
        .where("expiresAt", ">", now)
        .toSql();
      clusterStorage.execute(slideBuilt.sql, slideBuilt.params)
        .catch(function () { /* best-effort */ });
    }
    var stored = row.valueJson;
    if (typeof stored === "string" && stored.indexOf(CACHE_SEAL_PREFIX) === 0) {
      try {
        var unsealed = vault().unseal(stored.substring(CACHE_SEAL_PREFIX.length));
        return safeJson.parse(unsealed, { maxBytes: C.BYTES.mib(64) });
      } catch (_e) { return undefined; }
    }
    try { return safeJson.parse(stored, { maxBytes: C.BYTES.mib(64) }); }
    catch (_e) { return undefined; }
  }

  async function set(key, value, expiresAt, meta) {
    var json = safeJson.stringify(value);
    if (meta && meta.seal === true) {
      json = CACHE_SEAL_PREFIX + vault().seal(json);
    }
    var storedExpires = (expiresAt === Infinity) ? Number.MAX_SAFE_INTEGER : expiresAt;
    var now = clock();
    var ck = _composedKey(key);
    var tags = meta && Array.isArray(meta.tags) ? meta.tags : null;
    var upsertBuilt = sql.upsert(_cacheSqlTable(), _cacheSqlOpts())
      .columns(["cacheKey", "valueJson", "expiresAt", "updatedAt"])
      .values({ cacheKey: ck, valueJson: json, expiresAt: storedExpires, updatedAt: now })
      .onConflict(["cacheKey"])
      .doUpdate({ valueJson: "?", expiresAt: "?", updatedAt: "?" }, [json, storedExpires, now])
      .toSql();
    var tagsDelBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
      .where("cacheKey", ck)
      .toSql();
    await clusterStorage.transaction(async function (tx) {
      await tx.execute(upsertBuilt.sql, upsertBuilt.params);
      await tx.execute(tagsDelBuilt.sql, tagsDelBuilt.params);
      if (tags && tags.length > 0) {
        for (var i = 0; i < tags.length; i++) {
          var tagInsBuilt = sql.upsert(_cacheTagsSqlTable(), _cacheSqlOpts())
            .columns(["cacheKey", "tag"])
            .values({ cacheKey: ck, tag: tags[i] })
            .onConflict(["cacheKey", "tag"])
            .doNothing()
            .toSql();
          await tx.execute(tagInsBuilt.sql, tagInsBuilt.params);
        }
      }
    });
  }

  async function _updateRow(key, mutatorFn, expiresAt, meta) {
    var ck = _composedKey(key);
    var maxRetries = 5;
    for (var attempt = 0; attempt < maxRetries; attempt++) {
      var outcome = await clusterStorage.transaction(async function (tx) {
        var now = clock();
        var rowSelBuilt = sql.select(_cacheSqlTable(), _cacheSqlOpts())
          .columns(["valueJson", "expiresAt"])
          .where("cacheKey", ck)
          .toSql();
        var row = await tx.executeOne(rowSelBuilt.sql, rowSelBuilt.params);
        var oldRaw = null;
        var current = null;
        if (row && row.expiresAt > now) {
          oldRaw = row.valueJson;
          var stored = row.valueJson;
          if (typeof stored === "string" && stored.indexOf(CACHE_SEAL_PREFIX) === 0) {
            stored = vault().unseal(stored.substring(CACHE_SEAL_PREFIX.length));
          }
          current = safeJson.parse(stored, { maxBytes: C.BYTES.mib(64) });
        }
        var decision = mutatorFn(current);
        if (decision && decision.abort !== undefined) return { aborted: decision.abort };
        if (decision && decision.delete === true) {
          if (oldRaw !== null) {
            var casDelBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
              .where("cacheKey", ck)
              .where("valueJson", oldRaw)
              .toSql();
            await tx.execute(casDelBuilt.sql, casDelBuilt.params);
            var casTagDelBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
              .where("cacheKey", ck)
              .toSql();
            await tx.execute(casTagDelBuilt.sql, casTagDelBuilt.params);
          }
          return { updated: true, deleted: true };
        }
        var json = safeJson.stringify(decision.value);
        if (meta && meta.seal === true) json = CACHE_SEAL_PREFIX + vault().seal(json);
        var effExpires = (decision.ttlMs !== undefined) ? now + decision.ttlMs
          : (decision.expiresAt !== undefined ? decision.expiresAt : expiresAt);
        var storedExpires = (effExpires === Infinity) ? Number.MAX_SAFE_INTEGER : effExpires;
        if (oldRaw === null) {
          var insBuilt = sql.upsert(_cacheSqlTable(), _cacheSqlOpts())
            .columns(["cacheKey", "valueJson", "expiresAt", "updatedAt"])
            .values({ cacheKey: ck, valueJson: json, expiresAt: storedExpires, updatedAt: now })
            .onConflict(["cacheKey"])
            .doNothing()
            .toSql();
          var ins = await tx.execute(insBuilt.sql, insBuilt.params);
          if (!ins || ins.rowCount !== 1) return { conflict: true };
        } else {
          var updBuilt = sql.update(_cacheSqlTable(), _cacheSqlOpts())
            .set({ valueJson: json, expiresAt: storedExpires, updatedAt: now })
            .where("cacheKey", ck)
            .where("valueJson", oldRaw)
            .toSql();
          var upd = await tx.execute(updBuilt.sql, updBuilt.params);
          if (!upd || upd.rowCount !== 1) return { conflict: true };
        }
        return { updated: true, value: decision.value };
      });
      if (outcome && outcome.conflict) continue;
      return outcome;
    }
    throw _err("cache/update-contention",
      "cache.update: exceeded " + maxRetries + " retries under write contention for key");
  }

  async function del(key) {
    var ck = _composedKey(key);
    var delBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
      .where("cacheKey", ck)
      .toSql();
    var result = await clusterStorage.execute(delBuilt.sql, delBuilt.params);
    var tagDelBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
      .where("cacheKey", ck)
      .toSql();
    await clusterStorage.execute(tagDelBuilt.sql, tagDelBuilt.params)
      .catch(function () { /* best-effort */ });
    return !!(result && result.rowCount && result.rowCount > 0);
  }

  async function invalidateTag(tag) {
    var prefix = namespace + ":";
    var keysBuilt = sql.select(_cacheTagsSqlTable(), _cacheSqlOpts())
      .columns(["cacheKey"])
      .where("tag", tag)
      .whereLike("cacheKey", prefix, "prefix")
      .toSql();
    var keysResult = await clusterStorage.execute(keysBuilt.sql, keysBuilt.params);
    var keys = (keysResult && keysResult.rows) || [];
    if (keys.length === 0) {
      var orphanBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
        .where("tag", tag)
        .whereLike("cacheKey", prefix, "prefix")
        .toSql();
      await clusterStorage.execute(orphanBuilt.sql, orphanBuilt.params);
      return 0;
    }
    var purged = 0;
    for (var i = 0; i < keys.length; i++) {
      var ck = keys[i].cacheKey;
      var rBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
        .where("cacheKey", ck)
        .toSql();
      var r = await clusterStorage.execute(rBuilt.sql, rBuilt.params);
      if (r && r.rowCount > 0) purged += r.rowCount;
      var tagDelBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
        .where("cacheKey", ck)
        .toSql();
      await clusterStorage.execute(tagDelBuilt.sql, tagDelBuilt.params);
    }
    return purged;
  }

  async function getTags(key) {
    var built = sql.select(_cacheTagsSqlTable(), _cacheSqlOpts())
      .columns(["tag"])
      .where("cacheKey", _composedKey(key))
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    if (!result || !result.rows) return [];
    return result.rows.map(function (r) { return r.tag; });
  }

  async function has(key) {
    var now = clock();
    var built = sql.select(_cacheSqlTable(), _cacheSqlOpts())
      .columns(["expiresAt"])
      .where("cacheKey", _composedKey(key))
      .where("expiresAt", ">", now)
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    return !!(result && result.rows && result.rows.length > 0);
  }

  async function clear() {
    var prefix = namespace + ":";
    var clrBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
      .whereLike("cacheKey", prefix, "prefix")
      .toSql();
    var result = await clusterStorage.execute(clrBuilt.sql, clrBuilt.params);
    var tagClrBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
      .whereLike("cacheKey", prefix, "prefix")
      .toSql();
    await clusterStorage.execute(tagClrBuilt.sql, tagClrBuilt.params)
      .catch(function () { /* best-effort */ });
    return (result && result.rowCount) || 0;
  }

  async function size() {
    var now = clock();
    var prefix = namespace + ":";
    var built = sql.select(_cacheSqlTable(), _cacheSqlOpts())
      .count("*", "n")
      .whereLike("cacheKey", prefix, "prefix")
      .where("expiresAt", ">", now)
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    if (!result || !result.rows || result.rows.length === 0) return 0;
    var n = result.rows[0].n;
    return Number(n) || 0;
  }

  async function _sweep() {
    var now = clock();
    var prefix = namespace + ":";
    var expiredBuilt = sql.select(_cacheSqlTable(), _cacheSqlOpts())
      .columns(["cacheKey"])
      .whereLike("cacheKey", prefix, "prefix")
      .where("expiresAt", "<=", now)
      .toSql();
    var expiredResult = await clusterStorage.execute(expiredBuilt.sql, expiredBuilt.params);
    var expiredKeys = (expiredResult && expiredResult.rows) || [];
    var sweepDelBuilt = sql.delete(_cacheSqlTable(), _cacheSqlOpts())
      .whereLike("cacheKey", prefix, "prefix")
      .where("expiresAt", "<=", now)
      .toSql();
    await clusterStorage.execute(sweepDelBuilt.sql, sweepDelBuilt.params);
    for (var i = 0; i < expiredKeys.length; i++) {
      var tagSweepBuilt = sql.delete(_cacheTagsSqlTable(), _cacheSqlOpts())
        .where("cacheKey", expiredKeys[i].cacheKey)
        .toSql();
      await clusterStorage.execute(tagSweepBuilt.sql, tagSweepBuilt.params)
        .catch(function () { /* best-effort */ });
    }
  }

  function _startSweep(intervalMs) {
    cfg._sweepTimer = safeAsync.repeating(_sweep, intervalMs, { name: "cache-sweep-cluster" });
  }

  async function close() {
    if (cfg._sweepTimer) { cfg._sweepTimer.stop(); cfg._sweepTimer = null; }
  }

  return {
    name:           "cluster",
    get:            get,
    set:            set,
    update:         _updateRow,
    del:            del,
    has:            has,
    clear:          clear,
    size:           size,
    close:          close,
    invalidateTag:  invalidateTag,
    getTags:        getTags,
    _startSweep:    _startSweep,
  };
}

function _customBackend(operatorBackend, cfg) {
  return {
    name:         "custom",
    get:          function (key) { return operatorBackend.get(key); },
    set:          function (key, value, expiresAt, meta) {
      return operatorBackend.set(key, value, expiresAt, meta);
    },
    del:          function (key) { return operatorBackend.del(key); },
    has:          function (key) {
      if (typeof operatorBackend.has === "function") return operatorBackend.has(key);
      return Promise.resolve(operatorBackend.get(key)).then(function (v) { return v !== undefined; });
    },
    clear:        function () { return operatorBackend.clear(); },
    size:         function () { return operatorBackend.size(); },
    bytes:        function () {
      if (typeof operatorBackend.bytes === "function") return operatorBackend.bytes();
      return Promise.resolve(0);
    },
    invalidateTag: function (tag) {
      if (typeof operatorBackend.invalidateTag === "function") return operatorBackend.invalidateTag(tag);
      return Promise.resolve(0);
    },
    getTags: function (key) {
      if (typeof operatorBackend.getTags === "function") return operatorBackend.getTags(key);
      return Promise.resolve(null);
    },
    close:        function () { return operatorBackend.close(); },
    _startSweep:  function () { /* operator backend manages its own sweep */ },
  };
}

/**
 * @primitive b.cache.create
 * @signature b.cache.create(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.pubsub.create, b.audit
 *
 * Build a `CacheInstance` bound to a `namespace`. The instance owns
 * its sweep timer, its backend connection, its single-flight inflight
 * map, and (when `invalidationPubsub` is supplied) a pubsub
 * subscription that mirrors `del` / `clear` / `invalidateTag` events
 * across nodes. Multiple instances coexist — a "session.user" memory
 * cache and a "billing.invoice" cluster cache share neither keys nor
 * tags. `close()` releases everything.
 *
 * The `backend` opt picks the storage tier: `"memory"` (default,
 * single-process LRU+TTL), `"cluster"` (shared SQL table for
 * multi-node coherence), `"redis"` (when `redisUrl` is supplied;
 * native EXPIRE-based TTL), or an operator-supplied object with
 * `{ get, set, del, clear, size, close }` for any other store.
 * Backends are interchangeable from the caller's perspective —
 * `await cache.get(key)` returns the same shape regardless.
 *
 * @opts
 *   namespace:               string,                       // required; collision domain; must not contain ':'
 *   backend:                 "memory" | "cluster" | "redis" | object,  // default "memory"
 *   ttlMs:                   number | Infinity,            // default C.TIME.minutes(5)
 *   maxEntries:              number | Infinity,            // memory backend cap; default 10000
 *   maxBytes:                number | Infinity,            // memory backend cap; default Infinity
 *   sizeOf:                  function(value) -> number,    // memory bytes accounting override
 *   sweepIntervalMs:         number,                       // expired-entry sweep cadence; default C.TIME.minutes(1); minimum 1000
 *   staleWhileRevalidate:    boolean,                      // wrap() serves stale + refreshes in background; default false
 *   slidingTtl:              boolean,                      // bump expiresAt on hit; default false
 *   auditFailures:           boolean,                      // emit audit on backend errors; default true
 *   auditClear:              boolean,                      // emit audit on clear / invalidateTag; default true
 *   audit:                   { emit } | b.audit,           // audit sink override
 *   observability:           { event } | b.observability,  // metrics sink override
 *   clock:                   function() -> number,         // Date.now() override (testing)
 *   invalidationPubsub:      b.pubsub instance,            // cross-node del/clear/tag mirroring
 *   redisUrl:                string,                       // backend === "redis" only; required there
 *   redisPassword:           string,                       // backend === "redis" only
 *   redisUsername:           string,                       // backend === "redis" only
 *   redisTls:                boolean,                      // backend === "redis" only
 *   redisCa:                 string | Buffer,              // backend === "redis" only; PEM CA bundle
 *   redisServername:         string,                       // backend === "redis" only; SNI override
 *   redisConnectTimeoutMs:   number,                       // backend === "redis" only
 *   redisCommandTimeoutMs:   number,                       // backend === "redis" only
 *   redisMaxReconnectAttempts: number,                     // backend === "redis" only
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var C = b.constants;
 *
 *   // Simple set/get against the default memory backend.
 *   var sessions = b.cache.create({
 *     namespace:  "session.user",
 *     ttlMs:      C.TIME.minutes(5),
 *     maxEntries: 10000,
 *   });
 *   await sessions.set("u-42", { uid: "u-42", role: "admin" });
 *   var hit = await sessions.get("u-42");
 *   // → { uid: "u-42", role: "admin" }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var C = b.constants;
 *
 *   // wrap() pattern with per-call TTL override + single-flight.
 *   // Concurrent callers collapse to one DB read; subsequent reads
 *   // serve from cache for 10 minutes.
 *   var profiles = b.cache.create({
 *     namespace: "billing.profile",
 *     ttlMs:     C.TIME.minutes(2),
 *   });
 *   var profile = await profiles.wrap(
 *     "u-42",
 *     function () { return { uid: "u-42", plan: "pro" }; },
 *     { ttlMs: C.TIME.minutes(10) }
 *   );
 *   // → { uid: "u-42", plan: "pro" }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var C = b.constants;
 *
 *   // Cluster-shared cache: every node sees the same entries via the
 *   // _blamejs_cache table. Tag-based bulk invalidation purges across
 *   // every namespace member in one call.
 *   var inventory = b.cache.create({
 *     namespace: "catalog.item",
 *     backend:   "cluster",
 *     ttlMs:     C.TIME.minutes(15),
 *   });
 *   await inventory.set("sku-1001", { qty: 42 }, { tags: ["warehouse:east"] });
 *   var purged = await inventory.invalidateTag("warehouse:east");
 *   // → 1
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "backend", "ttlMs", "maxEntries", "maxBytes", "sizeOf",
    "sweepIntervalMs", "staleWhileRevalidate", "slidingTtl",
    "auditFailures", "auditClear",
    "audit", "observability", "clock",
    "redisUrl", "redisPassword", "redisUsername", "redisTls", "redisCa",
    "redisServername", "redisConnectTimeoutMs", "redisCommandTimeoutMs",
    "redisMaxReconnectAttempts",
    "invalidationPubsub",
  ], "cache");
  _validateCreateOpts(opts);
  var cfg0 = validateOpts.applyDefaults(opts, DEFAULTS);

  var namespace        = opts.namespace;
  var backendKind      = cfg0.backend;
  var defaultTtlMs     = cfg0.ttlMs;
  var maxEntries       = cfg0.maxEntries;
  var maxBytes         = cfg0.maxBytes;
  var sizeOf           = (typeof opts.sizeOf === "function") ? opts.sizeOf : _defaultSizeOf;
  var sweepIntervalMs  = cfg0.sweepIntervalMs;
  var staleRevalidate  = cfg0.staleWhileRevalidate;
  var slidingTtl       = cfg0.slidingTtl;
  var auditFailures    = cfg0.auditFailures;
  var auditClear       = cfg0.auditClear;
  var audit            = opts.audit || null;
  var operatorObs      = opts.observability || null;
  var clock            = opts.clock || function () { return Date.now(); };
  var invalidationPubsub = opts.invalidationPubsub || null;
  if (invalidationPubsub) {
    validateOpts.requireMethods(invalidationPubsub, ["publish", "subscribe", "unsubscribe"],
      "cache.create: invalidationPubsub (b.pubsub.create instance)", CacheError, "cache/bad-opt");
  }
  var invalidationChannel = "cache:" + namespace + ":invalidate";
  var invalidationToken = null;
  var inboundInvalidation = false;

  function emitObs(name, labels) {
    try {
      if (operatorObs) operatorObs.event(name, 1, labels || {});
      else observability().event(name, 1, labels || {});
    } catch (_e) { /* hot-path observability sink — drops silent on internal throws */ }
  }

  var emitAudit = validateOpts.makeAuditEmitter(audit);

  function _actor(callerOpts) {
    return requestHelpers.resolveActorWithOverride(callerOpts);
  }

  function _backendFailedAudit(op, err) {
    if (!auditFailures) return;
    emitAudit("cache.backend.failed", {
      actor:    requestHelpers.extractActorContext(null),
      resource: { kind: "cache", id: namespace },
      outcome:  "failure",
      reason:   "backend-error",
      metadata: { op: op, code: (err && err.code) || null, message: (err && err.message) || String(err) },
    });
  }

  var cfg = {
    namespace:     namespace,
    maxEntries:    maxEntries,
    maxBytes:      maxBytes,
    sizeOf:        sizeOf,
    slidingTtl:    slidingTtl,
    defaultTtlMs:  defaultTtlMs,
    clock:         clock,
    emitObs:       emitObs,
    _sweepTimer:   null,
  };
  var backend;
  if (backendKind === "memory") {
    backend = _memoryBackend(cfg);
  } else if (backendKind === "cluster") {
    backend = _clusterBackend(cfg);
  } else if (backendKind === "redis") {
    backend = _customBackend(cacheRedis.create(Object.assign(
      redisClient.pickClientOpts(opts, "redis"),
      {
        namespace:    namespace,
        slidingTtl:   slidingTtl,
        defaultTtlMs: defaultTtlMs,
        clock:        clock,
        emitObs:      emitObs,
      }
    )), cfg);
  } else {
    backend = _customBackend(opts.backend, cfg);
  }

  backend._startSweep(sweepIntervalMs);

  var closed = false;
  function _ensureOpen(method) {
    if (closed) {
      throw _err("cache/bad-state", "cache." + method + ": cache instance has been closed");
    }
  }

  var inflight = new Map();

  var softExpiry = new Map();
  var swrInflight = new Map();
  var SWR_HARD_MULTIPLIER = 2;

  function _resolveTtl(callerOpts, methodName) {
    if (callerOpts && callerOpts.ttlMs !== undefined) {
      _validateTtl("cache." + methodName + ": ttlMs", callerOpts.ttlMs);
      return callerOpts.ttlMs;
    }
    return defaultTtlMs;
  }

  async function get(key) {
    _ensureOpen("get");
    _validateKey(key, "cache.get");
    var v;
    try { v = await backend.get(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "get" });
      _backendFailedAudit("get", e);
      throw e;
    }
    if (v === undefined) emitObs("cache.miss", { namespace: namespace });
    else emitObs("cache.hit", { namespace: namespace });
    return v;
  }

  async function set(key, value, callerOpts) {
    _ensureOpen("set");
    _validateKey(key, "cache.set");
    var ttlMs = _resolveTtl(callerOpts, "set");
    if (ttlMs === 0) return;
    var expiresAt = (ttlMs === Infinity) ? Infinity : (clock() + ttlMs);
    var tags = (callerOpts && Array.isArray(callerOpts.tags)) ? callerOpts.tags : null;
    if (tags) {
      for (var i = 0; i < tags.length; i++) {
        if (typeof tags[i] !== "string" || tags[i].length === 0) {
          throw _err("cache/bad-opt", "cache.set: tags must be an array of non-empty strings");
        }
      }
    }
    var seal = !!(callerOpts && callerOpts.seal === true);
    if (seal && backend.name !== "cluster") {
      throw _err("cache/bad-opt",
        "cache.set: seal: true is only supported on the cluster backend " +
        "(this cache instance uses '" + (backend.name || "custom") + "'). " +
        "Memory-backed caches do not need seal because the value never reaches disk; " +
        "custom backends wrap their own at-rest encryption.");
    }
    try { await backend.set(key, value, expiresAt, { ttlMs: ttlMs, tags: tags, seal: seal }); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
      _backendFailedAudit("set", e);
      throw e;
    }
    emitObs("cache.set", { namespace: namespace });
  }

  /**
   * @primitive b.cache.update
   * @signature b.cache.update(key, mutatorFn, opts?)
   * @since     0.13.39
   * @status    stable
   * @related   b.cache.create
   *
   * Atomic read-modify-write. Reads the current value, calls
   * `mutatorFn(current | null)`, and commits the result in one operation
   * so a concurrent writer cannot clobber the change (lost update) — the
   * race that makes a plain `get` → mutate → `set` unsafe for counters,
   * sets, and quorum state. The memory backend is atomic by single-thread;
   * the cluster backend uses a transaction with compare-and-set + retry.
   *
   * `mutatorFn` returns one of: `{ value }` to commit the new value,
   * `{ abort: data }` to leave the entry untouched and surface `data` to
   * the caller, or `{ delete: true }` to remove the entry. A committing
   * decision may also set the written value's lifetime — `{ value, ttlMs }`
   * (a duration the backend resolves against its own clock) or
   * `{ value, expiresAt }` (an absolute time) — when the new value's own
   * state decides how long it should live; otherwise the call `ttlMs`
   * applies. The call resolves to `{ updated: true, value }`,
   * `{ updated: true, deleted: true }`, or `{ aborted: data }`.
   *
   * @opts
   *   ttlMs:  number | Infinity,   // lifetime of the written value; default the instance ttlMs
   *   seal:   boolean,             // cluster backend only — seal the value at rest
   *
   * @example
   *   await counters.update("hits", function (n) {
   *     return { value: (n || 0) + 1 };
   *   });
   */
  async function update(key, mutatorFn, callerOpts) {
    _ensureOpen("update");
    _validateKey(key, "cache.update");
    if (typeof mutatorFn !== "function") {
      throw _err("cache/bad-opt", "cache.update: mutatorFn must be a function, got " + typeof mutatorFn);
    }
    if (typeof backend.update !== "function") {
      throw _err("cache/unsupported",
        "cache.update is unsupported by the '" + (backend.name || "custom") + "' backend " +
        "(memory + cluster implement it; a custom backend must provide update for atomic RMW).");
    }
    var ttlMs = _resolveTtl(callerOpts, "update");
    var expiresAt = (ttlMs === Infinity) ? Infinity : (clock() + ttlMs);
    var seal = !!(callerOpts && callerOpts.seal === true);
    if (seal && backend.name !== "cluster") {
      throw _err("cache/bad-opt",
        "cache.update: seal: true is only supported on the cluster backend " +
        "(this cache instance uses '" + (backend.name || "custom") + "').");
    }
    var result;
    try { result = await backend.update(key, mutatorFn, expiresAt, { ttlMs: ttlMs, seal: seal }); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "update" });
      _backendFailedAudit("update", e);
      throw e;
    }
    if (result && (result.updated || result.deleted)) {
      emitObs("cache.update", { namespace: namespace });
      if (result.deleted) { softExpiry.delete(key); _publishInvalidation({ kind: "del", key: key }); }
    }
    return result;
  }

  async function del(key) {
    _ensureOpen("del");
    _validateKey(key, "cache.del");
    var existed;
    try { existed = await backend.del(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "del" });
      _backendFailedAudit("del", e);
      throw e;
    }
    if (existed) emitObs("cache.del", { namespace: namespace });
    softExpiry.delete(key);
    _publishInvalidation({ kind: "del", key: key });
    return existed;
  }

  async function has(key) {
    _ensureOpen("has");
    _validateKey(key, "cache.has");
    try { return await backend.has(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "has" });
      _backendFailedAudit("has", e);
      throw e;
    }
  }

  async function clear(callerOpts) {
    _ensureOpen("clear");
    var purged;
    try { purged = await backend.clear(); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "clear" });
      _backendFailedAudit("clear", e);
      throw e;
    }
    emitObs("cache.clear", { namespace: namespace });
    if (auditClear) {
      emitAudit("cache.cleared", {
        actor:    _actor(callerOpts),
        resource: { kind: "cache", id: namespace },
        outcome:  "success",
        metadata: { itemCount: purged },
      });
    }
    inflight.clear();
    swrInflight.clear();
    softExpiry.clear();
    _publishInvalidation({ kind: "clear" });
    return purged;
  }

  async function size() {
    _ensureOpen("size");
    try { return await backend.size(); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "size" });
      _backendFailedAudit("size", e);
      throw e;
    }
  }

  async function bytes() {
    _ensureOpen("bytes");
    try {
      if (typeof backend.bytes !== "function") return 0;
      return await backend.bytes();
    } catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "bytes" });
      _backendFailedAudit("bytes", e);
      throw e;
    }
  }

  async function invalidateTag(tag, callerOpts) {
    _ensureOpen("invalidateTag");
    if (typeof tag !== "string" || tag.length === 0) {
      throw _err("cache/bad-opt", "cache.invalidateTag: tag must be a non-empty string");
    }
    if (typeof backend.invalidateTag !== "function") {
      throw _err("cache/not-supported",
        "cache.invalidateTag: backend '" + (backend.name || "custom") +
        "' does not implement invalidateTag. Operator-supplied custom backends " +
        "must export invalidateTag(tag) → number to participate in tag-based wipes.");
    }
    var purged;
    try { purged = await backend.invalidateTag(tag); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "invalidateTag" });
      _backendFailedAudit("invalidateTag", e);
      throw e;
    }
    emitObs("cache.tag.invalidated", { namespace: namespace, tag: tag });
    if (auditClear && purged > 0) {
      emitAudit("cache.tag.invalidated", {
        actor:    _actor(callerOpts),
        resource: { kind: "cache.tag", id: namespace + ":" + tag },
        outcome:  "success",
        metadata: { tag: tag, itemCount: purged },
      });
    }
    inflight.clear();
    swrInflight.clear();
    _publishInvalidation({ kind: "tag", tag: tag });
    return purged;
  }

  async function getTags(key) {
    _ensureOpen("getTags");
    _validateKey(key, "cache.getTags");
    if (typeof backend.getTags !== "function") return null;
    try { return await backend.getTags(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "getTags" });
      _backendFailedAudit("getTags", e);
      throw e;
    }
  }

  function _backgroundRefresh(key, fn, ttlMs) {
    if (swrInflight.has(key)) return;
    var p = (async function () {
      var startedAt = clock();
      var computed;
      try { computed = await fn(); }
      finally {
        emitObs("cache.wrap.compute", { namespace: namespace, ms: clock() - startedAt });
      }
      var expiresAt = _writeWithSwr(key, computed, ttlMs);
      void expiresAt;
      return computed;
    })();
    swrInflight.set(key, p);
    p.then(
      function () { swrInflight.delete(key); },
      function (_e) {
        swrInflight.delete(key);
        emitObs("cache.refresh.failed", { namespace: namespace });
      }
    );
  }

  function _writeWithSwr(key, value, ttlMs) {
    if (ttlMs === 0) return null;
    var now = clock();
    var hardTtlMs = (ttlMs === Infinity)
      ? Infinity
      : (staleRevalidate ? ttlMs * SWR_HARD_MULTIPLIER : ttlMs);
    var expiresAt = (hardTtlMs === Infinity) ? Infinity : (now + hardTtlMs);
    if (staleRevalidate && ttlMs !== Infinity) {
      softExpiry.set(key, now + ttlMs);
    } else {
      softExpiry.delete(key);
    }
    backend.set(key, value, expiresAt, { ttlMs: ttlMs }).catch(function (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
      _backendFailedAudit("set", e);
    });
    return expiresAt;
  }

  async function wrap(key, fn, callerOpts) {
    _ensureOpen("wrap");
    _validateKey(key, "cache.wrap");
    if (typeof fn !== "function") {
      throw _err("cache/bad-opt", "cache.wrap: fn must be a function, got " + typeof fn);
    }
    var ttlMs = _resolveTtl(callerOpts, "wrap");
    var singleFlight = !(callerOpts && callerOpts.singleFlight === false);

    var existing;
    try { existing = await backend.get(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "get" });
      _backendFailedAudit("get", e);
      throw e;
    }

    if (existing !== undefined) {
      var soft = softExpiry.get(key);
      var now = clock();
      if (staleRevalidate && soft !== undefined && soft <= now) {
        emitObs("cache.hit", { namespace: namespace });
        _backgroundRefresh(key, fn, ttlMs);
        return existing;
      }
      emitObs("cache.hit", { namespace: namespace });
      return existing;
    }
    emitObs("cache.miss", { namespace: namespace });

    if (singleFlight && inflight.has(key)) {
      emitObs("cache.wrap.singleflight.collapsed", { namespace: namespace });
      return inflight.get(key);
    }

    var promise = (async function () {
      var startedAt = clock();
      var computed;
      try { computed = await fn(); }
      finally {
        emitObs("cache.wrap.compute", { namespace: namespace, ms: clock() - startedAt });
      }
      if (ttlMs !== 0) {
        if (staleRevalidate) {
          _writeWithSwr(key, computed, ttlMs);
        } else {
          var expiresAt = (ttlMs === Infinity) ? Infinity : (clock() + ttlMs);
          try { await backend.set(key, computed, expiresAt, { ttlMs: ttlMs }); }
          catch (e) {
            emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
            _backendFailedAudit("set", e);
          }
        }
      }
      return computed;
    })();
    if (singleFlight) {
      inflight.set(key, promise);
      promise.then(
        function () { inflight.delete(key); },
        function () { inflight.delete(key); }
      );
    }
    return promise;
  }

  function _publishInvalidation(ev) {
    if (!invalidationPubsub || inboundInvalidation) return;
    try { invalidationPubsub.publish(invalidationChannel, ev); }
    catch (_e) { /* publish best-effort — local invalidation already happened */ }
  }

  async function _onInboundInvalidation(ev ) {
    if (!ev || closed) return;
    inboundInvalidation = true;
    try {
      if (ev.kind === "tag" && typeof ev.tag === "string" &&
          typeof backend.invalidateTag === "function") {
        try { await backend.invalidateTag(ev.tag); }
        catch (e) { log.debug("invalidation-apply-failed", { op: "invalidateTag", tag: ev.tag, error: e.message }); }
      } else if (ev.kind === "del" && typeof ev.key === "string") {
        try { await backend.del(ev.key); }
        catch (e) { log.debug("invalidation-apply-failed", { op: "del", key: ev.key, error: e.message }); }
      } else if (ev.kind === "clear") {
        try { await backend.clear(); }
        catch (e) { log.debug("invalidation-apply-failed", { op: "clear", error: e.message }); }
      }
      inflight.clear();
      swrInflight.clear();
      softExpiry.clear();
    } finally {
      inboundInvalidation = false;
    }
  }

  if (invalidationPubsub) {
    invalidationToken = invalidationPubsub.subscribe(invalidationChannel, _onInboundInvalidation);
  }

  async function close() {
    if (closed) return;
    closed = true;
    if (invalidationPubsub && invalidationToken) {
      try { invalidationPubsub.unsubscribe(invalidationToken); }
      catch (e) { log.debug("close-cleanup-failed", { op: "unsubscribe", error: e.message }); }
      invalidationToken = null;
    }
    inflight.clear();
    swrInflight.clear();
    softExpiry.clear();
    try { await backend.close(); }
    catch (_e) { /* close best-effort */ }
  }

  return {
    get:                    get,
    set:                    set,
    update:                 update,
    del:                    del,
    has:                    has,
    clear:                  clear,
    size:                   size,
    bytes:                  bytes,
    wrap:                   wrap,
    invalidateTag:          invalidateTag,
    getTags:                getTags,
    close:                  close,
    namespace:              namespace,
    _backend:               backend,
    _inflight:              inflight,
  };
}

module.exports = {
  create:        create,
  CacheError:    CacheError,
  DEFAULTS:      DEFAULTS,
};
