"use strict";
/**
 * Redis-backed cache backend for b.cache.
 *
 * Storage layout (operator-overridable namespace; default = "blamejs:cache"):
 *   <namespace>:e:<key>            STRING — JSON-encoded value
 *                                          PEXPIREAT honours the cache's TTL
 *   <namespace>:t:<tag>            SET     — cacheKeys carrying that tag
 *                                          (powers invalidateTag fan-out)
 *   <namespace>:k:<key>:tags       SET     — tags this key carries
 *                                          (powers per-key tag cleanup on
 *                                          del / set-overwrite, expires
 *                                          alongside the entry)
 *
 * Same backend contract as the framework's other cache backends (memory,
 * cluster, custom): get / set / del / has / clear / size / close, plus
 * the optional invalidateTag + getTags + bytes + _startSweep hooks the
 * `_customBackend` wrapper looks for.
 *
 * TTL is enforced by Redis itself (PEXPIREAT) — the framework does NOT
 * run a sweep timer for this backend; expired entries vanish from the
 * key space without app-side intervention.
 *
 * Sliding TTL: bumps the entry's expiry to `now + defaultTtlMs` on every
 * read when the cache was created with `slidingTtl: true` and the cache
 * has a finite defaultTtlMs. Same shape as the cluster backend.
 *
 * Concurrency: Redis is single-threaded for command execution; our get
 * + set + tag updates are sequential, not pipelined inside a MULTI, so
 * a worst-case interleaving might leave a tag set with a key that no
 * longer exists. The reverse `keyTags` set + `del()` cleanup means the
 * stale entry is reaped on the next `invalidateTag` (the SET membership
 * is filtered against actual key existence — see invalidateTag below).
 */

var C = require("./constants");
var { boot } = require("./log");
var redisClient = require("./redis-client");
var safeJson = require("./safe-json");
var { CacheError } = require("./framework-error");

var log = boot("cache-redis");

var _err = CacheError.factory;

function _toStr(v) {
  if (v === null || v === undefined) return null;
  return Buffer.isBuffer(v) ? v.toString("utf8") : String(v);
}

function create(cfg) {
  cfg = cfg || {};
  if (typeof cfg.url !== "string" || cfg.url.length === 0) {
    throw _err("BAD_OPT", "cache-redis: opts.url is required (e.g. redis://localhost:6379/0)");
  }
  var namespace      = cfg.namespace;
  var clock          = cfg.clock || function () { return Date.now(); };
  var emitObs        = cfg.emitObs || function () {};
  var slidingTtl     = cfg.slidingTtl;
  var defaultTtlMs   = cfg.defaultTtlMs;

  var client = redisClient.create(redisClient.pickClientOpts(cfg));

  // Lazy connect — defer until first op so cache.create stays sync-safe.
  var connectPromise = null;
  function _ensureConnected() {
    if (client.isOpen()) return Promise.resolve();
    if (!connectPromise) connectPromise = client.connect();
    return connectPromise;
  }

  function _key(k)         { return namespace + ":e:" + k; }
  function _tagKey(t)      { return namespace + ":t:" + t; }
  function _keyTagsKey(k)  { return namespace + ":k:" + k + ":tags"; }

  async function get(key) {
    await _ensureConnected();
    var v = await client.command("GET", _key(key));
    var s = _toStr(v);
    if (s === null) return undefined;
    var parsed;
    try { parsed = safeJson.parse(s, { maxBytes: C.BYTES.mib(64) }); }
    catch (_e) { return undefined; }
    // Sliding TTL: extend the entry's life on every read. Best-effort
    // (PEXPIREAT may race with delete; if it fails the operator just
    // sees the original TTL play out).
    if (slidingTtl && typeof defaultTtlMs === "number" && isFinite(defaultTtlMs) && defaultTtlMs > 0) {
      var newExp = clock() + defaultTtlMs;
      client.command("PEXPIREAT", _key(key), String(Math.floor(newExp)))
        .catch(function () { /* best-effort */ });
      client.command("PEXPIREAT", _keyTagsKey(key), String(Math.floor(newExp)))
        .catch(function () { /* best-effort */ });
    }
    return parsed;
  }

  async function set(key, value, expiresAt, meta) {
    await _ensureConnected();
    var json = safeJson.stringify(value);

    // Drop any prior tag membership for this key (tags may have changed
    // across sets). The reverse-tag set tells us which tag SETs need
    // pruning without scanning every tag in the namespace.
    var oldTagsRv = await client.command("SMEMBERS", _keyTagsKey(key));
    var oldTags = (oldTagsRv || []).map(_toStr).filter(Boolean);
    for (var ot = 0; ot < oldTags.length; ot++) {
      try { await client.command("SREM", _tagKey(oldTags[ot]), key); }
      catch (_e) { /* best-effort */ }
    }
    if (oldTags.length > 0) {
      try { await client.command("DEL", _keyTagsKey(key)); }
      catch (_e) { /* best-effort */ }
    }

    // Write the value with PEXPIREAT for finite TTLs; un-expiring SET
    // for Infinity (operator opted for "cache forever until evicted").
    if (typeof expiresAt === "number" && isFinite(expiresAt)) {
      await client.command("SET", _key(key), json, "PXAT", String(Math.floor(expiresAt)));
    } else {
      await client.command("SET", _key(key), json);
    }

    // Wire the new tags. SADD is idempotent on duplicate tag names.
    var tags = meta && Array.isArray(meta.tags) ? meta.tags : null;
    if (tags && tags.length > 0) {
      for (var t = 0; t < tags.length; t++) {
        await client.command("SADD", _tagKey(tags[t]), key);
        await client.command("SADD", _keyTagsKey(key), tags[t]);
      }
      // Match the entry's lifetime on the keyTags reverse-set so
      // membership doesn't outlive the value.
      if (typeof expiresAt === "number" && isFinite(expiresAt)) {
        try { await client.command("PEXPIREAT", _keyTagsKey(key), String(Math.floor(expiresAt))); }
        catch (_e) { /* best-effort */ }
      }
    }
    emitObs("cache.redis.set", { namespace: namespace });
  }

  async function del(key) {
    await _ensureConnected();
    var oldTagsRv = await client.command("SMEMBERS", _keyTagsKey(key));
    var oldTags = (oldTagsRv || []).map(_toStr).filter(Boolean);
    for (var i = 0; i < oldTags.length; i++) {
      try { await client.command("SREM", _tagKey(oldTags[i]), key); }
      catch (_e) { /* best-effort */ }
    }
    var dels = await Promise.all([
      client.command("DEL", _key(key)),
      client.command("DEL", _keyTagsKey(key)),
    ]);
    return Number(dels[0]) === 1;
  }

  async function has(key) {
    await _ensureConnected();
    var rv = await client.command("EXISTS", _key(key));
    return Number(rv) === 1;
  }

  async function clear() {
    await _ensureConnected();
    // SCAN-and-DEL every key under this namespace. Using SCAN avoids
    // KEYS' O(N) blocking pass and lets a busy Redis serve other
    // commands between cursor batches.
    var cursor = "0";
    do {
      var rv = await client.command("SCAN", cursor, "MATCH", namespace + ":*", "COUNT", "200");
      cursor = _toStr(rv[0]) || "0";
      var keys = (rv[1] || []).map(_toStr).filter(Boolean);
      if (keys.length > 0) {
        await client.command.apply(client, ["DEL"].concat(keys));
      }
    } while (cursor !== "0");
  }

  async function size() {
    await _ensureConnected();
    var cursor = "0";
    var n = 0;
    do {
      var rv = await client.command("SCAN", cursor, "MATCH", namespace + ":e:*", "COUNT", "200");
      cursor = _toStr(rv[0]) || "0";
      n += (rv[1] || []).length;
    } while (cursor !== "0");
    return n;
  }

  function bytes() {
    // Per-entry byte accounting on Redis would mean a MEMORY USAGE call
    // per key, which is operator-expensive and Redis-version-dependent.
    // Operators wanting this use the memory backend or run their own
    // monitoring against MEMORY STATS at the cluster level.
    return Promise.resolve(0);
  }

  async function invalidateTag(tag) {
    await _ensureConnected();
    var rv = await client.command("SMEMBERS", _tagKey(tag));
    var keys = (rv || []).map(_toStr).filter(Boolean);
    var dropped = 0;
    for (var i = 0; i < keys.length; i++) {
      // Filter out stale tag-membership entries (key already expired
      // from PEXPIREAT but lingered in the tag SET) by checking
      // EXISTS before del. Saves an unnecessary DEL round-trip on
      // ghost keys.
      var existsRv = await client.command("EXISTS", _key(keys[i]));
      if (Number(existsRv) === 1) {
        await del(keys[i]);
        dropped += 1;
      } else {
        // Ghost — just SREM from this tag set + drop the reverse.
        try { await client.command("SREM", _tagKey(tag), keys[i]); }
        catch (e) { log.debug("invalidateTag-cleanup-failed", { op: "SREM", tag: tag, error: e.message }); }
      }
    }
    // Drop the tag set itself if it's now empty (or empty after the
    // ghost cleanup above).
    var remaining = await client.command("SCARD", _tagKey(tag));
    if (Number(remaining) === 0) {
      try { await client.command("DEL", _tagKey(tag)); }
      catch (e) { log.debug("invalidateTag-cleanup-failed", { op: "DEL", tag: tag, error: e.message }); }
    }
    emitObs("cache.redis.invalidateTag", { namespace: namespace, tag: tag, dropped: dropped });
    return dropped;
  }

  async function getTags(key) {
    await _ensureConnected();
    var rv = await client.command("SMEMBERS", _keyTagsKey(key));
    return (rv || []).map(_toStr).filter(Boolean);
  }

  async function close() {
    try { await client.close(); }
    catch (_e) { /* best-effort */ }
  }

  return {
    name:           "redis",
    get:            get,
    set:            set,
    del:            del,
    has:            has,
    clear:          clear,
    size:           size,
    bytes:          bytes,
    invalidateTag:  invalidateTag,
    getTags:        getTags,
    close:          close,
    // Redis enforces TTL itself; the framework's sweeper is a no-op here.
    _startSweep:    function () {},
  };
}

module.exports = { create: create };
