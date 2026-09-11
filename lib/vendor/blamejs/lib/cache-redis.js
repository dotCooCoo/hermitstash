// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
    throw _err("cache-redis/bad-opt", "cache-redis: opts.url is required (e.g. redis://localhost:6379/0)");
  }
  var namespace      = cfg.namespace;
  var clock          = cfg.clock || function () { return Date.now(); };
  var emitObs        = cfg.emitObs || function () {};
  var slidingTtl     = cfg.slidingTtl;
  var defaultTtlMs   = cfg.defaultTtlMs;

  var client = redisClient.create(redisClient.pickClientOpts(cfg));

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

    if (typeof expiresAt === "number" && isFinite(expiresAt)) {
      await client.command("SET", _key(key), json, "PXAT", String(Math.floor(expiresAt)));
    } else {
      await client.command("SET", _key(key), json);
    }

    var tags = meta && Array.isArray(meta.tags) ? meta.tags : null;
    if (tags && tags.length > 0) {
      for (var t = 0; t < tags.length; t++) {
        await client.command("SADD", _tagKey(tags[t]), key);
        await client.command("SADD", _keyTagsKey(key), tags[t]);
      }
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
    return Promise.resolve(0);
  }

  async function invalidateTag(tag) {
    await _ensureConnected();
    var rv = await client.command("SMEMBERS", _tagKey(tag));
    var keys = (rv || []).map(_toStr).filter(Boolean);
    var dropped = 0;
    for (var i = 0; i < keys.length; i++) {
      var existsRv = await client.command("EXISTS", _key(keys[i]));
      if (Number(existsRv) === 1) {
        await del(keys[i]);
        dropped += 1;
      } else {
        try { await client.command("SREM", _tagKey(tag), keys[i]); }
        catch (e) { log.debug("invalidateTag-cleanup-failed", { op: "SREM", tag: tag, error: e.message }); }
      }
    }
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
    _startSweep:    function () {},
  };
}

module.exports = { create: create };
