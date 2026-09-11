// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var frameworkSchema = require("./framework-schema");
var safeAsync = require("./safe-async");
var sql = require("./sql");
var { defineClass } = require("./framework-error");
var { boundedMap } = require("./bounded-map");

var NONCE_TABLE = "_blamejs_api_encrypt_nonces";   // allow:hand-rolled-sql — canonical logical table-name declaration

function _nonceSqlOpts() { return { dialect: clusterStorage.dialect() }; }

var NonceStoreError = defineClass("NonceStoreError");

var DEFAULT_SWEEP_INTERVAL_MS = C.TIME.minutes(5);
var DEFAULT_MAX_ENTRIES = 1000000;

function _err(code, message) {
  return new NonceStoreError(code, message, true);
}

function _memoryBackend(opts) {
  var sweepIntervalMs = opts.sweepIntervalMs || DEFAULT_SWEEP_INTERVAL_MS;
  var maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES;
  var seen = boundedMap({ maxEntries: maxEntries, policy: "reject" });
  var capacityRejects = 0;

  function _purgeExpiredSync() {
    var now = Date.now();
    var removed = 0;
    for (var entry of seen) {
      if (entry[1] <= now) { seen.delete(entry[0]); removed++; }
    }
    return removed;
  }

  var sweepTimer = safeAsync.repeating(_purgeExpiredSync, sweepIntervalMs, { name: "nonce-sweep" });

  function checkAndInsert(nonce, expireAt) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      return Promise.reject(_err("nonce-store/invalid-nonce", "nonce must be a non-empty string"));
    }
    if (typeof expireAt !== "number" || !Number.isFinite(expireAt)) {
      return Promise.reject(_err("nonce-store/invalid-expire", "expireAt must be a finite number (unix ms)"));
    }
    var existing = seen.get(nonce);
    if (existing !== undefined && existing > Date.now()) {
      return Promise.resolve(false);
    }
    var stored = seen.set(nonce, expireAt);
    if (!stored) {
      _purgeExpiredSync();
      stored = seen.set(nonce, expireAt);
    }
    if (!stored) {
      capacityRejects += 1;
      return Promise.resolve(false);
    }
    return Promise.resolve(true);
  }

  function release(nonce) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      return Promise.reject(_err("nonce-store/invalid-nonce", "nonce must be a non-empty string"));
    }
    var existed = seen.get(nonce) !== undefined;
    if (existed) seen.delete(nonce);
    return Promise.resolve(existed);
  }

  function purgeExpired() {
    return Promise.resolve(_purgeExpiredSync());
  }

  function close() {
    if (sweepTimer) { sweepTimer.stop(); sweepTimer = null; }
    seen.clear();
  }

  return {
    name:            "memory",
    checkAndInsert:  checkAndInsert,
    release:         release,
    purgeExpired:    purgeExpired,
    close:           close,
    _size:           function () { return seen.size; },
    _capacityRejects: function () { return capacityRejects; },
  };
}

function _clusterBackend(_opts) {
  async function checkAndInsert(nonce, expireAt) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      throw _err("nonce-store/invalid-nonce", "nonce must be a non-empty string");
    }
    if (typeof expireAt !== "number" || !Number.isFinite(expireAt)) {
      throw _err("nonce-store/invalid-expire", "expireAt must be a finite number (unix ms)");
    }
    var built = sql.upsert(frameworkSchema.tableName(NONCE_TABLE), _nonceSqlOpts())
      .columns(["nonceHash", "expireAt"])
      .values({ nonceHash: nonce, expireAt: expireAt })
      .onConflict(["nonceHash"])
      .doNothing()
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    return (result && result.rowCount > 0);
  }

  async function release(nonce) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      throw _err("nonce-store/invalid-nonce", "nonce must be a non-empty string");
    }
    var built = sql.delete(frameworkSchema.tableName(NONCE_TABLE), _nonceSqlOpts())
      .where("nonceHash", "=", nonce)
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    return (result && result.rowCount > 0);
  }

  async function purgeExpired() {
    var built = sql.delete(frameworkSchema.tableName(NONCE_TABLE), _nonceSqlOpts())
      .where("expireAt", "<=", Date.now())
      .toSql();
    var result = await clusterStorage.execute(built.sql, built.params);
    return (result && result.rowCount) || 0;
  }

  function close() { /* no resources held */ }

  return {
    name:           "cluster",
    checkAndInsert: checkAndInsert,
    release:        release,
    purgeExpired:   purgeExpired,
    close:          close,
  };
}

function create(opts) {
  opts = opts || {};
  var backend = opts.backend;
  if (backend && typeof backend === "object" && typeof backend.checkAndInsert === "function") {
    return Object.assign({
      name:         "custom",
      purgeExpired: function () { return Promise.resolve(0); },
      release:      function () {
        return Promise.reject(_err("nonce-store/backend-no-release",
          "this custom nonce backend does not implement release(nonce); " +
          "the reserve -> commit -> rollback pattern requires it"));
      },
      close:        function () {},
    }, backend);
  }
  if (backend === "cluster") return _clusterBackend(opts);
  if (!backend || backend === "memory") return _memoryBackend(opts);
  throw _err("nonce-store/unknown-backend",
    "nonce-store: unknown backend '" + backend +
    "' (must be 'memory', 'cluster', or { checkAndInsert, release?, purgeExpired?, close? })");
}

async function enforceReplay(store, jti, expireAtMs, opts) {
  opts = opts || {};
  var inserted;
  try {
    inserted = await store.checkAndInsert(jti, expireAtMs);
  } catch (e) {
    throw new opts.errorClass(opts.storeFailedCode,
      "replayStore.checkAndInsert threw: " + ((e && e.message) || String(e)));
  }
  if (!inserted) {
    throw new opts.errorClass(opts.replayCode,
      opts.tokenLabel + " jti='" + jti + "' has been seen before — replay refused");
  }
}

module.exports = {
  create:           create,
  enforceReplay:    enforceReplay,
  NonceStoreError:  NonceStoreError,
  _memoryBackend:   _memoryBackend,
  _clusterBackend:  _clusterBackend,
};
