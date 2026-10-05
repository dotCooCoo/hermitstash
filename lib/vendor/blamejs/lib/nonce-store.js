// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.nonceStore
 * @nav    Identity
 * @title  Nonce Store
 * @slug   nonce-store
 *
 * @intro
 *   The record of which one-time values have already been spent. A nonce
 *   proves a request is not a replay only if something remembers that it
 *   was used, and remembers it for as long as the value stays valid.
 *
 *   A store answers one question: is this the first time this value has
 *   been seen? The answer has to be atomic, because two copies of the same
 *   replayed request arriving together must not both be told "first time".
 *   The memory backend holds the record in one process; the cluster backend
 *   holds it in the shared database, which is what a deployment behind more
 *   than one node needs.
 *
 * @card
 *   Remember which one-time values have been spent, so a replayed request
 *   is refused. Atomic check-and-insert, in this process or across the
 *   cluster, with expiry sweeping.
 */

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

/**
 * @primitive b.nonceStore.create
 * @signature b.nonceStore.create(opts?)
 * @since     0.2.8
 * @status    stable
 * @compliance soc2, pci-dss
 * @related   b.nonceStore.enforceReplay, b.cluster.init
 *
 * Open a store and answer the handle to spend nonces against. The handle
 * carries `checkAndInsert(nonce, expireAtMs)`, which answers true the first
 * time a value is seen and false every time after; `release(nonce)`, which
 * gives a reserved value back so a request that failed downstream can be
 * retried; `purgeExpired()`; and `close()`.
 *
 * `"memory"` keeps the record in this process, which is right for a single
 * node and wrong for several, since each would answer "first time" for the
 * same replay. `"cluster"` keeps it in the shared database. An object
 * carrying `checkAndInsert` is used as given, and one that carries no
 * `release` refuses that call rather than pretending the value came back.
 *
 * @opts
 *   backend:         string|object,  // "memory" (default), "cluster", or { checkAndInsert, release?, purgeExpired?, close? }
 *   sweepIntervalMs: number,         // expiry sweep interval; default 300000
 *   maxEntries:      number,         // memory backend ceiling; default 1000000, refuses past it
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.nonceStore.create({ backend: "memory" });
 *   var expiry = Date.now() + b.constants.TIME.minutes(5);
 *   await store.checkAndInsert("nonce-1", expiry);   // → true
 *   await store.checkAndInsert("nonce-1", expiry);   // → false
 */
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

/**
 * @primitive b.nonceStore.enforceReplay
 * @signature b.nonceStore.enforceReplay(store, jti, expireAtMs, opts)
 * @since     0.15.13
 * @status    stable
 * @compliance soc2, pci-dss
 * @related   b.nonceStore.create
 *
 * Spend a token's `jti` against a store and throw when it has been spent
 * already. A token verifier calls this after its signature check, so a
 * captured token cannot be presented twice.
 *
 * A store that throws is not treated as a store that answered no: the
 * failure raises `storeFailedCode`, distinct from the `replayCode` a real
 * replay raises, so an operator can tell a broken backend from an attack
 * instead of reading one as the other. Both are errors, so neither
 * outcome lets the token through.
 *
 * @opts
 *   errorClass:      FrameworkError,  // class to construct; required
 *   replayCode:      string,          // code for a value already spent
 *   storeFailedCode: string,          // code for a store that threw
 *   tokenLabel:      string,          // what the message calls the token
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.nonceStore.create();
 *   await b.nonceStore.enforceReplay(store, proof.jti, proof.exp * 1000, {
 *     errorClass:      b.frameworkError.AuthError,
 *     replayCode:      "auth-dpop/replay",
 *     storeFailedCode: "auth-dpop/replay-store-failed",
 *     tokenLabel:      "DPoP proof",
 *   });
 */
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
