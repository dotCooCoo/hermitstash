"use strict";
/**
 * nonce-store — pluggable replay-protection store.
 *
 * The api-encrypt middleware and any other surface that needs
 * "first-time-only" semantics for a request-supplied nonce uses this
 * primitive. The store is shaped around two operations:
 *
 *   await store.checkAndInsert(nonce, expireAt) → boolean
 *     Returns true if the nonce was unseen (and is now recorded);
 *     returns false if it was already present (= replay attempt).
 *     The check + insert MUST be atomic — checking first and
 *     inserting second would race on concurrent requests carrying
 *     the same nonce.
 *
 *   await store.purgeExpired() → number
 *     Removes entries past their expireAt. Called periodically by the
 *     middleware that uses the store. Returns the count purged.
 *
 *   store.close()
 *     Releases any timer / pool resources. Memory backend stops its
 *     periodic sweep; cluster backend is a no-op (table prune is
 *     called explicitly).
 *
 * Backends:
 *
 *   'memory' (default) — Map-backed; periodic sweep evicts expired
 *     entries. Single-process accuracy only — a request hitting
 *     node A and a replay hitting node B will NOT be caught.
 *
 *   'cluster' — INSERT...ON CONFLICT DO NOTHING into the framework
 *     table _blamejs_api_encrypt_nonces. The PRIMARY KEY race is what
 *     makes the check + insert atomic across nodes.
 *
 *   { checkAndInsert, purgeExpired, close } — operator-supplied
 *     custom backend (Redis SETNX, Memcached add, etc.). Use this
 *     for cross-process accuracy without a per-request SQL hop.
 *
 * Sweep cadence: memory backend sweeps every opts.sweepIntervalMs
 * (default 5 minutes). Cluster backend's purgeExpired is invoked by
 * the api-encrypt middleware on a rate-limited schedule.
 */

var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");
var { boundedMap } = require("./bounded-map");

var NonceStoreError = defineClass("NonceStoreError");

var DEFAULT_SWEEP_INTERVAL_MS = C.TIME.minutes(5);
// Memory-backend ceiling. Each request carries an attacker-choosable unique
// nonce, so between sweeps the store would otherwise grow without bound (a
// memory-amplification DoS). Capped — but a replay-protection store must
// NOT evict a live nonce to admit a new one (that reopens a replay window
// for the evicted nonce), so the cap uses the "reject" policy and the
// backend fails CLOSED at capacity (see checkAndInsert).
var DEFAULT_MAX_ENTRIES = 1000000;

function _err(code, message) {
  return new NonceStoreError(code, message, true);
}

// ---- Memory backend ----

function _memoryBackend(opts) {
  var sweepIntervalMs = opts.sweepIntervalMs || DEFAULT_SWEEP_INTERVAL_MS;
  var maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES;
  // policy "reject" — never evict a live nonce (that would reopen a replay
  // window for the dropped one). At capacity the backend fails closed.
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
      return Promise.reject(_err("INVALID_NONCE", "nonce must be a non-empty string"));
    }
    if (typeof expireAt !== "number" || !Number.isFinite(expireAt)) {
      return Promise.reject(_err("INVALID_EXPIRE", "expireAt must be a finite number (unix ms)"));
    }
    var existing = seen.get(nonce);
    if (existing !== undefined && existing > Date.now()) {
      return Promise.resolve(false);   // replay
    }
    var stored = seen.set(nonce, expireAt);
    if (!stored) {
      // At capacity. Reclaim expired entries inline, then retry once.
      _purgeExpiredSync();
      stored = seen.set(nonce, expireAt);
    }
    if (!stored) {
      // Still full of LIVE nonces — a genuine flood. FAIL CLOSED: we
      // cannot record this nonce, so we cannot prove it is first-seen.
      // Refuse it (report as "seen") rather than admit an unprotected
      // request. Evicting a live nonce to make room would reopen a replay
      // window, so we never evict — the request is rejected instead.
      capacityRejects += 1;
      return Promise.resolve(false);
    }
    return Promise.resolve(true);
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
    purgeExpired:    purgeExpired,
    close:           close,
    // Test hooks — underlying entry count + count of capacity fail-closed
    // rejections (a nonce flood that hit the ceiling).
    _size:           function () { return seen.size; },
    _capacityRejects: function () { return capacityRejects; },
  };
}

// ---- Cluster backend ----

function _clusterBackend(_opts) {
  async function checkAndInsert(nonce, expireAt) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      throw _err("INVALID_NONCE", "nonce must be a non-empty string");
    }
    if (typeof expireAt !== "number" || !Number.isFinite(expireAt)) {
      throw _err("INVALID_EXPIRE", "expireAt must be a finite number (unix ms)");
    }
    // INSERT ... ON CONFLICT DO NOTHING is the atomic primitive.
    // rowCount === 1 → won (first sighting); rowCount === 0 → lost
    // (someone else already inserted the same nonce, i.e. replay).
    // The middleware hashes the raw nonce before passing it here so
    // the table only ever sees hashes, not the originals.
    var result = await clusterStorage.execute(
      "INSERT INTO _blamejs_api_encrypt_nonces (nonceHash, expireAt) " +
      "VALUES (?, ?) ON CONFLICT (nonceHash) DO NOTHING",
      [nonce, expireAt]
    );
    return (result && result.rowCount > 0);
  }

  async function purgeExpired() {
    var result = await clusterStorage.execute(
      "DELETE FROM _blamejs_api_encrypt_nonces WHERE expireAt <= ?",
      [Date.now()]
    );
    return (result && result.rowCount) || 0;
  }

  function close() { /* no resources held */ }

  return {
    name:           "cluster",
    checkAndInsert: checkAndInsert,
    purgeExpired:   purgeExpired,
    close:          close,
  };
}

// ---- Resolution ----

function create(opts) {
  opts = opts || {};
  var backend = opts.backend;
  if (backend && typeof backend === "object" && typeof backend.checkAndInsert === "function") {
    // Operator-supplied custom backend (Redis, Memcached, etc.). Fill
    // in any missing optional methods so the rest of the framework
    // can call them unconditionally.
    return Object.assign({
      name:         "custom",
      purgeExpired: function () { return Promise.resolve(0); },
      close:        function () {},
    }, backend);
  }
  if (backend === "cluster") return _clusterBackend(opts);
  if (!backend || backend === "memory") return _memoryBackend(opts);
  throw _err("UNKNOWN_BACKEND",
    "nonce-store: unknown backend '" + backend +
    "' (must be 'memory', 'cluster', or { checkAndInsert, purgeExpired, close })");
}

module.exports = {
  create:           create,
  NonceStoreError:  NonceStoreError,
  _memoryBackend:   _memoryBackend,
  _clusterBackend:  _clusterBackend,
};
