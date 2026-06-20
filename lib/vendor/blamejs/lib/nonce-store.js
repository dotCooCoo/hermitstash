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
 *   await store.release(nonce) → boolean
 *     Un-claims a single nonce so a later checkAndInsert of the same value
 *     succeeds again — the rollback half of reserve -> commit -> rollback.
 *     A handler that claims an event id the moment a signature verifies (to
 *     win the race against a concurrent duplicate) MUST release it when
 *     downstream processing fails, otherwise the provider's at-least-once
 *     redelivery is reported as a replay and the event is dropped. Returns
 *     whether a live claim existed. Pair with checkAndInsert; without it an
 *     eager claim inverts the at-least-once contract on any failure.
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
 *   { checkAndInsert, release?, purgeExpired?, close? } — operator-supplied
 *     custom backend (Redis SETNX, Memcached add, etc.). release() is
 *     optional but required to use reserve -> rollback; a backend omitting
 *     it throws NONCE_BACKEND_NO_RELEASE the first time release() is called
 *     (a loud gap, never a silent dropped rollback). Use this
 *     for cross-process accuracy without a per-request SQL hop.
 *
 * Sweep cadence: memory backend sweeps every opts.sweepIntervalMs
 * (default 5 minutes). Cluster backend's purgeExpired is invoked by
 * the api-encrypt middleware on a rate-limited schedule.
 */

var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var frameworkSchema = require("./framework-schema");
var safeAsync = require("./safe-async");
var sql = require("./sql");
var { defineClass } = require("./framework-error");
var { boundedMap } = require("./bounded-map");

// Cluster-backend table — resolved through frameworkSchema.tableName so a
// configured table prefix (b.frameworkSchema.setTablePrefix) is honored.
// The name is identity-mapped in LOCAL_TO_EXTERNAL, so clusterStorage's
// resolveTables leaves it untouched at dispatch and the resolved name is
// what reaches the backend on both sides.
var NONCE_TABLE = "_blamejs_api_encrypt_nonces";   // allow:hand-rolled-sql — canonical logical table-name declaration

// b.sql opts for every cluster-backend statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting and dialect
// idioms (ON CONFLICT vs ON DUPLICATE KEY) match the backend the SQL
// dispatches to. Defaulting to "sqlite" works on Postgres only by accident
// (both double-quote identifiers) and emits invalid quoting + ON CONFLICT on
// MySQL. clusterStorage.execute still rewrites table names + translates `?`
// placeholders at dispatch; this controls only the builder-side quoting +
// idiom selection.
function _nonceSqlOpts() { return { dialect: clusterStorage.dialect() }; }

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

  // Un-claim a nonce so a future checkAndInsert of the same value succeeds
  // again — the rollback half of reserve -> commit -> rollback. A handler
  // that claims an event id the moment a signature verifies (to win the race
  // against a concurrent duplicate) MUST release it when downstream processing
  // fails, otherwise the provider's at-least-once redelivery is reported as a
  // replay and the event is dropped. Returns whether a live claim existed.
  function release(nonce) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      return Promise.reject(_err("INVALID_NONCE", "nonce must be a non-empty string"));
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
      throw _err("INVALID_NONCE", "nonce must be a non-empty string");
    }
    // Un-claim a single nonce (the reserve -> rollback half). The middleware
    // hashes the raw nonce before it reaches here, so we delete by hash.
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
      // A custom backend that omits release() cannot participate in
      // reserve -> rollback. Fail LOUDLY (not a silent no-op) so the gap
      // surfaces the first time a handler tries to un-claim, rather than
      // silently dropping the rollback and inverting the at-least-once contract.
      release:      function () {
        return Promise.reject(_err("BACKEND_NO_RELEASE",
          "this custom nonce backend does not implement release(nonce); " +
          "the reserve -> commit -> rollback pattern requires it"));
      },
      close:        function () {},
    }, backend);
  }
  if (backend === "cluster") return _clusterBackend(opts);
  if (!backend || backend === "memory") return _memoryBackend(opts);
  throw _err("UNKNOWN_BACKEND",
    "nonce-store: unknown backend '" + backend +
    "' (must be 'memory', 'cluster', or { checkAndInsert, release?, purgeExpired?, close? })");
}

// enforceReplay(store, jti, expireAtMs, opts) — single-use enforcement
// against a replay store: `await store.checkAndInsert(jti, expireAtMs)`,
// raising opts.errorClass(opts.storeFailedCode, …) if the store itself
// fails (a store outage must NOT be mistaken for a clean token) and
// opts.errorClass(opts.replayCode, "<opts.tokenLabel> jti='<jti>' has
// been seen before — replay refused") if the jti was already seen. The
// fail-closed anti-replay control flow every JWT / DPoP verifier repeated
// identically — centralised here so the contract lives in one place.
// Verifiers with a divergent message or store contract (e.g. an atomic
// back-channel-logout-token store) keep their own inline check.
async function enforceReplay(store, jti, expireAtMs, opts) {
  opts = opts || {};
  var inserted;
  try {
    inserted = await store.checkAndInsert(jti, expireAtMs);
  } catch (e) {
    throw new opts.errorClass(opts.storeFailedCode,
      "replayStore.checkAndInsert threw: " + ((e && e.message) || String(e)));
  }
  if (inserted === false) {
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
