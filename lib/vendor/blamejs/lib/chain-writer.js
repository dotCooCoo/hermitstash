// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.chainWriter
 * @nav    Observability
 * @title  Chain Writer
 *
 * @intro
 *   Race-safe append to a hash-chained log table. Both `audit_log` and
 *   `consent_log` share the same row shape — take next monotonic
 *   counter, read previous row's `rowHash`, seal the logical row via
 *   field-crypto, materialize null entries for every hashable column
 *   so canonicalization sees the same key set at write-time and
 *   verify-time, compute `rowHash` over the sealed content, INSERT
 *   with `prevHash` / `rowHash` / `nonce` / `fencingToken`.
 *
 *   The chain-writer extracts that pattern so every consumer gets the
 *   same race protection. Each instance owns a per-chain Mutex
 *   serializing read-prev → compute-hash → insert (without it,
 *   concurrent appends hash against the same prev-tip and fork the
 *   chain), plus a Once initializing the in-process counter from
 *   `MAX(monotonicCounter)` on first use.
 *
 *   Writes route through the cluster-storage dispatcher so the same
 *   chain definition works on single-node SQLite and on cluster-mode
 *   external Postgres. `cluster.requireLeader()` runs before the
 *   mutex; followers reject with `NotLeaderError`. Table names are
 *   restricted to the `ALLOWED_CHAIN_TABLES` allowlist so a misconfig
 *   can't point a writer at a non-chain table and corrupt the chain
 *   semantics.
 *
 *   Operators usually don't construct chain-writers directly — `b.audit`
 *   and `b.consent` each construct one at module load. Direct use is
 *   for new chain-backed tables registered in `ALLOWED_CHAIN_TABLES`.
 *
 * @card
 *   Race-safe append to a hash-chained log table.
 */

var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var cryptoField = require("./crypto-field");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var C = require("./constants");
var boundedMap = require("./bounded-map");
var numericBounds = require("./numeric-bounds");
var time = require("./time");
var { FrameworkError } = require("./framework-error");

var ALLOWED_CHAIN_TABLES = new Set(["audit_log", "consent_log"]);
var ORIGIN_HASH_HEX_LEN = C.BYTES.bytes(64) * 2;

var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

class ChainWriterError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "ChainWriterError";
    this.code = code || "chain-writer/invalid";
    this.isChainWriterError = true;
  }
}

/**
 * @primitive b.chainWriter.registerTable
 * @signature b.chainWriter.registerTable(table)
 * @since     0.15.13
 * @status    stable
 * @related   b.chainWriter.create, b.safeSql.validateIdentifier
 *
 * Register a consumer-owned append-only table as chain-writable so
 * `b.chainWriter.create({ table })` accepts it. Call once at boot (config
 * time) for each app table carrying the chain columns (`monotonicCounter`,
 * `recordedAt`, `nonce`, `prevHash`, `rowHash` — plus `fencingToken` in
 * cluster mode). The framework chains (`audit_log`, `consent_log`) are
 * pre-registered. Throws `ChainWriterError` (`chain-writer/invalid-config`) on
 * a non-identifier name; the name is validated against the SQL identifier
 * rules because it is interpolated into the chain SQL. Idempotent. Returns the
 * registered name.
 *
 * Operator footgun to avoid on a MULTI-chain table (one configured with a
 * `chainKey`): the per-key writer restarts `monotonicCounter` at 1 for each
 * key, so a UNIQUE index on `monotonicCounter` ALONE (the shape the framework
 * `audit_log` uses for its single chain) will reject the second key's first
 * row. A keyed chain's uniqueness must be the composite
 * `(chainKey, monotonicCounter)`, never `monotonicCounter` by itself.
 *
 * @example
 *   b.chainWriter.registerTable("device_event_log");
 *   var writer = b.chainWriter.create({
 *     table:            "device_event_log",
 *     chainKey:         "deviceId",
 *     columnsForInsert: ["_id", "deviceId", "monotonicCounter", "recordedAt",
 *                        "kind", "payload",
 *                        "prevHash", "rowHash", "nonce", "fencingToken"],
 *     hashableColumns:  ["_id", "deviceId", "monotonicCounter", "recordedAt",
 *                        "kind", "payload"],
 *   });
 */
function registerTable(table) {
  if (typeof table !== "string" || table.length === 0) {
    throw new ChainWriterError(
      "registerTable requires a non-empty table name",
      "chain-writer/invalid-config"
    );
  }
  safeSql.validateIdentifier(table);
  ALLOWED_CHAIN_TABLES.add(table);
  return table;
}

/**
 * @primitive b.chainWriter.create
 * @signature b.chainWriter.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.audit, b.consent, b.auditChain, b.chainWriter.registerTable
 *
 * Build a chain-writer bound to a single hash-chained table. Returns
 * `{ table, chainKey, append, _resetForTest, _getMutexForTest }`.
 * `append(logical)` is the public surface — async, leader-gated,
 * mutex-serialized; on success it returns the logical row decorated with the
 * computed `rowHash` and `prevHash`.
 *
 * A `chainKey` makes one table hold many independent chains (one per account /
 * device / tenant): tip-read, counter monotonicity, and the append Mutex all
 * scope per key, so concurrent appends to DIFFERENT keys run in parallel while
 * same-key appends serialize. Bind `chainKey` into `hashableColumns` so the
 * partition is tamper-evident in the row hash, and key the table's uniqueness
 * constraint on `(chainKey, monotonicCounter)`, never `monotonicCounter` alone.
 *
 * @opts
 *   table:            string,    // a registered chain table (audit_log | consent_log | registerTable name)
 *   chainKey:         string,    // optional partition column — one independent chain per key value
 *   columnsForInsert: string[],  // INSERT column order (every name is identifier-validated)
 *   hashableColumns:  string[],  // columns that participate in the rowHash canonicalization
 *   validateInput:    Function,  // optional; (logical) -> throws on invalid shape
 *
 * @example
 *   var writer = b.chainWriter.create({
 *     table:            "audit_log",
 *     columnsForInsert: ["_id", "monotonicCounter", "recordedAt",
 *                        "action", "outcome",
 *                        "prevHash", "rowHash", "nonce", "fencingToken"],
 *     hashableColumns:  ["_id", "monotonicCounter", "recordedAt",
 *                        "action", "outcome"],
 *   });
 *
 *   var row = await writer.append({
 *     action:  "user.login",
 *     outcome: "success",
 *   });
 *   row.rowHash;     // → "<hex sha3-512 digest>"
 *   row.prevHash;    // → "<previous tip rowHash, or zero-hash on first row>"
 */
function create(opts) {
  if (!opts || !opts.table || !Array.isArray(opts.columnsForInsert) ||
      !Array.isArray(opts.hashableColumns)) {
    throw new ChainWriterError(
      "create requires { table, columnsForInsert, hashableColumns }",
      "chain-writer/invalid-config"
    );
  }
  safeSql.validateIdentifier(opts.table);
  safeSql.assertOneOf(opts.table, ALLOWED_CHAIN_TABLES);

  for (var i = 0; i < opts.columnsForInsert.length; i++) {
    safeSql.validateIdentifier(opts.columnsForInsert[i]);
  }
  for (var j = 0; j < opts.hashableColumns.length; j++) {
    safeSql.validateIdentifier(opts.hashableColumns[j]);
  }

  var table             = opts.table;
  var columnsForInsert  = opts.columnsForInsert.slice();
  var hashableColumns   = opts.hashableColumns.slice();
  var validateInput     = opts.validateInput || null;
  var resolveOrigin = (opts.resolveOrigin === undefined || opts.resolveOrigin === null)
    ? null : opts.resolveOrigin;
  if (resolveOrigin !== null && typeof resolveOrigin !== "function") {
    throw new ChainWriterError(
      "resolveOrigin must be a function, got " + typeof opts.resolveOrigin +
        " — a value that cannot be called would silently disable origin resolution",
      "chain-writer/invalid-config"
    );
  }

  var chainKey = opts.chainKey || null;
  if (chainKey !== null) {
    safeSql.validateIdentifier(chainKey);
    if (columnsForInsert.indexOf(chainKey) === -1) {
      throw new ChainWriterError(
        "chainKey '" + chainKey + "' must be listed in columnsForInsert so " +
        "every appended row carries its partition key",
        "chain-writer/invalid-config"
      );
    }
  }

  var _SINGLE_CHAIN_KEY = "__single_chain__";
  var _mutexByKey = new Map();
  function _mutexFor(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    return boundedMap.getOrInsert(_mutexByKey, k, function () { return new safeAsync.Mutex(); });
  }

  var _nextCounterByKey = new Map();
  var _counterInitByKey = new Map();
  var _originByKey = new Map();
  var _originStaleByKey = new Map();

  var _clockByKey = new Map();
  function _clockFor(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    return boundedMap.getOrInsert(_clockByKey, k, function () {
      return time.monotonicClock({ label: table + ":" + k });
    });
  }

  var _hasRecordedAt = columnsForInsert.indexOf("recordedAt") !== -1;

  async function _readOrigin(keyValue) {
    var origin = await resolveOrigin(keyValue);
    if (origin == null) return { hash: auditChain.ZERO_HASH, counter: 0 };
    if (typeof origin !== "object") {
      throw new ChainWriterError(
        "resolveOrigin must return { hash, counter } or nothing",
        "chain-writer/bad-origin"
      );
    }
    if (!safeBuffer.isHex(origin.hash, ORIGIN_HASH_HEX_LEN)) {
      throw new ChainWriterError(
        "resolveOrigin returned hash '" + String(origin.hash).slice(0, 32) +
          "', which is not a SHA3-512 hex digest — refusing to append a row " +
          "whose link into the chain cannot be established",
        "chain-writer/bad-origin"
      );
    }
    var counter = Number(origin.counter);
    if (!numericBounds.isIncrementableSafeInt(counter)) {
      throw new ChainWriterError(
        "resolveOrigin returned counter '" + String(origin.counter) +
          "', which is not a whole non-negative number the chain can resume " +
          "above while staying below 2^53",
        "chain-writer/bad-origin"
      );
    }
    return { hash: origin.hash, counter: counter };
  }

  var _ORIGIN_TERM_ATTEMPTS = 3;
  async function _resolveOriginInOneTerm(keyValue) {
    for (var attempt = 0; attempt < _ORIGIN_TERM_ATTEMPTS; attempt += 1) {
      var term = cluster.fencingToken();
      var origin = await _readOrigin(keyValue);
      if (cluster.fencingToken() === term) {
        return { hash: origin.hash, counter: origin.counter, term: term };
      }
    }
    throw new ChainWriterError(
      "leadership changed during every attempt to resolve where " + table +
        " resumes; an origin read across a term change may already be superseded",
      "chain-writer/origin-term-unstable"
    );
  }

  async function _cachedOrigin(k, keyValue) {
    if (_originByKey.has(k)) return _originByKey.get(k);
    var resolved = await _resolveOriginInOneTerm(keyValue);
    boundedMap.getOrInsert(_originByKey, k, function () { return resolved; });
    return _originByKey.get(k);
  }

  function _invalidateOriginIfTermChanged(keyValue) {
    if (!resolveOrigin) return;
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var cached = _originByKey.get(k);
    if (!cached) return;
    if (cached.term === cluster.fencingToken()) return;
    _originByKey.delete(k);
    _originStaleByKey.set(k, true);
  }

  async function _reprimeIfStale(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    if (!_originStaleByKey.get(k)) return;
    _originStaleByKey.delete(k);
    var had = _nextCounterByKey.get(k);
    _counterInitByKey.delete(k);
    _nextCounterByKey.delete(k);
    await _ensureCounterInit(keyValue);
    var derived = _nextCounterByKey.get(k);
    if (had != null && had > derived) _nextCounterByKey.set(k, had);
  }

  function _ensureCounterInit(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var once = boundedMap.getOrInsert(_counterInitByKey, k, function () {
      return new safeAsync.Once(async function () {
        var maxQ = sql.select(table, _sqlOpts()).max("monotonicCounter", "m");
        if (chainKey !== null) maxQ = maxQ.where(chainKey, keyValue);
        var maxBuilt = maxQ.toSql();
        var row = await safeAsync.withTimeout(
          safeAsync.asyncRetry(function () {
            return clusterStorage.executeOne(maxBuilt.sql, maxBuilt.params);
          }),
          FRAMEWORK_SQL_TIMEOUT_MS,
          { name: table + ".readMaxCounter" }
        );
        _nextCounterByKey.set(k, (row && row.m ? Number(row.m) : 0) + 1);
      });
    });
    return once.invoke();
  }

  async function _readChainTipRow(keyValue) {
    var tipQ = sql.select(table, _sqlOpts())
      .columns(_hasRecordedAt ? ["rowHash", "recordedAt"] : ["rowHash"])
      .orderBy("monotonicCounter", "desc")
      .limit(1);
    if (chainKey !== null) tipQ = tipQ.where(chainKey, keyValue);
    var tipBuilt = tipQ.toSql();
    return await safeAsync.withTimeout(
      safeAsync.asyncRetry(function () {
        return clusterStorage.executeOne(tipBuilt.sql, tipBuilt.params);
      }),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: table + ".readChainTip" }
    );
  }

  async function _insertRow(values) {
    var rowObj = {};
    for (var ci = 0; ci < columnsForInsert.length; ci++) {
      rowObj[columnsForInsert[ci]] = values[ci];
    }
    var insBuilt = sql.insert(table, _sqlOpts())
      .columns(columnsForInsert)
      .values(rowObj)
      .toSql();
    return await safeAsync.withTimeout(
      clusterStorage.execute(insBuilt.sql, insBuilt.params),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: table + ".insertRow" }
    );
  }

  async function append(logical) {
    if (validateInput) validateInput(logical);
    cluster.requireLeader();

    var keyValue = _SINGLE_CHAIN_KEY;
    if (chainKey !== null) {
      keyValue = logical ? logical[chainKey] : undefined;
      if (keyValue === undefined || keyValue === null || String(keyValue).length === 0) {
        throw new ChainWriterError(
          "append: a chainKey writer requires logical['" + chainKey + "'] to be a " +
          "non-empty partition value",
          "chain-writer/invalid-input"
        );
      }
    }
    _invalidateOriginIfTermChanged(keyValue);
    await _reprimeIfStale(keyValue);
    await _ensureCounterInit(keyValue);

    return await _mutexFor(keyValue).runExclusive(async function () {
      return await _appendInsideMutex(logical, keyValue);
    });
  }

  async function _appendInsideMutex(logical, keyValue) {
    var _ck = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;

    if (!_nextCounterByKey.has(_ck)) await _ensureCounterInit(keyValue);

    if (resolveOrigin) {
      var floor = (await _cachedOrigin(_ck, keyValue)).counter;
      if (_nextCounterByKey.get(_ck) <= floor) _nextCounterByKey.set(_ck, floor + 1);
    }

    var counter = _nextCounterByKey.get(_ck);
    _nextCounterByKey.set(_ck, counter + 1);
    try {
      return await _buildAndInsert(logical, keyValue, _ck, counter);
    } catch (e) {
      _nextCounterByKey.delete(_ck);
      _counterInitByKey.delete(_ck);
      throw e;
    }
  }

  async function _buildAndInsert(logical, keyValue, _ck, counter) {

    var tipRow = await _readChainTipRow(keyValue);
    var clock = _clockFor(keyValue);
    if (_hasRecordedAt && tipRow && tipRow.recordedAt !== undefined && tipRow.recordedAt !== null) {
      var tipMs = Number(tipRow.recordedAt);
      if (!Number.isSafeInteger(tipMs) || tipMs < 0 || tipMs >= Number.MAX_SAFE_INTEGER) {
        throw new ChainWriterError(
          "append: the chain tip for " + table + " carries an unusable recordedAt (" +
          String(tipRow.recordedAt) + "), so the next row's timestamp cannot be " +
          "ordered against it. The row is corrupt or was written outside the " +
          "framework; verify the chain before appending.",
          "chain-writer/bad-tip-timestamp"
        );
      }
      clock.observeFloor(tipMs);
    }
    var nowMs   = clock.now();
    var nonce   = generateBytes(C.BYTES.bytes(16));

    var fullLogical = Object.assign({}, logical, {
      _id:               (logical && logical._id) || generateToken(C.BYTES.bytes(16)),
      recordedAt:        nowMs,
      monotonicCounter:  counter,
    });

    var sealed = cryptoField.sealRow(table, fullLogical);

    for (var hci = 0; hci < hashableColumns.length; hci++) {
      if (!(hashableColumns[hci] in sealed)) sealed[hashableColumns[hci]] = null;
    }

    if (resolveOrigin && !tipRow) {
      var held = _originByKey.get(_ck);
      if (held && held.term !== cluster.fencingToken()) {
        _originByKey.delete(_ck);
        _originStaleByKey.set(_ck, true);
        throw new ChainWriterError(
          "leadership changed while this append waited for the " + table +
            " chain lock; where the chain resumes may have moved with it",
          "chain-writer/origin-term-changed"
        );
      }
    }
    var prevHash = tipRow ? tipRow.rowHash
      : (resolveOrigin ? (await _cachedOrigin(_ck, keyValue)).hash : auditChain.ZERO_HASH);
    var rowHash = auditChain.computeRowHash(prevHash, sealed, nonce);

    sealed.prevHash = prevHash;
    sealed.rowHash  = rowHash;
    sealed.nonce    = nonce;

    var fencingToken = cluster.fencingToken();
    var values = columnsForInsert.map(function (c) {
      if (c === "fencingToken") return fencingToken;
      return c in sealed ? sealed[c] : null;
    });
    await _insertRow(values);

    return Object.assign({ rowHash: rowHash, prevHash: prevHash }, fullLogical);
  }

  function _resetForTest() {
    _mutexByKey = new Map();
    _counterInitByKey = new Map();
    _nextCounterByKey = new Map();
    _originByKey = new Map();
    _originStaleByKey = new Map();
    _clockByKey = new Map();
  }

  return {
    table:          table,
    chainKey:       chainKey,
    append:         append,
    withChainLock: function (keyValue, fn) {
      return _mutexFor(keyValue).runExclusive(fn);
    },
    invalidateOrigin: function (keyValue) {
      var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
      _originByKey.delete(k);
      _originStaleByKey.set(k, true);
    },
    _resetForTest:  _resetForTest,
    _getMutexForTest: function (keyValue) { return _mutexFor(keyValue); },
  };
}

module.exports = {
  create:               create,
  registerTable:        registerTable,
  ChainWriterError:     ChainWriterError,
  ALLOWED_CHAIN_TABLES: ALLOWED_CHAIN_TABLES,
  FRAMEWORK_SQL_TIMEOUT_MS: FRAMEWORK_SQL_TIMEOUT_MS,
};
