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
var safeSql = require("./safe-sql");
var sql = require("./sql");
var C = require("./constants");
var boundedMap = require("./bounded-map");
var { FrameworkError } = require("./framework-error");

// Allowlist of chain table names. The two framework chains ship registered; a
// consumer's own append-only hash-chained table is added at config time via
// registerTable() BEFORE create() accepts it. The allowlist is never bypassed
// — an unregistered table throws at create(), so a misconfig can't point a
// chain-writer at a non-chain table and corrupt the chain semantics.
var ALLOWED_CHAIN_TABLES = new Set(["audit_log", "consent_log"]);

var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

// b.sql opts for every chain-table statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting + dialect
// idioms match the backend the SQL dispatches to. Defaulting to "sqlite"
// works on Postgres only by accident (both double-quote identifiers) and
// emits the wrong quoting on MySQL. clusterStorage.execute still rewrites
// table names + translates `?` placeholders at dispatch; this controls only
// the builder-side quoting + idiom selection.
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
  // Identifier-validate before admitting to the allowlist — the name is
  // interpolated into the chain SQL, so the same shape rules create() relies
  // on must hold here, at the config-time entry point.
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
  // Validate table name shape AND require it's in the chain-table allowlist.
  safeSql.validateIdentifier(opts.table);
  safeSql.assertOneOf(opts.table, ALLOWED_CHAIN_TABLES);

  // Validate every column name against the SQL identifier rules — we
  // interpolate them into the INSERT SQL.
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

  // chainKey: the partition column for many independent chains in one table
  // (one chain per account / device / tenant). When set, the tip read,
  // counter priming, and the append Mutex all scope to a single key value, so
  // appends to DIFFERENT keys run in parallel while same-key appends
  // serialize. Identifier-validated at config time (THROW tier) because it is
  // interpolated as a column name; it must also appear in columnsForInsert so
  // every row carries its partition key.
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

  // Per-CHAIN-KEY Mutex serializes the read-prev-tip + compute-hash + insert
  // sequence. Without serialization, two concurrent awaiting append() calls
  // would hash against the same prev-tip and fork the chain. A single-chain
  // writer (no chainKey) uses one shared lock under the sentinel key; a
  // multi-chain writer keys the lock by the partition value so appends to
  // DIFFERENT keys run concurrently while same-key appends serialize.
  var _SINGLE_CHAIN_KEY = "__single_chain__";   // sentinel; not a valid driver value
  var _mutexByKey = new Map();
  function _mutexFor(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    return boundedMap.getOrInsert(_mutexByKey, k, function () { return new safeAsync.Mutex(); });
  }

  // Lazy counter primer — first append for a given key reads
  // MAX(monotonicCounter) [WHERE chainKey = ?] and increments from there.
  // Per-key so each chain's counter is independent; a per-key Once shares one
  // in-flight init across concurrent first-callers for the same key.
  var _nextCounterByKey = new Map();
  var _counterInitByKey = new Map();

  function _ensureCounterInit(keyValue) {
    var k = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var once = boundedMap.getOrInsert(_counterInitByKey, k, function () {
      return new safeAsync.Once(async function () {
        // BARE logical table name — clusterStorage rewrites the framework
        // name to the configured-prefix form (consumer tables pass through
        // unchanged) and placeholderizes; b.sql quotes the camelCase column +
        // emits the MAX aggregate. A keyed writer scopes the MAX to the
        // partition via a bound WHERE.
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
      .columns(["rowHash"])
      .orderBy("monotonicCounter", "desc")
      .limit(1);
    // Scope the tip to the partition so per-key chains link correctly —
    // bound value, never interpolated.
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
    // b.sql INSERT: map each column (identifier-validated at create()) to
    // its positional value and bind as a row object — the unambiguous form
    // (a flat value array whose first element is a Buffer/object would be
    // misread as an array-of-rows). BARE logical table name — clusterStorage
    // rewrites + placeholderizes per dialect.
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

    // Resolve the partition key from the logical row for a multi-chain writer.
    // Fail closed: a keyed writer with a missing / empty key can't pick a
    // chain to append to, so refuse rather than silently fold the row into the
    // wrong chain.
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
    await _ensureCounterInit(keyValue);

    return await _mutexFor(keyValue).runExclusive(async function () {
      return await _appendInsideMutex(logical, keyValue);
    });
  }

  async function _appendInsideMutex(logical, keyValue) {
    var _ck = chainKey !== null ? String(keyValue) : _SINGLE_CHAIN_KEY;
    var counter = _nextCounterByKey.get(_ck);
    _nextCounterByKey.set(_ck, counter + 1);
    var nowMs   = Date.now();
    var nonce   = generateBytes(C.BYTES.bytes(16));

    // Caller-supplied logical row: spread + add framework-managed fields.
    var fullLogical = Object.assign({}, logical, {
      _id:               (logical && logical._id) || generateToken(C.BYTES.bytes(16)),
      recordedAt:        nowMs,
      monotonicCounter:  counter,
    });

    // Seal sealed-fields, compute derived hashes
    var sealed = cryptoField.sealRow(table, fullLogical);

    // Materialize null entries for every hashable column the schema
    // expects, so canonicalize sees the same key set at write-time and
    // verify-time. JSON canonicalization distinguishes missing-key
    // from key:null — must not.
    for (var hci = 0; hci < hashableColumns.length; hci++) {
      if (!(hashableColumns[hci] in sealed)) sealed[hashableColumns[hci]] = null;
    }

    // Compute rowHash over the sealed content fields, linking to THIS key's tip.
    var tipRow = await _readChainTipRow(keyValue);
    var prevHash = tipRow ? tipRow.rowHash : auditChain.ZERO_HASH;
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
  }

  return {
    table:          table,
    chainKey:       chainKey,
    append:         append,
    _resetForTest:  _resetForTest,
    // Expose for diagnostic introspection — the lock for a given key (or the
    // single-chain lock when no chainKey is configured).
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
