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
var { FrameworkError } = require("./framework-error");

// Allowlist of chain table names. Adding a new chain-backed table
// (e.g. some future _blamejs_security_log) requires registering it here
// so an operator can't accidentally point a chain-writer at a non-chain
// table and corrupt the chain semantics.
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
 * @primitive b.chainWriter.create
 * @signature b.chainWriter.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.audit, b.consent, b.auditChain
 *
 * Build a chain-writer bound to a single hash-chained table. Returns
 * `{ table, append, _resetForTest, _getMutexForTest }`. `append(logical)`
 * is the public surface — async, leader-gated, mutex-serialized; on
 * success it returns the logical row decorated with the computed
 * `rowHash` and `prevHash`.
 *
 * @opts
 *   table:            string,    // one of ALLOWED_CHAIN_TABLES (audit_log | consent_log)
 *   columnsForInsert: string[],  // INSERT column order (every name is identifier-validated)
 *   hashableColumns:  string[],  // columns that participate in the rowHash canonicalization
 *   validateInput:    Function,  // optional; (logical) → throws on invalid shape
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

  // Per-chain Mutex serializes the read-prev-tip + compute-hash + insert
  // sequence. Without serialization, two concurrent awaiting append() calls
  // would hash against the same prev-tip and produce sibling rows with the
  // same prevHash — forking the chain.
  var _chainMutex = new safeAsync.Mutex();

  // Lazy counter primer — first append reads MAX(monotonicCounter) and
  // increments from there. Once ensures concurrent first-callers share
  // one in-flight init Promise.
  var _nextCounter = 1;
  var _counterInit = null;

  function _ensureCounterInit() {
    if (!_counterInit) {
      _counterInit = new safeAsync.Once(async function () {
        // BARE logical table name — clusterStorage rewrites the framework
        // name to the configured-prefix form and placeholderizes; b.sql
        // quotes the camelCase column + emits the MAX aggregate.
        var maxBuilt = sql.select(table, _sqlOpts())
          .max("monotonicCounter", "m")
          .toSql();
        var row = await safeAsync.withTimeout(
          safeAsync.asyncRetry(function () {
            return clusterStorage.executeOne(maxBuilt.sql, maxBuilt.params);
          }),
          FRAMEWORK_SQL_TIMEOUT_MS,
          { name: table + ".readMaxCounter" }
        );
        _nextCounter = (row && row.m ? Number(row.m) : 0) + 1;
      });
    }
    return _counterInit.invoke();
  }

  async function _readChainTipRow() {
    var tipBuilt = sql.select(table, _sqlOpts())
      .columns(["rowHash"])
      .orderBy("monotonicCounter", "desc")
      .limit(1)
      .toSql();
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
    await _ensureCounterInit();

    return await _chainMutex.runExclusive(async function () {
      return await _appendInsideMutex(logical);
    });
  }

  async function _appendInsideMutex(logical) {
    var counter = _nextCounter++;
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

    // Compute rowHash over the sealed content fields
    var tipRow = await _readChainTipRow();
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
    _chainMutex = new safeAsync.Mutex();
    _counterInit = null;
    _nextCounter = 1;
  }

  return {
    table:          table,
    append:         append,
    _resetForTest:  _resetForTest,
    // Expose for diagnostic introspection
    _getMutexForTest: function () { return _chainMutex; },
  };
}

module.exports = {
  create:               create,
  ChainWriterError:     ChainWriterError,
  ALLOWED_CHAIN_TABLES: ALLOWED_CHAIN_TABLES,
  FRAMEWORK_SQL_TIMEOUT_MS: FRAMEWORK_SQL_TIMEOUT_MS,
};
