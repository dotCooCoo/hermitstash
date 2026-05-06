"use strict";
/**
 * Chain-writer primitive — race-safe append to a hash-chained log table.
 *
 * The framework's audit_log AND consent_log have the same shape:
 *
 *   1. Take the next monotonic counter
 *   2. Compute prevHash from the previous row's rowHash
 *   3. Seal the logical row via field-crypto (sealedFields → vault.seal,
 *      derivedHashes computed)
 *   4. Materialize null entries for every hashable column (so canonicalize
 *      at write-time and verify-time agree on the key set)
 *   5. Compute rowHash over the sealed content (excluding chain bookkeeping)
 *   6. INSERT with prevHash / rowHash / nonce / fencingToken
 *
 * audit.js and consent.js previously each carried their own copy of
 * the chain-write pattern. The duplication produced bugs at the same
 * architectural points: a chain-fork race had to be fixed in audit
 * via Mutex, and consent had the same race because the fix hadn't
 * propagated. Per the framework's "if a task repeats more than once
 * it should be a primitive" rule, the pattern lives here and every
 * chain-writer consumer gets the same safety guarantees automatically.
 *
 * Each chain-writer instance owns:
 *   - The table name (validated via sql-safe.assertOneOf at construction)
 *   - The full column list (for INSERT)
 *   - The hashable column list (for canonicalization)
 *   - A Mutex serializing the chain (read-prev → compute-hash → insert)
 *   - A Once initializing the in-process counter from MAX(monotonicCounter)
 *
 * Writes go through the cluster-storage dispatcher so the same chain
 * definition works in single-node SQLite and cluster-mode external-db.
 *
 * Public API:
 *
 *   chainWriter.create({
 *     table:           "audit_log" | "consent_log" | …,
 *     columnsForInsert: [string],            order matters; INSERT uses this
 *     hashableColumns:  [string],            for canonicalize null-fill
 *     validateAction:   function (event)     optional; throws on invalid input
 *   })
 *
 *   writer.append(logical)                   async; returns { rowHash, prevHash, …logical }
 *   writer._resetForTest()                   re-initializes counter + mutex
 *
 * Operators usually don't construct chain-writers directly; audit and
 * consent each construct one at module load.
 */

var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var cryptoField = require("./crypto-field");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var safeAsync = require("./safe-async");
var safeSql = require("./safe-sql");
var C = require("./constants");
var { FrameworkError } = require("./framework-error");

// Allowlist of chain table names. Adding a new chain-backed table
// (e.g. some future _blamejs_security_log) requires registering it here
// so an operator can't accidentally point a chain-writer at a non-chain
// table and corrupt the chain semantics.
var ALLOWED_CHAIN_TABLES = new Set(["audit_log", "consent_log"]);

var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

class ChainWriterError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "ChainWriterError";
    this.code = code || "chain-writer/invalid";
    this.isChainWriterError = true;
  }
}

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
        var row = await safeAsync.withTimeout(
          safeAsync.asyncRetry(function () {
            return clusterStorage.executeOne(
              "SELECT MAX(monotonicCounter) AS m FROM " + safeSql.quoteIdentifier(table)
            );
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
    return await safeAsync.withTimeout(
      safeAsync.asyncRetry(function () {
        return clusterStorage.executeOne(
          "SELECT rowHash FROM " + safeSql.quoteIdentifier(table) +
          " ORDER BY monotonicCounter DESC LIMIT 1"
        );
      }),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: table + ".readChainTip" }
    );
  }

  async function _insertRow(values) {
    // Build INSERT with quoted identifiers + ? placeholders. cluster-
    // storage handles dialect-specific placeholder translation.
    var quoted = columnsForInsert.map(function (c) { return safeSql.quoteIdentifier(c); }).join(", ");
    var placeholders = columnsForInsert.map(function () { return "?"; }).join(", ");
    return await safeAsync.withTimeout(
      clusterStorage.execute(
        "INSERT INTO " + safeSql.quoteIdentifier(table) +
        " (" + quoted + ") VALUES (" + placeholders + ")",
        values
      ),
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
