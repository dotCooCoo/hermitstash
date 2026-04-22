/**
 * Vault key rotation — core logic.
 *
 * v1.9.3 ships `validateSchemaMatch(db)` — the schema-drift guardrail that
 * runs before any rotation work. Without this check, a live DB with a
 * sealed-looking column not listed in `field-crypto.js FIELD_SCHEMA` would
 * silently survive rotation unrotated, and post-swap be unreadable forever.
 *
 * Later phases of v1.9.3 will add:
 *   - rotateDataDirectory(oldKeys, newKeys, dataDir, stagingDir, opts)
 *   - verifyRotation(keys, dataDir, opts)  — shared sampler primitive
 *     used by scripts/vault-key-verify.js
 *
 * All functions in this module are pure in the functional sense: they
 * read FIELD_SCHEMA and inspect the provided db handle but do not mutate
 * shared state. Callers pass a Node built-in `node:sqlite` DatabaseSync
 * handle — same module lib/db.js uses. Zero new dependencies.
 */
"use strict";

var fs = require("fs");
var path = require("path");
var { DatabaseSync } = require("node:sqlite");

var FIELD_SCHEMA = require("./field-crypto").FIELD_SCHEMA;
var C = require("./constants");
var VAULT_PREFIX = C.VAULT_PREFIX;
var cryptoLib = require("./crypto");

// Real columns present in every table that hold non-sealed infrastructure
// values (primary keys, timestamps, JSON overflow). The drift detector
// excludes these from its "unknown column" scan. If a new infrastructure
// column is added across all tables, extend this list.
var INFRA_COLUMNS = [
  "_id",
  "data",          // JSON overflow — may contain vault:-prefixed values in its values,
                   // but those are walked separately by the rotation loop, not by this drift check
  "createdAt",
  "updatedAt",
  "deletedAt",
  "lastLogin",
  "lockedUntil",
  "accessedAt",
  "lastAttempt",
  "lastTriggered",
  "expectedFiles",
  "receivedFiles",
  "skippedCount",
  "totalSize",
  "downloads",
  "failedLoginAttempts",
  "status",
  "role",
  "active",
  "keyHash",
  "tokenHash",
  "codeHash",
  "fingerprintHash",
  "emailHash",
  "shareIdHash",
  "bundleShareIdHash",
  "slugHash",
  "revokedAt",
  "attempts",
  "failures",
  "size",
  "counter",
  "seq",
  "bundleId",
  "teamId",
  "userId",
  "uploadedBy",
  "webhookId",
  "bundleShareId",
  "type",
  "key",
  "vaultEncrypted",
  "accessMode",
  "bundleType",
  "statusCode",
  "syncEnabled",
  "maxFileSize",
  "maxFiles",
  "maxBundleSize",
  "defaultExpiry",
  "bundleCount",
  "totalBytes",
  "backedUp",
  "enabled",
  "certFingerprint",
];

// Sample up to this many rows per table when scanning for drift. Enough
// to catch systematic drift (a column consistently sealed) without scanning
// millions of rows during pre-flight.
var DRIFT_SAMPLE_LIMIT = 100;

function _listLiveTables(db) {
  var rows = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
  ).all();
  return rows.map(function (r) { return r.name; });
}

function _listLiveColumns(db, table) {
  // PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
  // table name comes from sqlite_master — safe to interpolate.
  return db.prepare("PRAGMA table_info(" + table + ")").all()
    .map(function (c) { return c.name; });
}

/**
 * Validate that FIELD_SCHEMA (lib/field-crypto.js) and the live DB schema
 * agree on which columns are sealed. Returns { warnings, errors }:
 *
 *   warnings — non-fatal issues. Rotation can still proceed; the affected
 *              columns/tables are just skipped. Typical cause: a table or
 *              column was removed from the schema but remnants exist, or a
 *              new schema entry hasn't been applied to an older DB yet.
 *
 *   errors   — fatal. Rotation MUST NOT proceed. The sampler found at least
 *              one row with a vault:-prefixed value in a real column that
 *              FIELD_SCHEMA doesn't know about. Rotating would leave that
 *              column encrypted with the OLD key post-swap, unreadable
 *              forever.
 *
 * Callers (pre-flight and the eventual rotation entry point) should print
 * warnings to stderr, and on any error exit non-zero before touching data.
 */
function validateSchemaMatch(db) {
  var warnings = [];
  var errors = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = {};
  for (var t = 0; t < liveTables.length; t++) liveTableSet[liveTables[t]] = true;

  for (var table in FIELD_SCHEMA) {
    if (!Object.prototype.hasOwnProperty.call(FIELD_SCHEMA, table)) continue;

    if (!liveTableSet[table]) {
      warnings.push({
        kind: "table_missing",
        table: table,
        message: "FIELD_SCHEMA table '" + table + "' not present in live DB (will be skipped during rotation)",
      });
      continue;
    }

    var schema = FIELD_SCHEMA[table];
    var liveCols = _listLiveColumns(db, table);
    var liveColSet = {};
    for (var c = 0; c < liveCols.length; c++) liveColSet[liveCols[c]] = true;

    // Every schema-declared sealed column should exist in the live table.
    // Missing → warn; rotation skips it, which is safe (there's nothing to rotate).
    if (schema.seal) {
      for (var i = 0; i < schema.seal.length; i++) {
        var sealCol = schema.seal[i];
        if (!liveColSet[sealCol]) {
          warnings.push({
            kind: "sealed_column_missing",
            table: table,
            column: sealCol,
            message: "FIELD_SCHEMA lists '" + table + "." + sealCol + "' as sealed, but the live table has no such column (will be skipped)",
          });
        }
      }
    }

    // Drift detection: for real columns that are NOT in FIELD_SCHEMA.seal,
    // FIELD_SCHEMA.derived, FIELD_SCHEMA.hash, or the infra allowlist,
    // sample rows and check whether any hold vault:-prefixed values.
    //
    // If yes → the column is silently being sealed by some route without
    // being declared to FIELD_SCHEMA, and rotation would miss it.
    var knownCols = {};
    for (var ic = 0; ic < INFRA_COLUMNS.length; ic++) knownCols[INFRA_COLUMNS[ic]] = true;
    if (schema.seal) for (var si = 0; si < schema.seal.length; si++) knownCols[schema.seal[si]] = true;
    if (schema.hash) for (var hi = 0; hi < schema.hash.length; hi++) knownCols[schema.hash[hi]] = true;
    if (schema.derived) for (var dk in schema.derived) {
      if (Object.prototype.hasOwnProperty.call(schema.derived, dk)) knownCols[dk] = true;
    }

    var unknownCols = [];
    for (var lc = 0; lc < liveCols.length; lc++) {
      if (!knownCols[liveCols[lc]]) unknownCols.push(liveCols[lc]);
    }
    if (unknownCols.length === 0) continue;

    // Build a safe SELECT — quote each column name with double quotes per
    // SQLite identifier rules to handle any unusual column name that slipped
    // into the schema.
    var quotedCols = unknownCols.map(function (col) {
      return '"' + col.replace(/"/g, '""') + '"';
    }).join(", ");
    var sampleSql = "SELECT " + quotedCols + " FROM \"" + table + "\" LIMIT " + DRIFT_SAMPLE_LIMIT;
    var sampleRows;
    try {
      sampleRows = db.prepare(sampleSql).all();
    } catch (e) {
      warnings.push({
        kind: "sample_failed",
        table: table,
        message: "Could not sample rows for drift detection in '" + table + "': " + e.message,
      });
      continue;
    }

    var flaggedInThisTable = {};
    for (var r = 0; r < sampleRows.length; r++) {
      var row = sampleRows[r];
      for (var uc = 0; uc < unknownCols.length; uc++) {
        var uname = unknownCols[uc];
        if (flaggedInThisTable[uname]) continue;
        var val = row[uname];
        if (typeof val === "string" && val.indexOf(VAULT_PREFIX) === 0) {
          flaggedInThisTable[uname] = true;
          errors.push({
            kind: "drift",
            table: table,
            column: uname,
            message: "Live DB has vault:-prefixed value in '" + table + "." + uname + "' but FIELD_SCHEMA does NOT list it as sealed. Rotating now would leave this column encrypted with the OLD key, unreadable post-rotation. Add '" + uname + "' to FIELD_SCHEMA['" + table + "'].seal (lib/field-crypto.js) and re-test before rotating.",
          });
        }
      }
    }
  }

  return { warnings: warnings, errors: errors };
}

/**
 * Format a validation result for human-readable CLI output. Returns a
 * multi-line string. Callers choose whether to write it to stdout or
 * stderr depending on exit-code semantics.
 */
function formatValidationResult(result) {
  var lines = [];
  if (result.warnings.length === 0 && result.errors.length === 0) {
    lines.push("[vault-rotate] schema match: OK");
    return lines.join("\n");
  }
  if (result.warnings.length > 0) {
    lines.push("[vault-rotate] schema warnings (" + result.warnings.length + ", non-fatal):");
    for (var w = 0; w < result.warnings.length; w++) {
      lines.push("  - " + result.warnings[w].message);
    }
  }
  if (result.errors.length > 0) {
    lines.push("[vault-rotate] schema errors (" + result.errors.length + ", FATAL — rotation refused):");
    for (var e = 0; e < result.errors.length; e++) {
      lines.push("  - " + result.errors[e].message);
    }
  }
  return lines.join("\n");
}

// =====================================================================
// Rotation — Phase 2 core.
// Produces a rotated copy of dataDir at stagingDir; caller handles swap.
// File-inventory-driven so v1.9.4 can append PEM entries without code
// change here. See spec §5.
// =====================================================================

var VAULT_SEALED_FILES = [
  { relativePath: "db.key.enc", required: true, description: "SQLite file encryption key" },
  // v1.9.4 will append ca.key.sealed + tls/privkey.pem.sealed
];

var VERBATIM_FILES = [
  { relativePath: "ca.key", required: false },
  { relativePath: "ca.crt", required: false },
];

var VERBATIM_DIRS = [
  { relativePath: "tls", required: false },
];

var ROW_BATCH_SIZE_DEFAULT = 1000;
var VERIFY_SAMPLE_MIN = 5;
var VERIFY_SAMPLE_FRAC = 0.01;

function _emit(cb, event) {
  if (typeof cb === "function") {
    try { cb(event); } catch (_e) { /* progress callback errors are non-fatal */ }
  }
}

function _fsyncDir(dirPath) {
  try {
    var fd = fs.openSync(dirPath, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* fsync on dir isn't supported on all platforms; best effort */ }
}

function _fsyncFile(filePath) {
  try {
    var fd = fs.openSync(filePath, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort */ }
}

function _runStmt(db, sql) {
  // Single-statement shim to keep per-line statements out of multi-statement
  // execution paths. Equivalent to the SQLite method of the same purpose.
  db.prepare(sql).run();
}

function _copyFile(src, dest) {
  fs.copyFileSync(src, dest);
}

function _copyDirRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  var entries = fs.readdirSync(src, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var name = entries[i].name;
    var s = path.join(src, name);
    var d = path.join(dest, name);
    if (entries[i].isDirectory()) _copyDirRecursive(s, d);
    else if (entries[i].isFile()) _copyFile(s, d);
  }
}

function _reSealValue(sealedValue, oldKeys, newKeys) {
  if (typeof sealedValue !== "string") return sealedValue;
  if (sealedValue.indexOf(VAULT_PREFIX) !== 0) return sealedValue;
  var payload = sealedValue.substring(VAULT_PREFIX.length);
  var plain = cryptoLib.decrypt(payload, oldKeys);
  return VAULT_PREFIX + cryptoLib.encrypt(plain, newKeys);
}

function _walkAndReSeal(node, oldKeys, newKeys) {
  if (typeof node === "string") {
    if (node.indexOf(VAULT_PREFIX) !== 0) return { value: node, changed: false };
    return { value: _reSealValue(node, oldKeys, newKeys), changed: true };
  }
  if (Array.isArray(node)) {
    var outArr = new Array(node.length);
    var anyChanged = false;
    for (var i = 0; i < node.length; i++) {
      var r = _walkAndReSeal(node[i], oldKeys, newKeys);
      outArr[i] = r.value;
      if (r.changed) anyChanged = true;
    }
    return { value: outArr, changed: anyChanged };
  }
  if (node && typeof node === "object") {
    var outObj = {};
    var objChanged = false;
    for (var k in node) {
      if (!Object.prototype.hasOwnProperty.call(node, k)) continue;
      var rv = _walkAndReSeal(node[k], oldKeys, newKeys);
      outObj[k] = rv.value;
      if (rv.changed) objChanged = true;
    }
    return { value: outObj, changed: objChanged };
  }
  return { value: node, changed: false };
}

function _rotateTableColumn(db, table, column, oldKeys, newKeys, batchSize, progressCallback) {
  var quotedTable = '"' + table + '"';
  var quotedCol = '"' + column + '"';
  var total = db.prepare("SELECT COUNT(*) AS n FROM " + quotedTable + " WHERE " + quotedCol + " IS NOT NULL").get().n;
  if (total === 0) return 0;

  var select = db.prepare(
    "SELECT _id, " + quotedCol + " AS v FROM " + quotedTable +
    " WHERE " + quotedCol + " IS NOT NULL AND _id > ? ORDER BY _id LIMIT ?"
  );
  var update = db.prepare("UPDATE " + quotedTable + " SET " + quotedCol + " = ? WHERE _id = ?");

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = select.all(lastId, batchSize);
    if (rows.length === 0) break;

    _runStmt(db, "BEGIN");
    try {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        if (typeof row.v === "string" && row.v.indexOf(VAULT_PREFIX) === 0) {
          var newVal = _reSealValue(row.v, oldKeys, newKeys);
          update.run(newVal, row._id);
        }
      }
      _runStmt(db, "COMMIT");
    } catch (e) {
      _runStmt(db, "ROLLBACK");
      throw e;
    }

    processed += rows.length;
    lastId = rows[rows.length - 1]._id;
    _emit(progressCallback, {
      phase: "rotate_rows",
      table: table,
      column: column,
      rowsProcessed: processed,
      rowsTotal: total,
    });
  }
  return processed;
}

function _rotateOverflowData(db, table, oldKeys, newKeys, batchSize, progressCallback, warnings) {
  var quotedTable = '"' + table + '"';
  var colInfo = db.prepare("PRAGMA table_info(" + quotedTable + ")").all();
  if (!colInfo.some(function (c) { return c.name === "data"; })) return 0;

  var total = db.prepare("SELECT COUNT(*) AS n FROM " + quotedTable + " WHERE data IS NOT NULL").get().n;
  if (total === 0) return 0;

  var select = db.prepare(
    "SELECT _id, data FROM " + quotedTable +
    " WHERE data IS NOT NULL AND _id > ? ORDER BY _id LIMIT ?"
  );
  var update = db.prepare("UPDATE " + quotedTable + " SET data = ? WHERE _id = ?");

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = select.all(lastId, batchSize);
    if (rows.length === 0) break;

    _runStmt(db, "BEGIN");
    try {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var doc;
        try { doc = JSON.parse(row.data); } catch (_e) {
          warnings.push("malformed overflow JSON at " + table + "._id=" + row._id + " — left unrotated");
          continue;
        }
        var mutated = _walkAndReSeal(doc, oldKeys, newKeys);
        if (mutated.changed) {
          update.run(JSON.stringify(mutated.value), row._id);
        }
      }
      _runStmt(db, "COMMIT");
    } catch (e) {
      _runStmt(db, "ROLLBACK");
      throw e;
    }

    processed += rows.length;
    lastId = rows[rows.length - 1]._id;
    _emit(progressCallback, {
      phase: "rotate_overflow",
      table: table,
      rowsProcessed: processed,
      rowsTotal: total,
    });
  }
  return processed;
}

/**
 * Rotate the data directory onto a new vault keypair.
 *
 * Produces a rotated copy at opts.stagingDir. Does NOT touch opts.dataDir.
 * Caller performs the atomic swap after verifying staging (spec §5).
 *
 * opts:
 *   oldKeys, newKeys  — vault keypairs (4 PEM fields each)
 *   dataDir, stagingDir — paths; stagingDir must NOT exist
 *   mode              — "plaintext" or "wrapped"
 *   newPassphrase     — Buffer (wrapped mode only)
 *   rowBatchSize      — default 1000
 *   progressCallback  — optional, called with { phase, ... }
 *
 * Returns: { durationMs, tablesProcessed, totalRowsProcessed, verifyResult, warnings }
 * Throws on failure; caller should rm -rf stagingDir on throw.
 */
async function rotateDataDirectory(opts) {
  var startedAt = Date.now();
  var warnings = [];
  var oldKeys = opts.oldKeys;
  var newKeys = opts.newKeys;
  var dataDir = opts.dataDir;
  var stagingDir = opts.stagingDir;
  var mode = opts.mode || "plaintext";
  var rowBatchSize = opts.rowBatchSize || ROW_BATCH_SIZE_DEFAULT;
  var progress = opts.progressCallback;

  if (!oldKeys || !newKeys) throw new Error("rotateDataDirectory: oldKeys and newKeys required");
  if (mode === "wrapped" && !opts.newPassphrase) throw new Error("rotateDataDirectory: newPassphrase required in wrapped mode");
  if (fs.existsSync(stagingDir)) throw new Error("rotateDataDirectory: stagingDir already exists: " + stagingDir);

  _emit(progress, { phase: "init", message: "Creating staging directory" });
  fs.mkdirSync(stagingDir, { recursive: true, mode: 0o700 });

  // Step 1: copy verbatim files/dirs
  _emit(progress, { phase: "copy_files" });
  for (var vf = 0; vf < VERBATIM_FILES.length; vf++) {
    var entry = VERBATIM_FILES[vf];
    var src = path.join(dataDir, entry.relativePath);
    if (!fs.existsSync(src)) {
      if (entry.required) throw new Error("Required file missing in dataDir: " + entry.relativePath);
      continue;
    }
    _copyFile(src, path.join(stagingDir, entry.relativePath));
  }
  for (var vd = 0; vd < VERBATIM_DIRS.length; vd++) {
    var dentry = VERBATIM_DIRS[vd];
    var sdir = path.join(dataDir, dentry.relativePath);
    if (!fs.existsSync(sdir)) {
      if (dentry.required) throw new Error("Required dir missing in dataDir: " + dentry.relativePath);
      continue;
    }
    _copyDirRecursive(sdir, path.join(stagingDir, dentry.relativePath));
  }

  // Step 2: write new vault key (plaintext or wrapped)
  _emit(progress, { phase: "write_vault_key" });
  var keysJson = JSON.stringify(newKeys, null, 2);
  if (mode === "wrapped") {
    var vaultWrap = require("./vault-wrap");
    var sealed = await vaultWrap.wrap(keysJson, opts.newPassphrase);
    fs.writeFileSync(path.join(stagingDir, "vault.key.sealed"), sealed, { mode: 0o600 });
  } else {
    fs.writeFileSync(path.join(stagingDir, "vault.key"), keysJson, { mode: 0o600 });
  }

  // Step 3: re-seal every vault-sealed file (db.key.enc today; PEMs in v1.9.4)
  _emit(progress, { phase: "reseal_files" });
  for (var sf = 0; sf < VAULT_SEALED_FILES.length; sf++) {
    var sealedEntry = VAULT_SEALED_FILES[sf];
    var sealedSrc = path.join(dataDir, sealedEntry.relativePath);
    if (!fs.existsSync(sealedSrc)) {
      if (sealedEntry.required) throw new Error("Required sealed file missing in dataDir: " + sealedEntry.relativePath);
      continue;
    }
    var sealedDestDir = path.join(stagingDir, path.dirname(sealedEntry.relativePath));
    if (!fs.existsSync(sealedDestDir)) fs.mkdirSync(sealedDestDir, { recursive: true, mode: 0o700 });
    var current = fs.readFileSync(sealedSrc, "utf8").trim();
    if (current.indexOf(VAULT_PREFIX) !== 0) {
      throw new Error("Vault-sealed file does not start with '" + VAULT_PREFIX + "': " + sealedEntry.relativePath);
    }
    var resealed = _reSealValue(current, oldKeys, newKeys);
    fs.writeFileSync(path.join(stagingDir, sealedEntry.relativePath), resealed, { mode: 0o600 });
  }

  // Step 4: decrypt DB, rotate rows, re-encrypt
  // db.key.enc wrapping changed in step 3 but the UNDERLYING 32-byte dbKey
  // is unchanged — so the on-disk DB ciphertext decrypts with the same key.
  var encDbPath = path.join(dataDir, "hermitstash.db.enc");
  var hasEncDb = fs.existsSync(encDbPath);
  var tablesProcessed = 0;
  var totalRowsProcessed = 0;
  var verifyResult = null;

  if (hasEncDb) {
    _emit(progress, { phase: "decrypt_db" });
    var oldDbKeySealed = fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8").trim();
    if (oldDbKeySealed.indexOf(VAULT_PREFIX) !== 0) throw new Error("db.key.enc is not vault-sealed");
    var dbKey = Buffer.from(
      cryptoLib.decrypt(oldDbKeySealed.substring(VAULT_PREFIX.length), oldKeys),
      "base64"
    );
    var packed = fs.readFileSync(encDbPath);
    var plainBytes = cryptoLib.decryptPacked(packed, dbKey);

    var tmpDbPath = path.join(stagingDir, "hermitstash.db.tmp");
    fs.writeFileSync(tmpDbPath, plainBytes);

    var db = new DatabaseSync(tmpDbPath);
    try {
      _runStmt(db, "PRAGMA journal_mode=WAL");
      _runStmt(db, "PRAGMA synchronous=NORMAL");
      _runStmt(db, "PRAGMA cache_size=-8000");
      _runStmt(db, "PRAGMA temp_store=MEMORY");

      _emit(progress, { phase: "rotate_rows", message: "Starting row rotation" });
      for (var table in FIELD_SCHEMA) {
        if (!Object.prototype.hasOwnProperty.call(FIELD_SCHEMA, table)) continue;
        var schema = FIELD_SCHEMA[table];

        var tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table);
        if (!tableExists) continue;

        var tableRows = 0;
        if (schema.seal) {
          var liveCols = db.prepare('PRAGMA table_info("' + table + '")').all()
            .map(function (c) { return c.name; });
          var liveColSet = {};
          for (var lc = 0; lc < liveCols.length; lc++) liveColSet[liveCols[lc]] = true;

          for (var sc = 0; sc < schema.seal.length; sc++) {
            var sealCol = schema.seal[sc];
            if (!liveColSet[sealCol]) continue;
            tableRows += _rotateTableColumn(db, table, sealCol, oldKeys, newKeys, rowBatchSize, progress);
          }
        }
        tableRows += _rotateOverflowData(db, table, oldKeys, newKeys, rowBatchSize, progress, warnings);

        if (tableRows > 0) {
          tablesProcessed++;
          totalRowsProcessed += tableRows;
        }
      }

      _runStmt(db, "PRAGMA wal_checkpoint(TRUNCATE)");
    } finally {
      db.close();
    }

    try { fs.unlinkSync(tmpDbPath + "-wal"); } catch (_e) { /* may not exist */ }
    try { fs.unlinkSync(tmpDbPath + "-shm"); } catch (_e) { /* may not exist */ }

    _emit(progress, { phase: "reencrypt_db" });
    var mutatedBytes = fs.readFileSync(tmpDbPath);
    var newPacked = cryptoLib.encryptPacked(mutatedBytes, dbKey);
    fs.writeFileSync(path.join(stagingDir, "hermitstash.db.enc"), newPacked);
    fs.unlinkSync(tmpDbPath);

    _emit(progress, { phase: "verify" });
    var verifyPacked = fs.readFileSync(path.join(stagingDir, "hermitstash.db.enc"));
    var verifyPlain = cryptoLib.decryptPacked(verifyPacked, dbKey);
    var verifyTmpPath = path.join(stagingDir, "hermitstash.db.verify.tmp");
    fs.writeFileSync(verifyTmpPath, verifyPlain);
    var verifyDb = new DatabaseSync(verifyTmpPath);
    try {
      verifyResult = verifyRotation(newKeys, verifyDb, { oldKeys: oldKeys });
    } finally {
      verifyDb.close();
      try { fs.unlinkSync(verifyTmpPath); } catch (_e) { /* best-effort */ }
      try { fs.unlinkSync(verifyTmpPath + "-wal"); } catch (_e) { /* best-effort */ }
      try { fs.unlinkSync(verifyTmpPath + "-shm"); } catch (_e) { /* best-effort */ }
    }
    if (!verifyResult.ok) {
      throw new Error(
        "Round-trip verification failed — " + verifyResult.failures.length +
        " decrypt failure(s), " + verifyResult.regressions.length + " non-rotated row(s). " +
        "First issue: " + JSON.stringify(verifyResult.failures[0] || verifyResult.regressions[0])
      );
    }
  }

  // Step 7: fsync staging for durability before caller proceeds to marker+swap
  _emit(progress, { phase: "fsync" });
  var stagingEntries = fs.readdirSync(stagingDir);
  for (var se = 0; se < stagingEntries.length; se++) {
    var fullPath = path.join(stagingDir, stagingEntries[se]);
    var stat = fs.statSync(fullPath);
    if (stat.isFile()) _fsyncFile(fullPath);
  }
  _fsyncDir(stagingDir);

  var durationMs = Date.now() - startedAt;
  _emit(progress, {
    phase: "done",
    durationMs: durationMs,
    tablesProcessed: tablesProcessed,
    totalRowsProcessed: totalRowsProcessed,
  });

  return {
    durationMs: durationMs,
    tablesProcessed: tablesProcessed,
    totalRowsProcessed: totalRowsProcessed,
    verifyResult: verifyResult,
    warnings: warnings,
  };
}

/**
 * Verify that every sealed column in a live DB decrypts with the given
 * keypair. Shared between rotateDataDirectory's round-trip step and the
 * scripts/vault-key-verify.js read-only CLI.
 *
 * If opts.oldKeys is passed, also asserts at least one sampled row per
 * table NO LONGER decrypts with oldKeys — the anti-regression check that
 * rotation actually took effect rather than being a silent no-op.
 *
 * Returns { ok, passed, failures, regressions }.
 */
function verifyRotation(keys, db, opts) {
  var opts2 = opts || {};
  var sampleMin = opts2.sampleMin || VERIFY_SAMPLE_MIN;
  var samplePct = opts2.samplePercent || VERIFY_SAMPLE_FRAC;
  var checkOldFails = !!opts2.oldKeys;
  var oldKeys = opts2.oldKeys;

  var passed = [];
  var failures = [];
  var regressions = [];

  for (var table in FIELD_SCHEMA) {
    if (!Object.prototype.hasOwnProperty.call(FIELD_SCHEMA, table)) continue;
    var schema = FIELD_SCHEMA[table];
    if (!schema.seal || schema.seal.length === 0) continue;

    var tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table);
    if (!tableExists) continue;

    var total = db.prepare('SELECT COUNT(*) AS n FROM "' + table + '"').get().n;
    if (total === 0) continue;

    var sampleN = Math.max(sampleMin, Math.ceil(total * samplePct));
    if (sampleN > total) sampleN = total;

    var sampled = db.prepare('SELECT * FROM "' + table + '" ORDER BY RANDOM() LIMIT ?').all(sampleN);
    var foundOldFail = !checkOldFails;
    var verified = 0;

    for (var i = 0; i < sampled.length; i++) {
      var row = sampled[i];
      var rowHadFailure = false;
      for (var c = 0; c < schema.seal.length; c++) {
        var col = schema.seal[c];
        var val = row[col];
        if (typeof val !== "string" || val.indexOf(VAULT_PREFIX) !== 0) continue;
        var payload = val.substring(VAULT_PREFIX.length);
        try {
          cryptoLib.decrypt(payload, keys);
        } catch (e) {
          rowHadFailure = true;
          failures.push({ table: table, column: col, _id: row._id, error: e.message });
        }
        if (checkOldFails && !foundOldFail) {
          try {
            cryptoLib.decrypt(payload, oldKeys);
            regressions.push({
              table: table, column: col, _id: row._id,
              error: "old keys still decrypt sampled value — rotation didn't take effect",
            });
          } catch (_e) {
            foundOldFail = true;
          }
        }
      }
      if (!rowHadFailure) verified++;
    }

    passed.push({ table: table, sampled: sampled.length, verified: verified });
  }

  return {
    ok: failures.length === 0 && regressions.length === 0,
    passed: passed,
    failures: failures,
    regressions: regressions,
  };
}

module.exports = {
  validateSchemaMatch: validateSchemaMatch,
  formatValidationResult: formatValidationResult,
  rotateDataDirectory: rotateDataDirectory,
  verifyRotation: verifyRotation,
  VAULT_SEALED_FILES: VAULT_SEALED_FILES,
  VERBATIM_FILES: VERBATIM_FILES,
  VERBATIM_DIRS: VERBATIM_DIRS,
  INFRA_COLUMNS: INFRA_COLUMNS,
  DRIFT_SAMPLE_LIMIT: DRIFT_SAMPLE_LIMIT,
  ROW_BATCH_SIZE_DEFAULT: ROW_BATCH_SIZE_DEFAULT,
};
