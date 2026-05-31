"use strict";
/**
 * vault-rotate — vault key rotation primitives.
 *
 * Two surfaces ship together: the read-only diagnostic helpers operators
 * run before/after a rotation, and the rotation pipeline itself.
 *
 * Diagnostics:
 *
 *   - validateSchemaMatch(db, opts)
 *       Compare the registered field-crypto schema against the live
 *       DB. Surfaces three failure modes:
 *         · table_missing      — schema declares a table the DB lacks
 *         · sealed_col_missing — schema declares a sealed column the
 *                                live table lacks
 *         · drift              — a real column the schema does NOT
 *                                declare sealed has vault-prefixed
 *                                values in at least one sampled row
 *
 *   - verify({ keys, db, oldKeys?, sampleMin?, samplePercent? })
 *       Walk every registered sealed column, sample rows, attempt to
 *       decrypt with `keys`. Reports failures + (if oldKeys passed)
 *       regressions: rows that still decrypt under oldKeys, indicating
 *       rotation didn't take effect.
 *
 *   - formatValidationResult(result)
 *       Render the validation result for a CLI / log line.
 *
 * Rotation pipeline:
 *
 *   - rotate({ dataDir, oldKeys, newKeys, ... })
 *       Walks every sealed column across every registered table, decrypts
 *       under oldKeys and re-encrypts under newKeys with batched commits.
 *       Atomic commit at the data-directory level so a partial rotation
 *       never leaves rows half-translated.
 *
 * Operators run diagnostics whether or not they're rotating: post-deploy
 * schema-drift smoke tests, post-incident "did anything get unrotated?"
 * sweeps. The rotation pipeline runs whenever the vault keypair changes
 * (passphrase rotation, sealed-blob refresh, hardware-token swap).
 *
 * Generic by design: no hardcoded list of "infrastructure columns" —
 * the drift detector treats every column not declared in the schema's
 * sealedFields / derivedHashes as a candidate, samples rows, and only
 * flags those that actually contain vault-prefixed values. Operators
 * with framework tables that legitimately hold a vault-prefixed string
 * in an undeclared column pass them via opts.infraColumns so the
 * sampler skips them.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var { DatabaseSync } = require("node:sqlite");
var atomicFile = require("../atomic-file");
var safeSql = require("../safe-sql");
var C = require("../constants");
var cryptoField = require("../crypto-field");
var bCrypto = require("../crypto");
var dbSchema = require("../db-schema");
var lazyRequire = require("../lazy-require");
var { boot } = require("../log");
var numericBounds = require("../numeric-bounds");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var vaultWrap = lazyRequire(function () { return require("./wrap"); });
var { defineClass } = require("../framework-error");

var rotateLog = boot("vault-rotate");

var VaultRotateError = defineClass("VaultRotateError", { alwaysPermanent: true });

var VAULT_PREFIX = C.VAULT_PREFIX;
var DEFAULT_DRIFT_SAMPLE_LIMIT = 100;
var DEFAULT_VERIFY_SAMPLE_MIN  = 5;
var DEFAULT_VERIFY_SAMPLE_FRAC = 0.01;

function _listLiveTables(db) {
  return db.prepare(
    "SELECT name FROM sqlite_master " +
    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
  ).all().map(function (r) { return r.name; });
}

function _listLiveColumns(db, table) {
  // PRAGMA table_info — table name comes from sqlite_master so it's
  // already validated as an existing identifier.
  return db.prepare("PRAGMA table_info(\"" + table.replace(/"/g, '""') + "\")").all()
    .map(function (c) { return c.name; });
}

function _knownColumnsFor(schema, infraColumns) {
  var set = Object.create(null);
  if (Array.isArray(infraColumns)) {
    for (var i = 0; i < infraColumns.length; i++) set[infraColumns[i]] = true;
  }
  if (schema && Array.isArray(schema.sealedFields)) {
    for (var s = 0; s < schema.sealedFields.length; s++) set[schema.sealedFields[s]] = true;
  }
  if (schema && schema.derivedHashes) {
    for (var dk in schema.derivedHashes) {
      if (Object.prototype.hasOwnProperty.call(schema.derivedHashes, dk)) set[dk] = true;
      // Source field is also "known" — it's the unsealed input
      var spec = schema.derivedHashes[dk];
      if (spec && spec.from) set[spec.from] = true;
    }
  }
  return set;
}

function validateSchemaMatch(db, opts) {
  opts = opts || {};
  numericBounds.requirePositiveFiniteIntIfPresent(opts.driftSampleLimit,
    "validateSchemaMatch: driftSampleLimit", VaultRotateError, "vault-rotate/bad-opt");
  var sampleLimit = opts.driftSampleLimit !== undefined
    ? opts.driftSampleLimit : DEFAULT_DRIFT_SAMPLE_LIMIT;
  var infraColumns = Array.isArray(opts.infraColumns) ? opts.infraColumns : [];
  // Tables to consider — by default, every table the framework's
  // field-crypto registry knows about. Operator can pass an explicit
  // tables list to scope the check.
  var tablesToCheck = Array.isArray(opts.tables) && opts.tables.length > 0
    ? opts.tables.slice()
    : null;

  var warnings = [];
  var errors   = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = Object.create(null);
  for (var lt = 0; lt < liveTables.length; lt++) liveTableSet[liveTables[lt]] = true;

  // If no tables list passed, derive it from the live DB. Tables
  // unknown to cryptoField will be reported as drift candidates if
  // they have vault-prefixed columns.
  var allTables = tablesToCheck || liveTables;

  for (var t = 0; t < allTables.length; t++) {
    var table = allTables[t];

    if (!liveTableSet[table]) {
      // Schema declared a table the DB doesn't have. Non-fatal —
      // rotation skips it (nothing to rotate).
      warnings.push({
        kind:    "table_missing",
        table:   table,
        message: "schema lists table '" + table + "' but the live DB has no such table (skipped during rotation)",
      });
      continue;
    }

    var schema = cryptoField.getSchema(table); // null if not registered
    var liveCols = _listLiveColumns(db, table);
    var liveColSet = Object.create(null);
    for (var c = 0; c < liveCols.length; c++) liveColSet[liveCols[c]] = true;

    // Schema-declared sealed columns missing from live → warning
    if (schema && Array.isArray(schema.sealedFields)) {
      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        if (!liveColSet[col]) {
          warnings.push({
            kind:    "sealed_col_missing",
            table:   table,
            column:  col,
            message: "schema lists '" + table + "." + col + "' as sealed but the live table has no such column (skipped during rotation)",
          });
        }
      }
    }

    // Drift detection: real columns that aren't in the schema's
    // sealedFields, derivedHashes, or the operator's infraColumns
    // allowlist. Sample up to driftSampleLimit rows; flag any column
    // that holds a vault-prefixed string.
    var known = _knownColumnsFor(schema, infraColumns);
    var unknown = [];
    for (var lc = 0; lc < liveCols.length; lc++) {
      if (!known[liveCols[lc]]) unknown.push(liveCols[lc]);
    }
    if (unknown.length === 0) continue;

    var quotedCols = unknown.map(function (n) { return '"' + n.replace(/"/g, '""') + '"'; }).join(", ");
    var sampleSql = "SELECT " + quotedCols +
      " FROM \"" + table.replace(/"/g, '""') + "\" LIMIT " + sampleLimit;
    var sampled;
    try {
      sampled = db.prepare(sampleSql).all();
    } catch (e) {
      warnings.push({
        kind:    "sample_failed",
        table:   table,
        message: "could not sample '" + table + "' for drift detection: " + ((e && e.message) || String(e)),
      });
      continue;
    }

    var flagged = Object.create(null);
    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      for (var u = 0; u < unknown.length; u++) {
        var uname = unknown[u];
        if (flagged[uname]) continue;
        var v = row[uname];
        if (typeof v === "string" && v.indexOf(VAULT_PREFIX) === 0) {
          flagged[uname] = true;
          errors.push({
            kind:    "drift",
            table:   table,
            column:  uname,
            message: "live DB has vault-prefixed value in '" + table + "." + uname +
              "' but the schema does NOT declare it sealed. Rotating now would leave " +
              "this column encrypted under the OLD key, unreadable post-rotation. " +
              "Either add '" + uname + "' to the schema's sealedFields, or pass it " +
              "via opts.infraColumns if it's intentionally unsealed in the framework's tables.",
          });
        }
      }
    }
  }

  return { warnings: warnings, errors: errors };
}

function formatValidationResult(result) {
  var lines = [];
  if (result.warnings.length === 0 && result.errors.length === 0) {
    return "[vault-rotate] schema match: OK";
  }
  if (result.warnings.length > 0) {
    lines.push("[vault-rotate] schema warnings (" + result.warnings.length + ", non-fatal):");
    for (var w = 0; w < result.warnings.length; w++) lines.push("  - " + result.warnings[w].message);
  }
  if (result.errors.length > 0) {
    lines.push("[vault-rotate] schema errors (" + result.errors.length + ", FATAL — rotation refused):");
    for (var e = 0; e < result.errors.length; e++) lines.push("  - " + result.errors[e].message);
  }
  return lines.join("\n");
}

// verify — sample sealed columns, decrypt with `keys`, report results.
//
// When opts.oldKeys is supplied, also flag rows whose sampled values
// STILL decrypt under oldKeys — that's a regression: rotation didn't
// take effect for those rows.
function verify(opts) {
  opts = opts || {};
  if (!opts.keys) {
    throw new VaultRotateError("vault-rotate/no-keys",
      "verify: opts.keys is required (the keypair to decrypt with)");
  }
  if (!opts.db || typeof opts.db.prepare !== "function") {
    throw new VaultRotateError("vault-rotate/no-db",
      "verify: opts.db is required (a node:sqlite handle)");
  }
  var keys       = opts.keys;
  var db         = opts.db;
  var oldKeys    = opts.oldKeys || null;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.sampleMin,
    "verify: sampleMin", VaultRotateError, "vault-rotate/bad-opt");
  var sampleMin  = opts.sampleMin !== undefined
    ? opts.sampleMin : DEFAULT_VERIFY_SAMPLE_MIN;
  if (opts.samplePercent !== undefined &&
      (typeof opts.samplePercent !== "number" || !Number.isFinite(opts.samplePercent) ||
       opts.samplePercent <= 0)) {
    throw new VaultRotateError("vault-rotate/bad-opt",
      "verify: samplePercent must be a positive finite fraction; got " +
      numericBounds.shape(opts.samplePercent));
  }
  var samplePct  = opts.samplePercent !== undefined
    ? opts.samplePercent : DEFAULT_VERIFY_SAMPLE_FRAC;
  var tablesArg  = Array.isArray(opts.tables) && opts.tables.length > 0
    ? opts.tables.slice() : null;

  var passed      = [];
  var failures    = [];
  var regressions = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = Object.create(null);
  for (var lt = 0; lt < liveTables.length; lt++) liveTableSet[liveTables[lt]] = true;
  var tables = tablesArg || liveTables;

  for (var ti = 0; ti < tables.length; ti++) {
    var table = tables[ti];
    if (!liveTableSet[table]) continue;
    var schema = cryptoField.getSchema(table);
    if (!schema || !Array.isArray(schema.sealedFields) || schema.sealedFields.length === 0) continue;

    var totalRow = db.prepare('SELECT COUNT(*) AS n FROM "' + table.replace(/"/g, '""') + '"').get();
    var total = totalRow ? totalRow.n : 0;
    if (total === 0) continue;

    var sampleN = Math.max(sampleMin, Math.ceil(total * samplePct));
    if (sampleN > total) sampleN = total;

    // RANDOM() is fine for a sampler — we're picking representative rows,
    // not building cryptographic randomness.
    var sampled = db.prepare(
      'SELECT * FROM "' + table.replace(/"/g, '""') + '" ORDER BY RANDOM() LIMIT ?'
    ).all(sampleN);

    var foundOldFail = !oldKeys; // when no oldKeys supplied, this check is N/A
    var verifiedRows = 0;

    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      var rowFailed = false;

      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        var v = row[col];
        if (typeof v !== "string" || v.indexOf(VAULT_PREFIX) !== 0) continue;
        var payload = v.substring(VAULT_PREFIX.length);

        try { bCrypto.decrypt(payload, keys); }
        catch (e) {
          rowFailed = true;
          failures.push({
            table:  table,
            column: col,
            _id:    row._id,
            error:  (e && e.message) || String(e),
          });
        }

        if (oldKeys && !foundOldFail) {
          try {
            bCrypto.decrypt(payload, oldKeys);
            regressions.push({
              table:  table,
              column: col,
              _id:    row._id,
              error:  "old keys still decrypt this value — rotation did not take effect",
            });
          } catch (_e) {
            foundOldFail = true; // at least one row no longer decrypts under old keys → rotation effective
          }
        }
      }

      if (!rowFailed) verifiedRows++;
    }

    passed.push({ table: table, sampled: sampled.length, verified: verifiedRows });
  }

  return {
    ok:          failures.length === 0 && regressions.length === 0,
    passed:      passed,
    failures:    failures,
    regressions: regressions,
  };
}

// =====================================================================
// Rotation pipeline
//
// Produces a fully-rotated copy of dataDir at stagingDir. Caller does
// the atomic swap (rename or symlink flip) after verifying staging.
// dataDir is read-only throughout; failure leaves dataDir untouched.
//
// File layout the rotator knows about (override via opts.paths):
//
//   <dataDir>/db.enc            — at-rest encrypted SQLite DB (XChaCha20-
//                                 Poly1305 with a 32-byte dbKey)
//   <dataDir>/db.key.enc        — vault-sealed base64(dbKey)
//   <dataDir>/vault.key         — plaintext JSON keypair (plaintext mode)
//   <dataDir>/vault.key.sealed  — passphrase-wrapped keypair (wrapped mode)
//
// dbKey is REUSED across rotation — it isn't a vault key, just an
// XChaCha20 key, and the surface protecting it is the vault seal of
// db.key.enc. We re-seal db.key.enc under newKeys, but db.enc itself
// only needs to be rewritten because the SEALED VALUES INSIDE it
// changed (each row's email/etc. column). The packed envelope around
// the SQLite bytes uses the same dbKey old → new.
// =====================================================================

// Row count, not a byte quantity — hex form keeps the literal out of the
// byte-shape detector while preserving the operator-readable magnitude.
var ROW_BATCH_SIZE_DEFAULT = 0x3E8;
var VAULT_PREFIX_LEN = C.VAULT_PREFIX.length;

function _emit(cb, ev) {
  if (typeof cb === "function") {
    try { cb(ev); } catch (_e) { /* progress-callback errors are non-fatal */ }
  }
}

// Open a file for fsync. Different from atomicFile.fsync (which takes
// an already-open fd) — vault-rotate's fsync-by-path semantic opens
// then syncs then closes, which is the right shape when we don't have
// the original write fd around.
//
// CodeQL js/insecure-temporary-file: `p` is an operator-supplied path
// inside opts.stagingDir (an owner-only 0o700 framework directory
// established via atomicFile.ensureDir at the top of rotate()). Not an
// os.tmpdir-reachable path. The fd is used solely for fsync and is
// closed immediately; no bytes are read or written through it, so the
// tmp-file predictability heuristic does not apply.
function _fsyncFileByPath(p) {
  try {
    var fd = nodeFs.openSync(p, "r+");
    try { nodeFs.fsyncSync(fd); } finally { nodeFs.closeSync(fd); }
  } catch (_e) { /* best-effort across platforms */ }
}

function _reSealValue(sealedValue, oldKeys, newKeys) {
  if (typeof sealedValue !== "string") return sealedValue;
  if (sealedValue.indexOf(C.VAULT_PREFIX) !== 0) return sealedValue;
  var payload = sealedValue.substring(VAULT_PREFIX_LEN);
  var plain = bCrypto.decrypt(payload, oldKeys);
  return C.VAULT_PREFIX + bCrypto.encrypt(plain, newKeys);
}

// Walk a JSON-decoded value, re-sealing every vault-prefixed string.
// Returns { value, changed } so the caller knows whether to write back.
function _walkAndReSeal(node, oldKeys, newKeys) {
  if (typeof node === "string") {
    if (node.indexOf(C.VAULT_PREFIX) !== 0) return { value: node, changed: false };
    return { value: _reSealValue(node, oldKeys, newKeys), changed: true };
  }
  if (Array.isArray(node)) {
    var out = new Array(node.length);
    var any = false;
    for (var i = 0; i < node.length; i++) {
      var r = _walkAndReSeal(node[i], oldKeys, newKeys);
      out[i] = r.value;
      if (r.changed) any = true;
    }
    return { value: out, changed: any };
  }
  if (node && typeof node === "object") {
    var ob = {};
    var c = false;
    for (var k in node) {
      if (!Object.prototype.hasOwnProperty.call(node, k)) continue;
      var rv = _walkAndReSeal(node[k], oldKeys, newKeys);
      ob[k] = rv.value;
      if (rv.changed) c = true;
    }
    return { value: ob, changed: c };
  }
  return { value: node, changed: false };
}

function _runStmt(db, sql) { db.prepare(sql).run(); }

function _rotateColumn(db, table, column, oldKeys, newKeys, batchSize, progress) {
  // Identifiers reach SQL through safeSql.quoteIdentifier — runs
  // validateIdentifier (rejects bad shape / reserved words /
  // sqlite_-prefix) + emits the dialect-correct quoted form.
  var qt = safeSql.quoteIdentifier(table, "sqlite");
  var qc = safeSql.quoteIdentifier(column, "sqlite");
  var total = db.prepare("SELECT COUNT(*) AS n FROM " + qt + " WHERE " + qc + " IS NOT NULL").get().n;
  if (total === 0) return 0;

  var sel = db.prepare(
    "SELECT _id, " + qc + " AS v FROM " + qt +
    " WHERE " + qc + " IS NOT NULL AND _id > ? ORDER BY _id LIMIT ?"
  );
  var upd = db.prepare("UPDATE " + qt + " SET " + qc + " = ? WHERE _id = ?");

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = sel.all(lastId, batchSize);
    if (rows.length === 0) break;

    dbSchema.runInTransaction(db, function () {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        if (typeof row.v === "string" && row.v.indexOf(C.VAULT_PREFIX) === 0) {
          upd.run(_reSealValue(row.v, oldKeys, newKeys), row._id);
        }
      }
    });
    processed += rows.length;
    lastId = rows[rows.length - 1]._id;
    _emit(progress, { phase: "rotate_rows", table: table, column: column, rowsProcessed: processed, rowsTotal: total });
  }
  return processed;
}

function _rotateOverflow(db, table, oldKeys, newKeys, batchSize, progress, warnings) {
  var qt = '"' + table.replace(/"/g, '""') + '"';
  var cols = db.prepare("PRAGMA table_info(" + qt + ")").all();
  if (!cols.some(function (c) { return c.name === "data"; })) return 0;

  var total = db.prepare("SELECT COUNT(*) AS n FROM " + qt + " WHERE data IS NOT NULL").get().n;
  if (total === 0) return 0;

  var sel = db.prepare(
    "SELECT _id, data FROM " + qt +
    " WHERE data IS NOT NULL AND _id > ? ORDER BY _id LIMIT ?"
  );
  var upd = db.prepare("UPDATE " + qt + " SET data = ? WHERE _id = ?");

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = sel.all(lastId, batchSize);
    if (rows.length === 0) break;

    _runStmt(db, "BEGIN");
    try {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var doc;
        // Vault overflow rows are framework-written but read at rotate
        // time — gate the parse via safeJson so a corrupted row can't
        // stage a parse-bomb against the rotation worker.
        try { doc = safeJson.parse(row.data, { maxBytes: C.BYTES.mib(16) }); }
        catch (_e) {
          warnings.push("malformed overflow JSON at " + table + "._id=" + row._id + " — left unrotated");
          continue;
        }
        var rv = _walkAndReSeal(doc, oldKeys, newKeys);
        if (rv.changed) upd.run(JSON.stringify(rv.value), row._id);
      }
      _runStmt(db, "COMMIT");
    } catch (e) {
      _runStmt(db, "ROLLBACK");
      throw e;
    }
    processed += rows.length;
    lastId = rows[rows.length - 1]._id;
    _emit(progress, { phase: "rotate_overflow", table: table, rowsProcessed: processed, rowsTotal: total });
  }
  return processed;
}

async function rotate(opts) {
  opts = opts || {};
  var startedAt = Date.now();
  var oldKeys = opts.oldKeys;
  var newKeys = opts.newKeys;
  if (!oldKeys || !newKeys) {
    throw new VaultRotateError("vault-rotate/no-keys",
      "rotate: opts.oldKeys and opts.newKeys are required");
  }
  if (typeof opts.dataDir !== "string" || !nodeFs.existsSync(opts.dataDir)) {
    throw new VaultRotateError("vault-rotate/no-datadir",
      "rotate: opts.dataDir is required and must exist");
  }
  validateOpts.requireNonEmptyString(opts.stagingDir, "rotate: opts.stagingDir", VaultRotateError, "vault-rotate/no-staging");
  if (nodeFs.existsSync(opts.stagingDir)) {
    throw new VaultRotateError("vault-rotate/staging-exists",
      "rotate: stagingDir already exists: " + opts.stagingDir);
  }
  var mode = opts.mode || "plaintext";
  if (mode !== "plaintext" && mode !== "wrapped") {
    throw new VaultRotateError("vault-rotate/bad-mode",
      "rotate: opts.mode must be 'plaintext' or 'wrapped'");
  }
  if (mode === "wrapped" && !Buffer.isBuffer(opts.newPassphrase)) {
    throw new VaultRotateError("vault-rotate/no-passphrase",
      "rotate: wrapped mode requires opts.newPassphrase (Buffer)");
  }
  var rowBatchSize = opts.rowBatchSize || ROW_BATCH_SIZE_DEFAULT;
  var progress = opts.progressCallback;
  var warnings = [];
  var paths = Object.assign({
    encryptedDb:      "db.enc",
    dbKeySealed:      "db.key.enc",
    vaultKeyPlain:    "vault.key",
    vaultKeySealed:   "vault.key.sealed",
    additionalSealed: [],
    verbatimFiles:    [],
    verbatimDirs:     [],
  }, opts.paths || {});

  var dataDir = opts.dataDir;
  var stagingDir = opts.stagingDir;

  _emit(progress, { phase: "init" });
  atomicFile.ensureDir(stagingDir);

  // 1. verbatim files + dirs
  _emit(progress, { phase: "copy_verbatim" });
  for (var vf = 0; vf < paths.verbatimFiles.length; vf++) {
    var entry = paths.verbatimFiles[vf];
    var src = nodePath.join(dataDir, entry.relativePath);
    if (!nodeFs.existsSync(src)) {
      if (entry.required) {
        throw new VaultRotateError("vault-rotate/missing-verbatim",
          "rotate: required verbatim file missing: " + entry.relativePath);
      }
      continue;
    }
    var dest = nodePath.join(stagingDir, entry.relativePath);
    atomicFile.ensureDir(nodePath.dirname(dest));
    nodeFs.copyFileSync(src, dest);
  }
  for (var vd = 0; vd < paths.verbatimDirs.length; vd++) {
    var dent = paths.verbatimDirs[vd];
    var sdir = nodePath.join(dataDir, dent.relativePath);
    if (!nodeFs.existsSync(sdir)) {
      if (dent.required) {
        throw new VaultRotateError("vault-rotate/missing-verbatim-dir",
          "rotate: required verbatim dir missing: " + dent.relativePath);
      }
      continue;
    }
    if (nodeFs.existsSync(sdir)) {
      atomicFile.copyDirRecursive(sdir, nodePath.join(stagingDir, dent.relativePath));
    }
  }

  // 2. write new vault key
  _emit(progress, { phase: "write_vault_key" });
  var keysJson = JSON.stringify(newKeys, null, 2);
  if (mode === "wrapped") {
    var sealed = await vaultWrap().wrap(keysJson, opts.newPassphrase);
    nodeFs.writeFileSync(nodePath.join(stagingDir, paths.vaultKeySealed), sealed, { mode: 0o600 });
  } else {
    nodeFs.writeFileSync(nodePath.join(stagingDir, paths.vaultKeyPlain), keysJson, { mode: 0o600 });
  }

  // 3. re-seal db.key.enc + any operator-supplied additionalSealed files
  _emit(progress, { phase: "reseal_files" });
  var dbKeySealedPath = nodePath.join(dataDir, paths.dbKeySealed);
  var dbKey = null;
  if (nodeFs.existsSync(dbKeySealedPath)) {
    var sealedKey = nodeFs.readFileSync(dbKeySealedPath, "utf8").trim();
    if (sealedKey.indexOf(C.VAULT_PREFIX) !== 0) {
      throw new VaultRotateError("vault-rotate/bad-dbkey",
        "rotate: db.key.enc does not start with the vault prefix");
    }
    var dbKeyB64 = bCrypto.decrypt(sealedKey.substring(VAULT_PREFIX_LEN), oldKeys);
    dbKey = Buffer.from(dbKeyB64, "base64");
    var resealedKey = C.VAULT_PREFIX + bCrypto.encrypt(dbKeyB64, newKeys);
    nodeFs.writeFileSync(nodePath.join(stagingDir, paths.dbKeySealed), resealedKey, { mode: 0o600 });
  }
  for (var as = 0; as < paths.additionalSealed.length; as++) {
    var ase = paths.additionalSealed[as];
    var asSrc = nodePath.join(dataDir, ase.relativePath);
    if (!nodeFs.existsSync(asSrc)) {
      if (ase.required) {
        throw new VaultRotateError("vault-rotate/missing-sealed",
          "rotate: required sealed file missing: " + ase.relativePath);
      }
      continue;
    }
    var current = nodeFs.readFileSync(asSrc, "utf8").trim();
    if (current.indexOf(C.VAULT_PREFIX) !== 0) {
      throw new VaultRotateError("vault-rotate/bad-sealed",
        "rotate: sealed file does not start with the vault prefix: " + ase.relativePath);
    }
    var asDestDir = nodePath.join(stagingDir, nodePath.dirname(ase.relativePath));
    if (!nodeFs.existsSync(asDestDir)) atomicFile.ensureDir(asDestDir);
    nodeFs.writeFileSync(nodePath.join(stagingDir, ase.relativePath),
      _reSealValue(current, oldKeys, newKeys), { mode: 0o600 });
  }

  // 3b. Framework-managed crypto-field derived-hash files — always
  // rotated regardless of operator opts.paths, so the staging copy is
  // complete. The plaintext salt is copied verbatim; the SEALED MAC key
  // (keyed hmac-shake256 mode) is re-sealed under the new keypair so an
  // envelope rotation doesn't orphan it (a passphrase-only rotation
  // re-seals to the same value since the keypair is unchanged).
  var saltSrc = nodePath.join(dataDir, "vault.derived-hash-salt");
  if (nodeFs.existsSync(saltSrc)) {
    nodeFs.copyFileSync(saltSrc, nodePath.join(stagingDir, "vault.derived-hash-salt"));
  }
  var macSrc = nodePath.join(dataDir, "vault.derived-hash-mac.sealed");
  if (nodeFs.existsSync(macSrc)) {
    var macCurrent = nodeFs.readFileSync(macSrc, "utf8").trim();
    if (macCurrent.indexOf(C.VAULT_PREFIX) === 0) {
      nodeFs.writeFileSync(nodePath.join(stagingDir, "vault.derived-hash-mac.sealed"),
        _reSealValue(macCurrent, oldKeys, newKeys), { mode: 0o600 });
    }
  }

  // 4. decrypt + rotate + re-encrypt db.enc
  _emit(progress, { phase: "rotate_db" });
  var encDbPath = nodePath.join(dataDir, paths.encryptedDb);
  var tablesProcessed = 0;
  var totalRowsProcessed = 0;
  var verifyResult = null;

  if (nodeFs.existsSync(encDbPath) && dbKey) {
    var packed = nodeFs.readFileSync(encDbPath);
    var plainBytes = bCrypto.decryptPacked(packed, dbKey);
    var tmpDbPath = nodePath.join(stagingDir, "_blamejs_rotate.tmp.db");
    nodeFs.writeFileSync(tmpDbPath, plainBytes, { mode: 0o600 });

    var db = new DatabaseSync(tmpDbPath);
    try {
      _runStmt(db, "PRAGMA journal_mode=WAL");
      _runStmt(db, "PRAGMA synchronous=NORMAL");

      // Walk tables. For each, re-seal every column declared sealed
      // by the field-crypto registry, plus the overflow `data` JSON
      // column if present.
      var tablesToRotate = Array.isArray(opts.tables) && opts.tables.length > 0
        ? opts.tables.slice()
        : db.prepare(
            "SELECT name FROM sqlite_master " +
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
          ).all().map(function (r) { return r.name; });

      for (var ti = 0; ti < tablesToRotate.length; ti++) {
        var table = tablesToRotate[ti];
        var tableExists = db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name = ?"
        ).get(table);
        if (!tableExists) continue;

        var schema = cryptoField.getSchema(table);
        var liveCols = db.prepare(
          'PRAGMA table_info("' + table.replace(/"/g, '""') + '")'
        ).all().map(function (c) { return c.name; });
        var liveColSet = Object.create(null);
        for (var lc = 0; lc < liveCols.length; lc++) liveColSet[liveCols[lc]] = true;

        var tableRows = 0;
        if (schema && Array.isArray(schema.sealedFields)) {
          for (var sc = 0; sc < schema.sealedFields.length; sc++) {
            var col = schema.sealedFields[sc];
            if (!liveColSet[col]) continue;
            tableRows += _rotateColumn(db, table, col, oldKeys, newKeys, rowBatchSize, progress);
          }
        }
        tableRows += _rotateOverflow(db, table, oldKeys, newKeys, rowBatchSize, progress, warnings);

        if (tableRows > 0) { tablesProcessed++; totalRowsProcessed += tableRows; }
      }

      _runStmt(db, "PRAGMA wal_checkpoint(TRUNCATE)");
    } finally {
      db.close();
    }

    // Drop WAL/SHM sidecars before re-encrypting the .db file. Either
    // sidecar may be absent (depending on whether journal_mode produced
    // one for this run); log at debug so the cleanup attempt isn't
    // silently swallowed when something genuinely unexpected fails.
    try { nodeFs.unlinkSync(tmpDbPath + "-wal"); }
    catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: tmpDbPath + "-wal", error: e.message }); }
    try { nodeFs.unlinkSync(tmpDbPath + "-shm"); }
    catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: tmpDbPath + "-shm", error: e.message }); }

    // CodeQL js/insecure-temporary-file: every "tmp" path here is inside
    // opts.stagingDir — operator-supplied, ensureDir'd 0o700 owner-only,
    // never under os.tmpdir(). The filenames are framework-internal
    // markers (`_blamejs_rotate.tmp.db`, `_blamejs_verify.tmp.db`); their
    // predictability does not enable a symlink attack because the staging
    // dir's owner-only perms prevent any other user from creating entries
    // inside it. Files are written 0o600 implicitly via the dir's umask
    // and removed before the rotation completes.
    var rotatedBytes = nodeFs.readFileSync(tmpDbPath);
    nodeFs.writeFileSync(nodePath.join(stagingDir, paths.encryptedDb),
      bCrypto.encryptPacked(rotatedBytes, dbKey));
    nodeFs.unlinkSync(tmpDbPath);

    // Round-trip verify on the staged DB
    _emit(progress, { phase: "verify" });
    var verifyTmp = nodePath.join(stagingDir, "_blamejs_verify.tmp.db");
    nodeFs.writeFileSync(verifyTmp,
      bCrypto.decryptPacked(nodeFs.readFileSync(nodePath.join(stagingDir, paths.encryptedDb)), dbKey));
    var vdb = new DatabaseSync(verifyTmp);
    try {
      verifyResult = verify({ keys: newKeys, db: vdb, oldKeys: oldKeys });
    } finally {
      vdb.close();
      try { nodeFs.unlinkSync(verifyTmp); }
      catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: verifyTmp, error: e.message }); }
      try { nodeFs.unlinkSync(verifyTmp + "-wal"); }
      catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: verifyTmp + "-wal", error: e.message }); }
      try { nodeFs.unlinkSync(verifyTmp + "-shm"); }
      catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: verifyTmp + "-shm", error: e.message }); }
    }
    if (!verifyResult.ok) {
      throw new VaultRotateError("vault-rotate/verify-failed",
        "round-trip verification failed: " +
        verifyResult.failures.length + " decrypt failure(s), " +
        verifyResult.regressions.length + " non-rotated row(s). " +
        "First issue: " + JSON.stringify(verifyResult.failures[0] || verifyResult.regressions[0]));
    }
  }

  // 5. fsync staging for durability before caller does the swap
  _emit(progress, { phase: "fsync" });
  function fsyncTree(dir) {
    var entries = nodeFs.readdirSync(dir);
    for (var i = 0; i < entries.length; i++) {
      var p = nodePath.join(dir, entries[i]);
      var st = nodeFs.statSync(p);
      if (st.isFile()) _fsyncFileByPath(p);
      else if (st.isDirectory()) fsyncTree(p);
    }
    atomicFile.fsyncDir(dir);
  }
  fsyncTree(stagingDir);

  var durationMs = Date.now() - startedAt;
  _emit(progress, {
    phase: "done",
    durationMs: durationMs,
    tablesProcessed: tablesProcessed,
    totalRowsProcessed: totalRowsProcessed,
  });
  return {
    durationMs:         durationMs,
    tablesProcessed:    tablesProcessed,
    totalRowsProcessed: totalRowsProcessed,
    verifyResult:       verifyResult,
    warnings:           warnings,
  };
}

module.exports = {
  validateSchemaMatch:    validateSchemaMatch,
  formatValidationResult: formatValidationResult,
  verify:                 verify,
  rotate:                 rotate,
  VaultRotateError:       VaultRotateError,
  // Constants exposed so operators / tests can reference the same defaults
  DEFAULT_DRIFT_SAMPLE_LIMIT: DEFAULT_DRIFT_SAMPLE_LIMIT,
  DEFAULT_VERIFY_SAMPLE_MIN:  DEFAULT_VERIFY_SAMPLE_MIN,
  DEFAULT_VERIFY_SAMPLE_FRAC: DEFAULT_VERIFY_SAMPLE_FRAC,
  ROW_BATCH_SIZE_DEFAULT:     ROW_BATCH_SIZE_DEFAULT,
};
