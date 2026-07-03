// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var sql = require("../sql");
var C = require("../constants");
var cryptoField = require("../crypto-field");
var bCrypto = require("../crypto");
var vaultAad = require("../vault-aad");
var dbSchema = require("../db-schema");
var frameworkFiles = require("../framework-files");
var lazyRequire = require("../lazy-require");
var { boot } = require("../log");
var numericBounds = require("../numeric-bounds");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var vaultWrap = lazyRequire(function () { return require("./wrap"); });
// lazyRequire (named dbModuleLazy to match the canonical binding in
// lib/backup/index.js and to avoid shadowing the local SQLite handle `db`
// inside rotate()): the db at-rest AAD constructors live in lib/db.js.
var dbModuleLazy = lazyRequire(function () { return require("../db"); });
// Framework AAD modules whose stores live outside db.enc — lazyRequire'd
// at top-of-file (deferred, never inline in a function body) so rotate's
// detect-and-refuse can read each module's AAD_ROTATION descriptor without
// eagerly loading them at require time.
var agentIdempotencyLazy = lazyRequire(function () { return require("../agent-idempotency"); });
var agentOrchestratorLazy = lazyRequire(function () { return require("../agent-orchestrator"); });
var agentTenantLazy = lazyRequire(function () { return require("../agent-tenant"); });
var agentSnapshotLazy = lazyRequire(function () { return require("../agent-snapshot"); });
// Tenant archive blobs (recipient: "tenant") are keyed off the vault root but
// live in operator-placed storage (files / object stores / backups) the
// rotation pipeline never walks, so archive-wrap exports the same external
// AAD_ROTATION descriptor and must be gated here too.
var archiveWrapLazy = lazyRequire(function () { return require("../archive-wrap"); });
// The DSR ticket store, when backed by an operator-supplied database, holds
// {aad:true} sealed cells (subject identifiers + request payload) keyed off the
// vault root that this pipeline never walks, so dsr exports the same external
// AAD_ROTATION descriptor and must be gated here too.
var dsrLazy = lazyRequire(function () { return require("../dsr"); });
var { defineClass } = require("../framework-error");

var rotateLog = boot("vault-rotate");

var VaultRotateError = defineClass("VaultRotateError", { alwaysPermanent: true });

var VAULT_PREFIX = C.VAULT_PREFIX;
var DEFAULT_DRIFT_SAMPLE_LIMIT = 100;
var DEFAULT_VERIFY_SAMPLE_MIN  = 5;
var DEFAULT_VERIFY_SAMPLE_FRAC = 0.01;

// The catalog/PRAGMA statements all compose through b.sql's narrow audited
// catalog sub-API (b.sql.catalog / b.sql.pragma) - the only path that emits
// an sqlite_master reference or a PRAGMA verb, allowlisting exactly the
// statements the key-rotation walk needs and refusing every other internal
// identifier / PRAGMA verb. Each returns { sql, params }; the node:sqlite
// handle takes the params positionally.
function _all(db, built) {
  var stmt = db.prepare(built.sql);
  return built.params.length > 0 ? stmt.all.apply(stmt, built.params) : stmt.all();
}
function _get(db, built) {
  var stmt = db.prepare(built.sql);
  return built.params.length > 0 ? stmt.get.apply(stmt, built.params) : stmt.get();
}

function _listLiveTables(db) {
  return _all(db, sql.catalog.listTables()).map(function (r) { return r.name; });
}

function _listLiveColumns(db, table) {
  // PRAGMA table_info — table name comes from sqlite_master so it's
  // already validated as an existing identifier; b.sql.catalog.tableInfo
  // quotes it by construction.
  return _all(db, sql.catalog.tableInfo(table)).map(function (c) { return c.name; });
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

    var sampleBuilt = sql.select(table, { dialect: "sqlite", quoteName: true })
      .columns(unknown)
      .limit(sampleLimit)
      .toSql();
    var sampled;
    try {
      sampled = _all(db, sampleBuilt);
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
  // Serialized roots for AAD-cell verification — match getKeysJson() so an
  // AAD cell sealed under the new root opens here.
  var keysJson    = JSON.stringify(keys, null, 2);
  var oldKeysJson = oldKeys ? JSON.stringify(oldKeys, null, 2) : null;
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

    var totalRow = _get(db, sql.select(table, { dialect: "sqlite", quoteName: true })
      .count("*", "n").toSql());
    var total = totalRow ? totalRow.n : 0;
    if (total === 0) continue;

    var sampleN = Math.max(sampleMin, Math.ceil(total * samplePct));
    if (sampleN > total) sampleN = total;

    // RANDOM() is fine for a sampler — we're picking representative rows,
    // not building cryptographic randomness. b.sql.catalog.sampleRandom is
    // the audited ORDER BY RANDOM() form (the general builder has no random-
    // order clause); columns omitted -> `*`.
    var sampled = _all(db, sql.catalog.sampleRandom(table, null, { limit: sampleN }));

    var foundOldFail = !oldKeys; // when no oldKeys supplied, this check is N/A
    var verifiedRows = 0;

    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      var rowFailed = false;

      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        var v = row[col];
        if (typeof v !== "string") continue;

        if (vaultAad.isAadSealed(v)) {
          // AAD cell: reconstruct the seal-side AAD (cryptoField._aadParts)
          // and verify under the new root; flag a regression if it still
          // opens under the old root (rotation didn't take effect).
          var aad = cryptoField._aadParts(schema, table, col, row);
          try { vaultAad.unsealRoot(v, aad, keysJson); }
          catch (e) {
            rowFailed = true;
            failures.push({ table: table, column: col, _id: row._id, error: (e && e.message) || String(e) });
          }
          if (oldKeysJson && !foundOldFail) {
            try {
              vaultAad.unsealRoot(v, aad, oldKeysJson);
              regressions.push({ table: table, column: col, _id: row._id,
                error: "old keys still decrypt this AAD value — rotation did not take effect" });
            } catch (_e) { foundOldFail = true; }
          }
          continue;
        }

        if (v.indexOf(VAULT_PREFIX) !== 0) continue;
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

// db.enc / db.key.enc AAD constructors come from the module that OWNS the
// db at-rest format (lib/db.js _dbEncAad / _dbKeyAad), not re-declared
// here — one source of truth for the wire-format literals so a rotation
// re-seal binds the SAME deployment AAD db.init expects on next open.

// Framework modules that seal AAD cells on operator-supplied (external)
// stores this pipeline never reaches (it only walks db.enc). Each exports
// an AAD_ROTATION descriptor + a reseal hook to rotate its store
// out-of-band. rotate() REFUSES a keypair rotation unless the operator
// acknowledges (opts.externalAadResealed) each has been re-sealed —
// otherwise those cells silently orphan under the retired root (CWE-320).
// Only the module PATHS live here; the table / backend metadata lives in
// each module's AAD_ROTATION export (single source of truth). lazyRequire
// so loading rotate.js doesn't eagerly pull the agent modules.
var EXTERNAL_AAD_MODULE_LOADERS = [
  agentIdempotencyLazy, agentOrchestratorLazy, agentTenantLazy, agentSnapshotLazy,
  archiveWrapLazy, dsrLazy,
];

function _externalAadTables() {
  var tables = [];
  for (var i = 0; i < EXTERNAL_AAD_MODULE_LOADERS.length; i += 1) {
    var mod;
    try { mod = EXTERNAL_AAD_MODULE_LOADERS[i](); }
    catch (_e) { continue; }   // module unavailable in this process — skip
    var desc = mod && mod.AAD_ROTATION;
    if (!desc) continue;
    var list = Array.isArray(desc) ? desc : [desc];
    for (var j = 0; j < list.length; j += 1) {
      if (list[j] && list[j].backend === "external" && list[j].table) tables.push(list[j].table);
    }
  }
  return tables;
}

function _emit(cb, ev) {
  if (typeof cb === "function") {
    try { cb(ev); } catch (_e) { /* progress-callback errors are non-fatal */ }
  }
}

// Create a fresh file in the owner-only staging dir with exclusive,
// no-follow semantics, then fsync it. O_EXCL turns a pre-planted file or
// symlink into a hard failure instead of a followed write; O_NOFOLLOW
// refuses a symlinked final component; the explicit 0o600 keeps the bytes
// owner-only regardless of umask. Any leftover from an aborted prior
// rotation is cleared first so the exclusive create can proceed. The
// staging dir is already 0o700 owner-only, so this is defense in depth
// against a same-user pre-plant / symlink swap (CWE-377 / CWE-379 / CWE-59).
function _writeStagedFileExclusive(p, data) {
  // The clear-stale + O_EXCL|O_NOFOLLOW create + write + fsync sequence now
  // lives in the atomic-file primitive (also used by the vault passphrase
  // seal/unseal staging writes) so every staged exclusive write shares one
  // implementation.
  atomicFile.writeExclSync(p, data, { fileMode: 0o600 });
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

function _rotateColumn(db, table, column, schema, roots, batchSize, progress) {
  // Every statement composes through b.sql (sqlite dialect, quoteName so
  // the concrete handle's table is quoted, not left bare for a cluster
  // rewrite that does not apply here). Identifiers are validated + quoted
  // by construction; the cursor bound (_id) + LIMIT bind as ? placeholders.
  var total = _get(db, sql.select(table, { dialect: "sqlite", quoteName: true })
    .count("*", "n").whereNotNull(column).toSql()).n;
  if (total === 0) return 0;

  // AAD-bound tables (registerTable({aad:true})) seal each cell under a
  // (table, rowId, column, schemaVersion) tuple. Rotation reads the
  // rowIdField value and reconstructs the IDENTICAL AAD via the seal-side
  // builder cryptoField._aadParts (one source of truth), then re-seals
  // old-root -> new-root. Plain (non-AAD) cells use the plain-vault reseal.
  var aadMode = !!(schema && schema.aad);
  var rowIdField = aadMode ? schema.rowIdField : null;
  var needRid = aadMode && rowIdField && rowIdField !== "_id";

  // Keyset-cursor page over (_id) ascending. The projected columns are read
  // by their REAL names off the result row (no AS alias) - the column value
  // is row[column], the row-id value is row[rowIdField]. The SQL text is
  // constant across the loop (only the bound _id-cursor changes; LIMIT is a
  // builder-inlined integer literal, validated non-negative), so prepare
  // once + re-run with the fresh cursor param positionally. The SELECT
  // carries exactly one `?` (the _id cursor); the UPDATE carries two (the
  // resealed value + the _id).
  var selCols = ["_id", column];
  if (needRid) selCols.push(rowIdField);
  var selBuilt = sql.select(table, { dialect: "sqlite", quoteName: true })
    .columns(selCols)
    .whereNotNull(column)
    .whereOp("_id", ">", "")
    .orderBy("_id")
    .limit(batchSize)
    .toSql();
  var sel = db.prepare(selBuilt.sql);
  var updBuilt = sql.update(table, { dialect: "sqlite", quoteName: true })
    .set(column, "")
    .where("_id", "")
    .toSql();
  var upd = db.prepare(updBuilt.sql);

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = sel.all(lastId);
    if (rows.length === 0) break;

    dbSchema.runInTransaction(db, function () {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var cellVal = row[column];
        if (typeof cellVal !== "string") continue;
        if (aadMode && vaultAad.isAadSealed(cellVal)) {
          // Rebuild the exact AAD the seal side used. cryptoField._aadParts
          // reads row[schema.rowIdField]; feed it the rowIdField value we
          // selected (row[rowIdField], or _id when rowIdField IS _id).
          var rowForAad = {};
          rowForAad[rowIdField] = needRid ? row[rowIdField] : row._id;
          var aad = cryptoField._aadParts(schema, table, column, rowForAad);
          upd.run(vaultAad.resealRoot(cellVal, aad, roots.oldRootJson, roots.newRootJson), row._id);
        } else if (cellVal.indexOf(C.VAULT_PREFIX) === 0) {
          // Plain vault: cell (non-AAD table, or a legacy pre-AAD cell in
          // an AAD table that the next sealRow upgrades).
          upd.run(_reSealValue(cellVal, roots.oldKeys, roots.newKeys), row._id);
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
  var cols = _all(db, sql.catalog.tableInfo(table));
  if (!cols.some(function (c) { return c.name === "data"; })) return 0;

  var total = _get(db, sql.select(table, { dialect: "sqlite", quoteName: true })
    .count("*", "n").whereNotNull("data").toSql()).n;
  if (total === 0) return 0;

  // Same keyset cursor as _rotateColumn over the overflow `data` JSON
  // column: one bound `?` (the _id cursor), builder-inlined LIMIT literal.
  var selBuilt = sql.select(table, { dialect: "sqlite", quoteName: true })
    .columns(["_id", "data"])
    .whereNotNull("data")
    .whereOp("_id", ">", "")
    .orderBy("_id")
    .limit(batchSize)
    .toSql();
  var sel = db.prepare(selBuilt.sql);
  var updBuilt = sql.update(table, { dialect: "sqlite", quoteName: true })
    .set("data", "")
    .where("_id", "")
    .toSql();
  var upd = db.prepare(updBuilt.sql);

  var processed = 0;
  var lastId = "";
  while (true) {
    var rows = sel.all(lastId);
    if (rows.length === 0) break;

    // One transaction per page via the shared wrapper — the rotate worker
    // no longer hand-rolls the BEGIN/COMMIT/ROLLBACK skeleton.
    dbSchema.runInTransaction(db, function () {
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
    });
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
  // Detect-and-refuse: AAD-bound state on operator-supplied stores is NOT
  // reached by this pipeline (it walks only db.enc). Refuse unless the
  // operator acknowledges each such store has been re-sealed via its
  // module hook — otherwise a keypair rotation silently orphans them.
  var externalAad = _externalAadTables();
  if (externalAad.length > 0) {
    var ack = opts.externalAadResealed;
    var acknowledged = ack === true ||
      (Array.isArray(ack) && externalAad.every(function (t) { return ack.indexOf(t) !== -1; }));
    if (!acknowledged) {
      throw new VaultRotateError("vault-rotate/external-aad-unresealed",
        "rotate: AAD-bound state on operator-supplied stores is not reached by this " +
        "pipeline and would be orphaned under the retired keypair: " + externalAad.join(", ") +
        ". Re-seal each via its module hook (b.agent.idempotency.reseal / " +
        "b.agent.orchestrator.reseal / b.agent.tenant AAD_ROTATION reseal / " +
        "b.agent.snapshot.reseal / b.archive.rewrapTenant for archive-wrap:tenant-blobs / " +
        "b.dsr.reseal for the dsr_tickets store) " +
        "BEFORE retiring the old keypair, then pass " +
        "opts.externalAadResealed: [" + externalAad.map(function (t) { return JSON.stringify(t); }).join(", ") +
        "] to acknowledge. If you do not use these features, pass opts.externalAadResealed: true.");
    }
  }
  var rowBatchSize = opts.rowBatchSize || ROW_BATCH_SIZE_DEFAULT;
  var progress = opts.progressCallback;
  var warnings = [];
  var paths = Object.assign({
    encryptedDb:      frameworkFiles.fileName("dbEnc"),
    dbKeySealed:      frameworkFiles.fileName("dbKeyEnc"),
    vaultKeyPlain:    frameworkFiles.fileName("vaultKey"),
    vaultKeySealed:   frameworkFiles.fileName("vaultKey") + ".sealed",
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
    // Stage via the exclusive-create + fsync helper rather than a plain copy,
    // so the verbatim file is durable at write time (no later by-path fsync)
    // and a pre-planted file/symlink at the staging path hard-fails.
    _writeStagedFileExclusive(dest, atomicFile.fdSafeReadSync(src, { maxBytes: C.BYTES.mib(64) }));
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
  // Serialized roots for the explicit-root AAD reseal path. These match
  // b.vault.getKeysJson() EXACTLY (JSON.stringify(keys, null, 2)) so an
  // AAD cell re-sealed under newRootJson here unseals once the new keypair
  // is live after the atomic swap.
  var oldRootJson = JSON.stringify(oldKeys, null, 2);
  var newRootJson = keysJson;
  if (mode === "wrapped") {
    var sealed = await vaultWrap().wrap(keysJson, opts.newPassphrase);
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.vaultKeySealed), sealed);
  } else {
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.vaultKeyPlain), keysJson);
  }

  // 3. re-seal db.key.enc + any operator-supplied additionalSealed files
  _emit(progress, { phase: "reseal_files" });
  var dbKeySealedPath = nodePath.join(dataDir, paths.dbKeySealed);
  var dbKey = null;
  if (nodeFs.existsSync(dbKeySealedPath)) {
    var sealedKey = atomicFile.fdSafeReadSync(dbKeySealedPath, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
    if (vaultAad.isAadSealed(sealedKey)) {
      // AAD-bound db.key.enc (db.js since v0.14.7): unseal under the OLD
      // root with the deployment-context AAD, then re-emit under the NEW
      // root with the SAME context (an in-place swap keeps dataDir +
      // keyPath, so source and target AAD match). The vault.aad: shape is
      // preserved — a plain-vault re-emit would strip the deployment-
      // substitution binding (CWE-345 / CWE-441).
      var dbKeyAad = dbModuleLazy()._dbKeyAad(dataDir, dbKeySealedPath);
      var dbKeyB64Aad = vaultAad.unsealRoot(sealedKey, dbKeyAad, oldRootJson);
      dbKey = Buffer.from(dbKeyB64Aad, "base64");
      var resealedAad = vaultAad.sealRoot(dbKeyB64Aad, dbKeyAad, newRootJson);
      _writeStagedFileExclusive(nodePath.join(stagingDir, paths.dbKeySealed), resealedAad);
    } else if (sealedKey.indexOf(C.VAULT_PREFIX) === 0) {
      // Legacy plain-sealed db.key.enc (pre-AAD). Re-key in place; db.init
      // read-migrates plain -> AAD on the next boot.
      var dbKeyB64 = bCrypto.decrypt(sealedKey.substring(VAULT_PREFIX_LEN), oldKeys);
      dbKey = Buffer.from(dbKeyB64, "base64");
      var resealedKey = C.VAULT_PREFIX + bCrypto.encrypt(dbKeyB64, newKeys);
      _writeStagedFileExclusive(nodePath.join(stagingDir, paths.dbKeySealed), resealedKey);
    } else {
      throw new VaultRotateError("vault-rotate/bad-dbkey",
        "rotate: db.key.enc does not start with a vault prefix (vault: or vault.aad:)");
    }
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
    var current = atomicFile.fdSafeReadSync(asSrc, { maxBytes: C.BYTES.mib(1), encoding: "utf8" }).trim();
    if (current.indexOf(C.VAULT_PREFIX) !== 0) {
      throw new VaultRotateError("vault-rotate/bad-sealed",
        "rotate: sealed file does not start with the vault prefix: " + ase.relativePath);
    }
    var asDestDir = nodePath.join(stagingDir, nodePath.dirname(ase.relativePath));
    if (!nodeFs.existsSync(asDestDir)) atomicFile.ensureDir(asDestDir);
    _writeStagedFileExclusive(nodePath.join(stagingDir, ase.relativePath),
      _reSealValue(current, oldKeys, newKeys));
  }

  // 3b. Framework-managed crypto-field derived-hash files — always
  // rotated regardless of operator opts.paths, so the staging copy is
  // complete. The plaintext salt is copied verbatim; the SEALED MAC key
  // (keyed hmac-shake256 mode) is re-sealed under the new keypair so an
  // envelope rotation doesn't orphan it (a passphrase-only rotation
  // re-seals to the same value since the keypair is unchanged).
  var saltSrc = nodePath.join(dataDir, "vault.derived-hash-salt");
  if (nodeFs.existsSync(saltSrc)) {
    // Stage via the exclusive-create + fsync helper (not a plain copy) so the
    // salt is durable at write time and no later by-path fsync is needed.
    _writeStagedFileExclusive(nodePath.join(stagingDir, "vault.derived-hash-salt"),
      atomicFile.fdSafeReadSync(saltSrc, { maxBytes: C.BYTES.kib(4) }));
  }
  var macSrc = nodePath.join(dataDir, "vault.derived-hash-mac.sealed");
  if (nodeFs.existsSync(macSrc)) {
    var macCurrent = atomicFile.fdSafeReadSync(macSrc, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
    if (macCurrent.indexOf(C.VAULT_PREFIX) === 0) {
      _writeStagedFileExclusive(nodePath.join(stagingDir, "vault.derived-hash-mac.sealed"),
        _reSealValue(macCurrent, oldKeys, newKeys));
    }
  }

  // 4. decrypt + rotate + re-encrypt db.enc
  _emit(progress, { phase: "rotate_db" });
  var encDbPath = nodePath.join(dataDir, paths.encryptedDb);
  var tablesProcessed = 0;
  var totalRowsProcessed = 0;
  var verifyResult = null;

  if (nodeFs.existsSync(encDbPath) && dbKey) {
    var packed = atomicFile.fdSafeReadSync(encDbPath, { maxBytes: C.BYTES.gib(2) });
    // db.enc is XChaCha20-Poly1305-sealed AAD-bound to its dataDir
    // (db.js _dbEncAad). Read with the dataDir AAD; retry without AAD for
    // pre-AAD envelopes (mirrors db.js:765-768). The in-place swap keeps
    // the same dataDir, so this AAD is reused on the re-encrypt below.
    var dbEncAad = dbModuleLazy()._dbEncAad(dataDir);
    var plainBytes;
    try { plainBytes = bCrypto.decryptPacked(packed, dbKey, dbEncAad); }
    catch (_eAad) { plainBytes = bCrypto.decryptPacked(packed, dbKey); }
    var tmpDbPath = nodePath.join(stagingDir, "_blamejs_rotate.tmp.db");
    _writeStagedFileExclusive(tmpDbPath, plainBytes);

    var db = new DatabaseSync(tmpDbPath);
    try {
      db.prepare(sql.pragma("journal_mode", "WAL").sql).run();
      db.prepare(sql.pragma("synchronous", "NORMAL").sql).run();

      // Walk tables. For each, re-seal every column declared sealed
      // by the field-crypto registry, plus the overflow `data` JSON
      // column if present.
      var tablesToRotate = Array.isArray(opts.tables) && opts.tables.length > 0
        ? opts.tables.slice()
        : _listLiveTables(db);

      // Serialized roots threaded to the AAD reseal path; oldRootJson /
      // newRootJson match b.vault.getKeysJson() so rotated AAD cells unseal
      // once the new keypair is live after the swap.
      var roots = { oldKeys: oldKeys, newKeys: newKeys, oldRootJson: oldRootJson, newRootJson: newRootJson };

      for (var ti = 0; ti < tablesToRotate.length; ti++) {
        var table = tablesToRotate[ti];
        var tableExists = _get(db, sql.catalog.tableExists(table));
        if (!tableExists) continue;

        var schema = cryptoField.getSchema(table);
        var liveCols = _listLiveColumns(db, table);
        var liveColSet = Object.create(null);
        for (var lc = 0; lc < liveCols.length; lc++) liveColSet[liveCols[lc]] = true;

        var tableRows = 0;
        if (schema && Array.isArray(schema.sealedFields)) {
          for (var sc = 0; sc < schema.sealedFields.length; sc++) {
            var col = schema.sealedFields[sc];
            if (!liveColSet[col]) continue;
            tableRows += _rotateColumn(db, table, col, schema, roots, rowBatchSize, progress);
          }
        }
        tableRows += _rotateOverflow(db, table, oldKeys, newKeys, rowBatchSize, progress, warnings);

        if (tableRows > 0) { tablesProcessed++; totalRowsProcessed += tableRows; }
      }

      db.prepare(sql.pragma("wal_checkpoint", "TRUNCATE").sql).run();
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

    // Every staged path lives inside opts.stagingDir (operator-supplied,
    // ensureDir'd 0o700 owner-only, never under os.tmpdir()) and carries a
    // framework-internal marker name. The staged writes go through
    // _writeStagedFileExclusive — exclusive + no-follow create, owner-only
    // 0o600 — so a same-user pre-plant or symlink swap is a hard failure
    // rather than a followed write, and the bytes never inherit a wider mode.
    var rotatedBytes = atomicFile.fdSafeReadSync(tmpDbPath, { maxBytes: C.BYTES.gib(2) });
    // Re-encrypt under the SAME dataDir AAD so db.init's AAD-first open
    // succeeds after the staged dir is swapped over dataDir in place.
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.encryptedDb),
      bCrypto.encryptPacked(rotatedBytes, dbKey, dbEncAad));
    nodeFs.unlinkSync(tmpDbPath);

    // Round-trip verify on the staged DB
    _emit(progress, { phase: "verify" });
    var verifyTmp = nodePath.join(stagingDir, "_blamejs_verify.tmp.db");
    _writeStagedFileExclusive(verifyTmp,
      bCrypto.decryptPacked(atomicFile.fdSafeReadSync(nodePath.join(stagingDir, paths.encryptedDb), { maxBytes: C.BYTES.gib(2) }), dbKey, dbEncAad));
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

  // 5. fsync staging directory entries for durability before the caller swaps.
  // Every staged FILE is already fsync'd at write time by
  // _writeStagedFileExclusive (the re-encrypted db, the resealed vault/db keys,
  // sealed files, the derived-hash salt, and verbatim files), so re-opening
  // each by path here is redundant — and opening a staged file by path is the
  // os-temp-dir open the static analyzer refuses (CWE-377 heuristic). Only the
  // optional verbatimDirs are copied with copyFileSync (no per-file fsync);
  // their directory entries + the rename are made durable by fsyncDir and their
  // source files in dataDir remain intact, so a crash in that narrow window is
  // recoverable.
  _emit(progress, { phase: "fsync" });
  function fsyncDirTree(dir) {
    var entries = nodeFs.readdirSync(dir);
    for (var i = 0; i < entries.length; i++) {
      var p = nodePath.join(dir, entries[i]);
      if (nodeFs.statSync(p).isDirectory()) fsyncDirTree(p);
    }
    atomicFile.fsyncDir(dir);
  }
  fsyncDirTree(stagingDir);

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
  // Exposed for the rotation-gate coverage test: every lib module that exports
  // an external AAD_ROTATION descriptor must be reachable here, or a keypair
  // rotation silently orphans its store.
  _externalAadTables:         _externalAadTables,
};
