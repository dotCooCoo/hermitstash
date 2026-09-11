// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  var tablesToCheck = Array.isArray(opts.tables) && opts.tables.length > 0
    ? opts.tables.slice()
    : null;

  var warnings = [];
  var errors   = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = Object.create(null);
  for (var lt = 0; lt < liveTables.length; lt++) liveTableSet[liveTables[lt]] = true;

  var allTables = tablesToCheck || liveTables;

  for (var t = 0; t < allTables.length; t++) {
    var table = allTables[t];

    if (!liveTableSet[table]) {
      warnings.push({
        kind:    "table_missing",
        table:   table,
        message: "schema lists table '" + table + "' but the live DB has no such table (skipped during rotation)",
      });
      continue;
    }

    var schema = cryptoField.getSchema(table);
    var liveCols = _listLiveColumns(db, table);
    var liveColSet = Object.create(null);
    for (var c = 0; c < liveCols.length; c++) liveColSet[liveCols[c]] = true;

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

    var sampled = _all(db, sql.catalog.sampleRandom(table, null, { limit: sampleN }));

    var foundOldFail = !oldKeys;
    var verifiedRows = 0;

    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      var rowFailed = false;

      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        var v = row[col];
        if (typeof v !== "string") continue;

        if (vaultAad.isAadSealed(v)) {
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
            foundOldFail = true;
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

var ROW_BATCH_SIZE_DEFAULT = 0x3E8;
var VAULT_PREFIX_LEN = C.VAULT_PREFIX.length;

var EXTERNAL_AAD_MODULE_LOADERS = [
  agentIdempotencyLazy, agentOrchestratorLazy, agentTenantLazy, agentSnapshotLazy,
  archiveWrapLazy, dsrLazy,
];

function _externalAadTables() {
  var tables = [];
  for (var i = 0; i < EXTERNAL_AAD_MODULE_LOADERS.length; i += 1) {
    var mod;
    try { mod = EXTERNAL_AAD_MODULE_LOADERS[i](); }
    catch (_e) { continue; }
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

function _writeStagedFileExclusive(p, data) {
  atomicFile.writeExclSync(p, data, { fileMode: 0o600 });
}

function _reSealValue(sealedValue, oldKeys, newKeys) {
  if (typeof sealedValue !== "string") return sealedValue;
  if (sealedValue.indexOf(C.VAULT_PREFIX) !== 0) return sealedValue;
  var payload = sealedValue.substring(VAULT_PREFIX_LEN);
  var plain = bCrypto.decrypt(payload, oldKeys);
  return C.VAULT_PREFIX + bCrypto.encrypt(plain, newKeys);
}

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
  var total = _get(db, sql.select(table, { dialect: "sqlite", quoteName: true })
    .count("*", "n").whereNotNull(column).toSql()).n;
  if (total === 0) return 0;

  var aadMode = !!(schema && schema.aad);
  var rowIdField = aadMode ? schema.rowIdField : null;
  var needRid = aadMode && rowIdField && rowIdField !== "_id";

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
          var rowForAad = {};
          rowForAad[rowIdField] = needRid ? row[rowIdField] : row._id;
          var aad = cryptoField._aadParts(schema, table, column, rowForAad);
          upd.run(vaultAad.resealRoot(cellVal, aad, roots.oldRootJson, roots.newRootJson), row._id);
        } else if (cellVal.indexOf(C.VAULT_PREFIX) === 0) {
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

    dbSchema.runInTransaction(db, function () {
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var doc;
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

  _emit(progress, { phase: "write_vault_key" });
  var keysJson = JSON.stringify(newKeys, null, 2);
  var oldRootJson = JSON.stringify(oldKeys, null, 2);
  var newRootJson = keysJson;
  if (mode === "wrapped") {
    var sealed = await vaultWrap().wrap(keysJson, opts.newPassphrase);
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.vaultKeySealed), sealed);
  } else {
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.vaultKeyPlain), keysJson);
  }

  _emit(progress, { phase: "reseal_files" });
  var dbKeySealedPath = nodePath.join(dataDir, paths.dbKeySealed);
  var dbKey = null;
  if (nodeFs.existsSync(dbKeySealedPath)) {
    var sealedKey = atomicFile.fdSafeReadSync(dbKeySealedPath, { maxBytes: C.BYTES.kib(64), encoding: "utf8" }).trim();
    if (vaultAad.isAadSealed(sealedKey)) {
      var dbKeyAad = dbModuleLazy()._dbKeyAad(dataDir, dbKeySealedPath);
      var dbKeyB64Aad = vaultAad.unsealRoot(sealedKey, dbKeyAad, oldRootJson);
      dbKey = Buffer.from(dbKeyB64Aad, "base64");
      var resealedAad = vaultAad.sealRoot(dbKeyB64Aad, dbKeyAad, newRootJson);
      _writeStagedFileExclusive(nodePath.join(stagingDir, paths.dbKeySealed), resealedAad);
    } else if (sealedKey.indexOf(C.VAULT_PREFIX) === 0) {
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

  var saltSrc = nodePath.join(dataDir, "vault.derived-hash-salt");
  if (nodeFs.existsSync(saltSrc)) {
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

  _emit(progress, { phase: "rotate_db" });
  var encDbPath = nodePath.join(dataDir, paths.encryptedDb);
  var tablesProcessed = 0;
  var totalRowsProcessed = 0;
  var verifyResult = null;

  if (nodeFs.existsSync(encDbPath) && dbKey) {
    var packed = atomicFile.fdSafeReadSync(encDbPath, { maxBytes: C.BYTES.gib(2) });
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

      var tablesToRotate = Array.isArray(opts.tables) && opts.tables.length > 0
        ? opts.tables.slice()
        : _listLiveTables(db);

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

    try { nodeFs.unlinkSync(tmpDbPath + "-wal"); }
    catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: tmpDbPath + "-wal", error: e.message }); }
    try { nodeFs.unlinkSync(tmpDbPath + "-shm"); }
    catch (e) { rotateLog.debug("cleanup-failed", { op: "fs.unlinkSync", path: tmpDbPath + "-shm", error: e.message }); }

    var rotatedBytes = atomicFile.fdSafeReadSync(tmpDbPath, { maxBytes: C.BYTES.gib(2) });
    _writeStagedFileExclusive(nodePath.join(stagingDir, paths.encryptedDb),
      bCrypto.encryptPacked(rotatedBytes, dbKey, dbEncAad));
    nodeFs.unlinkSync(tmpDbPath);

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
  DEFAULT_DRIFT_SAMPLE_LIMIT: DEFAULT_DRIFT_SAMPLE_LIMIT,
  DEFAULT_VERIFY_SAMPLE_MIN:  DEFAULT_VERIFY_SAMPLE_MIN,
  DEFAULT_VERIFY_SAMPLE_FRAC: DEFAULT_VERIFY_SAMPLE_FRAC,
  ROW_BATCH_SIZE_DEFAULT:     ROW_BATCH_SIZE_DEFAULT,
  _externalAadTables:         _externalAadTables,
};
