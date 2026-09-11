// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var atomicFile = require("./atomic-file");
var clusterStorage = require("./cluster-storage");
var frameworkSchema = require("./framework-schema");
var safeAsync = require("./safe-async");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var observability = require("./observability");

// Lazy to break the db-schema -> compliance -> (audit/db) load chain.
// resolveDriftMode reads the globally-pinned posture so a regulated
// deployment refuses to boot under undeclared schema drift by default.
var compliance = lazyRequire(function () { return require("./compliance"); });

function runSql(database, sql) { return database["exec"](sql); }

function runSqlOnHandle(db, sql) {
  if (db && typeof db["exec"] === "function") return db["exec"](sql);
  if (db && typeof db["runSql"] === "function") return db["runSql"](sql);
  throw new Error("dbSchema.runSqlOnHandle: handle exposes no DDL runner (exec / runSql)");
}

function runInTransaction(db, fn, opts) {
  if (typeof fn !== "function") {
    throw new TypeError("dbSchema.runInTransaction: fn must be a function");
  }
  opts = opts || {};
  var beginSql = opts.lockMode ? "BEGIN " + opts.lockMode : "BEGIN";
  runSqlOnHandle(db, beginSql);
  try {
    var result = fn();
    runSqlOnHandle(db, "COMMIT");
    return result;
  } catch (e) {
    try { runSqlOnHandle(db, "ROLLBACK"); }
    catch (rollbackErr) {
      safeAsync.safeInvoke(opts.onRollbackFail, rollbackErr);
    }
    throw e;
  }
}

async function runInTransactionAsync(db, fn, opts) {
  if (typeof fn !== "function") {
    throw new TypeError("dbSchema.runInTransactionAsync: fn must be a function");
  }
  opts = opts || {};
  var beginSql = opts.lockMode ? "BEGIN " + opts.lockMode : "BEGIN";
  runSqlOnHandle(db, beginSql);
  try {
    var result = await fn();
    runSqlOnHandle(db, "COMMIT");
    return result;
  } catch (e) {
    try { runSqlOnHandle(db, "ROLLBACK"); }
    catch (rollbackErr) {
      safeAsync.safeInvoke(opts.onRollbackFail, rollbackErr);
    }
    throw e;
  }
}

var MIGRATIONS_TABLE = "_blamejs_migrations";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName
function _migrationsTable() { return frameworkSchema.tableName(MIGRATIONS_TABLE); }
var _SQL_OPTS = { dialect: "sqlite", quoteName: true };

function ensureMigrationsTable(database) {
  runSql(database, sql.createTable(_migrationsTable(), [
    { name: "name",        type: "text", primaryKey: true },
    { name: "description", type: "text" },
    { name: "appliedAt",   type: "text", notNull: true },
  ], _SQL_OPTS).sql);
}

function reconcile(database, schema, opts) {
  if (!Array.isArray(schema)) {
    throw new Error("db.init({ schema }) must be an array of table definitions");
  }
  var driftMode = resolveDriftMode(opts);
  var report = { tables: [], drifted: false };
  for (var i = 0; i < schema.length; i++) {
    var tableReport = reconcileTable(database, schema[i], { onDrift: driftMode });
    if (tableReport.drift) {
      report.tables.push(tableReport.drift);
      report.drifted = true;
    }
  }
  return report;
}

function reconcileTable(database, table, opts) {
  if (!table || !table.name) {
    throw new Error("schema entry missing required 'name' property");
  }
  if (!table.columns || typeof table.columns !== "object") {
    throw new Error("schema entry '" + table.name + "' missing 'columns' object");
  }
  var driftMode = resolveDriftMode(opts);
  var dialect = _handleDialect(database);
  function q(ident) { return safeSql.quoteIdentifier(ident, dialect, { allowReserved: true }); }

  var name = table.name;
  validateIdent(name, "table name");

  var colDefs = [];
  for (var col in table.columns) {
    validateIdent(col, "column name");
    colDefs.push(q(col) + " " + table.columns[col]);
  }
  if (colDefs.length === 0) {
    throw new Error("schema entry '" + name + "' has no columns");
  }

  if (table.primaryKey) {
    var pkCols = Array.isArray(table.primaryKey) ? table.primaryKey : [table.primaryKey];
    pkCols.forEach(function (c) { validateIdent(c, "primary key column"); });
    pkCols.forEach(function (c) {
      if (!Object.prototype.hasOwnProperty.call(table.columns, c)) {
        throw new Error("primaryKey '" + c + "' is not declared in columns of table '" + name + "'");
      }
    });
    colDefs.push("PRIMARY KEY (" + pkCols.map(function (c) { return q(c); }).join(", ") + ")");
  }

  if (Array.isArray(table.foreignKeys)) {
    for (var fi = 0; fi < table.foreignKeys.length; fi++) {
      var fk = table.foreignKeys[fi];
      if (!fk || !fk.column || !fk.references) {
        throw new Error("foreignKey on table '" + name + "' requires { column, references }");
      }
      var localCols = Array.isArray(fk.column) ? fk.column : [fk.column];
      var refStr = String(fk.references);
      var dotIdx = refStr.indexOf(".");
      if (dotIdx <= 0) {
        throw new Error("foreignKey 'references' must be 'table.column' (or 'table.col1,col2' for composite): " + refStr);
      }
      var refTable = refStr.slice(0, dotIdx);
      var refColsStr = refStr.slice(dotIdx + 1);
      var refCols = refColsStr.split(",").map(function (s) { return s.trim(); });
      validateIdent(refTable, "foreign key referenced table");
      localCols.forEach(function (c) { validateIdent(c, "foreign key local column"); });
      refCols.forEach(function (c) { validateIdent(c, "foreign key referenced column"); });
      if (localCols.length !== refCols.length) {
        throw new Error("foreignKey on '" + name + "': local-column count must match referenced-column count");
      }
      var clause = "FOREIGN KEY (" + localCols.map(function (c) { return q(c); }).join(", ") + ")" +
        " REFERENCES " + q(refTable) + " (" + refCols.map(function (c) { return q(c); }).join(", ") + ")";
      if (fk.onDelete) clause += " ON DELETE " + _validateAction(fk.onDelete, "ON DELETE", name);
      if (fk.onUpdate) clause += " ON UPDATE " + _validateAction(fk.onUpdate, "ON UPDATE", name);
      colDefs.push(clause);
    }
  }

  runSql(database, safeSql.assertSingleStatement(
    // allow:hand-rolled-sql — operator verbatim column DDL + composite FK clauses outside b.sql.createTable's structured API
    "CREATE TABLE IF NOT EXISTS " + q(name) + " (" + colDefs.join(", ") + ")",
    { label: "schema.reconcile" }));

  var existingCols = listColumns(database, name);
  for (var newCol in table.columns) {
    if (!existingCols.has(newCol)) {
      try {
        runSql(database, safeSql.assertSingleStatement(
          // allow:hand-rolled-sql — operator verbatim ADD COLUMN DDL (validated + quoted identifier); type string is operator-controlled
          "ALTER TABLE " + q(name) + " ADD COLUMN " + q(newCol) + " " + table.columns[newCol],
          { label: "schema.reconcile" }));
      } catch (e) {
        throw new Error("failed to add column '" + newCol + "' to '" + name + "': " + e.message);
      }
    }
  }

  if (Array.isArray(table.indexes)) {
    for (var k = 0; k < table.indexes.length; k++) {
      reconcileIndex(database, name, table.indexes[k]);
    }
  }

  if (driftMode !== "ignore") {
    var drift = _detectColumnDrift(database, name, table.columns);
    if (drift) {
      if (driftMode === "refuse") {
        throw new Error(_driftMessage(name, drift));
      }
      // "warn": record the drift on the drop-silent observability sink.
      observability.safeEvent("db.schema.drift", 1, {
        table:        name,
        extraCount:   String(drift.extra.length),
        missingCount: String(drift.missing.length),
      });
      return { drift: drift };
    }
  }
  return { drift: null };
}

function _detectColumnDrift(database, tableName, declaredColumns) {
  var liveCols = listColumns(database, tableName);
  var declaredSet = new Set();
  for (var col in declaredColumns) {
    if (Object.prototype.hasOwnProperty.call(declaredColumns, col)) declaredSet.add(col);
  }
  var extra = [];
  liveCols.forEach(function (c) { if (!declaredSet.has(c)) extra.push(c); });
  var missing = [];
  declaredSet.forEach(function (c) { if (!liveCols.has(c)) missing.push(c); });
  if (extra.length === 0 && missing.length === 0) return null;
  extra.sort();
  missing.sort();
  return { table: tableName, extra: extra, missing: missing };
}

function _driftMessage(tableName, drift) {
  var parts = [];
  if (drift.extra.length) {
    parts.push("undeclared column(s) [" + drift.extra.join(", ") + "]");
  }
  if (drift.missing.length) {
    parts.push("missing declared column(s) [" + drift.missing.join(", ") + "]");
  }
  return "schema drift on table '" + tableName + "': " + parts.join("; ") +
    " (onDrift: 'refuse')";
}

function _validateAction(action, label, tableName) {
  var allowed = ["CASCADE", "SET NULL", "SET DEFAULT", "RESTRICT", "NO ACTION"];
  var up = String(action).toUpperCase();
  if (allowed.indexOf(up) === -1) {
    throw new Error(label + " on '" + tableName + "' must be one of " + allowed.join(", ") + " (got: " + action + ")");
  }
  return up;
}

var DRIFT_MODES = ["ignore", "warn", "refuse"];

var REGULATED_DRIFT_REFUSE = Object.freeze({
  "hipaa": true, "pci-dss": true, "gdpr": true, "soc2": true,
  "iso-27001-2022": true, "dora": true, "fedramp-rev5-moderate": true,
  "nist-800-53": true, "nist-800-53-r5-privacy": true, "dpdp": true,
  "lgpd-br": true, "pipl-cn": true, "uk-gdpr": true,
});

function _pinnedRegulatedDrift() {
  try {
    var pinned = compliance().current();
    if (typeof pinned === "string" && REGULATED_DRIFT_REFUSE[pinned] === true) {
      return "refuse";
    }
  } catch (_e) { /* compliance unavailable — fall through to back-compat */ }
  return "ignore";
}

function resolveDriftMode(opts) {
  if (!opts || opts.onDrift === undefined || opts.onDrift === null) {
    return _pinnedRegulatedDrift();
  }
  var mode = opts.onDrift;
  if (typeof mode !== "string" || DRIFT_MODES.indexOf(mode) === -1) {
    throw new TypeError(
      "db reconcile: onDrift must be one of " + DRIFT_MODES.join(", ") +
      " (got: " + (typeof mode === "string" ? "'" + mode + "'" : typeof mode) + ")");
  }
  return mode;
}

function reconcileIndex(database, tableName, idx) {
  var cols, indexName, unique;
  if (typeof idx === "string") {
    cols = [idx];
    indexName = "idx_" + tableName + "_" + idx;
    unique = false;
  } else if (idx && typeof idx === "object") {
    cols = Array.isArray(idx.columns) ? idx.columns : [idx.columns];
    indexName = idx.name || ("idx_" + tableName + "_" + cols.join("_"));
    unique = !!idx.unique;
  } else {
    throw new Error("invalid index spec on table '" + tableName + "'");
  }
  validateIdent(indexName, "index name");
  cols.forEach(function (c) { validateIdent(c, "indexed column"); });
  var dialect = _handleDialect(database);
  function q(ident) { return safeSql.quoteIdentifier(ident, dialect, { allowReserved: true }); }
  var quotedCols = cols.map(function (c) { return q(c); }).join(", ");
  if (dialect === "mysql") {
    try {
      runSql(database,
        "CREATE " + (unique ? "UNIQUE " : "") + "INDEX " + q(indexName) +
        " ON " + q(tableName) + " (" + quotedCols + ")");
    } catch (e) {
      if (!clusterStorage.duplicateIndexCode(e)) throw e;
    }
    return;
  }
  runSql(database,
    "CREATE " + (unique ? "UNIQUE " : "") + "INDEX IF NOT EXISTS " + q(indexName) +
    " ON " + q(tableName) + " (" + quotedCols + ")"
  );
}

function handleDialect(database) {
  var d = database && database.dialect;
  if (d === "postgres" || d === "mysql" || d === "sqlite") return d;
  return "sqlite";
}
var _handleDialect = handleDialect;

function sqlOpts(database) {
  return { dialect: handleDialect(database), quoteName: true };
}

function keyTextType(database) {
  return handleDialect(database) === "mysql" ? "VARCHAR(191)" : "text";
}

function listColumns(database, tableName) {
  var dialect = _handleDialect(database);
  var set = new Set();
  if (dialect === "sqlite") {
    var rows = database.prepare('PRAGMA table_info("' + tableName + '")').all();
    for (var i = 0; i < rows.length; i++) set.add(rows[i].name);
    return set;
  }
  var infoSql = dialect === "mysql"
    // allow:hand-rolled-sql — static information_schema introspection, single bound param
    ? "SELECT column_name FROM information_schema.columns " +
      "WHERE table_schema = DATABASE() AND table_name = ?"
    // allow:hand-rolled-sql — Postgres branch, same static-introspection shape
    : "SELECT column_name FROM information_schema.columns " +
      "WHERE table_schema = current_schema() AND table_name = ?";
  var stmt = database.prepare(infoSql);
  var irows = stmt.all.apply(stmt, [tableName]);
  for (var j = 0; j < irows.length; j++) {
    var name = irows[j].column_name;
    if (name === undefined) name = irows[j].COLUMN_NAME;
    if (name !== undefined && name !== null) set.add(name);
  }
  return set;
}

function validateIdent(ident, kind) {
  if (typeof ident !== "string" ||
      ident.length === 0 ||
      ident.length > safeSql.MAX_IDENTIFIER_LENGTH ||
      !safeSql.isDefaultIdentifier(ident)) {
    throw new Error("invalid " + kind + ": '" + ident +
      "' (must be " + safeSql.DEFAULT_IDENTIFIER_SHAPE + ", length 1.." +
      safeSql.MAX_IDENTIFIER_LENGTH + ")");
  }
}

function runMigrations(database, migrationDir) {
  if (!migrationDir) return { applied: [], skipped: [] };

  ensureMigrationsTable(database);

  var files = atomicFile.listDir(migrationDir, {
    filter: function (f) { return /^\d+-.+\.js$/.test(f); },
  }).map(function (e) { return e.name; }).sort();

  var appliedSet = new Set();
  var namesQ = sql.select(_migrationsTable(), _SQL_OPTS).columns(["name"]).toSql();
  var namesStmt = database.prepare(namesQ.sql);
  namesStmt.all.apply(namesStmt, namesQ.params).forEach(function (r) {
    appliedSet.add(r.name);
  });

  var applied = [];
  var skipped = [];
  for (var i = 0; i < files.length; i++) {
    var file = files[i];
    if (appliedSet.has(file)) {
      skipped.push(file);
      continue;
    }
    var fullPath = nodePath.join(migrationDir, file);
    var mig;
    try {
      mig = require(fullPath);   // allow:dynamic-require-operator-module — operator-supplied migration
    } catch (e) {
      throw new Error("migration '" + file + "' failed to load: " + e.message);
    }
    if (!mig || typeof mig.up !== "function") {
      throw new Error("migration '" + file + "' must export an `up(db)` function");
    }

    try {
      runInTransaction(database, function () {
        mig.up(database);
        var insQ = sql.insert(_migrationsTable(), _SQL_OPTS)
          .values({ name: file, description: mig.description || "",
                    appliedAt: new Date().toISOString() }).toSql();
        var insStmt = database.prepare(insQ.sql);
        insStmt.run.apply(insStmt, insQ.params);
      });
    } catch (e) {
      throw new Error("migration '" + file + "' failed: " + e.message);
    }
    applied.push(file);
  }

  return { applied: applied, skipped: skipped };
}

module.exports = {
  reconcile:        reconcile,
  reconcileTable:   reconcileTable,
  runMigrations:    runMigrations,
  validateIdent:    validateIdent,
  runSql:           runSql,
  runSqlOnHandle:   runSqlOnHandle,
  runInTransaction: runInTransaction,
  runInTransactionAsync: runInTransactionAsync,
  handleDialect:    handleDialect,
  sqlOpts:          sqlOpts,
  keyTextType:      keyTextType,
  listColumns:      listColumns,
  MIGRATIONS_TABLE: MIGRATIONS_TABLE,
  DRIFT_MODES:      DRIFT_MODES,
};
