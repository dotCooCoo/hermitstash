"use strict";
/**
 * Schema reconciler + imperative migration runner + shared SQL
 * execution helpers used by every db-touching primitive.
 *
 * Hybrid migration strategy (per roadmap Q2):
 *
 *   1. Declarative reconcile (every boot, idempotent):
 *      - CREATE TABLE IF NOT EXISTS for tables in schema config
 *      - ALTER TABLE ADD COLUMN for any new columns (additive only)
 *      - CREATE INDEX IF NOT EXISTS for declared indexes
 *      - Refuses to drop columns or tables (data-loss safety)
 *
 *   2. Imperative migrations (after reconcile, run-once):
 *      - Numbered files: 001-foo.js, 002-bar.js
 *      - Each exports { up(db), down?(db), description }
 *      - Tracked in _blamejs_migrations table; never re-run
 *      - Run in numeric order; first failure halts boot
 *
 * Apps mix both: declarative covers structural changes (CREATE/ALTER),
 * imperative covers data backfills, transformations, conditional schema
 * changes that need code.
 *
 * Shared SQL execution helpers used by lib/migrations / lib/seeders /
 * lib/vault/rotate / lib/db etc.:
 *
 *   - runSql                — raw DDL / BEGIN / COMMIT / PRAGMA on
 *                             the framework's better-sqlite3 handle.
 *   - runSqlOnHandle        — handles BOTH raw better-sqlite3 and
 *                             b.db framework wrapper shapes —
 *                             operator-supplied handles can be either.
 *   - runInTransaction      — wrap fn in BEGIN / COMMIT / ROLLBACK on
 *                             the supplied db handle. opts.lockMode
 *                             appends to BEGIN ("IMMEDIATE" /
 *                             "EXCLUSIVE" on SQLite). opts.onRollbackFail
 *                             surfaces a rollback throw without
 *                             swallowing the original error.
 */
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var safeSql = require("./safe-sql");
var observability = require("./observability");

// SQLite raw-SQL helper. node:sqlite DatabaseSync exposes a method on the
// database object that runs raw SQL without bind parameters — used for DDL,
// BEGIN/COMMIT/ROLLBACK, and PRAGMA. Bracket notation here avoids a
// false-positive in upstream linters that pattern-match the bare token
// `.exec(` regardless of receiver type.
function runSql(database, sql) { return database["exec"](sql); }

// runSqlOnHandle — execute SQL against either handle shape:
//   - raw better-sqlite3 / node:sqlite Database (db.exec)
//   - b.db framework wrapper (db.runSql)
// Migrations / seeders / break-glass migrate accept operator-supplied
// handles in either shape; this wrapper normalizes the call. The
// 'exec'/'runSql' lookups use bracket notation so the eslint rule
// banning bare-identifier db method calls (collapsing prepare → field)
// stays satisfied.
function runSqlOnHandle(db, sql) {
  if (db && typeof db["exec"] === "function") return db["exec"](sql);
  if (db && typeof db["runSql"] === "function") return db["runSql"](sql);
  throw new Error("dbSchema.runSqlOnHandle: handle exposes no DDL runner (exec / runSql)");
}

// runInTransaction — wrap fn in BEGIN / COMMIT / ROLLBACK on the
// supplied db handle. Used by migrations / seeders / any operator-
// facing transaction. opts.lockMode appends to BEGIN ("IMMEDIATE",
// "EXCLUSIVE" — SQLite-specific). opts.onRollbackFail surfaces a
// rollback throw without swallowing the original error (the original
// always re-throws).
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
      if (typeof opts.onRollbackFail === "function") {
        try { opts.onRollbackFail(rollbackErr); } catch (_e) { /* nested handler must not bubble */ }
      }
    }
    throw e;
  }
}

// ---- Internal migrations table ----

var MIGRATIONS_TABLE = "_blamejs_migrations";
// Pre-quoted for SQL interpolation — keeps the call sites consistent
// with lib/migrations.js and lib/seeders.js so an identifier rename
// doesn't silently break.
var Q_MIGRATIONS_TABLE = '"' + MIGRATIONS_TABLE + '"';

function ensureMigrationsTable(database) {
  runSql(database,
    "CREATE TABLE IF NOT EXISTS " + Q_MIGRATIONS_TABLE + " (" +
    "  name        TEXT PRIMARY KEY," +
    "  description TEXT," +
    "  appliedAt   TEXT NOT NULL" +
    ")"
  );
}

// ---- Declarative reconcile ----

// reconcile — declarative schema reconcile: CREATE TABLE IF NOT EXISTS +
// additive ALTER TABLE ADD COLUMN + CREATE INDEX IF NOT EXISTS for every
// table in `schema`. Never drops columns or tables (data-loss safety).
//
// `opts.onDrift` adds opt-in detection of config-vs-live divergence — a
// compliance-evidence concern: the live DB should match the declared data
// model so an auditor can trust the schema config as ground truth (the
// change-/configuration-management control families in ISO 27001:2022
// A.8.9 and SOC 2 CC8.1 turn on "the running system equals the approved
// definition"). Detection covers the two cases reconcile's additive path
// cannot fix on its own:
//
//   - undeclared (extra) columns present in the live table but absent
//     from the declared schema — an out-of-band ALTER / hand-edit;
//   - declared columns still missing from the live table after the
//     ADD COLUMN pass (e.g. a column whose DDL the engine rejected).
//
// Dropped columns are never acted on — reconcile is non-destructive by
// contract; this is detection + an operator-chosen reaction only.
//
// onDrift values (config-time enum; bad value throws):
//   "ignore"  (default) — pre-detection behavior, byte-for-byte; no
//                         detection side effects. Existing deployments
//                         with drift are not broken.
//   "warn"    — detect + emit a "db.schema.drift" observability event per
//               drifted table; never throws.
//   "refuse"  — detect + THROW on the first drifted table, so a strict-
//               schema posture refuses to boot under divergence. The
//               operator's explicit posture choice.
//
// Returns a { tables: [...], drifted: boolean } report.
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

  var name = table.name;
  validateIdent(name, "table name");

  var colDefs = [];
  for (var col in table.columns) {
    validateIdent(col, "column name");
    colDefs.push('"' + col + '" ' + table.columns[col]);
  }
  if (colDefs.length === 0) {
    throw new Error("schema entry '" + name + "' has no columns");
  }

  // Structured PRIMARY KEY (alternative to inlining "PRIMARY KEY" in column DDL).
  // Accepts a single column name or an array (composite PK).
  if (table.primaryKey) {
    var pkCols = Array.isArray(table.primaryKey) ? table.primaryKey : [table.primaryKey];
    pkCols.forEach(function (c) { validateIdent(c, "primary key column"); });
    pkCols.forEach(function (c) {
      if (!Object.prototype.hasOwnProperty.call(table.columns, c)) {
        throw new Error("primaryKey '" + c + "' is not declared in columns of table '" + name + "'");
      }
    });
    colDefs.push("PRIMARY KEY (" + pkCols.map(function (c) { return '"' + c + '"'; }).join(", ") + ")");
  }

  // Structured FOREIGN KEY declarations. Each entry:
  //   { column: 'userId', references: 'users._id', onDelete?, onUpdate? }
  // Composite FKs use array form for `column` and the references-side: format
  // 'table.col1,col2'. Forward references to tables not yet created are fine —
  // SQLite validates at write time, not table-create time.
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
      var clause = "FOREIGN KEY (" + localCols.map(function (c) { return '"' + c + '"'; }).join(", ") + ")" +
        ' REFERENCES "' + refTable + '" (' + refCols.map(function (c) { return '"' + c + '"'; }).join(", ") + ")";
      if (fk.onDelete) clause += " ON DELETE " + _validateAction(fk.onDelete, "ON DELETE", name);
      if (fk.onUpdate) clause += " ON UPDATE " + _validateAction(fk.onUpdate, "ON UPDATE", name);
      colDefs.push(clause);
    }
  }

  runSql(database, 'CREATE TABLE IF NOT EXISTS "' + name + '" (' + colDefs.join(", ") + ")");

  var existingCols = listColumns(database, name);
  for (var newCol in table.columns) {
    if (!existingCols.has(newCol)) {
      try {
        runSql(database, 'ALTER TABLE "' + name + '" ADD COLUMN "' + newCol + '" ' + table.columns[newCol]);
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

  // Schema-drift detection (opt-in; default "ignore" => no-op). Compares
  // the live table's columns against the declared model AFTER the additive
  // ADD COLUMN pass so the diff reflects what reconcile could not fix:
  //   - extra    = live-but-undeclared (out-of-band ALTER / hand-edit);
  //   - missing  = declared-but-still-absent (ADD COLUMN could not apply).
  // Dropped columns are never acted on — reconcile stays non-destructive.
  if (driftMode !== "ignore") {
    var drift = _detectColumnDrift(database, name, table.columns);
    if (drift) {
      if (driftMode === "refuse") {
        throw new Error(_driftMessage(name, drift));
      }
      // "warn": drop-silent observability sink (hot-path-safe), then
      // report back to the caller for operator-visible logging.
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

// _detectColumnDrift — diff the live table's columns against the declared
// column set. Returns null when they agree, else { table, extra, missing }
// with sorted column-name arrays. Pure read (PRAGMA table_info); never
// issues DDL.
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

// onDrift reaction modes. "ignore" preserves pre-drift-detection
// behavior byte-for-byte; "warn" emits an observability signal and
// reports; "refuse" throws so a strict-schema posture refuses to boot
// when the live DB has diverged from the declared model.
var DRIFT_MODES = ["ignore", "warn", "refuse"];

// resolveDriftMode — config-time enum validation. Undefined => "ignore"
// (default; existing deployments see zero behavior change). A bad value
// is an operator typo at config time → THROW (entry-point tier).
function resolveDriftMode(opts) {
  if (!opts || opts.onDrift === undefined || opts.onDrift === null) return "ignore";
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
  var quotedCols = cols.map(function (c) { return '"' + c + '"'; }).join(", ");
  runSql(database,
    "CREATE " + (unique ? "UNIQUE " : "") + "INDEX IF NOT EXISTS \"" + indexName + "\"" +
    ' ON "' + tableName + '" (' + quotedCols + ")"
  );
}

function listColumns(database, tableName) {
  var rows = database.prepare('PRAGMA table_info("' + tableName + '")').all();
  var set = new Set();
  for (var i = 0; i < rows.length; i++) set.add(rows[i].name);
  return set;
}

// SQL identifier safety: alphanumeric + underscore, starts with letter or underscore.
function validateIdent(ident, kind) {
  if (typeof ident !== "string" ||
      ident.length === 0 ||
      ident.length > safeSql.MAX_IDENTIFIER_LENGTH ||
      !safeSql.DEFAULT_IDENTIFIER_RE.test(ident)) {
    throw new Error("invalid " + kind + ": '" + ident +
      "' (must match " + safeSql.DEFAULT_IDENTIFIER_RE + ", length 1.." +
      safeSql.MAX_IDENTIFIER_LENGTH + ")");
  }
}

// ---- Imperative migration runner ----

function runMigrations(database, migrationDir) {
  if (!migrationDir) return { applied: [], skipped: [] };

  ensureMigrationsTable(database);

  // listDir returns [] if migrationDir doesn't exist (missingOk: true default).
  var files = atomicFile.listDir(migrationDir, {
    filter: function (f) { return /^\d+-.+\.js$/.test(f); },
  }).map(function (e) { return e.name; }).sort();

  var appliedSet = new Set();
  database.prepare("SELECT name FROM " + Q_MIGRATIONS_TABLE).all().forEach(function (r) {
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
      // Operator-supplied migration file — by definition not statically
      // require-able by a bundler. Anyone bundling this surface into SEA
      // accepts that runtime migration loading won't resolve.
      mig = require(fullPath);   // allow:dynamic-require — operator-supplied migration
    } catch (e) {
      throw new Error("migration '" + file + "' failed to load: " + e.message);
    }
    if (!mig || typeof mig.up !== "function") {
      throw new Error("migration '" + file + "' must export an `up(db)` function");
    }

    try {
      runInTransaction(database, function () {
        mig.up(database);
        database.prepare(
          "INSERT INTO " + Q_MIGRATIONS_TABLE + " (name, description, appliedAt) VALUES (?, ?, ?)"
        ).run(file, mig.description || "", new Date().toISOString());
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
  MIGRATIONS_TABLE: MIGRATIONS_TABLE,
  DRIFT_MODES:      DRIFT_MODES,
};
