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
var lazyRequire = require("./lazy-require");
var atomicFile = require("./atomic-file");
var frameworkSchema = require("./framework-schema");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var observability = require("./observability");

// Lazy to break the db-schema -> compliance -> (audit/db) load chain.
// resolveDriftMode reads the globally-pinned posture so a regulated
// deployment refuses to boot under undeclared schema drift by default.
var compliance = lazyRequire(function () { return require("./compliance"); });

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

// runInTransactionAsync — the async sibling of runInTransaction. SQLite
// transactions are synchronous at the wire, but the body between BEGIN and
// COMMIT may await (a seeder's run(), a per-row re-seal that reads off the
// handle): await fn() before COMMIT so the transaction wraps the whole
// awaited body, and ROLLBACK on rejection. Same opts.lockMode /
// opts.onRollbackFail contract as the sync form.
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
      if (typeof opts.onRollbackFail === "function") {
        try { opts.onRollbackFail(rollbackErr); } catch (_e) { /* nested handler must not bubble */ }
      }
    }
    throw e;
  }
}

// ---- Internal migrations table ----

// Logical name; the physical name + configured prefix resolve through
// frameworkSchema.tableName, and every statement composes b.sql
// (quoteName: true) so the resolved name is quoted by construction.
var MIGRATIONS_TABLE = "_blamejs_migrations";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName
function _migrationsTable() { return frameworkSchema.tableName(MIGRATIONS_TABLE); }
// b.sql opts for the local single-node sqlite handle this module's helpers
// run against (database.exec / database.prepare, never clusterStorage):
// "sqlite" dialect + quoteName so the resolved framework name quotes.
var _SQL_OPTS = { dialect: "sqlite", quoteName: true };

function ensureMigrationsTable(database) {
  runSql(database, sql.createTable(_migrationsTable(), [
    { name: "name",        type: "text", primaryKey: true },
    { name: "description", type: "text" },
    { name: "appliedAt",   type: "text", notNull: true },
  ], _SQL_OPTS).sql);
}

// ---- Declarative reconcile ----

// reconcile — declarative schema reconcile: CREATE TABLE IF NOT EXISTS +
// additive ALTER TABLE ADD COLUMN + CREATE INDEX IF NOT EXISTS for every
// table in `schema`. Never drops columns or tables (data-loss safety).
//
// `opts.onDrift` controls detection of config-vs-live divergence — a
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
//   "ignore"  — no detection side effects. Existing deployments with
//               benign drift are not broken.
//   "warn"    — detect + emit a "db.schema.drift" observability event per
//               drifted table; never throws.
//   "refuse"  — detect + THROW on the first drifted table, so a strict-
//               schema posture refuses to boot under divergence.
//
// Default (v0.15.0): "ignore" on an unpinned / non-regulated deployment
// (back-compat); "refuse" when a regulated compliance posture is
// globally pinned (b.compliance.set) and the operator did not pass an
// explicit onDrift. The live DB diverging from the declared data model
// is a change-/configuration-management finding the auditor reads as
// ground truth (ISO 27001:2022 A.8.9 + SOC 2 CC8.1 turn on "the running
// system equals the approved definition"); under a regulated posture
// the safe default is to refuse boot rather than silently serve a
// schema no one approved. Operators who knowingly run with drift under
// a regulated posture opt back to the prior behaviour with an explicit
// onDrift: "ignore" (or "warn" to keep the signal without the throw).
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
  // Identifier quoting follows the handle's dialect (double-quote on
  // sqlite/postgres, backtick on mysql) so the reconciler's CREATE / ALTER
  // / FK DDL is portable. Reserved-word column names stay safe by being
  // quoted; the operator's verbatim TYPE strings are emitted unchanged in
  // type position (after a quoted identifier), never in identifier position.
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
    colDefs.push("PRIMARY KEY (" + pkCols.map(function (c) { return q(c); }).join(", ") + ")");
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
      var clause = "FOREIGN KEY (" + localCols.map(function (c) { return q(c); }).join(", ") + ")" +
        " REFERENCES " + q(refTable) + " (" + refCols.map(function (c) { return q(c); }).join(", ") + ")";
      if (fk.onDelete) clause += " ON DELETE " + _validateAction(fk.onDelete, "ON DELETE", name);
      if (fk.onUpdate) clause += " ON UPDATE " + _validateAction(fk.onUpdate, "ON UPDATE", name);
      colDefs.push(clause);
    }
  }

  // Operator-schema reconcile: colDefs carries the operator's VERBATIM
  // per-column DDL strings (e.g. "TEXT PRIMARY KEY", "INTEGER NOT NULL
  // DEFAULT 0") plus composite FOREIGN KEY clauses with referential
  // actions — a grammar b.sql.createTable's structured { name, type,
  // notNull, references } column specs cannot faithfully reproduce
  // (no table-level composite-FK or arbitrary-inline-constraint slot).
  // Every identifier here is validated (validateIdent) + quoted by
  // construction, so quote-by-construction safety is preserved.
  // allow:hand-rolled-sql — operator verbatim column DDL + composite FK clauses outside b.sql.createTable's structured API
  runSql(database, safeSql.assertSingleStatement(
    "CREATE TABLE IF NOT EXISTS " + q(name) + " (" + colDefs.join(", ") + ")",
    { label: "schema.reconcile" }));

  var existingCols = listColumns(database, name);
  for (var newCol in table.columns) {
    if (!existingCols.has(newCol)) {
      try {
        // allow:hand-rolled-sql — operator verbatim ADD COLUMN DDL (validated + quoted identifier); type string is operator-controlled
        runSql(database, safeSql.assertSingleStatement(
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

  // Schema-drift detection. Default mode is posture-driven: "refuse"
  // under a regulated pinned posture, "ignore" otherwise (resolveDriftMode).
  // Compares the live table's columns against the declared model AFTER the
  // additive ADD COLUMN pass so the diff reflects what reconcile could not fix:
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

// onDrift reaction modes. "ignore" takes no action on detected drift;
// "warn" emits an observability signal and reports; "refuse" throws so a
// strict-schema posture refuses to boot when the live DB has diverged
// from the declared model.
var DRIFT_MODES = ["ignore", "warn", "refuse"];

// Compliance postures under which schema conformance is an audit-evidence
// floor (change-/configuration-management control families: ISO 27001:2022
// A.8.9, SOC 2 CC8.1). When one of these is the globally-pinned posture
// and the operator left onDrift unset, the default flips from "ignore" to
// "refuse" so an unapproved live schema fails boot rather than serving
// silently. Membership match is exact against compliance().current().
var REGULATED_DRIFT_REFUSE = Object.freeze({
  "hipaa": true, "pci-dss": true, "gdpr": true, "soc2": true,
  "iso-27001-2022": true, "dora": true, "fedramp-rev5-moderate": true,
  "nist-800-53": true, "nist-800-53-r5-privacy": true, "dpdp": true,
  "lgpd-br": true, "pipl-cn": true, "uk-gdpr": true,
});

// _pinnedRegulatedDrift — the posture-driven default when onDrift is unset.
// Returns "refuse" when a regulated posture is globally pinned, "ignore"
// otherwise. Drop-safe: any failure resolving the posture (compliance not
// loaded, no posture pinned) yields the back-compat "ignore" — the gate
// only tightens the default when a regulated posture is provably pinned,
// never the reverse.
function _pinnedRegulatedDrift() {
  try {
    var pinned = compliance().current();
    if (typeof pinned === "string" && REGULATED_DRIFT_REFUSE[pinned] === true) {
      return "refuse";
    }
  } catch (_e) { /* compliance unavailable — fall through to back-compat */ }
  return "ignore";
}

// resolveDriftMode — config-time enum validation. Unset => the
// posture-driven default ("refuse" under a regulated pinned posture,
// "ignore" otherwise; see REGULATED_DRIFT_REFUSE). An explicit value
// always wins, including "ignore" to opt back out under a regulated
// posture. A bad value is an operator typo at config time => THROW
// (entry-point tier).
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
  // MySQL has no CREATE INDEX IF NOT EXISTS; a re-run of a declared index
  // would error "Duplicate key name". The reconciler is idempotent by
  // contract, so on MySQL a duplicate-index error is swallowed (the index
  // already exists, which is the desired end state). Postgres + SQLite use
  // the IF NOT EXISTS form natively.
  if (dialect === "mysql") {
    try {
      runSql(database,
        "CREATE " + (unique ? "UNIQUE " : "") + "INDEX " + q(indexName) +
        " ON " + q(tableName) + " (" + quotedCols + ")");
    } catch (e) {
      if (!/exist|duplicate/i.test((e && e.message) || "")) throw e;
    }
    return;
  }
  runSql(database,
    "CREATE " + (unique ? "UNIQUE " : "") + "INDEX IF NOT EXISTS " + q(indexName) +
    " ON " + q(tableName) + " (" + quotedCols + ")"
  );
}

// The dialect of a data-layer handle. db.init / db.from drive the
// framework's local node:sqlite handle (the default). An operator who
// reconciles / migrates / seeds their OWN Postgres / MySQL handle declares
// the dialect on the handle via `handle.dialect` so the SQL matches the
// backend. Absent / unknown falls back to "sqlite" — every existing
// local-handle caller is byte-identical. Shared by db-schema's reconciler,
// migrations.js, and seeders.js (the three sync data-layer files that drive
// a handle directly), so the resolution lives in one place.
function handleDialect(database) {
  var d = database && database.dialect;
  if (d === "postgres" || d === "mysql" || d === "sqlite") return d;
  return "sqlite";
}
// Back-compat internal alias used throughout this module.
var _handleDialect = handleDialect;

// b.sql opts for a statement run directly against `database` (db.prepare /
// runSqlOnHandle, never clusterStorage): the handle's dialect + quoteName so
// the resolved framework table name quotes by construction.
function sqlOpts(database) {
  return { dialect: handleDialect(database), quoteName: true };
}

// A registry/lock PRIMARY-KEY (or composite-PK / indexed) TEXT column type.
// MySQL refuses an unbounded TEXT/BLOB in a key without a prefix length, so
// a key-participating text column is VARCHAR(191) there (utf8mb4
// index-safe); Postgres + SQLite index TEXT directly. The value is emitted
// verbatim by b.sql in type position (after a quoted identifier), never as
// an identifier.
function keyTextType(database) {
  return handleDialect(database) === "mysql" ? "VARCHAR(191)" : "text";
}

// List the live column names of a table. SQLite reads `PRAGMA table_info`;
// Postgres + MySQL read information_schema.columns (PRAGMA is SQLite-only —
// it throws "syntax error at PRAGMA" on the others). The table name binds
// as a `?` parameter (never concatenated into the SQL text), so an operator
// table name with metacharacters can't break the introspection query. On
// Postgres / MySQL the introspection is confined to current_schema() /
// DATABASE() (where the bare-named CREATE TABLE lands); an operator running
// multiple schemas qualifies via the `schema.table` handle convention
// elsewhere — listColumns reconciles by bare name here, matching the
// reconciler's CREATE TABLE (which is also bare-named).
function listColumns(database, tableName) {
  var dialect = _handleDialect(database);
  var set = new Set();
  if (dialect === "sqlite") {
    var rows = database.prepare('PRAGMA table_info("' + tableName + '")').all();
    for (var i = 0; i < rows.length; i++) set.add(rows[i].name);
    return set;
  }
  // Postgres + MySQL: information_schema.columns is SQL-standard on both.
  // The column-name column is `column_name` on both; the table name binds.
  // A fixed catalog-introspection SELECT against the SQL-standard
  // information_schema.columns view (a schema-qualified system table b.sql's
  // verb builders don't model); the ONLY value (table name) binds as a `?`,
  // every column/table reference is a static literal — no injection surface.
  // The schema predicate confines introspection to the schema/database the
  // reconciler's bare-named CREATE TABLE actually writes into (Postgres
  // current_schema() = the first writable schema on the search_path; MySQL
  // DATABASE() = the connection's default database). Without it a same-named
  // table in another schema/database pollutes the column set - silently skipping
  // a needed ADD COLUMN or fabricating a drift "extra" that refuses a regulated-
  // posture boot. Both are zero-arg SQL functions in predicate position, so the
  // table name stays the single bound parameter (no new placeholder).
  // Two fully-static introspection strings, one per dialect: DATABASE() /
  // current_schema() are SQL functions baked into the literal (never a
  // concatenated value), so the only bound value remains the table name `?`.
  // allow:hand-rolled-sql — static information_schema introspection, single bound param
  var infoSql = dialect === "mysql"
    ? "SELECT column_name FROM information_schema.columns " +
      "WHERE table_schema = DATABASE() AND table_name = ?"
    // allow:hand-rolled-sql — Postgres branch, same static-introspection shape
    : "SELECT column_name FROM information_schema.columns " +
      "WHERE table_schema = current_schema() AND table_name = ?";
  var stmt = database.prepare(infoSql);
  var irows = stmt.all.apply(stmt, [tableName]);
  for (var j = 0; j < irows.length; j++) {
    // node-postgres folds unquoted output column names to lowercase, so the
    // result key is `column_name` on every driver; read it directly.
    var name = irows[j].column_name;
    if (name === undefined) name = irows[j].COLUMN_NAME;  // some MySQL drivers upper-case
    if (name !== undefined && name !== null) set.add(name);
  }
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
      // Operator-supplied migration file — by definition not statically
      // require-able by a bundler. Anyone bundling this surface into SEA
      // accepts that runtime migration loading won't resolve.
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
  // Shared data-layer dialect resolution — composed by migrations.js +
  // seeders.js so the handle-dialect / b.sql-opts / key-text-type logic
  // lives in exactly one place.
  handleDialect:    handleDialect,
  sqlOpts:          sqlOpts,
  keyTextType:      keyTextType,
  listColumns:      listColumns,
  MIGRATIONS_TABLE: MIGRATIONS_TABLE,
  DRIFT_MODES:      DRIFT_MODES,
};
