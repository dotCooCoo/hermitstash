"use strict";
/**
 * migrations — public migration runner with up / down / status.
 *
 * Wraps the schema-runner already inside lib/db-schema.js (which db.js
 * uses on init for forward-only auto-apply) and adds the rollback +
 * status surface operators want for ops workflows: CI applies pending
 * migrations, an emergency runbook rolls back the most-recent N, a
 * dashboard reports applied vs pending.
 *
 * Migration file format (filename pattern: NNNN-<slug>.js):
 *
 *   // migrations/0001-create-users.js
 *   module.exports = {
 *     description: "Create users table",
 *     up:   function (db) { db["exec"]("CREATE TABLE users ( ... )"); },
 *     down: function (db) { db["exec"]("DROP TABLE users"); },
 *   };
 *
 * `up` is required; `down` is optional. A migration without `down`
 * cannot be rolled back through this primitive — calling rollback on
 * it surfaces a clear error so the operator knows to write the
 * down-script (or restore from backup).
 *
 *   var migrations = b.migrations.create({
 *     db:  b.db,                       // optional; defaults to b.db
 *     dir: "./migrations",
 *   });
 *
 *   await migrations.up();             // → { applied, skipped }
 *   await migrations.down({ steps:1 }); // → { reverted }
 *   migrations.status();               // → { applied: [...], pending: [...] }
 *
 * Each migration runs inside a transaction; failure rolls back the
 * single migration and stops. _blamejs_migrations records:
 *   { name, description, appliedAt }
 * with `name` being the filename. Rollback removes the row after
 * down() succeeds.
 */

var nodePath = require("node:path");
var moduleLoader = require("./module-loader");
var atomicFile = require("./atomic-file");
var dbSchema = require("./db-schema");
var frameworkSchema = require("./framework-schema");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var migrationFiles = require("./migration-files");
var numericBounds = require("./numeric-bounds");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var db = lazyRequire(function () { return require("./db"); });
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

var log = boot("migrations");

class MigrationError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "MigrationError";
    this.permanent = !!permanent;
    this.isMigrationError = true;
  }
}

// Logical names; the physical names resolve through
// frameworkSchema.tableName so a configured table prefix flows here too.
// SQL is composed with b.sql (quoteName: true) so the resolved name is
// quoted by construction — a reserved-word / whitespace-bearing name
// still emits a valid `"..."` identifier.
var MIGRATIONS_TABLE = "_blamejs_migrations";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName below
function _migrationsTable() { return frameworkSchema.tableName(MIGRATIONS_TABLE); }
// b.sql opts for the migration bookkeeping statements. db.prepare /
// runSqlOnHandle run these directly against the handle (never
// clusterStorage), so the dialect must match the handle: db.from()'s local
// node:sqlite default, or an operator's own Postgres / MySQL handle (which
// declares `handle.dialect`). The handle-dialect / opts / key-text-type
// resolution is shared with db-schema's reconciler + seeders.js, so it is
// composed from db-schema rather than re-derived here. The historical
// default (sqlite) is byte-identical for every existing local-handle caller.
var _handleDialect = dbSchema.handleDialect;
var _sqlOpts = dbSchema.sqlOpts;
var _keyTextType = dbSchema.keyTextType;
// A ms-epoch column type. Date.now() exceeds a 32-bit INTEGER, so the
// lock timestamp needs a 64-bit type on Postgres + MySQL (BIGINT) — b.sql's
// logical "int" resolves to BIGINT on both and INTEGER on SQLite, so passing
// the logical name through the handle dialect is enough.
var _MS_EPOCH_TYPE = "int";
// Filename grammar: leading numeric prefix (any width), then '-', then a
// non-empty body, then '.js'. Numeric prefix orders execution. Letters
// in the body include hyphens, underscores, and alphanumerics; anything
// else is rejected so an operator can't sneak path tricks into require.
// Length capped before the regex test so a hostile directory listing
// can't drive the engine against an unbounded filename string.
var FILE_RE = migrationFiles.MIGRATION_FILE_RE;
var FILE_NAME_MAX = 255;

function _isMigrationFile(name) {
  return typeof name === "string" &&
         name.length > 0 &&
         name.length <= FILE_NAME_MAX &&
         FILE_RE.test(name);
}

// Bracket-notation wrapper for the SQLite handle's exec method. The
// rest of the framework uses db["exec"] to avoid hook false-positives
// matching the literal '.exec(' token; mirror that here.
var _runSql = dbSchema.runSqlOnHandle;

function _ensureTable(db) {
  _runSql(db, sql.createTable(_migrationsTable(), [
    { name: "name",        type: _keyTextType(db), primaryKey: true },
    { name: "description", type: "text" },
    { name: "appliedAt",   type: "text", notNull: true },
  ], _sqlOpts(db)).sql);
}

// Single-row advisory-lock table. Two processes running `migrate up`
// concurrently against the same DB race on this table: the winner of
// the INSERT acquires the lock; the loser sees a UNIQUE violation and
// the operator gets a clear "lock held by other process" error.
var LOCK_TABLE = "_blamejs_migrations_lock";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName below
function _lockTable() { return frameworkSchema.tableName(LOCK_TABLE); }

function _ensureLockTable(db) {
  // The single-row invariant (CHECK scope = 'lock') is a static,
  // framework-controlled column constraint — b.sql guards the verbatim
  // fragment (allowLiterals) and quotes the column by construction. The
  // CHECK references `scope` with the handle's identifier quoting (backtick
  // on mysql) so the constraint parses on every dialect. lockedAt is an
  // ms-epoch value (`int` → BIGINT on Postgres/MySQL, INTEGER on SQLite);
  // a 32-bit INTEGER would overflow Date.now() and make the lock
  // unacquirable on Postgres.
  var dialect = _handleDialect(db);
  var scopeCheck = "CHECK (" + safeSql.quoteIdentifier("scope", dialect, { allowReserved: true }) + " = 'lock')";
  _runSql(db, sql.createTable(_lockTable(), [
    { name: "scope",    type: _keyTextType(db), primaryKey: true, constraints: scopeCheck },
    { name: "lockedAt", type: _MS_EPOCH_TYPE,   notNull: true },
    { name: "lockedBy", type: "text",           notNull: true },
  ], _sqlOpts(db)).sql);
}

function _lockHolderId() {
  // process.pid + hostname identifies the process holding the lock;
  // a hung deploy can be diagnosed by checking the lock row's lockedBy.
  return String(process.pid) + "@" + (require("node:os").hostname() || "unknown");
}

function _acquireLock(db, opts) {
  _ensureLockTable(db);
  var holder = _lockHolderId();
  var nowMs = Date.now();
  // staleAfterMs gates whether an existing lock is considered stale.
  // 0 (the default) means "never replace — wait for the operator".
  // Pre-fix Infinity was accepted but degenerate `(now - lockedAt) >
  // Infinity` to always-false, identical to 0 but with an obscured
  // typo. Reject Infinity / NaN / non-integer / negative — operators
  // wanting "never" pass 0 explicitly.
  var staleAfterMs;
  if (!opts || opts.staleAfterMs === undefined) {
    staleAfterMs = 0;
  } else if (!numericBounds.isNonNegativeFiniteInt(opts.staleAfterMs)) {
    throw new Error("migrations.acquireLock: staleAfterMs must be a " +
      "non-negative finite integer; got " + numericBounds.shape(opts.staleAfterMs));
  } else {
    staleAfterMs = opts.staleAfterMs;
  }
  var insertLock = sql.insert(_lockTable(), _sqlOpts(db))
    .values({ scope: "lock", lockedAt: nowMs, lockedBy: holder }).toSql();
  // Try to insert; if there's a stale lock, optionally force-replace it.
  try {
    var insStmt = db.prepare(insertLock.sql);
    insStmt.run.apply(insStmt, insertLock.params);
    return holder;
  } catch {
    // PRIMARY KEY conflict → existing lock. Inspect it.
    var selExisting = sql.select(_lockTable(), _sqlOpts(db))
      .columns(["lockedAt", "lockedBy"]).where("scope", "lock").toSql();
    var selStmt = db.prepare(selExisting.sql);
    var existing = selStmt.get.apply(selStmt, selExisting.params);
    if (!existing) {
      // Race window between INSERT failure and SELECT — try once more.
      try {
        var retryStmt = db.prepare(insertLock.sql);
        retryStmt.run.apply(retryStmt, insertLock.params);
        return holder;
      } catch (e2) {
        throw new MigrationError("migrations/lock-busy",
          "could not acquire migration lock: " + ((e2 && e2.message) || String(e2)),
          true);
      }
    }
    var ageMs = nowMs - Number(existing.lockedAt);
    if (staleAfterMs > 0 && ageMs > staleAfterMs) {
      // Force-replace the stale lock. The DELETE + INSERT run in a single
      // transaction so the next process can't slip in between. The
      // transaction boundary is dialect-aware: only SQLite has the
      // `BEGIN IMMEDIATE` write-lock-up-front form — Postgres + MySQL
      // reject the `IMMEDIATE` keyword, so the shared runInTransaction
      // helper emits a plain portable `BEGIN`/`COMMIT`/`ROLLBACK` there.
      var lockMode = _handleDialect(db) === "sqlite" ? "IMMEDIATE" : null;
      try {
        return dbSchema.runInTransaction(db, function () {
          var delStale = sql.delete(_lockTable(), _sqlOpts(db))
            .where("scope", "lock").where("lockedAt", existing.lockedAt).toSql();
          var delStaleStmt = db.prepare(delStale.sql);
          delStaleStmt.run.apply(delStaleStmt, delStale.params);
          var replStmt = db.prepare(insertLock.sql);
          replStmt.run.apply(replStmt, insertLock.params);
          return holder;
        }, {
          lockMode: lockMode,
          onRollbackFail: function (rollbackErr) {
            log.debug("rollback-failed", {
              op: "lock-stale-replace",
              error: rollbackErr && rollbackErr.message,
            });
          },
        });
      } catch (forceErr) {
        throw new MigrationError("migrations/lock-stale-replace-failed",
          "could not replace stale lock: " + ((forceErr && forceErr.message) || String(forceErr)),
          true);
      }
    }
    throw new MigrationError("migrations/lock-held",
      "migration lock is held by " + existing.lockedBy +
      " (acquired " + ageMs + "ms ago). Another process is running migrations" +
      " — wait for it to finish, or pass staleAfterMs to force-replace stale locks.",
      true);
  }
}

function _releaseLock(db, holder) {
  // Only release our own lock — a process whose deploy was killed
  // shouldn't have its lock cleared by an unrelated next deploy unless
  // the operator explicitly used the staleAfterMs nodePath.
  try {
    var rel = sql.delete(_lockTable(), _sqlOpts(db))
      .where("scope", "lock").where("lockedBy", holder).toSql();
    var relStmt = db.prepare(rel.sql);
    relStmt.run.apply(relStmt, rel.params);
  } catch (_e) { /* best-effort release; operator can DELETE manually */ }
}

function _withLock(db, opts, fn) {
  var holder = _acquireLock(db, opts);
  try { return fn(); }
  finally { _releaseLock(db, holder); }
}

function _list(dir) {
  return atomicFile.listDir(dir, {
    filter: _isMigrationFile,
  }).map(function (e) { return e.name; }).sort();
}

function _resolveDb(opts) {
  if (opts && opts.db && typeof opts.db.prepare === "function") return opts.db;
  // Fall back to the framework's singleton db when one isn't passed —
  // operator-side wiring usually does `b.migrations.create({ dir })`.
  var d = db();
  if (typeof d.prepare !== "function") {
    throw new MigrationError("migrations/no-db",
      "no db handle: pass opts.db or initialize b.db before create()",
      true);
  }
  return d;
}

function _loadMigration(file, dir) {
  var mod = moduleLoader.requireFresh(nodePath.join(dir, file), function (e) {
    return new MigrationError("migrations/load-failed",
      "migration '" + file + "' failed to load: " + ((e && e.message) || String(e)),
      true);
  });
  if (!mod || typeof mod.up !== "function") {
    throw new MigrationError("migrations/missing-up",
      "migration '" + file + "' must export an `up(db)` function", true);
  }
  return mod;
}

var _txn = dbSchema.runInTransaction;

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["dir", "db", "staleAfterMs"], "b.migrations");
  if (typeof opts.dir !== "string" || opts.dir.length === 0) {
    throw new MigrationError("migrations/no-dir",
      "migrations.create requires opts.dir (path to migrations directory)",
      true);
  }
  var dir = opts.dir;

  function _appliedRows() {
    var db = _resolveDb(opts);
    _ensureTable(db);
    var q = sql.select(_migrationsTable(), _sqlOpts(db))
      .columns(["name", "description", "appliedAt"])
      .orderBy("appliedAt", "asc").orderBy("name", "asc").toSql();
    var stmt = db.prepare(q.sql);
    return stmt.all.apply(stmt, q.params);
  }

  function status() {
    var applied = _appliedRows();
    var appliedNames = new Set(applied.map(function (r) { return r.name; }));
    var files = _list(dir);
    var pending = files.filter(function (f) { return !appliedNames.has(f); });
    return {
      applied:  applied,
      pending:  pending,
      total:    files.length,
    };
  }

  function up() {
    var db = _resolveDb(opts);
    _ensureTable(db);
    return _withLock(db, opts, function () {
      var namesQ = sql.select(_migrationsTable(), _sqlOpts(db)).columns(["name"]).toSql();
      var namesStmt = db.prepare(namesQ.sql);
      var appliedSet = new Set(
        namesStmt.all.apply(namesStmt, namesQ.params)
          .map(function (r) { return r.name; })
      );
      var files = _list(dir);
      var applied = [];
      var skipped = [];
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        if (appliedSet.has(file)) { skipped.push(file); continue; }
        var mod = _loadMigration(file, dir);
        try {
          _txn(db, function () {
            mod.up(db);
            var insQ = sql.insert(_migrationsTable(), _sqlOpts(db))
              .values({ name: file, description: mod.description || "",
                        appliedAt: new Date().toISOString() }).toSql();
            var insStmt = db.prepare(insQ.sql);
            insStmt.run.apply(insStmt, insQ.params);
          });
        } catch (e) {
          throw new MigrationError("migrations/up-failed",
            "migration '" + file + "' failed: " + ((e && e.message) || String(e)),
            true);
        }
        applied.push(file);
      }
      return { applied: applied, skipped: skipped };
    });
  }

  function down(opts2) {
    opts2 = opts2 || {};
    var steps = opts2.steps === undefined ? 1 : Number(opts2.steps);
    if (!Number.isFinite(steps) || steps < 1 || Math.floor(steps) !== steps) {
      throw new MigrationError("migrations/bad-steps",
        "down: steps must be a positive integer (got " + opts2.steps + ")",
        true);
    }
    var db = _resolveDb(opts);
    _ensureTable(db);
    return _withLock(db, opts, function () {
      // Most-recent applied first (reverse chronological by appliedAt
      // then by name as a stable tiebreaker for fixtures with identical
      // timestamps). steps is a validated positive integer, so b.sql
      // inlines the LIMIT.
      var downQ = sql.select(_migrationsTable(), _sqlOpts(db)).columns(["name"])
        .orderBy("appliedAt", "desc").orderBy("name", "desc").limit(steps).toSql();
      var downStmt = db.prepare(downQ.sql);
      var rows = downStmt.all.apply(downStmt, downQ.params);

      var reverted = [];
      for (var i = 0; i < rows.length; i++) {
        var file = rows[i].name;
        var mod = _loadMigration(file, dir);
        if (typeof mod.down !== "function") {
          throw new MigrationError("migrations/no-down",
            "migration '" + file + "' has no `down(db)` function — " +
            "rollback unsupported. Restore from backup or write a down().",
            true);
        }
        try {
          _txn(db, function () {
            mod.down(db);
            var delQ = sql.delete(_migrationsTable(), _sqlOpts(db)).where("name", file).toSql();
            var delStmt = db.prepare(delQ.sql);
            delStmt.run.apply(delStmt, delQ.params);
          });
        } catch (e) {
          throw new MigrationError("migrations/down-failed",
            "rollback of '" + file + "' failed: " + ((e && e.message) || String(e)),
            true);
        }
        reverted.push(file);
      }
      return { reverted: reverted };
    });
  }

  return {
    up:       up,
    down:     down,
    status:   status,
    dir:      dir,
  };
}

module.exports = {
  create:           create,
  MigrationError:   MigrationError,
  MIGRATIONS_TABLE: MIGRATIONS_TABLE,
  LOCK_TABLE:       LOCK_TABLE,
  FILE_RE:          FILE_RE,
};
