// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

var MIGRATIONS_TABLE = "_blamejs_migrations";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName below
function _migrationsTable() { return frameworkSchema.tableName(MIGRATIONS_TABLE); }
var _handleDialect = dbSchema.handleDialect;
var _sqlOpts = dbSchema.sqlOpts;
var _keyTextType = dbSchema.keyTextType;
var _MS_EPOCH_TYPE = "int";
var FILE_RE = migrationFiles.MIGRATION_FILE_RE;
var FILE_NAME_MAX = 255;

function _isMigrationFile(name) {
  return typeof name === "string" &&
         name.length > 0 &&
         name.length <= FILE_NAME_MAX &&
         FILE_RE.test(name);
}

var _runSql = dbSchema.runSqlOnHandle;

function _ensureTable(db) {
  _runSql(db, sql.createTable(_migrationsTable(), [
    { name: "name",        type: _keyTextType(db), primaryKey: true },
    { name: "description", type: "text" },
    { name: "appliedAt",   type: "text", notNull: true },
  ], _sqlOpts(db)).sql);
}

var LOCK_TABLE = "_blamejs_migrations_lock";  // allow:hand-rolled-sql — logical name declaration; physical name + prefix resolve via frameworkSchema.tableName below
function _lockTable() { return frameworkSchema.tableName(LOCK_TABLE); }

function _ensureLockTable(db) {
  var dialect = _handleDialect(db);
  var scopeCheck = "CHECK (" + safeSql.quoteIdentifier("scope", dialect, { allowReserved: true }) + " = 'lock')";
  _runSql(db, sql.createTable(_lockTable(), [
    { name: "scope",    type: _keyTextType(db), primaryKey: true, constraints: scopeCheck },
    { name: "lockedAt", type: _MS_EPOCH_TYPE,   notNull: true },
    { name: "lockedBy", type: "text",           notNull: true },
  ], _sqlOpts(db)).sql);
}

function _lockHolderId() {
  return String(process.pid) + "@" + (require("node:os").hostname() || "unknown");
}

function _acquireLock(db, opts) {
  _ensureLockTable(db);
  var holder = _lockHolderId();
  var nowMs = Date.now();
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
  try {
    var insStmt = db.prepare(insertLock.sql);
    insStmt.run.apply(insStmt, insertLock.params);
    return holder;
  } catch {
    var selExisting = sql.select(_lockTable(), _sqlOpts(db))
      .columns(["lockedAt", "lockedBy"]).where("scope", "lock").toSql();
    var selStmt = db.prepare(selExisting.sql);
    var existing = selStmt.get.apply(selStmt, selExisting.params);
    if (!existing) {
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
    var conn = _resolveDb(opts);
    _ensureTable(conn);
    var q = sql.select(_migrationsTable(), _sqlOpts(conn))
      .columns(["name", "description", "appliedAt"])
      .orderBy("appliedAt", "asc").orderBy("name", "asc").toSql();
    var stmt = conn.prepare(q.sql);
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
    var conn = _resolveDb(opts);
    _ensureTable(conn);
    return _withLock(conn, opts, function () {
      var namesQ = sql.select(_migrationsTable(), _sqlOpts(conn)).columns(["name"]).toSql();
      var namesStmt = conn.prepare(namesQ.sql);
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
          _txn(conn, function () {
            mod.up(conn);
            var insQ = sql.insert(_migrationsTable(), _sqlOpts(conn))
              .values({ name: file, description: mod.description || "",
                        appliedAt: new Date().toISOString() }).toSql();
            var insStmt = conn.prepare(insQ.sql);
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
    var conn = _resolveDb(opts);
    _ensureTable(conn);
    return _withLock(conn, opts, function () {
      var downQ = sql.select(_migrationsTable(), _sqlOpts(conn)).columns(["name"])
        .orderBy("appliedAt", "desc").orderBy("name", "desc").limit(steps).toSql();
      var downStmt = conn.prepare(downQ.sql);
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
          _txn(conn, function () {
            mod.down(conn);
            var delQ = sql.delete(_migrationsTable(), _sqlOpts(conn)).where("name", file).toSql();
            var delStmt = conn.prepare(delQ.sql);
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
