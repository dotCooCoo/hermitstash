// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeSql = require("./safe-sql");
var { LocalDbThinError } = require("./framework-error");
var atomicFile = require("./atomic-file");

var _DEFAULT_SQL_LENGTH = C.BYTES.mib(1);

var audit = lazyRequire(function () { return require("./audit"); });

var PREPARE_CACHE_MAX = 256;

var ALLOWED_RECOVERY = ["refuse", "rename-and-recreate"];

var NUL_BYTE = String.fromCharCode(0);

function _validateOpts(opts) {
  validateOpts.requireObject(opts, "localDb.thin", LocalDbThinError, "localdb-thin/bad-opts");
  validateOpts.requireNonEmptyString(opts.file, "file", LocalDbThinError, "localdb-thin/bad-file");
  if (opts.file.indexOf(NUL_BYTE) !== -1) {
    throw new LocalDbThinError("localdb-thin/bad-file",
      "localDb.thin: file path must not contain NUL bytes");
  }
  validateOpts.requireNonEmptyString(opts.schemaSql, "schemaSql",
    LocalDbThinError, "localdb-thin/bad-schema-sql");
  var recovery = opts.recovery || "refuse";
  if (ALLOWED_RECOVERY.indexOf(recovery) === -1) {
    throw new LocalDbThinError("localdb-thin/bad-recovery",
      "localDb.thin: recovery must be one of " + ALLOWED_RECOVERY.join(", ") +
      " (got '" + recovery + "')");
  }
  if (opts.pragmas !== undefined &&
      (typeof opts.pragmas !== "object" || Array.isArray(opts.pragmas))) {
    throw new LocalDbThinError("localdb-thin/bad-pragmas",
      "localDb.thin: pragmas must be an object mapping pragma name -> value");
  }
  if (opts.limits !== undefined &&
      (typeof opts.limits !== "object" || opts.limits === null || Array.isArray(opts.limits))) {
    throw new LocalDbThinError("localdb-thin/bad-limits",
      "localDb.thin: limits must be an object of node:sqlite SQLITE_LIMIT_* caps " +
      "(e.g. { sqlLength: 1048576 })");
  }
}

function _resolveLimits(opts) {
  return Object.assign({ sqlLength: _DEFAULT_SQL_LENGTH }, opts.limits || {});
}

function _runPragmas(database, extra) {
  database.exec("PRAGMA journal_mode=WAL");
  database.exec("PRAGMA synchronous=NORMAL");
  database.exec("PRAGMA busy_timeout=5000");
  database.exec("PRAGMA foreign_keys=ON");
  database.exec("PRAGMA secure_delete=ON");
  try { database.exec("PRAGMA trusted_schema=OFF"); } catch (_e) { /* sqlite < 3.31 */ }
  try { database.exec("PRAGMA cell_size_check=ON"); } catch (_e) { /* sqlite < 3.26 */ }
  if (extra && typeof extra === "object") {
    var keys = Object.keys(extra);
    for (var i = 0; i < keys.length; i += 1) {
      var name = keys[i];
      if (!safeSql.isDefaultIdentifier(name) ||
          name.length > safeSql.MAX_IDENTIFIER_LENGTH) {
        throw new LocalDbThinError("localdb-thin/bad-pragma-name",
          "localDb.thin: pragma name '" + name + "' must be a bare identifier");
      }
      var value = extra[name];
      if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
        throw new LocalDbThinError("localdb-thin/bad-pragma-value",
          "localDb.thin: pragma '" + name + "' value must be string|number|boolean");
      }
      database.exec("PRAGMA " + name + "=" + String(value));
    }
  }
}

function _integrityOk(database) {
  try {
    var rows = database.prepare("PRAGMA integrity_check").all();
    return rows.length === 1 && rows[0] && rows[0].integrity_check === "ok";
  } catch (_e) {
    return false;
  }
}

function thin(opts) {
  _validateOpts(opts);

  var auditOn  = opts.audit !== false;
  var file = opts.file;
  var recovery = opts.recovery || "refuse";

  function _safeEmitAudit(action, metadata) {
    if (!auditOn) return;
    try { audit().safeEmit({ action: action, outcome: "success", metadata: metadata || {} }); }
    catch (_e) { /* drop-silent — audit best-effort */ }
  }

  var nodeSqlite = require("node:sqlite");
  var DatabaseSync = nodeSqlite.DatabaseSync;
  if (typeof DatabaseSync !== "function") {
    throw new LocalDbThinError("localdb-thin/sqlite-missing",
      "localDb.thin: node:sqlite is unavailable on this Node build (requires Node 24.14+)");
  }

  try { nodeFs.mkdirSync(nodePath.dirname(file), { recursive: true }); } catch (_e) { /* best-effort */ }

  var database = null;
  var renamedTo = null;

  function _attemptOpen() {
    var db = new DatabaseSync(file, { limits: _resolveLimits(opts) });
    _runPragmas(db, opts.pragmas);
    if (!_integrityOk(db)) {
      try { db.close(); } catch (_e) { /* best-effort */ }
      throw new LocalDbThinError("localdb-thin/corrupt",
        "localDb.thin: PRAGMA integrity_check failed for '" + file + "'");
    }
    db.exec(opts.schemaSql);
    return db;
  }

  try {
    database = _attemptOpen();
  } catch (e) {
    var corrupt = (e && e.code === "localdb-thin/corrupt") ||
                  (e && typeof e.message === "string" &&
                   /SQLITE_CORRUPT|malformed|not a database/i.test(e.message));
    if (corrupt && recovery === "rename-and-recreate") {
      var stamp = String(Date.now());
      renamedTo = file + ".corrupt-" + stamp;
      var renamed = false;
      var lastRenameErr = null;
      for (var attempt = 0; attempt < 20 && !renamed; attempt += 1) {
        try {
          if (nodeFs.existsSync(file)) atomicFile.renameWithRetry(file, renamedTo);
          renamed = true;
        } catch (re) {
          lastRenameErr = re;
          if (re && (re.code === "EBUSY" || re.code === "EPERM")) {
            var until = Date.now() + 100;
            while (Date.now() < until) { /* spin */ }
            continue;
          }
          throw new LocalDbThinError("localdb-thin/recovery-failed",
            "localDb.thin: rename of corrupt file failed: " + ((re && re.message) || String(re)));
        }
      }
      if (!renamed) {
        throw new LocalDbThinError("localdb-thin/recovery-failed",
          "localDb.thin: rename of corrupt file failed: " +
          ((lastRenameErr && lastRenameErr.message) || "unknown"));
      }
      ["-wal", "-shm"].forEach(function (suffix) {
        var sibling = file + suffix;
        if (nodeFs.existsSync(sibling)) {
          try { atomicFile.renameWithRetry(sibling, sibling + ".corrupt-" + stamp); }
          catch (_se) { /* best-effort */ }
        }
      });
      database = _attemptOpen();
      _safeEmitAudit("localdb.thin.recovered", { file: file, renamedTo: renamedTo });
    } else if (corrupt) {
      throw new LocalDbThinError("localdb-thin/corrupt",
        "localDb.thin: file '" + file + "' is corrupt; pass recovery: 'rename-and-recreate' to auto-recover");
    } else if (e && e.isLocalDbThinError) {
      throw e;
    } else {
      throw new LocalDbThinError("localdb-thin/open-failed",
        "localDb.thin: open of '" + file + "' failed: " + ((e && e.message) || String(e)));
    }
  }

  _safeEmitAudit("localdb.thin.opened", { file: file });

  var prepareCache = new Map();
  var closed = false;

  function _ensureOpen() {
    if (closed) {
      throw new LocalDbThinError("localdb-thin/closed",
        "localDb.thin: handle is closed");
    }
  }

  function prepare(sql) {
    _ensureOpen();
    validateOpts.requireNonEmptyString(sql, "sql",
      LocalDbThinError, "localdb-thin/bad-sql");
    if (prepareCache.has(sql)) {
      var hit = prepareCache.get(sql);
      prepareCache.delete(sql);
      prepareCache.set(sql, hit);
      return hit;
    }
    var stmt = database.prepare(sql);
    prepareCache.set(sql, stmt);
    if (prepareCache.size > PREPARE_CACHE_MAX) {
      var oldest = prepareCache.keys().next().value;
      prepareCache.delete(oldest);
    }
    return stmt;
  }

  function run(sql ) {
    _ensureOpen();
    var params = Array.prototype.slice.call(arguments, 1);
    var stmt = prepare(sql);
    return stmt.run.apply(stmt, params);
  }

  function query(sql ) {
    _ensureOpen();
    var params = Array.prototype.slice.call(arguments, 1);
    var stmt = prepare(sql);
    return stmt.all.apply(stmt, params);
  }

  function close() {
    if (closed) return;
    prepareCache.clear();
    database.close();
    closed = true;
    _safeEmitAudit("localdb.thin.closed", { file: file });
  }

  return {
    db:           database,
    prepare:      prepare,
    run:          run,
    query:        query,
    close:        close,
    file:         file,
    recovered:    !!renamedTo,
    recoveredTo:  renamedTo,
  };
}

module.exports = {
  thin:               thin,
  LocalDbThinError:   LocalDbThinError,
};
