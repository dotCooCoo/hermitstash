// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.localDb
 * @nav    Data
 * @title  Local DB
 * @slug   local-db
 *
 * @intro
 *   A small SQLite store on <code>node:sqlite</code>, for the side-tables a
 *   deployment keeps next to its application data: sessions, the cluster's
 *   own bookkeeping, a job ledger. It is deliberately thin, and it is
 *   <strong>not encrypted</strong>, so application data belongs in
 *   <code>b.db</code> instead.
 *
 *   The pragmas that decide durability and SQL trust are fixed rather than
 *   configurable: write-ahead logging, foreign keys, secure delete, untrusted
 *   schema and cell-size checking are set at open, and a config naming any of
 *   them is refused instead of quietly ignored. What remains adjustable is the
 *   part that is a tuning decision, the synchronous level and the busy
 *   timeout.
 *
 *   The integrity check runs at open, and what happens next is the operator's
 *   choice: refuse and keep the file for inspection, or move it aside and
 *   start clean while reporting where the old one went.
 *
 * @card
 *   A thin, unencrypted SQLite store for side-tables, with WAL, foreign keys
 *   and secure delete fixed at open and a corrupt file either refused or
 *   renamed aside.
 */

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
  validateOpts.optionalBoolean(opts.audit, "localDb.thin: audit",
    LocalDbThinError, "localdb-thin/bad-opts");
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

var _PRAGMA_FLOOR = [
  ["journal_mode", "WAL", false],
  ["foreign_keys", "ON", false],
  ["secure_delete", "ON", false],
  ["trusted_schema", "OFF", true],
  ["cell_size_check", "ON", true],
];
var _PRAGMA_DEFAULTS = [
  ["synchronous", "NORMAL"],
  ["busy_timeout", 5000],
];

function _suppliedPragma(extra, lowerName) {
  if (!extra || typeof extra !== "object") return false;
  return Object.keys(extra).some(function (k) {
    return String(k).toLowerCase() === lowerName;
  });
}

function _runPragmas(database, extra) {
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
      if (_isFloorPragma(name)) {
        throw new LocalDbThinError("localdb-thin/pragma-not-overridable",
          "localDb.thin: pragma '" + name + "' is part of the store's fixed set and " +
          "cannot be overridden; remove it from opts.pragmas");
      }
      database.exec("PRAGMA " + name + "=" + String(value));
    }
  }
  for (var d = 0; d < _PRAGMA_DEFAULTS.length; d += 1) {
    var def = _PRAGMA_DEFAULTS[d];
    if (_suppliedPragma(extra, def[0])) continue;
    database.exec("PRAGMA " + def[0] + "=" + String(def[1]));
  }
  for (var f = 0; f < _PRAGMA_FLOOR.length; f += 1) {
    var row = _PRAGMA_FLOOR[f];
    if (!row[2]) { database.exec("PRAGMA " + row[0] + "=" + row[1]); continue; }
    try { database.exec("PRAGMA " + row[0] + "=" + row[1]); }
    catch (_e) { /* older sqlite does not know this pragma */ }
  }
}

function _isFloorPragma(name) {
  var lower = String(name).toLowerCase();
  for (var i = 0; i < _PRAGMA_FLOOR.length; i += 1) {
    if (_PRAGMA_FLOOR[i][0] === lower) return true;
  }
  return false;
}

function _looksCorrupt(message) {
  return /SQLITE_CORRUPT|SQLITE_NOTADB|database disk image is malformed|file is not a database|file is encrypted or is not a database/i
    .test(String(message || ""));
}

function _integrityVerdict(database) {
  var rows;
  try {
    rows = database.prepare("PRAGMA integrity_check").all();
  } catch (e) {
    var message = (e && e.message) || String(e);
    if (_looksCorrupt(message)) {
      return { ok: false, corrupt: true, detail: message };
    }
    var readFailure = null;
    try {
      database.prepare("SELECT count(*) AS n FROM sqlite_schema").all();
    } catch (readErr) {
      readFailure = (readErr && readErr.message) || String(readErr);
    }
    if (readFailure !== null && _looksCorrupt(readFailure)) {
      return { ok: false, corrupt: true, detail: message + "; " + readFailure };
    }
    return {
      ok:          false,
      corrupt:     false,
      detail:      readFailure === null ? message : (message + "; " + readFailure),
      checkFailed: true,
    };
  }
  if (rows.length === 1 && rows[0] && rows[0].integrity_check === "ok") {
    return { ok: true, corrupt: false, detail: "ok" };
  }
  var reported = rows.map(function (r) {
    return (r && r.integrity_check) || String(r);
  }).join("; ");
  return { ok: false, corrupt: true, detail: reported || "integrity_check reported no rows" };
}

/**
 * @primitive b.localDb.thin
 * @signature b.localDb.thin(opts)
 * @since     0.8.45
 * @status    stable
 * @related   b.db.init, b.clusterStorage
 *
 * Open a small SQLite file through `node:sqlite` with the store's pragmas
 * already applied, run `schemaSql`, and return the handle plus cached
 * statement helpers. It is the store behind the framework's own side-tables,
 * and it is unencrypted: `b.db` is what holds application data.
 *
 * `journal_mode=WAL`, `foreign_keys=ON`, `secure_delete=ON`,
 * `trusted_schema=OFF` and `cell_size_check=ON` are fixed. Naming one of them
 * in `pragmas` raises `localdb-thin/pragma-not-overridable` rather than being
 * ignored, so a config that believes it changed them fails at open.
 * `synchronous=NORMAL` and `busy_timeout=5000` are defaults that `pragmas`
 * may replace.
 *
 * The integrity check runs at open. `recovery: "refuse"`, the default, raises
 * on a corrupt file and leaves it in place; `"rename-and-recreate"` moves it
 * aside and starts a new one, reporting the move as `recovered` and
 * `recoveredTo`, so a caller can tell the data is gone rather than assume an
 * empty database was always empty.
 *
 * The returned object carries `db` (the raw `DatabaseSync`), `prepare`, `run`,
 * `query`, `close` and `file`. `run` and `query` take their bind values as
 * further arguments rather than as an array. Prepared statements are cached,
 * up to 256.
 *
 * The configuration refusals name what is wrong: `localdb-thin/bad-opts` for
 * opts that are not an object, `localdb-thin/bad-file` for a missing path or
 * one carrying a NUL byte, `localdb-thin/bad-schema-sql` for a missing schema,
 * `localdb-thin/bad-recovery` for a recovery outside the two above,
 * `localdb-thin/bad-pragmas` and `localdb-thin/bad-limits` for a non-object,
 * and `localdb-thin/bad-pragma-name` or `localdb-thin/bad-pragma-value` for a
 * pragma this store will not send. Naming one of the five fixed pragmas raises
 * `localdb-thin/pragma-not-overridable`.
 *
 * Opening raises `localdb-thin/sqlite-missing` when the Node build has no
 * `node:sqlite` (24.14 or newer is needed), `localdb-thin/open-failed` when
 * the file cannot be opened, `localdb-thin/corrupt` when the integrity check
 * reports the file as damaged under the refusing recovery,
 * `localdb-thin/integrity-check-failed` when the check could not run at all
 * while the file still answers ordinary queries, which is not recovered from
 * under either recovery, and `localdb-thin/recovery-failed` when
 * the rename-and-recreate recovery cannot move the old file aside.
 * Afterwards, `localdb-thin/bad-sql` refuses a statement that is not a string
 * and `localdb-thin/closed` answers any call made after `close()`.
 *
 * @opts
 *   file:      string,   // required; no NUL bytes
 *   schemaSql: string,   // required; run at open
 *   recovery:  string,   // refuse | rename-and-recreate; default "refuse"
 *   pragmas:   object,   // extra pragmas; the fixed five are refused
 *   limits:    object,   // node:sqlite SQLITE_LIMIT_* caps
 *   audit:     boolean,  // false silences the open and recover audit events
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.localDb.thin({
 *     file:      "./data/notes.db",
 *     schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)",
 *   });
 *   store.run("INSERT INTO notes (body) VALUES (?)", "first");
 *   store.query("SELECT body FROM notes")[0].body;   // → "first"
 *   store.close();
 */
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
    try {
      _runPragmas(db, opts.pragmas);
      var verdict = _integrityVerdict(db);
      if (!verdict.ok && !verdict.corrupt) {
        throw new LocalDbThinError("localdb-thin/integrity-check-failed",
          "localDb.thin: PRAGMA integrity_check could not run for '" + file + "': " +
          verdict.detail + ". The database still answers ordinary queries, so it is " +
          "left in place rather than recovered from.");
      }
      if (!verdict.ok) {
        throw new LocalDbThinError("localdb-thin/corrupt",
          "localDb.thin: PRAGMA integrity_check reported '" + file +
          "' as damaged: " + verdict.detail);
      }
      db.exec(opts.schemaSql);
    } catch (e) {
      try { db.close(); } catch (_e) { /* best-effort */ }
      throw e;
    }
    return db;
  }

  try {
    database = _attemptOpen();
  } catch (e) {
    var corrupt = (e && e.code === "localdb-thin/corrupt") ||
                  (e && e.code !== "localdb-thin/integrity-check-failed" &&
                   _looksCorrupt(e.message));
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
      _safeEmitAudit("localdb.thin.recovered",
        { file: file, renamedTo: renamedTo, reason: (e && e.message) || String(e) });
    } else if (corrupt) {
      throw new LocalDbThinError("localdb-thin/corrupt",
        "localDb.thin: file '" + file + "' is corrupt (" + ((e && e.message) || String(e)) +
        "); pass recovery: 'rename-and-recreate' to auto-recover");
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
  thin:                      thin,
  LocalDbThinError:          LocalDbThinError,
  _integrityVerdictForTest:  _integrityVerdict,
};
