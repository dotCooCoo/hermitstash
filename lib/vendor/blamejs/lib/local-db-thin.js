// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.localDb.thin — lightweight node:sqlite wrapper for desktop-daemon-
 * shaped local state.
 *
 * The framework's full b.db is the right tool when the workload needs
 * vault-sealed columns, the audit chain, sealed-by-default schema
 * governance, framework-schema bootstrap, derived-hash lookup, sealed-
 * fields rotation, and the cross-cutting "encrypted at rest" envelope.
 * That stack costs vault keys, a tmpfs sealed-file dance, schema
 * declarations, and a startup audit chain — overkill for a daemon
 * keeping a hundred-row local registry on the operator's laptop.
 *
 * b.localDb.thin keeps the parts a daemon does need:
 *
 *   - A node:sqlite handle opened in WAL mode with sane busy-timeout.
 *   - Boot-time `PRAGMA integrity_check` (cheap + closes the partial-
 *     write data-loss class).
 *   - Optional corrupt-rename-and-recreate recovery: if the file fails
 *     integrity_check or open() raises SQLITE_CORRUPT, rename it to
 *     `<file>.corrupt-<unix-ms>` and start fresh against the operator-
 *     supplied schema.
 *   - LRU-bounded prepared-statement cache (matches b.db's shape so
 *     long-running daemons with diverse query shapes don't leak
 *     statement handles).
 *   - Audit hooks on open / recover / close so operators can wire
 *     the same incident review pipeline they already have for b.db.
 *
 * What it deliberately does NOT do:
 *
 *   - No vault, no field encryption, no per-row keys, no SHA3 derived
 *     hashes — operators with PHI / PCI go straight to b.db.
 *   - No audit chain — there is no server-side compliance posture for
 *     a desktop daemon's sqlite cache.
 *   - No schema governance — `schemaSql` is the operator's `CREATE
 *     TABLE IF NOT EXISTS ...` script, run verbatim at open.
 *   - No background flush / no encrypted-at-rest tmpfs — the file is
 *     opened in place. Operators wanting at-rest encryption use full
 *     b.db.
 *
 * Public surface:
 *   localDbThin.thin({
 *     file:       string,                // required absolute path
 *     schemaSql:  string,                // required CREATE TABLE / INDEX script
 *     recovery:   "refuse" | "rename-and-recreate",  // default: "refuse"
 *     pragmas:    object,                // optional extra PRAGMA overrides
 *     limits:     object,                // node:sqlite SQLITE_LIMIT_* caps; default { sqlLength: 1 MiB } (parity with b.db / CLI)
 *     audit:      boolean,               // default: true
 *   }) -> { db, prepare, run, query, close, file }
 *
 * Audit emits:
 *   localdb.thin.opened     { file }
 *   localdb.thin.recovered  { file, renamedTo }
 *   localdb.thin.closed     { file }
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeSql = require("./safe-sql");
var { LocalDbThinError } = require("./framework-error");
var atomicFile = require("./atomic-file");

// Default parse-time statement-size cap, matching b.db and the CLI opener
// (the v0.15.9 node:sqlite SQLITE_LIMIT_LENGTH floor). prepare()/exec() on the
// thin path parse operator/application SQL, so the same cap guards it against
// an attacker-influenced megaquery the parser would otherwise chew (SQLite's
// default is 1 GB). Operators raise/relax it via opts.limits.
var _DEFAULT_SQL_LENGTH = C.BYTES.mib(1);

var audit = lazyRequire(function () { return require("./audit"); });

// LRU prepared-statement cache cap — same magnitude as lib/db.js's full
// variant. Daemons issuing more than this many distinct SQL strings
// likely have a string-concat bug rather than a legitimate need.
var PREPARE_CACHE_MAX = 256;                                                       // distinct-statement cache cap

var ALLOWED_RECOVERY = ["refuse", "rename-and-recreate"];

// Bare NUL byte, expressed via String.fromCharCode so the source file
// itself stays pure ASCII (the codebase-patterns gate also guarantees
// this won't be confused with a literal embedded NUL during diffs).
var NUL_BYTE = String.fromCharCode(0);

function _validateOpts(opts) {
  validateOpts.requireObject(opts, "localDb.thin", LocalDbThinError, "localdb-thin/bad-opts");
  validateOpts.requireNonEmptyString(opts.file, "file", LocalDbThinError, "localdb-thin/bad-file");
  // `file` is operator-supplied (daemon's chosen storage nodePath), not
  // request-driven input. Reject NUL bytes defensively — Node's path
  // routines silently truncate at the first NUL, which would let a
  // typo open a different file than the operator intended.
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

// Merge operator-supplied limits over the framework default (sqlLength cap),
// so the thin path reaches parity with b.db / the CLI opener while letting an
// operator raise the cap or add SQLITE_LIMIT_* keys (e.g. attach: 0).
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
      // PRAGMA names are operator-supplied keys; reject anything that
      // isn't a bare SQL identifier so this never becomes a SQL-injection
      // vector even at config time. Composes the same identifier shape
      // safeSql.validateIdentifier enforces elsewhere.
      if (!safeSql.DEFAULT_IDENTIFIER_RE.test(name) ||
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
  // opts.file is operator-config (daemon-author chosen storage nodePath),
  // not request-driven input. Validation above already rejected non-
  // strings and NUL bytes. The operator picks the file location; the
  // wrapper opens it as-is.
  var file = opts.file;
  var recovery = opts.recovery || "refuse";

  function _safeEmitAudit(action, metadata) {
    if (!auditOn) return;
    try { audit().safeEmit({ action: action, outcome: "success", metadata: metadata || {} }); }
    catch (_e) { /* drop-silent — audit best-effort */ }
  }

  // node:sqlite is required lazily so a process never importing localDb
  // doesn't pay the cost of resolving it at module load.
  var nodeSqlite = require("node:sqlite");
  var DatabaseSync = nodeSqlite.DatabaseSync;
  if (typeof DatabaseSync !== "function") {
    throw new LocalDbThinError("localdb-thin/sqlite-missing",
      "localDb.thin: node:sqlite is unavailable on this Node build (requires Node 24.14+)");
  }

  // Ensure parent directory exists — operators commonly point this at
  // an OS app-data path that may not exist on first daemon launch.
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
      // Bounded rename retry — Windows holds a file lock for several
      // hundred ms after DatabaseSync.close() returns under load
      // (CI runner contention amplifies this). Linux/macOS land on
      // the first attempt. Capped at ~2s total so a genuinely-stuck
      // handle still surfaces as recovery-failed rather than hanging.
      var renamed = false;
      var lastRenameErr = null;
      for (var attempt = 0; attempt < 20 && !renamed; attempt += 1) {
        try {
          if (nodeFs.existsSync(file)) atomicFile.renameWithRetry(file, renamedTo);
          renamed = true;
        } catch (re) {
          lastRenameErr = re;
          if (re && (re.code === "EBUSY" || re.code === "EPERM")) {
            // Synchronous spin — don't reach for setTimeout in a
            // boot-time nodePath. 100ms × 20 = 2s upper bound.
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
      // Also move WAL/SHM siblings if present so the fresh DB doesn't
      // re-attach a half-open journal.
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
      // Bad-pragma / bad-shape errors bubble up from _runPragmas with
      // their own typed code already attached — re-throw verbatim
      // rather than re-wrapping behind open-failed.
      throw e;
    } else {
      throw new LocalDbThinError("localdb-thin/open-failed",
        "localDb.thin: open of '" + file + "' failed: " + ((e && e.message) || String(e)));
    }
  }

  _safeEmitAudit("localdb.thin.opened", { file: file });

  // ---- Prepared-statement cache ----
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
      // Touch for LRU
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

  function run(sql /* , ...params */) {
    _ensureOpen();
    var params = Array.prototype.slice.call(arguments, 1);
    var stmt = prepare(sql);
    return stmt.run.apply(stmt, params);
  }

  function query(sql /* , ...params */) {
    _ensureOpen();
    var params = Array.prototype.slice.call(arguments, 1);
    var stmt = prepare(sql);
    return stmt.all.apply(stmt, params);
  }

  function close() {
    if (closed) return;
    closed = true;
    prepareCache.clear();
    try { database.close(); } catch (_e) { /* best-effort */ }
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
