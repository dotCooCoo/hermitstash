"use strict";
/**
 * Framework-state SQL dispatch — runs against local SQLite in single-
 * node mode and against external-db in cluster mode.
 *
 * audit / consent / sessions / queue / subject all read and write the
 * framework's own tables (audit_log, consent_log, …). In single-node
 * mode those tables live in the framework's own SQLite (lib/db.js).
 * In cluster mode they live in the operator-supplied external-db with
 * a `_blamejs_` prefix to avoid colliding with app tables.
 *
 * This module is the dispatch primitive. Callers write SQL once using
 * unprefixed table names + `?` placeholders; the dispatcher translates
 * to the active backend's flavor:
 *
 *   single-node     local SQLite via db().prepare(sql).run/get/all(...)
 *   cluster (sqlite) externalDb.query(sql, params)              ? placeholders
 *   cluster (postgres) externalDb.query(translated, params)     $1, $2, …
 *
 * Tables are translated through frameworkSchema.tableName so callers
 * use logical names (audit_log) and the resolved name is automatically
 * prefixed in cluster mode (_blamejs_audit_log).
 *
 * The dispatcher is async-only — the operator's external-db driver
 * is async, and even local-SQLite calls return a resolved Promise to
 * keep the call shape uniform. Callers `await` this module's methods;
 * audit / consent / queue / session / subject all thread `async` /
 * `await` through their own surfaces to match.
 *
 * Public API:
 *   await execute(sql, params?)    { rows, rowCount }
 *   tableName(local)               external-db prefixed name (or unchanged
 *                                  in single-node mode)
 *   placeholderize(sql, dialect)   `?` to `$N` for postgres; passthrough
 *                                  for sqlite
 *   resolveTables(sql)             rewrites bare unprefixed table names
 *                                  in cluster mode (only the framework's
 *                                  known tables are rewritten — operator
 *                                  app-data SQL is unaffected)
 */

var cluster = require("./cluster");
var frameworkSchema = require("./framework-schema");
var externalDb = require("./external-db");
var lazyRequire = require("./lazy-require");
var { FrameworkError } = require("./framework-error");

class ClusterStorageError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "ClusterStorageError";
    this.code = code || "cluster-storage/invalid";
    this.isClusterStorageError = true;
  }
}

// ---- Lazy db ref to avoid circular require ----
var _localDb = lazyRequire(function () { return require("./db"); });

// ---- Table-name resolution ----

function tableName(local) {
  if (cluster.isClusterMode()) return frameworkSchema.tableName(local);
  return local;
}

// Precomputed rewrite table for resolveTables(). Built once at module
// load from the static frozen frameworkSchema.LOCAL_TO_EXTERNAL mapping —
// not from operator/request input. Order longest-first so prefix matches
// don't collide (audit_log before audit). Identity mappings are filtered
// out so the loop body has no no-op iterations. Framework table names
// are entirely [A-Za-z0-9_], so a manual word-boundary scan replaces
// the regex `\b...\b` exactly without runtime regex compilation.
// Character-code bounds for the word-character class \w that JavaScript
// regex `\b` uses. Stored as code-from-literal so the magic numbers are
// self-evident at the source rather than needing a comment to decode.
var _CC_0          = "0".charCodeAt(0);
var _CC_9          = "9".charCodeAt(0);
var _CC_A          = "A".charCodeAt(0);
var _CC_Z          = "Z".charCodeAt(0);
var _CC_UNDERSCORE = "_".charCodeAt(0);
var _CC_a          = "a".charCodeAt(0);
var _CC_z          = "z".charCodeAt(0);

function _isWordChar(code) {
  return (code >= _CC_0 && code <= _CC_9) ||
         (code >= _CC_A && code <= _CC_Z) ||
         code === _CC_UNDERSCORE          ||
         (code >= _CC_a && code <= _CC_z);
}

function _replaceWordBoundaryAll(haystack, needle, replacement) {
  if (haystack.length < needle.length) return haystack;
  var out = "";
  var cursor = 0;
  var matched = false;
  var idx = haystack.indexOf(needle);
  while (idx !== -1) {
    var beforeCode = idx === 0 ? -1 : haystack.charCodeAt(idx - 1);
    var afterPos   = idx + needle.length;
    var afterCode  = afterPos >= haystack.length ? -1 : haystack.charCodeAt(afterPos);
    var leftBoundary  = beforeCode === -1 || !_isWordChar(beforeCode);
    var rightBoundary = afterCode  === -1 || !_isWordChar(afterCode);
    if (leftBoundary && rightBoundary) {
      out += haystack.slice(cursor, idx) + replacement;
      cursor = afterPos;
      matched = true;
      idx = haystack.indexOf(needle, cursor);
    } else {
      // Boundary mismatch — advance past this position by one and keep
      // scanning. We do NOT flush partial output here; the final
      // haystack.slice(cursor) below covers any non-rewritten tail.
      idx = haystack.indexOf(needle, idx + 1);
    }
  }
  if (!matched) return haystack;
  return out + haystack.slice(cursor);
}

var _REWRITE_TABLE = (function () {
  var mapping = frameworkSchema.LOCAL_TO_EXTERNAL;
  var names = Object.keys(mapping).sort(function (a, b) {
    return b.length - a.length;
  });
  var entries = [];
  for (var i = 0; i < names.length; i++) {
    var local = names[i];
    var external = mapping[local];
    if (local === external) continue;
    entries.push({ local: local, external: external });
  }
  return Object.freeze(entries);
})();

// Rewrite bare table names in SQL when running in cluster mode. We only
// touch tokens that are exactly one of the framework's known table names
// (audit_log, consent_log, …) — anything else passes through unchanged
// so app-data SQL composed via this dispatcher (or operator-written
// migrations) isn't rewritten by accident.
function resolveTables(sql) {
  if (!cluster.isClusterMode()) return sql;
  var translated = sql;
  for (var i = 0; i < _REWRITE_TABLE.length; i++) {
    var entry = _REWRITE_TABLE[i];
    translated = _replaceWordBoundaryAll(translated, entry.local, entry.external);
  }
  return translated;
}

// ---- Placeholder translation ----
//
// SQLite and Postgres both accept `?` in some contexts, but Postgres
// only accepts `$N` for parameter binding. We translate at dispatch
// time so callers always write `?` and the right thing happens per
// dialect.

function placeholderize(sql, dialect) {
  if (dialect !== "postgres") return sql;
  // Walk the SQL and replace `?` with $1, $2, … but skip ones inside
  // single-quoted string literals.
  var out = "";
  var n = 0;
  var inStr = false;
  for (var i = 0; i < sql.length; i++) {
    var c = sql.charAt(i);
    if (c === "'" && !inStr) { inStr = true;  out += c; continue; }
    if (c === "'" &&  inStr) {
      // Handle escaped '' inside string
      if (sql.charAt(i + 1) === "'") { out += "''"; i += 1; continue; }
      inStr = false; out += c; continue;
    }
    if (!inStr && c === "?") { n += 1; out += "$" + n; continue; }
    out += c;
  }
  return out;
}

// ---- execute() ----

async function execute(sql, params) {
  if (typeof sql !== "string") {
    throw new ClusterStorageError("sql must be a string", "cluster-storage/bad-arg");
  }
  params = params || [];

  if (cluster.isClusterMode()) {
    var translated = placeholderize(resolveTables(sql), cluster.dialect());
    var result = await externalDb.query(translated, params, {
      backend: cluster.externalDbBackend(),
    });
    return result;
  }

  // Local SQLite path. node:sqlite is sync — wrap in a resolved Promise
  // so callers always see the same shape regardless of mode.
  var stmt = _localDb().prepare(sql);
  // Heuristic: if the statement returns rows (SELECT or has RETURNING),
  // use .all(); otherwise .run() and report changes as rowCount.
  if (/^\s*SELECT\b/i.test(sql) || /\bRETURNING\b/i.test(sql)) {
    var rows = stmt.all.apply(stmt, params);
    return { rows: rows, rowCount: rows.length };
  }
  var info = stmt.run.apply(stmt, params);
  return { rows: [], rowCount: info.changes };
}

// Convenience wrappers for the two common patterns.
async function executeOne(sql, params) {
  var result = await execute(sql, params);
  return result.rows.length > 0 ? result.rows[0] : null;
}

async function executeAll(sql, params) {
  var result = await execute(sql, params);
  return result.rows;
}

module.exports = {
  execute:               execute,
  executeOne:            executeOne,
  executeAll:            executeAll,
  tableName:             tableName,
  resolveTables:         resolveTables,
  placeholderize:        placeholderize,
  ClusterStorageError:   ClusterStorageError,
};
