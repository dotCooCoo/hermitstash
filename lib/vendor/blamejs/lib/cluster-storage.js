"use strict";
/**
 * @module b.clusterStorage
 * @nav    Production
 * @title  Cluster Storage
 *
 * @intro
 *   Cluster-aware framework-state SQL dispatch — runs against the
 *   framework's local SQLite in single-node mode and against the
 *   operator-supplied external DB in cluster mode. Distributed shared
 *   state for audit, consent, sessions, queue, and subject tables;
 *   write paths carry the cluster's fencing token so a stale leader
 *   cannot extend a chain after losing its lease.
 *
 *   Callers write SQL once using unprefixed logical table names
 *   (`audit_log`, `consent_log`, …) and `?` placeholders. The
 *   dispatcher rewrites bare framework tables to their `_blamejs_`-
 *   prefixed cluster names and translates `?` to `$N` for Postgres.
 *   Unknown identifiers pass through unchanged so operator-written
 *   migrations and app-data SQL are never touched.
 *
 *   The dispatcher is async-only. Even single-node SQLite calls
 *   return a resolved Promise so the call shape stays uniform across
 *   deployment topologies — callers `await` every method.
 *
 * @card
 *   Cluster-aware framework-state SQL dispatch — runs against the framework's local SQLite in single-node mode and against the operator-supplied external DB in cluster mode.
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

/**
 * @primitive b.clusterStorage.tableName
 * @signature b.clusterStorage.tableName(local)
 * @since     0.1.9
 * @status    stable
 * @related   b.clusterStorage.resolveTables, b.cluster.isClusterMode
 *
 * Resolve a logical framework table name to the active backend's
 * concrete name. In single-node mode returns the input unchanged; in
 * cluster mode returns the `_blamejs_`-prefixed name from the
 * framework-schema mapping (e.g. `audit_log` to `_blamejs_audit_log`).
 * Use this when composing SQL by hand against framework tables — the
 * `execute` family rewrites bare names automatically, but ad-hoc DDL
 * or admin queries that reference a specific table need the resolved
 * name explicitly.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var name = b.clusterStorage.tableName("audit_log");
 *   // → "audit_log"             (single-node)
 *   // → "_blamejs_audit_log"    (cluster mode)
 */
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
/**
 * @primitive b.clusterStorage.resolveTables
 * @signature b.clusterStorage.resolveTables(sql)
 * @since     0.1.9
 * @status    stable
 * @related   b.clusterStorage.tableName, b.clusterStorage.execute
 *
 * Rewrite bare framework table names in a SQL string to their
 * cluster-mode `_blamejs_`-prefixed equivalents. Word-boundary scan;
 * only exact identifier matches are rewritten — substrings,
 * column-qualified names, and operator app tables pass through
 * untouched. In single-node mode the SQL is returned unchanged. The
 * `execute` family calls this internally; callers reach for it
 * directly only when running raw SQL through a different path
 * (admin tooling, migration runners).
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sql = b.clusterStorage.resolveTables(
 *     "SELECT id FROM audit_log WHERE counter > ?"
 *   );
 *   // → "SELECT id FROM audit_log WHERE counter > ?"          (single-node)
 *   // → "SELECT id FROM _blamejs_audit_log WHERE counter > ?" (cluster)
 */
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

/**
 * @primitive b.clusterStorage.placeholderize
 * @signature b.clusterStorage.placeholderize(sql, dialect)
 * @since     0.1.9
 * @status    stable
 * @related   b.clusterStorage.execute, b.cluster.dialect
 *
 * Translate `?` placeholders to numbered `$1`, `$2`, … form for
 * Postgres backends; passthrough for `"sqlite"` and `"mysql"`. The
 * walker skips question marks inside single-quoted string literals so
 * `WHERE s = '?'` is preserved verbatim. Doubled-quote escapes (`''`)
 * inside strings are recognized. The `execute` family calls this on
 * every cluster-mode dispatch; reach for it directly only when
 * shipping raw SQL through a non-`execute` driver path.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sql = b.clusterStorage.placeholderize(
 *     "SELECT id FROM audit_log WHERE counter > ? AND actor = ?",
 *     "postgres"
 *   );
 *   // → "SELECT id FROM audit_log WHERE counter > $1 AND actor = $2"
 */
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

/**
 * @primitive b.clusterStorage.execute
 * @signature b.clusterStorage.execute(sql, params)
 * @since     0.1.9
 * @status    stable
 * @compliance soc2
 * @related   b.clusterStorage.executeOne, b.clusterStorage.executeAll, b.cluster.isClusterMode
 *
 * Run framework-state SQL against the active backend. In cluster mode
 * the SQL is routed through `resolveTables` + `placeholderize`, then
 * dispatched to the operator-supplied external DB. In single-node
 * mode it runs against the framework's local SQLite via
 * `db().prepare(...)` — `SELECT` and `RETURNING` queries use `.all()`,
 * everything else uses `.run()`. The shape is uniform either way:
 * resolves to `{ rows, rowCount }` where `rows` is the array of result
 * objects and `rowCount` is `rows.length` for selects or `info.changes`
 * for writes. Throws `ClusterStorageError` (code
 * `cluster-storage/bad-arg`) when `sql` is not a string.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var result = await b.clusterStorage.execute(
 *     "SELECT counter, row_hash FROM audit_log WHERE counter > ?",
 *     [42]
 *   );
 *   // → { rows: [ { counter: 43, row_hash: "..." } ], rowCount: 1 }
 */
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
/**
 * @primitive b.clusterStorage.executeOne
 * @signature b.clusterStorage.executeOne(sql, params)
 * @since     0.1.9
 * @status    stable
 * @related   b.clusterStorage.execute, b.clusterStorage.executeAll
 *
 * Convenience over `execute` for queries expected to return at most
 * one row. Returns the first row when the result set is non-empty,
 * `null` otherwise. The same dispatch rules as `execute` apply —
 * cluster mode routes to external DB, single-node hits local SQLite.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var row = await b.clusterStorage.executeOne(
 *     "SELECT counter, row_hash FROM audit_tip WHERE id = ?",
 *     [1]
 *   );
 *   // → { counter: 128, row_hash: "..." }
 *   // → null when no row matches
 */
async function executeOne(sql, params) {
  var result = await execute(sql, params);
  return result.rows.length > 0 ? result.rows[0] : null;
}

/**
 * @primitive b.clusterStorage.executeAll
 * @signature b.clusterStorage.executeAll(sql, params)
 * @since     0.1.9
 * @status    stable
 * @related   b.clusterStorage.execute, b.clusterStorage.executeOne
 *
 * Convenience over `execute` for queries expected to return a row
 * array. Returns the `rows` array directly without the surrounding
 * `{ rows, rowCount }` envelope. Empty result sets resolve to `[]`.
 * The same dispatch rules as `execute` apply.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rows = await b.clusterStorage.executeAll(
 *     "SELECT id, status FROM queue_jobs WHERE status = ?",
 *     ["pending"]
 *   );
 *   // → [ { id: 1, status: "pending" }, { id: 2, status: "pending" } ]
 */
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
