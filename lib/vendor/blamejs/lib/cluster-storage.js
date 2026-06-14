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

/**
 * @primitive b.clusterStorage.dialect
 * @signature b.clusterStorage.dialect()
 * @since     0.15.0
 * @status    stable
 * @related   b.clusterStorage.execute, b.cluster.dialect, b.frameworkSchema.ensureSchema
 *
 * Resolve the SQL dialect every framework-table data-layer file must pass
 * to `b.sql` so the emitted SQL matches the active backend. In cluster
 * mode it returns the operator-configured backend dialect (`"postgres"` |
 * `"mysql"` | `"sqlite"`, set at `b.cluster.init`); in single-node mode
 * the framework state lives in local node:sqlite, so it returns
 * `"sqlite"`. This is the canonical dialect source for framework-state
 * SQL — `b.sql` defaults to `"sqlite"` when no dialect is passed, which is
 * correct only on the single-node path and on Postgres by accident (both
 * double-quote identifiers); on MySQL the default would emit double-quoted
 * identifiers MySQL reads as string literals, so framework-table SQL must
 * thread this value explicitly.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var dialect = b.clusterStorage.dialect();
 *   // → "sqlite"    (single-node)
 *   // → "postgres"  (cluster mode, postgres backend)
 *   // → "mysql"     (cluster mode, mysql backend)
 *   var built = b.sql.select("_blamejs_cache", { dialect: dialect })
 *     .where("cacheKey", "k").toSql();
 */
function dialect() {
  return cluster.isClusterMode() ? cluster.dialect() : "sqlite";
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

// Rewrite table for resolveTables(), derived from the static frozen
// frameworkSchema.LOCAL_TO_EXTERNAL mapping — never from operator/request
// input. The external names are PREFIX-AWARE: resolved through
// frameworkSchema.tableName(local) so a configured framework-table prefix
// (set config-time via db.init({tablePrefix})) is honored in cluster-mode
// DML, matching the prefix the DDL builders created the tables under.
// Order longest-first so prefix matches don't collide (audit_log before
// audit). Entries that are identity under the CURRENT prefix are filtered
// so the loop body has no no-op iterations — under the default prefix this
// is byte-identical to the old local→external map (the already-prefixed
// `_blamejs_*` names map to themselves and drop out); under a custom prefix
// those same names rewrite to `<prefix>*` and stay in.
function _buildRewriteTable() {
  var mapping = frameworkSchema.LOCAL_TO_EXTERNAL;
  var names = Object.keys(mapping).sort(function (a, b) {
    return b.length - a.length;
  });
  var entries = [];
  for (var i = 0; i < names.length; i++) {
    var local = names[i];
    var external = frameworkSchema.tableName(local);   // prefix-aware external name
    if (local === external) continue;                  // no-op under the current prefix
    entries.push({ local: local, external: external });
  }
  return Object.freeze(entries);
}

var _REWRITE_TABLE = null;
var _rewriteTablePrefix = null;

// The rewrite table for the current framework-table prefix, rebuilt if the
// prefix changed since the last build. db.init({tablePrefix}) sets the prefix
// once at boot (config-time), so the rebuild fires at most once; the prefix
// read is a cheap module-var getter, not request input.
function _rewriteTable() {
  var prefix = frameworkSchema.getTablePrefix();
  if (_REWRITE_TABLE === null || prefix !== _rewriteTablePrefix) {
    _REWRITE_TABLE = _buildRewriteTable();
    _rewriteTablePrefix = prefix;
  }
  return _REWRITE_TABLE;
}

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
  var rewrite = _rewriteTable();
  var translated = sql;
  for (var i = 0; i < rewrite.length; i++) {
    var entry = rewrite[i];
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
 * Postgres backends; passthrough for `"sqlite"` and `"mysql"`. The walker
 * skips a `?` inside a single-quoted string literal (`WHERE s = '?'`), a
 * double-quoted or backtick-quoted identifier (`"c?l"`), and a `--` or
 * block comment — so only a true bind marker is renumbered. This skip set
 * is a SUPERSET of `b.safeSql.countPlaceholders`'s, so the count used to
 * size params and the renumbering done here can never diverge (a `?` one
 * scanner counts but the other rewrites would mis-align bound values).
 * Doubled-quote escapes (`''` / `""`) inside their span are recognized.
 * The `execute` family calls this on every cluster-mode dispatch; reach
 * for it directly only when shipping raw SQL through a non-`execute` path.
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
  var out = "";
  var n = 0;
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var c = sql.charAt(i);
    var nx = i + 1 < len ? sql.charAt(i + 1) : "";
    // Quote contexts: ' string literal, " identifier, ` mysql identifier.
    // A doubled quote escapes itself within the span.
    if (c === "'" || c === '"' || c === "`") {
      out += c;
      i += 1;
      while (i < len) {
        var q = sql.charAt(i);
        if (q === c) {
          if (sql.charAt(i + 1) === c) { out += c + c; i += 2; continue; }
          out += c; i += 1; break;
        }
        out += q; i += 1;
      }
      continue;
    }
    if (c === "-" && nx === "-") {                              // line comment
      while (i < len && sql.charAt(i) !== "\n") { out += sql.charAt(i); i += 1; }
      continue;
    }
    if (c === "/" && nx === "*") {                              // block comment
      out += "/*"; i += 2;
      while (i < len && !(sql.charAt(i) === "*" && sql.charAt(i + 1) === "/")) { out += sql.charAt(i); i += 1; }
      if (i < len) { out += "*/"; i += 2; }
      continue;
    }
    if (c === "?") { n += 1; out += "$" + n; i += 1; continue; }
    out += c;
    i += 1;
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
// Single-node transaction serialization. node:sqlite is synchronous and
// the framework shares ONE local connection, so a SQLite transaction is
// connection-global: any statement that runs between this connection's
// BEGIN and COMMIT lands INSIDE the transaction. `_activeTx` is a promise
// held for the duration of a single-node transaction(); execute() waits it
// out before running so a concurrent statement can't interleave into the
// open transaction on the shared connection. It is null in cluster mode
// (the pool gives each transaction its own connection, so the DB enforces
// isolation and no global lock is needed).
var _activeTx = null;

// Raw local exec — synchronous, no transaction-lock wait. Used by execute()
// AFTER the lock wait and by transaction() for its own statements (which
// must NOT wait on the lock they themselves hold). Because node:sqlite is
// synchronous this runs atomically to completion with no interleaving.
function _localExec(sql, params) {
  var stmt = _localDb().prepare(sql);
  // Heuristic: if the statement returns rows (SELECT or has RETURNING),
  // use .all(); otherwise .run() and report changes as rowCount.
  if (/^\s*SELECT\b/i.test(sql) || /\bRETURNING\b/i.test(sql)) {
    var rows = stmt.all.apply(stmt, params || []);
    return { rows: rows, rowCount: rows.length };
  }
  var info = stmt.run.apply(stmt, params || []);
  return { rows: [], rowCount: info.changes };
}

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
    // Coerce backend-native types back to the framework's canonical JS shape
    // for every clusterStorage reader at once: node-postgres returns BIGINT /
    // int8 as a decimal string and BYTEA as a Buffer, so a framework column
    // read back from Postgres would otherwise be the wrong JS type (a counter
    // compared as a string, a hash/nonce mis-typed). coerceRows only touches
    // columns in the framework's type map; operator columns pass through, and
    // it is idempotent (already-correct types are left alone), so a reader
    // that also coerces locally is unaffected.
    if (result && Array.isArray(result.rows) && result.rows.length > 0) {
      result.rows = frameworkSchema.coerceRows(result.rows);
    }
    return result;
  }

  // Local SQLite path. Wait out any open single-node transaction so this
  // statement can't interleave into it on the shared connection. The loop
  // re-checks after each wait (a new transaction may have started while we
  // waited); once it exits, `_localExec` runs synchronously to completion,
  // so no transaction can begin between the check and the statement.
  while (_activeTx) { try { await _activeTx; } catch (_e) { /* tx failed — proceed */ } }
  return _localExec(sql, params);
}

/**
 * @primitive b.clusterStorage.transaction
 * @signature b.clusterStorage.transaction(fn)
 * @since     0.13.38
 * @status    stable
 * @related   b.clusterStorage.execute
 *
 * Run `fn` inside an atomic transaction against the active backend, so a
 * multi-statement read-modify-write commits all-or-nothing. `fn` receives a
 * transaction handle exposing the same `execute` / `executeOne` /
 * `executeAll` surface as the module — but scoped to the open transaction.
 * Use the handle's methods inside `fn`; calling the module-level
 * `b.clusterStorage.execute` from within `fn` would deadlock single-node
 * (it waits for the very transaction `fn` is running).
 *
 * Cluster mode dispatches to the external DB's transaction (its own pooled
 * connection + deadlock retry). Single-node serializes against other
 * transactions and against `execute` on the shared SQLite connection.
 *
 * @example
 *   await b.clusterStorage.transaction(async function (tx) {
 *     var row = await tx.executeOne("SELECT v FROM t WHERE k = ?", ["x"]);
 *     await tx.execute("UPDATE t SET v = ? WHERE k = ?", [row.v + 1, "x"]);
 *   });
 */
async function transaction(fn) {
  if (typeof fn !== "function") {
    throw new ClusterStorageError("transaction requires a function", "cluster-storage/bad-arg");
  }

  if (cluster.isClusterMode()) {
    var dialect = cluster.dialect();
    return await externalDb.transaction(async function (txClient) {
      function txExec(sql, params) {
        var translated = placeholderize(resolveTables(sql), dialect);
        return txClient.query(translated, params || []);
      }
      var txHandle = {
        execute:    txExec,
        executeOne: async function (sql, params) {
          var r = await txExec(sql, params); return r.rows.length > 0 ? r.rows[0] : null;
        },
        executeAll: async function (sql, params) {
          var r = await txExec(sql, params); return r.rows;
        },
      };
      return await fn(txHandle);
    }, { backend: cluster.externalDbBackend() });
  }

  // Single-node: serialize this transaction behind any other open one, then
  // hold `_activeTx` so concurrent execute()/transaction() calls wait.
  while (_activeTx) { try { await _activeTx; } catch (_e) { /* prior tx failed */ } }
  var releaseTx;
  _activeTx = new Promise(function (resolve) { releaseTx = resolve; });
  function txExecLocal(sql, params) { return Promise.resolve(_localExec(sql, params)); }
  var localHandle = {
    execute:    txExecLocal,
    executeOne: async function (sql, params) {
      var r = await txExecLocal(sql, params); return r.rows.length > 0 ? r.rows[0] : null;
    },
    executeAll: async function (sql, params) {
      var r = await txExecLocal(sql, params); return r.rows;
    },
  };
  try {
    _localExec("BEGIN", []);
    try {
      var result = await fn(localHandle);
      _localExec("COMMIT", []);
      return result;
    } catch (e) {
      try { _localExec("ROLLBACK", []); } catch (_e) { /* already errored */ }
      throw e;
    }
  } finally {
    var r = releaseTx; _activeTx = null; r();
  }
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
  transaction:           transaction,
  tableName:             tableName,
  dialect:               dialect,
  resolveTables:         resolveTables,
  placeholderize:        placeholderize,
  ClusterStorageError:   ClusterStorageError,
};
