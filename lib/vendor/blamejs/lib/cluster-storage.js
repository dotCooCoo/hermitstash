// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var C = require("./constants");
var safeAsync = require("./safe-async");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var lazyRequire = require("./lazy-require");

var FENCED_UPSERT_TIMEOUT_MS = C.TIME.seconds(30);
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

/**
 * @primitive b.clusterStorage.missingRelationCode
 * @signature b.clusterStorage.missingRelationCode(err)
 * @since     0.18.58
 * @status    stable
 * @related   b.clusterStorage.missingColumnCode, b.clusterStorage.execute
 *
 * Does this driver error's own structured fields say the table is
 * absent? Reads `errno`, `code` and `sqlState`, so it holds across
 * SQLite, Postgres and MySQL regardless of how each worded the
 * message or what locale it was worded in.
 *
 * It answers only what the driver stated. A caller that also wants to
 * recognize a driver carrying no code adds its own message test on
 * top — and that test is the caller's, because how much wording to
 * accept differs: Postgres words a missing COLUMN and a missing TABLE
 * identically apart from the noun, so a reader that falls back to an
 * older projection when a column is absent must not treat a bare
 * "does not exist" as an absent table.
 *
 * @example
 *   try { await b.clusterStorage.execute(sql); }
 *   catch (e) {
 *     if (b.clusterStorage.missingRelationCode(e)) return null;   // not created yet
 *     throw e;                                                    // a real failure
 *   }
 */
function missingRelationCode(e) {
  if (!e) return false;
  if (e.errno === 1146) return true;
  var code     = (e.code != null) ? String(e.code) : "";
  var sqlState = (e.sqlState != null) ? String(e.sqlState) : "";
  return code === "ER_NO_SUCH_TABLE" ||
    code === "42S02" || code === "42P01" ||
    sqlState === "42S02" || sqlState === "42P01";
}

/**
 * @primitive b.clusterStorage.missingColumnCode
 * @signature b.clusterStorage.missingColumnCode(err)
 * @since     0.18.58
 * @status    stable
 * @related   b.clusterStorage.missingRelationCode
 *
 * Does this driver error's own structured fields say the column is
 * absent? The column-level sibling of
 * `b.clusterStorage.missingRelationCode`, for a reader that widens or
 * narrows its projection to match a table older than the code reading
 * it. The two are separate because they mean opposite things to such
 * a reader: an absent table ends the read, an absent column sends it
 * to an earlier projection.
 *
 * @example
 *   if (b.clusterStorage.missingColumnCode(e)) return readOlderShape();
 *   throw e;
 */
function missingColumnCode(e) {
  if (!e) return false;
  if (e.errno === 1054) return true;
  var code     = (e.code != null) ? String(e.code) : "";
  var sqlState = (e.sqlState != null) ? String(e.sqlState) : "";
  return code === "ER_BAD_FIELD_ERROR" ||
    code === "42S22" || code === "42703" ||
    sqlState === "42S22" || sqlState === "42703";
}

/**
 * @primitive b.clusterStorage.duplicateIndexCode
 * @signature b.clusterStorage.duplicateIndexCode(err)
 * @since     0.18.58
 * @status    stable
 * @related   b.clusterStorage.missingRelationCode, b.clusterStorage.missingColumnCode
 *
 * Does this driver error's own structured fields say the index name is
 * already taken? For a reconciler re-issuing `CREATE INDEX` on MySQL,
 * which has no `IF NOT EXISTS` form, so a second pass has to tell "the
 * index is already there" — the intended end state — from a statement
 * that genuinely failed.
 *
 * Answering that from the message cannot work: a test for `exist` also
 * matches `Table 'db.X' doesn't exist`, so a `CREATE INDEX` that failed
 * because its table was missing got swallowed and the schema was
 * reported reconciled with the index never created.
 *
 * @example
 *   try { await b.clusterStorage.execute(createIndexSql); }
 *   catch (e) {
 *     if (b.clusterStorage.duplicateIndexCode(e)) return;   // already present
 *     throw e;                                              // a real failure
 *   }
 */
function duplicateIndexCode(e) {
  if (!e) return false;
  if (e.errno === 1061) return true;
  return ((e.code != null) ? String(e.code) : "") === "ER_DUP_KEYNAME";
}

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
      idx = haystack.indexOf(needle, idx + 1);
    }
  }
  if (!matched) return haystack;
  return out + haystack.slice(cursor);
}

function _buildRewriteTable() {
  var mapping = frameworkSchema.LOCAL_TO_EXTERNAL;
  var names = Object.keys(mapping).sort(function (a, b) {
    return b.length - a.length;
  });
  var entries = [];
  for (var i = 0; i < names.length; i++) {
    var local = names[i];
    var external = frameworkSchema.tableName(local);
    if (local === external) continue;
    entries.push({ local: local, external: external });
  }
  return Object.freeze(entries);
}

var _REWRITE_TABLE = null;
var _rewriteTablePrefix = null;

function _rewriteTable() {
  var prefix = frameworkSchema.getTablePrefix();
  if (_REWRITE_TABLE === null || prefix !== _rewriteTablePrefix) {
    _REWRITE_TABLE = _buildRewriteTable();
    _rewriteTablePrefix = prefix;
  }
  return _REWRITE_TABLE;
}

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
  return safeSql.toPositional(sql, dialect);
}

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
var _activeTx = null;

function _localExec(sql, params) {
  var stmt = _localDb().prepare(sql);
  if (externalDb._statementReturnsRows(sql)) {
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
    if (result && Array.isArray(result.rows) && result.rows.length > 0) {
      result.rows = frameworkSchema.coerceRows(result.rows);
    }
    return result;
  }

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
      async function txExec(sql, params) {
        var translated = placeholderize(resolveTables(sql), dialect);
        var result = await txClient.query(translated, params || []);
        if (result && Array.isArray(result.rows) && result.rows.length > 0) {
          result.rows = frameworkSchema.coerceRows(result.rows);
        }
        return result;
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

/**
 * @primitive b.clusterStorage.fencedUpsert
 * @signature b.clusterStorage.fencedUpsert(opts)
 * @since     0.18.58
 * @status    stable
 * @related   b.cluster.fencingToken, b.audit.checkpoint, b.auditTools.purge
 *
 * Upsert a single row only if the caller's fencing token is at least the one
 * already stored, and report whether it was refused. This is how a
 * single-writer table stays single-writer across processes: a leader that has
 * been superseded still holds a valid-looking handle and can still issue
 * writes, and only the stored token says its turn has passed. Returns
 * `{ fenced: true }` when a higher token has been seen, meaning the write did
 * not happen and this node should step down rather than retry.
 *
 * The three dialects disagree about how to express that, which is the reason
 * this is one primitive rather than a shape each caller re-derives. Postgres
 * and SQLite take a `WHERE` on the conflict clause and report the refusal by
 * returning no rows; MySQL's `ON DUPLICATE KEY UPDATE` has neither, so the
 * fence becomes a per-column `IF()` and the statement "succeeds" while
 * changing nothing — detection there has to read the stored token back.
 *
 * @opts
 *   table:       string,    // bare logical table name
 *   keyColumns:  string[],  // the conflict target
 *   values:      object,    // every column to write, including the fence column
 *   fenceColumn:  string,   // default: "fencingToken"
 *   fenceColumns: string[], // several, all of which must be non-decreasing — for a value like a purge boundary that may only ever advance
 *   label:       string,    // for the query timeout's diagnostics
 *   timeoutMs:   number,    // per-statement ceiling
 *
 * @example
 *   var r = await b.clusterStorage.fencedUpsert({
 *     table: "_blamejs_audit_tip", keyColumns: ["scope"],
 *     values: { scope: "audit", atMonotonicCounter: 42, fencingToken: 7 },
 *     label: "audit.tip",
 *   });
 *   if (r.fenced) throw new Error("superseded by a higher-token leader");
 */
async function fencedUpsert(opts) {
  var table       = opts.table;
  var keyColumns  = opts.keyColumns;
  var values      = opts.values;
  var fenceColumns = opts.fenceColumns ||
    [opts.fenceColumn || "fencingToken"];
  var label       = opts.label || table;
  var timeoutMs   = opts.timeoutMs || FENCED_UPSERT_TIMEOUT_MS;
  var d           = dialect();

  var columns = Object.keys(values);
  var updates = columns.filter(function (c) { return keyColumns.indexOf(c) === -1; });

  var clauses = fenceColumns.map(function (col) {
    safeSql.validateIdentifier(col);
    var existing = safeSql.quoteQualified([table, col], d, { allowReserved: true });   // allow:hand-rolled-sql
    var proposed = d === "mysql"
      ? "VALUES(" + safeSql.quoteIdentifier(col, "mysql", { allowReserved: true }) + ")"
      : "EXCLUDED." + safeSql.quoteIdentifier(col, d, { allowReserved: true });
    return existing + " <= " + proposed;
  });

  var built = sql.upsert(table, { dialect: d })   // allow:hand-rolled-sql
    .columns(columns)
    .values(values)
    .onConflict(keyColumns)
    .doUpdateFromExcluded(updates)
    .conflictWhere(clauses.join(" AND "), [], { guardColumn: fenceColumns[0] })
    .returning(fenceColumns)
    .toSql();

  if (d === "mysql") {
    return await safeAsync.withTimeout(transaction(async function (tx) {
      await tx.execute(built.sql, built.params);
      var back = await tx.executeOne(built.readbackSql.sql, built.readbackSql.params);
      if (!back) return { fenced: true };
      var refused = fenceColumns.some(function (col) {
        return Number(back[col]) > Number(values[col]);
      });
      return { fenced: refused };
    }), timeoutMs, { name: label });
  }
  var result = await safeAsync.withTimeout(
    execute(built.sql, built.params), timeoutMs, { name: label });
  return { fenced: !result.rows || result.rows.length === 0 };
}

module.exports = {
  execute:               execute,
  executeOne:            executeOne,
  executeAll:            executeAll,
  fencedUpsert:          fencedUpsert,
  transaction:           transaction,
  tableName:             tableName,
  dialect:               dialect,
  missingRelationCode:   missingRelationCode,
  missingColumnCode:     missingColumnCode,
  duplicateIndexCode:    duplicateIndexCode,
  resolveTables:         resolveTables,
  placeholderize:        placeholderize,
  ClusterStorageError:   ClusterStorageError,
};
