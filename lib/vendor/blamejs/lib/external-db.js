// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.externalDb
 * @nav    Data
 * @title  External Database
 *
 * @intro
 *   External-database integration for app data — Postgres / MySQL /
 *   SQLite / MongoDB connection pooling, retry, circuit breaker,
 *   classification routing, residency enforcement, and audit hooks.
 *
 *   Framework state (audit_log, consent_log, _blamejs_*) stays in the
 *   local SQLite via `b.db`. This module is for APP DATA — when an
 *   operator keeps domain tables in Postgres / MySQL / MongoDB / libsql,
 *   they configure a backend here and use `b.externalDb.query()` instead
 *   of `b.db.from()` for those tables. The same surface also serves
 *   cluster-mode coordination (leader election advisory locks,
 *   cross-replica routing) when the cluster provider points at the same
 *   backend.
 *
 *   Bring-your-own-client design (per "zero npm runtime deps" rule):
 *   the operator supplies the actual DB driver via each backend's
 *   `connect` / `query` / `close` hooks. The framework layers
 *   connection pooling (lazy-create, idle reaping), transient-error
 *   retry, per-backend circuit breaker, classification routing
 *   (which backend serves which data class), residency enforcement
 *   against `db.getDataResidency().region`, and audit hooks
 *   (`system.externaldb.{query,transaction,read}`).
 *
 *   Read-replica routing exposes `b.externalDb.read.query()` and
 *   `b.externalDb.write.query()` — reads weight-round-robin across
 *   declared replicas with health tracking and primary fallback;
 *   writes always route to primary.
 *
 * @card
 *   External-database integration for app data — Postgres / MySQL / SQLite / MongoDB connection pooling, retry, circuit breaker, classification routing, residency enforcement, and audit hooks.
 */
var retryHelper = require("./retry");
var safeBuffer = require("./safe-buffer");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var dbRoleContext = require("./db-role-context");
var externalDbMigrate = require("./external-db-migrate");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeSql = require("./safe-sql");
var validateOpts = require("./validate-opts");
var codepointClass = require("./codepoint-class");
var { ExternalDbError } = require("./framework-error");

var log = boot("external-db");

var audit         = lazyRequire(function () { return require("./audit"); });
var db            = lazyRequire(function () { return require("./db"); });
var observability = lazyRequire(function () { return require("./observability"); });
// b.sql composes the framework's own internal queries against a backend
// (e.g. the pg_roles hardening scan). Lazy because b.sql -> framework-schema
// -> external-db would cycle at module load; resolved when a query runs.
var sql    = lazyRequire(function () { return require("./sql"); });

function _emitMetric(name, value, labels) {
  try { observability().event(name, value, labels || {}); }
  catch (_e) { /* hot-path observability sink — drop silent by design */ }
}

var _STATEMENT_CLASS_RE = /^(?:\s|\/\*(?:[^*]|\*(?!\/))*\*\/|--[^\n]*\n)*([A-Za-z]+)/;
var _STATEMENT_CLASS_MAP = Object.freeze({
  SELECT: "SELECT", VALUES: "SELECT", TABLE: "SELECT",   // allow:hand-rolled-sql — leading-keyword classifier table, not composed SQL
  SHOW: "READ_INFO", DESCRIBE: "READ_INFO", DESC: "READ_INFO",
  PRAGMA: "READ_INFO", USE: "READ_INFO",
  INSERT: "DML", UPDATE: "DML", DELETE: "DML", MERGE: "DML",
  UPSERT: "DML", REPLACE: "DML",
  CREATE: "DDL", DROP: "DDL", ALTER: "DDL", TRUNCATE: "DDL",
  RENAME: "DDL", COMMENT: "DDL",
  GRANT: "DCL", REVOKE: "DCL",
  SET: "SESSION", RESET: "SESSION",
  BEGIN: "TX", START: "TX", COMMIT: "TX", ROLLBACK: "TX",
  SAVEPOINT: "TX", RELEASE: "TX",
  CALL: "ROUTINE", EXECUTE: "ROUTINE", DO: "ROUTINE",
  COPY: "BULK",
  EXPLAIN: "META", ANALYZE: "META", VACUUM: "META",
});

var _CTE_MAIN_VERBS = Object.freeze({
  SELECT: true, VALUES: true, TABLE: true,
  INSERT: true, UPDATE: true, DELETE: true,
  MERGE: true, UPSERT: true, REPLACE: true,
});

function _isIdentStart(ch) {
  return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch === "_";
}
function _isIdentChar(ch) {
  return _isIdentStart(ch) || (ch >= "0" && ch <= "9");
}

function _skipOpaqueSpan(sql, i) {
  var n = sql.length;
  var ch = sql.charAt(i);
  if (ch === "'" || ch === "\"" || ch === "`") {
    var close = sql.indexOf(ch, i + 1);
    return close === -1 ? -1 : close + 1;
  }
  if (ch === "[") {
    var rb = sql.indexOf("]", i + 1);
    return rb === -1 ? -1 : rb + 1;
  }
  if (ch === "$") {
    var tagEnd = i + 1;
    while (tagEnd < n && _isIdentChar(sql.charAt(tagEnd))) tagEnd += 1;
    if (tagEnd < n && sql.charAt(tagEnd) === "$") {
      var tag = sql.slice(i, tagEnd + 1);
      var closeTag = sql.indexOf(tag, tagEnd + 1);
      return closeTag === -1 ? -1 : closeTag + tag.length;
    }
    return i;
  }
  if (ch === "-" && sql.charAt(i + 1) === "-") {
    var nl = sql.indexOf("\n", i + 2);
    return nl === -1 ? -1 : nl + 1;
  }
  if (ch === "/" && sql.charAt(i + 1) === "*") {
    var ce = sql.indexOf("*/", i + 2);
    return ce === -1 ? -1 : ce + 2;
  }
  return i;
}

function _cteMainKeyword(sql, start) {
  var n = sql.length;
  var depth = 0;
  var i = start;
  while (i < n) {
    var ch = sql.charAt(i);
    var skipped = _skipOpaqueSpan(sql, i);
    if (skipped === -1) return null;
    if (skipped !== i) { i = skipped; continue; }
    if (ch === "(") { depth += 1; i += 1; continue; }
    if (ch === ")") { depth -= 1; i += 1; continue; }
    if (_isIdentStart(ch)) {
      var we = i + 1;
      while (we < n && _isIdentChar(sql.charAt(we))) we += 1;
      if (depth === 0) {
        var word = sql.slice(i, we).toUpperCase();
        if (_CTE_MAIN_VERBS[word] === true) return word;
      }
      i = we;
      continue;
    }
    i += 1;
  }
  return null;
}

var _EXPLAIN_OPTION_WORDS = Object.freeze({
  ANALYZE: true, VERBOSE: true, COSTS: true, BUFFERS: true,
  SETTINGS: true, WAL: true, TIMING: true, SUMMARY: true,
  SERIALIZE: true, MEMORY: true, GENERIC_PLAN: true, FORMAT: true,
  TEXT: true, JSON: true, YAML: true, XML: true, TREE: true,
  EXTENDED: true, PARTITIONS: true,
  ON: true, OFF: true, TRUE: true, FALSE: true,
});

function _explainResolve(sql, start) {
  var n = sql.length;
  var hasAnalyze = false;
  var i = start;
  while (i < n) {
    var ch = sql.charAt(i);
    var skipped = _skipOpaqueSpan(sql, i);
    if (skipped === -1) return null;
    if (skipped !== i) { i = skipped; continue; }
    if (ch === "(") {
      var depth = 0;
      var j = i;
      while (j < n) {
        var c2 = sql.charAt(j);
        var s2 = _skipOpaqueSpan(sql, j);
        if (s2 === -1) return null;
        if (s2 !== j) { j = s2; continue; }
        if (c2 === "(") { depth += 1; j += 1; continue; }
        if (c2 === ")") { depth -= 1; j += 1; if (depth === 0) break; continue; }
        if (_isIdentStart(c2)) {
          var oe = j + 1;
          while (oe < n && _isIdentChar(sql.charAt(oe))) oe += 1;
          if (sql.slice(j, oe).toUpperCase() === "ANALYZE") hasAnalyze = true;
          j = oe;
          continue;
        }
        j += 1;
      }
      if (depth !== 0) return null;
      i = j;
      continue;
    }
    if (_isIdentStart(ch)) {
      var we = i + 1;
      while (we < n && _isIdentChar(sql.charAt(we))) we += 1;
      var word = sql.slice(i, we).toUpperCase();
      if (word === "ANALYZE") { hasAnalyze = true; i = we; continue; }
      if (_EXPLAIN_OPTION_WORDS[word] === true) { i = we; continue; }
      return { hasAnalyze: hasAnalyze, innerStart: i };
    }
    i += 1;
  }
  return null;
}

function _copyLoadsRows(sql) {
  var m = _STATEMENT_CLASS_RE.exec(sql);
  if (!m) return true;
  var n = sql.length;
  var i = m.index + m[0].length;
  while (i < n) {
    var ch = sql.charAt(i);
    var skipped = _skipOpaqueSpan(sql, i);
    if (skipped === -1) return true;
    if (skipped !== i) { i = skipped; continue; }
    if (ch === "(") {
      var depth = 0;
      var j = i;
      while (j < n) {
        var c2 = sql.charAt(j);
        var s2 = _skipOpaqueSpan(sql, j);
        if (s2 === -1) return true;
        if (s2 !== j) { j = s2; continue; }
        if (c2 === "(") { depth += 1; j += 1; continue; }
        if (c2 === ")") { depth -= 1; j += 1; if (depth === 0) break; continue; }
        j += 1;
      }
      i = j;
      continue;
    }
    if (_isIdentStart(ch)) {
      var we = i + 1;
      while (we < n && _isIdentChar(sql.charAt(we))) we += 1;
      var word = sql.slice(i, we).toUpperCase();
      if (word === "FROM") return true;
      if (word === "TO") return false;
      i = we;
      continue;
    }
    i += 1;
  }
  return true;
}

function _classifyStatement(sql) {
  if (typeof sql !== "string" || sql.length === 0) return "UNKNOWN";
  var m = _STATEMENT_CLASS_RE.exec(sql);
  if (!m) return "UNKNOWN";
  var kw = m[1].toUpperCase();
  if (kw === "WITH") {
    var main = _cteMainKeyword(sql, m.index + m[0].length);
    return main === null ? "UNKNOWN" : (_STATEMENT_CLASS_MAP[main] || "OTHER");
  }
  if (kw === "EXPLAIN") {
    var ex = _explainResolve(sql, m.index + m[0].length);
    if (ex === null) return "UNKNOWN";
    if (!ex.hasAnalyze) return "META";
    return _classifyStatement(sql.slice(ex.innerStart));
  }
  return _STATEMENT_CLASS_MAP[kw] || "OTHER";
}

function _hasTopLevelReturning(sql) {
  var n = sql.length, i = 0, depth = 0;
  while (i < n) {
    var skipped = _skipOpaqueSpan(sql, i);
    if (skipped === -1) return false;
    if (skipped !== i) { i = skipped; continue; }
    var ch = sql.charAt(i);
    if (ch === "(") { depth += 1; i += 1; continue; }
    if (ch === ")") { depth -= 1; i += 1; continue; }
    if (_isIdentStart(ch)) {
      var we = i + 1;
      while (we < n && _isIdentChar(sql.charAt(we))) we += 1;
      if (depth === 0 && sql.slice(i, we).toUpperCase() === "RETURNING") return true;
      i = we;
      continue;
    }
    i += 1;
  }
  return false;
}

var _ROW_RETURNING_CLASS = Object.freeze({ SELECT: true, READ_INFO: true });

function statementReturnsRows(sql) {
  if (typeof sql !== "string" || sql.length === 0) return false;
  var m = _STATEMENT_CLASS_RE.exec(sql);
  if (m && m[1].toUpperCase() === "EXPLAIN") {
    return _explainResolve(sql, m.index + m[0].length) !== null;
  }
  if (_ROW_RETURNING_CLASS[_classifyStatement(sql)] === true) return true;
  return _hasTopLevelReturning(sql);
}

var _RESIDENCY_READ_CLASS = Object.freeze({
  SELECT: true, READ_INFO: true, SESSION: true,
  TX: true, DCL: true, DDL: true, META: true,
});

var _OTEL_DB_SYSTEM = Object.freeze({
  postgres: "postgresql",
  mysql:    "mysql",
  sqlite:   "sqlite",
  mongodb:  "mongodb",
  other:    "other_sql",
});

function _otelOperation(sql) {
  if (typeof sql !== "string" || sql.length === 0) return null;
  var m = _STATEMENT_CLASS_RE.exec(sql);
  if (!m) return null;
  return m[1].toUpperCase();
}

function _otelDbAttributes(b, sql, includeStatement) {
  var attrs = {
    "db.system":    _OTEL_DB_SYSTEM[b.dialect] || "other_sql",
    "db.name":      b.name,
  };
  var op = _otelOperation(sql);
  if (op !== null) attrs["db.operation"] = op;
  if (includeStatement) {
    attrs["db.statement"] = String(sql == null ? "" : sql).slice(0, 256);
  }
  return attrs;
}

var _RELATION_RE = /\b(?:FROM|INTO|UPDATE|JOIN|TABLE|COPY)\s+((?:"[^"]+"|`[^`]+`|[A-Za-z_][\w$]*)(?:\.(?:"[^"]+"|`[^`]+`|[A-Za-z_][\w$]*))?)/ig;
function _hasControlChar(s) {
  return codepointClass.firstControlCharOffset(s, { forbidTab: true }) !== -1;
}
function _extractTargetRelation(sql) {
  if (typeof sql !== "string" || sql.length === 0) return null;
  var clean = sql.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");
  _RELATION_RE.lastIndex = 0;
  var m = _RELATION_RE.exec(clean);
  if (!m) return null;
  var segs = m[1].split(".").map(function (s) { return s.replace(/^["`]|["`]$/g, ""); });
  for (var i = 0; i < segs.length; i += 1) {
    if (segs[i].length === 0 || _hasControlChar(segs[i])) return null;
  }
  return segs.join(".");
}

function _countTargetRelations(sql) {
  if (typeof sql !== "string") return 0;
  var clean = sql.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");
  _RELATION_RE.lastIndex = 0;
  var n = 0;
  while (_RELATION_RE.exec(clean) !== null) n += 1;
  return n;
}

var _AUTH_FAILURE_CODES = Object.freeze({
  "28000": "invalid_authorization_specification",
  "28P01": "invalid_password",
  "42501": "insufficient_privilege",
});

function _emitAuthFailureAudit(backend, role, sql, e) {
  if (!e || !e.code) return;
  var kind = _AUTH_FAILURE_CODES[e.code];
  if (!kind) return;
  var attemptedTable = _extractTargetRelation(sql);
  var relationCount  = _countTargetRelations(sql);
  var resource = { kind: "db.backend", id: backend.name };
  if (attemptedTable !== null) resource.attemptedTable = attemptedTable;
  audit().safeEmit({
    action:   "db.auth.failed",
    actor:    {},
    resource: resource,
    outcome:  "denied",
    reason:   kind,
    metadata: {
      backend:               backend.name,
      dialect:               backend.dialect,
      sqlIdentity:           role || null,
      sqlstate:              e.code,
      statementClass:        _classifyStatement(sql),
      attemptedTable:        attemptedTable,
      attemptedRelationCount: relationCount,
    },
  });
  _emitMetric("db.auth.failed", 1, {
    backend:        backend.name,
    sqlstate:       e.code,
    statementClass: _classifyStatement(sql),
  });
}

var _SLOW_QUERY_BUCKETS = Object.freeze([
  { ms: C.TIME.seconds(30), label: "30s" },
  { ms: C.TIME.seconds(5),  label: "5s" },
  { ms: C.TIME.seconds(1),  label: "1s" },
]);

function _emitSlowQuery(backendName, role, durationMs, statementClass) {
  if (typeof durationMs !== "number" || !isFinite(durationMs)) return;
  for (var i = 0; i < _SLOW_QUERY_BUCKETS.length; i++) {
    var bucket = _SLOW_QUERY_BUCKETS[i];
    if (durationMs >= bucket.ms) {
      _emitMetric("db.query.slow", durationMs, {
        backend:        backendName,
        role:           role || "(none)",
        bucket:         bucket.label,
        statementClass: statementClass || "UNKNOWN",
      });
      return;
    }
  }
}

var _err = ExternalDbError.factory;

var initialized = false;
var backends = {};
var defaultBackend = null;
var dbRoleBackends = {};

class Pool {
  constructor(name, config) {
    this.name = name;
    this.config = Object.assign({ min: 1, max: 10, idleTimeoutMs: C.TIME.minutes(1) }, config.pool || {});
    this.connect = config.connect;
    this.close = config.close || function () { return Promise.resolve(); };
    this.idle = [];
    this.active = 0;
    this.waiters = [];
    this._reaper = safeAsync.repeating(this._reapIdle.bind(this),
      C.TIME.seconds(10), { name: "external-db-reaper" });
  }

  async acquire() {
    if (this.idle.length > 0) {
      var entry = this.idle.pop();
      this.active += 1;
      return entry.client;
    }
    if (this.active < this.config.max) {
      this.active += 1;
      try {
        return await this.connect();
      } catch (e) {
        this.active -= 1;
        throw e;
      }
    }
    var self = this;
    var waitStartedAt = Date.now();
    return new Promise(function (resolve, reject) {
      self.waiters.push({
        resolve: function (client) {
          _emitMetric("externaldb.pool.acquire_wait", Date.now() - waitStartedAt,
            { backend: self.name });
          resolve(client);
        },
        reject:  reject,
      });
    });
  }

  release(client) {
    this.active -= 1;
    if (this.waiters.length > 0) {
      var w = this.waiters.shift();
      this.active += 1;
      w.resolve(client);
      return;
    }
    this.idle.push({ client: client, lastUsedAt: Date.now() });
  }

  async destroy(client) {
    this.active -= 1;
    try { await this.close(client); } catch (_e) { /* best effort */ }
    if (this.waiters.length > 0) {
      var w = this.waiters.shift();
      this.acquire().then(w.resolve, w.reject);
    }
  }

  _reapIdle() {
    var min = (typeof this.config.min === "number" && isFinite(this.config.min) && this.config.min > 0)
      ? this.config.min : 0;
    var reapable = this.idle.length - min;
    if (reapable <= 0) return;
    var now = Date.now();
    var keep = [];
    var reaped = 0;
    var self = this;
    this.idle.forEach(function (entry) {
      if (reaped < reapable && (now - entry.lastUsedAt) >= self.config.idleTimeoutMs) {
        reaped += 1;
        Promise.resolve().then(function () { return self.close(entry.client); }).catch(function () {});
      } else {
        keep.push(entry);
      }
    });
    this.idle = keep;
  }

  async drain() {
    if (this._reaper) { this._reaper.stop(); this._reaper = null; }
    var idleClients = this.idle.map(function (e) { return e.client; });
    this.idle = [];
    var self = this;
    await Promise.all(idleClients.map(function (c) {
      return Promise.resolve().then(function () { return self.close(c); }).catch(function () {});
    }));
    this.waiters.forEach(function (w) { w.reject(_err("external-db/pool-drained", "pool is shutting down", true)); });
    this.waiters = [];
  }

  stats() {
    return { active: this.active, idle: this.idle.length, waiters: this.waiters.length };
  }
}

/**
 * @primitive b.externalDb.init
 * @signature b.externalDb.init(opts)
 * @since     0.4.0
 * @related   b.externalDb.query, b.externalDb.shutdown, b.externalDb.adapters.connectAs
 *
 * Register one or more app-data backends. Each backend declares its
 * `connect` / `query` driver hooks plus optional pooling, classification,
 * residency, retry, and replica configuration. Throws synchronously on
 * malformed input (missing hooks, unknown dialect, residency mismatch
 * against `db.getDataResidency()`, dotted GUC names that fail
 * identifier validation).
 *
 * Boot-time residency check: when `db.getDataResidency().region` is set,
 * any backend serving `personal` (or `*`) data must carry a
 * `residencyTag` in the allowed-region list — refused with
 * `external-db/residency-violation` when not.
 *
 * Opt-in transport posture: set `requireTls: true` on a backend to
 * refuse it at config time (`external-db/tls-required`) unless its declared
 * transport is encrypted (`tls: true`, an `ssl` object, or
 * `sslmode: "require" | "verify-ca" | "verify-full"`). `sslmode` values
 * that permit a plaintext fallback (`prefer` / `allow` / `disable`) are
 * refused. The gate is OFF by default — a backend that omits
 * `requireTls` is used exactly as supplied, with no transport check.
 * Mandated for cardholder data by PCI-DSS v4.0 Req 4 and for ePHI by
 * HIPAA §164.312(e).
 *
 * @opts
 *   backends:        { [name]: BackendConfig },   // required; one or more named backends
 *   defaultBackend?: string,                      // pool used when no opts.backend / classification / role match (defaults to first)
 *   dbRoleBackends?: { [sqlRole]: backendName },  // request-time role → backend mapping for the dbRoleFor middleware
 *
 *   // BackendConfig shape:
 *   //   connect():            async () → driver client                 (required)
 *   //   query(client, sql, p): async → { rows, rowCount }              (required)
 *   //   close(client):        async → void                             (optional; default no-op)
 *   //   ping(client):         async → void                             (optional; default `SELECT 1`)
 *   //   beginTx / commit / rollback(client):  async → void             (optional; default `BEGIN`/`COMMIT`/`ROLLBACK`)
 *   //   batch(client, statements):  async → void                        (optional; atomic multi-statement path for batch-only adapters, e.g. D1 db.batch)
 *   //   supportsTransactions:  boolean                                  (interactive-tx capability; set false on a stateless/autocommit-per-statement adapter so transaction()/outbox REFUSE rather than silently run non-atomic — default assumes stateful)
 *   //   dialect:              "postgres" | "mysql" | "sqlite" | "mongodb" | "other"  (default "postgres")
 *   //   requireTls:           boolean                                  (opt-in TLS posture gate; default off — see below)
 *   //   tls / ssl / sslmode:  transport-TLS declaration consulted by requireTls (tls:true | ssl:<obj> | sslmode:"require"|"verify-ca"|"verify-full")
 *   //   applicationName:      string ≤ 63 bytes, no CR/LF/NUL          (Postgres pg_stat_activity tag; default null)
 *   //   pool:                 { min, max, idleTimeoutMs }              (defaults: 1 / 10 / C.TIME.minutes(1))
 *   //   classifications:      string[]                                 (defaults to ["*"])
 *   //   residencyTag:         "EU" | "US" | "unrestricted" | ...       (defaults to "unrestricted")
 *   //   retry, breaker:       passthrough to b.retry / CircuitBreaker
 *   //   replicas:             [{ connect, query, weight?, residencyTag?, allowCrossBorder? }]
 *   //   replicaFallbackToPrimary: boolean                              (default true)
 *
 * @example
 *   var pg = require("pg");
 *   var pool = new pg.Pool({ connectionString: "postgres://app:pw@db.example.com/app" });
 *
 *   b.externalDb.init({
 *     backends: {
 *       main: {
 *         dialect:         "postgres",
 *         applicationName: "blamejs-app",
 *         connect:         function () { return pool.connect(); },
 *         query:           function (client, sql, params) { return client.query(sql, params); },
 *         close:           function (client) { return client.release(); },
 *         classifications: ["personal", "operational"],
 *         residencyTag:    "EU",
 *         pool:            { min: 2, max: 20, idleTimeoutMs: 60000 },
 *       },
 *     },
 *     defaultBackend: "main",
 *   });
 */
function init(opts) {
  if (initialized) return;
  if (!opts || !opts.backends) throw new Error("externalDb.init({ backends }) is required");

  backends = {};
  dbRoleBackends = {};
  for (var name in opts.backends) {
    var cfg = opts.backends[name];
    if (typeof cfg.connect !== "function") {
      throw _err("external-db/invalid-config", "backend '" + name + "' missing connect() function", true);
    }
    if (typeof cfg.query !== "function") {
      throw _err("external-db/invalid-config", "backend '" + name + "' missing query() function", true);
    }
    var dialect = (cfg.dialect || "postgres").toLowerCase();
    if (["postgres", "mysql", "sqlite", "mongodb", "other"].indexOf(dialect) === -1) {
      throw _err("external-db/invalid-config",
        "backend '" + name + "': dialect must be one of " +
        "'postgres' | 'mysql' | 'sqlite' | 'mongodb' | 'other', got '" + dialect + "'", true);
    }
    _assertConnectionTls(name, cfg);
    var applicationName = cfg.applicationName !== undefined ? cfg.applicationName : null;
    if (applicationName !== null && (typeof applicationName !== "string" || applicationName.length === 0)) {
      throw _err("external-db/invalid-config",
        "backend '" + name + "': applicationName must be a non-empty string", true);
    }
    if (applicationName !== null) {
      // eslint-disable-next-line no-control-regex
      if (/[\r\n\u0000]/.test(applicationName)) {
      throw _err("external-db/invalid-config",
        "backend '" + name + "': applicationName must not contain CR, LF, or NUL characters", true);
      }
      if (safeBuffer.byteLengthOf(applicationName) > C.BYTES.bytes(63)) {
      throw _err("external-db/invalid-config",
        "backend '" + name + "': applicationName exceeds Postgres 63-byte limit (got " +
        applicationName.length + ")", true);
      }
    }
    if (cfg.supportsTransactions !== undefined && cfg.supportsTransactions !== null) {
      validateOpts.optionalBoolean(cfg.supportsTransactions,
        "backend '" + name + "': supportsTransactions", ExternalDbError, "external-db/invalid-config");
    }
    if (cfg.batch !== undefined && cfg.batch !== null && typeof cfg.batch !== "function") {
      throw _err("external-db/invalid-config",
        "backend '" + name + "': batch must be a function (client, statements) when supplied", true);
    }
    var hasInteractiveHooks =
      typeof cfg.beginTx === "function" &&
      typeof cfg.commit === "function" &&
      typeof cfg.rollback === "function";
    var hasBatch = typeof cfg.batch === "function";
    var supportsTransactions;
    if (cfg.supportsTransactions === false) {
      supportsTransactions = false;
    } else {
      supportsTransactions = true;
    }

    var rawConnect = cfg.connect;
    var rawQuery   = cfg.query;
    var connectFn = rawConnect;
    if (dialect === "postgres" && applicationName !== null) {
      connectFn = (function (cn, qn, appName) {
        var quotedAppName = "'" + appName.replace(/'/g, "''") + "'";
        return async function () {
          var client = await cn();
          try {
            await qn(client, "SET application_name TO " + quotedAppName, []);   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
          } catch (_e) {
            void _e;
          }
          return client;
        };
      })(rawConnect, rawQuery, applicationName);
    }
    var poolCfg = Object.assign({}, cfg, { connect: connectFn });
    backends[name] = {
      name:            name,
      dialect:         dialect,
      applicationName: applicationName,
      pool:            new Pool(name, poolCfg),
      query:           cfg.query,
      ping:            cfg.ping || null,
      beginTx:         cfg.beginTx  || function (client) { return cfg.query(client, "BEGIN", []); },
      commit:          cfg.commit   || function (client) { return cfg.query(client, "COMMIT", []); },
      rollback:        cfg.rollback || function (client) { return cfg.query(client, "ROLLBACK", []); },
      supportsTransactions: supportsTransactions,
      hasInteractiveHooks:  hasInteractiveHooks,
      batch:                hasBatch ? cfg.batch : null,
      classifications: Array.isArray(cfg.classifications) && cfg.classifications.length > 0
                         ? cfg.classifications.slice()
                         : ["*"],
      residencyTag:    cfg.residencyTag || "unrestricted",
      breaker:         new retryHelper.CircuitBreaker("externalDb:" + name, cfg.breaker),
      retryConfig:     cfg.retry || null,
      replicas:        _buildReplicas(name, cfg),
      replicaIdx:      0,
      replicaFallbackToPrimary: cfg.replicaFallbackToPrimary !== false,
    };
  }

  if (opts.defaultBackend !== undefined && opts.defaultBackend !== null) {
    validateOpts.requireNonEmptyString(opts.defaultBackend, "defaultBackend", ExternalDbError, "external-db/invalid-config");
    if (!Object.prototype.hasOwnProperty.call(backends, opts.defaultBackend)) {
      throw _err("external-db/invalid-config",
        "defaultBackend: no backend named '" + opts.defaultBackend + "' " +
        "(declared backends: " + Object.keys(backends).join(", ") + ")", true);
    }
    defaultBackend = opts.defaultBackend;
  } else {
    defaultBackend = Object.keys(backends)[0];
  }

  if (opts.dbRoleBackends !== undefined && opts.dbRoleBackends !== null) {
    if (typeof opts.dbRoleBackends !== "object" || Array.isArray(opts.dbRoleBackends)) {
      throw _err("external-db/invalid-config",
        "dbRoleBackends must be an object map of role → backendName", true);
    }
    for (var role in opts.dbRoleBackends) {
      if (!Object.prototype.hasOwnProperty.call(opts.dbRoleBackends, role)) continue;
      try {
        safeSql.validateIdentifier(role, { allowReserved: false });
      } catch (e) {
        throw _err("external-db/invalid-config",
          "dbRoleBackends: role '" + role + "' is not a valid SQL identifier: " +
          ((e && e.message) || String(e)), true);
      }
      var bn = opts.dbRoleBackends[role];
      if (typeof bn !== "string" || bn.length === 0) {
        throw _err("external-db/invalid-config",
          "dbRoleBackends['" + role + "']: backend name must be a non-empty string", true);
      }
      if (!Object.prototype.hasOwnProperty.call(backends, bn)) {
        throw _err("external-db/invalid-config",
          "dbRoleBackends['" + role + "']: no backend named '" + bn + "' " +
          "(declared backends: " + Object.keys(backends).join(", ") + ")", true);
      }
      dbRoleBackends[role] = bn;
    }
  }

  _validateResidency();
  initialized = true;
}

var _TLS_GUARANTEED_SSLMODES = Object.freeze({
  require:       true,
  "verify-ca":   true,
  "verify-full": true,
});
var _TLS_PLAINTEXT_SSLMODES = Object.freeze({
  disable: true,
  allow:   true,
  prefer:  true,
});

function _declaresTls(cfg) {
  if (cfg.tls === true) return true;
  if (cfg.ssl !== undefined && cfg.ssl !== null && cfg.ssl !== false) return true;
  if (typeof cfg.sslmode === "string") {
    return _TLS_GUARANTEED_SSLMODES[cfg.sslmode.toLowerCase()] === true;
  }
  return false;
}

function _assertConnectionTls(name, cfg) {
  if (cfg.requireTls === undefined || cfg.requireTls === null) return;
  validateOpts.optionalBoolean(cfg.requireTls,
    "backend '" + name + "': requireTls", ExternalDbError, "external-db/invalid-config");
  if (cfg.requireTls !== true) return;
  if (_declaresTls(cfg)) return;
  var declared;
  if (typeof cfg.sslmode === "string" && _TLS_PLAINTEXT_SSLMODES[cfg.sslmode.toLowerCase()]) {
    declared = "sslmode '" + cfg.sslmode +
      "' permits a plaintext fallback (only 'require' / 'verify-ca' / 'verify-full' guarantee encryption)";
  } else if (cfg.tls === false || cfg.ssl === false) {
    declared = "transport is declared non-TLS (tls/ssl is false)";
  } else {
    declared = "no TLS transport is declared (set tls: true, an ssl object, or sslmode: 'require' / 'verify-ca' / 'verify-full')";
  }
  throw _err("external-db/tls-required",
    "backend '" + name + "': requireTls is set but " + declared +
    ". PCI-DSS v4.0 Req 4 / HIPAA §164.312(e) require an encrypted channel " +
    "for cardholder data / ePHI in transit.", true);
}

function _validateResidency() {
  var residency;
  try { residency = db().getDataResidency(); } catch (_e) { residency = null; }
  if (!residency || !residency.region) return;

  var allowed = [residency.region].concat(residency.allowedStorageRegions || []);
  for (var name in backends) {
    var b = backends[name];
    var serves = b.classifications.indexOf("*") !== -1 || b.classifications.indexOf("personal") !== -1;
    if (!serves) continue;
    if (allowed.indexOf(b.residencyTag) === -1) {
      throw _err("external-db/residency-violation",
        "externalDb backend '" + name + "' serves 'personal' data with residencyTag '" +
        b.residencyTag + "' but app's dataResidency.region is '" + residency.region + "'",
        true);
    }
  }
}

function _pickBackend(opts) {
  opts = opts || {};
  if (opts.backend) {
    var b = backends[opts.backend];
    if (!b) throw _err("external-db/unknown-backend", "no backend named '" + opts.backend + "'", true);
    if (opts.classification && !_servesClassification(b, opts.classification)) {
      throw _err("external-db/classification-mismatch",
        "backend '" + opts.backend + "' does not serve classification '" + opts.classification + "'", true);
    }
    return b;
  }
  var classification = opts.classification;
  if (classification) {
    for (var name in backends) {
      if (_servesClassification(backends[name], classification)) return backends[name];
    }
    throw _err("external-db/no-backend-for-classification",
      "no backend serves classification '" + classification + "'", true);
  }
  var role = dbRoleContext.getRole();
  if (role && Object.prototype.hasOwnProperty.call(dbRoleBackends, role)) {
    return backends[dbRoleBackends[role]];
  }
  return backends[defaultBackend] || null;
}

function _servesClassification(b, cls) {
  return b.classifications.indexOf("*") !== -1 || b.classifications.indexOf(cls) !== -1;
}

function _assertInteractiveTransactions(b, where) {
  if (!b) return;
  if (b.supportsTransactions === false) {
    throw _err("external-db/non-atomic-backend",
      "externalDb." + where + " requires an interactive transaction, but backend '" +
      b.name + "' declares supportsTransactions: false (a stateless / " +
      "autocommit-per-statement adapter). BEGIN / the body statements / COMMIT " +
      "would each run on a different session — no isolation, no rollback — so the " +
      "block would NOT be atomic. Supply interactive beginTx / commit / rollback " +
      "hooks, or a batch(client, statements) adapter, on this backend before using " +
      "externalDb." + where + " (and b.outbox, which is built on it).",
      true);
  }
}

/**
 * @primitive b.externalDb.supportsTransactions
 * @signature b.externalDb.supportsTransactions(opts?)
 * @since     0.15.16
 * @related   b.externalDb.transaction, b.externalDb.init
 *
 * Report whether the picked (or default) backend can provide an
 * interactive transaction. Returns `false` only when the backend declares
 * `supportsTransactions: false` at `init()` — a stateless /
 * autocommit-per-statement adapter on which `transaction()` would run
 * `BEGIN` / the body / `COMMIT` on different sessions (no isolation, no
 * rollback). Consumers built on the dual-write guarantee (`b.outbox`) call
 * this at construction so a non-atomic backend is refused up front rather
 * than at the first transaction.
 *
 * Same backend-selection `opts` as `b.externalDb.query` (`backend` /
 * `classification`).
 *
 * @opts
 *   backend?:        string,   // explicit backend name
 *   classification?: string,   // route by data class
 *
 * @example
 *   if (!b.externalDb.supportsTransactions()) {
 *     throw new Error("this backend cannot run atomic transactions");
 *   }
 */
function supportsTransactions(opts) {
  _requireInit();
  var b = _pickBackend(opts);
  return !!(b && b.supportsTransactions !== false);
}

/**
 * @primitive b.externalDb.query
 * @signature b.externalDb.query(sql, params, opts)
 * @since     0.4.0
 * @related   b.externalDb.transaction, b.externalDb.read.query, b.externalDb.write.query
 *
 * Execute a single statement against the picked backend. Returns the
 * driver-shaped `{ rows, rowCount }` from the backend's `query` hook.
 * Wraps the call in `b.retry.withRetry` for transient driver errors
 * and the per-backend circuit breaker; emits `system.externaldb.query`
 * audit events plus duration / slow-query metrics; surfaces Postgres
 * SQLSTATE 28000 / 28P01 / 42501 as `db.auth.failed` audit rows for
 * SOC2 forensic walks.
 *
 * Backend selection precedence: `opts.backend` (explicit) →
 * `opts.classification` (first backend serving the class) → ALS-bound
 * dbRole + `dbRoleBackends` map (set by `b.middleware.dbRoleFor` or
 * `b.externalDb.runAs`) → the configured `defaultBackend`.
 *
 * @opts
 *   backend?:           string,   // explicit backend name; bypasses classification + role pick
 *   classification?:    string,   // route to first backend whose classifications include this value
 *   includeSqlInAudit?: boolean,  // emit SQL text in audit metadata (off by default — may carry literal PII)
 *   rowResidencyTag?:   string,   // the row's residency region tag; required for a write (DML, CALL/EXECUTE/DO, COPY ... FROM, REPLACE, or a WITH/EXPLAIN-ANALYZE wrapping one) to a residency-tagged backend under a cross-border regulated posture (pass "global"/"unrestricted" for region-neutral rows)
 *
 * @example
 *   var res = await b.externalDb.query(
 *     "SELECT id, email FROM users WHERE tenant_id = $1",
 *     ["acme"],
 *     { classification: "personal" }
 *   );
 *   res.rowCount;   // → 42
 *   res.rows[0];    // → { id: 1, email: "ada@example.com" }
 */
async function query(sql, params, opts) {
  _requireInit();
  opts = opts || {};
  var b = _pickBackend(opts);
  var role = dbRoleContext.getRole();

  var _resRefusal = _assertRowResidency(sql, opts, b);
  if (_resRefusal) {
    _emit("db.residency.gate.rejected", "denied", _resRefusal.metadata, _resRefusal.code);
    throw _err(_resRefusal.code, _resRefusal.message, true);
  }

  var t0 = Date.now();
  try {
    var result = await retryHelper.withRetry(function () {
      return b.breaker.wrap(async function () {
        var client = await b.pool.acquire();
        try {
          var res = await b.query(client, sql, params || []);
          b.pool.release(client);
          return res;
        } catch (e) {
          if (e && (e.code === "ECONNRESET" || e.code === "ECONNREFUSED" ||
                    e.code === "ETIMEDOUT" || e.code === "ENOTFOUND" ||
                    e.code === "EPIPE")) {
            await b.pool.destroy(client);
          } else {
            b.pool.release(client);
          }
          throw e;
        }
      });
    }, b.retryConfig);

    var durationMs = Date.now() - t0;
    _emit("system.externaldb.query", "success", Object.assign({
      backend:        b.name,
      role:           role,
      durationMs:     durationMs,
      classification: opts.classification || null,
      rowCount:       result && result.rowCount,
      sql:            opts.includeSqlInAudit ? sql : null,
    }, _otelDbAttributes(b, sql, opts.includeSqlInAudit)));
    _emitMetric("externaldb.query.success", 1,
      { backend: b.name, role: role || "(none)" });
    _emitMetric("externaldb.query.duration_ms", durationMs,
      { backend: b.name, role: role || "(none)" });
    _emitSlowQuery(b.name, role, durationMs, _classifyStatement(sql));
    return result;
  } catch (e) {
    var failureMs = Date.now() - t0;
    _emit("system.externaldb.query", "failure", Object.assign({
      backend:        b.name,
      role:           role,
      durationMs:     failureMs,
      classification: opts.classification || null,
      errorCode:      e.code || null,
    }, _otelDbAttributes(b, sql, opts.includeSqlInAudit)), (e && e.message) || String(e));
    _emitMetric("externaldb.query.failure", 1,
      { backend: b.name, role: role || "(none)", errorCode: e.code || "(none)" });
    _emitSlowQuery(b.name, role, failureMs, _classifyStatement(sql));
    if (e && e.code === "42501") {
      _emitMetric("db.role.denied", 1,
        { backend: b.name, role: role || "(none)" });
    }
    _emitAuthFailureAudit(b, role, sql, e);
    throw e;
  }
}

/**
 * @primitive b.externalDb.transaction
 * @signature b.externalDb.transaction(fn, opts)
 * @since     0.4.0
 * @related   b.externalDb.query, b.externalDb.write.query
 *
 * Run `fn(tx)` inside a transaction on the picked backend. Wraps the
 * body in `BEGIN` / `COMMIT` / `ROLLBACK` via the backend's hooks;
 * commits on resolve, rolls back on throw. Transient deadlock /
 * serialization failures (Postgres SQLSTATE `40P01` / `40001`) retry
 * automatically with a small jittered backoff (default 3 attempts;
 * tune via `opts.deadlockRetries`).
 *
 * `tx.query(sql, params)` runs against the same client used by
 * `BEGIN`, so RLS state set by `sessionGucs` (`SET LOCAL`) applies for
 * the duration of the transaction and resets at COMMIT/ROLLBACK.
 *
 * Refuses (`external-db/non-atomic-backend`) when the picked backend declares
 * `supportsTransactions: false` — a stateless / autocommit-per-statement
 * adapter on which BEGIN / the body / COMMIT would run on different
 * sessions (no isolation, no rollback). Supply interactive
 * `beginTx`/`commit`/`rollback` hooks or a `batch` adapter on the backend
 * instead of shipping a silently non-atomic block.
 *
 * @opts
 *   backend?:                    string,                       // explicit backend name
 *   classification?:             string,                       // route by data class
 *   sessionGucs?:                { [name]: string|number|boolean },  // SET LOCAL bindings (e.g. { "app.tenant_id": "acme" })
 *   statementTimeoutMs?:         number,                       // SET LOCAL statement_timeout
 *   idleInTransactionTimeoutMs?: number,                       // SET LOCAL idle_in_transaction_session_timeout
 *   deadlockRetries?:            number,                       // retries for 40P01 / 40001 (default 3)
 *   rowResidencyTag?:            string,                       // residency tag applied to every statement; a per-call tx.query(sql, params, { rowResidencyTag }) overrides it for that statement
 *
 * @example
 *   var summary = await b.externalDb.transaction(async function (tx) {
 *     await tx.query("INSERT INTO orders(id, total) VALUES ($1, $2)", ["o-1", 4200]);
 *     await tx.query("UPDATE inventory SET qty = qty - 1 WHERE sku = $1", ["sku-7"]);
 *     var res = await tx.query("SELECT count(*) AS n FROM orders WHERE id = $1", ["o-1"]);
 *     return res.rows[0];
 *   }, {
 *     classification: "operational",
 *     sessionGucs:    { "app.tenant_id": "acme" },
 *     statementTimeoutMs: 5000,
 *   });
 *   summary.n;   // → 1
 */
async function transaction(fn, opts) {
  _requireInit();
  if (typeof fn !== "function") throw _err("external-db/invalid-fn", "transaction requires a function", true);
  opts = opts || {};
  var b = _pickBackend(opts);
  _assertInteractiveTransactions(b, "transaction");
  var role = dbRoleContext.getRole();

  var prebuiltGucs = _buildSessionGucsStatements(opts.sessionGucs);

  var t0 = Date.now();
  var stmtTimeoutMs = opts.statementTimeoutMs;
  var idleTimeoutMs = opts.idleInTransactionTimeoutMs;
  if (opts.deadlockRetries !== undefined) {
    if (typeof opts.deadlockRetries !== "number" || !isFinite(opts.deadlockRetries) ||
        opts.deadlockRetries < 0 || (opts.deadlockRetries | 0) !== opts.deadlockRetries) {
      throw _err("external-db/invalid-opt",
        "transaction: opts.deadlockRetries must be a non-negative integer");
    }
  }
  var maxRetries = (typeof opts.deadlockRetries === "number")
    ? Math.floor(opts.deadlockRetries) : 3;
  if (opts.rowResidencyTag !== undefined && opts.rowResidencyTag !== null &&
      (typeof opts.rowResidencyTag !== "string" || opts.rowResidencyTag.length === 0)) {
    throw _err("external-db/invalid-opt",
      "transaction: opts.rowResidencyTag must be a non-empty string when supplied", true);
  }
  return await b.breaker.wrap(async function () {
    var client = await b.pool.acquire();
    var txClient = {
      query: function (sql, params, perCallOpts) {
        var effOpts = (perCallOpts && perCallOpts.rowResidencyTag !== undefined)
          ? perCallOpts
          : { rowResidencyTag: opts.rowResidencyTag };
        var refusal = _assertRowResidency(sql, effOpts, b);
        if (refusal) {
          _emit("db.residency.gate.rejected", "denied", refusal.metadata, refusal.code);
          throw _err(refusal.code, refusal.message, true);
        }
        return b.query(client, sql, params || []);
      },
    };
    var committed = false;
    var attempt = 0;
    try {
      for (;;) {
        attempt += 1;
        committed = false;
        try {
          await b.beginTx(client);
          if (typeof stmtTimeoutMs === "number" && isFinite(stmtTimeoutMs) && stmtTimeoutMs > 0) {
            await b.query(client, "SET LOCAL statement_timeout = " + Math.floor(stmtTimeoutMs), []);   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
          }
          if (typeof idleTimeoutMs === "number" && isFinite(idleTimeoutMs) && idleTimeoutMs > 0) {
            await b.query(client, "SET LOCAL idle_in_transaction_session_timeout = " + Math.floor(idleTimeoutMs), []);   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
          }
          for (var gi = 0; gi < prebuiltGucs.length; gi++) {
            await b.query(client, prebuiltGucs[gi], []);
          }
          var result = await fn(txClient);
          await b.commit(client);
          committed = true;
          var durationMs = Date.now() - t0;
          _emit("system.externaldb.transaction", "success", Object.assign({
            backend: b.name, role: role, durationMs: durationMs,
            classification: opts.classification || null,
          }, _otelDbAttributes(b, "BEGIN", opts.includeSqlInAudit)));
          _emitMetric("externaldb.transaction.success", 1,
            { backend: b.name, role: role || "(none)" });
          _emitMetric("externaldb.transaction.duration_ms", durationMs,
            { backend: b.name, role: role || "(none)" });
          return result;
        } catch (txErr) {
          try { if (!committed) await b.rollback(client); } catch (_e) { /* best-effort */ }
          var isTransient = txErr && (txErr.code === "40P01" || txErr.code === "40001");
          if (isTransient && attempt <= maxRetries) {
            _emitMetric("externaldb.transaction.retry", 1,
              { backend: b.name, code: txErr.code, attempt: String(attempt) });
            var jitter = bCrypto.randomInt(0, 6);
            await safeAsync.sleep(attempt * 5 + jitter);
            continue;
          }
          var failureMs = Date.now() - t0;
          _emit("system.externaldb.transaction", "failure", Object.assign({
            backend: b.name, role: role, durationMs: failureMs,
            classification: opts.classification || null,
            errorCode: txErr.code || null,
          }, _otelDbAttributes(b, "BEGIN", opts.includeSqlInAudit)), (txErr && txErr.message) || String(txErr));
          _emitMetric("externaldb.transaction.failure", 1,
            { backend: b.name, role: role || "(none)", errorCode: txErr.code || "(none)" });
          if (txErr && txErr.code === "42501") {
            _emitMetric("db.role.denied", 1,
              { backend: b.name, role: role || "(none)" });
          }
          _emitAuthFailureAudit(b, role, "BEGIN", txErr);
          throw txErr;
        }
      }
    } finally {
      b.pool.release(client);
    }
  });
}

/**
 * @primitive b.externalDb.healthCheck
 * @signature b.externalDb.healthCheck(backendName)
 * @since     0.4.0
 * @related   b.externalDb.listBackends, b.externalDb.shutdown
 *
 * Ping a backend by acquiring a client and running its `ping` hook (or
 * `SELECT 1` when none is supplied). Returns `{ ok, breakerState, pool }`
 * for a single backend, or a `{ [name]: result }` map when called with
 * no argument. Connection-shape errors destroy the client; the breaker
 * state is reflected in the returned record so health endpoints can
 * surface circuit-open conditions.
 *
 * @example
 *   var all = await b.externalDb.healthCheck();
 *   all.main.ok;             // → true
 *   all.main.breakerState;   // → "closed"
 *   all.main.pool;           // → { idle: 1, active: 0, waiters: 0 }
 *
 *   var one = await b.externalDb.healthCheck("main");
 *   one.ok;                  // → true
 */
async function healthCheck(backendName) {
  _requireInit();
  if (backendName) {
    return _pingBackend(backends[backendName]);
  }
  var out = {};
  for (var name in backends) {
    out[name] = await _pingBackend(backends[name]);
  }
  return out;
}

async function _pingBackend(b) {
  if (!b) return { ok: false, error: "unknown backend" };
  try {
    var client = await b.pool.acquire();
    try {
      if (b.ping) await b.ping(client);
      else        await b.query(client, "SELECT 1", []);   // allow:hand-rolled-sql — fixed connectivity ping (no table / b.sql verb)
      b.pool.release(client);
      return { ok: true, breakerState: b.breaker.getState(), pool: b.pool.stats() };
    } catch (e) {
      await b.pool.destroy(client);
      return { ok: false, error: e.message, breakerState: b.breaker.getState() };
    }
  } catch (e) {
    return { ok: false, error: e.message, breakerState: b.breaker.getState() };
  }
}

/**
 * @primitive b.externalDb.listBackends
 * @signature b.externalDb.listBackends()
 * @since     0.4.0
 * @related   b.externalDb.healthCheck, b.externalDb.init
 *
 * Snapshot every registered backend's name, dialect, classifications,
 * residency tag, breaker state, and live pool stats. Returns `[]` when
 * `init()` has not run. Cheap — does not open any new connections.
 *
 * @example
 *   // requires: backends registered via b.externalDb.init({ backends })
 *   var rows = b.externalDb.listBackends();
 *   rows[0].name;             // → "main"
 *   rows[0].dialect;          // → "postgres"
 *   rows[0].classifications;  // → ["personal", "operational"]
 *   rows[0].residencyTag;     // → "EU"
 *   rows[0].breakerState;     // → "closed"
 *   rows[0].pool;             // → { idle: 2, active: 0, waiters: 0 }
 */
function listBackends() {
  if (!initialized) return [];
  return Object.keys(backends).map(function (name) {
    var b = backends[name];
    return {
      name:            name,
      dialect:         b.dialect,
      classifications: b.classifications.slice(),
      residencyTag:    b.residencyTag,
      breakerState:    b.breaker.getState(),
      pool:            b.pool.stats(),
    };
  });
}

/**
 * @primitive b.externalDb.shutdown
 * @signature b.externalDb.shutdown()
 * @since     0.4.0
 * @related   b.externalDb.init, b.externalDb.healthCheck
 *
 * Drain every backend pool (and replica pool), close idle clients,
 * then clear all registry state so a subsequent `init()` starts from
 * scratch. Idempotent — calling before `init()` is a no-op. Wire to
 * `b.appShutdown` so process exit waits for in-flight queries to
 * release their clients.
 *
 * @example
 *   process.on("SIGTERM", async function () {
 *     await b.externalDb.shutdown();
 *     process.exit(0);
 *   });
 */
async function shutdown() {
  if (!initialized) return;
  for (var name in backends) {
    try { await backends[name].pool.drain(); } catch (_e) { /* best effort */ }
    var bk = backends[name];
    if (bk && bk.replicas) {
      for (var i = 0; i < bk.replicas.length; i++) {
        try { await bk.replicas[i].pool.drain(); } catch (_e) { /* best effort */ }
      }
    }
  }
  backends = {};
  defaultBackend = null;
  initialized = false;
}

function _buildSessionGucsStatements(sessionGucs) {
  if (sessionGucs === undefined || sessionGucs === null) return [];
  if (typeof sessionGucs !== "object" || Array.isArray(sessionGucs)) {
    throw _err("external-db/invalid-session-gucs",
      "sessionGucs must be an object map of name → value", true);
  }
  var out = [];
  for (var name in sessionGucs) {
    if (!Object.prototype.hasOwnProperty.call(sessionGucs, name)) continue;
    if (typeof name !== "string" || name.length === 0) {
      throw _err("external-db/invalid-session-gucs",
        "sessionGucs: GUC name must be a non-empty string", true);
    }
    var qName;
    try {
      qName = safeSql.quoteQualified(name, "postgres", { allowReserved: true });
    } catch (e) {
      throw _err("external-db/invalid-session-gucs",
        "sessionGucs: name '" + name + "' is not a valid identifier: " +
        ((e && e.message) || String(e)), true);
    }
    var value = sessionGucs[name];
    var literal;
    if (typeof value === "number" && isFinite(value)) {
      literal = String(value);
    } else if (typeof value === "boolean") {
      literal = value ? "true" : "false";
    } else if (typeof value === "string") {
      if (safeBuffer.byteLengthOf(value) > C.BYTES.kib(4)) {
        throw _err("external-db/invalid-session-gucs",
          "sessionGucs['" + name + "']: value exceeds 4 KiB cap (got " +
          value.length + " chars)", true);
      }
      literal = "'" + value.replace(/'/g, "''") + "'";
    } else if (value === null || value === undefined) {
      throw _err("external-db/invalid-session-gucs",
        "sessionGucs['" + name + "']: value must be a string, finite number, or boolean (got " +
        (value === null ? "null" : "undefined") + ")", true);
    } else {
      throw _err("external-db/invalid-session-gucs",
        "sessionGucs['" + name + "']: value must be a string, finite number, or boolean (got " +
        typeof value + ")", true);
    }
    out.push("SET LOCAL " + qName + " = " + literal);   // allow:hand-rolled-sql — Postgres session GUC SET (no table; not a b.sql verb)
  }
  return out;
}

function _emit(action, outcome, metadata, reason) {
  audit().safeEmit({ action: action, outcome: outcome, reason: reason, metadata: metadata });
}

function _requireInit() {
  if (!initialized) throw _err("external-db/not-initialized", "externalDb.init() must be called first", true);
}

var REPLICA_UNHEALTHY_COOLDOWN_MS = C.TIME.seconds(30);

function _crossBorderRegulated(posture) {
  if (posture === null || posture === undefined) return false;
  try {
    var compliance = require("./compliance");                                                    // allow:inline-require — defensive against optional load
    return compliance.isCrossBorderRegulated(posture);
  } catch (_e) { return false; }
}

function _residencyCompatible(primaryTag, replicaTag) {
  if (!primaryTag || !replicaTag) return true;
  if (primaryTag === replicaTag) return true; // allow:raw-hash-compare-nonsecret-tag — residency tag string, not a secret hash
  if (primaryTag === "unrestricted" || replicaTag === "unrestricted") return true;
  return false;
}

function _hasTrailingStatement(sql) {
  if (typeof sql !== "string") return false;
  var n = sql.length;
  var i = 0;
  while (i < n) {
    var ch = sql.charAt(i);
    var skipped = _skipOpaqueSpan(sql, i);
    if (skipped === -1) return false;
    if (skipped !== i) { i = skipped; continue; }
    if (ch !== ";") { i += 1; continue; }
    var j = i + 1;
    while (j < n) {
      var c = sql.charAt(j);
      if (c === " " || c === "\t" || c === "\r" || c === "\n") { j += 1; continue; }
      if (c === "/" && sql.charAt(j + 1) === "*") {
        var end = sql.indexOf("*/", j + 2);
        if (end === -1) return false;
        j = end + 2;
        continue;
      }
      if (c === "-" && sql.charAt(j + 1) === "-") {
        var nl = sql.indexOf("\n", j + 2);
        if (nl === -1) return false;
        j = nl + 1;
        continue;
      }
      return true;
    }
    return false;
  }
  return false;
}

function _activePosture() {
  try {
    var compliance = require("./compliance");                                                    // allow:inline-require — defensive against optional load
    return compliance.current();
  } catch (_e) { return null; }
}

function _assertRowResidency(sql, opts, backend) {
  var tag = opts && opts.rowResidencyTag;
  if (tag !== undefined && tag !== null &&
      (typeof tag !== "string" || tag.length === 0)) {
    return {
      code:     "external-db/invalid-opt",
      message:  "rowResidencyTag must be a non-empty string when supplied",
      metadata: { backend: backend.name, statementClass: _classifyStatement(sql) },
    };
  }
  var backendTag = backend.residencyTag || "unrestricted";
  var posture = _activePosture();
  var regulated = _crossBorderRegulated(posture);
  if (regulated && backendTag !== "unrestricted") {
    if (_hasTrailingStatement(sql)) {
      return {
        code:     "external-db/multi-statement-refused",
        message:  "multi-statement SQL is not supported on the residency-gated " +
                  "write path; pass one statement per query()",
        metadata: { backend: backend.name, backendTag: backendTag, posture: posture,
                    statementClass: _classifyStatement(sql), scope: "external" },
      };
    }
    var cls = _classifyStatement(sql);
    if (cls === "UNKNOWN") {
      return {
        code:     "external-db/statement-unresolved-refused",
        message:  "could not resolve the effective statement class on the " +
                  "residency-gated write path; pass one plain statement per " +
                  "query() (an unparseable WITH/EXPLAIN prefix or quoting)",
        metadata: { backend: backend.name, backendTag: backendTag, posture: posture,
                    statementClass: cls, scope: "external" },
      };
    }
    var isWrite = !(_RESIDENCY_READ_CLASS[cls] === true ||
                    (cls === "BULK" && !_copyLoadsRows(sql)));
    if (!isWrite) return null;
    if (!tag) {
      return {
        code: "external-db/residency-gate-required",
        message: "write to backend '" + backend.name + "' (residencyTag='" +
          backendTag + "') under '" + posture + "' posture requires " +
          "opts.rowResidencyTag. Pass { rowResidencyTag: \"" + backendTag +
          "\" } for rows belonging to this region, or declare per-row " +
          "residency via b.cryptoField.declarePerRowResidency for local tables",
        metadata: { backend: backend.name, backendTag: backendTag,
                    rowTag: null, posture: posture, statementClass: cls,
                    scope: "external" },
      };
    }
    if (tag !== "global" && tag !== "unrestricted" &&
        !_residencyCompatible(tag, backendTag)) {
      return {
        code: "external-db/residency-tag-mismatch",
        message: "row residencyTag '" + tag + "' is not compatible with backend '" +
          backend.name + "' residencyTag '" + backendTag + "' under '" + posture +
          "' posture (cross-border transfer refused)",
        metadata: { backend: backend.name, backendTag: backendTag,
                    rowTag: tag, posture: posture, statementClass: cls,
                    scope: "external" },
      };
    }
    return null;
  }
  if (tag) {
    var advisoryCls = _classifyStatement(sql);
    var advisoryWrite = advisoryCls !== "UNKNOWN" &&
      !(_RESIDENCY_READ_CLASS[advisoryCls] === true ||
        (advisoryCls === "BULK" && !_copyLoadsRows(sql)));
    if (advisoryWrite) {
      _emit("db.residency.gate.advisory", "info", {
        backend: backend.name, backendTag: backendTag, rowTag: tag,
        posture: posture || null, statementClass: advisoryCls, scope: "external",
      });
    }
  }
  return null;
}

function _buildReplicas(backendName, cfg) {
  if (!cfg.replicas) return null;
  if (!Array.isArray(cfg.replicas) || cfg.replicas.length === 0) {
    throw _err("external-db/invalid-config",
      "backend '" + backendName + "': replicas must be a non-empty array", true);
  }
  var primaryTag = cfg.residencyTag || "unrestricted";
  var posture = _activePosture();
  var out = [];
  for (var i = 0; i < cfg.replicas.length; i++) {
    var r = cfg.replicas[i];
    if (!r || typeof r.connect !== "function") {
      throw _err("external-db/invalid-config",
        "backend '" + backendName + "': replicas[" + i + "].connect must be a function", true);
    }
    if (typeof r.query !== "function") {
      throw _err("external-db/invalid-config",
        "backend '" + backendName + "': replicas[" + i + "].query must be a function", true);
    }
    var weight = r.weight !== undefined ? r.weight : 1;
    numericBounds.requirePositiveFiniteInt(weight,
      "backend '" + backendName + "': replicas[" + i + "].weight", ExternalDbError,
      "external-db/invalid-config", null, { permanent: true });
    var replicaTag = r.residencyTag || "unrestricted";
    var allowCrossBorder = r.allowCrossBorder === true;
    if (!_residencyCompatible(primaryTag, replicaTag) && !allowCrossBorder) {
      var underPosture = _crossBorderRegulated(posture);
      throw _err("external-db/residency-mismatch",
        "backend '" + backendName + "': replica[" + i +
        "] residencyTag '" + replicaTag +
        "' is not compatible with primary residencyTag '" + primaryTag +
        "'" + (underPosture ? " under '" + posture + "' posture" : "") +
        ". This is a cross-border data transfer (GDPR Art 46 / DPDP / PIPL " +
        "category). Pass allowCrossBorder: true on the replica config with a " +
        "documented legal basis (SCCs / BCRs / adequacy decision) to suppress.", true);
    }
    if (!_residencyCompatible(primaryTag, replicaTag) && allowCrossBorder) {
      _emit("db.residency.replica.cross_border_allowed", "warning",
        { backend: backendName, replicaIndex: i,
          primaryTag: primaryTag, replicaTag: replicaTag,
          legalBasis: r.legalBasis || null,
          posture: posture || null });
    }
    out.push({
      index:           i,
      pool:            new Pool(backendName + ":replica:" + i, r),
      query:           r.query,
      weight:          weight,
      residencyTag:    replicaTag,
      allowCrossBorder: allowCrossBorder,
      lastFailureAt:   0,
      consecutiveFailures: 0,
    });
  }
  return out;
}

function _pickReplica(b) {
  if (!b.replicas || b.replicas.length === 0) return null;
  var now = Date.now();
  var healthy = [];
  for (var i = 0; i < b.replicas.length; i++) {
    var r = b.replicas[i];
    if (now - r.lastFailureAt >= REPLICA_UNHEALTHY_COOLDOWN_MS) healthy.push(r);
  }
  if (healthy.length === 0) return null;
  var totalWeight = 0;
  for (var w = 0; w < healthy.length; w++) totalWeight += healthy[w].weight;
  var cursor = (b.replicaIdx++) % totalWeight;
  var acc = 0;
  for (var c = 0; c < healthy.length; c++) {
    acc += healthy[c].weight;
    if (cursor < acc) return healthy[c];
  }
  return healthy[0];
}

async function _readQuery(sql, params, opts) {
  _requireInit();
  opts = opts || {};
  var b = _pickBackend(opts);
  if (!b.replicas || b.replicas.length === 0) {
    return query(sql, params, opts);
  }
  var replica = _pickReplica(b);
  if (!replica) {
    if (b.replicaFallbackToPrimary) return query(sql, params, opts);
    throw _err("external-db/all-replicas-unhealthy",
      "backend '" + b.name + "': all replicas unhealthy and fallback disabled", true);
  }
  var _readPosture = _activePosture();
  var _tagPresent = opts.rowResidencyTag && typeof opts.rowResidencyTag === "string";
  var _replicaConstrained = replica.residencyTag &&
    replica.residencyTag !== "unrestricted" && replica.residencyTag !== "global";
  if (!_tagPresent && _crossBorderRegulated(_readPosture) &&
      _replicaConstrained && !replica.allowCrossBorder) {
    _emit("db.residency.replica.tag_required", "denied", {
      backend: b.name, replicaIdx: replica.index,
      replicaTag: replica.residencyTag, posture: _readPosture,
    });
    throw _err("external-db/replica-residency-tag-required",
      "read routed to residency-tagged replica " + replica.index + " of backend '" +
      b.name + "' (residencyTag='" + replica.residencyTag + "') under '" + _readPosture +
      "' posture without opts.rowResidencyTag - identify the row's region or set " +
      "allowCrossBorder on the replica (audited)", true);
  }
  if (_tagPresent) {
    if (_crossBorderRegulated(_readPosture) &&
        opts.rowResidencyTag !== "global" && opts.rowResidencyTag !== "unrestricted" &&
        !_residencyCompatible(opts.rowResidencyTag, replica.residencyTag)) {
      if (replica.allowCrossBorder) {
        _emit("db.residency.replica.cross_border", "warning", {
          backend: b.name, replicaIdx: replica.index,
          rowTag: opts.rowResidencyTag, replicaTag: replica.residencyTag,
          posture: _readPosture,
        });
      } else {
        _emit("db.residency.replica.incompatible", "denied", {
          backend: b.name, replicaIdx: replica.index,
          rowTag: opts.rowResidencyTag, replicaTag: replica.residencyTag,
          posture: _readPosture,
        });
        throw _err("external-db/replica-residency-incompatible",
          "read for row residencyTag '" + opts.rowResidencyTag + "' routed to replica " +
          replica.index + " of backend '" + b.name + "' (residencyTag='" +
          replica.residencyTag + "') under '" + _readPosture +
          "' posture; set allowCrossBorder on the replica to permit (audited)", true);
      }
    }
  }
  var role = dbRoleContext.getRole();
  var t0 = Date.now();
  try {
    var client = await replica.pool.acquire();
    try {
      var res = await replica.query(client, sql, params || []);
      replica.pool.release(client);
      replica.consecutiveFailures = 0;
      var durationMs = Date.now() - t0;
      _emit("system.externaldb.read", "success", Object.assign({
        backend:    b.name,
        role:       role,
        replicaIdx: replica.index,
        durationMs: durationMs,
        rowCount:   res && res.rowCount,
      }, _otelDbAttributes(b, sql, opts.includeSqlInAudit)));
      _emitMetric("externaldb.read.success", 1,
        { backend: b.name, role: role || "(none)", replicaIdx: replica.index });
      _emitMetric("externaldb.read.duration_ms", durationMs,
        { backend: b.name, role: role || "(none)", replicaIdx: replica.index });
      return res;
    } catch (e) {
      if (e && (e.code === "ECONNRESET" || e.code === "ECONNREFUSED" ||
                e.code === "ETIMEDOUT" || e.code === "ENOTFOUND" ||
                e.code === "EPIPE")) {
        await replica.pool.destroy(client);
        replica.lastFailureAt = Date.now();
        replica.consecutiveFailures += 1;
      } else {
        replica.pool.release(client);
      }
      throw e;
    }
  } catch (e) {
    _emit("system.externaldb.read", "failure", Object.assign({
      backend:    b.name,
      role:       role,
      replicaIdx: replica.index,
      durationMs: Date.now() - t0,
      errorCode:  e.code || null,
    }, _otelDbAttributes(b, sql, opts.includeSqlInAudit)), (e && e.message) || String(e));
    _emitMetric("externaldb.read.failure", 1,
      { backend: b.name, role: role || "(none)", errorCode: e.code || "(none)" });
    if (e && e.code === "42501") {
      _emitMetric("db.role.denied", 1,
        { backend: b.name, role: role || "(none)" });
    }
    _emitAuthFailureAudit(b, role, sql, e);
    if (b.replicaFallbackToPrimary) {
      return query(sql, params, opts);
    }
    throw e;
  }
}

/**
 * @primitive b.externalDb.read.query
 * @signature b.externalDb.read.query(sql, params, opts)
 * @since     0.4.0
 * @related   b.externalDb.write.query, b.externalDb.query, b.externalDb.init
 *
 * Route a read against the backend's declared replicas using weighted
 * round-robin. A failed replica is sidelined for 30 seconds and the
 * call falls back to primary when `replicaFallbackToPrimary` is true
 * (the default). Backends without replicas transparently route to
 * primary. Same `opts` selection rules as `b.externalDb.query`
 * (`backend` / `classification` / ALS-bound role).
 *
 * @opts
 *   backend?:        string,   // explicit backend name
 *   classification?: string,   // route by data class
 *
 * @example
 *   var res = await b.externalDb.read.query(
 *     "SELECT id, total FROM orders WHERE tenant_id = $1",
 *     ["acme"],
 *     { classification: "operational" }
 *   );
 *   res.rowCount;   // → 7
 *   res.rows[0];    // → { id: "o-1", total: 4200 }
 */
var read = {
  query: _readQuery,
};

/**
 * @primitive b.externalDb.write.query
 * @signature b.externalDb.write.query(sql, params, opts)
 * @since     0.4.0
 * @related   b.externalDb.read.query, b.externalDb.query, b.externalDb.write.transaction
 *
 * Symmetric alias for `b.externalDb.query` — always routes to primary.
 * Pair with `b.externalDb.read.query` when an operator wants the call
 * site to express read/write intent without a magic-comment hint.
 * Same `opts` selection rules as `b.externalDb.query`.
 *
 * @opts
 *   backend?:           string,   // explicit backend name
 *   classification?:    string,   // route by data class
 *   includeSqlInAudit?: boolean,  // emit SQL text in audit metadata
 *
 * @example
 *   var res = await b.externalDb.write.query(
 *     "INSERT INTO orders(id, tenant_id, total) VALUES ($1, $2, $3)",
 *     ["o-2", "acme", 1500],
 *     { classification: "operational" }
 *   );
 *   res.rowCount;   // → 1
 */
/**
 * @primitive b.externalDb.write.transaction
 * @signature b.externalDb.write.transaction(fn, opts)
 * @since     0.4.0
 * @related   b.externalDb.transaction, b.externalDb.write.query
 *
 * Symmetric alias for `b.externalDb.transaction` — always runs against
 * primary. Same `opts` shape (sessionGucs / statementTimeoutMs /
 * idleInTransactionTimeoutMs / deadlockRetries) as the canonical form.
 *
 * @opts
 *   backend?:                    string,
 *   classification?:             string,
 *   sessionGucs?:                { [name]: string|number|boolean },
 *   statementTimeoutMs?:         number,
 *   idleInTransactionTimeoutMs?: number,
 *   deadlockRetries?:            number,
 *
 * @example
 *   var n = await b.externalDb.write.transaction(async function (tx) {
 *     await tx.query("UPDATE counters SET n = n + 1 WHERE k = $1", ["hits"]);
 *     var res = await tx.query("SELECT n FROM counters WHERE k = $1", ["hits"]);
 *     return res.rows[0].n;
 *   }, { sessionGucs: { "app.tenant_id": "acme" } });
 *   typeof n;   // → "number"
 */
var write = {
  query:       function (sql, params, opts) { return query(sql, params, opts); },
  transaction: function (fn, opts) { return transaction(fn, opts); },
};

function _resetForTest() {
  Object.keys(backends).forEach(function (n) {
    try { backends[n].pool.drain(); }
    catch (e) { log.debug("test-reset pool drain failed", { backend: n, error: e.message }); }
    var bk = backends[n];
    if (bk && bk.replicas) {
      bk.replicas.forEach(function (r) {
        try { r.pool.drain(); }
        catch (e2) { log.debug("test-reset replica drain failed", { backend: n, error: e2.message }); }
      });
    }
  });
  backends = {};
  defaultBackend = null;
  dbRoleBackends = {};
  initialized = false;
  audit.reset();
  db.reset();
}

/**
 * @primitive b.externalDb.configurePool
 * @signature b.externalDb.configurePool(backendName, opts)
 * @since     0.4.0
 * @related   b.externalDb.init, b.externalDb.listBackends
 *
 * Resize a registered backend's pool at runtime. New `max` takes effect
 * on the next acquire; existing idle clients are kept; `min` is honored
 * when the pool next refills; `idleTimeoutMs` applies on the next
 * reaper tick. Throws on unknown options or non-positive integers so a
 * config typo surfaces at the call site.
 *
 * @opts
 *   min?:           number,   // positive integer; floor on idle clients
 *   max?:           number,   // positive integer; ceiling on total clients (must be >= min)
 *   idleTimeoutMs?: number,   // positive integer; reap idle clients after this many ms
 *
 * @example
 *   b.externalDb.configurePool("main", {
 *     min:           4,
 *     max:           50,
 *     idleTimeoutMs: 120000,
 *   });
 */
function configurePool(backendName, opts) {
  _requireInit();
  if (typeof backendName !== "string" || backendName.length === 0) {
    throw _err("external-db/invalid-config", "configurePool: backendName must be a non-empty string", true);
  }
  var bk = backends[backendName];
  if (!bk) throw _err("external-db/unknown-backend", "configurePool: no backend named '" + backendName + "'", true);
  if (!opts || typeof opts !== "object") {
    throw _err("external-db/invalid-config", "configurePool: opts must be an object", true);
  }
  var allowed = ["min", "max", "idleTimeoutMs"];
  for (var k in opts) {
    if (!Object.prototype.hasOwnProperty.call(opts, k)) continue;
    if (allowed.indexOf(k) === -1) {
      throw _err("external-db/invalid-config",
        "configurePool: unknown option '" + k + "'. Allowed: " + allowed.join(", "), true);
    }
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["min", "max", "idleTimeoutMs"], "configurePool", ExternalDbError,
    "external-db/invalid-config", { permanent: true });
  if (opts.min !== undefined && opts.max !== undefined && opts.min > opts.max) {
    throw _err("external-db/invalid-config", "configurePool: min must be <= max", true);
  }
  Object.assign(bk.pool.config, opts);
}

function _connectAs(rawConnect, query, opts) {
  if (typeof rawConnect !== "function") {
    throw _err("external-db/invalid-config", "connectAs: connect must be a function", true);
  }
  if (typeof query !== "function") {
    throw _err("external-db/invalid-config", "connectAs: query must be a function", true);
  }
  opts = opts || {};
  var allowed = ["role", "searchPath", "applicationName", "statementTimeoutMs", "gucs"];
  for (var k in opts) {
    if (!Object.prototype.hasOwnProperty.call(opts, k)) continue;
    if (allowed.indexOf(k) === -1) {
      throw _err("external-db/invalid-config",
        "connectAs: unknown option '" + k + "'. Allowed: " + allowed.join(", "), true);
    }
  }

  if (opts.role !== undefined) {
    safeSql.validateIdentifier(String(opts.role), { allowReserved: false });
  }
  var pathSegments = null;
  if (opts.searchPath !== undefined) {
    var raw = Array.isArray(opts.searchPath) ? opts.searchPath : [opts.searchPath];
    if (raw.length === 0) {
      throw _err("external-db/invalid-config", "connectAs: searchPath must have at least one schema", true);
    }
    pathSegments = [];
    for (var pi = 0; pi < raw.length; pi++) {
      safeSql.validateIdentifier(String(raw[pi]), { allowReserved: false });
      pathSegments.push(String(raw[pi]));
    }
  }
  if (opts.applicationName !== undefined && typeof opts.applicationName !== "string") {
    throw _err("external-db/invalid-config", "connectAs: applicationName must be a string", true);
  }
  if (opts.statementTimeoutMs !== undefined) {
    numericBounds.requirePositiveFiniteIntIfPresent(opts.statementTimeoutMs,
      "connectAs: statementTimeoutMs", ExternalDbError, "external-db/invalid-config", { permanent: true });
  }
  if (opts.gucs !== undefined && (typeof opts.gucs !== "object" || opts.gucs === null)) {
    throw _err("external-db/invalid-config", "connectAs: gucs must be an object", true);
  }
  if (opts.gucs) {
    for (var gname in opts.gucs) {
      safeSql.validateIdentifier(gname, { allowReserved: true });
    }
  }

  var stmts = [];
  if (opts.role) {
    stmts.push('SET ROLE "' + opts.role + '"');   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
  }
  if (pathSegments) {
    var pathSql = pathSegments.map(function (s) { return '"' + s + '"'; }).join(", ");
    stmts.push("SET search_path TO " + pathSql);   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
  }
  if (opts.applicationName !== undefined) {
    var an = String(opts.applicationName).replace(/'/g, "''");
    stmts.push("SET application_name TO '" + an + "'");   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
  }
  if (opts.statementTimeoutMs !== undefined) {
    stmts.push("SET statement_timeout TO " + opts.statementTimeoutMs);   // allow:hand-rolled-sql — Postgres session SET (no table; not a b.sql verb)
  }
  if (opts.gucs) {
    for (var gn in opts.gucs) {
      var gv = opts.gucs[gn];
      if (typeof gv === "number") {
        if (!isFinite(gv)) {
          throw _err("external-db/invalid-config",
            "connectAs: gucs[" + gn + "] number must be finite (got " + gv + ")",
            true);
        }
        stmts.push('SET "' + gn + '" TO ' + gv);
      } else {
        var gvs = String(gv).replace(/'/g, "''");
        // eslint-disable-next-line no-control-regex
        if (/[\r\n\u0000]/.test(gvs)) {
          throw _err("external-db/invalid-config",
            "connectAs: gucs[" + gn + "] string value must not contain NUL or newline characters",
            true);
        }
        stmts.push('SET "' + gn + '" TO \'' + gvs + "'");
      }
    }
  }

  return async function wrappedConnect() {
    var client = await rawConnect();
    try {
      for (var i = 0; i < stmts.length; i++) {
        await query(client, stmts[i], []);
      }
    } catch (e) {
      throw e;
    }
    return client;
  };
}

/**
 * @primitive b.externalDb.adapters.connectAs
 * @signature b.externalDb.adapters.connectAs(connect, opts)
 * @since     0.4.0
 * @related   b.externalDb.init, b.externalDb.runAs
 *
 * Wrap a Postgres `connect` so every fresh client runs `SET ROLE`,
 * `SET search_path`, `SET application_name`, `SET statement_timeout`,
 * and any operator-supplied `gucs` before being handed to the pool.
 * Identifier inputs (role, schemas, GUC names) are validated via
 * `safeSql.validateIdentifier` at call time so a bad name throws once
 * at boot rather than per acquired client. Returns the wrapped
 * `connect` function suitable for a backend's `connect` hook.
 *
 * @opts
 *   query:               function,    // required — the backend's query function (used to issue SET statements)
 *   role?:               string,      // SQL identifier; runs SET ROLE "<role>"
 *   searchPath?:         string[],    // SQL identifiers; runs SET search_path TO "<a>", "<b>", ...
 *   applicationName?:    string,      // appears in pg_stat_activity
 *   statementTimeoutMs?: number,      // positive integer; SET statement_timeout TO <ms>
 *   gucs?:               { [name]: string|number },   // raw GUC bindings; finite numbers required for numeric values
 *
 * @example
 *   var pg = require("pg");
 *   var pool = new pg.Pool({ connectionString: "postgres://app:pw@db.example.com/app" });
 *   var rawConnect = function () { return pool.connect(); };
 *   var rawQuery   = function (client, sql, params) { return client.query(sql, params); };
 *
 *   b.externalDb.init({
 *     backends: {
 *       analytics: {
 *         dialect: "postgres",
 *         connect: b.externalDb.adapters.connectAs(rawConnect, {
 *           query:               rawQuery,
 *           role:                "analytics_user",
 *           searchPath:          ["analytics", "public"],
 *           applicationName:     "blamejs:analytics",
 *           statementTimeoutMs:  30000,
 *           gucs:                { idle_in_transaction_session_timeout: "60s" },
 *         }),
 *         query: rawQuery,
 *       },
 *     },
 *   });
 */
function _adaptersConnectAs(connect, opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("external-db/invalid-config",
      "adapters.connectAs: opts must be an object", true);
  }
  if (typeof opts.query !== "function") {
    throw _err("external-db/invalid-config",
      "adapters.connectAs: opts.query is required (the backend's query function)", true);
  }
  var query = opts.query;
  var roleOpts = {};
  for (var k in opts) {
    if (Object.prototype.hasOwnProperty.call(opts, k) && k !== "query") {
      roleOpts[k] = opts[k];
    }
  }
  return _connectAs(connect, query, roleOpts);
}

/**
 * @primitive b.externalDb.runAs
 * @signature b.externalDb.runAs(role, fn)
 * @since     0.4.0
 * @related   b.externalDb.currentRole, b.externalDb.adapters.connectAs
 *
 * Bind a SQL role on the deep async-local context for the duration of
 * `fn()`. Every `b.externalDb.query` / `read.query` / `write.query` /
 * `transaction` call inside the bound region picks the backend mapped
 * to `role` via the `dbRoleBackends` map declared at `init()`, so
 * background workers (cron, queue consumers, CLI commands) get the
 * same role-aware routing as HTTP requests under
 * `b.middleware.dbRoleFor`. Pass `null` to clear. Audits role
 * transitions as `db.role.switched`. Identifier-validates the role at
 * the call site so a typo throws synchronously.
 *
 * @example
 *   await b.externalDb.runAs("analytics_user", async function () {
 *     var res = await b.externalDb.read.query(
 *       "SELECT count(*) AS n FROM events WHERE day = $1",
 *       ["2026-05-09"]
 *     );
 *     return res.rows[0].n;
 *   });
 */
function runAs(role, fn) {
  if (typeof fn !== "function") {
    throw _err("external-db/invalid-fn", "externalDb.runAs: fn must be a function", true);
  }
  if (role !== null && role !== undefined) {
    if (typeof role !== "string" || role.length === 0) {
      throw _err("external-db/invalid-role",
        "externalDb.runAs: role must be a non-empty string or null", true);
    }
    safeSql.validateIdentifier(role, { allowReserved: false });
  }
  var previousRole = dbRoleContext.getRole();
  var newRole = role || null;
  if (previousRole !== newRole) {
    audit().safeEmit({
      action:   "db.role.switched",
      actor:    {},
      resource: { kind: "db.role", id: newRole || "(none)" },
      outcome:  "success",
      metadata: {
        previousRole: previousRole,
        newRole:      newRole,
        source:       "runAs",
      },
    });
  }
  return dbRoleContext.runWithRole(role || null, fn);
}

/**
 * @primitive b.externalDb.currentRole
 * @signature b.externalDb.currentRole()
 * @since     0.4.0
 * @related   b.externalDb.runAs
 *
 * Read the SQL role bound on the deep async-local context. Returns
 * `null` when no role is bound. Useful for diagnostic logs, audit
 * metadata, and observability labels — the value flows through the
 * same context that `b.externalDb.query` consults for backend pick.
 *
 * @example
 *   await b.externalDb.runAs("analytics_user", async function () {
 *     b.externalDb.currentRole();   // → "analytics_user"
 *   });
 *   b.externalDb.currentRole();     // → null
 */
function currentRole() {
  return dbRoleContext.getRole();
}

/**
 * @primitive b.externalDb.assertRoleHardening
 * @signature b.externalDb.assertRoleHardening(opts)
 * @since     0.7.0
 * @related   b.externalDb.runAs, b.externalDb.adapters.connectAs
 *
 * Compare `pg_roles` membership against an operator-declared role
 * allowlist on a Postgres backend. Surfaces unrecognized roles
 * (forgotten ALTER ROLE leftovers, migration roles, privileged grants
 * added outside change-management) and missing roles (declared but not
 * present). Default `mode: "audit"` emits
 * `db.role.hardening.unrecognized` / `.ok` so dashboards see drift
 * without breaking boot; `mode: "throw"` fails boot when unrecognized
 * roles surface. Non-Postgres dialects emit `db.role.hardening.skipped`
 * and return empty observed lists.
 *
 * @opts
 *   declaredRoles: string[],            // required; allowlist of expected role names
 *   backend?:      string,              // explicit backend name (defaults to defaultBackend)
 *   mode?:         "audit" | "throw",   // default "audit"
 *   ignoreSystem?: boolean,             // skip postgres / pg_* / rds_* / azure_* / cloudsqlsuperuser (default true)
 *
 * @example
 *   var report = await b.externalDb.assertRoleHardening({
 *     backend:       "main",
 *     declaredRoles: ["app_user", "analytics_user", "admin"],
 *     mode:          "audit",
 *     ignoreSystem:  true,
 *   });
 *   report.unrecognized;   // → []
 *   report.missing;        // → []
 *   report.observed;       // → ["admin", "analytics_user", "app_user"]
 */
async function assertRoleHardening(opts) {
  _requireInit();
  if (!opts || typeof opts !== "object") {
    throw _err("external-db/invalid-config",
      "assertRoleHardening: opts is required ({ declaredRoles, backend?, mode? })", true);
  }
  if (!Array.isArray(opts.declaredRoles)) {
    throw _err("external-db/invalid-config",
      "assertRoleHardening: opts.declaredRoles must be an array of role names", true);
  }
  for (var i = 0; i < opts.declaredRoles.length; i++) {
    var r = opts.declaredRoles[i];
    if (typeof r !== "string" || r.length === 0) {
      throw _err("external-db/invalid-config",
        "assertRoleHardening: declaredRoles[" + i + "] must be a non-empty string", true);
    }
  }
  var mode = opts.mode || "audit";
  if (mode !== "audit" && mode !== "throw") {
    throw _err("external-db/invalid-config",
      "assertRoleHardening: mode must be 'audit' or 'throw' (got '" + mode + "')", true);
  }
  var backendName = opts.backend || defaultBackend;
  var b = backends[backendName];
  if (!b) {
    throw _err("external-db/unknown-backend",
      "assertRoleHardening: no backend named '" + backendName + "'", true);
  }
  if (b.dialect !== "postgres") {
    audit().safeEmit({
      action:   "db.role.hardening.skipped",
      actor:    {},
      resource: { kind: "db.backend", id: backendName },
      outcome:  "success",
      metadata: { dialect: b.dialect, reason: "non-postgres" },
    });
    return { declared: opts.declaredRoles.slice(), observed: [], unrecognized: [], missing: [] };
  }
  var ignoreSystem = opts.ignoreSystem !== false;
  var rows;
  try {
    var rolesBuilt = sql().select("pg_roles", { dialect: "postgres" })
      .columns(["rolname"]).orderBy("rolname", "asc").toSql();
    var res = await query(rolesBuilt.sql, rolesBuilt.params, { backend: backendName });
    rows = (res && res.rows) || [];
  } catch (e) {
    audit().safeEmit({
      action:   "db.role.hardening.unreadable",
      actor:    {},
      resource: { kind: "db.backend", id: backendName },
      outcome:  "failure",
      reason:   (e && e.message) || String(e),
      metadata: { backend: backendName },
    });
    throw _err("external-db/role-hardening-unreadable",
      "assertRoleHardening: could not read pg_roles on backend '" + backendName + "': " +
      ((e && e.message) || String(e)), true);
  }
  var observed = rows.map(function (r) { return r.rolname; });
  if (ignoreSystem) {
    observed = observed.filter(function (n) {
      return !(n === "postgres" || n.indexOf("pg_") === 0 || n.indexOf("rds_") === 0 ||
               n.indexOf("rdsadmin") === 0 || n.indexOf("azure_") === 0 ||
               n.indexOf("cloudsqlsuperuser") === 0);
    });
  }
  var declaredSet = {};
  opts.declaredRoles.forEach(function (n) { declaredSet[n] = true; });
  var observedSet = {};
  observed.forEach(function (n) { observedSet[n] = true; });
  var unrecognized = observed.filter(function (n) { return !declaredSet[n]; });
  var missing      = opts.declaredRoles.filter(function (n) { return !observedSet[n]; });
  if (unrecognized.length > 0 || missing.length > 0) {
    audit().safeEmit({
      action:   "db.role.hardening.unrecognized",
      actor:    {},
      resource: { kind: "db.backend", id: backendName },
      outcome:  unrecognized.length > 0 ? "denied" : "failure",
      metadata: {
        backend:      backendName,
        unrecognized: unrecognized,
        missing:      missing,
        observedCount: observed.length,
      },
    });
    if (mode === "throw" && unrecognized.length > 0) {
      throw _err("external-db/role-hardening-fail",
        "assertRoleHardening: pg_roles surfaces " + unrecognized.length +
        " unrecognized role(s) on backend '" + backendName + "': " +
        unrecognized.join(", ") + ". Either add them to declaredRoles after " +
        "review, REVOKE them, or set mode: 'audit' to downgrade to audit-only.",
        true);
    }
  } else {
    audit().safeEmit({
      action:   "db.role.hardening.ok",
      actor:    {},
      resource: { kind: "db.backend", id: backendName },
      outcome:  "success",
      metadata: { backend: backendName, observedCount: observed.length },
    });
  }
  return {
    declared:     opts.declaredRoles.slice(),
    observed:     observed,
    unrecognized: unrecognized,
    missing:      missing,
  };
}

module.exports = {
  init:           init,
  query:          query,
  transaction:    transaction,
  supportsTransactions: supportsTransactions,
  healthCheck:    healthCheck,
  listBackends:   listBackends,
  shutdown:       shutdown,
  configurePool:        configurePool,
  read:                 read,
  write:                write,
  runAs:                runAs,
  currentRole:          currentRole,
  assertRoleHardening:  assertRoleHardening,
  adapters: {
    connectAs:    _adaptersConnectAs,
  },
  migrate:        externalDbMigrate,
  Pool:           Pool,
  _statementReturnsRows: statementReturnsRows,
  _resetForTest:  _resetForTest,
  _extractTargetRelation: _extractTargetRelation,
};
