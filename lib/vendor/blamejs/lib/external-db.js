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
var C = require("./constants");
var dbRoleContext = require("./db-role-context");
var externalDbMigrate = require("./external-db-migrate");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeSql = require("./safe-sql");
var { ExternalDbError } = require("./framework-error");

var log = boot("external-db");

var audit         = lazyRequire(function () { return require("./audit"); });
var db            = lazyRequire(function () { return require("./db"); });
var observability = lazyRequire(function () { return require("./observability"); });

function _emitMetric(name, value, labels) {
  try { observability().event(name, value, labels || {}); }
  catch (_e) { /* hot-path observability sink — drop silent by design */ }
}

// Statement-class classifier for auth-failure forensics (D-M2). Inspects
// the leading keyword only so an attacker-controlled trailing fragment
// can't smuggle a false classification. Skips leading whitespace plus
// SQL line / block comments before reading the keyword.
var _STATEMENT_CLASS_RE = /^\s*(?:\/\*[\s\S]*?\*\/\s*|--[^\n]*\n\s*)*([A-Za-z]+)/;
var _STATEMENT_CLASS_MAP = Object.freeze({
  SELECT: "SELECT", WITH: "SELECT", VALUES: "SELECT", TABLE: "SELECT",
  INSERT: "DML", UPDATE: "DML", DELETE: "DML", MERGE: "DML", UPSERT: "DML",
  CREATE: "DDL", DROP: "DDL", ALTER: "DDL", TRUNCATE: "DDL",
  RENAME: "DDL", COMMENT: "DDL",
  GRANT: "DCL", REVOKE: "DCL",
  SET: "SESSION", RESET: "SESSION",
  BEGIN: "TX", START: "TX", COMMIT: "TX", ROLLBACK: "TX",
  SAVEPOINT: "TX", RELEASE: "TX",
  CALL: "ROUTINE", EXECUTE: "ROUTINE",
  COPY: "BULK",
  EXPLAIN: "META", ANALYZE: "META", VACUUM: "META",
});

function _classifyStatement(sql) {
  if (typeof sql !== "string" || sql.length === 0) return "UNKNOWN";
  var m = _STATEMENT_CLASS_RE.exec(sql);
  if (!m) return "UNKNOWN";
  return _STATEMENT_CLASS_MAP[m[1].toUpperCase()] || "OTHER";
}

// Postgres SQLSTATE classes that indicate authentication / authorization
// failure at the DB level. SOC2 forensic gap (D-M2) — every match emits
// db.auth.failed with the SQL identity attempted, the database, and
// the statement class.
var _AUTH_FAILURE_CODES = Object.freeze({
  "28000": "invalid_authorization_specification",
  "28P01": "invalid_password",
  "42501": "insufficient_privilege",
});

function _emitAuthFailureAudit(backend, role, sql, e) {
  if (!e || !e.code) return;
  var kind = _AUTH_FAILURE_CODES[e.code];
  if (!kind) return;
  audit().safeEmit({
    action:   "db.auth.failed",
    actor:    {},
    resource: { kind: "db.backend", id: backend.name },
    outcome:  "denied",
    reason:   kind,
    metadata: {
      backend:        backend.name,
      dialect:        backend.dialect,
      sqlIdentity:    role || null,
      sqlstate:       e.code,
      statementClass: _classifyStatement(sql),
    },
  });
  _emitMetric("db.auth.failed", 1, {
    backend:        backend.name,
    sqlstate:       e.code,
    statementClass: _classifyStatement(sql),
  });
}

// Slow-query bucket emitter (D-L7). Single-shot per query — highest
// matched bucket wins. Operators dashboard on the `bucket` label
// rather than separate counters per threshold.
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
// Operator-declared { role: backendName } map for request-time pool pick.
// Populated at init() from opts.dbRoleBackends. Read by _pickBackend
// when no explicit opts.backend is supplied AND the ALS scope has a role.
var dbRoleBackends = {};

// ---- Pool ----
//
// Per-backend pool with lazy creation + LRU-ish reuse. Connections returned
// to the pool when query/transaction completes; idle connections expire.

class Pool {
  constructor(name, config) {
    this.name = name;
    this.config = Object.assign({ min: 1, max: 10, idleTimeoutMs: C.TIME.minutes(1) }, config.pool || {});
    this.connect = config.connect;
    this.close = config.close || function () { return Promise.resolve(); };
    this.idle = [];     // [{ client, lastUsedAt }]
    this.active = 0;    // count of in-use clients
    this.waiters = [];  // queued acquisitions when at max
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
    // At max — wait for a release. The waiter's clock starts now;
    // when release() resolves the waiter we emit the wait duration so
    // operators can see backpressure on the pool.
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
    var now = Date.now();
    var keep = [];
    var self = this;
    this.idle.forEach(function (entry) {
      if ((now - entry.lastUsedAt) >= self.config.idleTimeoutMs) {
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
    this.waiters.forEach(function (w) { w.reject(_err("POOL_DRAINED", "pool is shutting down", true)); });
    this.waiters = [];
  }

  stats() {
    return { active: this.active, idle: this.idle.length, waiters: this.waiters.length };
  }
}

// ---- Init ----

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
 * `RESIDENCY_VIOLATION` when not.
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
 *   //   dialect:              "postgres" | "mysql" | "sqlite" | "mongodb" | "other"  (default "postgres")
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
      throw _err("INVALID_CONFIG", "backend '" + name + "' missing connect() function", true);
    }
    if (typeof cfg.query !== "function") {
      throw _err("INVALID_CONFIG", "backend '" + name + "' missing query() function", true);
    }
    // dialect — informational marker so dialect-specific consumers
    // (e.g. b.db.declareView) can fail-fast at apply time. Defaults to
    // "postgres" because that's the dominant blamejs externalDb target;
    // operators on SQLite/MySQL/etc. set this explicitly so downstream
    // primitives surface NOT_SUPPORTED with a clear message instead of
    // emitting Postgres-flavored DDL into the wrong dialect.
    var dialect = (cfg.dialect || "postgres").toLowerCase();
    if (["postgres", "mysql", "sqlite", "mongodb", "other"].indexOf(dialect) === -1) {
      throw _err("INVALID_CONFIG",
        "backend '" + name + "': dialect must be one of " +
        "'postgres' | 'mysql' | 'sqlite' | 'mongodb' | 'other', got '" + dialect + "'", true);
    }
    // OWASP-3 — application_name normalization for Postgres backends.
    // Always set on every fresh connection (not just connectAs branch)
    // so pg_stat_activity / log_line_prefix / audit log surfaces show
    // a stable identifier instead of falling back to the driver's
    // bare process name. CR / LF / NUL refused at config-time —
    // those characters terminate the SET statement early in some
    // drivers and have no legitimate use in an application_name.
    // OWASP-3 — application_name normalization for Postgres backends.
    // Opt-in via `cfg.applicationName` to surface a stable identifier
    // in pg_stat_activity / log_line_prefix / Postgres audit log
    // surfaces. Default leaves application_name to the driver — issuing
    // a SET on every fresh connection at framework default would
    // double-count queries for operators counting per-pool query
    // activity (and break test fakes that count tracker.query calls).
    var applicationName = cfg.applicationName !== undefined ? cfg.applicationName : null;
    if (applicationName !== null && (typeof applicationName !== "string" || applicationName.length === 0)) {
      throw _err("INVALID_CONFIG",
        "backend '" + name + "': applicationName must be a non-empty string", true);
    }
    if (applicationName !== null) {
      // eslint-disable-next-line no-control-regex
      if (/[\r\n\u0000]/.test(applicationName)) {
      throw _err("INVALID_CONFIG",
        "backend '" + name + "': applicationName must not contain CR, LF, or NUL characters", true);
      }
      if (applicationName.length > C.BYTES.bytes(63)) {
      throw _err("INVALID_CONFIG",
        "backend '" + name + "': applicationName exceeds Postgres 63-byte limit (got " +
        applicationName.length + ")", true);
      }
    }
    var rawConnect = cfg.connect;
    var rawQuery   = cfg.query;
    var connectFn = rawConnect;
    if (dialect === "postgres" && applicationName !== null) {
      // IIFE captures per-iteration rawConnect/rawQuery; without this
      // the var-hoisted bindings are shared across the for-loop and
      // every backend's connectFn ends up calling the LAST iteration's
      // rawQuery (classic closure-in-loop bug).
      connectFn = (function (cn, qn, appName) {
        var quotedAppName = "'" + appName.replace(/'/g, "''") + "'";
        return async function () {
          var client = await cn();
          try {
            await qn(client, "SET application_name TO " + quotedAppName, []);
          } catch (_e) {
            // Best-effort. Real Postgres always supports SET
            // application_name; a driver that refuses it is a shim
            // (test fake / non-PG backend mislabeled "postgres") and
            // there's nothing useful to surface — keep the connection
            // and let the operator hit any real query failure
            // immediately afterwards.
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
      classifications: Array.isArray(cfg.classifications) && cfg.classifications.length > 0
                         ? cfg.classifications.slice()
                         : ["*"],
      residencyTag:    cfg.residencyTag || "unrestricted",
      breaker:         new retryHelper.CircuitBreaker("externalDb:" + name, cfg.breaker),
      retryConfig:     cfg.retry || null,
      replicas:        _buildReplicas(name, cfg),
      replicaIdx:      0,    // round-robin cursor
      replicaFallbackToPrimary: cfg.replicaFallbackToPrimary !== false,
    };
  }

  defaultBackend = opts.defaultBackend || Object.keys(backends)[0];

  // dbRoleBackends — request-time role → backend mapping. Each role name
  // validates as a SQL identifier at init (matches the dbRoleFor
  // middleware's runtime check) so a typo surfaces at boot rather than
  // as a silent default-backend fallback at the first request.
  if (opts.dbRoleBackends !== undefined && opts.dbRoleBackends !== null) {
    if (typeof opts.dbRoleBackends !== "object" || Array.isArray(opts.dbRoleBackends)) {
      throw _err("INVALID_CONFIG",
        "dbRoleBackends must be an object map of role → backendName", true);
    }
    for (var role in opts.dbRoleBackends) {
      if (!Object.prototype.hasOwnProperty.call(opts.dbRoleBackends, role)) continue;
      try {
        safeSql.validateIdentifier(role, { allowReserved: false });
      } catch (e) {
        throw _err("INVALID_CONFIG",
          "dbRoleBackends: role '" + role + "' is not a valid SQL identifier: " +
          ((e && e.message) || String(e)), true);
      }
      var bn = opts.dbRoleBackends[role];
      if (typeof bn !== "string" || bn.length === 0) {
        throw _err("INVALID_CONFIG",
          "dbRoleBackends['" + role + "']: backend name must be a non-empty string", true);
      }
      if (!Object.prototype.hasOwnProperty.call(backends, bn)) {
        throw _err("INVALID_CONFIG",
          "dbRoleBackends['" + role + "']: no backend named '" + bn + "' " +
          "(declared backends: " + Object.keys(backends).join(", ") + ")", true);
      }
      dbRoleBackends[role] = bn;
    }
  }

  _validateResidency();
  initialized = true;
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
      throw _err("RESIDENCY_VIOLATION",
        "externalDb backend '" + name + "' serves 'personal' data with residencyTag '" +
        b.residencyTag + "' but app's dataResidency.region is '" + residency.region + "'",
        true);
    }
  }
}

// ---- Backend selection ----
//
// Pick precedence:
//   1. opts.backend                       — explicit override always wins
//   2. opts.classification                — first backend serving that class
//   3. ALS-bound dbRole + dbRoleBackends  — request-time auto-pick
//   4. defaultBackend                     — final fallback
//
// The ALS path matches the dbRoleFor middleware shape: middleware sets
// the role; deep async reads pick up the matching backend without having
// to thread `req` through every call site.

function _pickBackend(opts) {
  opts = opts || {};
  if (opts.backend) {
    var b = backends[opts.backend];
    if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + opts.backend + "'", true);
    if (opts.classification && !_servesClassification(b, opts.classification)) {
      throw _err("CLASSIFICATION_MISMATCH",
        "backend '" + opts.backend + "' does not serve classification '" + opts.classification + "'", true);
    }
    return b;
  }
  var classification = opts.classification;
  if (classification) {
    for (var name in backends) {
      if (_servesClassification(backends[name], classification)) return backends[name];
    }
    throw _err("NO_BACKEND_FOR_CLASSIFICATION",
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

// ---- Public API ----

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
          // Connection-level errors → destroy the client; query errors →
          // release back to the pool. Heuristic: any error with a code
          // looking like a network/connection issue → destroy.
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
    _emit("system.externaldb.query", "success", {
      backend:        b.name,
      role:           role,
      durationMs:     durationMs,
      classification: opts.classification || null,
      rowCount:       result && result.rowCount,
      // SQL is NOT logged by default — may contain sensitive literal values
      // even in parameterized queries. Operators who want SQL in audit
      // metadata pass opts.includeSqlInAudit: true (then sealed via
      // field-crypto on the audit row).
      sql:            opts.includeSqlInAudit ? sql : null,
    });
    _emitMetric("externaldb.query.success", 1,
      { backend: b.name, role: role || "(none)" });
    _emitMetric("externaldb.query.duration_ms", durationMs,
      { backend: b.name, role: role || "(none)" });
    _emitSlowQuery(b.name, role, durationMs, _classifyStatement(sql));
    return result;
  } catch (e) {
    var failureMs = Date.now() - t0;
    _emit("system.externaldb.query", "failure", {
      backend:        b.name,
      role:           role,
      durationMs:     failureMs,
      classification: opts.classification || null,
      errorCode:      e.code || null,
    }, (e && e.message) || String(e));
    _emitMetric("externaldb.query.failure", 1,
      { backend: b.name, role: role || "(none)", errorCode: e.code || "(none)" });
    _emitSlowQuery(b.name, role, failureMs, _classifyStatement(sql));
    // Postgres signals authorization-denied as SQLSTATE 42501
    // (insufficient_privilege). RLS-shaped writes that violate a
    // policy and GRANT-denied SELECTs both surface this code. The
    // operator's role-views recipe relies on this signal: a row of
    // db.role.denied means a request-time role attempted something its
    // grant or RLS policy forbids — the highest-signal compliance event
    // the externalDb layer can emit.
    if (e && e.code === "42501") {
      _emitMetric("db.role.denied", 1,
        { backend: b.name, role: role || "(none)" });
    }
    // D-M2 — DB-auth audit visibility. Every 28000 / 28P01 / 42501
    // surfaces an auditable db.auth.failed row tagged with the SQL
    // identity and the statement class so SOC2 reviewers can
    // reconstruct the denial timeline.
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
 * @opts
 *   backend?:                    string,                       // explicit backend name
 *   classification?:             string,                       // route by data class
 *   sessionGucs?:                { [name]: string|number|boolean },  // SET LOCAL bindings (e.g. { "app.tenant_id": "acme" })
 *   statementTimeoutMs?:         number,                       // SET LOCAL statement_timeout
 *   idleInTransactionTimeoutMs?: number,                       // SET LOCAL idle_in_transaction_session_timeout
 *   deadlockRetries?:            number,                       // retries for 40P01 / 40001 (default 3)
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
  if (typeof fn !== "function") throw _err("INVALID_FN", "transaction requires a function", true);
  opts = opts || {};
  var b = _pickBackend(opts);
  var role = dbRoleContext.getRole();

  // sessionGucs — per-transaction `SET LOCAL "name" = value` plumbing.
  // Each name validates as a SQL identifier (Postgres GUC names follow
  // the same NAMEDATALEN-shaped rules; dotted GUCs like 'app.tenant_id'
  // validate per-segment via quoteQualified). Values are emitted as SQL
  // string literals (single-quote escaped) for strings, raw for finite
  // numbers. SET LOCAL ties the binding to the surrounding transaction
  // so the tenant_id used by RLS policies resets cleanly at
  // COMMIT/ROLLBACK without caller cleanup.
  var prebuiltGucs = _buildSessionGucsStatements(opts.sessionGucs);

  var t0 = Date.now();
  // D-H4 — per-statement timeout. SET LOCAL statement_timeout binds
  // the query-cancel ceiling to this transaction; D-M7 wires
  // idle_in_transaction_session_timeout from the same opt. Both
  // emit at SET LOCAL scope so the next pool checkout starts clean.
  var stmtTimeoutMs = opts.statementTimeoutMs;
  var idleTimeoutMs = opts.idleInTransactionTimeoutMs;
  // D-M8 — deadlock-retry policy. 40P01 (deadlock_detected) and 40001
  // (serialization_failure) are transient — retry with capped attempts
  // and a small jittered backoff. Operators tune retries via opts.deadlockRetries (default 3).
  // numeric-bounds doesn't have a non-negative-int helper; use a
  // direct check with allow marker (zero is permitted to disable
  // retries entirely).
  if (opts.deadlockRetries !== undefined) {
    if (typeof opts.deadlockRetries !== "number" || !isFinite(opts.deadlockRetries) ||
        opts.deadlockRetries < 0 || (opts.deadlockRetries | 0) !== opts.deadlockRetries) {
      throw _err("INVALID_OPT",
        "transaction: opts.deadlockRetries must be a non-negative integer");
    }
  }
  var maxRetries = (typeof opts.deadlockRetries === "number")
    ? Math.floor(opts.deadlockRetries) : 3;                                       // allow:numeric-opt-Infinity
  return await b.breaker.wrap(async function () {
    var client = await b.pool.acquire();
    var txClient = {
      query: function (sql, params) { return b.query(client, sql, params || []); },
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
            await b.query(client, "SET LOCAL statement_timeout = " + Math.floor(stmtTimeoutMs), []);
          }
          if (typeof idleTimeoutMs === "number" && isFinite(idleTimeoutMs) && idleTimeoutMs > 0) {
            await b.query(client, "SET LOCAL idle_in_transaction_session_timeout = " + Math.floor(idleTimeoutMs), []);
          }
          for (var gi = 0; gi < prebuiltGucs.length; gi++) {
            await b.query(client, prebuiltGucs[gi], []);
          }
          var result = await fn(txClient);
          await b.commit(client);
          committed = true;
          var durationMs = Date.now() - t0;
          _emit("system.externaldb.transaction", "success", {
            backend: b.name, role: role, durationMs: durationMs,
            classification: opts.classification || null,
          });
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
            var nodeCrypto = require("node:crypto");
            var jitter = nodeCrypto.randomInt(0, 6);                          // allow:raw-byte-literal — 0-5ms jitter
            await safeAsync.sleep(attempt * 5 + jitter);                           // allow:raw-time-literal — sub-second backoff
            continue;
          }
          var failureMs = Date.now() - t0;
          _emit("system.externaldb.transaction", "failure", {
            backend: b.name, role: role, durationMs: failureMs,
            classification: opts.classification || null,
            errorCode: txErr.code || null,
          }, (txErr && txErr.message) || String(txErr));
          _emitMetric("externaldb.transaction.failure", 1,
            { backend: b.name, role: role || "(none)", errorCode: txErr.code || "(none)" });
          if (txErr && txErr.code === "42501") {
            _emitMetric("db.role.denied", 1,
              { backend: b.name, role: role || "(none)" });
          }
          // D-M2 — DB-auth audit visibility on transaction-shaped denials.
          // Statement class always reads as "TX" since the failure
          // surface inside a transaction body could be any statement;
          // operators correlate via the transaction's audit row.
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
      else        await b.query(client, "SELECT 1", []);
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

// Build the SET LOCAL statements for a transaction's sessionGucs map.
// Identifier-validates each GUC name (per dot-segment so dotted names
// like 'app.tenant_id' work), quotes them with the Postgres dialect,
// and renders the value as either a SQL string literal (single-quoted,
// embedded quotes doubled) or a numeric literal for finite numbers.
// Bad shapes throw at the call site rather than as a confused Postgres
// error mid-transaction.
function _buildSessionGucsStatements(sessionGucs) {
  if (sessionGucs === undefined || sessionGucs === null) return [];
  if (typeof sessionGucs !== "object" || Array.isArray(sessionGucs)) {
    throw _err("INVALID_SESSION_GUCS",
      "sessionGucs must be an object map of name → value", true);
  }
  var out = [];
  for (var name in sessionGucs) {
    if (!Object.prototype.hasOwnProperty.call(sessionGucs, name)) continue;
    if (typeof name !== "string" || name.length === 0) {
      throw _err("INVALID_SESSION_GUCS",
        "sessionGucs: GUC name must be a non-empty string", true);
    }
    // Validate per-segment so dotted GUCs (Postgres custom GUC class.
    // setting form) pass. quoteQualified handles both the validation
    // and the dot-quoted rendering.
    var qName;
    try {
      qName = safeSql.quoteQualified(name, "postgres");
    } catch (e) {
      throw _err("INVALID_SESSION_GUCS",
        "sessionGucs: name '" + name + "' is not a valid identifier: " +
        ((e && e.message) || String(e)), true);
    }
    var value = sessionGucs[name];
    var literal;
    if (typeof value === "number" && isFinite(value)) {
      literal = String(value);
    } else if (typeof value === "boolean") {
      // Postgres SET accepts on/off/true/false — render true/false.
      literal = value ? "true" : "false";
    } else if (typeof value === "string") {
      // Cap the value length so an operator-controlled tenant_id of
      // 100 KB doesn't hit Postgres' SET LOCAL parser with payload
      // that bloats query logs and consumes max_stack_depth. The cap
      // is generous for legitimate tenant identifiers but rejects
      // amplification.
      if (value.length > C.BYTES.kib(4)) {
        throw _err("INVALID_SESSION_GUCS",
          "sessionGucs['" + name + "']: value exceeds 4 KiB cap (got " +
          value.length + " chars)", true);
      }
      literal = "'" + value.replace(/'/g, "''") + "'";
    } else if (value === null || value === undefined) {
      throw _err("INVALID_SESSION_GUCS",
        "sessionGucs['" + name + "']: value must be a string, finite number, or boolean (got " +
        (value === null ? "null" : "undefined") + ")", true);
    } else {
      throw _err("INVALID_SESSION_GUCS",
        "sessionGucs['" + name + "']: value must be a string, finite number, or boolean (got " +
        typeof value + ")", true);
    }
    out.push("SET LOCAL " + qName + " = " + literal);
  }
  return out;
}

// Fire-and-forget audit emission. We CANNOT await this in cluster mode:
// audit storage routes back through external-db when cluster mode is
// active, so awaiting would create a recursive dependency (every audit
// row insert triggers an external-db query which would await another
// audit row insert). Tests that need audit-row durability before reading
// audit_log should flush microtasks explicitly.
function _emit(action, outcome, metadata, reason) {
  audit().safeEmit({ action: action, outcome: outcome, reason: reason, metadata: metadata });
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "externalDb.init() must be called first", true);
}

// ---- Read-replica routing ----
//
// Operators with a primary + replicas declare replicas alongside the
// primary backend config:
//
//   externalDb.init({
//     backends: {
//       main: {
//         connect, query,                          // primary
//         replicas: [
//           { connect: replica1, query, weight: 1 },
//           { connect: replica2, query, weight: 2 },
//         ],
//         replicaFallbackToPrimary: true,          // default; on all-replicas-unhealthy,
//                                                  //   read.query falls back to primary
//       },
//     },
//   });
//
//   await externalDb.read.query("SELECT * FROM users");      // → replica
//   await externalDb.write.query("INSERT INTO users ...");    // → primary
//   await externalDb.query("...");                            // → primary (legacy, unchanged)
//
// Load balancing: weighted round-robin (default weight 1). Weights
// expand into a static plan at init — a [w1, w2, w3] vector becomes a
// pre-built index sequence, then read.query() advances replicaIdx.
//
// Health: each replica tracks `lastFailureAt`. After UNHEALTHY_COOLDOWN_MS
// since the last failure, the replica re-enters the rotation. Operators
// observing all-replicas-down see read.query() fall back to primary
// (overridable via replicaFallbackToPrimary: false).

var REPLICA_UNHEALTHY_COOLDOWN_MS = C.TIME.seconds(30);

// F-CBT-2 — replica residency-tag compatibility.
//
// A primary tagged "EU" replicating to a "US" replica is a GDPR
// Article 46 cross-border transfer; without an explicit operator
// opt-in the framework refuses init under gdpr / dpdp / pipl-cn /
// uk-gdpr postures. Operator suppresses the gate per replica via
// allowCrossBorder: true (which the framework records in the audit
// chain so a compliance reviewer sees the conscious decision).
//
// Compatible-residency rules:
//   - Identical tags  (EU↔EU, US↔US): always compatible.
//   - "unrestricted" tag on either side: compatible (operator
//     declared no constraint).
//   - Different tags: compatible only when allowCrossBorder is true.
var CROSS_BORDER_REGULATED_POSTURES = Object.freeze([
  "gdpr", "uk-gdpr", "dpdp", "pipl-cn", "lgpd-br", "appi-jp", "pdpa-sg",
]);

function _residencyCompatible(primaryTag, replicaTag) {
  if (!primaryTag || !replicaTag) return true;
  if (primaryTag === replicaTag) return true; // allow:raw-hash-compare — residency tag string, not a secret hash
  if (primaryTag === "unrestricted" || replicaTag === "unrestricted") return true;
  return false;
}

function _activePosture() {
  try {
    var compliance = require("./compliance");                                                    // allow:inline-require — defensive against optional load
    return compliance.current();
  } catch (_e) { return null; }
}

function _buildReplicas(backendName, cfg) {
  if (!cfg.replicas) return null;
  if (!Array.isArray(cfg.replicas) || cfg.replicas.length === 0) {
    throw _err("INVALID_CONFIG",
      "backend '" + backendName + "': replicas must be a non-empty array", true);
  }
  var primaryTag = cfg.residencyTag || "unrestricted";
  var posture = _activePosture();
  var out = [];
  for (var i = 0; i < cfg.replicas.length; i++) {
    var r = cfg.replicas[i];
    if (!r || typeof r.connect !== "function") {
      throw _err("INVALID_CONFIG",
        "backend '" + backendName + "': replicas[" + i + "].connect must be a function", true);
    }
    if (typeof r.query !== "function") {
      throw _err("INVALID_CONFIG",
        "backend '" + backendName + "': replicas[" + i + "].query must be a function", true);
    }
    var weight = r.weight !== undefined ? r.weight : 1;
    if (typeof weight !== "number" || !isFinite(weight) || weight <= 0 ||
        Math.floor(weight) !== weight) {
      throw _err("INVALID_CONFIG",
        "backend '" + backendName + "': replicas[" + i + "].weight must be a positive integer", true);
    }
    var replicaTag = r.residencyTag || "unrestricted";
    var allowCrossBorder = r.allowCrossBorder === true;
    if (!_residencyCompatible(primaryTag, replicaTag) && !allowCrossBorder) {
      var underPosture = posture && CROSS_BORDER_REGULATED_POSTURES.indexOf(posture) !== -1;
      throw _err("RESIDENCY_MISMATCH",
        "backend '" + backendName + "': replica[" + i +
        "] residencyTag '" + replicaTag +
        "' is not compatible with primary residencyTag '" + primaryTag +
        "'" + (underPosture ? " under '" + posture + "' posture" : "") +
        ". This is a cross-border data transfer (GDPR Art 46 / DPDP / PIPL " +
        "category). Pass allowCrossBorder: true on the replica config with a " +
        "documented legal basis (SCCs / BCRs / adequacy decision) to suppress.", true);
    }
    if (!_residencyCompatible(primaryTag, replicaTag) && allowCrossBorder) {
      _emit("externalDb.replica.cross_border_allowed", "warning",
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
  // Build a healthy candidate set.
  var healthy = [];
  for (var i = 0; i < b.replicas.length; i++) {
    var r = b.replicas[i];
    if (now - r.lastFailureAt >= REPLICA_UNHEALTHY_COOLDOWN_MS) healthy.push(r);
  }
  if (healthy.length === 0) return null;
  // Weighted round-robin: walk by weight, advancing replicaIdx by 1 each
  // call and modding by total weight. Each replica's "slot" in the
  // sequence repeats `weight` times.
  var totalWeight = 0;
  for (var w = 0; w < healthy.length; w++) totalWeight += healthy[w].weight;
  var cursor = (b.replicaIdx++) % totalWeight;
  var acc = 0;
  for (var c = 0; c < healthy.length; c++) {
    acc += healthy[c].weight;
    if (cursor < acc) return healthy[c];
  }
  return healthy[0];   // unreachable; defensive
}

async function _readQuery(sql, params, opts) {
  _requireInit();
  opts = opts || {};
  var b = _pickBackend(opts);
  if (!b.replicas || b.replicas.length === 0) {
    // No replicas configured — read.query() returns primary.
    return query(sql, params, opts);
  }
  var replica = _pickReplica(b);
  if (!replica) {
    if (b.replicaFallbackToPrimary) return query(sql, params, opts);
    throw _err("ALL_REPLICAS_UNHEALTHY",
      "backend '" + b.name + "': all replicas unhealthy and fallback disabled", true);
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
      _emit("system.externaldb.read", "success", {
        backend:    b.name,
        role:       role,
        replicaIdx: replica.index,
        durationMs: durationMs,
        rowCount:   res && res.rowCount,
      });
      _emitMetric("externaldb.read.success", 1,
        { backend: b.name, role: role || "(none)", replicaIdx: replica.index });
      _emitMetric("externaldb.read.duration_ms", durationMs,
        { backend: b.name, role: role || "(none)", replicaIdx: replica.index });
      return res;
    } catch (e) {
      // Connection-shape errors mark unhealthy + destroy.
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
    _emit("system.externaldb.read", "failure", {
      backend:    b.name,
      role:       role,
      replicaIdx: replica.index,
      durationMs: Date.now() - t0,
      errorCode:  e.code || null,
    }, (e && e.message) || String(e));
    _emitMetric("externaldb.read.failure", 1,
      { backend: b.name, role: role || "(none)", errorCode: e.code || "(none)" });
    if (e && e.code === "42501") {
      _emitMetric("db.role.denied", 1,
        { backend: b.name, role: role || "(none)" });
    }
    // D-M2 — DB-auth audit visibility for read-replica denials too.
    _emitAuthFailureAudit(b, role, sql, e);
    // Fallback to primary on a failed replica read when allowed.
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
// write namespace — alias for the primary path. Lets operators express
// intent symmetrically with read.query without a magic-comment hint.
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

// ---- configurePool — runtime resize of an existing backend's pool ----
//
// Operators tune pool sizing without restarting the app. Existing idle
// clients are kept; new acquisitions respect the new max. min is honored
// the next time the pool refills. idleTimeoutMs takes effect on the next
// reaper tick.
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
    throw _err("INVALID_CONFIG", "configurePool: backendName must be a non-empty string", true);
  }
  var bk = backends[backendName];
  if (!bk) throw _err("UNKNOWN_BACKEND", "configurePool: no backend named '" + backendName + "'", true);
  if (!opts || typeof opts !== "object") {
    throw _err("INVALID_CONFIG", "configurePool: opts must be an object", true);
  }
  var allowed = ["min", "max", "idleTimeoutMs"];
  for (var k in opts) {
    if (!Object.prototype.hasOwnProperty.call(opts, k)) continue;
    if (allowed.indexOf(k) === -1) {
      throw _err("INVALID_CONFIG",
        "configurePool: unknown option '" + k + "'. Allowed: " + allowed.join(", "), true);
    }
  }
  function _requirePosInt(name, value) {
    if (typeof value !== "number" || !isFinite(value) || value <= 0 || Math.floor(value) !== value) {
      throw _err("INVALID_CONFIG",
        "configurePool: " + name + " must be a positive integer, got " + JSON.stringify(value), true);
    }
  }
  if (opts.min           !== undefined) _requirePosInt("min", opts.min);
  if (opts.max           !== undefined) _requirePosInt("max", opts.max);
  if (opts.idleTimeoutMs !== undefined) _requirePosInt("idleTimeoutMs", opts.idleTimeoutMs);
  if (opts.min !== undefined && opts.max !== undefined && opts.min > opts.max) {
    throw _err("INVALID_CONFIG", "configurePool: min must be <= max", true);
  }
  Object.assign(bk.pool.config, opts);
}

// ---- adapters.connectAs — Postgres role-aware connect wrapper ----
//
// Wraps an operator's connect() so that every fresh client runs
// `SET ROLE`, `SET search_path`, `SET application_name`, and any other
// operator-supplied GUCs at acquire time. The pattern enables the
// search_path-views shape: the same SQL `SELECT * FROM sessions`
// resolves to `public.sessions` for app_user and to
// `analytics.sessions` (a view with PHI redacted) for analytics_user.
// See the "Compliance Patterns" wiki page.
//
// Identifier inputs (role, schemas in searchPath) are validated via
// safeSql.validateIdentifier — bad shapes throw at the call site. String
// values (applicationName, statement_timeout) are quoted as SQL string
// literals with single-quote escaping per the SQL standard.
//
//   connect: b.externalDb.adapters.connectAs(rawConnect, {
//     role:               "analytics_user",
//     searchPath:         ["analytics", "public"],
//     applicationName:    "wiki:analytics",
//     statementTimeoutMs: C.TIME.seconds(30),
//     gucs: {
//       idle_in_transaction_session_timeout: "60s",
//     },
//   })
//
// `query` is the same query function the backend declares; the wrapper
// uses it to issue the SET statements.
function _connectAs(rawConnect, query, opts) {
  if (typeof rawConnect !== "function") {
    throw _err("INVALID_CONFIG", "connectAs: connect must be a function", true);
  }
  if (typeof query !== "function") {
    throw _err("INVALID_CONFIG", "connectAs: query must be a function", true);
  }
  opts = opts || {};
  var allowed = ["role", "searchPath", "applicationName", "statementTimeoutMs", "gucs"];
  for (var k in opts) {
    if (!Object.prototype.hasOwnProperty.call(opts, k)) continue;
    if (allowed.indexOf(k) === -1) {
      throw _err("INVALID_CONFIG",
        "connectAs: unknown option '" + k + "'. Allowed: " + allowed.join(", "), true);
    }
  }

  // Validate inputs at config time so a malformed name surfaces at
  // boot rather than on the first connection.
  if (opts.role !== undefined) {
    safeSql.validateIdentifier(String(opts.role), { allowReserved: false });
  }
  var pathSegments = null;
  if (opts.searchPath !== undefined) {
    var raw = Array.isArray(opts.searchPath) ? opts.searchPath : [opts.searchPath];
    if (raw.length === 0) {
      throw _err("INVALID_CONFIG", "connectAs: searchPath must have at least one schema", true);
    }
    pathSegments = [];
    for (var pi = 0; pi < raw.length; pi++) {
      safeSql.validateIdentifier(String(raw[pi]), { allowReserved: false });
      pathSegments.push(String(raw[pi]));
    }
  }
  if (opts.applicationName !== undefined && typeof opts.applicationName !== "string") {
    throw _err("INVALID_CONFIG", "connectAs: applicationName must be a string", true);
  }
  if (opts.statementTimeoutMs !== undefined) {
    if (typeof opts.statementTimeoutMs !== "number" || !isFinite(opts.statementTimeoutMs) ||
        opts.statementTimeoutMs <= 0 || Math.floor(opts.statementTimeoutMs) !== opts.statementTimeoutMs) {
      throw _err("INVALID_CONFIG",
        "connectAs: statementTimeoutMs must be a positive integer", true);
    }
  }
  if (opts.gucs !== undefined && (typeof opts.gucs !== "object" || opts.gucs === null)) {
    throw _err("INVALID_CONFIG", "connectAs: gucs must be an object", true);
  }
  if (opts.gucs) {
    for (var gname in opts.gucs) {
      // GUC names: Postgres NAMEDATALEN-shaped identifiers.
      safeSql.validateIdentifier(gname, { allowReserved: true });
    }
  }

  // Pre-compute the SET statements once — every fresh client runs the
  // same list, so building it per-connect would burn microbenchmarks.
  var stmts = [];
  if (opts.role) {
    stmts.push('SET ROLE "' + opts.role + '"');
  }
  if (pathSegments) {
    var pathSql = pathSegments.map(function (s) { return '"' + s + '"'; }).join(", ");
    stmts.push("SET search_path TO " + pathSql);
  }
  if (opts.applicationName !== undefined) {
    // Single-quoted string literal — SQL-standard escape doubles embedded
    // single quotes.
    var an = String(opts.applicationName).replace(/'/g, "''");
    stmts.push("SET application_name TO '" + an + "'");
  }
  if (opts.statementTimeoutMs !== undefined) {
    stmts.push("SET statement_timeout TO " + opts.statementTimeoutMs);
  }
  if (opts.gucs) {
    for (var gn in opts.gucs) {
      var gv = opts.gucs[gn];
      if (typeof gv === "number") {
        // Numeric GUCs must be finite — Infinity / NaN serialize as
        // tokens that Postgres would reject at parse time, but only
        // AFTER the connection started using a half-set state. Refuse
        // at config-time instead.
        if (!isFinite(gv)) {
          throw _err("INVALID_CONFIG",
            "connectAs: gucs[" + gn + "] number must be finite (got " + gv + ")",
            true);
        }
        stmts.push('SET "' + gn + '" TO ' + gv);
      } else {
        var gvs = String(gv).replace(/'/g, "''");
        // Refuse embedded NUL / line breaks in GUC string values —
        // they have no legitimate use and would terminate the SET
        // statement early in some drivers.
        // eslint-disable-next-line no-control-regex
        if (/[\r\n\u0000]/.test(gvs)) {
          throw _err("INVALID_CONFIG",
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
      // Initialization failed — the operator's close hook isn't visible
      // here, so we throw and let the pool's catch destroy the partial
      // client.
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
// Operators import the helper as `b.externalDb.adapters.connectAs(connect, opts)`
// — declarative wrapping with shared input validation.
function _adaptersConnectAs(connect, opts) {
  // The backend's query function is needed to issue SET statements on a
  // freshly-acquired client. Operators pass it via opts.query — same
  // function they declare on the backend itself.
  if (!opts || typeof opts !== "object") {
    throw _err("INVALID_CONFIG",
      "adapters.connectAs: opts must be an object", true);
  }
  if (typeof opts.query !== "function") {
    throw _err("INVALID_CONFIG",
      "adapters.connectAs: opts.query is required (the backend's query function)", true);
  }
  // Pull query off and pass the remaining role-aware opts.
  var query = opts.query;
  var roleOpts = {};
  for (var k in opts) {
    if (Object.prototype.hasOwnProperty.call(opts, k) && k !== "query") {
      roleOpts[k] = opts[k];
    }
  }
  return _connectAs(connect, query, roleOpts);
}

// ---- runAs / currentRole — out-of-request role binding ----
//
// Inside an HTTP request the dbRoleFor middleware already pushes the
// role into the shared db-role-context ALS. Background workers (jobs,
// schedulers, CLI commands) don't run under that middleware — they wrap
// their work in runAs(role, fn) so the same backend-pick logic applies.
//
//   await b.externalDb.runAs("analytics_user", async function () {
//     return await b.externalDb.read.query("SELECT ...");   // → analytics backend
//   });
//
// currentRole() returns the active role (or null) — useful for diagnostic
// logs and observability labels.
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
    throw _err("INVALID_FN", "externalDb.runAs: fn must be a function", true);
  }
  if (role !== null && role !== undefined) {
    if (typeof role !== "string" || role.length === 0) {
      throw _err("INVALID_ROLE",
        "externalDb.runAs: role must be a non-empty string or null", true);
    }
    safeSql.validateIdentifier(role, { allowReserved: false });
  }
  // Audit the role transition. runAs has no req, so the actor 5 W's
  // come from whatever the caller has bound on the audit-context ALS
  // (log.js requestId, plus any request-bound actor that was set in
  // an outer scope). Same audit shape as the dbRoleFor middleware
  // path — forensic walkers can reconstruct the role timeline whether
  // the binding came from request middleware or a job runner.
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

// OWASP-2 — pg_roles enumeration / unrecognized-role guard.
//
// Boot-time check that compares pg_roles membership to the operator-
// declared role list. Operators declare every role they expect to
// exist on the cluster (via opts.declaredRoles); the gate refuses or
// audits when pg_roles surfaces names not in that list — typical
// signal of a forgotten ALTER ROLE / a leftover migration role / a
// privileged role added outside change-management.
//
//   await b.externalDb.assertRoleHardening({
//     backend:        "main",
//     declaredRoles:  ["app_user", "analytics_user", "admin"],
//     mode:           "audit",          // "audit" | "throw"
//     ignoreSystem:   true,              // skip rds_*, pg_*, postgres
//   });
//
// Returns { declared, observed, unrecognized, missing }. mode="throw"
// raises ROLE_HARDENING_FAIL when unrecognized rows surface; default
// "audit" emits db.role.hardening.unrecognized so dashboards see the
// drift without breaking boot.
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
    throw _err("INVALID_CONFIG",
      "assertRoleHardening: opts is required ({ declaredRoles, backend?, mode? })", true);
  }
  if (!Array.isArray(opts.declaredRoles)) {
    throw _err("INVALID_CONFIG",
      "assertRoleHardening: opts.declaredRoles must be an array of role names", true);
  }
  for (var i = 0; i < opts.declaredRoles.length; i++) {
    var r = opts.declaredRoles[i];
    if (typeof r !== "string" || r.length === 0) {
      throw _err("INVALID_CONFIG",
        "assertRoleHardening: declaredRoles[" + i + "] must be a non-empty string", true);
    }
  }
  var mode = opts.mode || "audit";
  if (mode !== "audit" && mode !== "throw") {
    throw _err("INVALID_CONFIG",
      "assertRoleHardening: mode must be 'audit' or 'throw' (got '" + mode + "')", true);
  }
  var backendName = opts.backend || defaultBackend;
  var b = backends[backendName];
  if (!b) {
    throw _err("UNKNOWN_BACKEND",
      "assertRoleHardening: no backend named '" + backendName + "'", true);
  }
  if (b.dialect !== "postgres") {
    // Non-Postgres dialects don't have pg_roles. The check is a no-op
    // with a clear audit row so operators see the skip rather than
    // assume hardening ran.
    audit().safeEmit({
      action:   "db.role.hardening.skipped",
      actor:    {},
      resource: { kind: "db.backend", id: backendName },
      outcome:  "success",
      metadata: { dialect: b.dialect, reason: "non-postgres" },
    });
    return { declared: opts.declaredRoles.slice(), observed: [], unrecognized: [], missing: [] };
  }
  var ignoreSystem = opts.ignoreSystem !== false;   // default true
  var rows;
  try {
    var res = await query(
      "SELECT rolname FROM pg_roles ORDER BY rolname",
      [],
      { backend: backendName }
    );
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
    throw _err("ROLE_HARDENING_UNREADABLE",
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
      throw _err("ROLE_HARDENING_FAIL",
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
  // Migration runner targeting an externalDb backend. Mirrors b.migrations
  // (which targets local SQLite) but runs against externalDb. Tracking +
  // lock tables live on the externalDb side. See lib/external-db-migrate.js.
  migrate:        externalDbMigrate,
  Pool:           Pool,
  _resetForTest:  _resetForTest,
};
