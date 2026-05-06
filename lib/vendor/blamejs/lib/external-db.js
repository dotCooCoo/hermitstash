"use strict";
/**
 * External database service — pluggable wrapper for app-data DB connections.
 *
 * Framework state (audit_log, consent_log, _blamejs_*) stays in the local
 * SQLite via b.db. This module is for APP DATA — when an operator wants to
 * keep their app's domain tables in Postgres / MySQL / MongoDB / libsql /
 * etc., they configure a backend here and use b.externalDb.query() instead
 * of b.db.from() for those tables.
 *
 * Bring-your-own-client design (per "zero npm runtime deps" rule):
 *   The operator supplies the actual DB driver via the backend's connect/
 *   query/close functions. The framework adds:
 *     - Connection pooling (lazy-create, reuse across queries)
 *     - Retry on transient errors (5xx-equivalent + network)
 *     - Circuit breaker per-backend
 *     - Classification routing (which backend serves which data class)
 *     - Residency enforcement (boot-time validation against
 *       db.getDataResidency().region)
 *     - Audit hooks (system.externaldb.{query,transaction,connect.failure})
 *
 * Built-in protocol adapters (native pg-wire, libsql-HTTP, MongoDB wire)
 * are not currently bundled — operators supply `connect`/`query`/`close`
 * directly using their wire client of choice. When framework-bundled
 * adapters land they will be available as `b.externalDb.adapters.pg`,
 * `.libsqlHttp`, etc., but the bring-your-own-client API is the
 * permanent surface.
 *
 * Public API:
 *   externalDb.init({ backends: { name: { connect, query, close?, ... } },
 *                     defaultBackend? })
 *   externalDb.query(sql, params?, opts?)         → { rows, rowCount }
 *   externalDb.transaction(fn, opts?)             → fn's return value
 *   externalDb.healthCheck(backendName?)          → backend status
 *   externalDb.listBackends()
 *   externalDb.shutdown()
 *
 * Backend config:
 *   {
 *     connect():  async () → client (returns operator's DB client)
 *     query(client, sql, params): async → { rows, rowCount }
 *     close(client): async → void
 *     ping(client): async → bool                  (optional health check)
 *     beginTx(client): async → void               (optional; default 'BEGIN')
 *     commit(client): async → void                (optional; default 'COMMIT')
 *     rollback(client): async → void              (optional; default 'ROLLBACK')
 *     pool: { min: 1, max: 10, idleTimeoutMs: C.TIME.minutes(1) }
 *     classifications: ['personal' | 'operational' | 'public' | <custom>]
 *     residencyTag: 'EU' | 'US' | ...
 *     retry, breaker
 *   }
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
    backends[name] = {
      name:            name,
      dialect:         dialect,
      pool:            new Pool(name, cfg),
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
    throw e;
  }
}

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
  return await b.breaker.wrap(async function () {
    var client = await b.pool.acquire();
    var txClient = {
      query: function (sql, params) { return b.query(client, sql, params || []); },
    };
    var committed = false;
    try {
      await b.beginTx(client);
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
    } catch (e) {
      try { if (!committed) await b.rollback(client); } catch (_e) { /* best effort */ }
      var failureMs = Date.now() - t0;
      _emit("system.externaldb.transaction", "failure", {
        backend: b.name, role: role, durationMs: failureMs,
        classification: opts.classification || null,
        errorCode: e.code || null,
      }, (e && e.message) || String(e));
      _emitMetric("externaldb.transaction.failure", 1,
        { backend: b.name, role: role || "(none)", errorCode: e.code || "(none)" });
      if (e && e.code === "42501") {
        _emitMetric("db.role.denied", 1,
          { backend: b.name, role: role || "(none)" });
      }
      throw e;
    } finally {
      b.pool.release(client);
    }
  });
}

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

function _buildReplicas(backendName, cfg) {
  if (!cfg.replicas) return null;
  if (!Array.isArray(cfg.replicas) || cfg.replicas.length === 0) {
    throw _err("INVALID_CONFIG",
      "backend '" + backendName + "': replicas must be a non-empty array", true);
  }
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
    out.push({
      index:           i,
      pool:            new Pool(backendName + ":replica:" + i, r),
      query:           r.query,
      weight:          weight,
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
    // Fallback to primary on a failed replica read when allowed.
    if (b.replicaFallbackToPrimary) {
      return query(sql, params, opts);
    }
    throw e;
  }
}

var read = {
  query: _readQuery,
};

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
        stmts.push('SET "' + gn + '" TO ' + gv);
      } else {
        var gvs = String(gv).replace(/'/g, "''");
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

function currentRole() {
  return dbRoleContext.getRole();
}

module.exports = {
  init:           init,
  query:          query,
  transaction:    transaction,
  healthCheck:    healthCheck,
  listBackends:   listBackends,
  shutdown:       shutdown,
  configurePool:  configurePool,
  read:           read,
  write:          write,
  runAs:          runAs,
  currentRole:    currentRole,
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
