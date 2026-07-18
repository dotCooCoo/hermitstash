// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.tenantQuota
 * @nav    Production
 * @title  Tenant Quota
 *
 * @intro
 *   Per-tenant rate / byte / row quotas with enforcement helpers and
 *   audit emission on breach. Multi-tenant deployments need three
 *   things the framework's DB layer doesn't natively provide:
 *
 *     1. Storage caps  — refuse INSERT when a tenant has consumed
 *                        more than its allowance (`defaultBytesCap`,
 *                        or a `perTenantBytesCap[tenantId]` override).
 *     2. Query budgets — refuse SELECT when a tenant exceeds its
 *                        rolling-window QPS or rows-read totals.
 *     3. Isolation     — every row a query reads under a claimed
 *                        tenantId MUST belong to that tenant.
 *                        Cross-tenant rows surface as
 *                        `db.tenant.crossover` audit events.
 *
 *   Replaces the global `maxRowsPerQuery` knob for tenant-scoped
 *   scenarios — operators were previously forced to pick one global
 *   cap that would starve large tenants or under-cap small ones.
 *
 *   Storage-cap accounting: `bytesUsed` is computed by walking every
 *   table whose schema declares the configured `tenantField` and
 *   summing the textual length of every column for matching rows.
 *   The framework caches the per-tenant total for `cacheTtlMs`
 *   (default 30s) so a hot path doesn't pay the scan on every assert.
 *
 *   Query budget: sliding-window counter keyed `(tenantId, windowStart)`.
 *   Window defaults to 60s. `observe()` rejects when either the
 *   QPS-equivalent call count exceeds `perTenantQpsCap * window` or
 *   the rows-read total exceeds `perTenantTotalRowsRead`.
 *
 *   Audit emissions:
 *     - `tenant.quota.exceeded`  — `assert()` refused an insert/update
 *     - `tenant.budget.exceeded` — `observe()` refused a query
 *     - `db.tenant.crossover`    — `instrumentQuery` saw rows belonging
 *                                  to the wrong tenant under the
 *                                  operator-claimed tenantId
 *
 *   SOC 2 CC6.1 ("logical access controls") + ISO 27001 A.8.1.5
 *   ("classification of information") map directly onto this
 *   primitive — operators wire its emissions into the same audit
 *   chain auditors read.
 *
 * @card
 *   Per-tenant rate / byte / row quotas with enforcement helpers and audit emission on breach.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var TenantQuotaError = defineClass("TenantQuotaError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var cryptoField = lazyRequire(function () { return require("./crypto-field"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_CACHE_TTL_MS = C.TIME.seconds(30);
var DEFAULT_WINDOW_MS    = C.TIME.minutes(1);
var DEFAULT_QPS_CAP      = 100;                                                    // request count, not bytes
var DEFAULT_ROWS_READ    = 50000;                                                  // row count, not bytes
var DEFAULT_BYTES_CAP    = C.BYTES.gib(1);

// ---- Per-tenant storage cap (assert / snapshot / list) ----

/**
 * @primitive b.tenantQuota.create
 * @signature b.tenantQuota.create(opts)
 * @since     0.7.0
 * @compliance soc2, gdpr
 * @related   b.tenantQuota.budget, b.tenantQuota.instrumentQuery
 *
 * Build a per-tenant storage-cap enforcer. Returns an object exposing
 * `assert(tenantId)` (throws `TenantQuotaError` on breach),
 * `snapshot(tenantId)` (returns `{ tenantId, bytesUsed, bytesCap,
 * percent }`), `list()` (snapshot every distinct tenant), and
 * `invalidate(tenantId?)` (drop the per-tenant cache so the next
 * assert recomputes). The cache TTL trades freshness for cost on
 * the hot path; bump it down for stricter limits.
 *
 * @opts
 *   {
 *     db:                 object,                    // required, b.db namespace
 *     tenantField:        string,                    // required, e.g. "tenantId"
 *     defaultBytesCap?:   number,                    // default: 1 GiB (C.BYTES.gib(1))
 *     perTenantBytesCap?: { [tenantId: string]: number },
 *     tables?:            string[],                  // override auto-detection
 *     audit?:             boolean,                   // default: true
 *     cacheTtlMs?:        number,                    // default: 30_000
 *   }
 *
 * @example
 *   var quota = b.tenantQuota.create({
 *     db:                b.db,
 *     tenantField:       "tenantId",
 *     defaultBytesCap:   b.constants.BYTES.gib(1),
 *     perTenantBytesCap: { "tenant-vip": b.constants.BYTES.gib(10) },
 *   });
 *   await quota.assert("tenant-acme");
 *   // → { tenantId: "tenant-acme", bytesUsed: 12345, bytesCap: 1073741824, percent: 0.0000115 }
 */
function create(opts) {
  validateOpts.requireObject(opts, "tenantQuota.create", TenantQuotaError);
  validateOpts(opts, [
    "db", "tenantField", "defaultBytesCap", "perTenantBytesCap",
    "tables", "audit", "cacheTtlMs",
  ], "tenantQuota.create");

  if (!opts.db || typeof opts.db.from !== "function" ||
      typeof opts.db.prepare !== "function" ||
      typeof opts.db.getTableMetadata !== "function") {
    throw new TenantQuotaError("tenant-quota/bad-db",
      "tenantQuota.create: opts.db must be the framework's b.db namespace");
  }
  validateOpts.requireNonEmptyString(opts.tenantField,
    "tenantQuota.create: tenantField", TenantQuotaError, "tenant-quota/bad-field");

  var defaultBytesCap = (opts.defaultBytesCap == null)
    ? DEFAULT_BYTES_CAP
    : opts.defaultBytesCap;
  if (typeof defaultBytesCap !== "number" || !isFinite(defaultBytesCap) || defaultBytesCap <= 0) {
    throw new TenantQuotaError("tenant-quota/bad-cap",
      "tenantQuota.create: defaultBytesCap must be a positive finite number");
  }

  var perTenantBytesCap = opts.perTenantBytesCap || {};
  if (typeof perTenantBytesCap !== "object" || Array.isArray(perTenantBytesCap)) {
    throw new TenantQuotaError("tenant-quota/bad-per-tenant",
      "tenantQuota.create: perTenantBytesCap must be a plain object {tenantId: bytes}");
  }
  // Validate every per-tenant override at config time so a typo
  // surfaces here rather than as a silent fall-through to default.
  var ptKeys = Object.keys(perTenantBytesCap);
  for (var pi = 0; pi < ptKeys.length; pi++) {
    var v = perTenantBytesCap[ptKeys[pi]];
    if (typeof v !== "number" || !isFinite(v) || v <= 0) {
      throw new TenantQuotaError("tenant-quota/bad-per-tenant",
        "tenantQuota.create: perTenantBytesCap['" + ptKeys[pi] +
        "'] must be a positive finite number");
    }
  }

  var auditOn = opts.audit !== false;
  var cacheTtlMs = (opts.cacheTtlMs == null) ? DEFAULT_CACHE_TTL_MS : opts.cacheTtlMs;
  if (typeof cacheTtlMs !== "number" || !isFinite(cacheTtlMs) || cacheTtlMs < 0) {
    throw new TenantQuotaError("tenant-quota/bad-ttl",
      "tenantQuota.create: cacheTtlMs must be a non-negative finite number");
  }

  var db = opts.db;
  var tenantField = opts.tenantField;

  // tables — operator-supplied table list (must include tenantField).
  // When omitted we walk getTableMetadata() and pick every table whose
  // schema declares the configured field.
  var tablesOverride = Array.isArray(opts.tables) ? opts.tables.slice() : null;

  function _resolveTables() {
    if (tablesOverride) return tablesOverride;
    var meta = db.getTableMetadata();
    var out = [];
    var keys = Object.keys(meta || {});
    for (var i = 0; i < keys.length; i++) {
      var t = meta[keys[i]];
      if (t && t.columns && Object.prototype.hasOwnProperty.call(t.columns, tenantField)) {
        out.push(keys[i]);
      }
    }
    return out;
  }

  // Per-tenant cached snapshot — { bytesUsed, takenAt }
  var cache = new Map();

  function _capFor(tenantId) {
    if (Object.prototype.hasOwnProperty.call(perTenantBytesCap, tenantId)) {
      return perTenantBytesCap[tenantId];
    }
    return defaultBytesCap;
  }

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  function _emitMetric(name, n) {
    try { observability().safeEvent(name, n || 1, {}); }
    catch (_e) { /* drop-silent */ }
  }

  async function _computeBytesUsed(tenantId) {
    var tables = _resolveTables();
    var total = 0;
    for (var i = 0; i < tables.length; i++) {
      var table = tables[i];
      // Resolve the tenant predicate. When tenantField is itself a SEALED
      // column, the plaintext tenantId never equals the on-disk vault
      // envelope, so the framework filters it by its derived-hash blind index.
      // Reuse cryptoField.lookupHash — the same rewrite db.from().where()
      // applies — so a sealed tenantField resolves correctly (including the
      // legacy dual-read across the keyed-MAC flip). A plaintext tenantField
      // compares directly. Without this, a schema that seals the tenant id
      // matches zero rows and the cap silently never fires.
      var whereField = tenantField;
      var whereVals = [tenantId];
      var sealed = cryptoField().getSealedFields(table) || [];
      if (sealed.indexOf(tenantField) !== -1) {
        var lk = cryptoField().lookupHash(table, tenantField, tenantId);
        if (!lk) {
          throw new TenantQuotaError("tenant-quota/sealed-tenant-no-hash",
            "tenantQuota: tenantField '" + tenantField + "' on table '" + table +
            "' is a sealed column without a derived hash; declare " +
            "derivedHashes: { <name>: { from: '" + tenantField + "' } } so it can be queried");
        }
        whereField = lk.field;
        whereVals = (lk.legacyValue != null && lk.legacyValue !== lk.value)
          ? [lk.value, lk.legacyValue]
          : [lk.value];
      }
      // Build the read with b.sql — the same builder db.from() uses — so the
      // table and column identifiers get identical handling (schema-qualified
      // "schema.table" names, reserved-word names, dialect quoting) without
      // re-implementing any of it here. Run it raw via db.prepare and, unlike
      // db.from().all(), do NOT route rows through cryptoField.unsealRow: a
      // storage cap must count what is actually on disk — the (much larger)
      // vault envelope of a sealed column, not the plaintext it unseals to —
      // or a tenant whose data lives in sealed columns sails under the cap.
      // The tenant value(s) are bound parameters.
      var built = sql.select(table, { dialect: "sqlite", quoteName: true })
        .whereIn(whereField, whereVals)
        .toSql();
      var stmt = db.prepare(built.sql);
      var rows = stmt.all.apply(stmt, built.params);
      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        var keys = Object.keys(row);
        for (var k = 0; k < keys.length; k++) {
          var v = row[keys[k]];
          if (v == null) continue;
          // BLOB columns round-trip as a typed-array view (node:sqlite hands
          // them back as Uint8Array, not a Node Buffer), so count the true
          // byte length off any ArrayBuffer view rather than stringifying it
          // — String(Uint8Array) is the decimal-joined bytes, a ~3x overcount
          // that would refuse inserts well below the real storage cap. Text
          // (including a sealed column's "vault:" envelope) is counted as its
          // UTF-8 byte length, not the JS string .length — a multi-byte
          // character occupies more than one byte on disk.
          if (ArrayBuffer.isView(v)) total += v.byteLength;
          else total += Buffer.byteLength(String(v), "utf8");
        }
      }
    }
    return total;
  }

  async function snapshot(tenantId) {
    validateOpts.requireNonEmptyString(tenantId,
      "tenantQuota.snapshot: tenantId", TenantQuotaError, "tenant-quota/bad-tenant");
    var now = Date.now();
    var cached = cache.get(tenantId);
    var bytesUsed;
    if (cached && (now - cached.takenAt) < cacheTtlMs) {
      bytesUsed = cached.bytesUsed;
    } else {
      bytesUsed = await _computeBytesUsed(tenantId);
      cache.set(tenantId, { bytesUsed: bytesUsed, takenAt: now });
    }
    var bytesCap = _capFor(tenantId);
    return {
      tenantId: tenantId,
      bytesUsed: bytesUsed,
      bytesCap:  bytesCap,
      percent:   bytesCap === 0 ? 0 : bytesUsed / bytesCap,
    };
  }

  async function assert(tenantId) {
    var snap = await snapshot(tenantId);
    if (snap.bytesUsed >= snap.bytesCap) {
      _emitAudit("tenant.quota.exceeded", "denied", {
        tenantId: tenantId,
        bytesUsed: snap.bytesUsed,
        bytesCap:  snap.bytesCap,
      });
      _emitMetric("tenant.quota.exceeded", 1);
      throw new TenantQuotaError("tenant-quota/exceeded",
        "tenantQuota.assert: tenant '" + tenantId + "' is at " +
        snap.bytesUsed + " of " + snap.bytesCap + " bytes; insert refused");
    }
    return snap;
  }

  async function list() {
    // Walk every table, distinct tenantId values, and snapshot each.
    var tables = _resolveTables();
    var seen = Object.create(null);
    for (var i = 0; i < tables.length; i++) {
      var ids = db.from(tables[i])
        .select([tenantField])
        .all();
      for (var j = 0; j < ids.length; j++) {
        var v = ids[j] && ids[j][tenantField];
        if (typeof v === "string" && v.length > 0) seen[v] = true;
      }
    }
    var out = [];
    var tenantIds = Object.keys(seen);
    for (var t = 0; t < tenantIds.length; t++) {
      out.push(await snapshot(tenantIds[t]));
    }
    return out;
  }

  function _invalidate(tenantId) {
    if (tenantId === undefined) cache.clear();
    else cache.delete(tenantId);
  }

  return {
    assert:     assert,
    snapshot:   snapshot,
    list:       list,
    invalidate: _invalidate,
  };
}

// ---- Per-tenant query budget (observe() — sliding window) ----

/**
 * @primitive b.tenantQuota.budget
 * @signature b.tenantQuota.budget(opts)
 * @since     0.7.0
 * @compliance soc2
 * @related   b.tenantQuota.create, b.tenantQuota.instrumentQuery
 *
 * Build a per-tenant query-budget enforcer. Returns an object exposing
 * `observe(tenantId, info)` (throws `TenantQuotaError` on breach),
 * `snapshot(tenantId)` (returns the current window's counters), and
 * `reset(tenantId?)` (drop counters). Sliding-window: every breach
 * past the configured QPS or rows-read total emits
 * `tenant.budget.exceeded` and refuses the call.
 *
 * @opts
 *   {
 *     db:                      object,    // required, b.db namespace
 *     tenantField:             string,    // required
 *     perTenantQpsCap?:        number,    // default: 100 calls/sec
 *     perTenantTotalRowsRead?: number,    // default: 50_000 rows per window
 *     window?:                 number,    // default: 60_000 ms (C.TIME.minutes(1))
 *     audit?:                  boolean,   // default: true
 *   }
 *
 * @example
 *   var budget = b.tenantQuota.budget({
 *     db:                     b.db,
 *     tenantField:            "tenantId",
 *     perTenantQpsCap:        100,
 *     perTenantTotalRowsRead: 50000,
 *     window:                 b.constants.TIME.minutes(1),
 *   });
 *   var snap = budget.observe("tenant-acme", { rowsRead: 12 });
 *   // → { calls: 1, rowsRead: 12, windowMs: 60000 }
 */
function budget(opts) {
  validateOpts.requireObject(opts, "tenantQuota.budget", TenantQuotaError);
  validateOpts(opts, [
    "db", "tenantField", "perTenantQpsCap", "perTenantTotalRowsRead",
    "window", "audit",
  ], "tenantQuota.budget");

  validateOpts.requireNonEmptyString(opts.tenantField,
    "tenantQuota.budget: tenantField", TenantQuotaError, "tenant-quota/bad-field");

  var qpsCap = (opts.perTenantQpsCap == null) ? DEFAULT_QPS_CAP : opts.perTenantQpsCap;
  if (typeof qpsCap !== "number" || !isFinite(qpsCap) || qpsCap <= 0) {
    throw new TenantQuotaError("tenant-quota/bad-qps",
      "tenantQuota.budget: perTenantQpsCap must be a positive finite number");
  }
  var rowsCap = (opts.perTenantTotalRowsRead == null) ? DEFAULT_ROWS_READ : opts.perTenantTotalRowsRead;
  if (typeof rowsCap !== "number" || !isFinite(rowsCap) || rowsCap <= 0) {
    throw new TenantQuotaError("tenant-quota/bad-rows",
      "tenantQuota.budget: perTenantTotalRowsRead must be a positive finite number");
  }
  var windowMs = (opts.window == null) ? DEFAULT_WINDOW_MS : opts.window;
  if (typeof windowMs !== "number" || !isFinite(windowMs) || windowMs <= 0) {
    throw new TenantQuotaError("tenant-quota/bad-window",
      "tenantQuota.budget: window must be a positive finite number");
  }
  var auditOn = opts.audit !== false;

  // TRUE sliding window (RFC-ish rolling counter, as advertised) — the prior
  // first-call-pinned fixed window admitted ~2x the cap in a boundary burst.
  // The window is split into BINS sub-bins; each observe lands in the current
  // bin and the cap is enforced against the trailing-window SUM, so a burst
  // straddling the reset can't double the rate. Mirrors network-byte-quota's
  // _slideAndSum ring (here with two counters + a configurable bin width).
  var BINS = 12;
  var binMs = Math.max(1, Math.floor(windowMs / BINS));

  // tenantId → { calls: number[BINS], rows: number[BINS], startBin }
  var counters = new Map();

  // Advance the ring so its BINS bins cover the trailing [nowBin-BINS+1 .. nowBin],
  // zeroing bins that scrolled out of the window. Returns the tenant's ring.
  function _slide(tenantId, now) {
    var nowBin = Math.floor(now / binMs);
    // A freshly-created ring is anchored at the current bin, so the advance
    // below evaluates to 0 (no-op) on the create path — get-or-insert and the
    // slide stay one code path.
    var c = boundedMap.getOrInsert(counters, tenantId, function () {
      return { calls: new Array(BINS).fill(0), rows: new Array(BINS).fill(0), startBin: nowBin - (BINS - 1) };
    });
    var advance = nowBin - (c.startBin + (BINS - 1));
    if (advance > 0) {
      if (advance >= BINS) {
        c.calls.fill(0); c.rows.fill(0);
      } else {
        for (var i = 0; i < BINS - advance; i++) { c.calls[i] = c.calls[i + advance]; c.rows[i] = c.rows[i + advance]; }
        for (var k = BINS - advance; k < BINS; k++) { c.calls[k] = 0; c.rows[k] = 0; }
      }
      c.startBin = nowBin - (BINS - 1);
    }
    return c;
  }

  function _sum(c) {
    var calls = 0, rows = 0;
    for (var i = 0; i < BINS; i++) { calls += c.calls[i]; rows += c.rows[i]; }
    return { calls: calls, rowsRead: rows };
  }

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  function _emitMetric(name, n) {
    try { observability().safeEvent(name, n || 1, {}); }
    catch (_e) { /* drop-silent */ }
  }

  function observe(tenantId, info) {
    validateOpts.requireNonEmptyString(tenantId,
      "tenantQuota.budget.observe: tenantId", TenantQuotaError, "tenant-quota/bad-tenant");
    info = info || {};
    var rowsRead = (typeof info.rowsRead === "number" && info.rowsRead >= 0) ? info.rowsRead : 0;
    // info.now lets a caller / test supply a deterministic clock (idiomatic —
    // mirrors auth verifiers' opts.now); defaults to wall-clock.
    var now = (typeof info.now === "number") ? info.now : Date.now();
    var c = _slide(tenantId, now);
    c.calls[BINS - 1] += 1;
    c.rows[BINS - 1] += rowsRead;
    var tot = _sum(c);
    var maxCalls = Math.max(1, Math.floor(qpsCap * (windowMs / C.TIME.seconds(1))));
    if (tot.calls > maxCalls || tot.rowsRead > rowsCap) {
      _emitAudit("tenant.budget.exceeded", "denied", {
        tenantId: tenantId,
        calls:    tot.calls,
        rowsRead: tot.rowsRead,
        qpsCap:   qpsCap,
        rowsCap:  rowsCap,
        windowMs: windowMs,
      });
      _emitMetric("tenant.budget.exceeded", 1);
      throw new TenantQuotaError("tenant-quota/budget-exceeded",
        "tenantQuota.budget: tenant '" + tenantId + "' exceeded budget " +
        "(calls=" + tot.calls + "/" + maxCalls + ", rowsRead=" + tot.rowsRead +
        "/" + rowsCap + ", windowMs=" + windowMs + ")");
    }
    return { calls: tot.calls, rowsRead: tot.rowsRead, windowMs: windowMs };
  }

  function snapshot(tenantId) {
    if (!counters.has(tenantId)) {
      return { tenantId: tenantId, calls: 0, rowsRead: 0, windowMs: windowMs };
    }
    var c = _slide(tenantId, Date.now());
    var tot = _sum(c);
    return { tenantId: tenantId, calls: tot.calls, rowsRead: tot.rowsRead, windowMs: windowMs };
  }

  function reset(tenantId) {
    if (tenantId === undefined) counters.clear();
    else counters.delete(tenantId);
  }

  return {
    observe:  observe,
    snapshot: snapshot,
    reset:    reset,
  };
}

// ---- Tenant-isolation breach detection (instrumentQuery) ----
//
// instrumentQuery wraps a result set + the operator-claimed tenantId
// and emits db.tenant.crossover when any row's tenantField value
// disagrees with the claim. Used by the framework's _readQuery /
// query primitives at the seam where a query result lands.

/**
 * @primitive b.tenantQuota.instrumentQuery
 * @signature b.tenantQuota.instrumentQuery(opts)
 * @since     0.7.0
 * @compliance soc2, gdpr
 * @related   b.tenantQuota.create, b.tenantQuota.budget
 *
 * Walk a result set and detect rows whose `tenantField` value
 * disagrees with the operator-claimed `tenantId` — a multi-tenant
 * isolation breach. Returns `{ ok, crossover }` where `crossover` is
 * the list of offending row indexes + their actual tenantId values.
 * Audit emission `db.tenant.crossover` fires with a five-row sample
 * when any breach is detected so the framework's chain-signed audit
 * carries the forensic trail without dumping the whole result set.
 *
 * @opts
 *   {
 *     rows:        object[],   // required, the query result rows
 *     tenantField: string,     // required, e.g. "tenantId"
 *     tenantId:    string,     // required, the operator-claimed tenant
 *     table?:      string,     // optional, recorded in the audit metadata
 *     audit?:      boolean,    // default: true
 *   }
 *
 * @example
 *   var rows = [
 *     { _id: 1, tenantId: "tenant-acme", name: "ok" },
 *     { _id: 2, tenantId: "tenant-other", name: "leak" },
 *   ];
 *   var result = b.tenantQuota.instrumentQuery({
 *     rows:        rows,
 *     tenantField: "tenantId",
 *     tenantId:    "tenant-acme",
 *     table:       "orders",
 *   });
 *   // → { ok: false, crossover: [{ index: 1, actualTenantId: "tenant-other" }] }
 */
function instrumentQuery(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TenantQuotaError("tenant-quota/bad-instr",
      "tenantQuota.instrumentQuery: opts object is required");
  }
  validateOpts(opts, [
    "rows", "tenantField", "tenantId", "audit", "table",
  ], "tenantQuota.instrumentQuery");

  if (!Array.isArray(opts.rows)) {
    throw new TenantQuotaError("tenant-quota/bad-rows",
      "tenantQuota.instrumentQuery: rows must be an array");
  }
  validateOpts.requireNonEmptyString(opts.tenantField,
    "tenantQuota.instrumentQuery: tenantField", TenantQuotaError, "tenant-quota/bad-field");
  validateOpts.requireNonEmptyString(opts.tenantId,
    "tenantQuota.instrumentQuery: tenantId", TenantQuotaError, "tenant-quota/bad-tenant");
  var auditOn = opts.audit !== false;

  var crossover = [];
  for (var i = 0; i < opts.rows.length; i++) {
    var row = opts.rows[i];
    if (!row || typeof row !== "object") continue;
    var actual = row[opts.tenantField];
    if (actual !== undefined && actual !== null && actual !== opts.tenantId) {
      crossover.push({ index: i, actualTenantId: String(actual) });
    }
  }
  if (crossover.length > 0) {
    if (auditOn) {
      try {
        audit().safeEmit({
          action:   "db.tenant.crossover",
          outcome:  "failure",
          metadata: {
            tenantField:   opts.tenantField,
            claimedTenant: opts.tenantId,
            table:         opts.table || null,
            rowCount:      crossover.length,
            sample:        crossover.slice(0, 5),                                  // sample size, not bytes
          },
        });
      } catch (_e) { /* audit best-effort */ }
    }
    try { observability().safeEvent("db.tenant.crossover", crossover.length, {}); }
    catch (_e) { /* drop-silent */ }
  }
  return {
    ok: crossover.length === 0,
    crossover: crossover,
  };
}

module.exports = {
  create:           create,
  budget:           budget,
  instrumentQuery:  instrumentQuery,
  TenantQuotaError: TenantQuotaError,
};
