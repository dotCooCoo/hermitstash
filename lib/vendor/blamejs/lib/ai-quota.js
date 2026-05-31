"use strict";
/**
 * @module b.ai.quota
 * @nav    Compliance
 * @title  AI usage quota
 *
 * @intro
 *   Per-tenant, per-model usage budgets for AI inference endpoints.
 *   OWASP LLM Top 10 2025 ranks <strong>LLM10: Unbounded
 *   Consumption</strong> — the class that includes "denial of
 *   wallet" (DoW), where an attacker drives a high volume of
 *   pay-per-use inferences until the bill itself becomes the
 *   attack — as a top application risk. A single misbehaving (or
 *   compromised) tenant can saturate context windows, exhaust GPU
 *   minutes, or run up an unbounded cloud-inference bill long
 *   before a human notices.
 *
 *   This primitive enforces a hard ceiling per
 *   <code>(tenant, model, dimension, period)</code>:
 *
 *   - <code>dimension</code> — what is being metered:
 *     <code>"tokens"</code> (context + completion tokens),
 *     <code>"requests"</code> (inference calls),
 *     <code>"cost-usd"</code> (provider spend), or
 *     <code>"compute-hours"</code> (GPU / accelerator time).
 *   - <code>period</code> — the budget window, calendar-aligned in
 *     UTC: <code>"second"</code>, <code>"minute"</code>,
 *     <code>"hour"</code>, <code>"day"</code>, <code>"week"</code>
 *     (Monday-aligned), or <code>"month"</code> (1st-of-month).
 *   - <code>enforcement</code> — <code>"hard"</code> (default,
 *     refuse the over-budget call), <code>"soft"</code> (admit but
 *     report <code>allowed:false</code> so the caller decides), or
 *     <code>"warn"</code> (admit + audit only).
 *
 *   <code>consume(tenant, model, amount)</code> is the single
 *   atomic check-and-charge entry point: in <code>"hard"</code>
 *   mode it reserves <code>amount</code> only if it fits under the
 *   limit, otherwise it refuses without charging. There is no
 *   separate "check then add" two-call shape to race against — the
 *   reservation and the limit test happen in one operation.
 *
 *   <strong>Single-process by default; cross-node via store.</strong>
 *   The in-memory counter is per-process. Multi-node deployments
 *   that need an aggregate ceiling across the cluster supply an
 *   <code>opts.store</code> adapter whose <code>reserve</code> (an
 *   atomic conditional test-and-charge — "add only if current +
 *   amount fits under the limit") and <code>add</code> are atomic on
 *   the shared backend: a Redis Lua script, or a SQL
 *   <code>UPDATE ... SET used = used + :amt WHERE used + :amt &lt;= :limit
 *   RETURNING used</code>. The conditional reserve is what keeps
 *   <code>hard</code> enforcement correct under cross-node
 *   contention — there is no charge-then-refund window for a
 *   concurrent call to observe. The framework records the active
 *   cluster node id on every breach event so a denial-of-wallet
 *   spike is attributable.
 *
 *   Limit resolution is most-specific-first:
 *   <code>perTenantModel[t|m]</code> →
 *   <code>perTenant[t]</code> → <code>perModel[m]</code> →
 *   <code>limit</code> (the default). Tenant and model identifiers
 *   are percent-encoded into the counter key so a hostile tenant
 *   name cannot collide with another tenant's budget.
 *
 *   Audit emissions (drop-silent via <code>b.audit.safeEmit</code>):
 *     - <code>ai/quota-applied</code>  — a consume succeeded.
 *     - <code>ai/quota-exceeded</code> — a consume hit the ceiling
 *       (refused under <code>"hard"</code>; reported under
 *       <code>"soft"</code> / <code>"warn"</code>).
 *
 *   NIST AI RMF (AI 100-1) MANAGE 2.x ("AI system performance and
 *   trustworthiness are monitored") and EU AI Act Art. 15
 *   (accuracy, robustness and cybersecurity of high-risk systems —
 *   resource-exhaustion resilience) map onto this primitive;
 *   operators wire its emissions into the same audit chain auditors
 *   read.
 *
 * @card
 *   Per-tenant, per-model AI usage budgets (tokens / requests /
 *   cost-usd / compute-hours) with atomic consume-and-check.
 *   Defends OWASP LLM10 unbounded consumption / denial-of-wallet.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var AiQuotaError = defineClass("AiQuotaError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });
var cluster = lazyRequire(function () { return require("./cluster"); });

var DIMENSIONS   = ["tokens", "requests", "cost-usd", "compute-hours"];
var PERIODS      = ["second", "minute", "hour", "day", "week", "month"];
var ENFORCEMENTS = ["hard", "soft", "warn"];

// ---- Calendar-aligned period windows (UTC) ----
//
// Fixed-duration periods (second / minute) align to the epoch, which
// is itself UTC midnight, so a modulo is exact. Hour / day / week /
// month align to human UTC boundaries via Date.UTC truncation —
// week starts Monday, month starts on the 1st — so "100k tokens per
// day" resets at 00:00 UTC, not at a rolling 24h offset from first
// use.

function _windowStartFor(period, now) {
  var d = new Date(now);
  switch (period) {
    case "second": return now - (now % C.TIME.seconds(1));
    case "minute": return now - (now % C.TIME.minutes(1));
    case "hour":
      return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours());
    case "day":
      return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
    case "week": {
      var dayMid = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
      var dow = new Date(dayMid).getUTCDay();            // 0=Sun .. 6=Sat
      var sinceMonday = (dow + 6) % 7;                   // 0=Mon .. 6=Sun
      return dayMid - sinceMonday * C.TIME.days(1);
    }
    case "month":
      return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
    default:
      // unreachable — period validated at create()
      return now;
  }
}

function _resetsAtFor(period, windowStart) {
  var d = new Date(windowStart);
  switch (period) {
    case "second": return windowStart + C.TIME.seconds(1);
    case "minute": return windowStart + C.TIME.minutes(1);
    case "hour":   return windowStart + C.TIME.hours(1);
    case "day":    return windowStart + C.TIME.days(1);
    case "week":   return windowStart + C.TIME.weeks(1);
    case "month":  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
    default:       return windowStart;
  }
}

// ---- Default in-memory atomic counter store ----
//
// Single-threaded JS makes each operation below one indivisible step,
// so a concurrent caller never observes a partial update. Entries
// self-expire at the window boundary; reads past expiry return 0 (a
// fresh window). _keysWithPrefix backs the reset(tenant) enumeration
// the default store can satisfy without an external scan.

function _memoryStore() {
  var m = new Map();                                     // key -> { value, expiresAt }
  function _slot(key, windowMs) {
    var now = Date.now();
    var e = m.get(key);
    if (!e || e.expiresAt <= now) {
      e = { value: 0, expiresAt: now + windowMs };
      m.set(key, e);
    }
    return e;
  }
  return {
    // Atomic conditional reserve — tests current + amount <= limit and
    // charges only if it fits, as one indivisible operation. Returns
    // { allowed, used }; on refusal the amount is NOT charged, so a
    // concurrent over-budget call cannot transiently inflate the
    // counter and falsely deny a smaller call that should fit.
    reserve: function (key, amount, limit, windowMs) {
      var e = _slot(key, windowMs);
      if (e.value + amount > limit) return { allowed: false, used: e.value };
      e.value += amount;
      return { allowed: true, used: e.value };
    },
    // Unconditional add — for soft / warn modes, which always charge.
    add: function (key, amount, windowMs) {
      var e = _slot(key, windowMs);
      e.value += amount;
      return e.value;
    },
    get: function (key) {
      var e = m.get(key);
      if (!e || e.expiresAt <= Date.now()) return 0;
      return e.value;
    },
    reset: function (key) {
      m.delete(key);
    },
    _keysWithPrefix: function (prefix) {
      var out = [];
      m.forEach(function (_e, k) { if (k.indexOf(prefix) === 0) out.push(k); });
      return out;
    },
    _clear: function () { m.clear(); },
  };
}

/**
 * @primitive b.ai.quota.create
 * @signature b.ai.quota.create(opts)
 * @since     0.12.27
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.tenantQuota.budget, b.ai.disclosure.chatbot
 *
 * Build a per-tenant AI usage-budget enforcer scoped to one
 * <code>dimension</code> and one <code>period</code>. Returns an
 * object exposing <code>consume(tenant, model, amount, opts?)</code>
 * (the atomic check-and-charge), <code>check(tenant, model)</code>
 * (read-only snapshot), <code>snapshot(tenant, model)</code> (alias
 * of <code>check</code>), and <code>reset(tenant?, model?)</code>
 * (drop the current window's counters).
 *
 * Spin up one enforcer per dimension you meter — e.g. a
 * <code>"cost-usd"</code> monthly budget and a
 * <code>"tokens"</code> per-minute burst cap can coexist as two
 * <code>create()</code> calls sharing the same store.
 *
 * @opts
 *   {
 *     dimension:        string,    // required, one of:
 *                                  //   "tokens" | "requests" |
 *                                  //   "cost-usd" | "compute-hours"
 *     period:           string,    // required, one of:
 *                                  //   "second" | "minute" | "hour" |
 *                                  //   "day" | "week" | "month"
 *     limit:            number,    // required, default ceiling (> 0)
 *     perTenant?:       { [tenantId: string]: number },
 *     perModel?:        { [model: string]: number },
 *     perTenantModel?:  { [tenantPipeModel: string]: number },
 *                                  // key is `tenantId + "|" + model`
 *     enforcement?:     string,    // "hard" (default) | "soft" | "warn"
 *     store?:           object,    // { reserve, add, get, reset };
 *                                  // default in-memory (per-process)
 *     audit?:           boolean,   // default: true
 *   }
 *
 * @example
 *   var budget = b.ai.quota.create({
 *     dimension:  "cost-usd",
 *     period:     "month",
 *     limit:      500,
 *     perTenant:  { "tenant-vip": 5000 },
 *     enforcement: "hard",
 *   });
 *   var r = await budget.consume("tenant-acme", "opus-4", 0.42);
 *   // → { tenantId: "tenant-acme", model: "opus-4",
 *   //     dimension: "cost-usd", period: "month", used: 0.42,
 *   //     limit: 500, remaining: 499.58, allowed: true,
 *   //     exceeded: false, windowStart: ..., resetsAt: ... }
 */
function create(opts) {
  validateOpts.requireObject(opts, "ai.quota.create", AiQuotaError);
  validateOpts(opts, [
    "dimension", "period", "limit", "perTenant", "perModel",
    "perTenantModel", "enforcement", "store", "audit",
  ], "ai.quota.create");

  var dimension = opts.dimension;
  if (DIMENSIONS.indexOf(dimension) === -1) {
    throw new AiQuotaError("ai-quota/bad-dimension",
      "ai.quota.create: dimension must be one of " + DIMENSIONS.join(" / ") +
      " (got " + JSON.stringify(dimension) + ")");
  }

  var period = opts.period;
  if (PERIODS.indexOf(period) === -1) {
    throw new AiQuotaError("ai-quota/bad-period",
      "ai.quota.create: period must be one of " + PERIODS.join(" / ") +
      " (got " + JSON.stringify(period) + ")");
  }

  if (typeof opts.limit !== "number" || !isFinite(opts.limit) || opts.limit <= 0) {
    throw new AiQuotaError("ai-quota/bad-limit",
      "ai.quota.create: limit must be a positive finite number");
  }
  var defaultLimit = opts.limit;

  var perTenant      = _validateLimitMap(opts.perTenant, "perTenant");
  var perModel       = _validateLimitMap(opts.perModel, "perModel");
  var perTenantModel = _validateLimitMap(opts.perTenantModel, "perTenantModel");

  var enforcement = (opts.enforcement == null) ? "hard" : opts.enforcement;
  if (ENFORCEMENTS.indexOf(enforcement) === -1) {
    throw new AiQuotaError("ai-quota/bad-enforcement",
      "ai.quota.create: enforcement must be one of " + ENFORCEMENTS.join(" / ") +
      " (got " + JSON.stringify(enforcement) + ")");
  }

  var store = opts.store || _memoryStore();
  _validateStore(store);
  var storeIsDefault = !opts.store;

  var auditOn = opts.audit !== false;

  function _limitFor(tenantId, model) {
    var tmKey = tenantId + "|" + model;
    if (Object.prototype.hasOwnProperty.call(perTenantModel, tmKey)) return perTenantModel[tmKey];
    if (Object.prototype.hasOwnProperty.call(perTenant, tenantId))   return perTenant[tenantId];
    if (Object.prototype.hasOwnProperty.call(perModel, model))       return perModel[model];
    return defaultLimit;
  }

  // Counter key — tenant + model percent-encoded so a value
  // containing the ":" separator cannot collide with another
  // (tenant, model) pair's budget.
  function _keyFor(tenantId, model, windowStart) {
    return "aiq:" + dimension + ":" + period + ":" +
      encodeURIComponent(tenantId) + ":" + encodeURIComponent(model) + ":" + windowStart;
  }
  function _keyPrefixForTenant(tenantId) {
    return "aiq:" + dimension + ":" + period + ":" + encodeURIComponent(tenantId) + ":";
  }

  function _nodeId() {
    try {
      if (cluster().isClusterMode()) return cluster().currentNodeId();
    } catch (_e) { /* cluster optional */ }
    return null;
  }

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} });
    } catch (_e) { /* audit best-effort — drop-silent */ }
  }

  function _emitMetric(name, n) {
    try { observability().safeEvent(name, n || 1, {}); }
    catch (_e) { /* drop-silent */ }
  }

  // `mode` is the enforcement actually applied to this call (the
  // per-call override when present, else the instance default) so the
  // returned `enforcement` reflects how the call was evaluated.
  function _result(tenantId, model, used, limit, windowStart, resetsAt, mode, allowed, exceeded) {
    var remaining = limit - used;
    return {
      tenantId:    tenantId,
      model:       model,
      dimension:   dimension,
      period:      period,
      used:        used,
      limit:       limit,
      remaining:   remaining < 0 ? 0 : remaining,
      allowed:     allowed,
      exceeded:    exceeded,
      enforcement: mode,
      windowStart: windowStart,
      resetsAt:    resetsAt,
    };
  }

  function consume(tenantId, model, amount, consumeOpts) {
    validateOpts.requireNonEmptyString(tenantId,
      "ai.quota.consume: tenantId", AiQuotaError, "ai-quota/bad-tenant");
    validateOpts.requireNonEmptyString(model,
      "ai.quota.consume: model", AiQuotaError, "ai-quota/bad-model");
    if (typeof amount !== "number" || !isFinite(amount) || amount < 0) {
      throw new AiQuotaError("ai-quota/bad-amount",
        "ai.quota.consume: amount must be a non-negative finite number");
    }
    consumeOpts = consumeOpts || {};
    // Per-call enforcement override lets a single endpoint dial a
    // softer mode for a trusted internal caller without a second
    // enforcer; still validated against the allowlist.
    var mode = (consumeOpts.enforcement == null) ? enforcement : consumeOpts.enforcement;
    if (ENFORCEMENTS.indexOf(mode) === -1) {
      throw new AiQuotaError("ai-quota/bad-enforcement",
        "ai.quota.consume: enforcement override must be one of " + ENFORCEMENTS.join(" / "));
    }

    var now = Date.now();
    var windowStart = _windowStartFor(period, now);
    var resetsAt = _resetsAtFor(period, windowStart);
    var windowMs = resetsAt - windowStart;
    var limit = _limitFor(tenantId, model);
    var key = _keyFor(tenantId, model, windowStart);

    if (mode === "hard") {
      // Atomic conditional reserve — the store tests current + amount
      // <= limit and charges only if it fits, as one indivisible
      // operation. Charging first and refunding the overage (a
      // read-then-add or add-then-refund shape) would let a concurrent
      // over-budget call transiently inflate the counter and falsely
      // deny a smaller call that should fit; the conditional reserve
      // never charges on refusal, so there is no transient to race.
      var rv = store.reserve(key, amount, limit, windowMs);
      if (rv.allowed) {
        _emitAudit("ai/quota-applied", "allowed", {
          tenantId: tenantId, model: model, dimension: dimension,
          period: period, amount: amount, used: rv.used, limit: limit,
          nodeId: _nodeId(),
        });
        _emitMetric("ai.quota.applied", 1);
        return _result(tenantId, model, rv.used, limit, windowStart, resetsAt, mode, true, false);
      }
      _emitAudit("ai/quota-exceeded", "denied", {
        tenantId: tenantId, model: model, dimension: dimension,
        period: period, amount: amount, used: rv.used, limit: limit,
        enforcement: mode, nodeId: _nodeId(),
      });
      _emitMetric("ai.quota.exceeded", 1);
      throw new AiQuotaError("ai-quota/exceeded",
        "ai.quota.consume: tenant '" + tenantId + "' model '" + model +
        "' is at " + rv.used + " of " + limit + " " + dimension +
        " this " + period + "; consuming " + amount + " would exceed the budget — call refused");
    }

    // soft / warn always charge — the call proceeds regardless of the
    // ceiling; the mode only changes how the overage is reported.
    var used = store.add(key, amount, windowMs);
    if (used > limit) {
      _emitAudit("ai/quota-exceeded", "allowed", {
        tenantId: tenantId, model: model, dimension: dimension,
        period: period, amount: amount, used: used, limit: limit,
        enforcement: mode, nodeId: _nodeId(),
      });
      _emitMetric("ai.quota.exceeded", 1);
      // soft reports allowed:false so the caller can choose to honor
      // the ceiling; warn reports allowed:true (advisory only).
      return _result(tenantId, model, used, limit, windowStart, resetsAt, mode, mode === "warn", true);
    }
    _emitAudit("ai/quota-applied", "allowed", {
      tenantId: tenantId, model: model, dimension: dimension,
      period: period, amount: amount, used: used, limit: limit,
      nodeId: _nodeId(),
    });
    _emitMetric("ai.quota.applied", 1);
    return _result(tenantId, model, used, limit, windowStart, resetsAt, mode, true, false);
  }

  function check(tenantId, model) {
    validateOpts.requireNonEmptyString(tenantId,
      "ai.quota.check: tenantId", AiQuotaError, "ai-quota/bad-tenant");
    validateOpts.requireNonEmptyString(model,
      "ai.quota.check: model", AiQuotaError, "ai-quota/bad-model");
    var now = Date.now();
    var windowStart = _windowStartFor(period, now);
    var resetsAt = _resetsAtFor(period, windowStart);
    var limit = _limitFor(tenantId, model);
    var used = store.get(_keyFor(tenantId, model, windowStart));
    return _result(tenantId, model, used, limit, windowStart, resetsAt, enforcement, used < limit, used >= limit);
  }

  function reset(tenantId, model) {
    var now = Date.now();
    var windowStart = _windowStartFor(period, now);
    if (tenantId === undefined) {
      // Clear everything. The default store supports a full clear;
      // an external store gets a no-arg reset() if it offers one.
      if (storeIsDefault) { store._clear(); return; }
      if (typeof store.reset === "function") { store.reset(); return; }
      return;
    }
    validateOpts.requireNonEmptyString(tenantId,
      "ai.quota.reset: tenantId", AiQuotaError, "ai-quota/bad-tenant");
    if (model !== undefined) {
      validateOpts.requireNonEmptyString(model,
        "ai.quota.reset: model", AiQuotaError, "ai-quota/bad-model");
      store.reset(_keyFor(tenantId, model, windowStart));
      return;
    }
    // tenant-wide reset needs key enumeration. The default in-memory
    // store can scan its own keys; an external store would need a
    // server-side prefix delete the framework can't portably issue.
    if (storeIsDefault) {
      var prefix = _keyPrefixForTenant(tenantId);
      var keys = store._keysWithPrefix(prefix);
      for (var i = 0; i < keys.length; i++) store.reset(keys[i]);
      return;
    }
    throw new AiQuotaError("ai-quota/reset-unsupported",
      "ai.quota.reset: tenant-wide reset with an external store requires " +
      "an explicit model argument (per-key) or a store-side prefix delete");
  }

  return {
    consume:   consume,
    check:     check,
    snapshot:  check,
    reset:     reset,
    dimension: dimension,
    period:    period,
  };
}

// Per-tenant / per-model / per-tenant-model limit-override maps are
// validated at config time so a typo (negative cap, NaN) surfaces at
// boot, not as a silent fall-through to the default ceiling.
function _validateLimitMap(map, label) {
  if (map == null) return {};
  if (typeof map !== "object" || Array.isArray(map)) {
    throw new AiQuotaError("ai-quota/bad-override",
      "ai.quota.create: " + label + " must be a plain object { key: limit }");
  }
  var keys = Object.keys(map);
  for (var i = 0; i < keys.length; i++) {
    var v = map[keys[i]];
    if (typeof v !== "number" || !isFinite(v) || v <= 0) {
      throw new AiQuotaError("ai-quota/bad-override",
        "ai.quota.create: " + label + "['" + keys[i] +
        "'] must be a positive finite number");
    }
  }
  return map;
}

function _validateStore(store) {
  if (!store || typeof store !== "object" ||
      typeof store.reserve !== "function" ||
      typeof store.add !== "function" ||
      typeof store.get !== "function" ||
      typeof store.reset !== "function") {
    throw new AiQuotaError("ai-quota/bad-store",
      "ai.quota.create: store must expose reserve / add / get / reset functions");
  }
}

module.exports = {
  create:       create,
  DIMENSIONS:   DIMENSIONS,
  PERIODS:      PERIODS,
  ENFORCEMENTS: ENFORCEMENTS,
  AiQuotaError: AiQuotaError,
};
