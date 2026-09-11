// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var safeAsync = require("../safe-async");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var HTTP_STATUS = requestHelpers.HTTP_STATUS;

var HealthError = defineClass("HealthError", { alwaysPermanent: true });

var TIERS = Object.freeze(["liveness", "readiness", "startup"]);
var TIER_SET = new Set(TIERS);

var DEFAULT_TIMEOUT_MS = C.TIME.seconds(5);

/**
 * @primitive b.middleware.health
 * @signature b.middleware.health(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.requestId
 *
 * Liveness / readiness / startup probe primitive. Constructed via
 * `b.middleware.health(opts)` returning a controller exposing
 * `registerCheck`, `markShuttingDown`, and `middleware()`; the
 * `middleware()` value has the `(req, res, next)` shape shown above. Three tiers, each
 * its own URL path: `/healthz` (process alive — orchestrator kill
 * decision), `/readyz` (can serve traffic — LB route decision),
 * `/startupz` (slow-init complete — Kubernetes startupProbe).
 * `markShuttingDown()` flips ONLY readiness to 503 so LBs drain
 * while `/healthz` keeps responding 200 through clean exit.
 * Detail level defaults to "minimal" (`{ status }` only — no
 * internal-state leakage); `detailLevel: "detailed"` and
 * `detailPredicate(req)` gate the full per-check breakdown to
 * authed endpoints. Per-check `Promise.all` + `withTimeout` so one
 * stuck check can't block the others. Returns a controller exposing
 * `registerCheck`, `markShuttingDown`, and `middleware()`.
 *
 * @opts
 *   {
 *     livenessPath:     string,    // default "/healthz"
 *     readinessPath:    string,    // default "/readyz"
 *     startupPath:      string,    // default "/startupz"
 *     detailLevel:      "minimal"|"detailed",   // default "minimal"
 *     detailPredicate:  function(req): boolean,
 *     defaultTimeoutMs: number,    // default 5000
 *     cacheMs:          number,    // default 0
 *     includeMeta:      boolean,
 *     version:          string,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var hc = b.middleware.health({
 *     livenessPath:    "/healthz",
 *     readinessPath:   "/readyz",
 *     defaultTimeoutMs: 5000,
 *   });
 *   hc.registerCheck("db", async function () { return { ok: true }; }, { tier: "readiness" });
 *   app.use(hc.middleware());
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "livenessPath", "readinessPath", "startupPath", "detailLevel",
    "detailPredicate", "defaultTimeoutMs", "cacheMs", "includeMeta", "version",
  ], "middleware.health");
  var livenessPath  = opts.livenessPath  || "/healthz";
  var readinessPath = opts.readinessPath || "/readyz";
  var startupPath   = opts.startupPath   || "/startupz";
  var detailLevel   = opts.detailLevel   || "minimal";
  if (detailLevel !== "minimal" && detailLevel !== "detailed") {
    throw new HealthError("health/bad-detail-level",
      "detailLevel must be 'minimal' or 'detailed'");
  }
  var detailPredicate  = typeof opts.detailPredicate === "function" ? opts.detailPredicate : null;
  var defaultTimeoutMs;
  if (opts.defaultTimeoutMs === undefined) {
    defaultTimeoutMs = DEFAULT_TIMEOUT_MS;
  } else if (numericBounds.isPositiveFiniteInt(opts.defaultTimeoutMs)) {
    defaultTimeoutMs = opts.defaultTimeoutMs;
  } else {
    throw new HealthError("health/bad-opt",
      "defaultTimeoutMs must be a positive finite integer; got " +
        numericBounds.shape(opts.defaultTimeoutMs));
  }
  var cacheMs;
  if (opts.cacheMs === undefined) {
    cacheMs = 0;
  } else if (numericBounds.isNonNegativeFiniteInt(opts.cacheMs)) {
    cacheMs = opts.cacheMs;
  } else {
    throw new HealthError("health/bad-opt",
      "cacheMs must be a non-negative finite integer; got " +
        numericBounds.shape(opts.cacheMs));
  }
  var includeMeta = opts.includeMeta !== false;
  var version = opts.version || null;

  var checks = [];
  var shuttingDown = false;
  var startedAt = Date.now();
  var cache = {};

  function registerCheck(name, fn, copts) {
    if (typeof name !== "string" || name.length === 0) {
      throw new HealthError("health/bad-name",
        "registerCheck: name must be a non-empty string");
    }
    if (typeof fn !== "function") {
      throw new HealthError("health/bad-fn",
        "registerCheck: fn must be a function");
    }
    copts = copts || {};
    var tier = copts.tier || "readiness";
    var tiers = Array.isArray(tier) ? tier : [tier];
    for (var i = 0; i < tiers.length; i++) {
      if (!TIER_SET.has(tiers[i])) {
        throw new HealthError("health/bad-tier",
          "registerCheck: tier '" + tiers[i] + "' must be one of " + TIERS.join(", "));
      }
    }
    for (var j = 0; j < checks.length; j++) {
      if (checks[j].name === name) {
        for (var k = 0; k < tiers.length; k++) {
          if (checks[j].tiers.has(tiers[k])) {
            throw new HealthError("health/duplicate-check",
              "registerCheck: check '" + name + "' already registered for tier '" + tiers[k] + "'");
          }
        }
      }
    }
    var timeoutMs;
    if (copts.timeoutMs === undefined) {
      timeoutMs = defaultTimeoutMs;
    } else if (numericBounds.isPositiveFiniteInt(copts.timeoutMs)) {
      timeoutMs = copts.timeoutMs;
    } else {
      throw new HealthError("health/bad-opt",
        "registerCheck: timeoutMs must be a positive finite integer; got " +
          numericBounds.shape(copts.timeoutMs));
    }
    checks.push({
      name:      name,
      fn:        fn,
      tiers:     new Set(tiers),
      timeoutMs: timeoutMs,
      critical:  copts.critical !== false,
    });
  }

  function _bypassCacheFor(tier) {
    return tier === "readiness" && shuttingDown;
  }

  async function runChecks(tier) {
    if (!TIER_SET.has(tier)) {
      throw new HealthError("health/bad-tier", "runChecks: tier must be one of " + TIERS.join(", "));
    }
    if (cacheMs > 0 && !_bypassCacheFor(tier)) {
      var cached = cache[tier];
      if (cached && cached.expiresAt > Date.now()) return cached.result;
    }
    var tierChecks = checks.filter(function (c) { return c.tiers.has(tier); });
    var promises = tierChecks.map(function (c) {
      var start = Date.now();
      return safeAsync.withTimeout(
          Promise.resolve().then(function () { return c.fn(); }),
          c.timeoutMs,
          { name: "health-check:" + c.name }
        )
        .then(function (raw) {
          var ok, detail;
          if (raw === true) { ok = true; detail = null; }
          else if (raw === false) { ok = false; detail = null; }
          else if (raw && typeof raw === "object") {
            ok = !!raw.ok;
            detail = raw;
          } else {
            ok = !!raw;
            detail = null;
          }
          return {
            name:     c.name,
            ok:       ok,
            detail:   detail,
            ms:       Date.now() - start,
            critical: c.critical,
          };
        })
        .catch(function (err) {
          return {
            name:     c.name,
            ok:       false,
            error:    (err && err.message) || String(err),
            ms:       Date.now() - start,
            critical: c.critical,
          };
        });
    });

    var checked = await Promise.all(promises);
    var results = {};
    var anyFailed = false;
    var anyCriticalFailed = false;
    for (var i = 0; i < checked.length; i++) {
      var r = checked[i];
      var entry = { ok: r.ok, ms: r.ms };
      if (r.detail) {
        validateOpts.assignOwnEnumerable(entry, r.detail, ["ok"]);
      }
      if (r.error) entry.error = r.error;
      if (!r.critical) entry.critical = false;
      results[r.name] = entry;
      if (!r.ok) {
        anyFailed = true;
        if (r.critical) anyCriticalFailed = true;
      }
    }

    var status;
    if (tier === "readiness" && shuttingDown) status = "shutting-down";
    else if (anyCriticalFailed) status = "fail";
    else if (anyFailed) status = "degraded";
    else status = "ok";

    var result = { status: status, checks: results, tier: tier, shuttingDown: shuttingDown };
    if (cacheMs > 0 && !_bypassCacheFor(tier)) {
      cache[tier] = { result: result, expiresAt: Date.now() + cacheMs };
    }
    return result;
  }

  function _writeResponse(res, result, includeDetail) {
    var status = (result.status === "ok" || result.status === "degraded")
      ? HTTP_STATUS.OK : HTTP_STATUS.SERVICE_UNAVAILABLE;
    var payload;
    if (includeDetail) {
      payload = { status: result.status, checks: result.checks };
      if (includeMeta) {
        payload.uptime = Date.now() - startedAt;
        if (version) payload.version = version;
      }
    } else {
      payload = { status: result.status };
    }
    var body = JSON.stringify(payload);
    res.writeHead(status, {
      "Content-Type":   "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
      "Cache-Control":  "no-store",
    });
    res.end(body);
  }

  function _wantDetail(req) {
    if (detailLevel === "detailed") return true;
    if (!detailPredicate) return false;
    try { return !!detailPredicate(req); }
    catch (_e) { return false;  }
  }

  function middleware() {
    return async function health(req, res, next) {
      if (req.method !== "GET" && req.method !== "HEAD") return next();
      var url = req.url || "";
      var path = url.split("?")[0];
      var tier;
      if (path === livenessPath)       tier = "liveness";
      else if (path === readinessPath) tier = "readiness";
      else if (path === startupPath)   tier = "startup";
      else return next();

      try {
        var result = await runChecks(tier);
        if (req.method === "HEAD") {
          var status = (result.status === "ok" || result.status === "degraded")
            ? HTTP_STATUS.OK : HTTP_STATUS.SERVICE_UNAVAILABLE;
          res.writeHead(status, { "Cache-Control": "no-store" });
          res.end();
          return;
        }
        _writeResponse(res, result, _wantDetail(req));
      } catch {
        var body = JSON.stringify({ status: "fail", error: "health-check-internal" });
        res.writeHead(HTTP_STATUS.SERVICE_UNAVAILABLE, {
          "Content-Type":   "application/json; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          "Cache-Control":  "no-store",
        });
        res.end(body);
      }
    };
  }

  function markShuttingDown() { shuttingDown = true; }
  function isShuttingDown()   { return shuttingDown; }
  function uptime()           { return Date.now() - startedAt; }

  function _resetForTest() {
    checks = [];
    shuttingDown = false;
    startedAt = Date.now();
    cache = {};
  }

  return {
    registerCheck:    registerCheck,
    middleware:       middleware,
    runChecks:        runChecks,
    markShuttingDown: markShuttingDown,
    isShuttingDown:   isShuttingDown,
    uptime:           uptime,
    _resetForTest:    _resetForTest,
  };
}

module.exports = {
  create:      create,
  HealthError: HealthError,
  TIERS:       TIERS,
};
