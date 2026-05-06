"use strict";
/**
 * health — liveness / readiness / startup endpoint primitive.
 *
 * Without this, every operator wires 5–20 lines of boilerplate that
 * gets subtly wrong: /readyz returning 200 before the DB is connected
 * (LB routes traffic into a half-booted process), /healthz blocking
 * on a slow check (orchestrator kills the pod), no graceful-shutdown
 * coordination (LB sends traffic into a draining process), or
 * leaking internal state on a public endpoint.
 *
 * Three probe tiers, each its own URL path, each its own check set:
 *
 *   /healthz   liveness   "process is alive" — defaults to always-200
 *                         unless the operator registers a liveness
 *                         check (e.g. deadlock detector). Orchestrators
 *                         use this to decide whether to KILL the pod.
 *   /readyz    readiness  "process can serve traffic" — every readiness
 *                         check must pass. Load balancers use this to
 *                         decide whether to ROUTE TRAFFIC. Default tier
 *                         for registerCheck.
 *   /startupz  startup    "slow init has finished" — separate from
 *                         readiness so a slow-loading model / migration
 *                         doesn't fail the liveness probe before it
 *                         finishes. Operators register here for the
 *                         first-N-seconds-of-process startup work.
 *
 * Graceful-shutdown integration: markShuttingDown() flips readiness
 * (and only readiness) to 503 immediately. /healthz keeps returning
 * 200 throughout so the orchestrator doesn't kill the pod mid-drain.
 * Standard Kubernetes pattern. `b.app.shutdown()` calls this on the
 * health-check instance it manages; standalone callers can invoke
 * markShuttingDown() directly.
 *
 *   var hc = b.middleware.health.create({
 *     livenessPath:    "/healthz",
 *     readinessPath:   "/readyz",
 *     startupPath:     "/startupz",
 *     defaultTimeoutMs: 5000,
 *     cacheMs:          0,
 *     detailLevel:      "minimal",     // "minimal" | "detailed"
 *     detailPredicate:  function (req) { ... },  // operator decides
 *   });
 *
 *   hc.registerCheck("db", async function () {
 *     return { ok: b.db.isReady(), latencyMs: ... };
 *   }, { tier: "readiness", timeoutMs: 1000, critical: true });
 *
 *   hc.registerCheck("queue", async function () {
 *     return b.queue.isReady();
 *   }, { tier: "readiness", critical: false });
 *
 *   router.use(hc.middleware());
 *
 *   // On SIGTERM:
 *   hc.markShuttingDown();
 *   // → /readyz returns 503 immediately; LB drains the pod;
 *   //   /healthz still 200 so orchestrator waits for clean exit.
 *
 * Check function shape — anything truthy/falsy works, but two patterns
 * are preferred:
 *
 *   () => true | false                    fast path; ok flag only
 *   () => ({ ok: bool, latencyMs?, ... })  detail visible in detailed mode
 *
 *   Promise versions of either also work; per-check timeout (default
 *   `defaultTimeoutMs`) bounds the wait. A timed-out check fails ok=false
 *   without blocking other checks.
 *
 * Status codes:
 *   200   "ok"             every check passed (or no checks registered)
 *   200   "degraded"       a NON-critical check failed; service still
 *                          serving (informational status; operator can
 *                          alert on the body content)
 *   503   "fail"           a CRITICAL check failed; LB should drain
 *   503   "shutting-down"  readiness only; markShuttingDown was called
 *
 * Security:
 *   - Default `detailLevel: "minimal"` returns only `{ status }` to the
 *     public endpoint. Internal state (per-check latency, error text,
 *     downstream service health) is not leaked.
 *   - `detailLevel: "detailed"` enables the full check breakdown for
 *     every probe — only suitable for endpoints behind operator auth.
 *   - `detailPredicate(req)` lets the operator decide per-request:
 *     return true for internal IPs / authed requests, false otherwise.
 *     Detail predicate throwing → minimal response (fail closed).
 *   - `Cache-Control: no-store` on every response so probes never get
 *     cached by intermediate proxies.
 *
 * Caching:
 *   - cacheMs > 0 caches each tier's result for that duration. With
 *     k8s-style 1Hz probes against 10 checks, this drops the ambient
 *     load substantially. Cache is per-tier (liveness cached separately
 *     from readiness) — markShuttingDown bypasses readiness cache.
 *
 * Concurrent execution:
 *   - All checks for a tier run via Promise.all with per-check withTimeout.
 *   - One stuck check doesn't block the others; the timed-out check
 *     fails as { ok: false, error: "timeout" } and the others complete.
 */

var C = require("../constants");
var nb = require("../numeric-bounds");
var requestHelpers = require("../request-helpers");
var safeAsync = require("../safe-async");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var HTTP_STATUS = requestHelpers.HTTP_STATUS;

var HealthError = defineClass("HealthError", { alwaysPermanent: true });

var TIERS = Object.freeze(["liveness", "readiness", "startup"]);
var TIER_SET = new Set(TIERS);

var DEFAULT_TIMEOUT_MS = C.TIME.seconds(5);

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
  } else if (nb.isPositiveFiniteInt(opts.defaultTimeoutMs)) {
    defaultTimeoutMs = opts.defaultTimeoutMs;
  } else {
    throw new HealthError("health/bad-opt",
      "defaultTimeoutMs must be a positive finite integer; got " +
        nb.shape(opts.defaultTimeoutMs));
  }
  var cacheMs;
  if (opts.cacheMs === undefined) {
    cacheMs = 0;
  } else if (nb.isNonNegativeFiniteInt(opts.cacheMs)) {
    cacheMs = opts.cacheMs;
  } else {
    throw new HealthError("health/bad-opt",
      "cacheMs must be a non-negative finite integer; got " +
        nb.shape(opts.cacheMs));
  }
  var includeMeta = opts.includeMeta !== false;
  var version = opts.version || null;

  var checks = [];     // { name, fn, tiers: Set, timeoutMs, critical }
  var shuttingDown = false;
  var startedAt = Date.now();
  var cache = {};      // tier → { result, expiresAt }

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
    // Refuse duplicate names within a tier — silent overwrite makes
    // operator config bugs impossible to debug.
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
    } else if (nb.isPositiveFiniteInt(copts.timeoutMs)) {
      timeoutMs = copts.timeoutMs;
    } else {
      throw new HealthError("health/bad-opt",
        "registerCheck: timeoutMs must be a positive finite integer; got " +
          nb.shape(copts.timeoutMs));
    }
    checks.push({
      name:      name,
      fn:        fn,
      tiers:     new Set(tiers),
      timeoutMs: timeoutMs,
      critical:  copts.critical !== false,
    });
  }

  // Bypass cache when shuttingDown was just flipped; readiness must
  // surface 503 immediately, not wait for the cache window to expire.
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
      // Wrap the check in withTimeout. Promise.resolve() coerces sync
      // returns into Promises so the timeout can be applied uniformly.
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
            // Truthy non-boolean / non-object → treat as ok=true. Falsy → ok=false.
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
        // Merge detail keys other than `ok` into the entry.
        var keys = Object.keys(r.detail);
        for (var n = 0; n < keys.length; n++) {
          if (keys[n] !== "ok") entry[keys[n]] = r.detail[keys[n]];
        }
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
    catch (_e) { return false; /* fail-closed */ }
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
          // HEAD: status code only, no body.
          var status = (result.status === "ok" || result.status === "degraded")
            ? HTTP_STATUS.OK : HTTP_STATUS.SERVICE_UNAVAILABLE;
          res.writeHead(status, { "Cache-Control": "no-store" });
          res.end();
          return;
        }
        _writeResponse(res, result, _wantDetail(req));
      } catch {
        // Catastrophic — write 503 with minimal detail and never leak
        // internal error info on a public endpoint.
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
