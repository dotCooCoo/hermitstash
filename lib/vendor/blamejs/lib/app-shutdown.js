"use strict";
/**
 * app-shutdown — graceful-shutdown orchestrator.
 *
 * SIGTERM is the contract between Kubernetes / systemd / docker stop
 * and the framework. Production rolling restarts depend on the
 * server draining cleanly: stop accepting new traffic, finish in-
 * flight requests, drain jobs, close DB, release the cluster lease.
 * Without orchestration each subsystem's shutdown races every other
 * subsystem's; the result is dropped requests, half-completed jobs,
 * stuck cluster leases that block the next pod from acquiring.
 *
 * This module ships a phase-ordered orchestrator. Each phase is
 * named, time-bounded, and best-effort — a phase failure logs an
 * issue but doesn't block subsequent phases (we still want to close
 * the DB and release the lease even if jobs draining timed out).
 *
 * Standard phase order:
 *
 *   1.  beforeStop          operator hook (run before anything else)
 *   2.  mark-draining       health.markShuttingDown() so /readyz → 503
 *                           and the LB starts draining the pod
 *   3.  stop-accepting      flip the orchestrator's `draining` flag —
 *                           middleware (orchestrator.middleware())
 *                           refuses new requests with 503
 *   4.  drain-in-flight     wait for the in-flight counter to reach 0
 *                           (tracked via the same middleware) up to
 *                           phaseTimeoutMs
 *   5.  afterDrain          operator hook (run after in-flight drained)
 *   6.  scheduler           scheduler.stop() if registered
 *   7.  jobs                jobs.shutdown() / queue.shutdown() — let
 *                           current handlers finish, refuse new lease
 *   8.  websockets          router.closeWebSockets() if HTTP server
 *   9.  http-server         server.close() — waits for keepalive
 *                           connections to drain
 *   10. cluster             cluster.shutdown() — release lease cleanly
 *                           so the next pod can acquire it without
 *                           waiting out the lease TTL
 *   11. db                  db.close() — flushes encrypted-at-rest
 *                           snapshot, closes SQLite handle
 *   12. external-db         externalDb.shutdown() — drain pool
 *
 * Custom phases can be added via opts.phases; each entry is
 * { name, run: async fn, timeoutMs? }. The orchestrator runs them
 * in array order. The standard phase set above is added by
 * createApp via the components map; standalone callers build their
 * own.
 *
 *   var orchestrator = b.appShutdown.create({
 *     graceMs:    30000,
 *     phases:     [
 *       { name: "beforeStop",   run: async function () { ... } },
 *       { name: "drain-in-flight", run: orchestrator.waitInFlight, timeoutMs: 10000 },
 *       { name: "db",           run: function () { db.close(); } },
 *     ],
 *     installSignalHandlers: true,    // SIGTERM + SIGINT auto-call shutdown
 *   });
 *
 *   var result = await orchestrator.shutdown();
 *   // → { ok, phases: [{ name, ms, ok, error? }, ...], totalMs, draining }
 *
 *   // Mounted as middleware to refuse new requests during drain +
 *   // track in-flight count.
 *   router.use(orchestrator.middleware());
 *
 *   orchestrator.draining();   // true once shutdown() has been called
 *   orchestrator.inFlight();   // current in-flight count
 *
 * Idempotency: shutdown() is idempotent. Calling it twice returns
 * the same Promise. Signal handlers fire it via `installSignalHandlers`
 * so SIGTERM + SIGINT both route through the same orchestration.
 *
 * Per-phase timeouts: each phase has a budget. If a phase doesn't
 * complete within timeoutMs it's marked failed and the orchestrator
 * moves to the next phase. Default = remaining grace divided by
 * remaining phases (so a slow phase doesn't starve later ones).
 *
 * Tracing integration: when b.tracing has an active registry, each
 * phase runs inside a span named "shutdown.<phase>" so operators see
 * which phase took how long in their tracing exporter.
 */

var safeAsync = require("./safe-async");
var nb = require("./numeric-bounds");
var tracing = null;
try { tracing = require("./tracing"); } catch (_e) { /* tracing optional */ }
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var C = require("./constants");

var AppShutdownError = defineClass("AppShutdownError", { alwaysPermanent: true });
var log = boot("app-shutdown");

var DEFAULT_GRACE_MS = C.TIME.seconds(30);

function create(opts) {
  opts = opts || {};
  nb.requirePositiveFiniteIntIfPresent(opts.graceMs,
    "app-shutdown.create: opts.graceMs", AppShutdownError, "app-shutdown/bad-grace-ms");
  var graceMs = opts.graceMs !== undefined ? opts.graceMs : DEFAULT_GRACE_MS;
  var phases = Array.isArray(opts.phases) ? opts.phases.slice() : [];
  var installSignalHandlers = !!opts.installSignalHandlers;
  for (var i = 0; i < phases.length; i++) {
    if (!phases[i] || typeof phases[i].name !== "string" || typeof phases[i].run !== "function") {
      throw new AppShutdownError("app-shutdown/bad-phase",
        "phases[" + i + "] must be { name: string, run: function, timeoutMs?: number }");
    }
  }

  var draining = false;
  var inFlightCount = 0;
  var inFlightWaiters = [];
  var shutdownPromise = null;
  var startTime = null;
  var signalsInstalled = false;
  var signalHandlers = {};

  function _drainComplete() {
    var pending = inFlightWaiters;
    inFlightWaiters = [];
    for (var i = 0; i < pending.length; i++) pending[i]();
  }

  function _trackResEnd(res) {
    var origEnd = res.end;
    res.end = function () {
      try { return origEnd.apply(res, arguments); }
      finally {
        inFlightCount--;
        if (inFlightCount === 0 && draining && inFlightWaiters.length > 0) {
          _drainComplete();
        }
      }
    };
  }

  function middleware() {
    return function shutdownGuard(req, res, next) {
      if (draining) {
        // Refuse new requests with 503 once the orchestrator has
        // started shutting down. Cache-Control: no-store so probes
        // don't get a stale 503 served from a CDN.
        if (typeof res.writeHead === "function") {
          var body = JSON.stringify({ error: "service-shutting-down" });
          res.writeHead(503, {
            "Content-Type":   "application/json; charset=utf-8",
            "Content-Length": Buffer.byteLength(body),
            "Cache-Control":  "no-store",
            "Connection":     "close",
          });
          res.end(body);
        }
        return;
      }
      inFlightCount++;
      _trackResEnd(res);
      return next();
    };
  }

  // Wait for inFlightCount to hit 0. Resolves immediately if already 0.
  // Caller-supplied timeout via the phase wrapper.
  function waitInFlight() {
    if (inFlightCount === 0) return Promise.resolve();
    return new Promise(function (resolve) { inFlightWaiters.push(resolve); });
  }

  // Run a single phase with a budget. Returns { name, ms, ok, error? }.
  async function _runPhase(phase, budgetMs, span) {
    var phaseStart = Date.now();
    var result = { name: phase.name, ms: 0, ok: true };
    var timeoutMs = typeof phase.timeoutMs === "number" && phase.timeoutMs > 0
                      ? Math.min(phase.timeoutMs, budgetMs) : budgetMs;
    try {
      await safeAsync.withTimeout(
        Promise.resolve().then(function () { return phase.run(); }),
        timeoutMs,
        { name: "shutdown." + phase.name }
      );
    } catch (e) {
      result.ok = false;
      result.error = (e && e.message) || String(e);
      log.error("shutdown phase '" + phase.name + "' failed: " + result.error);
    }
    result.ms = Date.now() - phaseStart;
    if (span && typeof span.setAttribute === "function") {
      span.setAttribute("shutdown.phase.ok", result.ok);
      span.setAttribute("shutdown.phase.ms", result.ms);
    }
    return result;
  }

  function shutdown() {
    if (shutdownPromise) return shutdownPromise;
    draining = true;
    startTime = Date.now();
    shutdownPromise = (async function () {
      var phaseResults = [];
      var remainingPhases = phases.length;
      for (var i = 0; i < phases.length; i++) {
        var elapsed = Date.now() - startTime;
        var remainingMs = Math.max(0, graceMs - elapsed);
        var perPhaseBudget = remainingPhases > 0 ? Math.floor(remainingMs / remainingPhases) : remainingMs;
        // Each phase wrapped in a tracing span if a registry is active.
        var phaseResult;
        if (tracing && typeof tracing.tap === "function") {
          phaseResult = await tracing.tap("shutdown." + phases[i].name, null, function (s) {
            return _runPhase(phases[i], perPhaseBudget, s);
          });
        } else {
          phaseResult = await _runPhase(phases[i], perPhaseBudget, null);
        }
        phaseResults.push(phaseResult);
        remainingPhases--;
      }
      // Allow any straggling in-flight resolvers to drop refs.
      _drainComplete();
      var totalMs = Date.now() - startTime;
      var allOk = phaseResults.every(function (p) { return p.ok; });
      log("shutdown complete in " + totalMs + "ms (" +
          phaseResults.filter(function (p) { return p.ok; }).length + "/" +
          phaseResults.length + " phases ok)");
      return { ok: allOk, phases: phaseResults, totalMs: totalMs, draining: true };
    })();
    return shutdownPromise;
  }

  function _signalCallback(sig) {
    return function () {
      log("received " + sig + " — initiating graceful shutdown");
      shutdown().then(function (result) {
        if (process.exitCode === undefined || process.exitCode === 0) {
          process.exitCode = result.ok ? 0 : 1;
        }
      }).catch(function (e) {
        log.error("shutdown threw unexpectedly: " + ((e && e.message) || String(e)));
        process.exitCode = 1;
      });
    };
  }

  function installSignals() {
    if (signalsInstalled) return;
    signalsInstalled = true;
    signalHandlers.SIGTERM = _signalCallback("SIGTERM");
    signalHandlers.SIGINT  = _signalCallback("SIGINT");
    process.on("SIGTERM", signalHandlers.SIGTERM);
    process.on("SIGINT",  signalHandlers.SIGINT);
  }

  function uninstallSignals() {
    if (!signalsInstalled) return;
    process.removeListener("SIGTERM", signalHandlers.SIGTERM);
    process.removeListener("SIGINT",  signalHandlers.SIGINT);
    signalsInstalled = false;
    signalHandlers = {};
  }

  if (installSignalHandlers) installSignals();

  return {
    shutdown:           shutdown,
    middleware:         middleware,
    waitInFlight:       waitInFlight,
    draining:           function () { return draining; },
    inFlight:           function () { return inFlightCount; },
    addPhase:           function (phase) {
      if (!phase || typeof phase.name !== "string" || typeof phase.run !== "function") {
        throw new AppShutdownError("app-shutdown/bad-phase",
          "addPhase requires { name: string, run: function, timeoutMs?: number }");
      }
      if (shutdownPromise) {
        throw new AppShutdownError("app-shutdown/already-started",
          "cannot addPhase after shutdown() has started");
      }
      phases.push(phase);
    },
    installSignals:     installSignals,
    uninstallSignals:   uninstallSignals,
    _resetForTest:      function () {
      uninstallSignals();
      shutdownPromise = null;
      draining = false;
      inFlightCount = 0;
      inFlightWaiters = [];
    },
  };
}

// Standard phase builder — given a components map, returns a phases
// array suitable for create({ phases }). Used by createApp; operators
// with custom topology call this directly to get the same ordering
// then prepend / append their own phases.
function standardPhases(components) {
  components = components || {};
  var phases = [];

  if (components.health && typeof components.health.markShuttingDown === "function") {
    phases.push({
      name: "mark-draining",
      run:  function () { components.health.markShuttingDown(); },
      timeoutMs: C.TIME.seconds(1),
    });
  }

  // The drain-in-flight phase needs the orchestrator's own
  // waitInFlight; it's added by createApp using addPhase after the
  // orchestrator instance exists. This function emits the phases that
  // don't need orchestrator references.

  if (components.scheduler && typeof components.scheduler.stop === "function") {
    phases.push({
      name: "scheduler",
      run:  function () { return components.scheduler.stop(); },
      timeoutMs: C.TIME.seconds(5),
    });
  }

  if (components.jobs && typeof components.jobs.shutdown === "function") {
    phases.push({
      name: "jobs",
      run:  function () { return components.jobs.shutdown({ timeoutMs: C.TIME.seconds(5) }); },
      timeoutMs: C.TIME.seconds(8),
    });
  } else if (components.queue && typeof components.queue.shutdown === "function") {
    phases.push({
      name: "queue",
      run:  function () { return components.queue.shutdown({ timeoutMs: C.TIME.seconds(5) }); },
      timeoutMs: C.TIME.seconds(8),
    });
  }

  if (components.router && typeof components.router.closeWebSockets === "function") {
    phases.push({
      name: "websockets",
      run:  function () { return components.router.closeWebSockets({ timeoutMs: C.TIME.seconds(3) }); },
      timeoutMs: C.TIME.seconds(5),
    });
  }

  if (components.server && typeof components.server.close === "function") {
    phases.push({
      name: "http-server",
      run:  function () {
        return new Promise(function (resolve) {
          components.server.close(function () { resolve(); });
        });
      },
      timeoutMs: C.TIME.seconds(10),
    });
  }

  if (components.cluster && typeof components.cluster.shutdown === "function") {
    phases.push({
      name: "cluster",
      run:  function () { return components.cluster.shutdown(); },
      timeoutMs: C.TIME.seconds(5),
    });
  }

  if (components.db && typeof components.db.close === "function") {
    phases.push({
      name: "db",
      run:  function () { components.db.close(); },
      timeoutMs: C.TIME.seconds(5),
    });
  }

  if (components.externalDb && typeof components.externalDb.shutdown === "function") {
    phases.push({
      name: "external-db",
      run:  function () { return components.externalDb.shutdown(); },
      timeoutMs: C.TIME.seconds(5),
    });
  }

  return phases;
}

module.exports = {
  create:            create,
  standardPhases:    standardPhases,
  AppShutdownError:  AppShutdownError,
  DEFAULT_GRACE_MS:  DEFAULT_GRACE_MS,
};
