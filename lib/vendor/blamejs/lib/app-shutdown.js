// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.appShutdown
 * @nav    Production
 * @title  App Shutdown
 *
 * @intro
 *   Graceful shutdown orchestrator — drain in-flight requests, flush
 *   audit, close DB, release the cluster lease, then exit. Configurable
 *   timeouts and signal handlers wire SIGTERM / SIGINT (and any
 *   operator-supplied signals) into a single phase-ordered shutdown.
 *
 *   SIGTERM is the contract between Kubernetes / systemd / `docker
 *   stop` and the framework. Production rolling restarts depend on the
 *   server draining cleanly. Without orchestration each subsystem's
 *   shutdown races every other subsystem's — the result is dropped
 *   requests, half-completed jobs, and stuck cluster leases that block
 *   the next pod from acquiring. The orchestrator runs phases in array
 *   order with per-phase budgets so a slow phase cannot starve later
 *   ones; a phase failure is logged but does not skip the remaining
 *   phases (the DB still closes even if jobs drain timed out).
 *
 *   `b.appShutdown.standardPhases(components)` builds the canonical
 *   ordering — mark-draining → scheduler → jobs → websockets →
 *   http-server → cluster → db → external-db — given a components map.
 *   Operators with custom topology call it directly and prepend or
 *   append their own phases. `b.appShutdown.pidLock(path)` is a single-
 *   instance file lock for daemons that must run exactly once on a
 *   host; it composes with the orchestrator via `addPhase` so the lock
 *   is released as part of graceful shutdown.
 *
 *   Idempotency: `shutdown()` is idempotent. Calling it twice returns
 *   the same Promise. Signal handlers route through the same call so
 *   SIGTERM, SIGINT, an `uncaughtException` reaching the operator hook,
 *   and a manual `orchestrator.shutdown()` all converge on one
 *   orchestration. When `b.tracing` has an active registry every phase
 *   runs inside a span named `shutdown.<phase>` so per-phase durations
 *   surface in the operator's tracing exporter.
 *
 * @card
 *   Graceful shutdown orchestrator — drain in-flight requests, flush audit, close DB, release the cluster lease, then exit.
 */

var safeAsync = require("./safe-async");
var numericBounds = require("./numeric-bounds");
var pidProbe = require("./pid-probe");
var validateOpts = require("./validate-opts");
var tracing = null;
try { tracing = require("./tracing"); } catch (_e) { /* tracing optional */ }
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var C = require("./constants");

var AppShutdownError = defineClass("AppShutdownError", { alwaysPermanent: true });
var log = boot("app-shutdown");

var DEFAULT_GRACE_MS = C.TIME.seconds(30);
var FORCE_EXIT_MARGIN_MS = C.TIME.seconds(5);

/**
 * @primitive b.appShutdown.create
 * @signature b.appShutdown.create(opts)
 * @since     0.6.0
 * @related   b.appShutdown.standardPhases, b.appShutdown.pidLock
 *
 * Build a graceful-shutdown orchestrator. Returns an instance with
 * `shutdown()` (idempotent — second call returns the same Promise),
 * `middleware()` (refuses new requests with 503 + tracks in-flight
 * count), `waitInFlight()`, `addPhase()`, `installSignals()`,
 * `uninstallSignals()`, `draining()`, and `inFlight()`. Each phase has
 * a per-phase budget; the default is remaining grace divided by
 * remaining phases so a slow phase doesn't starve later ones. A phase
 * failure is logged but does not skip the remaining phases.
 *
 * @opts
 *   graceMs:               number,    // total budget across all phases (default 30000)
 *   forceExitMarginMs:     number,    // headroom after graceMs before the signal-handler watchdog forces exit (default 5000); set the container stop grace above graceMs + this
 *   phases:                array,     // [{ name, run: async fn, timeoutMs? }]
 *   installSignalHandlers: boolean,   // wire SIGTERM/SIGINT (default false)
 *   signals:               array,     // signal names (default ["SIGTERM","SIGINT"])
 *   exitAfterPhases:       boolean,   // when true, a non-signal shutdown() also process.exit()s once phases complete (default false — only the signal path exits)
 *   onUncaught:            function,  // hook for uncaughtException / unhandledRejection
 *   installUncaught:       boolean,   // wire uncaughtException handler unconditionally
 *
 * @example
 *   var orchestrator = b.appShutdown.create({
 *     graceMs: 30000,
 *     phases: [
 *       { name: "before-stop", run: async function () { return "ok"; } },
 *       { name: "db",          run: function () { return; }, timeoutMs: 5000 },
 *     ],
 *   });
 *   var result = await orchestrator.shutdown();
 *   result.ok;                // → true
 *   result.phases.length;     // → 2
 */
function create(opts) {
  opts = opts || {};
  numericBounds.requirePositiveFiniteIntIfPresent(opts.graceMs,
    "app-shutdown.create: opts.graceMs", AppShutdownError, "app-shutdown/bad-grace-ms");
  var graceMs = opts.graceMs !== undefined ? opts.graceMs : DEFAULT_GRACE_MS;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.forceExitMarginMs,
    "app-shutdown.create: opts.forceExitMarginMs", AppShutdownError, "app-shutdown/bad-force-exit-margin-ms");
  var forceExitMarginMs = opts.forceExitMarginMs !== undefined ? opts.forceExitMarginMs : FORCE_EXIT_MARGIN_MS;
  validateOpts.optionalBoolean(opts.exitAfterPhases,
    "app-shutdown.create: opts.exitAfterPhases", AppShutdownError, "app-shutdown/bad-exit-after-phases");
  var exitAfterPhases = opts.exitAfterPhases === true;
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
        if (typeof res.writeHead === "function") {
          var body = JSON.stringify({ error: "service-shutting-down" });
          res.writeHead(C.HTTP.STATUS.SERVICE_UNAVAILABLE, {
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

  function waitInFlight() {
    if (inFlightCount === 0) return Promise.resolve();
    return new Promise(function (resolve) { inFlightWaiters.push(resolve); });
  }

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
      _drainComplete();
      var totalMs = Date.now() - startTime;
      var allOk = phaseResults.every(function (p) { return p.ok; });
      log("shutdown complete in " + totalMs + "ms (" +
          phaseResults.filter(function (p) { return p.ok; }).length + "/" +
          phaseResults.length + " phases ok)");
      if (exitAfterPhases) {
        var exitCode = (process.exitCode !== undefined && process.exitCode !== 0)
          ? process.exitCode : (allOk ? 0 : 1);
        setImmediate(function () {
          // allow:process-exit-operator-optin — operator opted into exitAfterPhases,
          process.exit(exitCode);
        });
      }
      return { ok: allOk, phases: phaseResults, totalMs: totalMs, draining: true };
    })();
    return shutdownPromise;
  }

  function _signalCallback(sig) {
    return function () {
      log("received " + sig + " — initiating graceful shutdown");
      var watchdog = setTimeout(function () {
        log.error("shutdown exceeded " + (graceMs + forceExitMarginMs) +
          "ms without the process exiting — forcing exit (exit handlers run " +
          "the final DB flush) before the supervisor SIGKILLs");
        // allow:process-exit-operator-optin — operator-delegated lifecycle, watchdog only
        process.exit(process.exitCode || 1);
      }, graceMs + forceExitMarginMs);
      if (typeof watchdog.unref === "function") watchdog.unref();
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

  var onUncaught = typeof opts.onUncaught === "function" ? opts.onUncaught : null;
  var uncaughtHandler = null;
  var unhandledRejHandler = null;

  var operatorSignals = Array.isArray(opts.signals) && opts.signals.length > 0
    ? opts.signals.slice() : ["SIGTERM", "SIGINT"];

  function _installUncaught() {
    if (uncaughtHandler || unhandledRejHandler) return;
    uncaughtHandler = function (err, origin) {
      log.error("uncaught " + (origin || "exception") + ": " + ((err && err.message) || String(err)));
      safeAsync.safeApply(onUncaught, [err, origin], function (e) {
        log.error("onUncaught hook failed: " + ((e && e.message) || String(e)));
      });
      shutdown().finally(function () { process.exitCode = process.exitCode || 1; });
    };
    unhandledRejHandler = function (reason) {
      uncaughtHandler(reason instanceof Error ? reason : new Error(String(reason)), "unhandledRejection");
    };
    process.on("uncaughtException", uncaughtHandler);
    process.on("unhandledRejection", unhandledRejHandler);
  }
  function _uninstallUncaught() {
    if (uncaughtHandler) { process.removeListener("uncaughtException", uncaughtHandler); uncaughtHandler = null; }
    if (unhandledRejHandler) { process.removeListener("unhandledRejection", unhandledRejHandler); unhandledRejHandler = null; }
  }

  function installSignals() {
    if (signalsInstalled) return;
    signalsInstalled = true;
    for (var si = 0; si < operatorSignals.length; si++) {
      var sig = operatorSignals[si];
      if (typeof sig !== "string" || sig.length === 0) continue;
      signalHandlers[sig] = _signalCallback(sig);
      process.on(sig, signalHandlers[sig]);
    }
    if (onUncaught || opts.installUncaught === true) _installUncaught();
  }

  function uninstallSignals() {
    if (!signalsInstalled) return;
    var keys = Object.keys(signalHandlers);
    for (var ki = 0; ki < keys.length; ki++) {
      process.removeListener(keys[ki], signalHandlers[keys[ki]]);
    }
    signalsInstalled = false;
    signalHandlers = {};
    _uninstallUncaught();
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

/**
 * @primitive b.appShutdown.standardPhases
 * @signature b.appShutdown.standardPhases(components)
 * @since     0.6.0
 * @related   b.appShutdown.create
 *
 * Build the canonical phases array for a components map. The order is
 * mark-draining → scheduler → jobs (or queue) → websockets →
 * http-server → cluster → db → external-db. Each entry carries a
 * conservative `timeoutMs`. Operators wire the result into
 * `b.appShutdown.create({ phases })`; with a non-standard topology they
 * prepend or append their own entries to the returned array.
 *
 * @example
 *   var phases = b.appShutdown.standardPhases({
 *     db: { close: function () { return; } },
 *   });
 *   phases.length;          // → 1
 *   phases[0].name;         // → "db"
 */
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

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");

/**
 * @primitive b.appShutdown.pidLock
 * @signature b.appShutdown.pidLock(lockPath)
 * @since     0.6.0
 * @related   b.appShutdown.create
 *
 * Single-instance file lock for daemons that must run exactly once on
 * a host. Returns `{ acquire, release, held, path }`. `acquire()`
 * writes the current PID atomically (open with O_EXCL + write + fsync)
 * and refuses to acquire if another live process already holds the
 * lock; stale lock files (PID gone) are reaped automatically. On
 * Windows the underlying advisory flock is unavailable, so the lock
 * file's exclusive presence is the lock. Compose with the orchestrator
 * by passing `release` as a phase via `addPhase`.
 *
 * @example
 *   var lock = b.appShutdown.pidLock("/tmp/blamejs-doc-example.pid");
 *   try {
 *     lock.acquire();
 *     lock.held();          // → true
 *   } finally {
 *     lock.release();
 *   }
 */
function pidLock(lockPath) {
  if (typeof lockPath !== "string" || lockPath.length === 0) {
    throw new AppShutdownError("app-shutdown/bad-pidlock-path",
      "pidLock(lockPath): lockPath must be a non-empty string (absolute path recommended)");
  }
  var fd = null;
  var ownsLock = false;

  function _readExisting() { return pidProbe.readPidFile(lockPath); }

  function acquire() {
    if (ownsLock) return;
    nodeFs.mkdirSync(nodePath.dirname(lockPath), { recursive: true });
    var existing = _readExisting();
    if (existing && pidProbe.isLivePid(existing) && existing !== process.pid) {
      throw new AppShutdownError("app-shutdown/pidlock-held",
        "pidLock: '" + lockPath + "' already held by live PID " + existing);
    }
    if (existing === process.pid) {
      try {
        fd = atomicFile.openNoFollowSync(lockPath);
      } catch (e) {
        throw new AppShutdownError("app-shutdown/pidlock-open-failed",
          "pidLock: failed to adopt self-held '" + lockPath + "': " + e.message);
      }
      ownsLock = true;
      return;
    }
    if (existing) {
      try { nodeFs.unlinkSync(lockPath); } catch (_e) { /* race: someone else reaped it */ }
    }
    try {
      fd = nodeFs.openSync(lockPath, nodeFs.constants.O_WRONLY | nodeFs.constants.O_CREAT | nodeFs.constants.O_EXCL, 0o600);
    } catch (e) {
      if (e.code === "EEXIST") {
        var winner = _readExisting();
        throw new AppShutdownError("app-shutdown/pidlock-held",
          "pidLock: '" + lockPath + "' acquired by PID " + (winner || "<unknown>") + " between read and write");
      }
      throw new AppShutdownError("app-shutdown/pidlock-open-failed",
        "pidLock: failed to open '" + lockPath + "': " + e.message);
    }
    nodeFs.writeSync(fd, String(process.pid) + "\n");
    nodeFs.fsyncSync(fd);
    ownsLock = true;
  }

  function release() {
    if (!ownsLock) return;
    try { nodeFs.closeSync(fd); } catch (_e) { /* best-effort close */ }
    fd = null;
    try {
      var current = _readExisting();
      if (current === process.pid) nodeFs.unlinkSync(lockPath);
    } catch (_e) { /* lock already gone — fine */ }
    ownsLock = false;
  }

  function held() { return ownsLock; }

  return {
    acquire: acquire,
    release: release,
    held:    held,
    path:    lockPath,
  };
}

module.exports = {
  create:            create,
  standardPhases:    standardPhases,
  pidLock:           pidLock,
  AppShutdownError:  AppShutdownError,
  DEFAULT_GRACE_MS:  DEFAULT_GRACE_MS,
};
