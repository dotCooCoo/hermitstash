// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.daemon
 * @nav    Production
 * @title  Daemon
 *
 * @intro
 *   Long-running process orchestration — supervisor wiring around
 *   `b.appShutdown`, foreground signal handling, detached-fork spawn
 *   via `b.processSpawn`, PID-file health probes, and a
 *   SIGTERM-then-SIGKILL restart policy on stop.
 *
 *   Two operator paths share one entry point:
 *
 *   1. Foreground service mode (no `command`): the current process
 *      acquires `pidFile`, redirects stdout/stderr to `logFile`, and
 *      installs signal handlers (defaults: SIGTERM, SIGINT, SIGHUP)
 *      that route through a `b.appShutdown` orchestrator the operator
 *      can extend with `addPhase`.
 *
 *   2. Detached fork mode (`command` + `args`): the parent spawns the
 *      child via `b.processSpawn` (filtered env), writes the child PID
 *      to `pidFile`, hands the log fd to the child's stdout/stderr,
 *      and returns immediately so the parent can exit.
 *
 *   Stale-PID handling — when `pidFile` exists but the recorded PID is
 *   no longer alive, `start` and `stop` clean up the sidecar and emit
 *   `daemon.stale_pid_cleaned`. Cross-process linkage uses
 *   `b.appShutdown.pidLock`, which layers O_EXCL atomic-create +
 *   signal-0 liveness probe + reap-on-stale.
 *
 *   On Windows a received signal can never reach a JS handler
 *   (process.kill maps it to TerminateProcess), so `stop` drives a
 *   cooperative stop-request sentinel (`<pidFile>.stop`) that `start`
 *   watches and routes into the same orchestrator, escalating to a hard
 *   TerminateProcess only after the stop timeout. `status` is a read-only
 *   liveness probe that never mutates the pidfile.
 *
 *   Audit events: `daemon.started` (pidFile + logFile + commandKind +
 *   pid), `daemon.stopped` (pidFile + signal + waitMs + escalated +
 *   mechanism: signal|cooperative|terminate), `daemon.spawn_failed`
 *   (pidFile + command) when a detached child fails to launch, and
 *   `daemon.stale_pid_cleaned` (pidFile + stalePid).
 *
 * @card
 *   Long-running process orchestration — supervisor wiring around `b.appShutdown`, foreground signal handling, detached-fork spawn via `b.processSpawn`, PID-file health probes, and a SIGTERM-then-SIGKILL restart policy on stop.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var numericBounds = require("./numeric-bounds");
var appShutdown = require("./app-shutdown");
var pidProbe = require("./pid-probe");
var processSpawn = require("./process-spawn");
var safeAsync = require("./safe-async");
var atomicFile = require("./atomic-file");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { boot } = require("./log");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var DaemonError = defineClass("DaemonError", { alwaysPermanent: true });
var log = boot("daemon");

var DEFAULT_STOP_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_STOP_SIGNAL     = "SIGTERM";
var DEFAULT_POLL_MS         = 100;
var DEFAULT_LOG_FILE_MODE   = 0o600;
var BOOT_DEATH_WINDOW_MS    = C.TIME.seconds(5);
var MAX_BOOT_DEATH_WINDOW_MS = 0x7FFFFFFF;
var STOP_SENTINEL_POLL_MS   = 250;

function _safeAuditEmit(action, outcome, metadata) {
  auditEmit.emit(action, metadata, outcome);
}

var _isLivePid  = pidProbe.isLivePid;
var _readPidFile = pidProbe.readPidFile;

function _stoppingMarkerPath(pidFile) { return pidFile + ".stopping"; }

function _reapOwnStalePidfile(pidFile, childPid, readPid) {
  readPid = readPid || _readPidFile;
  var preOwned = false;
  try { preOwned = String(readPid(pidFile)) === String(childPid); } catch (_pe) { preOwned = false; }
  if (!preOwned) return false;
  var claim = pidFile + ".reap-" + childPid;
  try {
    atomicFile.renameWithRetry(pidFile, claim);
  } catch (_e) {
    return false;
  }
  var mine = false;
  try { mine = String(readPid(claim)) === String(childPid); } catch (_e2) { mine = false; }
  if (mine) {
    try { nodeFs.unlinkSync(claim); } catch (_e3) { /* best-effort reap — the sidecar is already off pidFile */ }
  } else {
    try {
      nodeFs.linkSync(claim, pidFile);
    } catch (linkErr) {
      if (linkErr.code !== "EEXIST") {
        try { atomicFile.renameWithRetry(claim, pidFile); } catch (_re) { /* best-effort restore */ }
      }
    }
    try { nodeFs.unlinkSync(claim); } catch (_e5) { /* consumed by the rename fallback, or already gone */ }
  }
  return mine;
}

function _validateStartOpts(opts) {
  validateOpts.shape(opts, {
    pidFile: { rule: "required-string", code: "daemon/bad-pid-file",
               label: "daemon.start: opts.pidFile (absolute path recommended)" },
    logFile: { rule: "optional-string", code: "daemon/bad-log-file",
               label: "daemon.start: opts.logFile" },
    signals: function (value) {
      validateOpts.optionalNonEmptyStringArray(value,
        "daemon.start: opts.signals", DaemonError, "daemon/bad-signals");
      if (Array.isArray(value) && value.length === 0) {
        throw new DaemonError("daemon/bad-signals",
          "daemon.start: opts.signals must be a non-empty array of POSIX signal names");
      }
    },
    command: { rule: "optional-string", code: "daemon/bad-command",
               label: "daemon.start: opts.command (path to executable)" },
    cwd: { rule: "optional-string", code: "daemon/bad-cwd",
           label: "daemon.start: opts.cwd (working directory for the detached child)" },
    args: function (value) {
      if (value !== undefined && !Array.isArray(value)) {
        throw new DaemonError("daemon/bad-args",
          "daemon.start: opts.args must be an array of strings when present");
      }
      if (opts.command === undefined && value !== undefined) {
        throw new DaemonError("daemon/bad-args",
          "daemon.start: opts.args requires opts.command");
      }
    },
    bootDeathWindowMs: function (value) {
      if (value !== undefined && (typeof value !== "number" || !isFinite(value) ||
                                  value < 0 || value > MAX_BOOT_DEATH_WINDOW_MS)) {
        throw new DaemonError("daemon/bad-boot-window",
          "daemon.start: opts.bootDeathWindowMs must be a finite number of " +
          "milliseconds in [0, " + MAX_BOOT_DEATH_WINDOW_MS + "] when present " +
          "(a larger delay clamps setTimeout to ~1ms and defeats the boot window)");
      }
    },
  }, "daemon.start", DaemonError, "daemon/bad-opts");
}

function _validateStopOpts(opts) {
  validateOpts.shape(opts, {
    pidFile: { rule: "required-string", code: "daemon/bad-pid-file",
               label: "daemon.stop: opts.pidFile" },
    signal:  { rule: "optional-string", code: "daemon/bad-signal",
               label: "daemon.stop: opts.signal" },
    timeoutMs: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "daemon.stop: opts.timeoutMs", DaemonError, "daemon/bad-timeout");
    },
    pollMs: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "daemon.stop: opts.pollMs", DaemonError, "daemon/bad-poll");
    },
  }, "daemon.stop", DaemonError, "daemon/bad-opts");
}

function _validateStatusOpts(opts) {
  validateOpts.shape(opts, {
    pidFile: { rule: "required-string", code: "daemon/bad-pid-file",
               label: "daemon.status: opts.pidFile" },
  }, "daemon.status", DaemonError, "daemon/bad-opts");
}

function _maybeReapStale(pidFile) {
  var existing = _readPidFile(pidFile);
  if (existing === null) return false;
  if (_isLivePid(existing) && existing !== process.pid) {
    return false;
  }
  if (existing === process.pid) return false;
  try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* race: another reaper */ }
  _safeAuditEmit("daemon.stale_pid_cleaned", "success", {
    pidFile:  pidFile,
    stalePid: existing,
  });
  return true;
}

function _openLogFd(logFile) {
  /* c8 ignore next -- every caller gates on a truthy logFile string, so this guard never returns null */
  if (typeof logFile !== "string" || logFile.length === 0) return null;
  atomicFile.ensureDir(nodePath.dirname(logFile));
  var fd = atomicFile.openAppendNoFollowSync(logFile, DEFAULT_LOG_FILE_MODE);
  return fd;
}

function _redirectStdio(fd) {
  /* c8 ignore next -- only ever called with the numeric fd from _openLogFd; the non-number guard is unreachable */
  if (typeof fd !== "number") return;
  function _writer(chunk, encOrCb, maybeCb) {
    var enc = typeof encOrCb === "string" ? encOrCb : "utf8";
    var cb  = typeof encOrCb === "function" ? encOrCb : maybeCb;
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), enc);
    try { nodeFs.writeSync(fd, buf); }
    catch (_e) { /* log fd closed underneath us — drop */ }
    if (typeof cb === "function") cb();
    return true;
  }
  process.stdout.write = _writer;
  process.stderr.write = _writer;
}

var _foregroundOrchestrators = Object.create(null);

function _stopSentinelPath(pidFile) {
  return pidFile + ".stop";
}

function _cleanupSentinel(sentinelPath) {
  try { nodeFs.unlinkSync(sentinelPath); } catch (_e) { /* best-effort — may not exist */ }
}

function _installStopSentinelWatcher(pidFile, orchestrator) {
  var dir = nodePath.dirname(pidFile);
  var sentinelName = nodePath.basename(pidFile) + ".stop";
  var sentinelPath = nodePath.join(dir, sentinelName);
  var fired = false;
  var timer = null;
  function _stopPolling() {
    if (!timer) return;
    try { clearInterval(timer); } catch (_e) { /* best-effort */ }
    timer = null;
  }
  function _maybeFire() {
    /* c8 ignore next -- _stopPolling clears the interval on the first fire, so _maybeFire can't re-enter with fired=true */
    if (fired) return;
    if (!nodeFs.existsSync(sentinelPath)) return;
    fired = true;
    _stopPolling();
    log("cooperative stop-request observed (" + sentinelPath + ") — initiating graceful shutdown");
    Promise.resolve(orchestrator.shutdown()).then(function (result) {
      if (process.exitCode === undefined || process.exitCode === 0) {
        process.exitCode = (result && result.ok) ? 0 : 1;
      }
    }).catch(function () { process.exitCode = 1; });
  }
  try {
    timer = setInterval(_maybeFire, STOP_SENTINEL_POLL_MS);
    if (timer && typeof timer.unref === "function") timer.unref();
  } catch (_e) {
    timer = null;
  }
  _maybeFire();
  return {
    close: function () { _stopPolling(); },
    sentinelPath: sentinelPath,
  };
}

/**
 * @primitive b.daemon.start
 * @signature b.daemon.start(opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.daemon.stop, b.appShutdown.create, b.processSpawn.spawn
 *
 * Acquire `pidFile`, optionally redirect stdout/stderr to `logFile`,
 * and either install signal handlers in the current process
 * (foreground mode) or spawn a detached child (when `command` is
 * supplied). Reaps a stale pidfile before acquire and emits
 * `daemon.stale_pid_cleaned` when one is found.
 *
 * Returns `{ pid, pidFile, logFile, mode }`. In foreground mode the
 * return value also exposes `orchestrator` (the underlying
 * `b.appShutdown` handle), `addPhase` (operator-supplied shutdown
 * phases), and `shutdown` (manual trigger). In detached mode `mode`
 * is `"detached"`; in foreground mode it is `"foreground"`.
 *
 * Throws `DaemonError("daemon/already-running")` when the pidfile is
 * held by a live PID, `DaemonError("daemon/spawn-failed")` when the
 * detached spawn errors, and `DaemonError("daemon/log-open-failed")`
 * when the log file cannot be opened in foreground mode.
 *
 * @opts
 *   pidFile: string,    // absolute path of the PID sidecar (required)
 *   logFile: string,    // append-mode log; redirects stdout+stderr
 *   signals: string[],  // foreground signals; default: SIGTERM/SIGINT/SIGHUP
 *   command: string,    // executable for detached-fork mode
 *   args:    string[],  // argv for the detached child
 *   cwd:     string,    // cwd for the detached child
 *   bootDeathWindowMs: number,  // detached: keep the parent loop alive this long after spawn to observe a boot death (an abnormal exit in the window is audited as a spawn failure + reaps the pidfile); default 5000, 0 opts out (fire-and-forget)
 *
 * @example
 *   var handle = b.daemon.start({
 *     pidFile: "/tmp/blamejs-daemon-demo.pid",
 *     signals: ["SIGTERM", "SIGINT"],
 *   });
 *   handle.mode;    // → "foreground"
 *   handle.pidFile; // → "/tmp/blamejs-daemon-demo.pid"
 *   typeof handle.shutdown; // → "function"
 *   await handle.shutdown();
 */
function start(opts) {
  _validateStartOpts(opts);
  var pidFile = opts.pidFile;
  var logFile = opts.logFile || null;
  var signals = Array.isArray(opts.signals) && opts.signals.length > 0
    ? opts.signals.slice()
    : ["SIGTERM", "SIGINT", "SIGHUP"];

  _maybeReapStale(pidFile);

  if (typeof opts.command === "string" && opts.command.length > 0) {
    var existingLive = _readPidFile(pidFile);
    if (existingLive !== null && _isLivePid(existingLive)) {
      throw new DaemonError("daemon/already-running",
        "daemon.start: pidFile '" + pidFile + "' held by live PID " + existingLive);
    }
    var isWindows = process.platform === "win32";
    var logFd = (!isWindows && logFile) ? _openLogFd(logFile) : null;
    var spawnStdio;
    if (isWindows || logFd === null) {
      spawnStdio = "ignore";
    } else {
      spawnStdio = ["ignore", logFd, logFd];
    }
    var child;
    try {
      child = processSpawn.spawn(opts.command, opts.args || [], {
        detached:    true,
        stdio:       spawnStdio,
        cwd:         typeof opts.cwd === "string" ? opts.cwd : undefined,
        windowsHide: isWindows ? true : undefined,
      });
    } catch (e) {
      try { if (typeof logFd === "number") nodeFs.closeSync(logFd); }
      catch (_c) { /* best-effort */ }
      throw new DaemonError("daemon/spawn-failed",
        "daemon.start: spawn failed: " + ((e && e.message) || String(e)));
    }
    var spawnedAt = Date.now();
    var bootWindowMs = (typeof opts.bootDeathWindowMs === "number")
      ? opts.bootDeathWindowMs : BOOT_DEATH_WINDOW_MS;
    child.on("error", function (err) {
      if (typeof child.pid === "number") {
        _reapOwnStalePidfile(pidFile, child.pid);
      }
      _safeAuditEmit("daemon.spawn_failed", "failure", {
        pidFile: pidFile,
        command: opts.command,
        error:   (err && err.message) || String(err),
      });
    });
    if (typeof child.pid !== "number" || !isFinite(child.pid) || child.pid <= 0) {
      try { if (typeof logFd === "number") nodeFs.closeSync(logFd); }
      catch (_c) { /* best-effort */ }
      throw new DaemonError("daemon/spawn-failed",
        "daemon.start: spawn of '" + opts.command + "' produced no pid (the command " +
        "failed to launch)");
    }
    atomicFile.ensureDir(nodePath.dirname(pidFile));
    try { nodeFs.unlinkSync(_stoppingMarkerPath(pidFile)); } catch (_sm) { /* best-effort — usually absent */ }
    var pidStr = String(child.pid) + "\n";
    atomicFile.writeSync(pidFile, pidStr, { fileMode: 0o600 });
    var bootWatch = null;
    child.on("exit", function (code, signal) {
      if (bootWatch) { clearTimeout(bootWatch); bootWatch = null; }
      var wasOurs = _reapOwnStalePidfile(pidFile, child.pid);
      var abnormal   = (typeof code === "number" && code !== 0) || signal != null;
      var withinBoot = (Date.now() - spawnedAt) <= bootWindowMs;
      var beingStopped = _readPidFile(_stoppingMarkerPath(pidFile)) === child.pid;
      if (wasOurs && abnormal && withinBoot && !beingStopped) {
        _safeAuditEmit("daemon.spawn_failed", "failure", {
          pidFile:  pidFile,
          command:  opts.command,
          exitCode: code,
          signal:   signal || null,
        });
      }
    });
    if (bootWindowMs > 0) {
      bootWatch = setTimeout(function () { bootWatch = null; }, bootWindowMs);
    }
    try { child.unref(); } catch (_u) { /* best-effort */ }
    if (typeof logFd === "number") {
      try { nodeFs.closeSync(logFd); } catch (_c) { /* best-effort */ }
    }
    _safeAuditEmit("daemon.started", "success", {
      pidFile:     pidFile,
      logFile:     logFile,
      commandKind: "detached-fork",
      pid:         child.pid,
      stdioMode:   isWindows ? "ignore-windows" : (logFd === null ? "ignore" : "inherit-logfd"),
    });
    log("daemon started (detached) pid=" + child.pid + " pidFile=" + pidFile);
    return { pid: child.pid, pidFile: pidFile, logFile: logFile, mode: "detached" };
  }

  var lock = appShutdown.pidLock(pidFile);
  try { lock.acquire(); }
  catch (e) {
    if (e && /pidlock-held/.test(e.code || "")) {
      throw new DaemonError("daemon/already-running",
        "daemon.start: pidFile '" + pidFile + "' already held: " + e.message);
    }
    throw new DaemonError("daemon/pid-acquire-failed",
      "daemon.start: failed to acquire pidFile '" + pidFile + "': " +
      ((e && e.message) || String(e)));
  }

  var logFdForeground = null;
  if (logFile) {
    try {
      logFdForeground = _openLogFd(logFile);
      _redirectStdio(logFdForeground);
    } catch (e) {
      /* c8 ignore next -- pidLock.release() swallows its own fs errors, so this guard never catches */
      try { lock.release(); } catch (_r) { /* best-effort */ }
      throw new DaemonError("daemon/log-open-failed",
        "daemon.start: failed to open logFile '" + logFile + "': " +
        ((e && e.message) || String(e)));
    }
  }

  var stopWatcher = null;

  var orchestrator = appShutdown.create({
    signals:               signals,
    installSignalHandlers: true,
    phases: [
      {
        name: "pidLock-release",
        run:  function () {
          /* c8 ignore next -- close() delegates to _stopPolling, which self-catches, so stopWatcher.close never throws */
          if (stopWatcher) { try { stopWatcher.close(); } catch (_w) { /* best-effort */ } }
          /* c8 ignore next -- pidLock.release() swallows its own fs errors, so this guard never catches */
          try { lock.release(); } catch (_e) { /* best-effort */ }
          if (logFdForeground !== null) {
            try { nodeFs.closeSync(logFdForeground); } catch (_c) { /* best-effort */ }
          }
          _cleanupSentinel(_stopSentinelPath(pidFile));
        },
        timeoutMs: C.TIME.seconds(2),
      },
    ],
  });
  _foregroundOrchestrators[pidFile] = orchestrator;
  if (process.platform === "win32") {
    stopWatcher = _installStopSentinelWatcher(pidFile, orchestrator);
  }

  _safeAuditEmit("daemon.started", "success", {
    pidFile:     pidFile,
    logFile:     logFile,
    commandKind: "foreground",
    pid:         process.pid,
    signals:     signals,
  });
  log("daemon started (foreground) pid=" + process.pid + " pidFile=" + pidFile);

  return {
    pid:           process.pid,
    pidFile:       pidFile,
    logFile:       logFile,
    mode:          "foreground",
    orchestrator:  orchestrator,
    addPhase:      orchestrator.addPhase,
    shutdown:      orchestrator.shutdown,
  };
}

/**
 * @primitive b.daemon.stop
 * @signature b.daemon.stop(opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.daemon.start, b.appShutdown.create
 *
 * Read `pidFile`, send `signal` (default `SIGTERM`), poll for exit up
 * to `timeoutMs` (default 30 s), then escalate to `SIGKILL`. Cleans
 * up the pidfile on successful exit and emits `daemon.stopped` with
 * `escalated: true|false` recording whether SIGKILL was needed.
 *
 * Returns `{ stopped, pid, signal, escalated?, reason? }`. `reason`
 * is `"no-pidfile"` when nothing was running and `"stale"` when the
 * pidfile pointed at a dead PID (the file is removed and a
 * `daemon.stale_pid_cleaned` audit row lands).
 *
 * @opts
 *   pidFile:     string,         // absolute path of the PID sidecar (required)
 *   signal:      string,         // initial signal; default "SIGTERM"
 *   timeoutMs:   number,         // wait before SIGKILL escalation; default 30 s
 *   pollMs:      number,         // liveness-probe interval; default 100 ms
 *   abortSignal: AbortSignal,    // forwarded to b.safeAsync.sleep
 *
 * @example
 *   var report = await b.daemon.stop({
 *     pidFile:   "/tmp/blamejs-daemon-demo.pid",
 *     timeoutMs: b.constants.TIME.seconds(5),
 *   });
 *   report.stopped; // → false
 *   report.reason;  // → "no-pidfile"
 */
async function stop(opts) {
  _validateStopOpts(opts);
  var pidFile   = opts.pidFile;
  var signal    = opts.signal || DEFAULT_STOP_SIGNAL;
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_STOP_TIMEOUT_MS;
  var pollMs    = typeof opts.pollMs    === "number" ? opts.pollMs    : DEFAULT_POLL_MS;

  var pid = _readPidFile(pidFile);
  if (pid === null) {
    return { stopped: false, pid: null, reason: "no-pidfile" };
  }
  if (!_isLivePid(pid)) {
    try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    _safeAuditEmit("daemon.stale_pid_cleaned", "success", { pidFile: pidFile, stalePid: pid });
    return { stopped: false, pid: pid, reason: "stale" };
  }

  var stopMarker = _stoppingMarkerPath(pidFile);
  try { atomicFile.writeSync(stopMarker, String(pid), { fileMode: 0o600 }); } catch (_w) { /* best-effort hint */ }
  try {
    return await _stopLivePid(pidFile, pid, signal, timeoutMs, pollMs, opts);
  } finally {
    try { nodeFs.unlinkSync(stopMarker); } catch (_u) { /* best-effort */ }
  }
}

async function _stopLivePid(pidFile, pid, signal, timeoutMs, pollMs, opts) {
  var t0 = Date.now();

  if (process.platform === "win32") {
    return await _stopWin32Cooperative(pidFile, pid, signal, timeoutMs, pollMs, t0, opts);
  }

  try { process.kill(pid, signal); }
  catch (e) {
    if (e && e.code === "ESRCH") {
      try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false, mechanism: "signal",
      });
      return { stopped: true, pid: pid, signal: signal, mechanism: "signal" };
    }
    throw new DaemonError("daemon/kill-failed",
      "daemon.stop: kill(" + pid + ", " + signal + ") failed: " + e.message);
  }

  var deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    if (!_isLivePid(pid)) {
      try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false, mechanism: "signal",
      });
      return { stopped: true, pid: pid, signal: signal, mechanism: "signal" };
    }
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }

  try { process.kill(pid, "SIGKILL"); }
  catch (e) {
    if (!(e && e.code === "ESRCH")) {
      throw new DaemonError("daemon/kill-failed",
        "daemon.stop: SIGKILL escalation failed for pid " + pid + ": " + e.message);
    }
  }
  var killDeadline = Date.now() + C.TIME.seconds(2);
  while (Date.now() < killDeadline) {
    if (!_isLivePid(pid)) break;
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }
  try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
  _safeAuditEmit("daemon.stopped", "success", {
    pidFile: pidFile, signal: "SIGKILL", waitMs: Date.now() - t0, escalated: true, mechanism: "signal",
  });
  return { stopped: true, pid: pid, signal: "SIGKILL", escalated: true, mechanism: "signal" };
}

async function _stopWin32Cooperative(pidFile, pid, signal, timeoutMs, pollMs, t0, opts) {
  var sentinel = _stopSentinelPath(pidFile);
  try {
    atomicFile.writeSync(sentinel, String(pid) + "\n", { fileMode: 0o600 });
  } catch (e) {
    throw new DaemonError("daemon/stop-request-failed",
      "daemon.stop: failed to write cooperative stop-request '" + sentinel + "': " +
      ((e && e.message) || String(e)));
  }

  var deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    if (!_isLivePid(pid)) {
      _cleanupSentinel(sentinel);
      try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false, mechanism: "cooperative",
      });
      return { stopped: true, pid: pid, signal: signal, mechanism: "cooperative" };
    }
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }

  try { process.kill(pid, "SIGKILL"); }
  catch (e) {
    if (!(e && e.code === "ESRCH")) {
      _cleanupSentinel(sentinel);
      throw new DaemonError("daemon/kill-failed",
        "daemon.stop: TerminateProcess escalation failed for pid " + pid + ": " + e.message);
    }
  }
  var killDeadline = Date.now() + C.TIME.seconds(2);
  while (Date.now() < killDeadline) {
    if (!_isLivePid(pid)) break;
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }
  _cleanupSentinel(sentinel);
  try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
  _safeAuditEmit("daemon.stopped", "success", {
    pidFile: pidFile, signal: "SIGKILL", waitMs: Date.now() - t0, escalated: true, mechanism: "terminate",
  });
  return { stopped: true, pid: pid, signal: "SIGKILL", escalated: true, mechanism: "terminate" };
}

/**
 * @primitive b.daemon.status
 * @signature b.daemon.status(opts)
 * @since     0.17.13
 * @status    stable
 * @related   b.daemon.start, b.daemon.stop
 *
 * Read-only PID-liveness probe. Reads `pidFile` and reports whether the
 * recorded process is alive, WITHOUT mutating anything — unlike `stop()`,
 * a stale pidfile is reported but never unlinked, so a health check can't
 * disturb the daemon's lifecycle state. A missing / malformed / symlinked /
 * oversized pidfile reports `running: false` with `reason: "no-pidfile"`
 * rather than throwing (the same fd-safe, symlink-refusing, 1 KiB-capped
 * read that `start` and `stop` use). Bad opts throw `daemon/bad-pid-file`.
 *
 * Returns `{ running, pid, reason? }`. `reason` is `"no-pidfile"` when no
 * live sidecar was found and `"stale"` when the pidfile pointed at a dead
 * PID — the file is left in place for the operator to inspect or for `stop`
 * to reap.
 *
 * @opts
 *   pidFile: string,   // absolute path of the PID sidecar (required)
 *
 * @example
 *   var s = b.daemon.status({ pidFile: "/tmp/blamejs-daemon-demo.pid" });
 *   s.running; // → false
 *   s.reason;  // → "no-pidfile"
 */
function status(opts) {
  _validateStatusOpts(opts);
  var pidFile = opts.pidFile;
  var pid = _readPidFile(pidFile);
  if (pid === null) {
    return { running: false, pid: null, reason: "no-pidfile" };
  }
  if (!_isLivePid(pid)) {
    return { running: false, pid: pid, reason: "stale" };
  }
  return { running: true, pid: pid };
}

function _resetForTest() {
  var keys = Object.keys(_foregroundOrchestrators);
  for (var i = 0; i < keys.length; i++) {
    try { _foregroundOrchestrators[keys[i]]._resetForTest(); } catch (_e) { /* best-effort */ }
  }
  _foregroundOrchestrators = Object.create(null);
}

module.exports = {
  start:                start,
  stop:                 stop,
  status:               status,
  DaemonError:          DaemonError,
  DEFAULT_STOP_SIGNAL:  DEFAULT_STOP_SIGNAL,
  DEFAULT_STOP_TIMEOUT_MS: DEFAULT_STOP_TIMEOUT_MS,
  _resetForTest:        _resetForTest,
  _reapOwnStalePidfile: _reapOwnStalePidfile,
};
