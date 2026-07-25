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

// Tunables. Operator overrides via opts on stop(); for start() the
// defaults are baked in so the operator surface stays minimal.
var DEFAULT_STOP_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_STOP_SIGNAL     = "SIGTERM";
var DEFAULT_POLL_MS         = 100;
var DEFAULT_LOG_FILE_MODE   = 0o600;
// Poll cadence for the Windows cooperative-stop sentinel (a synchronous
// existsSync on this interval; see _installStopSentinelWatcher for why it is a
// poll and not a filesystem watch). Runs for a foreground daemon's whole
// lifetime, so it is coarser than DEFAULT_POLL_MS (which only polls during the
// brief stop window); 250ms keeps graceful-stop detection sub-second at
// negligible idle cost.
var STOP_SENTINEL_POLL_MS   = 250;

function _safeAuditEmit(action, outcome, metadata) {
  auditEmit.emit(action, metadata, outcome);
}

// Signal-0 liveness probe + fd-safe pidfile reader live in lib/pid-probe.js so
// b.daemon and b.appShutdown.pidLock share ONE implementation (they carried
// byte-identical copies). Local aliases keep the call sites terse.
var _isLivePid  = pidProbe.isLivePid;
var _readPidFile = pidProbe.readPidFile;

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
    // Live owner — caller will receive a daemon/already-running below.
    return false;
  }
  if (existing === process.pid) return false;
  // Stale: PID is gone (or signal-0 returned ESRCH). Reap + audit.
  try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* race: another reaper */ }
  _safeAuditEmit("daemon.stale_pid_cleaned", "success", {
    pidFile:  pidFile,
    stalePid: existing,
  });
  return true;
}

// Open the log file (append mode, 0o600) and return the fd.
// Used both by detached-spawn (passed via stdio) and by foreground
// redirect of the current process' stdout/stderr.
function _openLogFd(logFile) {
  if (typeof logFile !== "string" || logFile.length === 0) return null;
  atomicFile.ensureDir(nodePath.dirname(logFile));
  // O_NOFOLLOW append: refuse (ELOOP) a symlink planted at the daemon log
  // path rather than redirecting the detached process's stdout/stderr to an
  // attacker-chosen file (CWE-59).
  var fd = atomicFile.openAppendNoFollowSync(logFile, DEFAULT_LOG_FILE_MODE);
  return fd;
}

// Redirect the current process's stdout/stderr file descriptors at the
// given fd. Implemented via nodeFs.writeSync streams: Node doesn't expose a
// portable dup2, so we replace process.stdout.write / process.stderr.write
// with a writer that pushes to the log fd. This is the standard
// pattern for foreground daemons that don't want to lose output when
// detached from a terminal.
function _redirectStdio(fd) {
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

// Track foreground orchestrators per pidFile so stop() / repeat
// start() in the same process don't double-install signals.
var _foregroundOrchestrators = Object.create(null);

// Sibling-sentinel path a cooperative stop request is written to. Kept beside
// the pidFile so it inherits the same operator-owned directory + permissions.
function _stopSentinelPath(pidFile) {
  return pidFile + ".stop";
}

// Remove a cooperative stop sentinel (best-effort — it may already be gone, or
// never have existed on the POSIX path). unlink removes the LINK, not a target.
function _cleanupSentinel(sentinelPath) {
  try { nodeFs.unlinkSync(sentinelPath); } catch (_e) { /* best-effort — may not exist */ }
}

// Install the Windows cooperative-stop watcher for a foreground daemon. Fires
// the orchestrator's graceful shutdown the first time the sibling <pidFile>.stop
// sentinel appears — the same orchestrator.shutdown() the POSIX signal path
// drives, so the exit code is set from the phase result and the event loop
// drains once the phases release the daemon's resources.
//
// Detection is a synchronous existsSync on a plain unref'd interval, NOT a
// filesystem watch, for two Windows-specific reasons:
//   - fs.watch (libuv ReadDirectoryChangesW) aborts the whole process — an
//     uncatchable src/win/fs-event.c assertion, "!_wcsnicmp(filename, dir,
//     dirlen)" — when the watched directory is reached through an 8.3
//     short-name path, exactly the shape of a CI runner's temp dir
//     (C:\Users\RUNNER~1\AppData\Local\Temp\...): GetFinalPathNameByHandle
//     returns the long form and the prefix check fails. A try/catch cannot
//     recover from an abort().
//   - fs.watchFile's StatWatcher stats through the libuv threadpool, which
//     starves under heavy concurrent filesystem load and delays detection by
//     seconds; a synchronous existsSync runs inline on the main thread and is
//     immune.
// The interval is unref'd so it never itself keeps the process alive; a clean
// daemon exits on its own once shutdown completes. If the sentinel is never
// written the poll is a no-op the release phase clears at shutdown. Returns a
// handle exposing close().
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
    if (fired) return;
    // Synchronous existsSync on the main thread — deliberately not an async
    // stat, so detection never queues behind a saturated libuv threadpool.
    if (!nodeFs.existsSync(sentinelPath)) return;
    fired = true;
    _stopPolling();
    log("cooperative stop-request observed (" + sentinelPath + ") — initiating graceful shutdown");
    // Mirror the POSIX signal path: run the orchestrator's phases, derive the
    // exit code from the result, then let the loop drain (a foreground daemon's
    // phases release its server/db so the process exits on its own).
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
    // Timer scheduling unavailable — no cooperative channel; daemon.stop()
    // still hard-stops via TerminateProcess after its timeout.
    timer = null;
  }
  // The sentinel may already exist (stop() raced ahead of this install).
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

  // Reap a stale pidfile if present, then attempt acquire.
  _maybeReapStale(pidFile);

  // Detached-fork mode — caller wants us to spawn the child, write its
  // PID into pidFile, and return without taking the lock ourselves.
  if (typeof opts.command === "string" && opts.command.length > 0) {
    var existingLive = _readPidFile(pidFile);
    if (existingLive !== null && _isLivePid(existingLive)) {
      throw new DaemonError("daemon/already-running",
        "daemon.start: pidFile '" + pidFile + "' held by live PID " + existingLive);
    }
    // Detached-stdio strategy diverges by platform:
    //
    //   POSIX: inherit the parent's open log FD via stdio so the child
    //   writes to the operator's log file without re-opening it. POSIX
    //   keeps the FD alive across the parent's exit; the child sees it
    //   as fd 1 / 2 and writes normally.
    //
    //   Windows: passing a parent-opened FD through stdio causes the
    //   child to die the moment the parent's handle is closed (the OS
    //   ref-counts file handles per-process and the inherited handle
    //   becomes invalid on parent exit). The Windows-safe pattern is
    //   `stdio: "ignore"` + `windowsHide: true` so the child has no
    //   inherited handles to lose, and the operator's child code opens
    //   the log file itself once its logger initialises. The child is
    //   responsible for `--log` parsing on Windows — pass it via
    //   `opts.args` and let the application code handle the open.
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
    // A bad command does NOT throw synchronously from spawn — child_process
    // reports it ASYNC via a 'error' event, with child.pid left undefined. The
    // sync try/catch above only covers spawn() itself, so without this the old
    // path wrote "undefined\n" to the pidFile and returned success. Subscribe a
    // one-shot 'error' handler that reaps the sidecar + audits the failure, then
    // refuse to proceed for a child that never got a pid.
    child.on("error", function (err) {
      try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* best-effort — may not exist */ }
      _safeAuditEmit("daemon.spawn_failed", "failure", {
        pidFile: pidFile,
        command: opts.command,
        error:   (err && err.message) || String(err),
      });
    });
    // child.pid must be a real, positive PID. A command that failed to launch
    // leaves it undefined; the same positive-integer front-guard the shared
    // liveness probe (pidProbe.isLivePid) applies before it will signal a pid —
    // a non-number / non-finite / non-positive value is never a launched child.
    // Fail closed BEFORE any pidfile write so no "undefined" sidecar survives
    // for daemon.stop to misread.
    if (typeof child.pid !== "number" || !isFinite(child.pid) || child.pid <= 0) {
      try { if (typeof logFd === "number") nodeFs.closeSync(logFd); }
      catch (_c) { /* best-effort */ }
      throw new DaemonError("daemon/spawn-failed",
        "daemon.start: spawn of '" + opts.command + "' produced no pid (the command " +
        "failed to launch)");
    }
    // Write the child's PID via atomic temp+rename so a concurrent
    // observer never sees a half-written pidFile.
    atomicFile.ensureDir(nodePath.dirname(pidFile));
    var pidStr = String(child.pid) + "\n";
    atomicFile.writeSync(pidFile, pidStr, { fileMode: 0o600 });
    // Detach so the child survives parent exit.
    try { child.unref(); } catch (_u) { /* best-effort */ }
    if (typeof logFd === "number") {
      // Parent doesn't need its handle to the log; child inherited it.
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

  // Foreground mode — current process owns pidFile + signals.
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
      try { lock.release(); } catch (_r) { /* best-effort */ }
      throw new DaemonError("daemon/log-open-failed",
        "daemon.start: failed to open logFile '" + logFile + "': " +
        ((e && e.message) || String(e)));
    }
  }

  // Cooperative stop channel (Windows). Node maps process.kill(pid, "SIGTERM")
  // to TerminateProcess on win32, so a "signal" never reaches a JS handler and
  // the graceful orchestrator would be unreachable. daemon.stop() writes a
  // sibling <pidFile>.stop sentinel; a watcher installed below routes it into
  // the SAME orchestrator.shutdown() the POSIX signal path uses. Assigned after
  // the orchestrator exists; the release phase (which runs at shutdown) closes
  // it + removes the sentinel.
  var stopWatcher = null;

  var orchestrator = appShutdown.create({
    signals:               signals,
    installSignalHandlers: true,
    phases: [
      {
        name: "pidLock-release",
        run:  function () {
          if (stopWatcher) { try { stopWatcher.close(); } catch (_w) { /* best-effort */ } }
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
    // Stale — clean up and report.
    try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    _safeAuditEmit("daemon.stale_pid_cleaned", "success", { pidFile: pidFile, stalePid: pid });
    return { stopped: false, pid: pid, reason: "stale" };
  }

  var t0 = Date.now();

  // Windows has no cooperative signal: process.kill(pid, "SIGTERM") maps to
  // TerminateProcess (a hard kill), so the graceful appShutdown orchestration is
  // only reachable via the cooperative stop-request sentinel start() watches.
  // Drive that channel first and escalate to the hard kill only on timeout.
  if (process.platform === "win32") {
    return await _stopWin32Cooperative(pidFile, pid, signal, timeoutMs, pollMs, t0, opts);
  }

  // POSIX signal path — first signal (typically SIGTERM), wait up to timeoutMs
  // for exit, then escalate to SIGKILL. mechanism is always "signal" here.
  try { process.kill(pid, signal); }
  catch (e) {
    if (e && e.code === "ESRCH") {
      // Died between read and kill — cleanup + report.
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

  // Timed out — escalate to SIGKILL.
  try { process.kill(pid, "SIGKILL"); }
  catch (e) {
    if (!(e && e.code === "ESRCH")) {
      throw new DaemonError("daemon/kill-failed",
        "daemon.stop: SIGKILL escalation failed for pid " + pid + ": " + e.message);
    }
  }
  // Wait briefly for the kernel to reap.
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

// Windows cooperative stop. Writes the sibling <pidFile>.stop sentinel the
// foreground start() watcher routes into the graceful orchestrator, polls for a
// clean exit up to timeoutMs, and escalates to a hard TerminateProcess (Windows
// maps any real signal to it) ONLY on timeout — preserving the POSIX
// graceful-first / forced-on-timeout shape and the same brief post-kill reap
// wait. mechanism distinguishes the cooperative exit from the forced one; the
// sentinel is removed on both paths.
async function _stopWin32Cooperative(pidFile, pid, signal, timeoutMs, pollMs, t0, opts) {
  var sentinel = _stopSentinelPath(pidFile);
  // O_NOFOLLOW-staged write (atomicFile.writeSync → _openExclTemp with
  // O_EXCL | O_NOFOLLOW) so a symlink planted at <pidFile>.stop can't redirect
  // the request to an attacker-chosen file (CWE-59).
  try {
    atomicFile.writeSync(sentinel, String(pid) + "\n", { fileMode: 0o600 });
  } catch (e) {
    throw new DaemonError("daemon/stop-request-failed",
      "daemon.stop: failed to write cooperative stop-request '" + sentinel + "': " +
      ((e && e.message) || String(e)));
  }

  // Poll for cooperative exit up to timeoutMs.
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

  // Timed out — the daemon ignored the cooperative request. Hard-stop it.
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
    // Missing / malformed / symlinked / oversized — nothing live to report.
    // READ-ONLY: never unlink (stop() reaps; status() must not).
    return { running: false, pid: null, reason: "no-pidfile" };
  }
  if (!_isLivePid(pid)) {
    // Recorded PID is dead. Report it but leave the sidecar in place.
    return { running: false, pid: pid, reason: "stale" };
  }
  return { running: true, pid: pid };
}

// Test-only — drop process-wide foreground orchestrator state so smoke
// tests can re-run start() in the same process without leaking signal
// handlers across cases.
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
};
