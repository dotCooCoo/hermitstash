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
 *   Audit events: `daemon.started` (pidFile + logFile + commandKind +
 *   pid), `daemon.stopped` (pidFile + signal + waitMs + escalated),
 *   `daemon.stale_pid_cleaned` (pidFile + stalePid).
 *
 * @card
 *   Long-running process orchestration — supervisor wiring around `b.appShutdown`, foreground signal handling, detached-fork spawn via `b.processSpawn`, PID-file health probes, and a SIGTERM-then-SIGKILL restart policy on stop.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var numericBounds = require("./numeric-bounds");
var appShutdown = require("./app-shutdown");
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

function _safeAuditEmit(action, outcome, metadata) {
  auditEmit.emit(action, metadata, outcome);
}

function _isLivePid(pid) {
  if (typeof pid !== "number" || !isFinite(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e && e.code === "EPERM"; }
}

function _readPidFile(pidFile) {
  try {
    // Same fd-safe + capped + symlink-refusing read as app-shutdown's lockfile
    // reader (one shape): a PID file is never a legit symlink mount, so
    // refuseSymlink is safe; any throw → null ("nothing live there").
    var raw = atomicFile.fdSafeReadSync(pidFile, { maxBytes: C.BYTES.kib(1), refuseSymlink: true, encoding: "utf8" });
    var pid = parseInt(String(raw).trim(), 10);
    return isFinite(pid) && pid > 0 ? pid : null;
  } catch (_e) { return null; }
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

  var orchestrator = appShutdown.create({
    signals:               signals,
    installSignalHandlers: true,
    phases: [
      {
        name: "pidLock-release",
        run:  function () {
          try { lock.release(); } catch (_e) { /* best-effort */ }
          if (logFdForeground !== null) {
            try { nodeFs.closeSync(logFdForeground); } catch (_c) { /* best-effort */ }
          }
        },
        timeoutMs: C.TIME.seconds(2),
      },
    ],
  });
  _foregroundOrchestrators[pidFile] = orchestrator;

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
  // First signal — typically SIGTERM. Wait up to timeoutMs for exit.
  try { process.kill(pid, signal); }
  catch (e) {
    if (e && e.code === "ESRCH") {
      // Died between read and kill — cleanup + report.
      try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false,
      });
      return { stopped: true, pid: pid, signal: signal };
    }
    throw new DaemonError("daemon/kill-failed",
      "daemon.stop: kill(" + pid + ", " + signal + ") failed: " + e.message);
  }

  var deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    if (!_isLivePid(pid)) {
      try { nodeFs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false,
      });
      return { stopped: true, pid: pid, signal: signal };
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
    pidFile: pidFile, signal: "SIGKILL", waitMs: Date.now() - t0, escalated: true,
  });
  return { stopped: true, pid: pid, signal: "SIGKILL", escalated: true };
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
  DaemonError:          DaemonError,
  DEFAULT_STOP_SIGNAL:  DEFAULT_STOP_SIGNAL,
  DEFAULT_STOP_TIMEOUT_MS: DEFAULT_STOP_TIMEOUT_MS,
  _resetForTest:        _resetForTest,
};
