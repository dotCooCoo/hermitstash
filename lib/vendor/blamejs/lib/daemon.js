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
// A detached child that exits within this window of spawn is treated as a boot
// death (spawn_failed audit); an abnormal exit after it is a normal run/crash,
// and a clean exit or an operator stop() is never a spawn failure.
var BOOT_DEATH_WINDOW_MS    = C.TIME.seconds(5);
// setTimeout clamps a delay above this 32-bit ceiling to ~1ms, which would
// silently defeat the boot-window loop-hold — so the opt is refused above it.
var MAX_BOOT_DEATH_WINDOW_MS = 0x7FFFFFFF;   // 2,147,483,647
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

// An in-flight stop() writes a `<pidFile>.stopping` marker holding the pid it is
// stopping. The detached boot-death exit handler consults it so a stop()-induced
// exit within the boot window is not misread as a spawn failure — a FILESYSTEM
// marker (not an in-process flag) so it works whether stop() runs in the same
// process that called start() OR a different one (e.g. a `daemon stop` CLI). The
// marker carries the target pid so a stale marker from a crashed stopper can
// only ever suppress that same pid, never a later daemon reusing the pidfile.
function _stoppingMarkerPath(pidFile) { return pidFile + ".stopping"; }

// Reap the boot-dead child's OWN stale pidfile without a check-then-unlink race.
// A naive `if (read(pidFile) === childPid) unlink(pidFile)` can delete the WRONG
// file: a fast operator restart that rewrites pidFile with a NEW child's pid
// between the read and the unlink leaves the new daemon unmanageable via stop().
//
// A NON-DESTRUCTIVE ownership pre-check runs first: only when the sidecar still
// records THIS child's pid do we ATOMICALLY claim it (rename it to a per-pid path)
// so the confirming check and the removal act on the same exclusive file. A fast
// restart's replacement pidfile (a different pid) is thus never even temporarily
// hidden — we leave it untouched. Should a restart land in the tiny window between
// the pre-check and the claim, the post-claim re-check catches it (the claimed
// file's pid won't match) and restores the file. `readPid` defaults to the
// hardened reader and is injectable for tests. Returns whether the reaped sidecar
// was this child's.
function _reapOwnStalePidfile(pidFile, childPid, readPid) {
  readPid = readPid || _readPidFile;
  // Pre-check: don't claim (and momentarily hide) a pidfile that isn't ours.
  var preOwned = false;
  try { preOwned = String(readPid(pidFile)) === String(childPid); } catch (_pe) { preOwned = false; }
  if (!preOwned) return false;
  var claim = pidFile + ".reap-" + childPid;
  try {
    atomicFile.renameWithRetry(pidFile, claim);   // retries a transient Windows AV/indexer lock
  } catch (_e) {
    return false;   // pidFile vanished between the pre-check and the claim (stop() / a restart) — nothing to reap
  }
  // We now exclusively hold `claim`. Verify ownership against it (not pidFile) so
  // the check and the removal act on the same file; a restart that rewrites
  // pidFile after our rename creates a fresh, separate pidfile we never touch.
  var mine = false;
  try { mine = String(readPid(claim)) === String(childPid); } catch (_e2) { mine = false; }
  if (mine) {
    try { nodeFs.unlinkSync(claim); } catch (_e3) { /* best-effort reap — the sidecar is already off pidFile */ }
  } else {
    // Not ours (a fast restart's newer pidfile, or an unreadable one) — put it
    // back so stop() still finds the running daemon's sidecar, but ONLY if nothing
    // newer has since taken pidFile's place. linkSync is atomic and fails with
    // EEXIST when a still-newer daemon already wrote pidFile during our inspection,
    // so the restore never clobbers the newest pidfile with our older claimed one
    // (a plain rename would). A NON-EEXIST failure means hard links aren't
    // available on this filesystem (ENOTSUP on FAT / some network mounts), where
    // nothing newer is present — fall back to a plain rename so the pidfile isn't
    // lost entirely (it may clobber, but losing the running daemon's pidfile is
    // worse). Either way, drop our claim afterward.
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
  /* c8 ignore next -- every caller gates on a truthy logFile string, so this guard never returns null */
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
    /* c8 ignore next -- _stopPolling clears the interval on the first fire, so _maybeFire can't re-enter with fired=true */
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
    // Boot-death window is measured from the moment the child was spawned. An
    // abnormal exit within it is a boot failure; a later one is a normal
    // run/crash. Operators tune it for a slow-booting child (default 5s).
    var spawnedAt = Date.now();
    var bootWindowMs = (typeof opts.bootDeathWindowMs === "number")
      ? opts.bootDeathWindowMs : BOOT_DEATH_WINDOW_MS;
    // A bad command does NOT throw synchronously from spawn — child_process
    // reports it ASYNC via a 'error' event, with child.pid left undefined. The
    // sync try/catch above only covers spawn() itself, so without this the old
    // path wrote "undefined\n" to the pidFile and returned success. Subscribe a
    // one-shot 'error' handler that reaps the sidecar + audits the failure, then
    // refuse to proceed for a child that never got a pid.
    child.on("error", function (err) {
      // Reap ONLY a pidfile this child actually wrote. A numeric pid means the
      // sync path below wrote one, and the claim-then-verify reap removes only its
      // own sidecar (never a fast restart's). A no-pid spawn failure (child.pid
      // undefined) throws below BEFORE any pidfile write, so this late-firing
      // callback must not touch pidFile at all — else a caller that catches that
      // sync throw and retries with the same pidFile would have its replacement
      // daemon's pidfile deleted. (A numeric-but-invalid pid never reaches here:
      // child_process yields a positive int or undefined, and either way the
      // claim-then-verify reap only removes a sidecar recording that exact pid.)
      if (typeof child.pid === "number") {
        _reapOwnStalePidfile(pidFile, child.pid);
      }
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
    // Clear any STALE stop marker before claiming this pidfile: a stopper that was
    // SIGKILLed mid-stop leaves `<pidFile>.stopping` behind, and if the OS later
    // reuses that stopped pid for THIS fresh child, the stale marker would
    // wrongly suppress a genuine boot-death audit. A fresh start means no stop is
    // in flight, so the marker can only be stale.
    try { nodeFs.unlinkSync(_stoppingMarkerPath(pidFile)); } catch (_sm) { /* best-effort — usually absent */ }
    var pidStr = String(child.pid) + "\n";
    atomicFile.writeSync(pidFile, pidStr, { fileMode: 0o600 });
    // A detached child can spawn cleanly (valid pid above) yet DIE AT BOOT —
    // exit before it ever serves. The synchronous success handle is already
    // committed (detached mode returns immediately, so the sync return contract
    // stands), so recover asynchronously: a one-shot 'exit' handler reaps the
    // sidecar we just wrote — but ONLY when the pidFile still records THIS
    // child's pid, so a fast operator restart that rewrote it is never
    // clobbered — and audits the boot death so it leaves a trail instead of a
    // silently-stranded pidfile that daemon.stop would misread as running.
    // bootWatch (installed after this handler) holds the parent loop open through
    // the boot window so a short-lived launcher can't exit before observing the
    // death; the handler clears it the instant the child exits.
    var bootWatch = null;
    child.on("exit", function (code, signal) {
      if (bootWatch) { clearTimeout(bootWatch); bootWatch = null; }   // death observed — release the loop
      // Was the sidecar still OURS at exit? Atomically claim-then-verify (see
      // _reapOwnStalePidfile) so a fast operator restart that rewrote the pidfile
      // can't make us delete the NEW daemon's sidecar, and so the boot-death
      // signal survives a swallowed unlink failure. A stop() or a restart that
      // rewrote/cleared it means someone else owns it now — not a boot death.
      var wasOurs = _reapOwnStalePidfile(pidFile, child.pid);
      // Only a BOOT DEATH is a spawn failure: an ABNORMAL exit (non-zero code or
      // a terminating signal) SHORTLY after spawn, while the sidecar was still
      // ours (nobody stop()'d it). A clean exit (code 0), a later run/crash, or
      // an operator stop() is NOT a spawn failure — auditing those as one emits a
      // contradictory failure alongside the daemon.stopped record.
      var abnormal   = (typeof code === "number" && code !== 0) || signal != null;
      var withinBoot = (Date.now() - spawnedAt) <= bootWindowMs;
      // stop() (this process OR another) sends SIGTERM but unlinks the pidfile
      // only after observing the exit, so wasOurs is still true here. A
      // `<pidFile>.stopping` marker holding THIS child's pid means an operator
      // stop is in flight, so the exit is intentional — not a boot death that
      // should emit spawn_failed right before daemon.stopped.
      // Read the marker through the HARDENED pid-sidecar reader (1 KiB cap,
      // refuse-symlink, positive-int parse, null on any failure) — the marker
      // lives in the pidfile directory, so a raw readFileSync here would follow a
      // planted symlink or buffer an unbounded file (CWE-59 / DoS), the exact
      // threat _readPidFile hardens the pid read against. null (no/garbage marker)
      // !== child.pid, so a missing marker correctly reads as "not being stopped".
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
    // Keep the parent event loop alive through the boot-death window so the exit
    // handler above can actually observe a child that dies at boot. A short-lived
    // launcher (e.g. `blamejs daemon start`) would otherwise reach child.unref()
    // and exit before the child dies — stranding the pidfile for a later stop()
    // to misread, the very failure the handler exists to prevent. The timer is
    // ref'd (holds the loop), is cleared the instant the child exits, and
    // otherwise fires a no-op once the window elapses (boot succeeded → release
    // the loop, which child.unref() no longer holds). bootDeathWindowMs:0 opts
    // out entirely: no monitor, immediate exit (historical fire-and-forget).
    if (bootWindowMs > 0) {
      bootWatch = setTimeout(function () { bootWatch = null; }, bootWindowMs);
    }
    // Detach so a HEALTHY long-running child never holds the parent open past the
    // boot window (bootWatch is the only remaining ref, and it self-clears).
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
      /* c8 ignore next -- pidLock.release() swallows its own fs errors, so this guard never catches */
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
    // Stale — clean up and report.
    try { nodeFs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    _safeAuditEmit("daemon.stale_pid_cleaned", "success", { pidFile: pidFile, stalePid: pid });
    return { stopped: false, pid: pid, reason: "stale" };
  }

  // Publish a `<pidFile>.stopping` marker (holding the pid we are stopping) so the
  // boot-death exit handler — in THIS process or the still-alive starter of a
  // cross-process stop — treats the SIGTERM-induced exit as intentional, not a
  // boot death. The finally removes it on every exit (return OR a kill-failed
  // throw) so a later start() at the same path is never suppressed.
  var stopMarker = _stoppingMarkerPath(pidFile);
  try { atomicFile.writeSync(stopMarker, String(pid), { fileMode: 0o600 }); } catch (_w) { /* best-effort hint */ }
  try {
    return await _stopLivePid(pidFile, pid, signal, timeoutMs, pollMs, opts);
  } finally {
    try { nodeFs.unlinkSync(stopMarker); } catch (_u) { /* best-effort */ }
  }
}

// Signal a confirmed-live pid and wait for exit, escalating SIGTERM -> SIGKILL.
// Extracted from stop() so the .stopping marker wraps every exit via try/finally.
async function _stopLivePid(pidFile, pid, signal, timeoutMs, pollMs, opts) {
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
  _reapOwnStalePidfile: _reapOwnStalePidfile,
};
