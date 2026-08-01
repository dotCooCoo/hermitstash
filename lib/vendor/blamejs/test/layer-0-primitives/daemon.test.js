// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.daemon — pidfile + signal-handling + detached-fork tests.
 *
 * Run standalone: `node test/layer-0-primitives/daemon.test.js`
 * Or via smoke:   `node test/smoke.js`
 *
 * Detached-fork mode is exercised via a stubbed processSpawn.spawn so
 * the smoke run never fans out actual child processes (which would
 * race with the parallel runner and dirty the host PID namespace).
 * The stop() path is exercised against the current node process via
 * SIGUSR2 (no-op on POSIX, ignored on Windows so the test guards).
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var processSpawn = require("../../lib/process-spawn");

var atomicFile  = require("../../lib/atomic-file");

var _tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-daemon-test-"));
function _tmpFile(name) {
  return path.join(_tmpBase, Date.now() + "-" +
    Math.random().toString(36).slice(2, 8) + "-" + name);
}

// Temporarily present a different process.platform to start()/stop() so the
// POSIX code paths (detached-fork stdio, SIGTERM→SIGKILL escalation) are
// exercised on a win32 host too. process.platform is configurable (not
// writable), so it is swapped via a captured descriptor and restored.
function _withPlatform(plat) {
  var descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: plat, configurable: true, writable: true });
  return function restore() { Object.defineProperty(process, "platform", descriptor); };
}

function testDaemonSurface() {
  check("b.daemon namespace present",         typeof b.daemon === "object");
  check("b.daemon.start is a function",       typeof b.daemon.start === "function");
  check("b.daemon.stop is a function",        typeof b.daemon.stop === "function");
  check("DaemonError is a class",             typeof b.daemon.DaemonError === "function");
  check("DaemonError on frameworkError",      typeof b.frameworkError.DaemonError === "function");
}

function testDaemonStartRejectsBadOpts() {
  var threw = null;
  try { b.daemon.start({}); } catch (e) { threw = e; }
  check("daemon.start rejects empty opts",
        threw && /daemon\/bad-pid-file/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", signals: [] }); } catch (e) { threw = e; }
  check("daemon.start rejects empty signals[]",
        threw && /daemon\/bad-signals/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", args: ["a"] }); } catch (e) { threw = e; }
  check("daemon.start rejects args without command",
        threw && /daemon\/bad-args/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", bootDeathWindowMs: -1 }); } catch (e) { threw = e; }
  check("daemon.start rejects a negative bootDeathWindowMs",
        threw && /daemon\/bad-boot-window/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", bootDeathWindowMs: "soon" }); } catch (e) { threw = e; }
  check("daemon.start rejects a non-number bootDeathWindowMs",
        threw && /daemon\/bad-boot-window/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", bootDeathWindowMs: 3000000000 }); } catch (e) { threw = e; }
  check("daemon.start rejects a bootDeathWindowMs above setTimeout's 32-bit max",
        threw && /daemon\/bad-boot-window/.test(threw.code || ""));
}

function testDaemonStopRejectsBadOpts() {
  return b.daemon.stop({}).then(
    function () { check("daemon.stop({}) should throw", false); },
    function (e) {
      check("daemon.stop rejects empty opts",
            e && /daemon\/bad-pid-file/.test(e.code || ""));
    }
  );
}

async function testDaemonStopOnMissingPidfile() {
  var pidFile = _tmpFile("missing.pid");
  var r = await b.daemon.stop({ pidFile: pidFile });
  check("stop(): missing pidfile -> stopped=false",  r.stopped === false);
  check("stop(): missing pidfile -> reason=no-pidfile", r.reason === "no-pidfile");
}

async function testDaemonStopReapsStalePid() {
  var pidFile = _tmpFile("stale.pid");
  // Write a PID that's almost certainly not alive.
  fs.writeFileSync(pidFile, "999999\n");
  var r = await b.daemon.stop({ pidFile: pidFile });
  check("stop(): stale pidfile -> stopped=false",       r.stopped === false);
  check("stop(): stale pidfile -> reason=stale",        r.reason === "stale");
  check("stop(): stale pidfile cleaned up",             !fs.existsSync(pidFile));
}

async function testDaemonStartDetachedSpawn() {
  var pidFile = _tmpFile("detached.pid");
  var logFile = _tmpFile("detached.log");
  // Stub processSpawn.spawn so we don't fan out a real child during smoke.
  var origSpawn = processSpawn.spawn;
  var captured  = null;
  processSpawn.spawn = function (cmd, args, opts) {
    captured = { cmd: cmd, args: args, opts: opts };
    return {
      pid:    424242,
      unref:  function () { /* test stub */ },
      on:     function () { /* test stub */ },
    };
  };
  try {
    var r = b.daemon.start({
      pidFile: pidFile,
      logFile: logFile,
      command: process.execPath,
      args:    ["-e", "process.exit(0)"],
    });
    check("detached: returned pid=424242",         r.pid === 424242);
    check("detached: mode=detached",               r.mode === "detached");
    check("detached: pidFile written",             fs.existsSync(pidFile));
    check("detached: pidFile contents = 424242",   String(fs.readFileSync(pidFile, "utf8")).trim() === "424242");
    check("detached: spawn was invoked",           captured !== null);
    check("detached: spawn opts.detached=true",    captured.opts.detached === true);
    // Issue #101 — POSIX inherits the parent's log FD via stdio so the
    // detached child writes to the operator's log file. Windows uses
    // `stdio: "ignore"` + `windowsHide: true` because inherited FDs go
    // invalid on parent exit there; the child opens its own log file.
    if (process.platform === "win32") {
      check("detached: stdio is 'ignore' on Windows",
        captured.opts.stdio === "ignore");
      check("detached: windowsHide=true on Windows",
        captured.opts.windowsHide === true);
    } else {
      check("detached: stdio is [ignore, fd, fd] on POSIX",
        Array.isArray(captured.opts.stdio) && captured.opts.stdio[0] === "ignore" &&
        typeof captured.opts.stdio[1] === "number" && captured.opts.stdio[1] === captured.opts.stdio[2]);
    }
  } finally {
    processSpawn.spawn = origSpawn;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }
  }
}

async function testDaemonStartRejectsLivePidfile() {
  var pidFile = _tmpFile("live.pid");
  // Write the current test process's PID — guaranteed live.
  fs.writeFileSync(pidFile, String(process.pid) + "\n");
  var threw = null;
  try {
    b.daemon.start({
      pidFile: pidFile,
      command: process.execPath,
      args:    ["-e", "process.exit(0)"],
    });
  } catch (e) { threw = e; }
  check("start(): refuses pidfile held by live PID",
        threw && /daemon\/already-running/.test(threw.code || ""));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

async function testDaemonStartForegroundAcquiresLock() {
  var pidFile = _tmpFile("foreground.pid");
  var r = b.daemon.start({
    pidFile: pidFile,
    signals: ["SIGUSR2"],          // SIGUSR2 chosen so test doesn't trip SIGINT/SIGTERM
  });
  try {
    check("foreground: pid is current pid",        r.pid === process.pid);
    check("foreground: mode=foreground",           r.mode === "foreground");
    check("foreground: pidFile written",           fs.existsSync(pidFile));
    check("foreground: pidFile contents = pid",
      String(fs.readFileSync(pidFile, "utf8")).trim() === String(process.pid));
    check("foreground: orchestrator returned",     typeof r.shutdown === "function");
  } finally {
    // Run shutdown to release pidLock + uninstall handlers.
    await r.orchestrator.shutdown();
    r.orchestrator._resetForTest();
    b.daemon._resetForTest();
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

async function testDaemonStaleCleanupOnStartReap() {
  var pidFile = _tmpFile("reap.pid");
  // Write a stale PID before the start() call.
  fs.writeFileSync(pidFile, "999998\n");
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () {
    return { pid: 12345, unref: function () {}, on: function () {} };
  };
  try {
    var r = b.daemon.start({
      pidFile: pidFile,
      command: process.execPath,
      args:    ["-e", "process.exit(0)"],
    });
    check("reap: spawn proceeded after stale cleanup", r.pid === 12345);
    check("reap: pidFile rewritten with new PID",
      String(fs.readFileSync(pidFile, "utf8")).trim() === "12345");
  } finally {
    processSpawn.spawn = origSpawn;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

function testDaemonStartRejectsMalformedOptTypes() {
  var threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", logFile: 123 }); } catch (e) { threw = e; }
  check("start(): non-string logFile -> daemon/bad-log-file",
        threw && /daemon\/bad-log-file/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", command: 123 }); } catch (e) { threw = e; }
  check("start(): non-string command -> daemon/bad-command",
        threw && /daemon\/bad-command/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", command: "/bin/true", args: "not-an-array" }); }
  catch (e) { threw = e; }
  check("start(): non-array args -> daemon/bad-args",
        threw && /daemon\/bad-args/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", signals: "SIGTERM" }); } catch (e) { threw = e; }
  check("start(): non-array signals -> daemon/bad-signals",
        threw && /daemon\/bad-signals/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", signals: ["SIGTERM", ""] }); } catch (e) { threw = e; }
  check("start(): empty-string signal element -> daemon/bad-signals",
        threw && /daemon\/bad-signals/.test(threw.code || ""));

  threw = null;
  try { b.daemon.start({ pidFile: "/tmp/x.pid", bogusOpt: true }); } catch (e) { threw = e; }
  check("start(): unknown opt refused by exhaustive shape",
        threw && /daemon\/bad-opts/.test(threw.code || ""));
}

// The documented `cwd` opt (foreground-agnostic; forwarded to the detached
// child's spawn) must be accepted and threaded through to processSpawn. It
// was rejected by the exhaustive opts shape (undeclared field) despite being
// advertised in @opts — a passing operator call threw daemon/bad-opts.
async function testDaemonStartForwardsCwdToDetachedChild() {
  var pidFile = _tmpFile("cwd.pid");
  var chosenCwd = _tmpBase;
  var origSpawn = processSpawn.spawn;
  var captured = null;
  processSpawn.spawn = function (cmd, args, opts) {
    captured = { cmd: cmd, args: args, opts: opts };
    return { pid: 515151, unref: function () {}, on: function () {} };
  };
  try {
    var r = b.daemon.start({
      pidFile: pidFile,
      command: process.execPath,
      args:    ["-e", "process.exit(0)"],
      cwd:     chosenCwd,
    });
    check("cwd: documented opt accepted (no daemon/bad-opts)", r.pid === 515151);
    check("cwd: forwarded to processSpawn opts.cwd", captured && captured.opts.cwd === chosenCwd);
  } finally {
    processSpawn.spawn = origSpawn;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

async function testDaemonStopRejectsMalformedNumericOpts() {
  async function expect(opts, codeRe, label) {
    var threw = null;
    try { await b.daemon.stop(opts); } catch (e) { threw = e; }
    check(label, threw && codeRe.test(threw.code || ""));
  }
  await expect({ pidFile: "/tmp/x.pid", signal: 123 }, /daemon\/bad-signal/,
    "stop(): non-string signal -> daemon/bad-signal");
  await expect({ pidFile: "/tmp/x.pid", timeoutMs: -1 }, /daemon\/bad-timeout/,
    "stop(): negative timeoutMs -> daemon/bad-timeout");
  await expect({ pidFile: "/tmp/x.pid", timeoutMs: 0 }, /daemon\/bad-timeout/,
    "stop(): zero timeoutMs -> daemon/bad-timeout");
  await expect({ pidFile: "/tmp/x.pid", timeoutMs: 1.5 }, /daemon\/bad-timeout/,
    "stop(): non-integer timeoutMs -> daemon/bad-timeout");
  await expect({ pidFile: "/tmp/x.pid", timeoutMs: Infinity }, /daemon\/bad-timeout/,
    "stop(): Infinity timeoutMs -> daemon/bad-timeout");
  await expect({ pidFile: "/tmp/x.pid", pollMs: -5 }, /daemon\/bad-poll/,
    "stop(): negative pollMs -> daemon/bad-poll");
  await expect({ pidFile: "/tmp/x.pid", pollMs: NaN }, /daemon\/bad-poll/,
    "stop(): NaN pollMs -> daemon/bad-poll");
}

// stop() drives process.kill through three failure/edge branches that can't
// be reached with a real long-lived child inside smoke. We stub the global
// kill seam (restored in finally) to steer each branch deterministically.
// These edge branches are the POSIX signal path: on Windows process.kill maps
// any real signal to TerminateProcess, so stop() drives the cooperative
// stop-request sentinel instead (SIGTERM→ESRCH→SIGKILL has no analogue there).
// The Windows cooperative + terminate branches are covered by
// testDaemonStopWin32CooperativeStop.
async function testDaemonStopKillRaceAndEscalation() {
  if (process.platform === "win32") {
    check("kill-race edge branches are POSIX-only (win32 uses cooperative stop)", true);
    return;
  }
  var origKill = process.kill;

  // (1) Target dies between pidfile read and the first signal (ESRCH on the
  //     real kill) -> reported stopped=true with the original signal, pidfile
  //     cleaned, no escalation.
  var pidFile = _tmpFile("race.pid");
  fs.writeFileSync(pidFile, "4242\n");
  process.kill = function (pid, sig) {
    if (sig === 0) return true;                 // liveness probe: alive
    var err = new Error("no such process"); err.code = "ESRCH"; throw err;
  };
  try {
    var r1 = await b.daemon.stop({ pidFile: pidFile, signal: "SIGTERM" });
    check("stop(): ESRCH between read+kill -> stopped=true", r1.stopped === true);
    check("stop(): ESRCH race keeps original signal",        r1.signal === "SIGTERM");
    check("stop(): ESRCH race did not escalate",             r1.escalated === undefined);
    check("stop(): ESRCH race cleaned pidfile",              !fs.existsSync(pidFile));
  } finally { process.kill = origKill; }

  // (2) kill() fails with a non-ESRCH error (e.g. EINVAL bad signal name) ->
  //     surfaced as a typed daemon/kill-failed, never an uncaught throw.
  var pidFile2 = _tmpFile("killfail.pid");
  fs.writeFileSync(pidFile2, "4243\n");
  process.kill = function (pid, sig) {
    if (sig === 0) return true;
    var err = new Error("invalid signal"); err.code = "EINVAL"; throw err;
  };
  var threw = null;
  try { await b.daemon.stop({ pidFile: pidFile2, signal: "SIGTERM" }); }
  catch (e) { threw = e; }
  finally { process.kill = origKill; }
  check("stop(): non-ESRCH kill error -> daemon/kill-failed",
        threw && /daemon\/kill-failed/.test(threw.code || ""));
  try { fs.unlinkSync(pidFile2); } catch (_e) { /* best-effort */ }

  // (3) Target ignores SIGTERM past timeoutMs -> escalate to SIGKILL. The stub
  //     reports the pid alive until SIGKILL lands, then dead.
  var pidFile3 = _tmpFile("escalate.pid");
  fs.writeFileSync(pidFile3, "4244\n");
  var killed = false;
  process.kill = function (pid, sig) {
    if (sig === 0) {
      if (killed) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
      return true;
    }
    if (sig === "SIGKILL") { killed = true; return true; }
    return true;   // SIGTERM: swallowed, process keeps running
  };
  try {
    var r3 = await b.daemon.stop({ pidFile: pidFile3, signal: "SIGTERM", timeoutMs: 20, pollMs: 5 });
    check("stop(): unresponsive child escalates -> escalated=true", r3.escalated === true);
    check("stop(): escalation reports signal=SIGKILL",              r3.signal === "SIGKILL");
    check("stop(): escalation cleaned pidfile",                     !fs.existsSync(pidFile3));
  } finally {
    process.kill = origKill;
    try { fs.unlinkSync(pidFile3); } catch (_e) { /* best-effort */ }
  }
}

// Foreground start with a logFile opens an O_NOFOLLOW append fd (mode 0600)
// and redirects the current process's stdout/stderr to it. Verify the
// redirect actually routes writes into the log — restoring the real writers
// before any assertion so the harness output is never swallowed.
async function testDaemonForegroundLogRedirect() {
  var pidFile = _tmpFile("fg-log.pid");
  var logFile = _tmpFile("fg-log.log");
  var origOut = process.stdout.write;
  var origErr = process.stderr.write;
  var r = null;
  var writerCbFired = false;
  try {
    r = b.daemon.start({ pidFile: pidFile, logFile: logFile, signals: ["SIGUSR2"] });
    process.stdout.write("daemon-redirect-probe-out\n");
    process.stderr.write("daemon-redirect-probe-err\n");
    // Exercise the redirected writer's argument shapes: an explicit encoding
    // string, a Buffer chunk (no re-encode), and a completion callback.
    process.stdout.write("daemon-redirect-enc\n", "utf8");
    process.stdout.write(Buffer.from("daemon-redirect-buf\n"));
    process.stdout.write("daemon-redirect-cb\n", function () { writerCbFired = true; });
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
  try {
    check("fg+log: mode=foreground", r && r.mode === "foreground");
    check("fg+log: logFile created", fs.existsSync(logFile));
    var mode = fs.statSync(logFile).mode & 0o777;
    // Windows fs collapses POSIX perm bits; only assert the strict mode on POSIX.
    if (process.platform !== "win32") {
      check("fg+log: logFile mode is 0600", mode === 0o600);
    }
    var content = fs.readFileSync(logFile, "utf8");
    check("fg+log: stdout redirected into logFile",
          content.indexOf("daemon-redirect-probe-out") !== -1);
    check("fg+log: stderr redirected into logFile",
          content.indexOf("daemon-redirect-probe-err") !== -1);
    check("fg+log: writer honored an explicit encoding arg",
          content.indexOf("daemon-redirect-enc") !== -1);
    check("fg+log: writer passed a Buffer chunk through",
          content.indexOf("daemon-redirect-buf") !== -1);
    check("fg+log: writer invoked the completion callback", writerCbFired === true);
  } finally {
    if (r) { await r.orchestrator.shutdown(); r.orchestrator._resetForTest(); }
    b.daemon._resetForTest();
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }
  }
}

// Foreground start where the logFile cannot be opened (a path component is a
// regular file, so ensureDir/open throws) must release the just-acquired
// pidLock and surface daemon/log-open-failed — not leak the lock.
async function testDaemonForegroundLogOpenFailedReleasesLock() {
  var pidFile = _tmpFile("fg-openfail.pid");
  var blocker = _tmpFile("blocker-file");
  fs.writeFileSync(blocker, "x");                 // a file, not a directory
  var logFile = path.join(blocker, "cannot", "here.log");
  var threw = null;
  try {
    b.daemon.start({ pidFile: pidFile, logFile: logFile, signals: ["SIGUSR2"] });
  } catch (e) { threw = e; }
  check("fg+log-open-fail: surfaced as daemon/log-open-failed",
        threw && /daemon\/log-open-failed/.test(threw.code || ""));
  check("fg+log-open-fail: pidLock released (pidFile gone)", !fs.existsSync(pidFile));
  // Lock is free again: a second start on the same pidFile must succeed.
  var r2 = null;
  try {
    r2 = b.daemon.start({ pidFile: pidFile, signals: ["SIGUSR2"] });
    check("fg+log-open-fail: pidFile reusable after failure", r2.mode === "foreground");
  } finally {
    if (r2) { await r2.orchestrator.shutdown(); r2.orchestrator._resetForTest(); }
    b.daemon._resetForTest();
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(blocker); } catch (_e) { /* best-effort */ }
  }
}

// #498 — daemon.status(): a READ-ONLY PID-liveness probe. Unlike stop() it
// never unlinks the pidfile (a status check must not mutate the daemon's
// lifecycle state), returns { running, pid, reason? }, and refuses hostile
// pidfiles (symlink / oversized) as not-running rather than throwing.
async function testDaemonStatusReadOnlyProbe() {
  check("status: b.daemon.status is a function", typeof b.daemon.status === "function");
  if (typeof b.daemon.status !== "function") return;   // remaining asserts need the export

  // Missing pidfile -> not running, no pid.
  var missing = _tmpFile("status-missing.pid");
  var s1 = b.daemon.status({ pidFile: missing });
  check("status: missing -> running=false",       s1.running === false);
  check("status: missing -> pid=null",            s1.pid === null);
  check("status: missing -> reason=no-pidfile",   s1.reason === "no-pidfile");

  // Live (our own PID, guaranteed alive) -> running with our pid.
  var livePid = _tmpFile("status-live.pid");
  fs.writeFileSync(livePid, String(process.pid) + "\n");
  var s2 = b.daemon.status({ pidFile: livePid });
  check("status: live -> running=true",           s2.running === true);
  check("status: live -> pid = our pid",          s2.pid === process.pid);
  check("status: live pidfile NOT unlinked (read-only)", fs.existsSync(livePid));
  try { fs.unlinkSync(livePid); } catch (_e) { /* best-effort */ }

  // Stale (dead PID) -> not running, reason=stale, AND pidfile left in place.
  var stalePid = _tmpFile("status-stale.pid");
  fs.writeFileSync(stalePid, "999999\n");
  var s3 = b.daemon.status({ pidFile: stalePid });
  check("status: stale -> running=false",         s3.running === false);
  check("status: stale -> pid=999999",            s3.pid === 999999);
  check("status: stale -> reason=stale",          s3.reason === "stale");
  check("status: stale pidfile NOT unlinked (read-only)", fs.existsSync(stalePid));
  try { fs.unlinkSync(stalePid); } catch (_e) { /* best-effort */ }

  // Oversized pidfile (> 1 KiB cap) -> refused as not-running, never throws.
  var oversized = _tmpFile("status-oversized.pid");
  fs.writeFileSync(oversized, "1".repeat(2048));
  var s4 = null, s4Threw = null;
  try { s4 = b.daemon.status({ pidFile: oversized }); } catch (e) { s4Threw = e; }
  check("status: oversized pidfile does not throw", s4Threw === null);
  check("status: oversized pidfile -> running=false", s4 && s4.running === false);
  try { fs.unlinkSync(oversized); } catch (_e) { /* best-effort */ }

  // Symlink pidfile -> refused (O_NOFOLLOW) as not-running, never throws.
  // Windows may lack symlink-create privilege; skip the case if so.
  var symTarget = _tmpFile("status-symtarget.pid");
  fs.writeFileSync(symTarget, String(process.pid) + "\n");
  var symLink = _tmpFile("status-symlink.pid");
  var symMade = false;
  try { fs.symlinkSync(symTarget, symLink); symMade = true; } catch (_e) { /* no symlink priv */ }
  if (symMade) {
    var s5 = null, s5Threw = null;
    try { s5 = b.daemon.status({ pidFile: symLink }); } catch (e) { s5Threw = e; }
    check("status: symlink pidfile does not throw", s5Threw === null);
    check("status: symlink pidfile -> running=false (refused)", s5 && s5.running === false);
    try { fs.unlinkSync(symLink); } catch (_e) { /* best-effort */ }
  } else {
    check("status: symlink case skipped (no symlink privilege)", true);
  }
  try { fs.unlinkSync(symTarget); } catch (_e) { /* best-effort */ }

  // Bad opts -> config-time throw (same code the start/stop validators use).
  var badThrew = null;
  try { b.daemon.status({}); } catch (e) { badThrew = e; }
  check("status: bad opts -> daemon/bad-pid-file",
        badThrew && /daemon\/bad-pid-file/.test(badThrew.code || ""));
}

// #499 — a detached spawn that fails ASYNC leaves child.pid === undefined; the
// try/catch only wraps the SYNCHRONOUS spawn call, so the old path wrote
// "undefined\n" to the pidfile and reported success unconditionally. start()
// must validate child.pid BEFORE any pidfile write and throw daemon/spawn-failed.
async function testDaemonStartDetachedSpawnFailureUndefinedPid() {
  var pidFile = _tmpFile("spawnfail.pid");
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () {
    // Model an async spawn failure: the OS never launched the exec, so the
    // returned child object carries no pid (the real failure arrives later
    // via a 'error' event).
    return { pid: undefined, unref: function () {}, on: function () {} };
  };
  var threw = null;
  try {
    b.daemon.start({ pidFile: pidFile, command: "/nonexistent/cmd", args: [] });
  } catch (e) { threw = e; }
  finally { processSpawn.spawn = origSpawn; }
  check("spawn-fail: undefined child.pid -> daemon/spawn-failed",
        threw && /daemon\/spawn-failed/.test(threw.code || ""));
  check("spawn-fail: pidfile NOT written with 'undefined'",
        !fs.existsSync(pidFile) ||
        String(fs.readFileSync(pidFile, "utf8")).trim() !== "undefined");
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// #499 — a valid detached spawn must subscribe a one-shot child 'error' handler
// so an async launch failure after a valid initial pid still reaps the pidfile
// + audits, instead of leaving a stale sidecar for a child that never ran.
async function testDaemonStartDetachedSubscribesErrorHandler() {
  var pidFile = _tmpFile("spawn-errsub.pid");
  var origSpawn = processSpawn.spawn;
  var subscribed = Object.create(null);
  processSpawn.spawn = function () {
    return {
      pid:   434343,
      unref: function () {},
      on:    function (event) { subscribed[event] = true; },
    };
  };
  try {
    var r = b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "0"] });
    check("spawn-errsub: detached start succeeded with valid pid", r.pid === 434343);
    check("spawn-errsub: start subscribed a child 'error' handler", subscribed.error === true);
  } finally {
    processSpawn.spawn = origSpawn;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// #499 — a detached child that spawns fine but DIES AT BOOT (exits non-zero
// before it ever serves) must not strand a live pidfile that daemon.stop would
// later misread as a running service. start() keeps its synchronous
// success-handle contract (detached mode returns immediately), but a one-shot
// child 'exit' handler reaps the sidecar the moment the child dies — only when
// the pidfile still records THIS child's pid, so a fast restart isn't clobbered
// — and audits daemon.spawn_failed with the exit code. Uses a REAL short-lived
// spawn (node -e process.exit(1)) so the async 'exit' event actually fires;
// the reap is polled via helpers.waitUntil rather than a fixed sleep.
async function testDaemonStartDetachedBootDeathReapsPidfile() {
  var pidFile = _tmpFile("bootdeath.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  var r = null;
  try {
    r = b.daemon.start({
      pidFile: pidFile,
      command: process.execPath,
      args:    ["-e", "process.exit(1)"],
    });
    check("boot-death: detached start returned a live pid",
      typeof r.pid === "number" && r.pid > 0);
    check("boot-death: mode=detached",            r.mode === "detached");
    check("boot-death: pidFile written on start", fs.existsSync(pidFile));
    // The child dies at boot; poll for the one-shot exit handler to reap it.
    await helpers.waitUntil(function () { return !fs.existsSync(pidFile); }, {
      timeoutMs: 5000,
      label:     "boot-death: child exit reaps the stale pidfile",
    });
    check("boot-death: pidfile reaped after child exit", !fs.existsSync(pidFile));
    check("boot-death: daemon.spawn_failed audit emitted with exit code",
      captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" && e.outcome === "failure" &&
               e.metadata && e.metadata.pidFile === pidFile && e.metadata.exitCode === 1;
      }));
  } finally {
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// A detached child that exits CLEANLY (code 0) is a normal completion, not a
// boot failure: the one-shot exit handler still reaps the stale sidecar, but must
// NOT emit daemon.spawn_failed. A clean exit (or a graceful stop() that exits 0)
// is not a spawn failure, and auditing it as one emits a contradictory failure
// alongside the daemon.stopped record.
async function testDaemonStartDetachedCleanExitNoSpawnFailed() {
  var pidFile = _tmpFile("cleanexit.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    var r = b.daemon.start({
      pidFile: pidFile, command: process.execPath, args: ["-e", "process.exit(0)"],
    });
    check("clean-exit: detached start returned a live pid",
      typeof r.pid === "number" && r.pid > 0);
    await helpers.waitUntil(function () { return !fs.existsSync(pidFile); }, {
      timeoutMs: 5000, label: "clean-exit: child exit reaps the stale pidfile",
    });
    check("clean-exit: pidfile still reaped after a clean exit", !fs.existsSync(pidFile));
    check("clean-exit: no daemon.spawn_failed audit for a code-0 exit",
      !captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" &&
               e.metadata && e.metadata.pidFile === pidFile;
      }));
  } finally {
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// An abnormal child exit AFTER the boot window is a normal run/crash, not a spawn
// failure. bootDeathWindowMs:0 puts every exit past the window, so even an
// immediate abnormal exit is NOT audited as a boot death (the sidecar is still
// reaped). This is the operator-tunable knob for a slow-booting child.
async function testDaemonStartDetachedAbnormalPastBootWindow() {
  var pidFile = _tmpFile("pastwindow.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.daemon.start({
      pidFile: pidFile, command: process.execPath, args: ["-e", "process.exit(1)"],
      bootDeathWindowMs: 0,
    });
    await helpers.waitUntil(function () { return !fs.existsSync(pidFile); }, {
      timeoutMs: 5000, label: "past-window: child exit reaps the stale pidfile",
    });
    check("past-window: pidfile reaped even for an out-of-window exit", !fs.existsSync(pidFile));
    check("past-window: no daemon.spawn_failed for an abnormal exit past the boot window",
      !captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" &&
               e.metadata && e.metadata.pidFile === pidFile;
      }));
  } finally {
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// A short-lived launcher (the primary detached scenario: `daemon start` spawns
// the daemon then exits) must still observe a boot death. child.unref() lets the
// launcher's loop drain immediately, so without a ref'd boot-window timer the
// launcher exits BEFORE the child dies and the pidfile is stranded for a later
// stop() to misread. This spawns a REAL short launcher (requires lib/daemon,
// starts a child that dies at ~300ms, then does nothing else); with the timer it
// lingers on its own, observes the death, and reaps the pidfile before exiting.
async function testDaemonBootWindowSurvivesShortLauncher() {
  var pidFile    = _tmpFile("shortlauncher.pid");
  var daemonPath = require.resolve("../../lib/daemon.js");
  var script =
    "var d=require(" + JSON.stringify(daemonPath) + ");" +
    "d.start({pidFile:" + JSON.stringify(pidFile) + ",command:process.execPath," +
    "args:['-e','setTimeout(function(){process.exit(1)},300)'],bootDeathWindowMs:4000});";
  await new Promise(function (resolve, reject) {
    var cp = processSpawn.spawn(process.execPath, ["-e", script], { stdio: "ignore" });
    cp.once("exit",  function () { resolve(); });
    cp.once("error", reject);
  });
  // The launcher has fully exited. If the boot-window timer held it open, it
  // observed the ~300ms child death and reaped the sidecar; otherwise it exited
  // at once and the sidecar is stranded.
  check("boot-window: a short launcher lingers through the window and reaps a boot-dead child's pidfile",
        !fs.existsSync(pidFile));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// When the SAME process that called start() also stop()s the daemon within the
// boot window, stop() sends SIGTERM but unlinks the pidfile only after the exit,
// so the boot-death handler sees wasOurs + a signal + withinBoot. Without the
// _STOPPING mark it would emit daemon.spawn_failed right before daemon.stopped —
// a contradictory failure audit for an intentional stop.
async function testDaemonSameProcessStopWithinBootWindowNoSpawnFailed() {
  var pidFile = _tmpFile("sameproc-stop.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.daemon.start({
      pidFile: pidFile, command: process.execPath,
      args: ["-e", "setInterval(function(){}, 1000)"],   // long-lived child
      bootDeathWindowMs: 3000,                           // wide window so the stop lands inside it
    });
    // Low timeout: on win32 the raw child doesn't watch the cooperative sentinel,
    // so stop() escalates to a hard kill after the timeout — keep it short.
    var r = await b.daemon.stop({ pidFile: pidFile, timeoutMs: 600, pollMs: 25 });
    check("same-proc-stop: stop reported the daemon stopped", r && r.stopped === true);
    // Give any (suppressed) exit-handler audit path a beat to run.
    await helpers.passiveObserve(200, "same-proc-stop: no spawn_failed after a same-process stop");
    check("same-proc-stop: no daemon.spawn_failed for an operator stop in the boot window",
      !captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" && e.metadata && e.metadata.pidFile === pidFile;
      }));
    check("same-proc-stop: a daemon.stopped audit WAS emitted",
      captured.some(function (e) { return e && e.action === "daemon.stopped"; }));
  } finally {
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// A DIFFERENT process calling stop() during the boot window: the exit handler
// runs in the still-alive STARTER (this process), which has no in-process stop
// flag. The `<pidFile>.stopping` filesystem marker (written by the stopper, read
// by the starter's handler) suppresses the spurious spawn_failed cross-process.
async function testDaemonCrossProcessStopWithinBootWindowNoSpawnFailed() {
  var pidFile    = _tmpFile("crossproc-stop.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    // THIS process is the starter — it keeps the child's exit handler alive.
    b.daemon.start({
      pidFile: pidFile, command: process.execPath,
      args: ["-e", "setInterval(function(){}, 1000)"],
      bootDeathWindowMs: 3000,
    });
    // A SEPARATE process stops it (requires lib/daemon directly).
    var daemonPath = require.resolve("../../lib/daemon.js");
    var script =
      "require(" + JSON.stringify(daemonPath) + ").stop({pidFile:" + JSON.stringify(pidFile) +
      ",timeoutMs:600,pollMs:25}).then(function(){process.exit(0);},function(){process.exit(1);});";
    await new Promise(function (resolve) {
      var cp = processSpawn.spawn(process.execPath, ["-e", script], { stdio: "ignore" });
      cp.once("exit", function () { resolve(); });
    });
    // The other process killed the child; our exit handler ran. Give it a beat.
    await helpers.passiveObserve(200, "cross-proc-stop: no spawn_failed after a cross-process stop");
    check("cross-proc-stop: no daemon.spawn_failed for a cross-process stop in the boot window",
      !captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" && e.metadata && e.metadata.pidFile === pidFile;
      }));
  } finally {
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// The .stopping marker is a best-effort hint — a failed write (publishing it) or
// a failed unlink (removing it) must not break stop(). Force both to throw for
// the marker path only; stop() still terminates the daemon.
async function testDaemonStopMarkerFsFailuresSwallowed() {
  var pidFile = _tmpFile("stopmarker-fsfail.pid");
  b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "setInterval(function(){}, 1000)"] });
  var realWrite = atomicFile.writeSync, realUnlink = fs.unlinkSync;
  atomicFile.writeSync = function (p) {
    if (String(p).endsWith(".stopping")) throw new Error("marker write boom");
    return realWrite.apply(atomicFile, arguments);
  };
  fs.unlinkSync = function (p) {
    if (String(p).endsWith(".stopping")) throw new Error("marker unlink boom");
    return realUnlink.apply(fs, arguments);
  };
  try {
    var r = await b.daemon.stop({ pidFile: pidFile, timeoutMs: 600, pollMs: 25 });
    check("stop: swallows a .stopping marker write/unlink failure and still stops",
          r && r.stopped === true);
  } finally {
    atomicFile.writeSync = realWrite; fs.unlinkSync = realUnlink;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(pidFile + ".stopping"); } catch (_e) { /* best-effort */ }
  }
}

// A stopper SIGKILLed mid-stop leaves a stale <pidFile>.stopping marker; if the
// OS later reuses that stopped pid for a fresh child, the stale marker would
// wrongly suppress the new child's genuine boot-death audit. A fresh start()
// clears it (no stop is in flight when a daemon is starting).
async function testDaemonStartClearsStaleStoppingMarker() {
  var pidFile = _tmpFile("stalestop.pid");
  var marker  = pidFile + ".stopping";
  fs.writeFileSync(marker, "99999");   // stale marker left by a dead stopper
  b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "process.exit(0)"] });
  check("start() clears a stale .stopping marker before claiming the pidfile",
        !fs.existsSync(marker));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(marker); } catch (_e) { /* best-effort */ }
}

// #500 — on win32 process.kill(pid, "SIGTERM") maps to TerminateProcess (a hard
// kill), so the graceful appShutdown orchestration is unreachable via signals.
// stop() must instead write a cooperative <pidFile>.stop sentinel, poll for the
// daemon to exit, and escalate to TerminateProcess ONLY on timeout — reporting
// a `mechanism` that distinguishes the cooperative exit from the forced one.
async function testDaemonStopWin32CooperativeStop() {
  if (process.platform !== "win32") {
    check("cooperative-stop test skipped on non-win32 (POSIX uses signals)", true);
    return;
  }
  var origKill = process.kill;

  // (A) Cooperative: the daemon exits once it observes the stop-request file.
  var pidFile  = _tmpFile("coop.pid");
  var sentinel = pidFile + ".stop";
  fs.writeFileSync(pidFile, "5252\n");
  var terminatedA = false;
  process.kill = function (pid, sig) {
    if (sig === 0) {
      // Liveness probe: model a cooperative daemon that exits the moment it
      // sees the sentinel stop() writes.
      if (fs.existsSync(sentinel)) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
      return true;
    }
    terminatedA = true;             // any real signal on win32 = TerminateProcess
    return true;
  };
  try {
    var rA = await b.daemon.stop({ pidFile: pidFile, timeoutMs: 2000, pollMs: 5 });
    check("win32 stop: cooperative graceful exit -> stopped=true", rA.stopped === true);
    check("win32 stop: mechanism=cooperative",                     rA.mechanism === "cooperative");
    check("win32 stop: no hard TerminateProcess on graceful exit", terminatedA === false);
    check("win32 stop: cooperative did not escalate",              rA.escalated === undefined);
    check("win32 stop: sentinel cleaned up",                       !fs.existsSync(sentinel));
    check("win32 stop: pidfile cleaned up",                        !fs.existsSync(pidFile));
  } finally {
    process.kill = origKill;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sentinel); } catch (_e) { /* best-effort */ }
  }

  // (B) Forced: the daemon ignores the sentinel past the timeout -> escalate to
  // TerminateProcess, reported as mechanism=terminate + escalated=true.
  var pidFile2  = _tmpFile("coop-forced.pid");
  var sentinel2 = pidFile2 + ".stop";
  fs.writeFileSync(pidFile2, "5253\n");
  var terminatedB = false;
  process.kill = function (pid, sig) {
    if (sig === 0) {
      if (terminatedB) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
      return true;                  // stays alive despite the sentinel
    }
    terminatedB = true;             // TerminateProcess escalation
    return true;
  };
  try {
    var rB = await b.daemon.stop({ pidFile: pidFile2, timeoutMs: 30, pollMs: 5 });
    check("win32 stop: unresponsive daemon escalates -> escalated=true", rB.escalated === true);
    check("win32 stop: mechanism=terminate on escalation",               rB.mechanism === "terminate");
    check("win32 stop: TerminateProcess invoked on timeout",             terminatedB === true);
    check("win32 stop: forced path cleaned pidfile",                     !fs.existsSync(pidFile2));
    check("win32 stop: forced path cleaned sentinel",                    !fs.existsSync(sentinel2));
  } finally {
    process.kill = origKill;
    try { fs.unlinkSync(pidFile2); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sentinel2); } catch (_e) { /* best-effort */ }
  }
}

// #500 — the other half of the cooperative channel: a foreground start() on
// win32 must install a watcher on the sibling <pidFile>.stop sentinel so a
// stop() from another process routes into the SAME appShutdown orchestrator the
// POSIX signal path uses.
async function testDaemonStartWin32CooperativeStopWatcher() {
  if (process.platform !== "win32") {
    check("cooperative stop-watcher test skipped on non-win32", true);
    return;
  }
  var pidFile  = _tmpFile("coop-fg.pid");
  var sentinel = pidFile + ".stop";
  var r = b.daemon.start({ pidFile: pidFile, signals: ["SIGUSR2"] });
  try {
    check("coop-watcher: foreground start returned", r && r.mode === "foreground");
    // Model daemon.stop()'s cooperative request by writing the sentinel.
    fs.writeFileSync(sentinel, String(process.pid) + "\n");
    await helpers.waitUntil(function () { return r.orchestrator.draining() === true; },
      { timeoutMs: 5000, label: "coop-watcher: sentinel triggers orchestrator shutdown" });
    check("coop-watcher: sentinel routed into graceful shutdown",
          r.orchestrator.draining() === true);
  } finally {
    try { await r.orchestrator.shutdown(); } catch (_e) { /* best-effort */ }
    r.orchestrator._resetForTest();
    b.daemon._resetForTest();
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sentinel); } catch (_e) { /* best-effort */ }
  }
}

// _maybeReapStale must leave a pidfile held by a LIVE, DIFFERENT process alone
// (only truly-dead PIDs are reaped). process.ppid is guaranteed live and != our
// PID, so the detached path reports already-running without touching the file.
async function testDaemonReapStaleLivePidDifferentProcess() {
  var pidFile = _tmpFile("reap-live-other.pid");
  fs.writeFileSync(pidFile, String(process.ppid) + "\n");
  var origSpawn = processSpawn.spawn;
  var spawned = false;
  processSpawn.spawn = function () { spawned = true; return { pid: 1, unref: function () {}, on: function () {} }; };
  var threw = null;
  try {
    b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "0"] });
  } catch (e) { threw = e; }
  finally { processSpawn.spawn = origSpawn; }
  check("reap-live-other: live foreign PID not reaped -> already-running",
        threw && /daemon\/already-running/.test(threw.code || ""));
  check("reap-live-other: spawn never attempted for a live-held pidfile", spawned === false);
  check("reap-live-other: pidfile left in place (not reaped)", fs.existsSync(pidFile));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// POSIX detached-fork stdio: with a logFile the parent opens the append fd and
// hands [ignore, fd, fd] to the child (Issue #101), windowsHide stays undefined,
// omitted args default to [], and the parent closes its own fd afterward. Without
// a logFile the child inherits nothing (stdio: "ignore").
async function testDaemonStartDetachedPosixLogFdStdio() {
  var restore = _withPlatform("linux");
  var origSpawn = processSpawn.spawn;
  try {
    // (1) POSIX + logFile → inherit-logfd branch.
    var pidFile = _tmpFile("posix-det.pid");
    var logFile = _tmpFile("posix-det.log");
    var cap = null;
    processSpawn.spawn = function (cmd, args, opts) {
      cap = { cmd: cmd, args: args, opts: opts };
      return { pid: 717171, unref: function () {}, on: function () {} };
    };
    var r = b.daemon.start({ pidFile: pidFile, logFile: logFile, command: process.execPath });
    check("posix-det: returned child pid", r.pid === 717171);
    check("posix-det: stdio = [ignore, fd, fd]",
          Array.isArray(cap.opts.stdio) && cap.opts.stdio[0] === "ignore" &&
          typeof cap.opts.stdio[1] === "number" && cap.opts.stdio[1] === cap.opts.stdio[2]);
    check("posix-det: windowsHide undefined on POSIX", cap.opts.windowsHide === undefined);
    check("posix-det: omitted args default to []", Array.isArray(cap.args) && cap.args.length === 0);
    check("posix-det: logFile opened", fs.existsSync(logFile));
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }

    // (2) POSIX + no logFile → stdio "ignore".
    var pidFile2 = _tmpFile("posix-det-nolog.pid");
    cap = null;
    processSpawn.spawn = function (cmd, args, opts) {
      cap = { cmd: cmd, args: args, opts: opts };
      return { pid: 727272, unref: function () {}, on: function () {} };
    };
    var r2 = b.daemon.start({ pidFile: pidFile2, command: process.execPath, args: [] });
    check("posix-det-nolog: stdio = 'ignore'", cap.opts.stdio === "ignore");
    check("posix-det-nolog: pid returned", r2.pid === 727272);
    try { fs.unlinkSync(pidFile2); } catch (_e) { /* best-effort */ }

    // (3) POSIX + logFile, spawn succeeds, but the parent's post-spawn fd close
    //     throws -> swallowed (best-effort); start() still reports started.
    var pidFile3 = _tmpFile("posix-det-closefail.pid");
    var logFile3 = _tmpFile("posix-det-closefail.log");
    var realClose = fs.closeSync;
    var capturedFd3 = null;
    var realOpen3 = atomicFile.openAppendNoFollowSync;
    atomicFile.openAppendNoFollowSync = function () {
      var fd = realOpen3.apply(atomicFile, arguments);
      capturedFd3 = fd;
      return fd;
    };
    processSpawn.spawn = function () { return { pid: 737373, unref: function () {}, on: function () {} }; };
    fs.closeSync = function (fd) {
      if (fd === capturedFd3) throw new Error("close boom");
      return realClose.apply(fs, arguments);
    };
    var r3 = null, e3 = null;
    try {
      r3 = b.daemon.start({ pidFile: pidFile3, logFile: logFile3, command: process.execPath, args: [] });
    } catch (e) { e3 = e; }
    fs.closeSync = realClose;
    atomicFile.openAppendNoFollowSync = realOpen3;
    check("posix-det-closefail: start still returns despite fd-close throw",
          e3 === null && r3 && r3.pid === 737373);
    try { fs.closeSync(capturedFd3); } catch (_e) { /* leak guard */ }
    try { fs.unlinkSync(pidFile3); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile3); } catch (_e) { /* best-effort */ }
  } finally {
    processSpawn.spawn = origSpawn;
    restore();
  }
}

// A detached spawn that throws synchronously surfaces as daemon/spawn-failed;
// on the POSIX path a parent log fd was opened, so start() closes it (best-effort)
// on the way out. The thrown value carries no `.message` to drive the String(e)
// fallback in the error text.
async function testDaemonStartDetachedSpawnThrowsSync() {
  var restore = _withPlatform("linux");
  var origSpawn = processSpawn.spawn;
  var realClose = fs.closeSync;
  try {
    var pidFile = _tmpFile("spawn-throw.pid");
    var logFile = _tmpFile("spawn-throw.log");
    // Non-Error-message throw: an empty .message forces the String(e) fallback.
    processSpawn.spawn = function () { throw new Error(""); };
    fs.closeSync = function () { throw new Error("close boom"); };  // force the best-effort fd-close guard
    var threw = null;
    try {
      b.daemon.start({ pidFile: pidFile, logFile: logFile, command: process.execPath, args: [] });
    } catch (e) { threw = e; }
    fs.closeSync = realClose;
    check("spawn-throw: sync spawn throw -> daemon/spawn-failed",
          threw && /daemon\/spawn-failed/.test(threw.code || ""));
    check("spawn-throw: no pidfile written", !fs.existsSync(pidFile));
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }
  } finally {
    fs.closeSync = realClose;
    processSpawn.spawn = origSpawn;
    restore();
  }
}

// POSIX detached spawn returning an undefined pid with a log fd already open:
// start() closes the parent fd (swallowing a close failure) before failing closed.
async function testDaemonStartDetachedUndefinedPidClosesLogFd() {
  var restore = _withPlatform("linux");
  var origSpawn = processSpawn.spawn;
  var realClose = fs.closeSync;
  try {
    var pidFile = _tmpFile("posix-nopid.pid");
    var logFile = _tmpFile("posix-nopid.log");
    processSpawn.spawn = function () { return { pid: undefined, unref: function () {}, on: function () {} }; };
    fs.closeSync = function () { throw new Error("close boom"); };
    var threw = null;
    try {
      b.daemon.start({ pidFile: pidFile, logFile: logFile, command: process.execPath, args: [] });
    } catch (e) { threw = e; }
    fs.closeSync = realClose;
    check("posix-nopid: undefined pid -> daemon/spawn-failed",
          threw && /daemon\/spawn-failed/.test(threw.code || ""));
    check("posix-nopid: no pidfile written", !fs.existsSync(pidFile));
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }
  } finally {
    fs.closeSync = realClose;
    processSpawn.spawn = origSpawn;
    restore();
  }
}

// A detached child whose unref() throws must not derail start(): the best-effort
// guard swallows it and start() still reports the daemon as started.
async function testDaemonStartDetachedUnrefThrows() {
  var pidFile = _tmpFile("unref-throw.pid");
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () {
    return { pid: 909090, unref: function () { throw new Error("unref boom"); }, on: function () {} };
  };
  try {
    var r = b.daemon.start({ pidFile: pidFile, command: process.execPath, args: [] });
    check("unref-throw: start returns despite unref throw", r.pid === 909090);
    check("unref-throw: pidfile written", fs.existsSync(pidFile));
  } finally {
    processSpawn.spawn = origSpawn;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// A real detached child that dies at boot triggers the one-shot exit handler's
// pidfile reap; if that unlink throws, it is swallowed and the failure audit
// still lands (the pidfile is simply left for a later stop() to reap).
async function testDaemonStartDetachedExitHandlerUnlinkFailure() {
  var pidFile = _tmpFile("exit-unlinkfail.pid");
  var captured = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(pidFile)) throw new Error("unlink boom");
    return realUnlink.apply(fs, arguments);
  };
  try {
    b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "process.exit(1)"] });
    await helpers.waitUntil(function () {
      return captured.some(function (e) {
        return e && e.action === "daemon.spawn_failed" && e.metadata && e.metadata.pidFile === pidFile;
      });
    }, { timeoutMs: 5000, label: "exit-unlinkfail: boot-death audit lands despite swallowed unlink" });
    check("exit-unlinkfail: spawn_failed audit emitted despite unlink failure",
          captured.some(function (e) { return e && e.action === "daemon.spawn_failed"; }));
  } finally {
    fs.unlinkSync = realUnlink;
    b.audit.safeEmit = origSafeEmit;
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
}

// Foreground acquire failure paths: a pidFile whose parent is a regular file
// cannot be opened (a non-'pidlock-held' error -> daemon/pid-acquire-failed); a
// live foreign owner (process.ppid) drives the 'pidlock-held' arm; and a
// message-less acquire error drives the String(e) fallback in the error text.
async function testDaemonForegroundAcquireFailures() {
  // (A) parent-is-a-file -> daemon/pid-acquire-failed.
  var blocker = _tmpFile("acq-blocker");
  fs.writeFileSync(blocker, "x");
  var badPidFile = path.join(blocker, "nested", "d.pid");
  var tA = null;
  try { b.daemon.start({ pidFile: badPidFile, signals: ["SIGUSR2"] }); } catch (e) { tA = e; }
  check("fg-acq: parent-is-a-file -> daemon/pid-acquire-failed",
        tA && /daemon\/pid-acquire-failed/.test(tA.code || ""));
  try { fs.unlinkSync(blocker); } catch (_e) { /* best-effort */ }

  // (B) foreign live owner -> daemon/already-running via the pidlock-held arm.
  var heldPidFile = _tmpFile("fg-held.pid");
  fs.writeFileSync(heldPidFile, String(process.ppid) + "\n");
  var tB = null;
  try { b.daemon.start({ pidFile: heldPidFile, signals: ["SIGUSR2"] }); } catch (e) { tB = e; }
  check("fg-held: foreign live PID holds pidfile -> daemon/already-running",
        tB && /daemon\/already-running/.test(tB.code || ""));
  try { fs.unlinkSync(heldPidFile); } catch (_e) { /* best-effort */ }

  // (C) message-less acquire error -> String(e) fallback in daemon/pid-acquire-failed.
  var appShutdown = require("../../lib/app-shutdown");
  var realPidLock = appShutdown.pidLock;
  appShutdown.pidLock = function () {
    return { acquire: function () { throw Object.assign(new Error(""), { code: "weird-no-message" }); }, release: function () {}, held: function () { return false; } };
  };
  var strPidFile = _tmpFile("fg-acq-str.pid");
  var tC = null;
  try { b.daemon.start({ pidFile: strPidFile, signals: ["SIGUSR2"] }); } catch (e) { tC = e; }
  appShutdown.pidLock = realPidLock;
  check("fg-acq-str: message-less acquire error -> daemon/pid-acquire-failed",
        tC && /daemon\/pid-acquire-failed/.test(tC.code || ""));
  try { fs.unlinkSync(strPidFile); } catch (_e) { /* best-effort */ }

  // (D) an acquire error with NO `.code` drives the `e.code || ""` fallback in
  //     the pidlock-held test; it is not pidlock-held -> daemon/pid-acquire-failed.
  appShutdown.pidLock = function () {
    return { acquire: function () { throw new Error("acquire failed, no code"); }, release: function () {}, held: function () { return false; } };
  };
  var noCodePidFile = _tmpFile("fg-acq-nocode.pid");
  var tD = null;
  try { b.daemon.start({ pidFile: noCodePidFile, signals: ["SIGUSR2"] }); } catch (e) { tD = e; }
  appShutdown.pidLock = realPidLock;
  check("fg-acq-nocode: code-less acquire error -> daemon/pid-acquire-failed",
        tD && /daemon\/pid-acquire-failed/.test(tD.code || ""));
  try { fs.unlinkSync(noCodePidFile); } catch (_e) { /* best-effort */ }
}

// start() reaping a stale pidfile swallows a failure of the reap unlink (a race
// where another reaper wins) and proceeds to acquire.
async function testDaemonStartReapUnlinkFailureSwallowed() {
  var pidFile = _tmpFile("reap-unlinkfail.pid");
  fs.writeFileSync(pidFile, "999996\n");   // stale
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () { return { pid: 818181, unref: function () {}, on: function () {} }; };
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(pidFile)) throw new Error("reap unlink boom");
    return realUnlink.apply(fs, arguments);
  };
  var r = null, threw = null;
  try {
    r = b.daemon.start({ pidFile: pidFile, command: process.execPath, args: [] });
  } catch (e) { threw = e; }
  fs.unlinkSync = realUnlink;
  processSpawn.spawn = origSpawn;
  check("reap-unlinkfail: start proceeds despite a swallowed reap-unlink failure",
        threw === null && r && r.pid === 818181);
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// A foreground log-open failure whose error carries no `.message` drives the
// String(e) fallback in daemon/log-open-failed; the just-acquired pidLock is
// still released so the pidFile is reusable.
async function testDaemonForegroundLogOpenStringFallback() {
  var pidFile = _tmpFile("logopen-str.pid");
  var logFile = _tmpFile("logopen-str.log");
  var realOpen = atomicFile.openAppendNoFollowSync;
  atomicFile.openAppendNoFollowSync = function () { throw new Error(""); };
  var threw = null;
  try { b.daemon.start({ pidFile: pidFile, logFile: logFile, signals: ["SIGUSR2"] }); } catch (e) { threw = e; }
  atomicFile.openAppendNoFollowSync = realOpen;
  check("logopen-str: message-less open failure -> daemon/log-open-failed",
        threw && /daemon\/log-open-failed/.test(threw.code || ""));
  check("logopen-str: pidLock released (pidFile gone)", !fs.existsSync(pidFile));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  b.daemon._resetForTest();
}

// Foreground fd-error paths: the redirected writer swallows a writeSync failure
// on the log fd, and the pidLock-release shutdown phase swallows a closeSync
// failure on that same fd. Both are targeted precisely at the fd start() opened,
// so no other descriptor is disturbed.
async function testDaemonForegroundLogFdErrorPaths() {
  var pidFile = _tmpFile("fg-fderr.pid");
  var logFile = _tmpFile("fg-fderr.log");
  var realOpen = atomicFile.openAppendNoFollowSync;
  var capturedFd = null;
  atomicFile.openAppendNoFollowSync = function () {
    var fd = realOpen.apply(atomicFile, arguments);
    capturedFd = fd;
    return fd;
  };
  var origOut = process.stdout.write;
  var origErr = process.stderr.write;
  var r = null;
  try {
    r = b.daemon.start({ pidFile: pidFile, logFile: logFile, signals: ["SIGUSR2"] });
  } finally {
    atomicFile.openAppendNoFollowSync = realOpen;
  }
  // Writer swallows a writeSync failure on the log fd.
  var realWriteSync = fs.writeSync;
  fs.writeSync = function (fd) {
    if (fd === capturedFd) throw new Error("fd write boom");
    return realWriteSync.apply(fs, arguments);
  };
  var writeThrew = null;
  try { process.stdout.write("probe-write-fail\n"); } catch (e) { writeThrew = e; }
  fs.writeSync = realWriteSync;
  process.stdout.write = origOut;
  process.stderr.write = origErr;
  check("fg-fderr: redirected writer swallows a writeSync failure", writeThrew === null);

  // Shutdown swallows a closeSync failure on the log fd.
  var realClose = fs.closeSync;
  fs.closeSync = function (fd) {
    if (fd === capturedFd) throw new Error("fd close boom");
    return realClose.apply(fs, arguments);
  };
  var shutThrew = null;
  try { await r.orchestrator.shutdown(); } catch (e) { shutThrew = e; }
  fs.closeSync = realClose;
  check("fg-fderr: shutdown swallows a closeSync failure on the log fd", shutThrew === null);
  r.orchestrator._resetForTest();
  b.daemon._resetForTest();
  try { fs.closeSync(capturedFd); } catch (_e) { /* leak guard */ }
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(logFile); } catch (_e) { /* best-effort */ }
}

// _resetForTest swallows a throwing per-orchestrator reset so a corrupt handle
// can't wedge the whole process-wide teardown.
async function testDaemonResetForTestSwallowsThrow() {
  var pidFile = _tmpFile("reset-catch.pid");
  var r = b.daemon.start({ pidFile: pidFile, signals: ["SIGUSR2"] });
  var realReset = r.orchestrator._resetForTest;
  r.orchestrator._resetForTest = function () { throw new Error("reset boom"); };
  var resetThrew = null;
  try { b.daemon._resetForTest(); } catch (e) { resetThrew = e; }
  check("reset-catch: _resetForTest swallows a throwing orchestrator reset", resetThrew === null);
  r.orchestrator._resetForTest = realReset;
  try { await r.orchestrator.shutdown(); } catch (_e) { /* best-effort */ }
  r.orchestrator._resetForTest();
  b.daemon._resetForTest();
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// stop() on a stale pidfile swallows a failure of the stale-cleanup unlink and
// still reports reason="stale".
async function testDaemonStopStaleUnlinkFailureSwallowed() {
  var pidFile = _tmpFile("stale-unlink.pid");
  fs.writeFileSync(pidFile, "999997\n");
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) {
    if (String(p) === String(pidFile)) throw new Error("unlink boom");
    return realUnlink.apply(fs, arguments);
  };
  var r = null, threw = null;
  try { r = await b.daemon.stop({ pidFile: pidFile }); } catch (e) { threw = e; }
  fs.unlinkSync = realUnlink;
  check("stale-unlink: stop() swallows the stale-cleanup unlink failure", threw === null);
  check("stale-unlink: still reports stale", r && r.reason === "stale");
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
}

// POSIX SIGTERM→SIGKILL escalation path (skipped on win32 by stop(), which drives
// the cooperative sentinel instead). Forced here via a platform override + a
// stubbed process.kill so every branch — ESRCH races, non-ESRCH failures,
// in-loop graceful exit, escalation, and the post-kill reap poll — is exercised.
async function testDaemonStopPosixSignalPath() {
  var restore = _withPlatform("linux");
  var origKill = process.kill;
  try {
    // (1) ESRCH between pidfile read and first signal.
    var pf1 = _tmpFile("psx-esrch.pid"); fs.writeFileSync(pf1, "4242\n");
    process.kill = function (pid, sig) {
      if (sig === 0) return true;
      var e = new Error("gone"); e.code = "ESRCH"; throw e;
    };
    var r1 = await b.daemon.stop({ pidFile: pf1, signal: "SIGTERM" });
    process.kill = origKill;
    check("psx: ESRCH-at-kill -> stopped=true", r1.stopped === true);
    check("psx: ESRCH-at-kill mechanism=signal", r1.mechanism === "signal");
    check("psx: ESRCH-at-kill no escalation", r1.escalated === undefined);
    check("psx: ESRCH-at-kill pidfile cleaned", !fs.existsSync(pf1));

    // (2) non-ESRCH kill error -> daemon/kill-failed.
    var pf2 = _tmpFile("psx-killfail.pid"); fs.writeFileSync(pf2, "4243\n");
    process.kill = function (pid, sig) {
      if (sig === 0) return true;
      var e = new Error("bad signal"); e.code = "EINVAL"; throw e;
    };
    var t2 = null;
    try { await b.daemon.stop({ pidFile: pf2, signal: "SIGTERM" }); } catch (e) { t2 = e; }
    process.kill = origKill;
    check("psx: non-ESRCH kill -> daemon/kill-failed", t2 && /daemon\/kill-failed/.test(t2.code || ""));
    try { fs.unlinkSync(pf2); } catch (_e) { /* best-effort */ }

    // (3) SIGTERM delivered; target survives one probe then exits inside the loop.
    var pf3 = _tmpFile("psx-loopexit.pid"); fs.writeFileSync(pf3, "4244\n");
    var probes3 = 0;
    process.kill = function (pid, sig) {
      if (sig === 0) {
        probes3 += 1;
        if (probes3 >= 2) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
        return true;
      }
      return true;  // SIGTERM accepted, still running for the first probe
    };
    var r3 = await b.daemon.stop({ pidFile: pf3, signal: "SIGTERM", timeoutMs: 1000, pollMs: 5 });
    process.kill = origKill;
    check("psx: in-loop graceful exit -> stopped=true", r3.stopped === true);
    check("psx: in-loop graceful exit no escalation", r3.escalated === undefined);
    check("psx: in-loop graceful exit pidfile cleaned", !fs.existsSync(pf3));

    // (4) SIGTERM swallowed past timeout -> escalate to SIGKILL (which succeeds),
    //     surviving one post-kill reap poll before the process is seen gone.
    var pf4 = _tmpFile("psx-escalate.pid"); fs.writeFileSync(pf4, "4245\n");
    var killed4 = false, postProbes4 = 0;
    process.kill = function (pid, sig) {
      if (sig === 0) {
        if (!killed4) return true;
        postProbes4 += 1;
        if (postProbes4 >= 2) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
        return true;
      }
      if (sig === "SIGKILL") { killed4 = true; return true; }
      return true;  // SIGTERM swallowed
    };
    var r4 = await b.daemon.stop({ pidFile: pf4, signal: "SIGTERM", timeoutMs: 20, pollMs: 5 });
    process.kill = origKill;
    check("psx: escalation -> escalated=true", r4.escalated === true);
    check("psx: escalation signal=SIGKILL", r4.signal === "SIGKILL");
    check("psx: escalation pidfile cleaned", !fs.existsSync(pf4));

    // (5) SIGKILL escalation throws ESRCH (already gone) -> swallowed, reap proceeds.
    var pf5 = _tmpFile("psx-kill-esrch.pid"); fs.writeFileSync(pf5, "4246\n");
    var killAttempted5 = false;
    process.kill = function (pid, sig) {
      if (sig === 0) { if (killAttempted5) { var e = new Error("gone"); e.code = "ESRCH"; throw e; } return true; }
      if (sig === "SIGKILL") { killAttempted5 = true; var e2 = new Error("already gone"); e2.code = "ESRCH"; throw e2; }
      return true;  // SIGTERM swallowed
    };
    var r5 = await b.daemon.stop({ pidFile: pf5, signal: "SIGTERM", timeoutMs: 15, pollMs: 5 });
    process.kill = origKill;
    check("psx: SIGKILL-ESRCH swallowed -> escalated=true", r5.escalated === true);
    check("psx: SIGKILL-ESRCH pidfile cleaned", !fs.existsSync(pf5));

    // (6) SIGKILL escalation throws a non-ESRCH error -> daemon/kill-failed.
    var pf6 = _tmpFile("psx-kill-fail.pid"); fs.writeFileSync(pf6, "4247\n");
    process.kill = function (pid, sig) {
      if (sig === 0) return true;  // never dies
      if (sig === "SIGKILL") { var e = new Error("perm"); e.code = "EPERM"; throw e; }
      return true;  // SIGTERM swallowed
    };
    var t6 = null;
    try { await b.daemon.stop({ pidFile: pf6, signal: "SIGTERM", timeoutMs: 15, pollMs: 5 }); } catch (e) { t6 = e; }
    process.kill = origKill;
    check("psx: SIGKILL non-ESRCH -> daemon/kill-failed", t6 && /daemon\/kill-failed/.test(t6.code || ""));
    try { fs.unlinkSync(pf6); } catch (_e) { /* best-effort */ }

    // (7) ESRCH-at-kill path whose pidfile-cleanup unlink fails -> swallowed.
    var pf7 = _tmpFile("psx-esrch-unlinkfail.pid"); fs.writeFileSync(pf7, "4248\n");
    process.kill = function (pid, sig) {
      if (sig === 0) return true;
      var e = new Error("gone"); e.code = "ESRCH"; throw e;
    };
    var realUnlink7 = fs.unlinkSync;
    fs.unlinkSync = function (p) { if (String(p) === String(pf7)) throw new Error("unlink boom"); return realUnlink7.apply(fs, arguments); };
    var r7 = null, e7 = null;
    try { r7 = await b.daemon.stop({ pidFile: pf7, signal: "SIGTERM" }); } catch (e) { e7 = e; }
    fs.unlinkSync = realUnlink7;
    process.kill = origKill;
    check("psx: ESRCH-race unlink failure swallowed -> stopped=true", e7 === null && r7 && r7.stopped === true);
    try { fs.unlinkSync(pf7); } catch (_e) { /* best-effort */ }

    // (8) in-loop graceful exit whose pidfile-cleanup unlink fails -> swallowed.
    var pf8 = _tmpFile("psx-loop-unlinkfail.pid"); fs.writeFileSync(pf8, "4249\n");
    var probes8 = 0;
    process.kill = function (pid, sig) {
      if (sig === 0) { probes8 += 1; if (probes8 >= 2) { var e = new Error("gone"); e.code = "ESRCH"; throw e; } return true; }
      return true;
    };
    var realUnlink8 = fs.unlinkSync;
    fs.unlinkSync = function (p) { if (String(p) === String(pf8)) throw new Error("unlink boom"); return realUnlink8.apply(fs, arguments); };
    var r8 = null, e8 = null;
    try { r8 = await b.daemon.stop({ pidFile: pf8, signal: "SIGTERM", timeoutMs: 1000, pollMs: 5 }); } catch (e) { e8 = e; }
    fs.unlinkSync = realUnlink8;
    process.kill = origKill;
    check("psx: in-loop-exit unlink failure swallowed -> stopped=true", e8 === null && r8 && r8.stopped === true);
    try { fs.unlinkSync(pf8); } catch (_e) { /* best-effort */ }

    // (9) SIGKILL escalation whose pidfile-cleanup unlink fails -> swallowed.
    var pf9 = _tmpFile("psx-escalate-unlinkfail.pid"); fs.writeFileSync(pf9, "4250\n");
    var killed9 = false;
    process.kill = function (pid, sig) {
      if (sig === 0) { if (killed9) { var e = new Error("gone"); e.code = "ESRCH"; throw e; } return true; }
      if (sig === "SIGKILL") { killed9 = true; return true; }
      return true;
    };
    var realUnlink9 = fs.unlinkSync;
    fs.unlinkSync = function (p) { if (String(p) === String(pf9)) throw new Error("unlink boom"); return realUnlink9.apply(fs, arguments); };
    var r9 = null, e9 = null;
    try { r9 = await b.daemon.stop({ pidFile: pf9, signal: "SIGTERM", timeoutMs: 20, pollMs: 5 }); } catch (e) { e9 = e; }
    fs.unlinkSync = realUnlink9;
    process.kill = origKill;
    check("psx: escalation unlink failure swallowed -> escalated=true", e9 === null && r9 && r9.escalated === true);
    try { fs.unlinkSync(pf9); } catch (_e) { /* best-effort */ }
  } finally {
    process.kill = origKill;
    restore();
  }
}

// win32 cooperative-stop: sentinel-write failure -> daemon/stop-request-failed
// (message-less throw drives the String(e) fallback). Uses our own live PID so
// the request fails before any TerminateProcess is attempted.
async function testDaemonWin32StopRequestWriteFailure() {
  if (process.platform !== "win32") {
    check("win32 stop-request-failure test skipped on non-win32", true);
    return;
  }
  var pidFile = _tmpFile("win-stopreq.pid");
  fs.writeFileSync(pidFile, String(process.pid) + "\n");
  var realWrite = atomicFile.writeSync;
  atomicFile.writeSync = function () { throw new Error(""); };
  var threw = null;
  try { await b.daemon.stop({ pidFile: pidFile, timeoutMs: 50, pollMs: 5 }); } catch (e) { threw = e; }
  atomicFile.writeSync = realWrite;
  check("win-stopreq: sentinel write failure -> daemon/stop-request-failed",
        threw && /daemon\/stop-request-failed/.test(threw.code || ""));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(pidFile + ".stop"); } catch (_e) { /* best-effort */ }
}

// win32 TerminateProcess edge paths: escalation kill throws non-ESRCH
// (daemon/kill-failed) and ESRCH (swallowed, with a post-kill reap poll), plus
// swallowed pidfile-unlink failures on both the cooperative and forced exits.
async function testDaemonWin32TerminateEdgePaths() {
  if (process.platform !== "win32") {
    check("win32 terminate-edge test skipped on non-win32", true);
    return;
  }
  var origKill = process.kill;
  try {
    // (i) TerminateProcess throws non-ESRCH -> daemon/kill-failed.
    var pf1 = _tmpFile("win-term-fail.pid"); fs.writeFileSync(pf1, "6161\n");
    process.kill = function (pid, sig) {
      if (sig === 0) return true;
      var e = new Error("terminate denied"); e.code = "EPERM"; throw e;
    };
    var t1 = null;
    try { await b.daemon.stop({ pidFile: pf1, timeoutMs: 20, pollMs: 5 }); } catch (e) { t1 = e; }
    process.kill = origKill;
    check("win-term: TerminateProcess non-ESRCH -> daemon/kill-failed",
          t1 && /daemon\/kill-failed/.test(t1.code || ""));
    try { fs.unlinkSync(pf1); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(pf1 + ".stop"); } catch (_e) { /* best-effort */ }

    // (ii) TerminateProcess throws ESRCH (already gone) -> swallowed; the process
    //      is seen alive for one post-kill poll before it is reaped.
    var pf2 = _tmpFile("win-term-esrch.pid"); fs.writeFileSync(pf2, "6162\n");
    var killAttempted2 = false, postProbes2 = 0;
    process.kill = function (pid, sig) {
      if (sig === 0) {
        if (killAttempted2) {
          postProbes2 += 1;
          if (postProbes2 >= 2) { var e = new Error("gone"); e.code = "ESRCH"; throw e; }
          return true;
        }
        return true;
      }
      killAttempted2 = true; var e2 = new Error("already gone"); e2.code = "ESRCH"; throw e2;
    };
    var r2 = await b.daemon.stop({ pidFile: pf2, timeoutMs: 20, pollMs: 5 });
    process.kill = origKill;
    check("win-term: TerminateProcess ESRCH swallowed -> escalated=true", r2.escalated === true);
    check("win-term: escalation mechanism=terminate", r2.mechanism === "terminate");
    try { fs.unlinkSync(pf2); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(pf2 + ".stop"); } catch (_e) { /* best-effort */ }

    // (iii) cooperative exit whose pidfile unlink fails -> swallowed.
    var pf3 = _tmpFile("win-coop-unlinkfail.pid"); fs.writeFileSync(pf3, "6163\n");
    var sen3 = pf3 + ".stop";
    process.kill = function (pid, sig) {
      if (sig === 0) { if (fs.existsSync(sen3)) { var e = new Error("gone"); e.code = "ESRCH"; throw e; } return true; }
      return true;
    };
    var realUnlink3 = fs.unlinkSync;
    fs.unlinkSync = function (p) {
      if (String(p) === String(pf3)) throw new Error("unlink boom");
      return realUnlink3.apply(fs, arguments);
    };
    var r3 = null, e3 = null;
    try { r3 = await b.daemon.stop({ pidFile: pf3, timeoutMs: 2000, pollMs: 5 }); } catch (e) { e3 = e; }
    fs.unlinkSync = realUnlink3;
    process.kill = origKill;
    check("win-coop-unlinkfail: cooperative stop swallows pidfile unlink failure",
          e3 === null && r3 && r3.mechanism === "cooperative");
    try { fs.unlinkSync(pf3); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sen3); } catch (_e) { /* best-effort */ }

    // (iv) forced (timed-out) exit whose pidfile unlink fails -> swallowed.
    var pf4 = _tmpFile("win-forced-unlinkfail.pid"); fs.writeFileSync(pf4, "6164\n");
    var sen4 = pf4 + ".stop";
    var terminated4 = false;
    process.kill = function (pid, sig) {
      if (sig === 0) { if (terminated4) { var e = new Error("gone"); e.code = "ESRCH"; throw e; } return true; }
      terminated4 = true; return true;
    };
    var realUnlink4 = fs.unlinkSync;
    fs.unlinkSync = function (p) {
      if (String(p) === String(pf4)) throw new Error("unlink boom");
      return realUnlink4.apply(fs, arguments);
    };
    var r4 = null, e4 = null;
    try { r4 = await b.daemon.stop({ pidFile: pf4, timeoutMs: 20, pollMs: 5 }); } catch (e) { e4 = e; }
    fs.unlinkSync = realUnlink4;
    process.kill = origKill;
    check("win-forced-unlinkfail: forced stop swallows pidfile unlink failure",
          e4 === null && r4 && r4.escalated === true);
    try { fs.unlinkSync(pf4); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sen4); } catch (_e) { /* best-effort */ }
  } finally {
    process.kill = origKill;
  }
}

// win32 cooperative-stop watcher install/teardown timer failures: setInterval
// unavailable at install (watcher degrades, start() still succeeds) and
// clearInterval throwing at shutdown (swallowed by _stopPolling).
async function testDaemonWin32WatcherTimerFailures() {
  if (process.platform !== "win32") {
    check("win32 watcher-timer test skipped on non-win32", true);
    return;
  }
  // setInterval throws at install -> watcher has no timer, start() still succeeds.
  var pf1 = _tmpFile("win-noint.pid");
  var realSetInterval = global.setInterval;
  global.setInterval = function () { throw new Error("no timers"); };
  var r1 = null, e1 = null;
  try { r1 = b.daemon.start({ pidFile: pf1, signals: ["SIGUSR2"] }); } catch (e) { e1 = e; }
  global.setInterval = realSetInterval;
  check("win-noint: start succeeds despite setInterval throwing",
        e1 === null && r1 && r1.mode === "foreground");
  if (r1) {
    try { await r1.orchestrator.shutdown(); } catch (_e) { /* best-effort */ }
    r1.orchestrator._resetForTest();
  }
  b.daemon._resetForTest();
  try { fs.unlinkSync(pf1); } catch (_e) { /* best-effort */ }

  // clearInterval throws at shutdown -> _stopPolling swallows it.
  var pf2 = _tmpFile("win-noclear.pid");
  var r2 = b.daemon.start({ pidFile: pf2, signals: ["SIGUSR2"] });
  var realClearInterval = global.clearInterval;
  global.clearInterval = function () { throw new Error("no clear"); };
  var e2 = null;
  try { await r2.orchestrator.shutdown(); } catch (e) { e2 = e; }
  global.clearInterval = realClearInterval;
  check("win-noclear: shutdown swallows a clearInterval failure", e2 === null);
  r2.orchestrator._resetForTest();
  b.daemon._resetForTest();
  try { fs.unlinkSync(pf2); } catch (_e) { /* best-effort */ }
}

// win32 cooperative-stop watcher exit-code derivation: a defined-but-zero
// process.exitCode drives the `=== 0` arm, and a failing shutdown phase drives
// the `result.ok ? 0 : 1` → 1 arm. process.exitCode is restored so the test
// process still exits 0.
async function testDaemonWin32WatcherExitCodeBranches() {
  if (process.platform !== "win32") {
    check("win32 watcher exit-code test skipped on non-win32", true);
    return;
  }
  var pidFile = _tmpFile("win-exitcode.pid");
  var sentinel = pidFile + ".stop";
  var origExitCode = process.exitCode;
  var r = b.daemon.start({ pidFile: pidFile, signals: ["SIGUSR2"] });
  r.orchestrator.addPhase({ name: "coverage-fail", run: function () { throw new Error("phase-fail"); } });
  process.exitCode = 0;
  try {
    fs.writeFileSync(sentinel, String(process.pid) + "\n");
    await helpers.waitUntil(function () { return process.exitCode === 1; }, {
      timeoutMs: 5000, label: "win-exitcode: cooperative shutdown sets exitCode=1 on phase failure",
    });
    check("win-exitcode: failing phase -> watcher sets exitCode=1", process.exitCode === 1);
  } finally {
    process.exitCode = origExitCode;
    try { await r.orchestrator.shutdown(); } catch (_e) { /* best-effort */ }
    r.orchestrator._resetForTest();
    b.daemon._resetForTest();
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sentinel); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  testDaemonSurface();
  testDaemonStartRejectsBadOpts();
  testDaemonStartRejectsMalformedOptTypes();
  await testDaemonStartForwardsCwdToDetachedChild();
  await testDaemonStopRejectsBadOpts();
  await testDaemonStopRejectsMalformedNumericOpts();
  await testDaemonStopOnMissingPidfile();
  await testDaemonStopReapsStalePid();
  await testDaemonStopKillRaceAndEscalation();
  await testDaemonStartDetachedSpawn();
  await testDaemonStartRejectsLivePidfile();
  await testDaemonStartForegroundAcquiresLock();
  await testDaemonForegroundLogRedirect();
  await testDaemonForegroundLogOpenFailedReleasesLock();
  await testDaemonStaleCleanupOnStartReap();
  await testDaemonStatusReadOnlyProbe();
  await testDaemonStartDetachedSpawnFailureUndefinedPid();
  await testDaemonStartDetachedSubscribesErrorHandler();
  await testDaemonStartDetachedBootDeathReapsPidfile();
  await testDaemonStartDetachedCleanExitNoSpawnFailed();
  await testDaemonStartDetachedAbnormalPastBootWindow();
  await testDaemonBootWindowSurvivesShortLauncher();
  await testDaemonSameProcessStopWithinBootWindowNoSpawnFailed();
  await testDaemonCrossProcessStopWithinBootWindowNoSpawnFailed();
  await testDaemonStopMarkerFsFailuresSwallowed();
  await testDaemonStartClearsStaleStoppingMarker();
  await testDaemonStopWin32CooperativeStop();
  await testDaemonStartWin32CooperativeStopWatcher();
  await testDaemonReapStaleLivePidDifferentProcess();
  await testDaemonStartDetachedPosixLogFdStdio();
  await testDaemonStartDetachedSpawnThrowsSync();
  await testDaemonStartDetachedUndefinedPidClosesLogFd();
  await testDaemonStartDetachedUnrefThrows();
  await testDaemonStartDetachedExitHandlerUnlinkFailure();
  await testDaemonForegroundAcquireFailures();
  await testDaemonStartReapUnlinkFailureSwallowed();
  await testDaemonForegroundLogOpenStringFallback();
  await testDaemonForegroundLogFdErrorPaths();
  await testDaemonResetForTestSwallowsThrow();
  await testDaemonStopStaleUnlinkFailureSwallowed();
  await testDaemonStopPosixSignalPath();
  await testDaemonWin32StopRequestWriteFailure();
  await testDaemonWin32TerminateEdgePaths();
  await testDaemonWin32WatcherTimerFailures();
  await testDaemonWin32WatcherExitCodeBranches();
  await testDaemonReapPidfileRewriteRace();
  await testDaemonErrorHandlerNoPidPreservesReplacement();
  await testDaemonErrorHandlerValidPidReapsOwn();
  await testDaemonStartInvalidNumericPidRefused();
}

// A numeric-but-invalid pid (0 / negative / non-finite) is refused as a launch
// failure and writes no pidfile — the child_process contract yields a positive
// integer or undefined, so this guards a contract violation defensively.
async function testDaemonStartInvalidNumericPidRefused() {
  var origSpawn = processSpawn.spawn;
  var cases = [0, -1, Infinity, NaN];
  for (var i = 0; i < cases.length; i += 1) {
    var pidFile = _tmpFile("invalidpid-" + i + ".pid");
    (function (badPid) {
      processSpawn.spawn = function () { return { pid: badPid, unref: function () {}, on: function () {} }; };
    })(cases[i]);
    var threw = null;
    try { b.daemon.start({ pidFile: pidFile, command: process.execPath, args: [] }); }
    catch (e) { threw = e; }
    check("invalid-pid " + cases[i] + " refused as spawn-failed",
          threw && /daemon\/spawn-failed/.test(threw.code || ""));
    check("invalid-pid " + cases[i] + " wrote no pidfile", !fs.existsSync(pidFile));
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  }
  processSpawn.spawn = origSpawn;
}

// A no-PID spawn failure's late 'error' callback must NOT delete a pidfile: the
// failed start throws synchronously BEFORE writing one, so a caller that catches
// the throw and retries with the same pidFile keeps its replacement daemon's
// pidfile. RED before the fix: the handler unconditionally unlinked pidFile.
async function testDaemonErrorHandlerNoPidPreservesReplacement() {
  var pidFile = _tmpFile("errhandler-noreplace.pid");
  var handlers = Object.create(null);
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () {
    return { pid: undefined, unref: function () {}, on: function (event, fn) { handlers[event] = fn; } };
  };
  var threw = null;
  try { b.daemon.start({ pidFile: pidFile, command: "no-such-command-xyz", args: [] }); }
  catch (e) { threw = e; }
  processSpawn.spawn = origSpawn;
  check("errhandler: a no-pid spawn throws spawn-failed",
        threw && /daemon\/spawn-failed/.test(threw.code || ""));
  check("errhandler: no pidfile was written for the failed no-pid start", !fs.existsSync(pidFile));
  // A caller catches the throw and retries with the same pidFile; the retry writes its own pid.
  fs.writeFileSync(pidFile, "424242\n");
  // A non-Error argument exercises the audit's String(err) fallback.
  if (typeof handlers.error === "function") handlers.error("spawn ENOENT");
  check("errhandler: the replacement daemon's pidfile survives the late no-pid error callback",
        fs.existsSync(pidFile) && fs.readFileSync(pidFile, "utf8").trim() === "424242");
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  b.daemon._resetForTest();
}

// A valid-pid child that later fires 'error' has its OWN pidfile reaped (it wrote
// one), via the claim-then-verify reap.
async function testDaemonErrorHandlerValidPidReapsOwn() {
  var pidFile = _tmpFile("errhandler-reapown.pid");
  var handlers = Object.create(null);
  var origSpawn = processSpawn.spawn;
  processSpawn.spawn = function () {
    return { pid: 515151, unref: function () {}, on: function (event, fn) { handlers[event] = fn; } };
  };
  var r = null;
  try { r = b.daemon.start({ pidFile: pidFile, command: process.execPath, args: ["-e", "0"], bootDeathWindowMs: 0 }); }
  finally { processSpawn.spawn = origSpawn; }
  check("errhandler: valid-pid start wrote its pidfile", r && r.pid === 515151 && fs.existsSync(pidFile));
  // The child later errors; its own pidfile (still recording 515151) is reaped.
  if (typeof handlers.error === "function") handlers.error(new Error("late runtime error"));
  check("errhandler: a valid-pid child's own pidfile is reaped on a late error", !fs.existsSync(pidFile));
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
  b.daemon._resetForTest();
}

// The boot-death reap must not delete OR temporarily hide a pidfile a fast
// operator restart owns. A non-destructive ownership PRE-CHECK claims (renames
// aside) only when the sidecar is still this child's; a restart landing in the tiny
// window between the pre-check and the claim is caught by the post-claim re-check
// and the file restored. `_seqReader` yields a fixed sequence across the two reads
// (pre-check, then post-claim) so a test can simulate that gap deterministically.
function testDaemonReapPidfileRewriteRace() {
  function _seqReader(vals) {
    var i = 0;
    return function () {
      var v = vals[Math.min(i, vals.length - 1)]; i += 1;
      if (v === "throw") throw new Error("reap read boom");
      return v;
    };
  }
  var reap = b.daemon._reapOwnStalePidfile;

  // (1) The classic race: ours at the pre-check; a concurrent restart rewrites
  // pidFile as we read, but claim-then-verify removes only our exclusive copy and
  // leaves the new pidfile intact.
  var pidFile = _tmpFile("reap-race.pid");
  fs.writeFileSync(pidFile, "111\n");
  var readCount = 0;
  var racingReader = function () { readCount += 1; fs.writeFileSync(pidFile, "222\n"); return 111; };
  var wasOurs = reap(pidFile, 111, racingReader);
  check("reap race: ownership reader was consulted", readCount >= 1);
  check("reap race: this child's own sidecar counts as ours", wasOurs === true);
  check("reap race: the concurrently-rewritten pidfile survives",
        fs.existsSync(pidFile) && fs.readFileSync(pidFile, "utf8").trim() === "222");
  try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }

  // (2) Pre-check leaves a NOT-OURS pidfile untouched — never even claimed/hidden.
  var notOurs = _tmpFile("reap-notours.pid");
  fs.writeFileSync(notOurs, "999\n");
  var wasOurs2 = reap(notOurs, 111, _seqReader([999]));
  check("reap: a non-matching sidecar is left untouched (not claimed)",
        fs.existsSync(notOurs) && fs.readFileSync(notOurs, "utf8").trim() === "999");
  check("reap: a non-matching sidecar is not counted as ours", wasOurs2 === false);
  check("reap: a non-matching sidecar leaves no claim file behind", !fs.existsSync(notOurs + ".reap-111"));
  try { fs.unlinkSync(notOurs); } catch (_e) { /* best-effort */ }

  // (3) A restart lands in the gap: ours at the pre-check, a DIFFERENT pid once
  // claimed. The reap restores the (replacement) pidfile; not counted as ours.
  var raced = _tmpFile("reap-raced.pid");
  fs.writeFileSync(raced, "111\n");
  var wasOurs3 = reap(raced, 111, _seqReader([111, 999]));
  check("reap gap: a replacement claimed after the pre-check is restored", fs.existsSync(raced));
  check("reap gap: the gap-replacement is not counted as ours", wasOurs3 === false);
  try { fs.unlinkSync(raced + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(raced); } catch (_e) { /* best-effort */ }

  // (4) An already-gone pidfile is a no-op — the DEFAULT hardened reader returns
  // null on a missing file, so the pre-check declines to claim.
  var gone = _tmpFile("reap-gone.pid");
  var wasOurs4 = reap(gone, 111);
  check("reap: an already-gone pidfile is a no-op (not ours)", wasOurs4 === false && !fs.existsSync(gone));

  // (5) Ours at the pre-check, but the pidfile vanishes before the claim rename
  // (a stop()/restart in the gap): the rename fails and nothing is reaped.
  var vanished = _tmpFile("reap-vanish.pid");
  fs.writeFileSync(vanished, "111\n");
  var realRename0 = fs.renameSync;
  fs.renameSync = function () { var e = new Error("gone"); e.code = "ENOENT"; throw e; };
  var wasOurs5;
  try { wasOurs5 = reap(vanished, 111, _seqReader([111])); }
  finally { fs.renameSync = realRename0; }
  check("reap: a pidfile that vanishes before the claim is not counted as ours", wasOurs5 === false);
  try { fs.unlinkSync(vanished); } catch (_e) { /* best-effort */ }

  // (6) The PRE-CHECK reader throws → treat as not ours, leave the file untouched.
  var preThrow = _tmpFile("reap-prethrow.pid");
  fs.writeFileSync(preThrow, "111\n");
  var wasOurs6 = reap(preThrow, 111, _seqReader(["throw"]));
  check("reap: a pre-check reader error leaves the file untouched (not ours)",
        fs.existsSync(preThrow) && wasOurs6 === false);
  try { fs.unlinkSync(preThrow); } catch (_e) { /* best-effort */ }

  // (7) The POST-CLAIM reader throws (a gap-restart made it unreadable): restore.
  var postThrow = _tmpFile("reap-postthrow.pid");
  fs.writeFileSync(postThrow, "111\n");
  var wasOurs7 = reap(postThrow, 111, _seqReader([111, "throw"]));
  check("reap: a post-claim reader error restores the file, not counted as ours",
        fs.existsSync(postThrow) && wasOurs7 === false);
  try { fs.unlinkSync(postThrow + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(postThrow); } catch (_e) { /* best-effort */ }

  // (8) A swallowed unlink failure on OUR own claimed sidecar still reports ownership.
  var unlinkFail = _tmpFile("reap-unlinkfail2.pid");
  fs.writeFileSync(unlinkFail, "111\n");
  var realUnlink = fs.unlinkSync;
  fs.unlinkSync = function (p) { if (/\.reap-111$/.test(String(p))) throw new Error("reap unlink boom"); return realUnlink.apply(fs, arguments); };
  var wasOurs8;
  try { wasOurs8 = reap(unlinkFail, 111, _seqReader([111, 111])); }
  finally { fs.unlinkSync = realUnlink; }
  check("reap: a swallowed unlink failure still reports ownership", wasOurs8 === true);
  try { fs.unlinkSync(unlinkFail + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(unlinkFail); } catch (_e) { /* best-effort */ }

  // (9) EEXIST on restore — a still-newer daemon wrote pidFile after our claim, so
  // linkSync fails EEXIST and we leave the newer file (no clobber).
  var newer = _tmpFile("reap-newer.pid");
  fs.writeFileSync(newer, "111\n");
  var realLink0 = fs.linkSync;
  fs.linkSync = function () { fs.writeFileSync(newer, "333\n"); var e = new Error("exists"); e.code = "EEXIST"; throw e; };
  var wasOurs9;
  try { wasOurs9 = reap(newer, 111, _seqReader([111, 999])); }
  finally { fs.linkSync = realLink0; }
  check("reap: an EEXIST restore leaves the newer pidfile intact",
        fs.existsSync(newer) && fs.readFileSync(newer, "utf8").trim() === "333");
  check("reap: the EEXIST case is not counted as ours", wasOurs9 === false);
  try { fs.unlinkSync(newer + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(newer); } catch (_e) { /* best-effort */ }

  // (10) ENOTSUP on restore (no hard links) → fall back to a rename so the pidfile
  // is not lost.
  var noLink = _tmpFile("reap-nolink.pid");
  fs.writeFileSync(noLink, "111\n");
  var realLink = fs.linkSync;
  fs.linkSync = function () { var e = new Error("hard links unsupported"); e.code = "ENOTSUP"; throw e; };
  var wasOurs10;
  try { wasOurs10 = reap(noLink, 111, _seqReader([111, 999])); }
  finally { fs.linkSync = realLink; }
  check("reap: an ENOTSUP link failure falls back to a rename (pidfile not lost)", fs.existsSync(noLink));
  check("reap: an ENOTSUP fallback restore is not counted as ours", wasOurs10 === false);
  try { fs.unlinkSync(noLink + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(noLink); } catch (_e) { /* best-effort */ }

  // (11) Both link + rename-fallback fail (a doubly-broken FS) — swallowed, not ours.
  var doubly = _tmpFile("reap-doubly.pid");
  fs.writeFileSync(doubly, "111\n");
  var realLink2 = fs.linkSync, realRename = fs.renameSync, renameN = 0;
  fs.linkSync = function () { var e = new Error("no links"); e.code = "ENOTSUP"; throw e; };
  fs.renameSync = function () { renameN += 1; if (renameN >= 2) throw new Error("fallback rename boom"); return realRename.apply(fs, arguments); };
  var wasOurs11;
  try { wasOurs11 = reap(doubly, 111, _seqReader([111, 999])); }
  finally { fs.linkSync = realLink2; fs.renameSync = realRename; }
  check("reap: a doubly-failed (link + rename) restore is not counted as ours", wasOurs11 === false);
  try { fs.unlinkSync(doubly + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(doubly); } catch (_e) { /* best-effort */ }

  // (12) A swallowed claim-cleanup (unlink of the claim) failure during restore.
  var cleanupFail = _tmpFile("reap-cleanupfail.pid");
  fs.writeFileSync(cleanupFail, "111\n");
  var realUnlink2 = fs.unlinkSync;
  fs.unlinkSync = function (p) { if (/\.reap-111$/.test(String(p))) throw new Error("claim cleanup boom"); return realUnlink2.apply(fs, arguments); };
  var wasOurs12;
  try { wasOurs12 = reap(cleanupFail, 111, _seqReader([111, 999])); }
  finally { fs.unlinkSync = realUnlink2; }
  check("reap: a swallowed claim-cleanup failure is not counted as ours", wasOurs12 === false);
  check("reap: the sidecar is restored despite the claim-cleanup failure", fs.existsSync(cleanupFail));
  try { fs.unlinkSync(cleanupFail + ".reap-111"); } catch (_e) { /* leftover claim */ }
  try { fs.unlinkSync(cleanupFail); } catch (_e) { /* best-effort */ }
}

module.exports = {
  run: run,
  _tests: {
    testDaemonStatusReadOnlyProbe:                  testDaemonStatusReadOnlyProbe,
    testDaemonStartDetachedSpawnFailureUndefinedPid: testDaemonStartDetachedSpawnFailureUndefinedPid,
    testDaemonStartDetachedSubscribesErrorHandler:  testDaemonStartDetachedSubscribesErrorHandler,
    testDaemonStartDetachedBootDeathReapsPidfile:   testDaemonStartDetachedBootDeathReapsPidfile,
    testDaemonStopWin32CooperativeStop:             testDaemonStopWin32CooperativeStop,
    testDaemonStartWin32CooperativeStopWatcher:     testDaemonStartWin32CooperativeStopWatcher,
  },
};

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
