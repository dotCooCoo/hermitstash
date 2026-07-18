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

var _tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-daemon-test-"));
function _tmpFile(name) {
  return path.join(_tmpBase, Date.now() + "-" +
    Math.random().toString(36).slice(2, 8) + "-" + name);
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
async function testDaemonStopKillRaceAndEscalation() {
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
  try {
    r = b.daemon.start({ pidFile: pidFile, logFile: logFile, signals: ["SIGUSR2"] });
    process.stdout.write("daemon-redirect-probe-out\n");
    process.stderr.write("daemon-redirect-probe-err\n");
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
