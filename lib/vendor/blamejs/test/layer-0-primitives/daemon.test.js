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

async function run() {
  testDaemonSurface();
  testDaemonStartRejectsBadOpts();
  await testDaemonStopRejectsBadOpts();
  await testDaemonStopOnMissingPidfile();
  await testDaemonStopReapsStalePid();
  await testDaemonStartDetachedSpawn();
  await testDaemonStartRejectsLivePidfile();
  await testDaemonStartForegroundAcquiresLock();
  await testDaemonStaleCleanupOnStartReap();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
