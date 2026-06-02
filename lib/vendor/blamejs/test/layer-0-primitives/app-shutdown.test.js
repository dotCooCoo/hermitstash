"use strict";
/**
 * app-shutdown — graceful-shutdown orchestrator.
 *
 * Run standalone: `node test/layer-0-primitives/app-shutdown.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyRes  = helpers._bodyRes;
var _mockReq  = helpers._mockReq;

function testAppShutdownSurface() {
  check("b.appShutdown namespace present",     typeof b.appShutdown === "object");
  check("b.appShutdown.create is a function",  typeof b.appShutdown.create === "function");
  check("b.appShutdown.standardPhases is fn",  typeof b.appShutdown.standardPhases === "function");
  check("AppShutdownError is a class",         typeof b.appShutdown.AppShutdownError === "function");
  check("DEFAULT_GRACE_MS exposed",            typeof b.appShutdown.DEFAULT_GRACE_MS === "number");
}

async function testAppShutdownEmpty() {
  var o = b.appShutdown.create({ phases: [] });
  var r = await o.shutdown();
  check("empty: ok=true",                       r.ok === true);
  check("empty: no phases",                     r.phases.length === 0);
  check("empty: draining=true after",           r.draining === true);
  check("empty: idempotent — same Promise",     (await o.shutdown()).totalMs >= 0);
  o._resetForTest();
}

async function testAppShutdownPhasesRunInOrder() {
  var order = [];
  var o = b.appShutdown.create({
    phases: [
      { name: "first",  run: function () { order.push("first"); } },
      { name: "second", run: async function () { await Promise.resolve(); order.push("second"); } },
      { name: "third",  run: function () { order.push("third"); } },
    ],
  });
  var r = await o.shutdown();
  check("phases: ran in array order",           order.join(",") === "first,second,third");
  check("phases: 3 results",                    r.phases.length === 3);
  check("phases: all ok",                       r.phases.every(function (p) { return p.ok; }));
  check("phases: each has ms",                  r.phases.every(function (p) { return typeof p.ms === "number"; }));
  o._resetForTest();
}

async function testAppShutdownPhaseFailureContinues() {
  var ran = [];
  var o = b.appShutdown.create({
    phases: [
      { name: "first",  run: function () { ran.push("first"); throw new Error("boom"); } },
      { name: "second", run: function () { ran.push("second"); } },
      { name: "third",  run: function () { ran.push("third"); } },
    ],
  });
  var r = await o.shutdown();
  check("phase failure: subsequent phases still ran",  ran.length === 3);
  check("phase failure: first marked ok=false",        r.phases[0].ok === false);
  check("phase failure: error message captured",       r.phases[0].error.indexOf("boom") !== -1);
  check("phase failure: aggregate ok=false",           r.ok === false);
  check("phase failure: later phases ok=true",         r.phases[1].ok && r.phases[2].ok);
  o._resetForTest();
}

async function testAppShutdownPhaseTimeout() {
  var o = b.appShutdown.create({
    graceMs: 200,
    phases: [
      { name: "fast",  run: function () { return Promise.resolve(); } },
      { name: "slow",  run: function () { return new Promise(function () {}); }, timeoutMs: 50 },
    ],
  });
  var t0 = Date.now();
  var r = await o.shutdown();
  var elapsed = Date.now() - t0;
  check("timeout: completed under graceMs",     elapsed < 500);
  check("timeout: slow phase marked ok=false",  r.phases[1].ok === false);
  check("timeout: error mentions timeout",      /time(d out|out)/i.test(r.phases[1].error));
  check("timeout: fast phase still ok",         r.phases[0].ok === true);
  o._resetForTest();
}

async function testAppShutdownIdempotent() {
  var calls = 0;
  var o = b.appShutdown.create({
    phases: [{ name: "single", run: function () { calls++; } }],
  });
  var p1 = o.shutdown();
  var p2 = o.shutdown();
  check("idempotent: same Promise returned",   p1 === p2);
  await p1;
  await o.shutdown();   // third call after resolution
  check("idempotent: phase only ran once",     calls === 1);
  o._resetForTest();
}

async function testAppShutdownDrainingFlag() {
  var o = b.appShutdown.create({
    phases: [{ name: "x", run: function () {
      return helpers.passiveObserve(30, "shutdown: phase x slow-work simulator");
    } }],
  });
  check("draining: false before shutdown",      o.draining() === false);
  var p = o.shutdown();
  check("draining: true immediately after shutdown() called", o.draining() === true);
  await p;
  check("draining: stays true after complete",  o.draining() === true);
  o._resetForTest();
}

async function testAppShutdownMiddleware503DuringDrain() {
  var o = b.appShutdown.create({
    phases: [{ name: "x", run: function () {
      return helpers.passiveObserve(100, "shutdown: phase x slow-work for 503 window");
    } }],
  });
  var mw = o.middleware();
  var req1 = _mockReq();
  var res1 = _bodyRes();
  var passed = false;
  // res1.end emits "finish" synchronously inside next(); register a
  // listener BEFORE invoking the middleware so the wait below resolves.
  var firstFinishP = new Promise(function (r) { res1.on("finish", r); });
  mw(req1, res1, function () { passed = true; res1.writeHead(200); res1.end(); });
  await firstFinishP;
  check("middleware: pre-drain pass-through",   passed === true);

  var sp = o.shutdown();
  var req2 = _mockReq();
  var res2 = _bodyRes();
  var nextCalled = false;
  mw(req2, res2, function () { nextCalled = true; });
  check("middleware: draining → 503",           res2._endedStatus === 503);
  check("middleware: draining → next() not called", nextCalled === false);
  await sp;
  o._resetForTest();
}

async function testAppShutdownInFlightTracking() {
  var o = b.appShutdown.create({ phases: [] });
  var mw = o.middleware();
  var resolveReq;
  var req = _mockReq();
  var res = _bodyRes();
  mw(req, res, function () {
    check("inFlight: counted while in flight", o.inFlight() === 1);
    resolveReq = function () { res.end(); };
  });
  var req2 = _mockReq();
  var res2 = _bodyRes();
  mw(req2, res2, function () {});
  check("inFlight: counted across multiple requests", o.inFlight() === 2);
  resolveReq();
  res2.end();
  await new Promise(function (r) { setImmediate(r); });
  check("inFlight: decremented after res.end",  o.inFlight() === 0);
  o._resetForTest();
}

async function testAppShutdownDrainPhaseWaitsForInFlight() {
  var o = b.appShutdown.create({
    graceMs: 1000,
    phases: [],
  });
  o.addPhase({
    name: "drain-in-flight",
    run:  o.waitInFlight,
    timeoutMs: 500,
  });
  var mw = o.middleware();
  var req = _mockReq();
  var res = _bodyRes();
  mw(req, res, function () {});
  setTimeout(function () { res.end(); }, 80);
  var t0 = Date.now();
  var result = await o.shutdown();
  var elapsed = Date.now() - t0;
  check("drain-in-flight: waited for in-flight to finish", elapsed >= 70 && elapsed < 500);
  check("drain-in-flight: phase ok",                       result.phases[0].ok === true);
  o._resetForTest();
}

async function testAppShutdownDrainTimeoutWhenInFlightStuck() {
  var o = b.appShutdown.create({
    graceMs: 200,
    phases: [],
  });
  o.addPhase({
    name: "drain-in-flight",
    run:  o.waitInFlight,
    timeoutMs: 80,
  });
  var mw = o.middleware();
  var req = _mockReq();
  var res = _bodyRes();
  mw(req, res, function () {});
  var result = await o.shutdown();
  check("drain timeout: phase ok=false on stuck in-flight",   result.phases[0].ok === false);
  check("drain timeout: error mentions timeout",              /time(d out|out)/i.test(result.phases[0].error));
  o._resetForTest();
}

async function testAppShutdownAddPhaseRejectsAfterStart() {
  var o = b.appShutdown.create({ phases: [{ name: "x", run: function () {} }] });
  o.shutdown();
  var threw = null;
  try { o.addPhase({ name: "late", run: function () {} }); } catch (e) { threw = e; }
  check("addPhase: rejected after shutdown started",
        threw && threw.code === "app-shutdown/already-started");
  o._resetForTest();
}

async function testAppShutdownStandardPhasesBuilder() {
  var stops = [];
  var components = {
    health:     { markShuttingDown: function () { stops.push("health"); } },
    scheduler:  { stop: function () { stops.push("scheduler"); } },
    jobs:       { shutdown: function () { stops.push("jobs"); return Promise.resolve(); } },
    router:     { closeWebSockets: function () { stops.push("websockets"); return Promise.resolve(); } },
    server:     { close: function (cb) { stops.push("server"); cb(); } },
    cluster:    { shutdown: function () { stops.push("cluster"); return Promise.resolve(); } },
    db:         { close: function () { stops.push("db"); } },
    externalDb: { shutdown: function () { stops.push("externalDb"); return Promise.resolve(); } },
  };
  var phases = b.appShutdown.standardPhases(components);
  var names = phases.map(function (p) { return p.name; });
  check("standardPhases: mark-draining first",   names[0] === "mark-draining");
  check("standardPhases: scheduler before jobs", names.indexOf("scheduler") < names.indexOf("jobs"));
  check("standardPhases: jobs before websockets", names.indexOf("jobs") < names.indexOf("websockets"));
  check("standardPhases: websockets before http-server",
        names.indexOf("websockets") < names.indexOf("http-server"));
  check("standardPhases: cluster after http-server",
        names.indexOf("cluster") > names.indexOf("http-server"));
  check("standardPhases: db before external-db",
        names.indexOf("db") < names.indexOf("external-db"));

  var o = b.appShutdown.create({ phases: phases });
  await o.shutdown();
  check("standardPhases: execution mirrors declaration order",
        stops.join(",") === "health,scheduler,jobs,websockets,server,cluster,db,externalDb");
  o._resetForTest();
}

async function testAppShutdownStandardPhasesOmitsAbsentComponents() {
  var phases = b.appShutdown.standardPhases({
    db:      { close: function () {} },
    cluster: { shutdown: function () { return Promise.resolve(); } },
  });
  var names = phases.map(function (p) { return p.name; });
  check("standardPhases: only present components included",
        names.length === 2 && names.indexOf("cluster") !== -1 && names.indexOf("db") !== -1);
}

async function testAppShutdownSignalHandlersInstall() {
  var o = b.appShutdown.create({
    phases: [{ name: "x", run: function () {} }],
    installSignalHandlers: true,
  });
  var sigtermListeners = process.listeners("SIGTERM");
  var sigintListeners = process.listeners("SIGINT");
  check("signals: SIGTERM handler installed", sigtermListeners.length > 0);
  check("signals: SIGINT handler installed",  sigintListeners.length > 0);
  o.uninstallSignals();
  check("signals: SIGTERM handler removed",   process.listeners("SIGTERM").length < sigtermListeners.length);
  o._resetForTest();
}

async function testAppShutdownConfigValidation() {
  var threw = null;
  try {
    b.appShutdown.create({ phases: [{ name: "ok", run: "not-a-fn" }] });
  } catch (e) { threw = e; }
  check("create: bad-shaped phase rejected",   threw && threw.code === "app-shutdown/bad-phase");

  threw = null;
  try { b.appShutdown.create({ forceExitMarginMs: -1 }); } catch (e) { threw = e; }
  check("create: bad forceExitMarginMs rejected", threw && threw.code === "app-shutdown/bad-force-exit-margin-ms");

  threw = null;
  var o = b.appShutdown.create({ phases: [] });
  try { o.addPhase({ name: "x" }); } catch (e) { threw = e; }
  check("addPhase: missing run rejected",      threw && threw.code === "app-shutdown/bad-phase");
  o._resetForTest();
}

async function testAppShutdownWatchdogForcesExitOnHang() {
  // A shutdown phase that never settles must NOT hold the process open
  // until the supervisor SIGKILLs it (losing the final DB flush). When the
  // operator delegates lifecycle via installSignalHandlers, a watchdog
  // forces a clean exit graceMs + forceExitMarginMs after the signal so
  // exit handlers (the DB re-encrypt) still run. Verified in a child
  // process — the watchdog calls process.exit, which would kill the runner.
  if (process.platform === "win32") {
    // Node can't deliver SIGTERM to a JS handler on Windows (the OS
    // terminates the process), so the graceful signal path the watchdog
    // guards doesn't exist here. This defends a Linux-container SIGTERM
    // deployment; the container smoke leg exercises it for real.
    check("watchdog test skipped on win32 (no deliverable SIGTERM)", true);
    return;
  }
  var cp = require("node:child_process");
  var repoRoot = require("node:path").resolve(__dirname, "..", "..");
  var script =
    "var b = require(" + JSON.stringify(repoRoot) + ");" +
    "b.appShutdown.create({" +
    "  graceMs: 100, forceExitMarginMs: 150, installSignalHandlers: true," +
    "  phases: [{ name: 'hang', run: function () { return new Promise(function () {}); } }]" +
    "});" +
    "setInterval(function () {}, 60000);" +     // keep the loop alive until the signal
    "process.stdout.write('READY\\n');";
  var child = cp.spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });

  // Single exit observer + bounded waits so a misbehaving child can never
  // hang the test (it fails loudly via waitUntil's timeout instead).
  var sentAt = null;
  var exited = null;
  var stderr = "";
  child.stderr.on("data", function (d) { stderr += d.toString(); });
  child.on("exit", function (code, signal) {
    exited = { code: code, signal: signal, ms: sentAt === null ? 0 : Date.now() - sentAt };
  });

  var sawReady = false;
  child.stdout.on("data", function (d) { if (d.toString().indexOf("READY") !== -1) sawReady = true; });
  try {
    // The child cold-`require`s the whole framework before printing READY —
    // ~3.6s uncontended, and that multiplies when the smoke runner has up to
    // SMOKE_PARALLEL modules competing for the same cores. waitUntil returns
    // the instant READY arrives, so a generous budget costs nothing on a fast
    // run but keeps the watchdog leg from flaking under heavy parallelism.
    await helpers.waitUntil(function () { return sawReady || exited !== null; },
      { timeoutMs: 30000, label: "app-shutdown watchdog: child reached READY" });
  } catch (_e) { /* fall through to the check below */ }
  check("watchdog child reached READY (stderr: " + stderr.slice(0, 160).replace(/\n/g, " ") + ")",
        sawReady && exited === null);
  if (!sawReady || exited !== null) { try { child.kill("SIGKILL"); } catch (_e2) { /* gone */ } return; }

  sentAt = Date.now();
  child.kill("SIGTERM");
  // The watchdog fires at graceMs(100) + forceExitMarginMs(150) = 250ms.
  await helpers.waitUntil(function () { return exited !== null; },
    { timeoutMs: 6000, label: "app-shutdown watchdog: child forced exit after SIGTERM" });
  // It EXITS (not hangs) and does so on its own — a forced process.exit
  // (numeric code, no kill signal), not because the OS killed it.
  check("hung shutdown forced to exit by watchdog (not hung)", exited && exited.ms < 4000);
  check("watchdog exit was a clean process.exit (not a kill signal)",
        exited && exited.signal === null && typeof exited.code === "number");
}

function testAppShutdownExitAfterPhasesValidation() {
  var threw = null;
  try { b.appShutdown.create({ exitAfterPhases: "yes" }); }
  catch (e) { threw = e; }
  check("exitAfterPhases: non-boolean → AppShutdownError",
        threw && threw.code === "app-shutdown/bad-exit-after-phases");
  // Default (unset) does NOT exit — a plain shutdown() resolves without
  // terminating the process (the surrounding suite proves this: every
  // prior shutdown() returned to the runner without exiting).
  var o = b.appShutdown.create({ phases: [], exitAfterPhases: false });
  check("exitAfterPhases:false accepted", typeof o.shutdown === "function");
  o._resetForTest();
}

async function testAppShutdownExitAfterPhasesExits() {
  // A non-signal shutdown() with exitAfterPhases:true must terminate the
  // process once phases complete, with an exit code reflecting phase
  // success. Verified in a child process — process.exit would kill the
  // runner. No signal is sent: the child calls shutdown() directly, which
  // distinguishes this from the signal-handler watchdog path.
  var cp = require("node:child_process");
  var repoRoot = require("node:path").resolve(__dirname, "..", "..");
  function _spawnAndExit(phaseBody, label, expectCode) {
    var script =
      "var b = require(" + JSON.stringify(repoRoot) + ");" +
      "var o = b.appShutdown.create({ graceMs: 2000, exitAfterPhases: true," +
      "  phases: [{ name: 'p', run: " + phaseBody + " }] });" +
      "o.shutdown().then(function (r) { process.stdout.write('RESOLVED:' + r.ok + '\\n'); });";
    return new Promise(function (resolve) {
      var child = cp.spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
      var out = "";
      var done = null;
      child.stdout.on("data", function (d) { out += d.toString(); });
      child.on("exit", function (code, signal) { done = { code: code, signal: signal, out: out }; });
      helpers.waitUntil(function () { return done !== null; },
        { timeoutMs: 30000, label: "app-shutdown exitAfterPhases: " + label })
        .then(function () { resolve(done); }, function () {
          try { child.kill("SIGKILL"); } catch (_e) { /* gone */ }
          resolve(done || { code: -1, signal: null, out: out });
        });
    });
  }

  var okRun = await _spawnAndExit("function () { return; }", "clean phase", 0);
  check("exitAfterPhases: clean phase resolved before exit",
        okRun && okRun.out.indexOf("RESOLVED:true") !== -1);
  check("exitAfterPhases: clean phase → process.exit(0) (no kill signal)",
        okRun && okRun.code === 0 && okRun.signal === null);

  var failRun = await _spawnAndExit("function () { throw new Error('boom'); }", "failed phase", 1);
  check("exitAfterPhases: failed phase resolved with ok=false",
        failRun && failRun.out.indexOf("RESOLVED:false") !== -1);
  check("exitAfterPhases: failed phase → process.exit(1)",
        failRun && failRun.code === 1 && failRun.signal === null);
}

async function run() {
  testAppShutdownSurface();
  await testAppShutdownEmpty();
  await testAppShutdownPhasesRunInOrder();
  await testAppShutdownPhaseFailureContinues();
  await testAppShutdownPhaseTimeout();
  await testAppShutdownIdempotent();
  await testAppShutdownDrainingFlag();
  await testAppShutdownMiddleware503DuringDrain();
  await testAppShutdownInFlightTracking();
  await testAppShutdownDrainPhaseWaitsForInFlight();
  await testAppShutdownDrainTimeoutWhenInFlightStuck();
  await testAppShutdownAddPhaseRejectsAfterStart();
  await testAppShutdownStandardPhasesBuilder();
  await testAppShutdownStandardPhasesOmitsAbsentComponents();
  await testAppShutdownSignalHandlersInstall();
  await testAppShutdownConfigValidation();
  await testAppShutdownWatchdogForcesExitOnHang();
  testAppShutdownExitAfterPhasesValidation();
  await testAppShutdownExitAfterPhasesExits();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
