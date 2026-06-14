"use strict";
// #130: the scheduler watchdog force-clears task.running after maxJobMs and
// lets the next tick re-fire. The ORIGINAL (slow) run's promise then settles
// late and, before the fix, unconditionally wrote back task.running/lastFinish/
// lastError AND emitted system.scheduler.task.success|failure — clobbering the
// state the watchdog (and the new run) had moved on from, and double-counting.
// The fix tags each run with a generation the watchdog + each fire bump; a
// settle whose tag is stale is ignored.
//
// Driven through the public scheduler with a run() whose promise the test
// controls. RED on the buggy tree: resolving the watchdog-abandoned run emits
// a stale success. GREEN: it emits nothing; only the current run settles.

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var auditMod  = require("../../lib/audit");

var TASK = "wd-stale-settle-test";

async function run() {
  var realEmit = auditMod.safeEmit;
  var successes = 0;
  auditMod.safeEmit = function (ev) {
    if (ev && ev.action === "system.scheduler.task.success" &&
        ev.metadata && ev.metadata.name === TASK) {
      successes += 1;
    }
    return realEmit.call(auditMod, ev);
  };

  var resolvers = [];   // one resolve fn per fire — the test settles them by hand
  var sched = b.scheduler.create({ maxJobMs: 1, audit: true });   // 1ms watchdog → any stuck run is reaped next tick
  try {
    sched.schedule({
      name:  TASK,
      every: 1000,       // builder floor is 1000ms; fire 1 ≈ 1s, watchdog re-fire ≈ 2s
      run:   function () { return new Promise(function (resolve) { resolvers.push(resolve); }); },
    });
    sched.start();

    // Wait until the watchdog has reaped fire 1 (still pending) and re-fired,
    // so two runs exist: resolvers[0] (abandoned) + resolvers[1] (current).
    await helpers.waitUntil(function () { return resolvers.length >= 2; },
      { timeoutMs: 9000, label: "#130: watchdog re-fired the task after a stuck run" });

    var before = successes;
    // Settle the FIRST run — the one the watchdog abandoned. Its late resolve
    // must NOT emit a success (its generation is stale).
    resolvers[0]();
    await helpers.passiveObserve(400, "#130: stale-settle window for the abandoned run");
    check("#130 a watchdog-abandoned run's late resolve emits NO stale success",
          successes === before);

    // The current run still settles normally → exactly one success.
    resolvers[1]();
    await helpers.waitUntil(function () { return successes === before + 1; },
      { timeoutMs: 5000, label: "#130: the current run records its success" });
    check("#130 the current (post-watchdog) run still records its success",
          successes === before + 1);
  } finally {
    sched.stop();
    auditMod.safeEmit = realEmit;
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
