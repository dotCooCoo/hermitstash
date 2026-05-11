"use strict";
/**
 * b.safeAsync.repeating + b.safeAsync.flushLoop — bounded-cadence + flush
 * loop primitives that replace ad-hoc setInterval / setTimeout chains.
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var waitUntil = helpers.waitUntil;

function _sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

async function run() {
  // ---- Surface ----
  check("safeAsync.repeating is fn",   typeof b.safeAsync.repeating === "function");
  check("safeAsync.flushLoop is fn",   typeof b.safeAsync.flushLoop === "function");

  // ---- repeating: fires periodically; stop() halts ----
  var ticks = 0;
  var loop = b.safeAsync.repeating(function () { ticks += 1; }, 25);
  await _sleep(110);    // expect ~3-4 ticks
  loop.stop();
  var snap = ticks;
  await _sleep(60);
  check("repeating: tick count > 0",          ticks >= 2);
  check("repeating: stop() halts ticks",      ticks === snap);

  // ---- repeating: returns { stop } shape ----
  var loop2 = b.safeAsync.repeating(function () {}, 60000);
  check("repeating: returns object with stop",  typeof loop2.stop === "function");
  loop2.stop();
  loop2.stop();   // idempotent

  // ---- repeating: async fn; rejection routed through onError ----
  var caughtError = null;
  var loop3 = b.safeAsync.repeating(
    async function () { throw new Error("boom"); },
    25,
    { onError: function (e) { caughtError = e; } }
  );
  await _sleep(60);
  loop3.stop();
  check("repeating: async rejection caught by onError",
        caughtError && caughtError.message === "boom");

  // ---- repeating: sync throw → onError ----
  var caughtSync = null;
  var loop4 = b.safeAsync.repeating(
    function () { throw new Error("sync-boom"); },
    25,
    { onError: function (e) { caughtSync = e; } }
  );
  await _sleep(60);
  loop4.stop();
  check("repeating: sync throw caught by onError",
        caughtSync && caughtSync.message === "sync-boom");

  // ---- repeating: rejection without onError → drop-silent (no crash) ----
  var loopSilent = b.safeAsync.repeating(
    async function () { throw new Error("silent"); },
    25
  );
  await _sleep(60);
  loopSilent.stop();
  // No assertion — the goal is "process didn't crash from unhandled rejection."
  check("repeating: drop-silent path survives reject",  true);

  // ---- repeating: rejects bad args ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("repeating: rejects " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejects("non-fn",            function () { b.safeAsync.repeating("nope", 100); }, /async\/bad-arg/);
  rejects("bad ms (string)",   function () { b.safeAsync.repeating(function () {}, "100"); }, /async\/bad-arg/);
  rejects("bad ms (NaN)",      function () { b.safeAsync.repeating(function () {}, NaN); }, /async\/bad-arg/);
  rejects("bad ms (zero)",     function () { b.safeAsync.repeating(function () {}, 0); }, /async\/bad-arg/);
  rejects("bad ms (negative)", function () { b.safeAsync.repeating(function () {}, -1); }, /async\/bad-arg/);

  // ---- flushLoop: fires fn after intervalMs delay; reschedules after settle ----
  var flushCount = 0;
  var lp = b.safeAsync.flushLoop(async function () {
    flushCount += 1;
  }, 30);
  await waitUntil(function () { return flushCount >= 2; }, {
    timeoutMs: 5000,
    label:     "flushLoop: invoked >= 2 times",
  });
  lp.stop();
  var fSnap = flushCount;
  await _sleep(60);
  check("flushLoop: invoked multiple times",      flushCount >= 2);
  check("flushLoop: stop() halts further runs",   flushCount === fSnap);

  // ---- flushLoop: rejection routed through onError ----
  var fErr = null;
  var lp2 = b.safeAsync.flushLoop(
    async function () { throw new Error("flush-fail"); },
    25,
    { onError: function (e) { fErr = e; } }
  );
  await _sleep(80);
  lp2.stop();
  check("flushLoop: rejection caught by onError",
        fErr && fErr.message === "flush-fail");

  // ---- flushLoop: drop-silent without onError ----
  var lpSilent = b.safeAsync.flushLoop(
    async function () { throw new Error("silent-flush"); }, 25
  );
  await _sleep(60);
  lpSilent.stop();
  check("flushLoop: drop-silent path survives reject",  true);

  // ---- flushLoop: sync throw still reschedules ----
  var syncThrows = 0;
  var lpSync = b.safeAsync.flushLoop(
    function () { syncThrows += 1; throw new Error("s"); },
    25
  );
  await _sleep(200);
  lpSync.stop();
  check("flushLoop: sync throw reschedules",   syncThrows >= 2);

  // ---- flushLoop: respects stop in mid-flight ----
  var midFlight = 0;
  var lp3;
  lp3 = b.safeAsync.flushLoop(async function () {
    midFlight += 1;
    await _sleep(100);
    if (midFlight === 1) lp3.stop();   // stop while in-flight
  }, 25);
  await _sleep(200);
  var mfSnap = midFlight;
  await _sleep(120);
  check("flushLoop: stop during in-flight prevents reschedule",  midFlight === mfSnap);

  // ---- flushLoop: rejects bad args ----
  function rejectsF(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("flushLoop: rejects " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejectsF("non-fn",          function () { b.safeAsync.flushLoop("nope", 100); }, /async\/bad-arg/);
  rejectsF("bad ms (NaN)",    function () { b.safeAsync.flushLoop(function () {}, NaN); }, /async\/bad-arg/);
  rejectsF("bad ms (zero)",   function () { b.safeAsync.flushLoop(function () {}, 0); }, /async\/bad-arg/);
  rejectsF("bad ms (string)", function () { b.safeAsync.flushLoop(function () {}, "x"); }, /async\/bad-arg/);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
