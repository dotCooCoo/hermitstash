// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeAsync.parallel — bounded-concurrency mapAsync with continuous
 * worker queue (no Promise.all-batched chunks). Exercises ordering,
 * concurrency cap, error propagation, abort signal, config-time
 * validation.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _sleep(ms) { return helpers.passiveObserve(ms, "safe-async-parallel: simulated task duration"); }

async function run() {
  // ---- Surface ----
  check("safeAsync.parallel is fn", typeof b.safeAsync.parallel === "function");

  // ---- Empty input → empty results ----
  var empty = await b.safeAsync.parallel([], async function (x) { return x; });
  check("parallel: empty input → []", Array.isArray(empty) && empty.length === 0);

  // ---- Results in input order, not completion order ----
  var input = [1, 2, 3, 4, 5];
  var doubled = await b.safeAsync.parallel(input, async function (n, i) {
    // Stagger settlement so completion order != input order.
    await _sleep((input.length - i) * 10);
    return n * 2;
  }, { concurrency: 3 });
  check("parallel: results in input order",
        doubled.length === 5 && doubled.join(",") === "2,4,6,8,10");

  // ---- fn receives (item, index) ----
  var seenIdx = [];
  await b.safeAsync.parallel(["a", "b", "c"], async function (item, idx) {
    seenIdx.push(idx);
    return item;
  }, { concurrency: 1 });
  check("parallel: fn receives index", seenIdx.join(",") === "0,1,2");

  // ---- Concurrency cap respected (continuous-queue, not batched) ----
  var inFlight = 0;
  var maxInFlight = 0;
  var n = 20;
  var items = [];
  for (var i = 0; i < n; i++) items.push(i);

  await b.safeAsync.parallel(items, async function (idx) {
    inFlight += 1;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    // Variable durations — short items must NOT wait for long items
    // in the same chunk (continuous queue would let workers grab the
    // next index immediately).
    await _sleep(idx % 4 === 0 ? 40 : 5);
    inFlight -= 1;
    return idx;
  }, { concurrency: 4 });
  check("parallel: concurrency cap honored (max in-flight ≤ 4)", maxInFlight <= 4);
  check("parallel: concurrency cap reached",                     maxInFlight === 4);

  // ---- Continuous worker queue (no batched chunks) ----
  // If parallel batched chunks-of-N, the slow item in one chunk would
  // block the rest of the pool. Track "did any new task start while a
  // long task was still in-flight from an earlier index?"
  var startTimes = [];
  var longRunningStill = false;
  var workItems = [0, 1, 2, 3, 4, 5];   // 6 items, concurrency 2
  await b.safeAsync.parallel(workItems, async function (i) {
    startTimes[i] = Date.now();
    // Item 0 is the long-pole. Items 1..5 are short — under continuous
    // queue semantics, they should all complete before item 0 finishes.
    if (i === 0) {
      await _sleep(150);
      // By now, the rest should have started.
      for (var k = 1; k < workItems.length; k++) {
        if (startTimes[k] && startTimes[k] - startTimes[0] < 150) {
          longRunningStill = true;
        }
      }
      return i;
    }
    await _sleep(5);
    return i;
  }, { concurrency: 2 });
  check("parallel: continuous queue (short items don't wait for long-pole)",
        longRunningStill);

  // ---- First rejection propagates; results not partial ----
  var threwErr = null;
  try {
    await b.safeAsync.parallel([1, 2, 3], async function (n) {
      if (n === 2) throw new Error("boom-" + n);
      return n;
    }, { concurrency: 2 });
  } catch (e) { threwErr = e; }
  check("parallel: first rejection propagates",
        threwErr && /boom-2/.test(threwErr.message));

  // ---- Sync throw inside fn → rejection ----
  var syncErr = null;
  try {
    await b.safeAsync.parallel([1], function () { throw new Error("sync"); });
  } catch (e) { syncErr = e; }
  check("parallel: sync throw routed through rejection",
        syncErr && /sync/.test(syncErr.message));

  // ---- AbortSignal cancels further dispatch ----
  var controller = new AbortController();
  var seen = 0;
  var abortErr = null;
  var pAbort = b.safeAsync.parallel(items, async function (idx) {
    seen += 1;
    if (seen === 3) controller.abort();
    await _sleep(20);
    return idx;
  }, { concurrency: 2, signal: controller.signal }).catch(function (e) {
    abortErr = e;
  });
  await pAbort;
  check("parallel: aborted run rejects with async/aborted",
        abortErr && abortErr.code === "async/aborted");
  check("parallel: aborted run does NOT dispatch all items", seen < items.length);

  // ---- Pre-aborted signal rejects immediately ----
  var preAbortErr = null;
  var c2 = new AbortController();
  c2.abort();
  try {
    await b.safeAsync.parallel([1, 2, 3], async function (n) { return n; },
                                { signal: c2.signal });
  } catch (e) { preAbortErr = e; }
  check("parallel: pre-aborted signal short-circuits",
        preAbortErr && preAbortErr.code === "async/aborted");

  // ---- Config-time validation (throws synchronously, not as rejection) ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parallel: rejects " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejects("non-array items",   function () { b.safeAsync.parallel("nope", function () {}); }, /async\/bad-arg/);
  rejects("non-fn",            function () { b.safeAsync.parallel([1], "nope"); },             /async\/bad-arg/);
  rejects("concurrency 0",     function () { b.safeAsync.parallel([1], function () {}, { concurrency: 0 }); }, /async\/bad-arg/);
  rejects("concurrency 257",   function () { b.safeAsync.parallel([1], function () {}, { concurrency: 257 }); }, /async\/bad-arg/);
  rejects("concurrency NaN",   function () { b.safeAsync.parallel([1], function () {}, { concurrency: NaN }); }, /async\/bad-arg/);
  rejects("concurrency float", function () { b.safeAsync.parallel([1], function () {}, { concurrency: 2.5 }); }, /async\/bad-arg/);

  // ---- Default concurrency = 8 (no opts) ----
  var defaultMax = 0;
  var defaultIn = 0;
  var manyItems = [];
  for (var j = 0; j < 32; j++) manyItems.push(j);
  await b.safeAsync.parallel(manyItems, async function () {
    defaultIn += 1;
    if (defaultIn > defaultMax) defaultMax = defaultIn;
    await _sleep(5);
    defaultIn -= 1;
  });
  check("parallel: default concurrency is 8", defaultMax === 8);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
