"use strict";
/**
 * b.safeAsync.repeating + b.safeAsync.flushLoop — bounded-cadence + flush
 * loop primitives that replace ad-hoc setInterval / setTimeout chains.
 * Also covers b.safeAsync.makeBufferedEnqueue + b.safeAsync.makeDrainingClose
 * + b.safeAsync.makeBatchDrain — the backpressure enqueue, graceful
 * drain-then-close, and single-flight drain loop shared by the batching
 * log-stream sinks.
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var waitUntil = helpers.waitUntil;

function _sleep(ms) { return helpers.passiveObserve(ms, "safe-async-loops: real-time tick-window observation"); }

async function run() {
  // ---- Surface ----
  check("safeAsync.repeating is fn",   typeof b.safeAsync.repeating === "function");
  check("safeAsync.flushLoop is fn",   typeof b.safeAsync.flushLoop === "function");

  // ---- repeating: fires periodically; stop() halts ----
  var ticks = 0;
  var loop = b.safeAsync.repeating(function () { ticks += 1; }, 25);
  await waitUntil(function () { return ticks >= 2; }, {
    timeoutMs: 5000,
    label:     "safe-async-loops: repeating fired >= 2 ticks",
  });
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

  // ---- makeBufferedEnqueue: backpressure enqueue for batching sinks ----
  check("safeAsync.makeBufferedEnqueue is fn",
        typeof b.safeAsync.makeBufferedEnqueue === "function");

  // Partial batch defers to schedule; full batch fires flush; result shape.
  var beBuf = [];
  var flushes = 0, schedules = 0;
  var beEnqueue = b.safeAsync.makeBufferedEnqueue(beBuf, {
    batchSize:   3,
    bufferLimit: 5,
    // Drain on a microtask, mirroring the sinks' async _flush — the enqueue
    // return value must see the pre-drain depth.
    flush:       function () { flushes += 1; return Promise.resolve().then(function () { beBuf.length = 0; }); },
    schedule:    function () { schedules += 1; },
  });
  var r1 = await beEnqueue({ n: 1 });
  check("bufferedEnqueue: accepted result + queued depth",  r1.accepted === true && r1.queued === 1);
  check("bufferedEnqueue: partial batch schedules, no flush", schedules === 1 && flushes === 0);
  await beEnqueue({ n: 2 });
  var r3 = await beEnqueue({ n: 3 });            // batch full → flush, no schedule
  check("bufferedEnqueue: full batch triggers flush",        flushes === 1);
  check("bufferedEnqueue: queued depth reported pre-flush",  r3.queued === 3);
  check("bufferedEnqueue: full-batch turn does not schedule", schedules === 2);

  // Overflow: drop oldest once bufferLimit is reached, evicted record to onOverflow.
  var ovBuf = [];
  var ovDrops = [];
  var ovEnqueue = b.safeAsync.makeBufferedEnqueue(ovBuf, {
    batchSize:   100,            // never flush via batch — isolate overflow
    bufferLimit: 2,
    flush:       function () { return Promise.resolve(); },
    schedule:    function () {},
    onOverflow:  function (dropped) { ovDrops.push(dropped); },
  });
  await ovEnqueue({ id: "a" });
  await ovEnqueue({ id: "b" });
  await ovEnqueue({ id: "c" });   // len 2 >= limit 2 → evict "a", push "c"
  check("bufferedEnqueue: overflow drops oldest",
        ovBuf.length === 2 && ovBuf[0].id === "b" && ovBuf[1].id === "c");
  check("bufferedEnqueue: onOverflow receives evicted record",
        ovDrops.length === 1 && ovDrops[0].id === "a");

  // onOverflow is optional — overflow without it must stay silent.
  var noCbBuf = [];
  var noCbEnqueue = b.safeAsync.makeBufferedEnqueue(noCbBuf, {
    batchSize: 100, bufferLimit: 1,
    flush: function () { return Promise.resolve(); },
    schedule: function () {},
  });
  await noCbEnqueue({ x: 1 });
  await noCbEnqueue({ x: 2 });    // overflow, no onOverflow → silent
  check("bufferedEnqueue: overflow without onOverflow is silent",
        noCbBuf.length === 1 && noCbBuf[0].x === 2);

  // Config-time validation (TypeError) so sink-wiring typos surface at setup.
  function beRejects(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("bufferedEnqueue: rejects " + label, threw instanceof TypeError);
  }
  var okOpts = { batchSize: 1, bufferLimit: 1, flush: function () {}, schedule: function () {} };
  function withOpt(over) { return Object.assign({}, okOpts, over); }
  beRejects("non-array buffer",  function () { b.safeAsync.makeBufferedEnqueue({}, okOpts); });
  beRejects("missing opts",      function () { b.safeAsync.makeBufferedEnqueue([]); });
  beRejects("bad batchSize",     function () { b.safeAsync.makeBufferedEnqueue([], withOpt({ batchSize: 0 })); });
  beRejects("bad bufferLimit",   function () { b.safeAsync.makeBufferedEnqueue([], withOpt({ bufferLimit: -1 })); });
  beRejects("non-fn flush",      function () { b.safeAsync.makeBufferedEnqueue([], withOpt({ flush: null })); });
  beRejects("non-fn schedule",   function () { b.safeAsync.makeBufferedEnqueue([], withOpt({ schedule: null })); });
  beRejects("non-fn onOverflow", function () { b.safeAsync.makeBufferedEnqueue([], withOpt({ onOverflow: 5 })); });

  // ---- makeDrainingClose: graceful drain-then-close for batching sinks ----
  check("safeAsync.makeDrainingClose is fn",
        typeof b.safeAsync.makeDrainingClose === "function");

  // Order is load-bearing: cancel → await inflight → flush → markClosed.
  var seq = [];
  var dcInflight = Promise.resolve().then(function () { seq.push("inflight"); });
  var dcClose = b.safeAsync.makeDrainingClose({
    scheduler:   { cancel: function () { seq.push("cancel"); } },
    getInflight: function () { return dcInflight; },
    flush:       function () { seq.push("flush"); return Promise.resolve(); },
    markClosed:  function () { seq.push("closed"); },
  });
  await dcClose();
  check("drainingClose: drains in order cancel->inflight->flush->closed",
        seq.join(",") === "cancel,inflight,flush,closed");

  // No in-flight drain → still flushes + marks closed.
  var seq2 = [];
  var dcClose2 = b.safeAsync.makeDrainingClose({
    scheduler:   { cancel: function () { seq2.push("cancel"); } },
    getInflight: function () { return null; },
    flush:       function () { seq2.push("flush"); return Promise.resolve(); },
    markClosed:  function () { seq2.push("closed"); },
  });
  await dcClose2();
  check("drainingClose: no inflight still flushes + closes",
        seq2.join(",") === "cancel,flush,closed");

  // In-flight rejection is swallowed — close still flushes + marks closed.
  var dcClosedFlag = false;
  var dcClose3 = b.safeAsync.makeDrainingClose({
    scheduler:   { cancel: function () {} },
    getInflight: function () { return Promise.reject(new Error("drain boom")); },
    flush:       function () { return Promise.resolve(); },
    markClosed:  function () { dcClosedFlag = true; },
  });
  await dcClose3();
  check("drainingClose: in-flight rejection swallowed, close completes", dcClosedFlag === true);

  // Config-time validation.
  function dcRejects(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("drainingClose: rejects " + label, threw instanceof TypeError);
  }
  var okClose = {
    scheduler: { cancel: function () {} }, getInflight: function () {},
    flush: function () {}, markClosed: function () {},
  };
  function withClose(over) { return Object.assign({}, okClose, over); }
  dcRejects("missing opts",         function () { b.safeAsync.makeDrainingClose(); });
  dcRejects("scheduler w/o cancel", function () { b.safeAsync.makeDrainingClose(withClose({ scheduler: {} })); });
  dcRejects("non-fn getInflight",   function () { b.safeAsync.makeDrainingClose(withClose({ getInflight: null })); });
  dcRejects("non-fn flush",         function () { b.safeAsync.makeDrainingClose(withClose({ flush: null })); });
  dcRejects("non-fn markClosed",    function () { b.safeAsync.makeDrainingClose(withClose({ markClosed: null })); });

  // ---- makeBatchDrain: single-flight drain loop for batching sinks ----
  check("safeAsync.makeBatchDrain is fn",
        typeof b.safeAsync.makeBatchDrain === "function");

  // Drains the whole buffer in batchSize chunks via sendBatch.
  var bdBuf = [1, 2, 3, 4, 5];
  var bdSent = [];
  var bdDrain = b.safeAsync.makeBatchDrain({
    buffer:    bdBuf,
    batchSize: 2,
    scheduler: b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:  function () { return false; },
    sendBatch: function (batch) { bdSent.push(batch.slice()); return Promise.resolve(); },
    onRetryExhausted: function () {},
  });
  await bdDrain.flush();
  check("batchDrain: drains whole buffer in batchSize chunks",
        bdBuf.length === 0 && bdSent.length === 3 &&
        bdSent[0].join() === "1,2" && bdSent[2].join() === "5");
  check("batchDrain: isInFlight false after drain", bdDrain.isInFlight() === false);

  // retry-exhausted: a sendBatch throw reports + stops the loop, remainder kept.
  var reBuf = [1, 2, 3, 4];
  var reExhausted = null;
  var reDrain = b.safeAsync.makeBatchDrain({
    buffer:    reBuf,
    batchSize: 2,
    scheduler: b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:  function () { return false; },
    sendBatch: function () { return Promise.reject(new Error("send boom")); },
    onRetryExhausted: function (batch, e) { reExhausted = { n: batch.length, msg: e.message }; },
  });
  await reDrain.flush();
  check("batchDrain: retry-exhausted reported, loop stops, remainder kept",
        reExhausted && reExhausted.n === 2 && reExhausted.msg === "send boom" && reBuf.length === 2);

  // beforeDrain failure drains the WHOLE buffer as a drop, no send attempted.
  var bfBuf = [1, 2, 3];
  var bfFailed = null, bfSends = 0;
  var bfDrain = b.safeAsync.makeBatchDrain({
    buffer:      bfBuf,
    batchSize:   2,
    scheduler:   b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:    function () { return false; },
    beforeDrain: function () { return Promise.reject(new Error("autocreate boom")); },
    onBeforeDrainFail: function (records, e) { bfFailed = { n: records.length, msg: e.message }; },
    sendBatch:   function () { bfSends += 1; return Promise.resolve(); },
    onRetryExhausted: function () {},
  });
  await bfDrain.flush();
  check("batchDrain: beforeDrain failure drops whole buffer, no send",
        bfFailed && bfFailed.n === 3 && bfFailed.msg === "autocreate boom" &&
        bfSends === 0 && bfBuf.length === 0);

  // Custom takeBatch governs the batch shape (byte-cap style — one per batch).
  var tbBuf = [10, 20, 30];
  var tbSent = [];
  var tbDrain = b.safeAsync.makeBatchDrain({
    buffer:    tbBuf,
    batchSize: 100,
    scheduler: b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:  function () { return false; },
    takeBatch: function (buf) { return buf.splice(0, 1); },
    sendBatch: function (batch) { tbSent.push(batch[0]); return Promise.resolve(); },
    onRetryExhausted: function () {},
  });
  await tbDrain.flush();
  check("batchDrain: custom takeBatch governs batch shape",
        tbSent.join() === "10,20,30" && tbBuf.length === 0);

  // Single-flight: concurrent flushes drain the buffer once (no double-send).
  var sfBuf = [1, 2, 3];
  var sfSent = 0;
  var sfDrain = b.safeAsync.makeBatchDrain({
    buffer:    sfBuf,
    batchSize: 1,
    scheduler: b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:  function () { return false; },
    sendBatch: function () { sfSent += 1; return Promise.resolve(); },
    onRetryExhausted: function () {},
  });
  check("batchDrain: isInFlight false before flush", sfDrain.isInFlight() === false);
  var p1 = sfDrain.flush();
  check("batchDrain: isInFlight true synchronously after flush()", sfDrain.isInFlight() === true);
  var p2 = sfDrain.flush();          // in-flight → must not start a second drain
  await Promise.all([p1, p2]);
  check("batchDrain: concurrent flush drains buffer exactly once",
        sfSent === 3 && sfBuf.length === 0 && sfDrain.isInFlight() === false);

  // isClosed stops the loop between batches.
  var clBuf = [1, 2, 3, 4];
  var clSent = 0, clClosed = false;
  var clDrain = b.safeAsync.makeBatchDrain({
    buffer:    clBuf,
    batchSize: 1,
    scheduler: b.safeAsync.makeScheduledFlush(20, function () {}),
    isClosed:  function () { return clClosed; },
    sendBatch: function () { clSent += 1; clClosed = true; return Promise.resolve(); },
    onRetryExhausted: function () {},
  });
  await clDrain.flush();
  check("batchDrain: isClosed halts the loop after the current batch",
        clSent === 1 && clBuf.length === 3);

  // Config-time validation.
  function bdRejects(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("batchDrain: rejects " + label, threw instanceof TypeError);
  }
  var okDrain = {
    buffer: [], batchSize: 1, scheduler: { schedule: function () {} },
    isClosed: function () {}, sendBatch: function () {}, onRetryExhausted: function () {},
  };
  function withDrain(over) { return Object.assign({}, okDrain, over); }
  bdRejects("non-array buffer",        function () { b.safeAsync.makeBatchDrain(withDrain({ buffer: {} })); });
  bdRejects("bad batchSize",           function () { b.safeAsync.makeBatchDrain(withDrain({ batchSize: 0 })); });
  bdRejects("scheduler w/o schedule",  function () { b.safeAsync.makeBatchDrain(withDrain({ scheduler: {} })); });
  bdRejects("non-fn isClosed",         function () { b.safeAsync.makeBatchDrain(withDrain({ isClosed: null })); });
  bdRejects("non-fn sendBatch",        function () { b.safeAsync.makeBatchDrain(withDrain({ sendBatch: null })); });
  bdRejects("non-fn onRetryExhausted", function () { b.safeAsync.makeBatchDrain(withDrain({ onRetryExhausted: null })); });
  bdRejects("non-fn takeBatch",        function () { b.safeAsync.makeBatchDrain(withDrain({ takeBatch: 5 })); });

  // makeBatchingSink — the top-level composer (buffered enqueue + batch
  // drain + draining close). batchSize flush + final-drain-on-close: every
  // emitted record reaches sendBatch, none stranded on shutdown.
  var bsSent = [];
  var bsSink = b.safeAsync.makeBatchingSink({
    batchSize:     2,
    bufferLimit:   100,
    maxBatchAgeMs: 50,
    sendBatch:     function (batch) { bsSent.push(batch.slice()); return Promise.resolve(); },
  });
  await bsSink.emit({ message: "a" });
  await bsSink.emit({ message: "b" });
  await bsSink.emit({ message: "c" });
  await bsSink.close();
  var bsTotal = bsSent.reduce(function (n, batch) { return n + batch.length; }, 0);
  check("makeBatchingSink batches and drains all records on close (3 in -> 3 out)",
    bsTotal === 3 && bsSent.length >= 1);

  // config-time validation: sendBatch is required.
  var bsThrew = false;
  try { b.safeAsync.makeBatchingSink({ batchSize: 2 }); }
  catch (e) { bsThrew = /sendBatch/.test(e.message); }
  check("makeBatchingSink requires opts.sendBatch", bsThrew);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
