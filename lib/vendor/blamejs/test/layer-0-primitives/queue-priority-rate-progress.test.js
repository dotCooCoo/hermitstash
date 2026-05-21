"use strict";
/**
 * v0.4.20 queue + jobs — priority on enqueue, consume rate-limit,
 * handler ctx.progress(0..100).
 *
 * Run standalone: `node test/layer-0-primitives/queue-priority-rate-progress.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-prio-")); }

function _waitFor(predicate, timeoutMs) {
  return helpers.waitUntil(predicate, {
    timeoutMs: timeoutMs || 3000,
    label: "queue-priority _waitFor",
  });
}

async function testEnqueuePriorityHeadOfQueue() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // Three jobs: low (priority 0), high (priority 10), mid (priority 5)
    // — enqueue in low/high/mid order, expect lease order high/mid/low.
    await b.queue.enqueue("prio-q", { id: "low" });
    await b.queue.enqueue("prio-q", { id: "high" }, { priority: 10 });
    await b.queue.enqueue("prio-q", { id: "mid"  }, { priority: 5 });

    var seen = [];
    var consumer = b.queue.consume("prio-q",
      async function (job) { seen.push(job.payload.id); },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return seen.length >= 3; }, 5000);
    consumer.cancel();
    check("priority: high lease first",  seen[0] === "high");
    check("priority: mid lease second",  seen[1] === "mid");
    check("priority: low lease last",    seen[2] === "low");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testEnqueueDefaultPriorityZero() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("zero-prio", { id: "a" });
    await b.queue.enqueue("zero-prio", { id: "b" });
    var seen = [];
    var consumer = b.queue.consume("zero-prio",
      async function (job) { seen.push(job.payload.id); },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return seen.length >= 2; }, 3000);
    consumer.cancel();
    check("priority: equal priorities preserve insertion order",
          seen[0] === "a" && seen[1] === "b");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testRateLimitCapsThroughput() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // 6 jobs queued; rate cap at 3 per second; with the consumer running
    // ~1 second total we should observe AT MOST max + slack handlers.
    for (var i = 0; i < 6; i++) await b.queue.enqueue("rl-q", { i: i });

    var startedAt = Date.now();
    var doneTimestamps = [];
    var consumer = b.queue.consume("rl-q",
      async function () { doneTimestamps.push(Date.now() - startedAt); },
      { concurrency: 6, rateLimit: { max: 3, perSeconds: 1 },
        pollIntervalMs: 25, fastPollMs: 5 });
    // Wait long enough to drain — at 3/sec we expect ~2 seconds for 6 jobs.
    await _waitFor(function () { return doneTimestamps.length >= 6; }, 6000);
    consumer.cancel();

    // First 3 land roughly inside the first window; jobs 4..6 wait for
    // the next window. Assert jobs[3..5] all start at >= 1000ms.
    var firstThree = doneTimestamps.slice(0, 3);
    var lastThree  = doneTimestamps.slice(3, 6);
    check("rateLimit: first 3 within first window",
          firstThree.every(function (t) { return t < 1500; }));
    check("rateLimit: jobs 4-6 deferred to next window",
          lastThree.every(function (t) { return t >= 900; }));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testRateLimitValidation() {
  var threw = false;
  try {
    b.queue.consume("any", function () {}, { rateLimit: { max: 5 } });   // missing perSeconds
  } catch (_e) { threw = true; }
  check("rateLimit: rejects missing perSeconds",  threw);

  threw = false;
  try {
    b.queue.consume("any", function () {}, { rateLimit: { max: "5", perSeconds: 1 } });
  } catch (_e) { threw = true; }
  check("rateLimit: rejects non-numeric max",     threw);

  function rejects(label, opts) {
    var t = false;
    try { b.queue.consume("any", function () {}, { rateLimit: opts }); }
    catch (_e) { t = true; }
    check("rateLimit: " + label,  t);
  }
  rejects("rejects negative max",        { max: -1, perSeconds: 1 });
  rejects("rejects zero max",            { max: 0, perSeconds: 1 });
  rejects("rejects fractional max",      { max: 1.5, perSeconds: 1 });
  rejects("rejects NaN max",             { max: NaN, perSeconds: 1 });
  rejects("rejects Infinity max",        { max: Infinity, perSeconds: 1 });
  rejects("rejects negative perSeconds", { max: 5, perSeconds: -1 });
  rejects("rejects zero perSeconds",     { max: 5, perSeconds: 0 });
  rejects("rejects NaN perSeconds",      { max: 5, perSeconds: NaN });
  rejects("rejects Infinity perSeconds", { max: 5, perSeconds: Infinity });
}

async function testProgressEmitsAuditAndObservability() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("prog-q", { id: "p1" });

    var capturedObs = [];
    var origObsEvent = b.observability.event;
    b.observability.event = function (n, v, l) {
      if (n === "queue.progress") capturedObs.push({ v: v, l: l });
      return origObsEvent.apply(b.observability, arguments);
    };

    var done = false;
    var consumer = b.queue.consume("prog-q",
      async function (_job, ctx) {
        ctx.progress(0);
        ctx.progress(50);
        ctx.progress(100);
        done = true;
      },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return done; }, 3000);
    consumer.cancel();

    b.observability.event = origObsEvent;

    // 0 and 100 are markers (always emit). 50 may or may not pass the
    // throttle depending on timing — it's allowed but not required.
    var values = capturedObs.map(function (e) { return e.v; }).sort(function (a, b) { return a - b; });
    check("progress: emits 0 marker", values.indexOf(0) !== -1);
    check("progress: emits 100 marker", values.indexOf(100) !== -1);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testProgressThrottlesChattyHandler() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("chatty-q", { id: "c1" });

    var capturedObs = [];
    var origObsEvent = b.observability.event;
    b.observability.event = function (n, v) {
      if (n === "queue.progress") capturedObs.push(v);
      return origObsEvent.apply(b.observability, arguments);
    };

    var done = false;
    var consumer = b.queue.consume("chatty-q",
      async function (_job, ctx) {
        // Spam a hundred non-marker progress reports synchronously.
        // Throttle (PROGRESS_MIN_INTERVAL_MS = 250 in queue.js) means
        // most should be suppressed.
        for (var i = 1; i < 100; i++) ctx.progress(i);
        ctx.progress(100);
        done = true;
      },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return done; }, 3000);
    consumer.cancel();

    b.observability.event = origObsEvent;

    // Synchronous burst: throttle window means most non-marker calls
    // silently drop. Worst case we see 0 (start), maybe one mid value,
    // and 100 (end). Definitely not 100 distinct events.
    check("progress: synchronous burst is throttled",  capturedObs.length < 10);
    check("progress: 100 marker still landed",          capturedObs.indexOf(100) !== -1);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testProgressBadInputIgnored() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("bad-prog-q", { id: "x" });

    var threw = null;
    var done = false;
    var consumer = b.queue.consume("bad-prog-q",
      async function (_job, ctx) {
        // None of these should throw.
        try {
          ctx.progress("nope");
          ctx.progress(NaN);
          ctx.progress(undefined);
          ctx.progress(150);   // clamps to 100; allowed but not asserted
          ctx.progress(-1);    // clamps to 0
        } catch (e) { threw = e; }
        done = true;
      },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return done; }, 3000);
    consumer.cancel();
    check("progress: bad input doesn't throw",  threw === null);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testEnqueuePriorityHeadOfQueue();
  await testEnqueueDefaultPriorityZero();
  await testRateLimitCapsThroughput();
  await testRateLimitValidation();
  await testProgressEmitsAuditAndObservability();
  await testProgressThrottlesChattyHandler();
  await testProgressBadInputIgnored();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
