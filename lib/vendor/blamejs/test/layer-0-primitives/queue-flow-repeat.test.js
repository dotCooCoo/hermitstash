"use strict";
/**
 * v0.4.21 queue — repeat-in-queue (cron) + parent-child Flows.
 *
 * Run standalone: `node test/layer-0-primitives/queue-flow-repeat.test.js`
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

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-flow-")); }

function _waitFor(predicate, timeoutMs) {
  return new Promise(function (resolve, reject) {
    var deadline = Date.now() + (timeoutMs || 5000);
    (function poll() {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error("timeout: " + (predicate.label || "predicate")));
      setTimeout(poll, 25);
    })();
  });
}

// ---- Repeat-in-queue ----

async function testRepeatCronReEnqueuesAfterComplete() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    // "* * * * *" → every minute; first re-enqueue lands roughly 1 minute
    // out from now. We don't wait for it to fire — we just confirm a NEW
    // pending row was inserted with availableAt > now.
    var enq = await b.queue.enqueue("cron-q", { tag: "loop" },
      { repeat: { cron: "* * * * *" } });

    var seen = 0;
    var consumer = b.queue.consume("cron-q",
      async function (job) {
        seen++;
        // Confirm the leased row carries the cron metadata so a handler
        // could inspect it (e.g. to decide whether to do extra work).
        check("repeat: leased job carries repeatCron",  job.repeatCron === "* * * * *");
      },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return seen >= 1; }, 3000);

    // After complete, a second pending row should exist for the next minute.
    // The cron rounds UP to the next whole-minute boundary, so availableAt
    // lands on a :00 second boundary in the future relative to when
    // complete() ran. enqueue() honours opts.availableAt directly, so the
    // boundary survives the round-trip without drift.
    var pending = await b.db.from("_blamejs_jobs")
      .where({ queueName: "cron-q", status: "pending" }).all();
    check("repeat: a follow-up pending row was scheduled",  pending.length === 1);
    var availableAt = Number(pending[0].availableAt);
    check("repeat: next availableAt is on a minute boundary",
          availableAt % 60000 === 0);
    check("repeat: follow-up carries the same cron",
          pending[0].repeatCron === "* * * * *");

    consumer.cancel();
    void enq;
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testRepeatStopsOnFinalFailure() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    await b.queue.enqueue("cron-fail", { tag: "broken" },
      { repeat: { cron: "* * * * *" }, maxAttempts: 1 });

    var attempts = 0;
    var consumer = b.queue.consume("cron-fail",
      async function () { attempts++; throw new Error("always fails"); },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await _waitFor(function () { return attempts >= 1; }, 3000);
    // Give the failure path a tick to record.
    await new Promise(function (r) { setTimeout(r, 100); });
    consumer.cancel();

    var pending = await b.db.from("_blamejs_jobs")
      .where({ queueName: "cron-fail", status: "pending" }).all();
    check("repeat: no follow-up scheduled after final failure",
          pending.length === 0);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Flows ----

async function testFlowSurface() {
  check("b.queue.enqueueFlow is a function",  typeof b.queue.enqueueFlow === "function");
}

async function testFlowLinearChain() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var ord = [];
    var consumer = b.queue.consume("flow-q",
      async function (job) { ord.push(job.payload.tag); },
      { concurrency: 4, pollIntervalMs: 25, fastPollMs: 5 });

    var flow = await b.queue.enqueueFlow({
      queueName: "flow-q",
      children: [
        { name: "fetch",     payload: { tag: "fetch"     } },
        { name: "transform", payload: { tag: "transform" }, dependsOn: ["fetch"] },
        { name: "publish",   payload: { tag: "publish"   }, dependsOn: ["transform"] },
      ],
    });
    check("flow: returns flowId",            typeof flow.flowId === "string" && flow.flowId.indexOf("flow-") === 0);
    check("flow: returns 3 child jobIds",     flow.jobs.length === 3);

    await _waitFor(function () { return ord.length === 3; }, 5000);
    consumer.cancel();

    check("flow: chain order fetch → transform → publish",
          ord[0] === "fetch" && ord[1] === "transform" && ord[2] === "publish");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testFlowDiamondWaitsForAllDeps() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    // Diamond: root → [a, b] → end. End must NOT run until both a and b finish.
    var ord = [];
    var consumer = b.queue.consume("diamond-q",
      async function (job) {
        ord.push(job.payload.tag);
        // Slow down 'a' so 'b' would otherwise finish first.
        if (job.payload.tag === "a") await new Promise(function (r) { setTimeout(r, 80); });
      },
      { concurrency: 4, pollIntervalMs: 25, fastPollMs: 5 });

    await b.queue.enqueueFlow({
      queueName: "diamond-q",
      children: [
        { name: "root", payload: { tag: "root" } },
        { name: "a",    payload: { tag: "a"    }, dependsOn: ["root"] },
        { name: "b",    payload: { tag: "b"    }, dependsOn: ["root"] },
        { name: "end",  payload: { tag: "end"  }, dependsOn: ["a", "b"] },
      ],
    });
    await _waitFor(function () { return ord.length === 4; }, 5000);
    consumer.cancel();

    var endIdx = ord.indexOf("end");
    var aIdx   = ord.indexOf("a");
    var bIdx   = ord.indexOf("b");
    check("flow: end ran after both a + b",  endIdx > aIdx && endIdx > bIdx);
    check("flow: root ran first",            ord[0] === "root");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testFlowCycleDetection() {
  // No DB needed — cycle detection runs at registration before insert.
  // But the queue dispatcher requires init; we're inside a setupTestDb caller
  // for safety.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var threw = null;
    try {
      await b.queue.enqueueFlow({
        queueName: "cycle-q",
        children: [
          { name: "a", payload: {}, dependsOn: ["b"] },
          { name: "b", payload: {}, dependsOn: ["c"] },
          { name: "c", payload: {}, dependsOn: ["a"] },
        ],
      });
    } catch (e) { threw = e; }
    check("flow: cycle detected at enqueue",
          threw && /flow cycle detected/i.test(threw.message));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testFlowUnknownDepRejected() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var threw = null;
    try {
      await b.queue.enqueueFlow({
        queueName: "unknown-dep-q",
        children: [{ name: "a", payload: {}, dependsOn: ["does-not-exist"] }],
      });
    } catch (e) { threw = e; }
    check("flow: unknown dep rejected",
          threw && /unknown name 'does-not-exist'/i.test(threw.message));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testFlowValidation() {
  var threw = false;
  try { await b.queue.enqueueFlow(); } catch (_e) { threw = true; }
  check("flow: rejects missing opts",  threw);

  threw = false;
  try { await b.queue.enqueueFlow({ queueName: "x" }); } catch (_e) { threw = true; }
  check("flow: rejects missing children",  threw);

  threw = false;
  try {
    await b.queue.enqueueFlow({
      queueName: "x",
      children: [{ name: "a" }, { name: "a" }],
    });
  } catch (_e) { threw = true; }
  check("flow: rejects duplicate child name",  threw);
}

// Round-trip preservation regression gate — enqueue({availableAt: T})
// stores T in the row; future-self reads back exactly T. Catches the
// v0.6.21 bug shape ("primitive computes precise value, silently re-
// derives a less precise version on the way to storage") for any
// caller that wires availableAt directly.
async function testEnqueueRoundTripsAvailableAt() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // Three precise targets — sub-second, exact second, far future
    var targets = [
      Date.now() + 12345,           // ms-precision in the future
      Date.now() + 60000,           // exactly one minute out
      1888000000999,                // arbitrary future (ms precision)
    ];
    for (var i = 0; i < targets.length; i++) {
      var T = targets[i];
      await b.queue.enqueue("rt-q", { i: i }, { availableAt: T });
      var rows = await b.db.from("_blamejs_jobs")
        .where({ queueName: "rt-q", status: "pending" }).all();
      var row = rows.find(function (r) {
        // Compare the exact ms — round-trip preservation is what we test.
        return Number(r.availableAt) === T;
      });
      check("enqueue round-trips availableAt=" + T + " exactly", !!row);
    }
    // delaySeconds-only path still works (no availableAt provided)
    var beforeMs = Date.now();
    await b.queue.enqueue("rt-q", { tag: "rel" }, { delaySeconds: 5 });
    var relRows = await b.db.from("_blamejs_jobs")
      .where({ queueName: "rt-q", status: "pending" }).all();
    var relRow = relRows.find(function (r) {
      var aa = Number(r.availableAt);
      return aa >= beforeMs + 5000 && aa <= beforeMs + 5000 + 100;
    });
    check("enqueue with delaySeconds only computes nowMs+5000ms", !!relRow);
    // Both opts present — availableAt wins, delaySeconds is ignored
    var explicitT = Date.now() + 30000;
    await b.queue.enqueue("rt-q", { tag: "both" }, {
      availableAt:  explicitT,
      delaySeconds: 999,    // would be 999s if it won — but it shouldn't
    });
    var bothRows = await b.db.from("_blamejs_jobs")
      .where({ queueName: "rt-q", status: "pending" }).all();
    var bothRow = bothRows.find(function (r) { return Number(r.availableAt) === explicitT; });
    check("enqueue with both opts: availableAt wins, delaySeconds ignored", !!bothRow);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testFlowSurface();
  await testRepeatCronReEnqueuesAfterComplete();
  await testRepeatStopsOnFinalFailure();
  await testEnqueueRoundTripsAvailableAt();
  await testFlowLinearChain();
  await testFlowDiamondWaitsForAllDeps();
  await testFlowCycleDetection();
  await testFlowUnknownDepRejected();
  await testFlowValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
