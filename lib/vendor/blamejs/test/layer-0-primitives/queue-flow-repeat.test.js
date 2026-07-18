// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
    await helpers.waitUntil(function () { return seen >= 1; }, {
      timeoutMs: 3000, label: "queue cron-repeat: consumer saw the job",
    });

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

// A cron-repeat re-enqueue must preserve the operator's maxAttempts. The
// re-enqueue already carries priority / classification / traceId forward;
// dropping maxAttempts silently resets a fail-fast cron job (maxAttempts: 2)
// to the queue default (5) on every occurrence, so the operator's retry
// budget quietly stops holding after the first firing.
async function testRepeatPreservesMaxAttempts() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    await b.queue.enqueue("cron-max", { tag: "loop" },
      { repeat: { cron: "* * * * *" }, maxAttempts: 3 });

    var seen = 0;
    var consumer = b.queue.consume("cron-max",
      async function () { seen++; },
      { concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });
    await helpers.waitUntil(function () { return seen >= 1; }, {
      timeoutMs: 3000, label: "queue cron-max: consumer saw the job",
    });

    var pending = await b.db.from("_blamejs_jobs")
      .where({ queueName: "cron-max", status: "pending" }).all();
    check("repeat: a follow-up pending row was scheduled", pending.length === 1);
    check("repeat: follow-up preserves the operator's maxAttempts (not the default 5)",
          Number(pending[0].maxAttempts) === 3);

    consumer.cancel();
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
    await helpers.waitUntil(function () { return attempts >= 1; }, {
      timeoutMs: 3000, label: "queue cron-fail: consumer attempted the job once",
    });
    // Give the failure path a tick to record before cancelling.
    await helpers.passiveObserve(100, "queue cron-fail: failure path records before consumer cancel");
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

    await helpers.waitUntil(function () { return ord.length === 3; }, {
      timeoutMs: 5000, label: "queue flow: 3 jobs processed",
    });
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
        if (job.payload.tag === "a") {
          await helpers.passiveObserve(80, "queue diamond: slow 'a' so 'b' would otherwise finish first");
        }
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
    await helpers.waitUntil(function () { return ord.length === 4; }, {
      timeoutMs: 5000, label: "queue diamond: 4 jobs processed",
    });
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

// R7-4: a deps-bearing flow child must be PARKED (non-leaseable) from the
// instant it is enqueued. enqueueFlow's first pass now passes dependsOn so
// queue-local parks the child at FLOW_BLOCKED immediately, instead of leaving
// it leaseable until the second pass — a window in which a concurrent consumer
// could lease it before its dependencies have run. Driven on the real
// queue-local consumer (enqueue → lease), distinguishing jobs by returned id.
async function testFlowChildParkedAtEnqueue() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var queueLocal = require("../../lib/queue-local");
    var ql = queueLocal.create();   // default store (framework db, single-node)

    var childEnq = await ql.enqueue("park-q", { n: "child" },
      { dependsOn: ["dep-a"], flowId: "f1", flowChildName: "child" });
    var rootEnq = await ql.enqueue("park-q", { n: "root" },
      { flowId: "f1", flowChildName: "root" });
    var leased = await ql.lease("park-q", 30000, 10);
    var leasedIds = leased.map(function (j) { return j.jobId; });
    check("R7-4: a root (no-deps) child is immediately leaseable",
          leasedIds.indexOf(rootEnq.jobId) !== -1);
    check("R7-4: a deps-bearing child is PARKED (not leased) at enqueue time",
          leasedIds.indexOf(childEnq.jobId) === -1);

    // Contrast: WITHOUT dependsOn at enqueue (the pre-fix first-pass shape) the
    // same child WOULD be leaseable — proving the parking is what closes the
    // race, not some other gate.
    var unparkedEnq = await ql.enqueue("park-q2", { n: "unparked" },
      { flowId: "f2", flowChildName: "unparked" });
    var leased2 = await ql.lease("park-q2", 30000, 10);
    check("R7-4 contrast: a child enqueued WITHOUT dependsOn is leaseable",
          leased2.map(function (j) { return j.jobId; }).indexOf(unparkedEnq.jobId) !== -1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// P1: if a dependency completes in the WINDOW between enqueueFlow's first
// pass (which enqueues + parks the deps-bearing child) and its second pass
// (patchFlowDeps, which resolves dependency NAMES → sibling jobIds), the
// completion has already released the child (complete() →
// _maybeReleaseFlowChildren bumps availableAt to now). patchFlowDeps must
// NOT re-park it: the dependency is done and never completes again, so a
// re-park would strand the child pending-but-unleaseable forever. Driven on
// the real queue-local consumer: enqueue (parked) → complete the dep (the
// in-window release) → patchFlowDeps → the child MUST still be leaseable.
async function testPatchFlowDepsDoesNotReparkReleasedChild() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var queueLocal = require("../../lib/queue-local");
    var ql = queueLocal.create();

    // First-pass shape: a no-deps dependency + a deps-bearing child parked by
    // its dependsOn (the dependency NAMES the first pass writes).
    var depEnq = await ql.enqueue("win-q", { n: "dep" },
      { flowId: "fw", flowChildName: "dep-a" });
    var childEnq = await ql.enqueue("win-q", { n: "child" },
      { dependsOn: ["dep-a"], flowId: "fw", flowChildName: "child" });

    // The dependency completes BEFORE the second pass — releasing the child.
    var leasedDep = await ql.lease("win-q", 30000, 10);
    var leasedDepIds = leasedDep.map(function (j) { return j.jobId; });
    check("window: the dependency leased while the child is still parked",
          leasedDepIds.indexOf(depEnq.jobId) !== -1 &&
          leasedDepIds.indexOf(childEnq.jobId) === -1);
    await ql.complete(depEnq.jobId);   // → _maybeReleaseFlowChildren releases the child

    // Second pass runs AFTER the in-window release.
    await ql.patchFlowDeps(childEnq.jobId, [depEnq.jobId]);

    // The child must still be leaseable. On the pre-fix tree patchFlowDeps
    // re-parked availableAt at MAX_SAFE_INTEGER, stranding it forever.
    var leasedChild = await ql.lease("win-q", 30000, 10);
    check("P1: a child released in the enqueue window is NOT re-parked by patchFlowDeps",
          leasedChild.map(function (j) { return j.jobId; }).indexOf(childEnq.jobId) !== -1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testFlowChildParkedAtEnqueue();
  await testPatchFlowDepsDoesNotReparkReleasedChild();
  await testFlowSurface();
  await testRepeatCronReEnqueuesAfterComplete();
  await testRepeatPreservesMaxAttempts();
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
