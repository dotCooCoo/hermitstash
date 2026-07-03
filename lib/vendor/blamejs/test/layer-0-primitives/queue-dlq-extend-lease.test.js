// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * queue — DLQ + extendLease.
 *
 * 9.11h: handler context exposes ctx.extendLease(ms) so long-running
 *        jobs can push their lease forward atomically before the
 *        sweeper reclaims them.
 * 9.11a: dlqList/dlqRetry/dlqSize surface failed-after-retries jobs
 *        for operator review; failure path emits system.queue.dlq.write
 *        when a job exhausts its retry budget.
 *
 * Run standalone: `node test/layer-0-primitives/queue-dlq-extend-lease.test.js`
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


async function testQueueDlqSurface() {
  check("b.queue.dlqList is a function",       typeof b.queue.dlqList === "function");
  check("b.queue.dlqRetry is a function",      typeof b.queue.dlqRetry === "function");
  check("b.queue.dlqSize is a function",       typeof b.queue.dlqSize === "function");
}

async function testQueueExtendLeaseBackend() {
  // Direct-against-backend test of extendLease — no consumer needed.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qel-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("ext", { x: 1 });

    // Lease one job so it's in 'inflight'.
    // Backend instance is private to queue.js — use the SQL directly to
    // verify status transitions (we round-trip via b.queue's public API
    // for everything else).
    var leaseRows = b.db.prepare(
      "SELECT _id, leaseExpiresAt FROM _blamejs_jobs WHERE status = 'pending'"
    ).all();
    check("setup: 1 pending job",                 leaseRows.length === 1);

    // Manually set it to inflight with a short lease, then call backend.extendLease.
    // Easier: use queue.consume with a handler that calls ctx.extendLease.
    var observed = null;
    var consumer = b.queue.consume("ext", async function (job, ctx) {
      check("ctx provided to handler",            ctx && typeof ctx.extendLease === "function");
      var ok = await ctx.extendLease(60 * 1000);
      observed = ok;
    }, { concurrency: 1, pollIntervalMs: 30, fastPollMs: 10, leaseDurationMs: 1000 });

    await helpers.waitUntil(function () { return observed === true; }, {
      timeoutMs: 2000, label: "queue extendLease: inflight observation",
    });
    check("extendLease: returns true while inflight", observed === true);

    consumer.cancel();
    await b.queue.shutdown({ timeoutMs: 1000 });
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueDlqLifecycle() {
  // Enqueue a job that always fails. After maxAttempts retries it lands
  // in DLQ. dlqList surfaces it; dlqRetry resets to pending.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dlq-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var attempts = 0;
    var consumer = b.queue.consume("doomed", async function () {
      attempts++;
      throw new Error("intentional fail #" + attempts);
    }, { concurrency: 1, pollIntervalMs: 20, fastPollMs: 10, leaseDurationMs: 5000 });

    await b.queue.enqueue("doomed", { id: 1 }, { maxAttempts: 2 });

    // Wait for both attempts to fire AND the row to land in 'failed'
    // status (the second fail() is what writes status='failed').
    await helpers.waitUntil(function () {
      var row = b.db.prepare(
        "SELECT status FROM _blamejs_jobs WHERE queueName = 'doomed'"
      ).get();
      return row && row.status === "failed";
    }, { timeoutMs: 10000, label: "queue dlq: doomed job reached failed status" });

    consumer.cancel();
    // Wait briefly for shutdown to settle
    await b.queue.shutdown({ timeoutMs: 1000 });
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var dlq = await b.queue.dlqList("doomed");
    check("dlq: list returns 1 failed job",       dlq.length === 1);
    check("dlq: payload preserved",                dlq[0].payload && dlq[0].payload.id === 1);
    check("dlq: lastError captured (unsealed)",    typeof dlq[0].lastError === "string" && dlq[0].lastError.indexOf("intentional fail") !== -1);
    check("dlq: attempts == maxAttempts",          dlq[0].attempts === dlq[0].maxAttempts);

    var sz = await b.queue.dlqSize("doomed");
    check("dlqSize: 1",                            sz === 1);

    // Retry — resets to pending
    var ok = await b.queue.dlqRetry(dlq[0].jobId);
    check("dlqRetry: returns true",                ok === true);
    var sizeAfter = await b.queue.dlqSize("doomed");
    check("dlqSize after retry: 0",                sizeAfter === 0);

    // Audit chain captured the DLQ-write event
    await b.audit.flush();
    var dlqRows = await b.audit.query({ action: "system.queue.dlq.write" });
    check("audit: dlq.write event emitted on final failure", dlqRows.length === 1);

    var retryRows = await b.audit.query({ action: "system.queue.dlq.retry" });
    check("audit: dlq.retry event emitted on operator retry", retryRows.length === 1);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueDlqRetryUnknownReturnsFalse() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dlq-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var ok = await b.queue.dlqRetry("definitely-not-a-real-job-id");
    check("dlqRetry: unknown job returns false",  ok === false);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueExtendLeaseRejectsBadArgs() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qel-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var threw = null;
    var consumer = b.queue.consume("bad-ext", async function (_job, ctx) {
      try { await ctx.extendLease(0); } catch (e) { threw = e; }
    }, { concurrency: 1, pollIntervalMs: 20, fastPollMs: 10, leaseDurationMs: 5000 });
    await b.queue.enqueue("bad-ext", {});
    await helpers.waitUntil(function () { return threw !== null; }, {
      timeoutMs: 2000, label: "queue extendLease: zero argument rejection threw",
    });
    check("extendLease: zero rejected",            threw && /positive/i.test(threw.message));
    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// A stale completer/failer whose lease expired and whose job was re-leased
// to another worker must NOT mark the new worker's in-progress job done or
// re-queue it. queue-local fences complete()/fail()/extendLease() on the
// leased `attempts` value (bumped once per lease), mirroring the redis
// backend's COMPLETE_LUA/FAIL_LUA fence. Drive the backend directly so the
// interleaving is deterministic (no slow-handler timing).
async function testQueueLocalLeaseFence() {
  var localProto = require("../../lib/queue-local");
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qlfence-"));
  try {
    await setupTestDb(tmpDir);
    var ql = localProto.create({});
    var enq = await ql.enqueue("qlf", { work: 1 }, { maxAttempts: 5 });

    // Worker A leases on a short lease; it expires; sweepExpired re-queues it.
    var leaseA = await ql.lease("qlf", 1, 1);
    check("ql-fence: A leased at attempts=1", leaseA.length === 1 && leaseA[0].attempts === 1);
    var attemptA = leaseA[0].attempts;
    await helpers.waitUntil(async function () {
      var n = await ql.sweepExpired();
      return n >= 1 ? n : false;
    }, { label: "queue-local fence: A's lease expired + swept" });
    // Worker B re-leases (attempts → 2) and is STILL RUNNING.
    var leaseB = await ql.lease("qlf", 60000, 1);
    check("ql-fence: B re-leased at attempts=2",
          leaseB.length === 1 && leaseB[0].jobId === enq.jobId && leaseB[0].attempts === 2);

    // A finishes late: complete() with A's leased attempts must NOT win.
    var compA = await ql.complete(enq.jobId, { attempt: attemptA });
    check("ql-fence: stale A complete() does not steal the re-leased job", compA === false);
    // A fails late: fail() with A's leased attempts must NOT re-queue/DLQ.
    var failA = await ql.fail(enq.jobId, "late", { attempt: attemptA });
    check("ql-fence: stale A fail() does not clobber the re-leased job", failA === false);
    // B (current holder) can still complete its own job.
    var compB = await ql.complete(enq.jobId, { attempt: 2 });
    check("ql-fence: B (current lease holder) can still complete", compB === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testQueueDlqSurface();
  await testQueueExtendLeaseBackend();
  await testQueueDlqLifecycle();
  await testQueueDlqRetryUnknownReturnsFalse();
  await testQueueExtendLeaseRejectsBadArgs();
  await testQueueLocalLeaseFence();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
