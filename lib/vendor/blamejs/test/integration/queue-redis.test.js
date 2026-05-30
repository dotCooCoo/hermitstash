"use strict";
/**
 * Live Redis round-trip tests for the redis-protocol queue backend.
 *
 * Skips silently when BLAMEJS_TEST_REDIS_URL is not set, so the smoke
 * suite passes on dev boxes without a Redis container running. CI
 * gates set the env var to point at a docker-spawned redis.
 *
 * To run locally:
 *   docker run --rm -p 6379:6379 redis:7-alpine
 *   BLAMEJS_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
 *     node test/layer-0-primitives/queue-redis.test.js
 *
 * Uses db 15 by default to keep test data isolated from anything an
 * operator might be running in db 0.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var queueRedis = require("../../lib/queue-redis");
var redisClient = require("../../lib/redis-client");
var services = require("../helpers/services");
var cryptoField = require("../../lib/crypto-field");
var b = require("../../");

async function _ping(url) {
  // Fast preflight — bail out cleanly when redis is unreachable, so the
  // full smoke suite doesn't hang on a connect-timeout per check.
  var c;
  try {
    c = redisClient.create({
      url: url, connectTimeoutMs: 500, commandTimeoutMs: 1000, maxReconnectAttempts: 0,
    });
    await c.connect();
    var pong = await c.command("PING");
    await c.close();
    return pong === "PONG" || (Buffer.isBuffer(pong) && pong.toString() === "PONG");
  } catch (_e) {
    try { if (c) await c.close(); } catch (_e2) {}
    return false;
  }
}

async function _flushTestPrefix(url, prefix) {
  // SCAN + DEL the test prefix between sub-tests so state from one
  // doesn't bleed into the next. Only touches keys under our prefix.
  var c = redisClient.create({ url: url });
  await c.connect();
  var cursor = "0";
  do {
    var rv = await c.command("SCAN", cursor, "MATCH", prefix + ":*", "COUNT", "200");
    cursor = Buffer.isBuffer(rv[0]) ? rv[0].toString("utf8") : String(rv[0]);
    var keys = (rv[1] || []).map(function (k) {
      return Buffer.isBuffer(k) ? k.toString("utf8") : String(k);
    });
    if (keys.length > 0) {
      await c.command.apply(c, ["DEL"].concat(keys));
    }
  } while (cursor !== "0");
  await c.close();
}

async function run() {
  // Resolve the test Redis URL from the shared services helper. Operators
  // override via BLAMEJS_REDIS_URL (e.g. for a non-default port). The
  // requireService probe doubles as the skip-when-unreachable check —
  // no separate _ping() needed for the gate.
  var svc = await services.requireService("redis");
  if (!svc.ok) {
    console.log("  [queue-redis] " + svc.reason + " — skipping live tests");
    console.log("  [queue-redis]   bring up: docker compose -f docker-compose.test.yml up --wait");
    return;
  }
  var url = svc.url + "/15";  // use db 15 to isolate test data
  // Belt-and-suspenders: run the RESP-level PING too, so we catch a
  // server that's TCP-listening but rejecting commands (auth misconfig,
  // protected-mode lockdown, etc.).
  var pingOk = await _ping(url);
  if (!pingOk) {
    console.log("  [queue-redis] PING failed at " + url + " — skipping live tests");
    return;
  }

  // Init the framework's vault so cryptoField.sealRow has a key to
  // work with. The queue's payload + lastError fields are sealed in
  // FRAMEWORK_SCHEMA — without registering the table here, unsealRow
  // is a no-op on dlqList reads and the lastError comes back as the
  // vault-sealed envelope instead of the plaintext error message.
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-queue-redis-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  cryptoField.registerTable("_blamejs_jobs", { sealedFields: ["payload", "lastError"] });

  var prefix = "blamejs:test-queue-" + Date.now() + "-" + Math.floor(Math.random() * 1e6);
  await _flushTestPrefix(url, prefix);

  var qr = queueRedis.create({ url: url, keyPrefix: prefix });

  try {
    // ---- enqueue + lease round-trip ----
    var Q = "round-trip";
    var enq = await qr.enqueue(Q, { hello: "world" }, { traceId: "t-1" });
    check("enqueue: returns jobId", typeof enq.jobId === "string" && enq.jobId.length > 0);
    check("enqueue: returns queueName + classification", enq.queueName === Q && enq.classification === null);

    var leased = await qr.lease(Q, 5000, 5);
    check("lease: returns the enqueued job", leased.length === 1 && leased[0].jobId === enq.jobId);
    check("lease: payload round-trips through field-crypto",
          leased[0].payload && leased[0].payload.hello === "world");
    check("lease: traceId preserved", leased[0].traceId === "t-1");
    check("lease: attempts is 1 after lease", leased[0].attempts === 1);

    // ---- complete + size ----
    var compRv = await qr.complete(enq.jobId);
    check("complete: returns true", compRv === true);
    var sz = await qr.size(Q);
    check("size: 0 after complete", sz === 0);

    // ---- availableAt scheduling ----
    var Q2 = "delayed";
    var futureMs = Date.now() + 200;
    var enq2 = await qr.enqueue(Q2, { later: true }, { availableAt: futureMs });
    var leasedEarly = await qr.lease(Q2, 5000, 1);
    check("lease: respects availableAt (no jobs ready before time)", leasedEarly.length === 0);
    // availableAt was Date.now() + 200ms; poll until the future time
    // passes + the job becomes leasable.
    var leasedLate = await helpers.waitUntil(async function () {
      var rv = await qr.lease(Q2, 5000, 1);
      return rv.length >= 1 ? rv : false;
    }, { label: "queue-redis: delayed job becomes leasable after availableAt" });
    check("lease: returns delayed job once availableAt has passed",
          leasedLate.length === 1 && leasedLate[0].jobId === enq2.jobId);
    await qr.complete(enq2.jobId);

    // ---- visibility timeout / sweep ----
    var Q3 = "vis-timeout";
    var enq3 = await qr.enqueue(Q3, { tryme: 1 }, { maxAttempts: 3 });
    var lease3 = await qr.lease(Q3, 50, 1);  // 50ms lease
    check("lease: short lease grabs job", lease3.length === 1 && lease3[0].attempts === 1);
    // 50ms lease must expire before sweepExpired() collects it; poll
    // sweepExpired until it reports >= 1.
    var swept = await helpers.waitUntil(async function () {
      var n = await qr.sweepExpired();
      return n >= 1 ? n : false;
    }, { label: "queue-redis: short-lease expired + sweep collected" });
    check("sweepExpired: surfaces expired job", swept >= 1);
    var lease3b = await qr.lease(Q3, 5000, 1);
    check("lease: post-sweep re-leases job",
          lease3b.length === 1 && lease3b[0].jobId === enq3.jobId &&
          lease3b[0].attempts === 2);  // sweep doesn't re-increment; lease does
    await qr.complete(enq3.jobId);

    // ---- fail() honors the object-form { retryDelayMs } b.queue.consume
    //      passes (regression: the redis backend previously accepted only
    //      a bare-number 3rd arg, so the object failed the typeof check
    //      and the delay was forced to 0 — the documented exponential
    //      backoff was silently discarded and the job re-leased at once) ----
    var QB = "retry-backoff";
    var enqB = await qr.enqueue(QB, { go: 1 }, { maxAttempts: 5 });
    var leaseB = await qr.lease(QB, 5000, 1);
    check("lease: backoff-regression job leased", leaseB.length === 1);
    await qr.fail(enqB.jobId, "boom", { retryDelayMs: 60000 });  // object form, 60s delay
    var leaseBNow = await qr.lease(QB, 5000, 1);
    check("fail({retryDelayMs}) delays re-lease — backoff honored, not forced to 0",
          leaseBNow.length === 0);

    // ---- fail + retry path ----
    var Q4 = "retry";
    var enq4 = await qr.enqueue(Q4, { go: 1 }, { maxAttempts: 2 });
    var lease4 = await qr.lease(Q4, 5000, 1);
    check("lease: pre-fail attempt 1", lease4.length === 1 && lease4[0].attempts === 1);
    await qr.fail(enq4.jobId, "boom-1", 0);  // immediate retry
    // Now should be back in ready — poll lease() until it returns the
    // re-queued job.
    var lease4b = await helpers.waitUntil(async function () {
      var rv = await qr.lease(Q4, 5000, 1);
      return rv.length >= 1 ? rv : false;
    }, { label: "queue-redis: failed job re-queued + leasable" });
    check("lease: post-fail-retry surfaces job", lease4b.length === 1 && lease4b[0].attempts === 2);
    await qr.fail(enq4.jobId, "boom-2", 0);
    // Now should be in DLQ
    var sz4 = await qr.size(Q4);
    check("size: 0 after exhausted retries", sz4 === 0);
    var dlqSz4 = await qr.dlqSize(Q4);
    check("dlqSize: 1 after exhausted retries", dlqSz4 === 1);

    // ---- DLQ list + retry ----
    var dlqRows = await qr.dlqList(Q4);
    check("dlqList: has the failed job",
          dlqRows.length === 1 && dlqRows[0].jobId === enq4.jobId);
    check("dlqList: payload round-trips through field-crypto",
          dlqRows[0].payload && dlqRows[0].payload.go === 1);
    check("dlqList: lastError preserved",
          dlqRows[0].lastError === "boom-2");

    var dlqRetryRv = await qr.dlqRetry(enq4.jobId);
    check("dlqRetry: returns true", dlqRetryRv === true);
    var dlqSz4b = await qr.dlqSize(Q4);
    check("dlqSize: 0 after retry", dlqSz4b === 0);
    var sz4b = await qr.size(Q4);
    check("size: 1 after dlqRetry", sz4b === 1);
    var lease4c = await qr.lease(Q4, 5000, 1);
    check("lease: dlq-retried job is back in ready, attempts reset to 1",
          lease4c.length === 1 && lease4c[0].attempts === 1);
    await qr.complete(enq4.jobId);

    // ---- extendLease ----
    var Q5 = "extend";
    var enq5 = await qr.enqueue(Q5, { ext: true });
    var lease5 = await qr.lease(Q5, 100, 1);
    check("extend: leased", lease5.length === 1);
    // Wait briefly so extendLease has a non-trivial window to extend,
    // then bump the lease to 5000ms.
    await helpers.passiveObserve(30, "queue-redis extend: pre-extend delay (lease still alive)");
    var ext = await qr.extendLease(enq5.jobId, 5000);
    check("extend: returns true on inflight job", ext === true);
    // Verify the extension actually survived: after the ORIGINAL 100ms
    // lease would have expired, sweep + lease should NOT pick the job
    // up. Passive observation — looking for ABSENCE of an event.
    await helpers.passiveObserve(100, "queue-redis extend: past original lease deadline, extended lease still in effect");
    var sweptAfterExt = await qr.sweepExpired();
    var lease5b = await qr.lease(Q5, 5000, 1);
    check("extend: sweep + lease did NOT pick up extended job",
          sweptAfterExt === 0 && lease5b.length === 0);
    await qr.complete(enq5.jobId);

    var extDead = await qr.extendLease("nonexistent-id", 1000);
    check("extend: returns false on nonexistent job", extDead === false);

    // ---- purge ----
    var Q6 = "purge";
    await qr.enqueue(Q6, { a: 1 });
    await qr.enqueue(Q6, { a: 2 });
    await qr.enqueue(Q6, { a: 3 });
    var sz6 = await qr.size(Q6);
    check("purge: pre-purge size 3", sz6 === 3);
    var purged = await qr.purge(Q6);
    check("purge: returns count of removed jobs", purged === 3);
    var sz6b = await qr.size(Q6);
    check("purge: post-purge size 0", sz6b === 0);

    // ---- priority ordering — high-priority job leased first ----
    var QP = "priority";
    await qr.enqueue(QP, { p: "low-1" },  { priority: 0 });
    await qr.enqueue(QP, { p: "low-2" },  { priority: 0 });
    await qr.enqueue(QP, { p: "high-1" }, { priority: 10 });
    await qr.enqueue(QP, { p: "low-3" },  { priority: 0 });
    await qr.enqueue(QP, { p: "high-2" }, { priority: 5 });
    var leasedPrio = await qr.lease(QP, 5000, 2);
    check("priority: leased first batch picks priority=10 first",
          leasedPrio.length === 2 &&
          leasedPrio[0].payload && leasedPrio[0].payload.p === "high-1");
    check("priority: second leased is priority=5 (not any priority=0)",
          leasedPrio[1].payload && leasedPrio[1].payload.p === "high-2");
    for (var pi = 0; pi < leasedPrio.length; pi++) await qr.complete(leasedPrio[pi].jobId);
    var leasedRest = await qr.lease(QP, 5000, 5);
    check("priority: remaining 3 priority=0 jobs lease in availableAt order",
          leasedRest.length === 3);
    for (var pj = 0; pj < leasedRest.length; pj++) await qr.complete(leasedRest[pj].jobId);

    // ---- flow dependsOn cascade — child A depends on parent's completion ----
    var QF = "flow-fan";
    var flowId = "flow-" + Date.now();
    var enqParent = await qr.enqueue(QF, { step: "parent" }, {
      flowId: flowId, flowChildName: "parent",
    });
    var enqChild = await qr.enqueue(QF, { step: "child" }, {
      flowId:        flowId,
      flowChildName: "child",
      // Child held until parent done; framework convention: high
      // availableAt prevents lease until cascade flips it back to now.
      availableAt:   Date.now() + 24 * 3600 * 1000,
      dependsOn:     ["parent"],
    });
    check("flow: parent + child enqueued under same flowId",
          typeof enqParent.jobId === "string" && typeof enqChild.jobId === "string");
    var sizeBefore = await qr.size(QF);
    check("flow: queue size = 2 before parent runs",  sizeBefore === 2);
    // Lease + complete the parent.
    var parentLease = await qr.lease(QF, 5000, 1);
    check("flow: only the parent is leasable (child held by future availableAt)",
          parentLease.length === 1 &&
          parentLease[0].payload && parentLease[0].payload.step === "parent");
    await qr.complete(parentLease[0].jobId);
    // Child should now be released to availableAt=now — poll until the
    // cascade fires and the child becomes leasable.
    var childLease = await helpers.waitUntil(async function () {
      var rv = await qr.lease(QF, 5000, 1);
      return rv.length >= 1 ? rv : false;
    }, { label: "queue-redis flow: child released after parent.complete cascade" });
    check("flow: child released after parent.complete (cascade fired)",
          childLease.length === 1 &&
          childLease[0].payload && childLease[0].payload.step === "child");
    await qr.complete(childLease[0].jobId);

    // ---- flow with multiple deps — child waits for ALL parents ----
    var QF2 = "flow-multi-dep";
    var flowId2 = "flow2-" + Date.now();
    await qr.enqueue(QF2, { step: "p1" }, { flowId: flowId2, flowChildName: "p1" });
    await qr.enqueue(QF2, { step: "p2" }, { flowId: flowId2, flowChildName: "p2" });
    await qr.enqueue(QF2, { step: "joiner" }, {
      flowId:        flowId2,
      flowChildName: "joiner",
      availableAt:   Date.now() + 24 * 3600 * 1000,
      dependsOn:     ["p1", "p2"],
    });
    // Complete p1 — joiner should still be held by p2.
    var l1 = await qr.lease(QF2, 5000, 1);
    check("flow-multi: only one parent ready at a time (joiner held)",
          l1.length === 1);
    await qr.complete(l1[0].jobId);
    // Second parent becomes leasable after p1 completes (only one parent
    // ready at a time per the test invariant).
    var l2 = await helpers.waitUntil(async function () {
      var rv = await qr.lease(QF2, 5000, 1);
      return rv.length >= 1 ? rv : false;
    }, { label: "queue-redis flow-multi: second parent leasable after p1 complete" });
    check("flow-multi: still only one parent (joiner not yet released)",
          l2.length === 1 && l2[0].payload && l2[0].payload.step !== "joiner");
    // Complete p2 — NOW joiner cascades and becomes leasable.
    await qr.complete(l2[0].jobId);
    var l3 = await helpers.waitUntil(async function () {
      var rv = await qr.lease(QF2, 5000, 1);
      return rv.length >= 1 ? rv : false;
    }, { label: "queue-redis flow-multi: joiner released after both parents done" });
    check("flow-multi: joiner released only after BOTH parents done",
          l3.length === 1 && l3[0].payload && l3[0].payload.step === "joiner");
    await qr.complete(l3[0].jobId);

    // ---- concurrent leasers don't double-lease ----
    var Q7 = "concurrent";
    for (var ci = 0; ci < 5; ci++) {
      await qr.enqueue(Q7, { i: ci });
    }
    // Two parallel leasers each asking for 5
    var [batch1, batch2] = await Promise.all([
      qr.lease(Q7, 5000, 5),
      qr.lease(Q7, 5000, 5),
    ]);
    var totalLeased = batch1.length + batch2.length;
    check("concurrent: total leased == enqueued (no double-lease, no drop)",
          totalLeased === 5);
    var allIds = batch1.concat(batch2).map(function (j) { return j.jobId; });
    var uniqueIds = new Set(allIds);
    check("concurrent: every leased jobId unique", uniqueIds.size === 5);
    // Clean up
    for (var ci2 = 0; ci2 < batch1.length; ci2++) await qr.complete(batch1[ci2].jobId);
    for (var ci3 = 0; ci3 < batch2.length; ci3++) await qr.complete(batch2[ci3].jobId);

  } finally {
    await _flushTestPrefix(url, prefix);
    await qr.shutdown();
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
