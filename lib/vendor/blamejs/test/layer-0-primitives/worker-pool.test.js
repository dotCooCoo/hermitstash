// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * worker-pool primitive — layer-0 tests for b.workerPool.create.
 *
 * Exercises:
 *   - happy path: run() resolves with worker-supplied result
 *   - bounded concurrency: parallel runs distribute across workers
 *   - bad-script-path: non-string / relative / data: URL refused
 *   - bad-size: out-of-range integer refused
 *   - bad-max-queue-depth / bad-task-timeout: same
 *   - bad-on-exit: non-function refused
 *   - queue-full: run() past maxQueueDepth refuses
 *   - timeout: long-running task surfaces workerpool/timeout
 *   - task-failed: worker reply with ok:false rejects
 *   - bad-message: non-envelope reply surfaces workerpool/worker-bad-message
 *   - drain: resolves once all in-flight + queued tasks finish
 *   - terminate: aborts queued + in-flight tasks
 *   - stats: shape includes size/busy/idle/queued/totalTasks/totalErrors
 *   - error class exposed: b.workerPool.WorkerPoolError is fn
 */

var path = require("path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var FIXTURE = path.resolve(__dirname, "..", "fixtures", "worker-pool", "echo.js");

function _makePool(opts) {
  return b.workerPool.create(FIXTURE, opts || { size: 2, taskTimeoutMs: 2000 });
}

async function testHappyPath() {
  var pool = _makePool();
  try {
    var r = await pool.run({ kind: "echo", payload: { hi: "there" } });
    check("happy-path returns echo payload",
          r && r.hi === "there");
    var d = await pool.run({ kind: "double", n: 21 });
    check("happy-path double returns 42", d === 42);
  } finally { await pool.terminate(); }
}

async function testParallelDispatch() {
  var pool = b.workerPool.create(FIXTURE, { size: 4, taskTimeoutMs: 2000 });
  try {
    var results = await Promise.all([
      pool.run({ kind: "double", n: 1 }),
      pool.run({ kind: "double", n: 2 }),
      pool.run({ kind: "double", n: 3 }),
      pool.run({ kind: "double", n: 4 }),
    ]);
    check("parallel dispatch returns all results in order",
          results.join(",") === "2,4,6,8");
    var s = pool.stats();
    check("stats.totalTasks counts every completion",
          s.totalTasks === 4);
    check("stats.totalErrors is zero on happy path",
          s.totalErrors === 0);
    check("stats.size matches configured size",
          s.size === 4);
  } finally { await pool.terminate(); }
}

function testBadScriptPath() {
  try {
    b.workerPool.create(42, { size: 1 });
    check("non-string scriptPath should refuse", false);
  } catch (e) {
    check("non-string scriptPath refused",
          e && e.code === "workerpool/bad-script-path");
  }
  try {
    b.workerPool.create("relative/path.js", { size: 1 });
    check("relative scriptPath should refuse", false);
  } catch (e) {
    check("relative scriptPath refused",
          e && e.code === "workerpool/bad-script-path");
  }
  try {
    b.workerPool.create("data:text/javascript,1", { size: 1 });
    check("data URL scriptPath should refuse", false);
  } catch (e) {
    check("data URL scriptPath refused",
          e && e.code === "workerpool/bad-script-path");
  }
}

function testBadSize() {
  try {
    b.workerPool.create(FIXTURE, { size: 0 });
    check("size=0 should refuse", false);
  } catch (e) {
    check("size=0 refused", e && e.code === "workerpool/bad-size");
  }
  try {
    b.workerPool.create(FIXTURE, { size: 9999 });
    check("size=9999 should refuse", false);
  } catch (e) {
    check("size out-of-range refused", e && e.code === "workerpool/bad-size");
  }
  try {
    b.workerPool.create(FIXTURE, { size: Infinity });
    check("size=Infinity should refuse", false);
  } catch (e) {
    check("size=Infinity refused", e && e.code === "workerpool/bad-size");
  }
}

function testBadMaxQueueDepth() {
  try {
    b.workerPool.create(FIXTURE, { size: 1, maxQueueDepth: -1 });
    check("negative maxQueueDepth should refuse", false);
  } catch (e) {
    check("negative maxQueueDepth refused",
          e && e.code === "workerpool/bad-max-queue-depth");
  }
}

function testBadTaskTimeout() {
  try {
    b.workerPool.create(FIXTURE, { size: 1, taskTimeoutMs: 0 });
    check("taskTimeoutMs=0 should refuse", false);
  } catch (e) {
    check("taskTimeoutMs=0 refused",
          e && e.code === "workerpool/bad-task-timeout");
  }
}

function testBadOnExit() {
  try {
    b.workerPool.create(FIXTURE, { size: 1, onExit: "nope" });
    check("non-fn onExit should refuse", false);
  } catch (e) {
    check("non-fn onExit refused", e && e.code === "workerpool/bad-on-exit");
  }
}

async function testQueueFull() {
  // size=1, queueDepth=1, then submit 3 tasks — third should refuse.
  var pool = b.workerPool.create(FIXTURE, {
    size: 1,
    maxQueueDepth: 1,
    taskTimeoutMs: 2000,
  });
  try {
    var p1 = pool.run({ kind: "echo", payload: 1 });
    var p2 = pool.run({ kind: "echo", payload: 2 });
    var refused = false;
    try {
      await pool.run({ kind: "echo", payload: 3 });
    } catch (e) {
      refused = e && e.code === "workerpool/queue-full";
    }
    check("third task past queue cap refused", refused === true);
    await Promise.all([p1, p2]);
  } finally { await pool.terminate(); }
}

async function testTimeoutEnforced() {
  // 1000ms timeout — short enough to keep the test fast, long enough
  // that worker-recycle on container CI runners (Linux/Alpine) doesn't
  // trip the timeout for the follow-up echo task waiting on a freshly
  // spawned worker.
  var pool = b.workerPool.create(FIXTURE, {
    size: 1,
    taskTimeoutMs: 1000,
  });
  try {
    var refused = false;
    try {
      await pool.run({ kind: "loop" });
    } catch (e) {
      refused = e && e.code === "workerpool/timeout";
    }
    check("infinite-loop task triggers workerpool/timeout", refused === true);
    // Pool should recycle the worker — a follow-up task should still complete.
    // Give the spawn-replacement a beat.
    var r = await pool.run({ kind: "echo", payload: "alive" });
    check("pool recycles after timeout", r === "alive");
  } finally { await pool.terminate(); }
}

async function testTaskFailed() {
  var pool = _makePool();
  try {
    var caught = null;
    try {
      await pool.run({ kind: "throw", reason: "deliberate" });
    } catch (e) { caught = e; }
    check("throw-kind surfaces workerpool/task-failed",
          caught && caught.code === "workerpool/task-failed");
    check("task-failed message includes worker text",
          caught && /deliberate/.test(caught.message));
    check("stats.totalErrors increments on task-failed",
          pool.stats().totalErrors === 1);
  } finally { await pool.terminate(); }
}

async function testBadMessage() {
  var pool = _makePool();
  try {
    var caught = null;
    try {
      await pool.run({ kind: "bad" });
    } catch (e) { caught = e; }
    check("non-envelope reply surfaces workerpool/worker-bad-message",
          caught && caught.code === "workerpool/worker-bad-message");
  } finally { await pool.terminate(); }
}

async function testDrain() {
  var pool = b.workerPool.create(FIXTURE, { size: 2, taskTimeoutMs: 2000 });
  try {
    var promises = [
      pool.run({ kind: "double", n: 1 }),
      pool.run({ kind: "double", n: 2 }),
      pool.run({ kind: "double", n: 3 }),
      pool.run({ kind: "double", n: 4 }),
    ];
    await pool.drain();
    var s = pool.stats();
    check("drain resolves with no busy workers", s.busy === 0);
    check("drain resolves with empty queue", s.queued === 0);
    var results = await Promise.all(promises);
    check("drain waits for all results",
          results.join(",") === "2,4,6,8");
  } finally { await pool.terminate(); }
}

async function testTerminateAbortsQueued() {
  var pool = b.workerPool.create(FIXTURE, {
    size: 1,
    maxQueueDepth: 32,
    taskTimeoutMs: 2000,
  });
  // Block the only worker, then queue more tasks behind it.
  var blocking = pool.run({ kind: "loop" }).catch(function (e) { return e; });
  var queued = pool.run({ kind: "echo", payload: "never" }).catch(function (e) { return e; });
  await pool.terminate();
  var qErr = await queued;
  check("queued task rejects with workerpool/terminated",
        qErr && qErr.code === "workerpool/terminated");
  // The blocking task may surface as terminated or worker-exit depending
  // on timing — both are valid for an aborted in-flight task.
  var bErr = await blocking;
  check("blocking task rejects after terminate",
        bErr && (bErr.code === "workerpool/terminated" ||
                 bErr.code === "workerpool/worker-exit" ||
                 bErr.code === "workerpool/timeout"));
  // Subsequent run() rejects deterministically.
  var caught = null;
  try { await pool.run({ kind: "echo", payload: 1 }); }
  catch (e) { caught = e; }
  check("post-terminate run rejects with workerpool/terminated",
        caught && caught.code === "workerpool/terminated");
}

async function testStatsShape() {
  var pool = _makePool();
  try {
    var s = pool.stats();
    check("stats has size",        typeof s.size === "number");
    check("stats has busy",        typeof s.busy === "number");
    check("stats has idle",        typeof s.idle === "number");
    check("stats has queued",      typeof s.queued === "number");
    check("stats has totalTasks",  typeof s.totalTasks === "number");
    check("stats has totalErrors", typeof s.totalErrors === "number");
  } finally { await pool.terminate(); }
}

function testErrorClassExposed() {
  check("workerPool.WorkerPoolError is fn",
        typeof b.workerPool.WorkerPoolError === "function");
}

async function run() {
  testErrorClassExposed();
  testBadScriptPath();
  testBadSize();
  testBadMaxQueueDepth();
  testBadTaskTimeout();
  testBadOnExit();
  await testHappyPath();
  await testParallelDispatch();
  await testQueueFull();
  await testTimeoutEnforced();
  await testTaskFailed();
  await testBadMessage();
  await testDrain();
  await testTerminateAbortsQueued();
  await testStatsShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK - " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
