// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// #127: a task queued behind a timing-out (or erroring) task must not be
// dropped by slot recycling. _onTaskTimeout / _onWorkerError called
// _finishTask BEFORE marking the slot recycling. _finishTask sets slot.busy
// = false and drains the queue, so _findIdleSlot handed the freshly-queued
// task to the very slot whose worker was about to be terminated — the task's
// message went to a dying worker and came back as workerpool/worker-exit
// (or hung), even though a healthy replacement worker was about to spawn.
//
// This is deterministic (not a flaky race): _finishTask -> _drainQueue runs
// synchronously inside _onTaskTimeout, before _recycleWorker. The fix marks
// the slot recycling BEFORE _finishTask, so the drain skips the dying slot
// and the queued task waits for the replacement worker.
//
// RED on the buggy tree: the queued echo rejects with workerpool/worker-exit.
// GREEN after the fix: it runs on the replacement worker and returns its
// result.

var path = require("path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var FIXTURE = path.resolve(__dirname, "..", "fixtures", "worker-pool", "echo.js");

async function run() {
  // Single worker so the second task MUST queue behind the first, and a
  // short timeout so the busy-loop task is reaped quickly.
  var pool = b.workerPool.create(FIXTURE, { size: 1, taskTimeoutMs: 400 });
  try {
    // Task A occupies the only worker and busy-loops until it is reaped by
    // taskTimeoutMs. Its rejection (workerpool/timeout) is expected.
    var aErr = null;
    var aPromise = pool.run({ kind: "loop" }).catch(function (e) { aErr = e; });

    // Task B queues behind A (worker busy). It is a trivial echo that must
    // succeed once a healthy worker is available.
    var bResult = null;
    var bError  = null;
    var bPromise = pool.run({ kind: "echo", payload: { v: 42 } })
      .then(function (r) { bResult = r; })
      .catch(function (e) { bError = e; });

    // Bound the wait so a hung B fails the test rather than hanging the suite.
    // withTestTimeout clears its guard timer on settle (a raced waitUntil would
    // keep polling — and leave its in-flight poll timer — once Promise.all won).
    await helpers.withTestTimeout(
      "#127: queued task settles after the slot recycles",
      function () { return Promise.all([aPromise, bPromise]); },
      { timeoutMs: 8000 });

    check("#127 the timing-out task A is reaped (timeout, as expected)",
          aErr && aErr.code === "workerpool/timeout");
    check("#127 the task queued behind it is NOT dropped by slot recycling",
          bError === null);
    check("#127 the queued task runs on the replacement worker and returns its result",
          bResult && bResult.v === 42);
  } finally {
    // Await termination so the worker threads fully exit before run()
    // returns — an un-awaited terminate() leaves the worker's MessagePort
    // and reap timer alive past the assertions.
    await pool.terminate();
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
