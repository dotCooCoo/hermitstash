// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.workerPool — generic worker_threads pool with bounded concurrency.
 *
 * Reusable harness for operator-defined workers that need to run
 * CPU-bound work (compression, hashing, parser fan-out, batch render)
 * off the main event loop without rolling per-feature lifecycle code.
 * Wraps node:worker_threads with:
 *
 *   - Bounded concurrency — `size` workers, default
 *     `Math.max(2, os.cpus().length)`, clamped to 1..256.
 *   - Bounded queue — `maxQueueDepth` (default 1024) refuses new
 *     `run()` calls when the in-memory queue is full so a slow worker
 *     pool can't accumulate unbounded backlog.
 *   - Per-task timeout — `taskTimeoutMs` (default `C.TIME.minutes(5)`)
 *     terminates the worker on overrun; the pool spawns a replacement
 *     so steady-state size stays stable.
 *   - Worker recycle on uncaught error — same: terminate + spawn
 *     replacement; in-flight task on that worker rejects.
 *   - Audit-everything — every task lifecycle event emits to the
 *     audit chain: workerpool.task.completed / .failed / .timeout +
 *     workerpool.created / .terminated.
 *
 *   var pool = b.workerPool.create("/abs/path/to/worker.js", {
 *     size:           4,
 *     maxQueueDepth:  C.BYTES.kib(1),                  // 1024 max queued tasks
 *     taskTimeoutMs:  b.C.TIME.minutes(2),
 *     onExit:         function (code, workerId) { ... },
 *   });
 *   var result = await pool.run({ kind: "hash", payload: buf },
 *                                [buf.buffer]);  // optional transferList
 *   await pool.drain();
 *   await pool.terminate();
 *
 * Worker contract (operator-supplied script at scriptPath):
 *
 *   var { parentPort } = require("node:worker_threads");
 *   parentPort.on("message", function (msg) {
 *     try {
 *       var result = doWork(msg);
 *       parentPort.postMessage({ ok: true, result: result });
 *     } catch (e) {
 *       parentPort.postMessage({ ok: false, message: e.message });
 *     }
 *   });
 *
 * The pool tracks each task by an internal taskId (monotonic), pairs
 * the next reply from the assigned worker with that id, and resolves
 * the run() promise. The worker's reply must be a single
 * `{ ok: true, result }` or `{ ok: false, message }` envelope per
 * inbound message.
 *
 * Failure modes (every one throws WorkerPoolError):
 *   - workerpool/bad-script-path      — non-string / non-absolute / contains eval marker
 *   - workerpool/bad-size             — non-int / out of 1..256 range
 *   - workerpool/bad-max-queue-depth  — non-int / out of range
 *   - workerpool/bad-task-timeout     — non-positive-finite / out of range
 *   - workerpool/bad-on-exit          — onExit is not a function
 *   - workerpool/queue-full           — run() called past maxQueueDepth
 *   - workerpool/timeout              — task exceeded taskTimeoutMs
 *   - workerpool/worker-error         — worker emitted "error" mid-task
 *   - workerpool/worker-exit          — worker exited mid-task
 *   - workerpool/worker-bad-message   — worker reply was not envelope-shaped
 *   - workerpool/task-failed          — worker reported { ok: false }
 *   - workerpool/terminated           — pool.terminate() aborted in-flight tasks
 *   - workerpool/no-worker-threads    — runtime lacks node:worker_threads
 */

var os = require("node:os");
var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var { WorkerPoolError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MIN_SIZE = 1;
var MAX_SIZE = 256;                                                              // sanity ceiling on worker count, not bytes
var DEFAULT_MAX_QUEUE_DEPTH = 1024;                                              // task-queue depth, not bytes
var MAX_QUEUE_DEPTH_CAP = 1048576;                                               // task-queue depth ceiling, not bytes
var DEFAULT_TASK_TIMEOUT_MS = C.TIME.minutes(5);
var MAX_TASK_TIMEOUT_MS = C.TIME.hours(1);

// Refuse operator-supplied `eval`-style script paths. Worker_threads
// supports `{ eval: true }` to spawn from a string; this primitive
// only accepts a real absolute filesystem path so a typo / operator-
// supplied input can't be coerced into eval.
function _validateScriptPath(scriptPath) {
  validateOpts.requireNonEmptyString(scriptPath,
    "workerPool.create: scriptPath", WorkerPoolError, "workerpool/bad-script-path");
  if (!nodePath.isAbsolute(scriptPath)) {
    throw new WorkerPoolError("workerpool/bad-script-path",
      "workerPool.create: scriptPath must be an absolute path; got " +
      JSON.stringify(scriptPath));
  }
  // Defense-in-depth: refuse any path that looks like a data URL / eval
  // marker. Real filesystem paths never contain these.
  if (/^data:/i.test(scriptPath) || /^eval:/i.test(scriptPath)) {
    throw new WorkerPoolError("workerpool/bad-script-path",
      "workerPool.create: scriptPath must be a filesystem path, not an eval/data URL");
  }
}

function _emitAudit(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit best-effort */ }
}

function create(scriptPath, opts) {
  opts = opts || {};
  validateOpts(opts, ["size", "onExit", "maxQueueDepth", "taskTimeoutMs"], "workerPool.create");
  _validateScriptPath(scriptPath);

  var defaultSize = Math.max(2, (os.cpus() || []).length || 2);
  var size = (opts.size === undefined) ? defaultSize : opts.size;
  if (!numericBounds.isPositiveFiniteInt(size) || size < MIN_SIZE || size > MAX_SIZE) {
    throw new WorkerPoolError("workerpool/bad-size",
      "workerPool.create: opts.size must be a positive finite integer in [" +
      MIN_SIZE + ".." + MAX_SIZE + "]; got " + numericBounds.shape(size));
  }

  var maxQueueDepth = (opts.maxQueueDepth === undefined) ? DEFAULT_MAX_QUEUE_DEPTH : opts.maxQueueDepth;
  if (!numericBounds.isPositiveFiniteInt(maxQueueDepth) || maxQueueDepth > MAX_QUEUE_DEPTH_CAP) {
    throw new WorkerPoolError("workerpool/bad-max-queue-depth",
      "workerPool.create: opts.maxQueueDepth must be a positive finite integer <= " +
      MAX_QUEUE_DEPTH_CAP + "; got " + numericBounds.shape(maxQueueDepth));
  }

  var taskTimeoutMs = (opts.taskTimeoutMs === undefined) ? DEFAULT_TASK_TIMEOUT_MS : opts.taskTimeoutMs;
  if (!numericBounds.isPositiveFiniteInt(taskTimeoutMs) || taskTimeoutMs > MAX_TASK_TIMEOUT_MS) {
    throw new WorkerPoolError("workerpool/bad-task-timeout",
      "workerPool.create: opts.taskTimeoutMs must be a positive finite integer <= " +
      MAX_TASK_TIMEOUT_MS + "; got " + numericBounds.shape(taskTimeoutMs));
  }

  var onExit = opts.onExit;
  if (onExit !== undefined && onExit !== null && typeof onExit !== "function") {
    throw new WorkerPoolError("workerpool/bad-on-exit",
      "workerPool.create: opts.onExit must be a function; got " + typeof onExit);
  }

  var workerThreads;
  try { workerThreads = require("node:worker_threads"); }
  catch (_e) {
    throw new WorkerPoolError("workerpool/no-worker-threads",
      "workerPool.create: node:worker_threads is unavailable in this runtime");
  }

  // Per-pool state. Workers carry { id, worker, busy, currentTaskId,
  // currentTimer }. Queue holds { message, transferList, resolve,
  // reject } envelopes.
  var workerSlots = [];
  var workerSeq = 0;
  var taskSeq = 0;
  var queue = [];
  var totalTasks = 0;
  var totalErrors = 0;
  var terminated = false;
  var drainResolvers = [];

  function _spawnWorker() {
    var id = ++workerSeq;
    var worker;
    try {
      worker = new workerThreads.Worker(scriptPath);
    } catch (eSpawn) {
      _emitAudit("workerpool.spawn.failed", "failure", {
        scriptPath: scriptPath,
        message:    (eSpawn && eSpawn.message) || String(eSpawn),
      });
      throw new WorkerPoolError("workerpool/spawn-failed",
        "workerPool.create: failed to spawn worker: " + (eSpawn && eSpawn.message));
    }
    var slot = {
      id:             id,
      worker:         worker,
      busy:           false,
      currentTaskId:  null,
      currentTimer:   null,
      currentTask:    null,
    };
    worker.on("message", function (msg) { _onWorkerMessage(slot, msg); });
    worker.on("error",   function (err) { _onWorkerError(slot, err); });
    worker.on("exit",    function (code) { _onWorkerExit(slot, code); });
    workerSlots.push(slot);
    _emitAudit("workerpool.created", "success", { workerId: id, size: size });
    return slot;
  }

  function _findIdleSlot() {
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (!workerSlots[i].busy && !workerSlots[i].recycling) return workerSlots[i];
    }
    return null;
  }

  function _dispatch(slot, task) {
    slot.busy = true;
    slot.currentTaskId = task.id;
    slot.currentTask = task;
    slot.currentTimer = setTimeout(function () {
      _onTaskTimeout(slot);
    }, taskTimeoutMs);
    if (slot.currentTimer && typeof slot.currentTimer.unref === "function") {
      // Don't keep the event loop open just for the timeout.
      slot.currentTimer.unref();
    }
    try {
      slot.worker.postMessage(task.message, task.transferList || undefined);
    } catch (ePost) {
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/post-failed",
          "workerPool.run: postMessage failed: " + (ePost && ePost.message)));
    }
  }

  function _drainQueue() {
    while (!terminated && queue.length > 0) {
      var slot = _findIdleSlot();
      if (!slot) return;
      var task = queue.shift();
      _dispatch(slot, task);
    }
  }

  function _finishTask(slot, isError, payloadOrError) {
    var task = slot.currentTask;
    if (!task) return;
    if (slot.currentTimer) { clearTimeout(slot.currentTimer); slot.currentTimer = null; }
    slot.busy = false;
    slot.currentTaskId = null;
    slot.currentTask = null;
    totalTasks += 1;
    if (isError) {
      totalErrors += 1;
      task.reject(payloadOrError);
    } else {
      task.resolve(payloadOrError);
    }
    _maybeResolveDrain();
    _drainQueue();
  }

  function _onWorkerMessage(slot, msg) {
    if (!slot.currentTask) {
      // Stray message — worker posted before any task; ignore.
      return;
    }
    if (!msg || typeof msg !== "object" || typeof msg.ok !== "boolean") {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId, reason: "workerpool/worker-bad-message",
      });
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/worker-bad-message",
          "workerPool: worker reply was not { ok, ... } envelope-shaped"));
      return;
    }
    if (msg.ok) {
      _emitAudit("workerpool.task.completed", "success", {
        workerId: slot.id, taskId: slot.currentTaskId,
      });
      _finishTask(slot, false, msg.result);
    } else {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId,
        reason: "workerpool/task-failed",
        message: msg.message || "",
      });
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/task-failed",
          "workerPool: worker reported failure: " +
          (msg.message || "(no message)")));
    }
  }

  function _onWorkerError(slot, err) {
    var failingTask = slot.currentTask;
    _emitAudit("workerpool.task.failed", "failure", {
      workerId: slot.id, taskId: slot.currentTaskId,
      reason:   "workerpool/worker-error",
      message:  (err && err.message) || String(err),
    });
    // Mark the slot dying BEFORE _finishTask. _finishTask sets slot.busy =
    // false and drains the queue, so an unmarked slot would be handed a
    // freshly-queued task that then dies with this same worker. _recycleWorker
    // re-asserts the flag idempotently.
    slot.recycling = true;
    if (failingTask) {
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/worker-error",
          "workerPool: worker errored: " +
          (err && err.message ? err.message : String(err))));
    }
    // Worker is now in an indeterminate state; recycle it.
    _recycleWorker(slot);
  }

  function _onWorkerExit(slot, code) {
    var failingTask = slot.currentTask;
    if (failingTask) {
      _emitAudit("workerpool.task.failed", "failure", {
        workerId: slot.id, taskId: slot.currentTaskId,
        reason:   "workerpool/worker-exit", code: code,
      });
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/worker-exit",
          "workerPool: worker exited (code " + code + ") mid-task"));
    }
    _emitAudit("workerpool.terminated", "success", {
      workerId: slot.id, code: code,
    });
    if (typeof onExit === "function") {
      try { onExit(code, slot.id); } catch (_e) { /* drop-silent — operator hook */ }
    }
    // Remove from active set. If the pool is still live, spawn a replacement.
    var idx = workerSlots.indexOf(slot);
    if (idx !== -1) workerSlots.splice(idx, 1);
    if (!terminated && workerSlots.length < size) {
      try { _spawnWorker(); } catch (_e) { /* spawn already audited */ }
      _drainQueue();
    } else {
      _maybeResolveDrain();
    }
  }

  function _onTaskTimeout(slot) {
    var taskId = slot.currentTaskId;
    _emitAudit("workerpool.task.timeout", "failure", {
      workerId: slot.id, taskId: taskId, taskTimeoutMs: taskTimeoutMs,
    });
    var failingTask = slot.currentTask;
    // Mark the slot dying BEFORE _finishTask drains the queue, so the drain
    // skips this about-to-be-terminated slot instead of dispatching a queued
    // task onto it (which would die with the worker on terminate, surfacing as
    // workerpool/worker-exit on a task that never ran). _recycleWorker
    // re-asserts the flag idempotently.
    slot.recycling = true;
    if (failingTask) {
      _finishTask(slot, true,
        new WorkerPoolError("workerpool/timeout",
          "workerPool: task " + taskId + " exceeded taskTimeoutMs=" + taskTimeoutMs));
    }
    _recycleWorker(slot);
  }

  function _recycleWorker(slot) {
    // Mark the slot as dying so _findIdleSlot skips it before exit
    // fires. Without this, a new run() between terminate() and the
    // exit event would dispatch to a worker that's about to die and
    // surface as workerpool/worker-exit on a freshly-queued task.
    slot.busy = true;
    slot.recycling = true;
    try { slot.worker.terminate(); } catch (_e) { /* terminate best-effort */ }
  }

  function _maybeResolveDrain() {
    if (drainResolvers.length === 0) return;
    var anyBusy = false;
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (workerSlots[i].busy) { anyBusy = true; break; }
    }
    if (anyBusy || queue.length > 0) return;
    var pending = drainResolvers.splice(0, drainResolvers.length);
    for (var j = 0; j < pending.length; j += 1) {
      try { pending[j](); } catch (_e) { /* drop-silent — drain best-effort */ }
    }
  }

  function run(message, transferList) {
    if (terminated) {
      return Promise.reject(new WorkerPoolError("workerpool/terminated",
        "workerPool.run: pool has been terminated"));
    }
    if (transferList !== undefined && transferList !== null && !Array.isArray(transferList)) {
      return Promise.reject(new WorkerPoolError("workerpool/bad-transfer-list",
        "workerPool.run: transferList must be an array if supplied"));
    }
    if (queue.length >= maxQueueDepth) {
      return Promise.reject(new WorkerPoolError("workerpool/queue-full",
        "workerPool.run: queue is full (depth=" + queue.length +
        " >= maxQueueDepth=" + maxQueueDepth + ")"));
    }
    var taskId = ++taskSeq;
    return new Promise(function (resolve, reject) {
      var task = {
        id:           taskId,
        message:      message,
        transferList: transferList || null,
        resolve:      resolve,
        reject:       reject,
      };
      var slot = _findIdleSlot();
      if (slot) {
        _dispatch(slot, task);
      } else {
        queue.push(task);
      }
    });
  }

  function drain() {
    return new Promise(function (resolve) {
      var anyBusy = false;
      for (var i = 0; i < workerSlots.length; i += 1) {
        if (workerSlots[i].busy) { anyBusy = true; break; }
      }
      if (!anyBusy && queue.length === 0) { resolve(); return; }
      drainResolvers.push(resolve);
    });
  }

  function terminate() {
    terminated = true;
    // Reject queued tasks first so the caller sees a deterministic error.
    var pending = queue.splice(0, queue.length);
    for (var i = 0; i < pending.length; i += 1) {
      try {
        pending[i].reject(new WorkerPoolError("workerpool/terminated",
          "workerPool.terminate: task aborted before dispatch"));
      } catch (_e) { /* drop-silent — caller already has rejection */ }
    }
    // Then terminate every worker. _onWorkerExit will reject any in-flight task.
    var promises = [];
    for (var j = 0; j < workerSlots.length; j += 1) {
      var slot = workerSlots[j];
      if (slot.currentTimer) { clearTimeout(slot.currentTimer); slot.currentTimer = null; }
      try { promises.push(slot.worker.terminate()); }
      catch (_e) { /* terminate best-effort */ }
    }
    return Promise.all(promises).then(function () { /* swallow undefined returns */ });
  }

  function stats() {
    var busy = 0;
    for (var i = 0; i < workerSlots.length; i += 1) {
      if (workerSlots[i].busy) busy += 1;
    }
    return {
      size:         workerSlots.length,
      busy:         busy,
      idle:         workerSlots.length - busy,
      queued:       queue.length,
      totalTasks:   totalTasks,
      totalErrors:  totalErrors,
    };
  }

  // Bring up the pool eagerly so the first run() doesn't pay spawn cost.
  for (var k = 0; k < size; k += 1) _spawnWorker();

  return {
    run:          run,
    drain:        drain,
    terminate:    terminate,
    stats:        stats,
  };
}

module.exports = {
  create:                  create,
  MIN_SIZE:                MIN_SIZE,
  MAX_SIZE:                MAX_SIZE,
  DEFAULT_MAX_QUEUE_DEPTH: DEFAULT_MAX_QUEUE_DEPTH,
  MAX_QUEUE_DEPTH_CAP:     MAX_QUEUE_DEPTH_CAP,
  DEFAULT_TASK_TIMEOUT_MS: DEFAULT_TASK_TIMEOUT_MS,
  MAX_TASK_TIMEOUT_MS:     MAX_TASK_TIMEOUT_MS,
  WorkerPoolError:         WorkerPoolError,
};
