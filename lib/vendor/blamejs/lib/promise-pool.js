// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.promisePool
 * @nav    Async
 * @title  Promise Pool
 *
 * @intro
 *   Bounded-concurrency task runner for promise-returning work — the
 *   common gap between `b.workerPool` (worker_threads for CPU-bound
 *   work) and `b.queue` (durable cross-process messaging). Wraps the
 *   typical "I have N parallel I/O fan-outs and want at most K in
 *   flight at any moment" pattern with back-pressure on enqueue
 *   (so the caller can't out-run the worker side) and a clean drain
 *   path that composes with `b.appShutdown`.
 *
 *   Two enqueue paths:
 *
 *     - `pool.run(taskFn)` returns a Promise that resolves to the
 *       task's return value (or rejects with the task's error). When
 *       the pool is at capacity, `run` waits until a slot frees
 *       BEFORE the task starts — back-pressure is part of the
 *       contract, not an opt.
 *
 *     - `pool.fire(taskFn)` is the synchronous-enqueue variant for
 *       fan-out from non-async contexts. Returns the same Promise
 *       but the call itself can't await — useful inside event
 *       handlers that fire-and-forget.
 *
 *   Drain semantics: `pool.drain()` resolves when every queued and
 *   in-flight task settles. Callers wire this into shutdown via
 *   `b.appShutdown.create({ priority: 50, run: () => pool.drain() })`
 *   so the process doesn't tear down with work mid-flight.
 *
 *   The pool does NOT retry failed tasks; rejection of a task's
 *   promise is the caller's signal. Operators that want retry compose
 *   `b.retry.withRetry` inside the task body.
 *
 * @card
 *   Bounded-concurrency promise pool — back-pressure on enqueue, drain-on-shutdown, no hidden retry. The thing every consumer reaches for p-limit for.
 */

var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var PromisePoolError = defineClass("PromisePoolError", { alwaysPermanent: true });

var MAX_CONCURRENCY = 65536;

/**
 * @primitive b.promisePool.create
 * @signature b.promisePool.create(opts)
 * @since     0.10.8
 * @status    stable
 * @related   b.workerPool.create, b.appShutdown.create, b.retry.withRetry
 *
 * Build a bounded-concurrency pool. Returns
 * `{ run, fire, drain, size, inFlight, queued, closed }`. The pool is
 * closed via `drain({ close: true })`; subsequent enqueues throw.
 *
 * `queueLimit` bounds how many tasks may wait, not how many may run. A task
 * offered while a slot is free starts whatever the limit is. One offered with
 * every slot busy and `queueLimit` tasks already waiting refuses with
 * `promise-pool/queue-full`, so `queueLimit: 0` means run it now or refuse it.
 *
 * A `concurrency` that is not an integer in [1, 65536] raises
 * `promise-pool/bad-concurrency`, a `queueLimit` that is neither a
 * non-negative integer nor `Infinity` raises
 * `promise-pool/bad-queue-limit`, and an `opts` that is not an object, or an
 * `onFireError` that is not a function, raises `promise-pool/bad-opts`. A task
 * that is not a function raises `promise-pool/bad-task`, and enqueueing after
 * `drain({ close: true })` raises `promise-pool/closed`.
 *
 * `run` hands its rejection to the caller that holds the returned promise.
 * `fire` is for a caller that drops it, so a task that throws there would
 * otherwise reach the process as an unhandled rejection and exit it; `fire`
 * contains the rejection and passes it to `onFireError` when one is given.
 * That hook is operator code, so its own throw or rejection is contained the
 * same way and never reaches the process either.
 * Both still raise `promise-pool/bad-task`, `promise-pool/queue-full` and
 * `promise-pool/closed` synchronously to the caller.
 *
 * @opts
 *   concurrency: number,        // required; integer in [1, 65536]
 *   queueLimit:  number,        // default Infinity; waiting tasks, not running ones
 *   onFireError: function,      // (err) => void; receives a fire task's rejection
 *
 * @example
 *   var pool = b.promisePool.create({ concurrency: 8 });
 *   var results = await Promise.all(items.map(function (item) {
 *     return pool.run(function () { return fetchOne(item); });
 *   }));
 *   await pool.drain({ close: true });
 */
function create(opts) {
  validateOpts.requireObject(opts, "b.promisePool.create",
    PromisePoolError, "promise-pool/bad-opts");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.concurrency,
    "b.promisePool.create: concurrency", PromisePoolError, "promise-pool/bad-concurrency");
  if (opts.concurrency === undefined || opts.concurrency > MAX_CONCURRENCY) {
    throw new PromisePoolError("promise-pool/bad-concurrency",
      "b.promisePool.create: concurrency must be an integer in [1, " +
      MAX_CONCURRENCY + "] (got " + opts.concurrency + ")");
  }
  var queueLimit = opts.queueLimit === undefined ? Infinity : opts.queueLimit;
  if (queueLimit !== Infinity) {
    numericBounds.requireNonNegativeFiniteIntIfPresent(queueLimit,
      "b.promisePool.create: queueLimit", PromisePoolError,
      "promise-pool/bad-queue-limit");
  }
  validateOpts.optionalFunction(opts.onFireError,
    "b.promisePool.create: onFireError", PromisePoolError, "promise-pool/bad-opts");
  var onFireError = opts.onFireError || null;
  var concurrency = opts.concurrency;
  var inFlight = 0;
  var queue = [];
  var drainWaiters = [];
  var closed = false;

  function _pump() {
    while (inFlight < concurrency && queue.length > 0) {
      var slot = queue.shift();
      inFlight += 1;
      Promise.resolve().then(function () { return slot.taskFn(); })
        .then(function (val) { slot.resolve(val); _settle(); })
        .catch(function (err) { slot.reject(err); _settle(); });
    }
    if (inFlight === 0 && queue.length === 0 && drainWaiters.length > 0) {
      var waiters = drainWaiters.slice();
      drainWaiters.length = 0;
      for (var i = 0; i < waiters.length; i += 1) waiters[i]();
    }
  }

  function _settle() {
    inFlight -= 1;
    _pump();
  }

  function _enqueue(taskFn) {
    if (typeof taskFn !== "function") {
      throw new PromisePoolError("promise-pool/bad-task",
        "b.promisePool: task must be a function returning a value or Promise");
    }
    if (closed) {
      throw new PromisePoolError("promise-pool/closed",
        "b.promisePool: pool is closed (drain({close:true}) was called)");
    }
    if (inFlight >= concurrency && queue.length >= queueLimit) {
      throw new PromisePoolError("promise-pool/queue-full",
        "b.promisePool: queueLimit=" + queueLimit + " reached with " +
        inFlight + " task(s) in flight");
    }
    return new Promise(function (resolve, reject) {
      queue.push({ taskFn: taskFn, resolve: resolve, reject: reject });
      _pump();
    });
  }

  function run(taskFn)  { return _enqueue(taskFn); }
  function fire(taskFn) {
    return safeAsync.containRejection(_enqueue(taskFn), function (e) {
      safeAsync.safeInvoke(onFireError, e);
    });
  }

  function drain(drainOpts) {
    drainOpts = drainOpts || {};
    return new Promise(function (resolve) {
      function _done() {
        if (drainOpts.close === true) closed = true;
        resolve();
      }
      if (inFlight === 0 && queue.length === 0) { _done(); return; }
      drainWaiters.push(_done);
    });
  }

  return {
    run:      run,
    fire:     fire,
    drain:    drain,
    size:     function () { return concurrency; },
    inFlight: function () { return inFlight; },
    queued:   function () { return queue.length; },
    closed:   function () { return closed; },
  };
}

module.exports = {
  create:           create,
  PromisePoolError: PromisePoolError,
};
