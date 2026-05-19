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
var { defineClass } = require("./framework-error");

var PromisePoolError = defineClass("PromisePoolError", { alwaysPermanent: true });

var MAX_CONCURRENCY = 65536;                                                                    // allow:raw-byte-literal — uint16 ceiling on parallel I/O fan-out

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
 * @opts
 *   concurrency: number,        // required; integer in [1, 65536]
 *   queueLimit:  number,        // default Infinity; once exceeded, enqueue throws
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
    numericBounds.requirePositiveFiniteIntIfPresent(queueLimit + 1,
      "b.promisePool.create: queueLimit (must be non-negative int)", PromisePoolError,
      "promise-pool/bad-queue-limit");
  }
  var concurrency = opts.concurrency;
  var inFlight = 0;
  var queue = [];                // FIFO of pending { taskFn, resolve, reject }
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
    if (queue.length >= queueLimit) {
      throw new PromisePoolError("promise-pool/queue-full",
        "b.promisePool: queueLimit=" + queueLimit + " reached");
    }
    return new Promise(function (resolve, reject) {
      queue.push({ taskFn: taskFn, resolve: resolve, reject: reject });
      _pump();
    });
  }

  function run(taskFn)  { return _enqueue(taskFn); }
  function fire(taskFn) { return _enqueue(taskFn); }

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
