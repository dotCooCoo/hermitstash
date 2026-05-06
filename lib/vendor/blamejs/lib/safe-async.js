"use strict";
/**
 * Async resilience + safety primitives.
 *
 * The framework's async surfaces (external-db queries, cluster
 * coordination, queue operations, audit chain writes) all share the
 * same hazards: races between interleaved awaits, unbounded retries
 * masking real failures, hangs from unresponsive backends, and partial
 * results from operator-supplied drivers. This module collects the
 * primitives the framework uses to handle those hazards consistently.
 *
 * Surface includes:
 *   - Async coordination: withTimeout, withSignal, sleep, repeating,
 *     flushLoop, safeAwait, asyncRetry
 *   - Async state objects: Mutex, Semaphore, Once, CircuitBreaker
 *   - Sync helpers used by async pipelines: safeInvoke (callback
 *     wrapper with optional onError), makeDropCallback (factory for
 *     log-stream-style onDrop callbacks), makeScheduledFlush
 *     (idempotent setTimeout coalesce-and-flush helper)
 *
 * Design posture:
 *
 *   - **AbortSignal everywhere.** Every primitive that takes time
 *     accepts an `AbortSignal` and aborts cleanly when the signal
 *     fires. This is the modern Node.js convention (Node 18+) and
 *     replaces the older "cancellation token" pattern. Operators who
 *     don't pass a signal get the legacy non-cancellable behaviour.
 *
 *   - **Error.cause preserved.** Wrapper errors set `.cause` to the
 *     original failure so debugging traces back to the root. Callers
 *     who walk `.cause` chains see the full picture.
 *
 *   - **No leaked Promises.** Mutex / Semaphore release on path-out
 *     in finally blocks — even cancellation. No pending acquirer
 *     stays referenced after its abort.
 *
 *   - **Bounded by default.** Semaphore / Queue have explicit limits
 *     and reject acquisitions over the limit rather than growing
 *     unboundedly. Operators size limits explicitly for their workload.
 *
 *   - **Fail loud.** Errors propagate; primitives never silently
 *     swallow. safeAwait() opt-in for callers who need {error, value}
 *     tuples; everything else throws / rejects.
 *
 * Public API:
 *
 *   withTimeout(promise, ms, opts?)        promise; rejects on timeout
 *   withSignal(promise, signal)            promise; rejects on abort
 *   withTimeoutSignal(signal, ms)          AbortSignal composing user
 *                                          signal + a fresh timeout. Used
 *                                          by I/O primitives that already
 *                                          accept a signal and want to
 *                                          add a wall-clock deadline.
 *   sleep(ms, opts?)                       promise that resolves after ms;
 *                                          opts.signal aborts mid-sleep,
 *                                          timer is unref'd so a pending
 *                                          sleep doesn't keep the process
 *                                          alive
 *   safeAwait(promise)                     [error, value] never throws
 *
 *   Mutex                                  class; .runExclusive(fn)
 *   Semaphore(limit)                       class; .runWith(fn)
 *   Once(fn)                               class; .invoke()
 *
 *   asyncRetry(fn, opts?)                  re-export from object-store-retry
 *   CircuitBreaker(name, opts?)            re-export from object-store-retry
 *
 *   SafeAsyncError                         error class
 *
 * Best-practice notes for callers:
 *
 *   - Always pair `withTimeout` with the external-db / network calls
 *     where operator-supplied drivers might hang. The framework's
 *     external-db wrapper already retries; timeout puts a ceiling on
 *     each individual attempt.
 *
 *   - Wrap chain-writes with Mutex.runExclusive. Audit chain hashing
 *     reads the previous tip and writes a successor; without
 *     serialization, concurrent awaiting record() calls can hash
 *     against the same prev-tip and produce a forked chain. Mutex
 *     prevents this in single-process; for cross-process coordination
 *     the cluster module's leader election is the correct primitive.
 *
 *   - Use Once for boot-time lazy init (counter primer, schema
 *     check). Multiple concurrent first-callers correctly all wait
 *     on the same in-flight init Promise rather than each starting
 *     their own.
 *
 *   - Use safeAwait for fire-and-forget paths (audit hooks in
 *     middleware) that previously used try/catch — preserves the
 *     "log + continue" pattern without unhandled-rejection warnings.
 *
 *   - Prefer Promise.allSettled over Promise.all when partial failure
 *     is acceptable (e.g. emitting to multiple log sinks; one sink
 *     down shouldn't block the others). The framework's log-stream
 *     dispatcher already does this.
 */

var { FrameworkError } = require("./framework-error");

class SafeAsyncError extends FrameworkError {
  constructor(message, code, cause) {
    super(message);
    this.name = "SafeAsyncError";
    this.code = code || "async/invalid";
    if (cause !== undefined) this.cause = cause;
    this.isSafeAsyncError = true;
  }
}

// ---- withTimeout ----
//
// Race the promise against a timer. On timeout, the wrapper rejects with
// SafeAsyncError(code=async/timeout). The original promise continues
// running in the background — the framework cannot cancel an arbitrary
// async operation; only signal-aware ones can be aborted (see withSignal).
//
// opts.signal: AbortSignal — aborting the signal also rejects the wrapper
//              with code=async/aborted.
// opts.name:   diagnostic label included in the timeout message.

function withTimeout(promise, ms, opts) {
  opts = opts || {};
  if (typeof ms !== "number" || ms <= 0 || !Number.isFinite(ms)) {
    throw new SafeAsyncError("withTimeout: ms must be a positive finite number", "async/bad-arg");
  }
  return new Promise(function (resolve, reject) {
    var settled = false;
    // The timer is ref'd intentionally: while a withTimeout is pending,
    // the process should stay alive until either the underlying promise
    // settles or the timeout fires. unref'ing here would let Node exit
    // mid-await and the awaited Promise would never resolve.
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new SafeAsyncError(
        "operation timed out after " + ms + "ms" + (opts.name ? " (" + opts.name + ")" : ""),
        "async/timeout"
      ));
    }, ms);

    function _onAbort() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new SafeAsyncError(
        "operation aborted" + (opts.name ? " (" + opts.name + ")" : ""),
        "async/aborted",
        opts.signal && opts.signal.reason
      ));
    }
    if (opts.signal) {
      if (opts.signal.aborted) { _onAbort(); return; }
      opts.signal.addEventListener("abort", _onAbort, { once: true });
    }

    Promise.resolve(promise).then(function (v) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", _onAbort);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", _onAbort);
      reject(e);
    });
  });
}

// ---- withSignal ----
//
// Race the promise against an AbortSignal. The original promise continues
// running in the background; only the wrapper's resolution is short-
// circuited. Useful for plumbing a single signal through a chain of awaits.

function withSignal(promise, signal) {
  if (!signal) return Promise.resolve(promise);
  return new Promise(function (resolve, reject) {
    var settled = false;
    function _onAbort() {
      if (settled) return;
      settled = true;
      reject(new SafeAsyncError(
        "operation aborted",
        "async/aborted",
        signal.reason
      ));
    }
    if (signal.aborted) { _onAbort(); return; }
    signal.addEventListener("abort", _onAbort, { once: true });
    Promise.resolve(promise).then(function (v) {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", _onAbort);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", _onAbort);
      reject(e);
    });
  });
}

// ---- sleep ----
//
// Promise that resolves after `ms` milliseconds. opts.signal aborts the
// sleep cleanly — the wrapper rejects with SafeAsyncError(async/aborted).
//
// opts.unref (default false): if true, the timer is unref'd so a pending
// sleep does NOT keep the process alive. Use for fire-and-forget /
// heartbeat-style patterns where the program should be free to exit if
// nothing else is keeping it busy. The default is ref'd to match the
// natural meaning of `await sleep(ms)` — "I'm waiting, this IS my work,
// don't exit out from under me." (An unref'd-only event loop in Node
// exits even with pending awaits — the unref'd timer is not enough to
// hold the loop alive, so the awaiting promise never resolves.)
//
// ms <= 0 resolves immediately (matches setTimeout's clamp-to-1ms but
// without the wasted tick). Non-finite ms rejects.

function sleep(ms, opts) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) {
    return Promise.reject(new SafeAsyncError(
      "sleep: ms must be a finite number", "async/bad-arg"
    ));
  }
  if (ms <= 0) return Promise.resolve();

  var signal = opts && opts.signal;
  if (signal && signal.aborted) {
    return Promise.reject(new SafeAsyncError(
      "sleep aborted before start", "async/aborted", signal.reason
    ));
  }

  return new Promise(function (resolve, reject) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener("abort", _onAbort);
      resolve();
    }, ms);
    if (opts && opts.unref) timer.unref();

    function _onAbort() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new SafeAsyncError(
        "sleep aborted", "async/aborted", signal.reason
      ));
    }
    if (signal) signal.addEventListener("abort", _onAbort, { once: true });
  });
}

// ---- withTimeoutSignal ----
//
// Returns an AbortSignal that fires when EITHER the input signal aborts
// OR `ms` milliseconds elapse. Wraps the I/O-primitive composition that
// http-client was doing inline twice (h1 + h2 paths).
//
//   var sig = withTimeoutSignal(userSignal, 5000);
//   await fetch(url, { signal: sig });
//
// Edge cases:
//   - userSignal == null and ms not positive → returns null
//     (caller's "no signal needed" path)
//   - userSignal == null              → returns AbortSignal.timeout(ms)
//   - ms not positive (0/undefined)   → returns userSignal unchanged
//   - both                            → AbortSignal.any([user, timeout])
//
// Returning null when neither is requested means the caller can pass
// the result straight to APIs that treat null as "no abort" (the http
// `signal` option does), with no special-case branching needed.

function withTimeoutSignal(signal, ms) {
  var hasTimeout = typeof ms === "number" && ms > 0 && Number.isFinite(ms);
  if (!signal && !hasTimeout) return null;
  if (!signal)  return AbortSignal.timeout(ms);
  if (!hasTimeout) return signal;
  return AbortSignal.any([signal, AbortSignal.timeout(ms)]);
}

// ---- safeAwait ----
//
// Go-style [error, value] tuple. Never throws. Lets callers handle the
// "expected may fail; log and continue" pattern without try/catch
// scaffolding.
//
//   var [err, value] = await safeAwait(somePromise);
//   if (err) { /* log + continue */ }

async function safeAwait(promise) {
  try {
    var v = await promise;
    return [null, v];
  } catch (e) {
    return [e, null];
  }
}

// safeInvoke — call an operator-supplied callback with one payload arg.
// Drops silent if the callback is missing; routes throws to onError if
// supplied (also drop-silent if onError throws). The callback / onError
// pair is the shape every drop-callback / completion-callback /
// failure-callback site re-derives from scratch. Centralizing here so
// the contract is one definition.
//
//   safeInvoke(opts.onDrop, { reason: "buffer-full", batch: rows },
//              function (e) { log.warn("onDrop threw: " + e.message); });
function safeInvoke(callback, payload, onError) {
  if (typeof callback !== "function") return;
  try { callback(payload); }
  catch (e) {
    if (typeof onError === "function") {
      try { onError(e); } catch (_e2) { /* nested error handler must not bubble */ }
    }
  }
}

// makeDropCallback — every log-stream sink (cloudwatch / otlp-grpc /
// otlp-http / syslog / webhook) previously defined its own
// `_emitDrop(reason, batch, err)` 3-line wrapper. The shape is
// identical across sinks; the only differences are the operator's
// onDrop callback and the per-sink error logger. Returns a closure with
// the canonical payload shape `{ reason, batch, error: err || null }`.
//
//   var _emitDrop = safeAsync.makeDropCallback(onDrop,
//     function (e) { log.warn("onDrop-callback-failed: " + e.message); });
//   _emitDrop("buffer-full", batch, err);
function makeDropCallback(onDrop, onError) {
  return function (reason, batch, err) {
    safeInvoke(onDrop, { reason: reason, batch: batch, error: err || null }, onError);
  };
}

// makeScheduledFlush — idempotent setTimeout scheduler used by every
// log-stream sink (cloudwatch / otlp-grpc / otlp-http / syslog /
// webhook) to coalesce buffered writes. Each sink previously rolled
// its own:
//
//   var flushTimer = null;
//   function _scheduleFlush() {
//     if (flushTimer) return;
//     flushTimer = setTimeout(function () { flushTimer = null; _flush(); }, delayMs);
//     flushTimer.unref();
//   }
//
// Returns { schedule, cancel, isPending }. flushFn may be sync or
// async — async rejections are swallowed (best-effort sink — operators
// see drops via onDrop, not via a sea of unhandled promise rejections).
function makeScheduledFlush(delayMs, flushFn) {
  if (typeof delayMs !== "number" || !isFinite(delayMs) || delayMs < 0) {
    throw new TypeError("safeAsync.makeScheduledFlush: delayMs must be a non-negative finite number");
  }
  if (typeof flushFn !== "function") {
    throw new TypeError("safeAsync.makeScheduledFlush: flushFn must be a function");
  }
  var timer = null;
  return {
    schedule: function () {
      if (timer) return;
      timer = setTimeout(function () {
        timer = null;
        var p;
        try { p = flushFn(); }
        catch (_e) { return; }
        if (p && typeof p.catch === "function") {
          p.catch(function () { /* sink-specific drains errors via onDrop */ });
        }
      }, delayMs);
      if (timer && typeof timer.unref === "function") timer.unref();
    },
    cancel: function () {
      if (timer) { clearTimeout(timer); timer = null; }
    },
    isPending: function () { return timer !== null; },
  };
}

// ---- Mutex ----
//
// Async mutex — only one async region holds the lock at a time. Acquirers
// queue in arrival order. .runExclusive(fn) is the recommended call form
// (lock release is automatic via finally even if fn throws); .acquire()
// + .release() are exposed for callers needing finer control.
//
// Implementation note: a queued acquirer that's never released (operator
// bug) blocks the entire mutex. We don't add a hard-coded timeout because
// timeouts mask bugs and the real fix is releasing properly. If a caller
// wants a deadline, wrap the runExclusive call with withTimeout.

class Mutex {
  constructor() {
    this._waiters = [];     // [{ resolve, reject, signal, onAbort }]
    this._held = false;
  }

  // acquire(opts?) — opts.signal aborts a waiting acquirer cleanly.
  // When the signal fires, the waiter is removed from the queue and
  // its Promise rejects with async/aborted. The slot it WOULD have
  // taken stays free for the next waiter. If the mutex isn't held,
  // acquire returns immediately regardless of signal state.
  acquire(opts) {
    var self = this;
    var signal = opts && opts.signal;
    if (!self._held) {
      self._held = true;
      return Promise.resolve();
    }
    if (signal && signal.aborted) {
      return Promise.reject(new SafeAsyncError(
        "Mutex.acquire aborted", "async/aborted", signal.reason
      ));
    }
    return new Promise(function (resolve, reject) {
      var entry = { resolve: resolve, reject: reject, signal: signal, onAbort: null };
      if (signal) {
        entry.onAbort = function () {
          var idx = self._waiters.indexOf(entry);
          if (idx === -1) return;     // already taken or already aborted
          self._waiters.splice(idx, 1);
          reject(new SafeAsyncError(
            "Mutex.acquire aborted while waiting", "async/aborted", signal.reason
          ));
        };
        signal.addEventListener("abort", entry.onAbort, { once: true });
      }
      self._waiters.push(entry);
    });
  }

  release() {
    if (!this._held) {
      throw new SafeAsyncError("release on unheld Mutex", "async/bad-release");
    }
    if (this._waiters.length > 0) {
      var next = this._waiters.shift();
      if (next.signal && next.onAbort) {
        next.signal.removeEventListener("abort", next.onAbort);
      }
      next.resolve();
    } else {
      this._held = false;
    }
  }

  async runExclusive(fn, opts) {
    await this.acquire(opts);
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  isHeld() { return this._held; }
  pendingCount() { return this._waiters.length; }
}

// ---- Semaphore ----
//
// Bounded concurrency: at most `limit` simultaneous holders. Acquirers
// over the limit wait their turn. Use cases: limit external-db query
// concurrency, throttle outbound webhook fan-out, cap parallel file I/O.
//
// .runWith(fn) is the recommended form (release on finally); .acquire/
// .release are exposed for finer control.

class Semaphore {
  constructor(limit) {
    if (typeof limit !== "number" || limit < 1 || !Number.isInteger(limit)) {
      throw new SafeAsyncError("Semaphore limit must be a positive integer", "async/bad-arg");
    }
    this._limit = limit;
    this._inFlight = 0;
    this._waiters = [];     // [{ resolve, reject, signal, onAbort }]
  }

  // acquire(opts?) — opts.signal aborts a waiting acquirer cleanly.
  acquire(opts) {
    var self = this;
    var signal = opts && opts.signal;
    if (self._inFlight < self._limit) {
      self._inFlight += 1;
      return Promise.resolve();
    }
    if (signal && signal.aborted) {
      return Promise.reject(new SafeAsyncError(
        "Semaphore.acquire aborted", "async/aborted", signal.reason
      ));
    }
    return new Promise(function (resolve, reject) {
      var entry = { resolve: resolve, reject: reject, signal: signal, onAbort: null };
      if (signal) {
        entry.onAbort = function () {
          var idx = self._waiters.indexOf(entry);
          if (idx === -1) return;
          self._waiters.splice(idx, 1);
          reject(new SafeAsyncError(
            "Semaphore.acquire aborted while waiting", "async/aborted", signal.reason
          ));
        };
        signal.addEventListener("abort", entry.onAbort, { once: true });
      }
      self._waiters.push(entry);
    });
  }

  release() {
    if (this._inFlight === 0) {
      throw new SafeAsyncError("release on idle Semaphore", "async/bad-release");
    }
    if (this._waiters.length > 0) {
      var next = this._waiters.shift();
      if (next.signal && next.onAbort) {
        next.signal.removeEventListener("abort", next.onAbort);
      }
      next.resolve();
    } else {
      this._inFlight -= 1;
    }
  }

  async runWith(fn, opts) {
    await this.acquire(opts);
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  inFlight() { return this._inFlight; }
  pendingCount() { return this._waiters.length; }
}

// ---- Once ----
//
// Single-flight memoization. The first .invoke() call runs the function;
// subsequent calls (concurrent or later) await the same in-flight Promise
// and receive the same result. If the first invocation throws, the cached
// result is the rejected Promise — re-invocation will NOT retry.
//
// Use case: lazy boot-time init where multiple call sites might first-
// touch concurrently (counter primer, schema-check, key load). Without
// Once, the second concurrent caller would start its own init and produce
// double-initialization.
//
// .reset() clears the cached Promise so the next .invoke() runs fresh.
// Useful for tests, hot-reload, and operator-driven re-init after a
// transient init failure. To make resets explicit (avoid silent stale
// state), reset() does NOT cancel an in-flight first invocation —
// callers awaiting the prior invoke continue to see its result.

class Once {
  constructor(fn) {
    if (typeof fn !== "function") {
      throw new SafeAsyncError("Once: argument must be a function", "async/bad-arg");
    }
    this._fn = fn;
    this._promise = null;
  }

  invoke() {
    if (this._promise === null) {
      this._promise = Promise.resolve().then(this._fn);
    }
    return this._promise;
  }

  reset() {
    this._promise = null;
  }

  hasInvoked() { return this._promise !== null; }
}

// ---- repeating ----
//
// Bounded-cadence interval timer with consistent unref + cancel semantics.
// Replaces the scattered setInterval ceremony where each caller hand-rolled
// `var t = setInterval(...); t.unref();` and a corresponding clearInterval
// in shutdown — easy to forget the unref and silently block process exit.
//
//   var sweep = b.safeAsync.repeating(function () {
//     return cleanup();
//   }, b.constants.TIME.seconds(30), { name: "cache-sweep" });
//   ...
//   sweep.stop();
//
// fn may be sync or async. If fn returns a Promise, the next tick fires
// `intervalMs` after the prior fn() *started* (matching setInterval's
// fixed-rate semantics, not after-completion). Promise rejections are
// captured by the optional onError callback; if none provided, they're
// silently dropped — a repeating timer is by definition fire-and-forget,
// and an unhandled rejection here would crash the process.
//
// opts.unref defaults true: most repeating timers are background sweepers
// that should NOT keep the process alive. Cluster heartbeat etc. set
// `unref: false` so the lease keeps the leader from exiting silently.

function repeating(fn, intervalMs, opts) {
  if (typeof fn !== "function") {
    throw new SafeAsyncError("repeating: fn must be a function", "async/bad-arg");
  }
  if (typeof intervalMs !== "number" || !Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new SafeAsyncError("repeating: intervalMs must be a positive finite number, got " + intervalMs,
      "async/bad-arg");
  }
  opts = opts || {};
  var unref = opts.unref !== false;     // default true
  var onError = typeof opts.onError === "function" ? opts.onError : null;

  var stopped = false;
  function _tick() {
    if (stopped) return;
    var result;
    try { result = fn(); } catch (e) {
      if (onError) { try { onError(e); } catch (_e) { /* swallow */ } } return;
    }
    if (result && typeof result.then === "function") {
      result.then(null, function (e) {
        if (onError) { try { onError(e); } catch (_e) { /* swallow */ } }
      });
    }
  }
  var timer = setInterval(_tick, intervalMs);
  if (unref && typeof timer.unref === "function") timer.unref();

  return {
    stop: function () {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
    },
  };
}

// ---- flushLoop ----
//
// Schedule fn(), wait for it to settle (resolve or reject), then schedule
// the next fn() `intervalMs` later. Differs from `repeating` (fixed-rate,
// fire-and-forget) — flushLoop is the after-completion pattern most
// background flushers want: never overlap two flushes, and don't accumulate
// backlog if a flush is slow.
//
//   var loop = b.safeAsync.flushLoop(function () {
//     return otelExporter.flush();
//   }, b.constants.TIME.seconds(15), { name: "otel-flush" });
//   ...
//   loop.stop();
//
// Always unref'd — a pending flush should never keep the process alive
// (the operator's b.appShutdown drives the final drain explicitly).
// onError catches rejections; without one, they're silently dropped.

function flushLoop(fn, intervalMs, opts) {
  if (typeof fn !== "function") {
    throw new SafeAsyncError("flushLoop: fn must be a function", "async/bad-arg");
  }
  if (typeof intervalMs !== "number" || !Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new SafeAsyncError("flushLoop: intervalMs must be a positive finite number, got " + intervalMs,
      "async/bad-arg");
  }
  opts = opts || {};
  var onError = typeof opts.onError === "function" ? opts.onError : null;

  var stopped = false;
  var timer = null;

  function _schedule() {
    if (stopped) return;
    timer = setTimeout(function () {
      timer = null;
      if (stopped) return;
      var settled;
      try { settled = Promise.resolve(fn()); }
      catch (e) {
        if (onError) { try { onError(e); } catch (_e) { /* swallow */ } }
        _schedule();
        return;
      }
      settled.then(null, function (e) {
        if (onError) { try { onError(e); } catch (_e) { /* swallow */ } }
      }).then(_schedule);
    }, intervalMs);
    if (typeof timer.unref === "function") timer.unref();
  }
  _schedule();

  return {
    stop: function () {
      if (stopped) return;
      stopped = true;
      if (timer) { clearTimeout(timer); timer = null; }
    },
  };
}

// ---- Re-exports of resilience primitives from lib/retry.js ----
//
// withRetry + CircuitBreaker live in lib/retry.js (the canonical home).
// We re-export them here under safe-async-shaped names so call sites
// reaching for async safety primitives find them in one place.

var retryHelper = require("./retry");

var asyncRetry     = retryHelper.withRetry;
var CircuitBreaker = retryHelper.CircuitBreaker;

module.exports = {
  withTimeout:        withTimeout,
  withSignal:         withSignal,
  withTimeoutSignal:  withTimeoutSignal,
  sleep:              sleep,
  repeating:          repeating,
  flushLoop:          flushLoop,
  safeAwait:          safeAwait,
  safeInvoke:         safeInvoke,
  makeDropCallback:   makeDropCallback,
  makeScheduledFlush: makeScheduledFlush,
  Mutex:              Mutex,
  Semaphore:          Semaphore,
  Once:               Once,
  asyncRetry:         asyncRetry,
  CircuitBreaker:     CircuitBreaker,
  SafeAsyncError:     SafeAsyncError,
};
