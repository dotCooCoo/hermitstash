"use strict";
/**
 * @module b.safeAsync
 * @nav    Validation
 * @title  Safe Async
 *
 * @intro
 *   Timeout-bounded promises, AbortSignal-aware coordination,
 *   Promise.race-shaped helpers, and settled-state queries for the
 *   framework's async surfaces (external-db queries, cluster
 *   coordination, queue operations, audit chain writes).
 *
 *   Hazards this module addresses: races between interleaved awaits,
 *   unbounded retries masking real failures, hangs from unresponsive
 *   backends, and partial results from operator-supplied drivers.
 *
 *   Surface:
 *     - Async coordination: withTimeout, withSignal, withTimeoutSignal,
 *       sleep, repeating, flushLoop, safeAwait, parallel, asyncRetry
 *     - Async state objects: Mutex, Semaphore, Once, CircuitBreaker
 *     - Sync helpers used by async pipelines: safeInvoke (callback
 *       wrapper with optional onError), makeDropCallback (factory for
 *       log-stream-style onDrop callbacks), makeScheduledFlush
 *       (idempotent setTimeout coalesce-and-flush helper)
 *
 *   Design posture:
 *     - AbortSignal everywhere. Every time-bounded primitive accepts
 *       an AbortSignal and aborts cleanly when it fires.
 *     - Error.cause preserved. Wrapper errors set `.cause` to the
 *       original failure so debugging traces back to the root.
 *     - No leaked Promises. Mutex / Semaphore release on path-out
 *       in finally blocks — even on cancellation.
 *     - Bounded by default. Semaphore / parallel have explicit limits
 *       and reject over-the-limit acquisitions rather than growing
 *       unboundedly.
 *     - Fail loud. Errors propagate; primitives never silently
 *       swallow. safeAwait is the opt-in `{error, value}` tuple form
 *       for callers that want to log-and-continue.
 *
 *   Best-practice notes for callers:
 *     - Pair `withTimeout` with external-db / network calls where
 *       operator-supplied drivers might hang. Puts a ceiling on each
 *       individual attempt.
 *     - Wrap chain-writes with `Mutex.runExclusive`. Audit chain
 *       hashing reads the previous tip and writes a successor; without
 *       serialization, concurrent record() calls can hash against the
 *       same prev-tip and fork the chain.
 *     - Use `Once` for boot-time lazy init (counter primer, schema
 *       check). Multiple concurrent first-callers correctly wait on
 *       the same in-flight init Promise.
 *     - Use `safeAwait` for fire-and-forget paths (audit hooks in
 *       middleware) — preserves "log + continue" without unhandled-
 *       rejection warnings.
 *     - Prefer Promise.allSettled over Promise.all when partial
 *       failure is acceptable (multiple log sinks; one down shouldn't
 *       block the others).
 *
 * @card
 *   Timeout-bounded promises, AbortSignal-aware coordination, Promise.race-shaped helpers, and settled-state queries for the framework's async surfaces (external-db queries, cluster coordination, queue operations, audit chain writes).
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

/**
 * @primitive b.safeAsync.withTimeout
 * @signature b.safeAsync.withTimeout(promise, ms, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeAsync.withSignal, b.safeAsync.withTimeoutSignal, b.safeAsync.sleep
 *
 * Race a Promise against a wall-clock deadline. On timeout the
 * wrapper rejects with `SafeAsyncError` (`.code = "async/timeout"`);
 * the underlying Promise keeps running in the background since the
 * framework cannot cancel an arbitrary async operation. Pair with
 * AbortSignal-aware I/O when the caller also wants the work itself
 * to stop. `opts.signal` aborts the wrapper with
 * `.code = "async/aborted"`; `opts.name` is included in the timeout
 * message for diagnostics.
 *
 * @opts
 *   signal: AbortSignal,  // aborts the wrapper with async/aborted
 *   name:   string,       // diagnostic label baked into error messages
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Bound an HTTP call to 5s.
 *   var fetchUser = Promise.resolve({ id: 42, name: "alice" });
 *   var user = await b.safeAsync.withTimeout(fetchUser, 5000, { name: "fetchUser" });
 *   user.id;
 *   // → 42
 *
 *   // Timeout surfaces as SafeAsyncError(async/timeout).
 *   var hang = new Promise(function () {});
 *   try { await b.safeAsync.withTimeout(hang, 10, { name: "stuck" }); }
 *   catch (e) { e.code; }
 *   // → "async/timeout"
 */
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

/**
 * @primitive b.safeAsync.withSignal
 * @signature b.safeAsync.withSignal(promise, signal)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeAsync.withTimeout, b.safeAsync.withTimeoutSignal
 *
 * Race a Promise against an AbortSignal. When the signal aborts the
 * wrapper rejects with `SafeAsyncError` (`.code = "async/aborted"`,
 * `.cause = signal.reason`). The underlying Promise continues
 * running in the background — only the wrapper's resolution is
 * short-circuited. Useful for plumbing one signal through a chain
 * of awaits where some intermediates aren't signal-aware.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Propagate an AbortSignal through a non-signal-aware Promise.
 *   var ctrl = new AbortController();
 *   var slow = new Promise(function (resolve) { setTimeout(resolve, 50, "done"); });
 *   var wrapped = b.safeAsync.withSignal(slow, ctrl.signal);
 *   ctrl.abort();
 *   try { await wrapped; }
 *   catch (e) { e.code; }
 *   // → "async/aborted"
 */
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

/**
 * @primitive b.safeAsync.sleep
 * @signature b.safeAsync.sleep(ms, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeAsync.withTimeout, b.safeAsync.repeating
 *
 * Promise that resolves after `ms` milliseconds. `opts.signal`
 * aborts the sleep cleanly — the wrapper rejects with
 * `SafeAsyncError` (`.code = "async/aborted"`). `opts.unref` flips
 * the timer to non-process-holding (default `false`, so
 * `await sleep(ms)` reads naturally as "I'm waiting, this IS my
 * work"). `ms <= 0` resolves immediately; non-finite `ms` rejects.
 *
 * @opts
 *   signal: AbortSignal,  // aborts mid-sleep with async/aborted
 *   unref:  boolean,      // default false; true to not keep the process alive
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Backoff between retries.
 *   var t0 = Date.now();
 *   await b.safeAsync.sleep(20);
 *   (Date.now() - t0) >= 18;
 *   // → true
 *
 *   // Abort mid-sleep — propagates as SafeAsyncError(async/aborted).
 *   var ctrl = new AbortController();
 *   setTimeout(function () { ctrl.abort(); }, 5);
 *   try { await b.safeAsync.sleep(1000, { signal: ctrl.signal }); }
 *   catch (e) { e.code; }
 *   // → "async/aborted"
 */
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

/**
 * @primitive b.safeAsync.withTimeoutSignal
 * @signature b.safeAsync.withTimeoutSignal(signal, ms)
 * @since     0.7.4
 * @status    stable
 * @related   b.safeAsync.withTimeout, b.safeAsync.withSignal
 *
 * Compose an existing AbortSignal with a fresh wall-clock timeout.
 * Returns an AbortSignal that fires when EITHER the input signal
 * aborts OR `ms` milliseconds elapse — exactly the shape I/O
 * primitives like `fetch({ signal })` already accept. Edge cases:
 * neither argument supplied returns `null` (a naturally falsy "no
 * signal needed" value most signal-accepting APIs treat as no-op);
 * only `signal` returns it unchanged; only `ms` returns
 * `AbortSignal.timeout(ms)`.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Add a 5s deadline on top of the user's existing AbortSignal.
 *   var userCtrl = new AbortController();
 *   var sig = b.safeAsync.withTimeoutSignal(userCtrl.signal, 5000);
 *   sig instanceof AbortSignal;
 *   // → true
 *
 *   // No user signal + no timeout returns null (no-abort sentinel).
 *   b.safeAsync.withTimeoutSignal(null, 0);
 *   // → null
 */
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

/**
 * @primitive b.safeAsync.safeAwait
 * @signature b.safeAsync.safeAwait(promise)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeAsync.withTimeout, b.safeAsync.parallel
 *
 * Go-style `[error, value]` tuple wrapper. Never throws — a rejected
 * Promise becomes `[error, null]`, a resolved Promise becomes
 * `[null, value]`. Replaces try/catch scaffolding around
 * fire-and-forget paths (audit hooks in middleware, optional
 * lookups) where the caller wants to log-and-continue without
 * unhandled-rejection warnings. For settled-state inspection of
 * many concurrent Promises the standard `Promise.allSettled` pairs
 * naturally with this idiom.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Resolved Promise → [null, value].
 *   var ok = await b.safeAsync.safeAwait(Promise.resolve(42));
 *   ok[0];
 *   // → null
 *   ok[1];
 *   // → 42
 *
 *   // Rejected Promise → [error, null].
 *   var bad = await b.safeAsync.safeAwait(Promise.reject(new Error("nope")));
 *   bad[0].message;
 *   // → "nope"
 *
 *   // Pair with Promise.allSettled for bulk settled-state inspection.
 *   var results = await Promise.all([
 *     b.safeAsync.safeAwait(Promise.resolve("a")),
 *     b.safeAsync.safeAwait(Promise.reject(new Error("b-failed"))),
 *     b.safeAsync.safeAwait(Promise.resolve("c")),
 *   ]);
 *   results.filter(function (r) { return r[0] === null; }).length;
 *   // → 2
 */
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
/**
 * @primitive b.safeAsync.safeInvoke
 * @signature b.safeAsync.safeInvoke(callback, payload, onError)
 * @since     0.6.0
 * @status    stable
 * @related   b.safeAsync.makeDropCallback
 *
 * Drop-silent operator-callback invoker. Calls `callback(payload)`
 * if `callback` is a function, routes any throw to `onError(e)` if
 * supplied, and silently swallows nested throws from `onError`
 * itself. Used by every drop-callback / completion-callback /
 * failure-callback site in the framework so a buggy operator
 * callback can never crash the request that triggered the audit
 * hook. Hot-path observability sink — drop-silent by design.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Happy path: callback runs with the payload.
 *   var seen = null;
 *   b.safeAsync.safeInvoke(function (p) { seen = p; }, { reason: "buffer-full", batch: [1, 2] });
 *   seen.reason;
 *   // → "buffer-full"
 *
 *   // Throw routed to onError; original caller never sees it.
 *   var caught = null;
 *   b.safeAsync.safeInvoke(
 *     function () { throw new Error("boom"); },
 *     { batch: [] },
 *     function (e) { caught = e.message; }
 *   );
 *   caught;
 *   // → "boom"
 */
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
/**
 * @primitive b.safeAsync.makeDropCallback
 * @signature b.safeAsync.makeDropCallback(onDrop, onError)
 * @since     0.6.0
 * @status    stable
 * @related   b.safeAsync.safeInvoke, b.safeAsync.makeScheduledFlush
 *
 * Factory for the canonical log-stream-sink onDrop wrapper. Returns
 * a closure `(reason, batch, err) => void` that calls `onDrop` with
 * the framework-canonical payload shape `{ reason, batch, error }`,
 * routing any throw from the operator callback to `onError`. Every
 * sink (cloudwatch / otlp-grpc / otlp-http / syslog / webhook)
 * previously rolled its own three-line `_emitDrop` wrapper — this
 * factory removes that duplication.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var dropped = [];
 *   var emit = b.safeAsync.makeDropCallback(
 *     function (info) { dropped.push(info); },
 *     function (e) { console.warn("onDrop threw: " + e.message); }
 *   );
 *   emit("buffer-full", [{ id: 1 }], new Error("queue overflow"));
 *   dropped[0].reason;
 *   // → "buffer-full"
 *   dropped[0].error.message;
 *   // → "queue overflow"
 */
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
/**
 * @primitive b.safeAsync.makeScheduledFlush
 * @signature b.safeAsync.makeScheduledFlush(delayMs, flushFn)
 * @since     0.6.0
 * @status    stable
 * @related   b.safeAsync.flushLoop, b.safeAsync.makeDropCallback
 *
 * Idempotent setTimeout coalesce-and-flush scheduler used by every
 * log-stream sink to batch buffered writes. Returns
 * `{ schedule, cancel, isPending }` — calling `schedule()` repeatedly
 * within `delayMs` collapses to a single deferred `flushFn()` call.
 * The timer is unref'd so a pending flush never keeps the process
 * alive; async rejections from `flushFn` are swallowed (best-effort
 * sink — operators see drops via the sink's own onDrop). Throws
 * `TypeError` on bad arguments at construction time.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   // Coalesce many schedule() calls into one flush after delayMs.
 *   var flushed = 0;
 *   var sched = b.safeAsync.makeScheduledFlush(20, function () { flushed += 1; });
 *   sched.schedule();
 *   sched.schedule();
 *   sched.schedule();
 *   sched.isPending();
 *   // → true
 *   await b.safeAsync.sleep(40);
 *   flushed;
 *   // → 1
 */
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

// ---- parallel ----
//
// Bounded-concurrency mapAsync. Runs `fn(item, index)` over `items`
// with at most opts.concurrency in-flight at once; resolves with
// results in input order (NOT completion order). The first rejection
// from any `fn` invocation is propagated (other in-flight calls finish
// in the background; the wrapper does not cancel them — operator-
// supplied promises may not be signal-aware).
//
//   var results = await b.safeAsync.parallel(urls, fetchOne, {
//     concurrency: 16,
//     signal:      controller.signal,
//   });
//
// Worker-loop pattern: a fixed pool of `concurrency` workers each pull
// the next available index from a shared cursor. Avoids the
// Promise.all-batched-chunks pitfall where the next batch can't start
// until the slowest item in the current batch finishes (long-pole
// stragglers leave workers idle). See feedback_lpt_scheduling_for_
// parallel_tests.md — same shape applied to operator workloads.
//
// opts.concurrency: 1..256 (default 8). Throws at config time on
// out-of-range so operator typos surface immediately.
// opts.signal:      AbortSignal — cancels by refusing to dispatch
//                   further items; in-flight promises run to settle.

var PARALLEL_DEFAULT_CONCURRENCY = 8;                                              // worker pool count, not bytes
var PARALLEL_MAX_CONCURRENCY = 256;                                                // worker pool ceiling, not bytes

/**
 * @primitive b.safeAsync.parallel
 * @signature b.safeAsync.parallel(items, fn, opts?)
 * @since     0.7.0
 * @status    stable
 * @related   b.safeAsync.safeAwait, b.safeAsync.withTimeout
 *
 * Bounded-concurrency `mapAsync`. Runs `fn(item, index)` over `items`
 * with at most `opts.concurrency` in-flight at a time and resolves
 * with results in INPUT order (not completion order). Worker-loop
 * scheduling: a fixed pool of workers each pull the next index from
 * a shared cursor as soon as their previous task settles — avoids
 * the Promise.all-batched-chunks pitfall where a long-pole straggler
 * leaves workers idle. The first rejection is propagated;
 * still-in-flight calls finish in the background (operator-supplied
 * promises may not be signal-aware). `opts.concurrency` validates at
 * config time (1..256, default 8) and throws on out-of-range so
 * typos surface immediately.
 *
 * @opts
 *   concurrency: number,        // 1..256; default 8
 *   signal:      AbortSignal,   // refuses to dispatch further items; in-flight run to settle
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var urls = ["a", "b", "c", "d"];
 *   var fetchOne = function (u) { return Promise.resolve("loaded:" + u); };
 *   var results = await b.safeAsync.parallel(urls, fetchOne, { concurrency: 2 });
 *   results;
 *   // → ["loaded:a", "loaded:b", "loaded:c", "loaded:d"]
 *
 *   // First rejection wins; remaining workers drain.
 *   try {
 *     await b.safeAsync.parallel([1, 2, 3], function (n) {
 *       if (n === 2) return Promise.reject(new Error("bad-2"));
 *       return Promise.resolve(n);
 *     }, { concurrency: 1 });
 *   } catch (e) {
 *     e.message;
 *     // → "bad-2"
 *   }
 */
function parallel(items, fn, opts) {
  if (!Array.isArray(items)) {
    throw new SafeAsyncError("parallel: items must be an array", "async/bad-arg");
  }
  if (typeof fn !== "function") {
    throw new SafeAsyncError("parallel: fn must be a function", "async/bad-arg");
  }
  opts = opts || {};
  var concurrency = opts.concurrency != null ? opts.concurrency : PARALLEL_DEFAULT_CONCURRENCY;
  if (typeof concurrency !== "number" || !Number.isInteger(concurrency) ||
      concurrency < 1 || concurrency > PARALLEL_MAX_CONCURRENCY) {
    throw new SafeAsyncError(
      "parallel: concurrency must be an integer in [1.." +
      PARALLEL_MAX_CONCURRENCY + "], got " + concurrency,
      "async/bad-arg"
    );
  }
  var signal = opts.signal;
  if (signal && signal.aborted) {
    return Promise.reject(new SafeAsyncError(
      "parallel aborted before start", "async/aborted", signal.reason
    ));
  }
  if (items.length === 0) return Promise.resolve([]);

  return new Promise(function (resolve, reject) {
    var results = new Array(items.length);
    var cursor = 0;
    var settled = false;
    var firstError = null;
    var activeWorkers = 0;
    var workerCount = Math.min(concurrency, items.length);
    var onAbort = null;

    function _finish(err) {
      if (settled) return;
      settled = true;
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
      if (err) reject(err); else resolve(results);
    }

    if (signal) {
      onAbort = function () {
        if (firstError) return;
        firstError = new SafeAsyncError(
          "parallel aborted", "async/aborted", signal.reason
        );
        // In-flight workers finish their current item; new pulls
        // observe firstError and exit. _finish fires when the last
        // worker drains.
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    function _workerLoop() {
      // Continuous worker queue — each worker pulls the next index
      // from the shared cursor as soon as its previous task settles.
      // No batched chunks: a slow item never blocks unrelated items
      // from entering the pool.
      if (firstError || cursor >= items.length) {
        activeWorkers -= 1;
        if (activeWorkers === 0) _finish(firstError);
        return;
      }
      var idx = cursor++;
      var item = items[idx];
      var p;
      try { p = Promise.resolve(fn(item, idx)); }
      catch (e) { p = Promise.reject(e); }
      p.then(function (value) {
        results[idx] = value;
        _workerLoop();
      }, function (e) {
        if (!firstError) firstError = e;
        _workerLoop();
      });
    }

    for (var i = 0; i < workerCount; i++) {
      activeWorkers += 1;
      _workerLoop();
    }
  });
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

/**
 * @primitive b.safeAsync.repeating
 * @signature b.safeAsync.repeating(fn, intervalMs, opts?)
 * @since     0.6.0
 * @status    stable
 * @related   b.safeAsync.flushLoop, b.safeAsync.sleep
 *
 * Bounded-cadence interval timer with consistent unref + cancel
 * semantics. Replaces the scattered `setInterval` ceremony where
 * each caller hand-rolled `t.unref()` and a corresponding
 * `clearInterval` in shutdown. `fn` may be sync or async; if async,
 * the next tick fires `intervalMs` after the prior fn() STARTED
 * (fixed-rate, matching `setInterval`). Promise rejections are
 * captured by `opts.onError` if provided, otherwise silently
 * dropped — a repeating timer is fire-and-forget by definition and
 * an unhandled rejection here would crash the process. `opts.unref`
 * defaults `true`; set `false` for cluster heartbeat-style timers
 * that must hold the loop open. Returns `{ stop }`.
 *
 * @opts
 *   unref:   boolean,           // default true
 *   onError: function(error),   // captures sync throws + Promise rejections
 *   name:    string,            // diagnostic label
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var ticks = 0;
 *   var sweep = b.safeAsync.repeating(function () { ticks += 1; }, 10, {
 *     unref: true,
 *     name:  "tick-counter",
 *   });
 *   await b.safeAsync.sleep(35);
 *   sweep.stop();
 *   ticks >= 2;
 *   // → true
 */
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

/**
 * @primitive b.safeAsync.flushLoop
 * @signature b.safeAsync.flushLoop(fn, intervalMs, opts?)
 * @since     0.6.0
 * @status    stable
 * @related   b.safeAsync.repeating, b.safeAsync.makeScheduledFlush
 *
 * After-completion background flusher. Schedules `fn()`, awaits its
 * settle (resolve OR reject), then schedules the next call
 * `intervalMs` later. Differs from `repeating` (fixed-rate, no
 * overlap protection) — `flushLoop` is the right shape for
 * background flushers that must never overlap two flushes and
 * shouldn't accumulate backlog when one flush is slow. Always
 * unref'd; `opts.onError` catches rejections, otherwise they're
 * silently dropped. Returns `{ stop }`.
 *
 * @opts
 *   onError: function(error),   // captures sync throws + Promise rejections
 *   name:    string,            // diagnostic label
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var flushes = 0;
 *   var loop = b.safeAsync.flushLoop(function () {
 *     flushes += 1;
 *     return Promise.resolve();
 *   }, 10, { name: "telemetry-flush" });
 *   await b.safeAsync.sleep(35);
 *   loop.stop();
 *   flushes >= 1;
 *   // → true
 */
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
  parallel:           parallel,
  Mutex:              Mutex,
  Semaphore:          Semaphore,
  Once:               Once,
  asyncRetry:         asyncRetry,
  CircuitBreaker:     CircuitBreaker,
  SafeAsyncError:     SafeAsyncError,
};
