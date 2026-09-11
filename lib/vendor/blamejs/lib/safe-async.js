// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

/**
 * @primitive b.safeAsync.writeChunk
 * @signature b.safeAsync.writeChunk(writable, chunk)
 * @since     0.18.19
 * @status    stable
 * @related   b.render.stream, b.safeAsync.safeAwait
 *
 * Write one chunk to a `Writable` and resolve when it has been accepted,
 * waiting for `'drain'` when the stream says it is full.
 *
 * `write()` returning `false` is easy to discard, and nothing appears to break
 * when you do: a local client drains instantly, so the queue never grows in
 * testing. Under a slow client Node keeps buffering in memory and a
 * deliberately bounded-memory export becomes unbounded.
 *
 * Waiting is not enough on its own, either. A closed socket never emits
 * `'drain'`, so a loop that always awaits it hangs the request forever — this
 * settles on `'error'` and `'close'` as well, so a disconnected peer rejects
 * rather than stalls. Every listener it adds is removed on the way out,
 * whichever event wins.
 *
 * @example
 *   for await (var row of rows) {
 *     await b.safeAsync.writeChunk(res, row + "\n");
 *   }
 */
function _swallow() {}

function _reportsCompletion(writable) {
  if (!writable || typeof writable.write !== "function") return false;
  return writable.writableLength !== undefined || typeof writable._write === "function";
}

function _absorbOneError(writable) {
  if (!writable || typeof writable.once !== "function" ||
      typeof writable.removeListener !== "function") return;
  if (typeof writable.listenerCount === "function" &&
      writable.listenerCount("error") > 0) return;
  writable.once("error", _swallow);
  setImmediate(function () { writable.removeListener("error", _swallow); });
}

function writeChunk(writable, chunk) {
  return new Promise(function (resolve, reject) {
    if (!writable || typeof writable.write !== "function") {
      reject(new SafeAsyncError(
        "safeAsync.writeChunk: expected a writable with a write() method",
        "async/bad-writable"));
      return;
    }
    if (writable.destroyed === true || writable.closed === true ||
        writable.writableEnded === true) {
      reject(new SafeAsyncError(
        "safeAsync.writeChunk: the stream was already closed",
        "async/writable-closed"));
      return;
    }
    var settled = false;
    function done(err, absorbFollowingError) {
      if (settled) return;
      settled = true;
      if (typeof writable.removeListener === "function") {
        writable.removeListener("drain", onDrain);
        writable.removeListener("error", onError);
        writable.removeListener("close", onClose);
      }
      if (err) {
        if (absorbFollowingError) _absorbOneError(writable);
        reject(err);
        return;
      }
      resolve();
    }
    function onDrain() { done(null); }
    function onError(e) { done(e); }
    function onClose() {
      done(new SafeAsyncError(
        "safeAsync.writeChunk: the stream closed before it drained",
        "async/writable-closed"));
    }
    var accepted;
    var writeReturned = false;
    var answered = false;
    var answeredWith = null;
    var reportsCompletion = _reportsCompletion(writable);
    function onWritten(err) {
      answered = true;
      answeredWith = err || null;
      if (!writeReturned) return;
      if (err) { done(err, true); return; }
      if (accepted !== false) done(null);
    }
    try {
      accepted = reportsCompletion ? writable.write(chunk, onWritten) : writable.write(chunk);
    } catch (e) { done(e); return; }
    writeReturned = true;
    if (answered) {
      if (answeredWith) { done(answeredWith, true); return; }
      if (accepted !== false) { done(null); return; }
    }
    if (typeof writable.once !== "function") { done(null); return; }
    if (accepted !== false && !reportsCompletion) { done(null); return; }
    writable.once("error", onError);
    writable.once("close", onClose);
    if (accepted === false) writable.once("drain", onDrain);
  });
}

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

// Routes a throw to `onError`, and is drop-silent if `onError` throws.
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
 * An `async` callback is covered too: a returned promise that
 * rejects reaches `onError` exactly as a throw does, so a rejection
 * never escapes as an unhandled one. The callback is not awaited —
 * `safeInvoke` returns as soon as it has been called.
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
  safeApply(callback, [payload], onError);
}

/**
 * @primitive b.safeAsync.safeApply
 * @signature b.safeAsync.safeApply(callback, args, onError)
 * @since     0.18.58
 * @status    stable
 * @related   b.safeAsync.safeInvoke, b.safeAsync.containRejection
 *
 * Drop-silent operator-callback invoker for callbacks taking more
 * than one argument — `b.safeAsync.safeInvoke` with a positional
 * argument list in place of the single payload. Identical in every
 * other respect: a missing callback is a no-op, a throw and a
 * rejected promise both reach `onError(e)`, and a throw from
 * `onError` itself is swallowed.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var seen = null;
 *   b.safeAsync.safeApply(function (key, locale) { seen = key + "@" + locale; },
 *     ["greeting", "fr-CA"]);
 *   seen;
 *   // → "greeting@fr-CA"
 */
function safeApply(callback, args, onError) {
  if (typeof callback !== "function") return;
  var returned;
  try { returned = callback.apply(null, args || []); }
  catch (e) { _routeCallbackError(onError, e); return; }
  containRejection(returned, onError);
}

function _noop() {}

function _routeCallbackError(onError, e) {
  if (typeof onError !== "function") return;
  var returned;
  try { returned = onError(e); } catch (_e2) { return;  }
  if (!returned) return;
  try {
    var then = returned.then;
    if (typeof then !== "function") return;
    then.call(returned, _noop, function () { /* nowhere left to report */ });
  } catch (_e3) { /* a thenable that cannot be attached to */ }
}

/**
 * @primitive b.safeAsync.containRejection
 * @signature b.safeAsync.containRejection(value, onError)
 * @since     0.18.58
 * @status    stable
 * @related   b.safeAsync.safeInvoke
 *
 * Makes a value safe to ignore. If `value` is a promise, a rejection
 * is routed to `onError(e)` — and a throw from `onError` itself is
 * swallowed — so nothing reaches the process as an unhandled
 * rejection. Anything else is returned untouched.
 *
 * For the common case of calling an operator callback and discarding
 * its result, use `b.safeAsync.safeInvoke`, which does this already.
 * Reach for this one when the caller needs the returned value: a
 * refusal hook whose response commit decides whether the default
 * refusal still runs is called directly, and its rejection still has
 * to land somewhere.
 *
 * The value is NOT awaited — it is returned as it came in, so a
 * caller that wants to await it still can.
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var caught = null;
 *   var p = b.safeAsync.containRejection(
 *     Promise.reject(new Error("boom")),
 *     function (e) { caught = e.message; }
 *   );
 *   typeof p.then;
 *   // → "function"
 */
function containRejection(value, onError) {
  if (!value) return value;
  try {
    var then = value.then;
    if (typeof then !== "function") return value;
    then.call(value, _noop, function (e) { _routeCallbackError(onError, e); });
  } catch (e) { _routeCallbackError(onError, e); }
  return value;
}

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

/**
 * @primitive b.safeAsync.makeBufferedEnqueue
 * @signature b.safeAsync.makeBufferedEnqueue(buffer, opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeAsync.makeScheduledFlush, b.safeAsync.makeDropCallback
 *
 * Backpressure enqueue for batching egress sinks. Returns an
 * `enqueue(entry)` function that pushes `entry` onto the operator-owned
 * `buffer` array with drop-oldest overflow protection, then either kicks
 * a flush when the batch is full or defers to a coalescing scheduler.
 * Resolves `{ accepted: true, queued }` with the post-enqueue depth.
 *
 * This is the shared hot-path decision every batching log-stream sink
 * (CloudWatch, OTLP/HTTP, webhook) makes per record: bound the buffer,
 * surface dropped records to drop accounting, and trigger delivery on a
 * full batch without awaiting it. Bounding is mandatory — an unbounded
 * buffer behind a slow or dead collector is an out-of-memory vector.
 *
 * `opts.flush` returns the in-flight drain promise (its rejection is
 * swallowed here — the sink reports failures through its own onDrop).
 * `opts.schedule` is the coalescing deferral (typically a
 * `makeScheduledFlush` handle's `schedule`). `opts.onOverflow(dropped)`
 * is invoked with the evicted record so the caller can increment its
 * drop counter and emit a drop event. Validates wiring at construction
 * (`TypeError`) so a sink author's typo surfaces at setup, not under load.
 *
 * @opts
 *   batchSize:   number,    // flush when buffer reaches this depth
 *   bufferLimit: number,    // drop oldest once buffer exceeds this depth
 *   flush:       Function,  // () => Promise — non-awaited batch drain
 *   schedule:    Function,  // () => void  — coalescing deferred flush
 *   onOverflow:  Function,  // (dropped) => void — drop accounting (optional)
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var buffer = [];
 *   var dropped = 0;
 *   var sched = b.safeAsync.makeScheduledFlush(20, drain);
 *   var enqueue = b.safeAsync.makeBufferedEnqueue(buffer, {
 *     batchSize:   100,
 *     bufferLimit: 1000,
 *     flush:       drain,
 *     schedule:    sched.schedule,
 *     onOverflow:  function () { dropped += 1; },
 *   });
 *   function drain() { buffer.length = 0; return Promise.resolve(); }
 *
 *   await enqueue({ message: "hi" });
 *   // → { accepted: true, queued: 1 }
 */
function makeBufferedEnqueue(buffer, opts) {
  if (!Array.isArray(buffer)) {
    throw new TypeError("safeAsync.makeBufferedEnqueue: buffer must be an array");
  }
  if (!opts || typeof opts !== "object") {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts is required");
  }
  if (typeof opts.batchSize !== "number" || !isFinite(opts.batchSize) || opts.batchSize < 1) {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts.batchSize must be a positive finite number");
  }
  if (typeof opts.bufferLimit !== "number" || !isFinite(opts.bufferLimit) || opts.bufferLimit < 1) {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts.bufferLimit must be a positive finite number");
  }
  if (typeof opts.flush !== "function") {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts.flush must be a function");
  }
  if (typeof opts.schedule !== "function") {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts.schedule must be a function");
  }
  if (opts.onOverflow != null && typeof opts.onOverflow !== "function") {
    throw new TypeError("safeAsync.makeBufferedEnqueue: opts.onOverflow must be a function when provided");
  }
  var batchSize   = opts.batchSize;
  var bufferLimit = opts.bufferLimit;
  var flush       = opts.flush;
  var schedule    = opts.schedule;
  var onOverflow  = opts.onOverflow || null;
  return function enqueue(entry) {
    if (buffer.length >= bufferLimit) {
      var dropped = buffer.shift();
      if (onOverflow) onOverflow(dropped);
    }
    buffer.push(entry);
    if (buffer.length >= batchSize) {
      flush().catch(function () {});
    } else {
      schedule();
    }
    return Promise.resolve({ accepted: true, queued: buffer.length });
  };
}

/**
 * @primitive b.safeAsync.makeDrainingClose
 * @signature b.safeAsync.makeDrainingClose(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeAsync.makeBufferedEnqueue, b.safeAsync.makeScheduledFlush
 *
 * Graceful shutdown for a batching egress sink. Returns an async
 * `close()` that cancels the coalescing scheduler, awaits any in-flight
 * drain, runs one final flush, then marks the sink closed — in that
 * order, because the order is load-bearing.
 *
 * The flush loop typically guards on `!closed` to stop pulling from the
 * buffer; flipping `closed` first would strand the records an operator
 * queued in the moment before shutdown. Draining before the flip is the
 * difference between a clean shutdown and silently dropped tail records
 * (lost logs, lost audit). This primitive encodes that invariant once so
 * each sink can't reintroduce the reorder.
 *
 * `opts.getInflight` is read at close time (not construction) so it
 * observes whatever drain is running then; its rejection is swallowed —
 * the sink surfaces flush failures through its own onDrop. `opts.flush`
 * runs the final drain; `opts.markClosed` flips the sink's closed flag.
 *
 * @opts
 *   scheduler:   Object,    // { cancel() } — the coalescing flush handle
 *   getInflight: Function,  // () => Promise|null — current in-flight drain
 *   flush:       Function,  // () => Promise — final drain
 *   markClosed:  Function,  // () => void — flip the closed flag last
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var closed = false, inflight = null, buffer = [];
 *   var sched = b.safeAsync.makeScheduledFlush(20, drain);
 *   function drain() { inflight = Promise.resolve(); return inflight; }
 *   var close = b.safeAsync.makeDrainingClose({
 *     scheduler:   sched,
 *     getInflight: function () { return inflight; },
 *     flush:       drain,
 *     markClosed:  function () { closed = true; },
 *   });
 *
 *   await close();
 *   closed;
 *   // → true
 */
function makeDrainingClose(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("safeAsync.makeDrainingClose: opts is required");
  }
  if (!opts.scheduler || typeof opts.scheduler.cancel !== "function") {
    throw new TypeError("safeAsync.makeDrainingClose: opts.scheduler must expose cancel()");
  }
  if (typeof opts.getInflight !== "function") {
    throw new TypeError("safeAsync.makeDrainingClose: opts.getInflight must be a function");
  }
  if (typeof opts.flush !== "function") {
    throw new TypeError("safeAsync.makeDrainingClose: opts.flush must be a function");
  }
  if (typeof opts.markClosed !== "function") {
    throw new TypeError("safeAsync.makeDrainingClose: opts.markClosed must be a function");
  }
  var scheduler   = opts.scheduler;
  var getInflight = opts.getInflight;
  var flush       = opts.flush;
  var markClosed  = opts.markClosed;
  return async function close() {
    scheduler.cancel();
    var inflight = getInflight();
    if (inflight) {
      try { await inflight; } catch (_e) { /* surfaced via the sink's onDrop */ }
    }
    await flush();
    markClosed();
  };
}

/**
 * @primitive b.safeAsync.makeBatchDrain
 * @signature b.safeAsync.makeBatchDrain(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeAsync.makeBufferedEnqueue, b.safeAsync.makeDrainingClose
 *
 * The drain loop behind a batching egress sink. Owns the single-flight
 * latch and returns `{ flush, getInflight, isInFlight }`. Calling
 * `flush()` while a drain is in progress returns that same in-flight
 * promise (one drain at a time); otherwise it pulls batches off the
 * operator-owned `buffer` and ships each via `opts.sendBatch` until the
 * buffer empties or the sink closes, rescheduling itself if records
 * remain.
 *
 * `opts.sendBatch(batch)` is the per-sink transport (serialize + send,
 * typically wrapped in retry); a throw means the batch is permanently
 * rejected — the loop reports it via `opts.onRetryExhausted(batch, err)`
 * and stops (the buffer keeps the rest for the next cycle). `opts.isClosed`
 * is polled each iteration so a shutdown stops the loop promptly.
 *
 * Two optional hooks cover sinks that need more than a plain splice:
 * `opts.takeBatch(buffer)` returns the next batch (default
 * `buffer.splice(0, batchSize)`) for sinks with a byte-size cap; and
 * `opts.beforeDrain()` runs once before the loop (e.g. ensure a remote
 * log stream exists) — if it throws, the whole buffer is drained to
 * `opts.onBeforeDrainFail(records, err)` as a permanent drop, since every
 * batch would hit the same failure.
 *
 * @opts
 *   buffer:           Array,    // operator-owned record buffer
 *   batchSize:        number,   // default splice width
 *   scheduler:        Object,   // { schedule() } — reschedule when records remain
 *   isClosed:         Function, // () => boolean — polled each iteration
 *   sendBatch:        Function, // (batch) => Promise — throw ⇒ permanent reject
 *   onRetryExhausted: Function, // (batch, err) => void — permanent-reject accounting
 *   takeBatch:        Function, // (buffer) => batch — optional; default splice(0, batchSize)
 *   beforeDrain:      Function, // () => Promise — optional pre-loop step
 *   onBeforeDrainFail: Function,// (records, err) => void — optional; beforeDrain threw
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var buffer = [{ n: 1 }, { n: 2 }];
 *   var sent = [];
 *   var sched = b.safeAsync.makeScheduledFlush(20, function () {});
 *   var drain = b.safeAsync.makeBatchDrain({
 *     buffer:           buffer,
 *     batchSize:        10,
 *     scheduler:        sched,
 *     isClosed:         function () { return false; },
 *     sendBatch:        function (batch) { sent.push(batch); return Promise.resolve(); },
 *     onRetryExhausted: function () {},
 *   });
 *   await drain.flush();
 *   sent.length;
 *   // → 1
 */
function makeBatchDrain(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("safeAsync.makeBatchDrain: opts is required");
  }
  if (!Array.isArray(opts.buffer)) {
    throw new TypeError("safeAsync.makeBatchDrain: opts.buffer must be an array");
  }
  if (typeof opts.batchSize !== "number" || !isFinite(opts.batchSize) || opts.batchSize < 1) {
    throw new TypeError("safeAsync.makeBatchDrain: opts.batchSize must be a positive finite number");
  }
  if (!opts.scheduler || typeof opts.scheduler.schedule !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.scheduler must expose schedule()");
  }
  if (typeof opts.isClosed !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.isClosed must be a function");
  }
  if (typeof opts.sendBatch !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.sendBatch must be a function");
  }
  if (typeof opts.onRetryExhausted !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.onRetryExhausted must be a function");
  }
  if (opts.takeBatch != null && typeof opts.takeBatch !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.takeBatch must be a function when provided");
  }
  if (opts.beforeDrain != null && typeof opts.beforeDrain !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.beforeDrain must be a function when provided");
  }
  if (opts.onBeforeDrainFail != null && typeof opts.onBeforeDrainFail !== "function") {
    throw new TypeError("safeAsync.makeBatchDrain: opts.onBeforeDrainFail must be a function when provided");
  }
  var buffer           = opts.buffer;
  var batchSize        = opts.batchSize;
  var scheduler        = opts.scheduler;
  var isClosed         = opts.isClosed;
  var sendBatch        = opts.sendBatch;
  var onRetryExhausted = opts.onRetryExhausted;
  var takeBatch        = opts.takeBatch || function (buf) { return buf.splice(0, batchSize); };
  var beforeDrain      = opts.beforeDrain || null;
  var onBeforeDrainFail = opts.onBeforeDrainFail || null;

  var inFlight = false;
  var inFlightPromise = null;

  async function flush() {
    if (inFlight) return inFlightPromise;
    if (buffer.length === 0) return;
    inFlight = true;
    inFlightPromise = (async function () {
      try {
        if (beforeDrain) {
          try { await beforeDrain(); }
          catch (e) {
            var allBuffered = buffer.splice(0, buffer.length);
            if (onBeforeDrainFail) onBeforeDrainFail(allBuffered, e);
            return;
          }
        }
        while (buffer.length > 0 && !isClosed()) {
          var batch = takeBatch(buffer);
          if (batch.length === 0) break;
          try {
            await sendBatch(batch);
          } catch (sendErr) {
            onRetryExhausted(batch, sendErr);
            break;
          }
        }
      } finally {
        inFlight = false;
        inFlightPromise = null;
        if (buffer.length > 0) scheduler.schedule();
      }
    })();
    return inFlightPromise;
  }

  return {
    flush:       flush,
    getInflight: function () { return inFlightPromise; },
    isInFlight:  function () { return inFlight; },
  };
}

/**
 * @primitive b.safeAsync.makeBatchingSink
 * @signature b.safeAsync.makeBatchingSink(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeAsync.makeBatchDrain, b.safeAsync.makeBufferedEnqueue
 *
 * The complete batching egress-sink core — buffer, drop accounting,
 * single-flight drain, and graceful close, wired together. Returns
 * `{ emit, close, flush, stats }`. A sink built on this provides only
 * its transport (`sendBatch`) and config; the bounded buffer, overflow
 * and retry-exhaustion drop counting, batch-full flushing, and
 * drain-before-close shutdown all come from here.
 *
 * It composes the three lower-level primitives —
 * `makeBufferedEnqueue` (backpressure), `makeBatchDrain` (single-flight
 * drain), `makeDrainingClose` (shutdown) — so every sink shares one
 * implementation of the parts that are easy to get subtly wrong (an
 * unbounded buffer is an OOM vector; flipping closed before the final
 * drain strands tail records).
 *
 * `opts.sendBatch(batch)` is the transport; a throw means permanent
 * rejection (counted as a drop, reported via onDrop "retry-exhausted").
 * `opts.prepareRecord(record)` optionally transforms or rejects a record
 * before buffering — return `{ entry }` to buffer `entry`, or
 * `{ rejected: true, reason, dropKind?, drop?, error? }` to refuse it
 * (e.g. an oversize event past a provider's hard cap). `opts.takeBatch`
 * and `opts.beforeDrain` are forwarded to the drain (byte-cap batching;
 * a pre-drain handshake whose failure drops the buffer under
 * `opts.beforeDrainDropKind`).
 *
 * @opts
 *   batchSize:           number,   // flush at this depth
 *   bufferLimit:         number,   // drop oldest past this depth
 *   maxBatchAgeMs:       number,   // coalescing flush delay
 *   sendBatch:           Function, // (batch) => Promise — transport
 *   onDrop:              Function, // ({reason,batch,error}) => void (optional)
 *   prepareRecord:       Function, // (record) => {entry}|{rejected,...} (optional)
 *   takeBatch:           Function, // () => batch (optional; byte-cap sinks)
 *   beforeDrain:         Function, // () => Promise (optional pre-drain step)
 *   beforeDrainDropKind: string,   // drop kind when beforeDrain fails
 *
 * @example
 *   var b = require("blamejs");
 *
 *   var sent = [];
 *   var sink = b.safeAsync.makeBatchingSink({
 *     batchSize:     2,
 *     bufferLimit:   100,
 *     maxBatchAgeMs: 50,
 *     sendBatch:     function (batch) { sent.push(batch); return Promise.resolve(); },
 *   });
 *   await sink.emit({ message: "a" });
 *   await sink.emit({ message: "b" });  // batch full → flush
 *   await sink.close();
 *   sent.length;
 *   // → 1
 */
function makeBatchingSink(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("safeAsync.makeBatchingSink: opts is required");
  }
  if (typeof opts.sendBatch !== "function") {
    throw new TypeError("safeAsync.makeBatchingSink: opts.sendBatch must be a function");
  }
  if (opts.prepareRecord != null && typeof opts.prepareRecord !== "function") {
    throw new TypeError("safeAsync.makeBatchingSink: opts.prepareRecord must be a function when provided");
  }
  var prepareRecord = opts.prepareRecord || null;
  var beforeDrainDropKind = opts.beforeDrainDropKind || "before-drain-failed";
  var onDrop = makeDropCallback(opts.onDrop);

  var buffer = [];
  var dropCount = 0;
  var closed = false;

  var flushScheduler = makeScheduledFlush(opts.maxBatchAgeMs, function () { return _flush(); });

  var drain = makeBatchDrain({
    buffer:      buffer,
    batchSize:   opts.batchSize,
    scheduler:   flushScheduler,
    isClosed:    function () { return closed; },
    takeBatch:   opts.takeBatch,
    beforeDrain: opts.beforeDrain,
    onBeforeDrainFail: opts.beforeDrain
      ? function (records, e) { dropCount += records.length; onDrop(beforeDrainDropKind, records, e); }
      : undefined,
    sendBatch:   opts.sendBatch,
    onRetryExhausted: function (batch, e) { dropCount += batch.length; onDrop("retry-exhausted", batch, e); },
  });
  var _flush = drain.flush;

  var enqueue = makeBufferedEnqueue(buffer, {
    batchSize:   opts.batchSize,
    bufferLimit: opts.bufferLimit,
    flush:       _flush,
    schedule:    flushScheduler.schedule,
    onOverflow:  function (dropped) { dropCount += 1; onDrop("overflow", [dropped], null); },
  });

  function emit(record) {
    if (closed) return Promise.resolve({ accepted: false, reason: "sink closed" });
    if (prepareRecord) {
      var prepared = prepareRecord(record);
      if (prepared && prepared.rejected) {
        dropCount += 1;
        if (prepared.drop) onDrop(prepared.dropKind || prepared.reason, prepared.drop, prepared.error || null);
        return Promise.resolve({ accepted: false, reason: prepared.reason });
      }
      return enqueue(prepared && "entry" in prepared ? prepared.entry : record);
    }
    return enqueue(record);
  }

  var close = makeDrainingClose({
    scheduler:   flushScheduler,
    getInflight: drain.getInflight,
    flush:       _flush,
    markClosed:  function () { closed = true; },
  });

  return {
    emit:  emit,
    close: close,
    flush: _flush,
    stats: function (extra) {
      var base = { queued: buffer.length, dropped: dropCount, inFlight: drain.isInFlight() };
      return extra ? Object.assign(base, extra) : base;
    },
  };
}

var PARALLEL_DEFAULT_CONCURRENCY = 8;
var PARALLEL_MAX_CONCURRENCY = 256;

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
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }

    function _workerLoop() {
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

class Mutex {
  constructor() {
    this._waiters = [];
    this._held = false;
  }

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
          if (idx === -1) return;
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

class Semaphore {
  constructor(limit) {
    if (typeof limit !== "number" || limit < 1 || !Number.isInteger(limit)) {
      throw new SafeAsyncError("Semaphore limit must be a positive integer", "async/bad-arg");
    }
    this._limit = limit;
    this._inFlight = 0;
    this._waiters = [];
  }

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
  var unref = opts.unref !== false;
  var onError = typeof opts.onError === "function" ? opts.onError : null;

  var stopped = false;
  function _tick() {
    if (stopped) return;
    var result;
    try { result = fn(); } catch (e) {
      _routeCallbackError(onError, e); return;
    }
    containRejection(result, onError);
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
        _routeCallbackError(onError, e);
        _schedule();
        return;
      }
      settled.catch(function (e) {
        _routeCallbackError(onError, e);
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

/**
 * @primitive b.safeAsync.keyedSerializer
 * @signature b.safeAsync.keyedSerializer()
 * @since     0.15.42
 * @status    stable
 * @related   b.safeAsync.parallel
 *
 * Serializes async work per key: `run(key, fn)` queues `fn` behind any in-flight
 * or queued work for the same `key` and runs it once they settle, so a
 * read-modify-write or a check-then-create on a shared store cannot interleave
 * with another call for the same key in the same process. Different keys run
 * concurrently. The per-key chain is dropped once it drains, so the map does not
 * grow without bound.
 *
 * In-process only: it serializes calls within ONE process. A registry shared
 * across processes still needs its backend's own atomic create / unique
 * constraint to refuse a cross-process duplicate.
 *
 * @example
 *   var reg = b.safeAsync.keyedSerializer();
 *   // concurrent register("acme") calls apply one-at-a-time, so the second
 *   // sees the first's row and is refused as a duplicate:
 *   await reg.run("acme", function () { return register("acme", row); });
 */
function keyedSerializer() {
  var chains = new Map();
  function run(key, fn) {
    var prev = chains.get(key) || Promise.resolve();
    var result = prev.then(function () { return fn(); }, function () { return fn(); });
    var tail = result.then(function () {}, function () {});
    chains.set(key, tail);
    tail.then(function () { if (chains.get(key) === tail) chains.delete(key); });
    return result;
  }
  return { run: run };
}

var retryHelper = require("./retry");

var asyncRetry     = retryHelper.withRetry;
var CircuitBreaker = retryHelper.CircuitBreaker;

module.exports = {
  withTimeout:        withTimeout,
  withSignal:         withSignal,
  writeChunk:         writeChunk,
  withTimeoutSignal:  withTimeoutSignal,
  sleep:              sleep,
  repeating:          repeating,
  flushLoop:          flushLoop,
  safeAwait:          safeAwait,
  safeInvoke:         safeInvoke,
  safeApply:          safeApply,
  containRejection:   containRejection,
  makeDropCallback:   makeDropCallback,
  makeScheduledFlush: makeScheduledFlush,
  makeBufferedEnqueue: makeBufferedEnqueue,
  makeDrainingClose:  makeDrainingClose,
  makeBatchDrain:     makeBatchDrain,
  makeBatchingSink:   makeBatchingSink,
  parallel:           parallel,
  keyedSerializer:    keyedSerializer,
  Mutex:              Mutex,
  Semaphore:          Semaphore,
  Once:               Once,
  asyncRetry:         asyncRetry,
  CircuitBreaker:     CircuitBreaker,
  SafeAsyncError:     SafeAsyncError,
};
