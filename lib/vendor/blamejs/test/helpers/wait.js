"use strict";
/**
 * test/helpers/wait — poll-until-condition primitive for tests that
 * observe asynchronous state (queue drain, audit flush, fs.watch
 * delivery, mock-collector receive).
 *
 * Replace fixed-budget sleeps:
 *
 *     await new Promise(function (r) { setTimeout(r, 1500); });
 *     assert(collector.requestCount >= 1);
 *
 * with poll-until-event:
 *
 *     await waitUntil(function () { return collector.requestCount >= 1; });
 *     assert(collector.requestCount >= 1);
 *
 * Why this shape:
 *
 * - **Fast platforms exit in milliseconds.** A Linux runner that
 *   delivers the event on the first event-loop turn doesn't pay the
 *   full timeout budget — `waitUntil` returns as soon as the
 *   predicate is truthy.
 * - **Contended platforms get a generous budget.** macOS GitHub-
 *   Actions runners under SMOKE_PARALLEL=64 routinely take 1-2s
 *   to deliver an fs.watch event or flush a deferred-audit queue;
 *   the default `timeoutMs: 5000` covers the worst case without
 *   slowing down the non-contended path.
 * - **One source of truth.** Pre-helper, every flaky-on-contention
 *   test rolled its own `setTimeout(r, N)` with a hand-tuned N.
 *   When CI surfaced the flake, the fix was to bump N — at best a
 *   moving target, at worst it papered over the race. Centralizing
 *   the polling loop here means future fixes update one timeout
 *   ceiling instead of N inline budgets.
 *
 * The pattern that fixed v0.8.60's macOS watcher flake (priming
 * wait + poll-until-event with 5s cap) is the canonical use case;
 * every other "test passes alone, fails under SMOKE_PARALLEL=64"
 * flake (log-stream-otlp / safe-async-loops / sandbox / rate-limit-
 * cluster) is the same root cause: a fixed sleep too short for
 * runner-contention reality.
 */

var DEFAULT_TIMEOUT_MS  = 5000;                                                                  // allow:raw-byte-literal — 5s contention-tolerant default
var DEFAULT_INTERVAL_MS = 25;                                                                    // allow:raw-byte-literal — 40 polls/sec; doesn't burn CPU

/**
 * waitUntil(predicate, opts?) — poll a synchronous OR async predicate
 * every `intervalMs` until it returns truthy OR `timeoutMs` elapses.
 *
 * @param predicate {Function} — sync (returns boolean) or async
 *   (returns Promise<boolean>). Throws inside the predicate count as
 *   "not ready yet" — the next tick re-checks. Catch + log inside
 *   the predicate if you want different behavior.
 * @param opts.timeoutMs  — total budget (default 5000ms)
 * @param opts.intervalMs — poll cadence (default 25ms)
 * @param opts.label      — string in the timeout error for grep'ability
 * @returns {Promise<*>} the truthy value the predicate returned (so
 *   tests can `var info = await waitUntil(() => collector.last)` and
 *   chain assertions on the value).
 * @throws Error("waitUntil timeout: <label>") on timeout.
 */
async function waitUntil(predicate, opts) {
  opts = opts || {};
  if (typeof predicate !== "function") {
    throw new TypeError("waitUntil: predicate must be a function");
  }
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  var intervalMs = typeof opts.intervalMs === "number" ? opts.intervalMs : DEFAULT_INTERVAL_MS;
  var label = opts.label || "condition";
  var deadline = Date.now() + timeoutMs;
  var lastError = null;
  while (Date.now() < deadline) {
    var rv;
    try { rv = await predicate(); lastError = null; }
    catch (e) { lastError = e; rv = false; }
    if (rv) return rv;
    await new Promise(function (r) { setTimeout(r, intervalMs); });
  }
  // One last try right at the deadline — gives a final shot to a
  // predicate whose latency-to-truthy is exactly timeoutMs.
  try {
    var finalRv = await predicate();
    if (finalRv) return finalRv;
  } catch (e) { lastError = e; }
  var msg = "waitUntil timeout: " + label + " (after " + timeoutMs + "ms)";
  if (lastError) msg += " — last predicate threw: " + ((lastError && lastError.message) || String(lastError));
  throw new Error(msg);
}

/**
 * waitUntilEqual(getter, expected, opts?) — convenience wrapper for
 * the most common case ("wait until this value equals that value").
 * Compares with === for primitives, JSON.stringify for objects.
 */
async function waitUntilEqual(getter, expected, opts) {
  opts = opts || {};
  return waitUntil(function () {
    var v = getter();
    if (v === expected) return v;
    if (typeof v === "object" && typeof expected === "object" &&
        JSON.stringify(v) === JSON.stringify(expected)) return v;
    return false;
  }, Object.assign({ label: opts.label || ("value === " + JSON.stringify(expected)) }, opts));
}

/**
 * withTestTimeout(label, fn, opts?) — wrap an async test body with a
 * wall-clock ceiling. Tests doing real-time work (setTimeout-based
 * rate limiting, stream pipelines, child-process exits, fs.watch
 * delivery on contended runners) get a hard per-test deadline so a
 * future runner flake surfaces as `test timed out: <label>` in
 * seconds instead of burning the full GitHub Actions job timeout.
 *
 * Default budget is 10s — generous enough to absorb SMOKE_PARALLEL=64
 * contention on a macOS runner while keeping a hang's blast radius
 * to a single test rather than a 6-hour stuck job. Tests that need a
 * longer window pass `{ timeoutMs }` explicitly with a written reason
 * in the surrounding comment.
 *
 * @param label    {string}   — surfaced in the timeout message
 * @param fn       {Function} — async function (the test body)
 * @param opts     {object?}  — `timeoutMs` (default 10000)
 * @returns        {Promise}    resolves to fn's return value
 *
 * @example
 *   await withTestTimeout("rate enforcement", async function () {
 *     var t = b.streamThrottle.create({ bytesPerSec: 1024 });
 *     await pipeBuf(t.transform(), 4096, 1024);
 *   });
 */
var DEFAULT_TEST_TIMEOUT_MS = 10000;                                                             // allow:raw-byte-literal // allow:raw-time-literal — 10s per-test cap

function withTestTimeout(label, fn, opts) {
  opts = opts || {};
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_TEST_TIMEOUT_MS;
  if (typeof label !== "string" || label.length === 0) {
    throw new Error("withTestTimeout: label (string) required");
  }
  if (typeof fn !== "function") {
    throw new Error("withTestTimeout: fn (function) required");
  }
  return new Promise(function (resolve, reject) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new Error("test timed out: " + label + " (after " + timeoutMs + "ms)"));
    }, timeoutMs);
    Promise.resolve().then(fn).then(function (v) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(e);
    });
  });
}

module.exports = {
  waitUntil:       waitUntil,
  waitUntilEqual:  waitUntilEqual,
  withTestTimeout: withTestTimeout,
};
