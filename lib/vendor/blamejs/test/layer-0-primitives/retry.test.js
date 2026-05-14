"use strict";
/**
 * b.retry — withRetry, CircuitBreaker, isRetryable, backoffDelay.
 *
 * Run standalone: `node test/layer-0-primitives/retry.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Surface ----

function testRetrySurface() {
  check("b.retry namespace present",            typeof b.retry === "object");
  check("b.retry.withRetry is async fn",        typeof b.retry.withRetry === "function");
  check("b.retry.isRetryable is fn",            typeof b.retry.isRetryable === "function");
  check("b.retry.backoffDelay is fn",           typeof b.retry.backoffDelay === "function");
  check("b.retry.CircuitBreaker is class",      typeof b.retry.CircuitBreaker === "function");
  check("b.retry.DEFAULT_RETRY frozen object",  Object.isFrozen(b.retry.DEFAULT_RETRY));
  check("b.retry.DEFAULT_BREAKER frozen object", Object.isFrozen(b.retry.DEFAULT_BREAKER));
  check("b.retry.RETRYABLE_HTTP_STATUS array",  Array.isArray(b.retry.RETRYABLE_HTTP_STATUS));
  check("b.retry.NON_RETRYABLE_HTTP_STATUS arr", Array.isArray(b.retry.NON_RETRYABLE_HTTP_STATUS));
  check("b.retry.RETRYABLE_NET_ERRORS array",   Array.isArray(b.retry.RETRYABLE_NET_ERRORS));
  check("b.retry.STATES.CLOSED",                b.retry.STATES.CLOSED === "closed");
  check("b.retry.STATES.OPEN",                  b.retry.STATES.OPEN === "open");
  check("b.retry.STATES.HALF_OPEN",             b.retry.STATES.HALF_OPEN === "half-open");
}

// ---- isRetryable ----

function testIsRetryableHttpStatus() {
  var r = b.retry.isRetryable;
  check("isRetryable: 408 → true",  r({ statusCode: 408 }) === true);
  check("isRetryable: 425 → true",  r({ statusCode: 425 }) === true);
  check("isRetryable: 429 → true",  r({ statusCode: 429 }) === true);
  check("isRetryable: 500 → true",  r({ statusCode: 500 }) === true);
  check("isRetryable: 502 → true",  r({ statusCode: 502 }) === true);
  check("isRetryable: 503 → true",  r({ statusCode: 503 }) === true);
  check("isRetryable: 504 → true",  r({ statusCode: 504 }) === true);

  check("isRetryable: 400 → false", r({ statusCode: 400 }) === false);
  check("isRetryable: 401 → false", r({ statusCode: 401 }) === false);
  check("isRetryable: 403 → false", r({ statusCode: 403 }) === false);
  check("isRetryable: 404 → false", r({ statusCode: 404 }) === false);
  check("isRetryable: 422 → false", r({ statusCode: 422 }) === false);
  check("isRetryable: 501 → false", r({ statusCode: 501 }) === false);
}

function testIsRetryableUnknown5xx() {
  var r = b.retry.isRetryable;
  check("isRetryable: unknown 599 → true", r({ statusCode: 599 }) === true);
  check("isRetryable: 200 → false",        r({ statusCode: 200 }) === false);
}

function testIsRetryableNetErrors() {
  var r = b.retry.isRetryable;
  check("isRetryable: ECONNRESET → true",  r({ code: "ECONNRESET" }) === true);
  check("isRetryable: ETIMEDOUT → true",   r({ code: "ETIMEDOUT" }) === true);
  check("isRetryable: ENOTFOUND → true",   r({ code: "ENOTFOUND" }) === true);
  check("isRetryable: ENOENT → false",     r({ code: "ENOENT" }) === false);
}

function testIsRetryablePermanent() {
  var r = b.retry.isRetryable;
  check("isRetryable: err.permanent → false",
        r({ permanent: true, statusCode: 503 }) === false);
  check("isRetryable: isObjectStoreError + permanent → false",
        r({ isObjectStoreError: true, permanent: true, statusCode: 503 }) === false);
}

function testIsRetryableEmpty() {
  var r = b.retry.isRetryable;
  check("isRetryable: null → false",       r(null) === false);
  check("isRetryable: undefined → false",  r(undefined) === false);
  check("isRetryable: empty err → false",  r({}) === false);
  check("isRetryable: only message → false", r({ message: "boom" }) === false);
}

// ---- backoffDelay ----

function testBackoffDelayMonotonicAndCapped() {
  var opts = { baseDelayMs: 10, maxDelayMs: 1000, jitterFactor: 0 };   // no jitter for determinism
  var d1 = b.retry.backoffDelay(1, opts);
  var d2 = b.retry.backoffDelay(2, opts);
  var d3 = b.retry.backoffDelay(3, opts);
  var dHigh = b.retry.backoffDelay(20, opts);
  check("backoffDelay: attempt 1 = base",       d1 === 10);
  check("backoffDelay: attempt 2 doubles",      d2 === 20);
  check("backoffDelay: attempt 3 quadruples",   d3 === 40);
  check("backoffDelay: capped at maxDelayMs",   dHigh === 1000);
  check("backoffDelay: monotonic non-decreasing", d1 <= d2 && d2 <= d3);
}

function testBackoffDelayJitterRange() {
  var opts = { baseDelayMs: 100, maxDelayMs: 100, jitterFactor: 0.5 };
  // capped = 100, jitter window = capped*0.5 = 50 → result in [50, 100]
  for (var i = 0; i < 50; i++) {
    var d = b.retry.backoffDelay(1, opts);
    check("backoffDelay: jitter result in [50,100]", d >= 50 && d <= 100);
  }
}

function testBackoffDelayRejectsBadAttempt() {
  var threw = null;
  try { b.retry.backoffDelay(0); } catch (e) { threw = e; }
  check("backoffDelay: rejects 0", threw && /positive integer/.test(threw.message));
  threw = null;
  try { b.retry.backoffDelay(-1); } catch (e) { threw = e; }
  check("backoffDelay: rejects negative", threw && /positive integer/.test(threw.message));
  threw = null;
  try { b.retry.backoffDelay(1.5); } catch (e) { threw = e; }
  check("backoffDelay: rejects non-integer", threw && /positive integer/.test(threw.message));
  threw = null;
  try { b.retry.backoffDelay("1"); } catch (e) { threw = e; }
  check("backoffDelay: rejects string", threw && /positive integer/.test(threw.message));
}

// ---- withRetry ----

async function testWithRetryFirstSuccess() {
  var calls = 0;
  var r = await b.retry.withRetry(function () { calls++; return "ok"; });
  check("withRetry: first-call success returns value", r === "ok");
  check("withRetry: first-call success calls fn once", calls === 1);
}

async function testWithRetryTransientThenSuccess() {
  var calls = 0;
  var r = await b.retry.withRetry(function () {
    calls++;
    if (calls < 3) {
      var err = new Error("transient");
      err.code = "ECONNRESET";
      throw err;
    }
    return "ok";
  }, { baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });
  check("withRetry: succeeded after 3 attempts", r === "ok" && calls === 3);
}

async function testWithRetryStopsOnNonRetryable() {
  var calls = 0;
  var threw = null;
  try {
    await b.retry.withRetry(function () {
      calls++;
      var err = new Error("bad-request");
      err.statusCode = 400;
      throw err;
    }, { baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });
  } catch (e) { threw = e; }
  check("withRetry: stopped on non-retryable",       threw && threw.statusCode === 400);
  check("withRetry: only one attempt for 400",       calls === 1);
}

async function testWithRetryExhausts() {
  var calls = 0;
  var threw = null;
  try {
    await b.retry.withRetry(function () {
      calls++;
      var err = new Error("transient");
      err.code = "ECONNRESET";
      throw err;
    }, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 });
  } catch (e) { threw = e; }
  check("withRetry: throws after maxAttempts", threw && threw.code === "ECONNRESET");
  check("withRetry: ran maxAttempts times",     calls === 3);
}

async function testWithRetryCustomClassifier() {
  var calls = 0;
  var r = await b.retry.withRetry(function () {
    calls++;
    if (calls < 2) throw new Error("any-shape");   // default classifier would not retry
    return "ok";
  }, {
    isRetryable: function () { return true; },
    baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0,
  });
  check("withRetry: custom classifier retries", r === "ok" && calls === 2);
}

async function testWithRetryOnRetryCallback() {
  var observed = [];
  var calls = 0;
  await b.retry.withRetry(function () {
    calls++;
    if (calls < 3) {
      var err = new Error("transient");
      err.code = "ECONNRESET";
      throw err;
    }
    return "ok";
  }, {
    baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0,
    onRetry: function (info) { observed.push(info); },
  });
  check("withRetry: onRetry fired per failed attempt",
        observed.length === 2);
  check("withRetry: onRetry payload has attempt+delay+error",
        observed[0].attempt === 1 &&
        typeof observed[0].delay === "number" &&
        observed[0].error && observed[0].error.code === "ECONNRESET");
}

async function testWithRetryOnRetryThrowSwallowed() {
  var calls = 0;
  var r = await b.retry.withRetry(function () {
    calls++;
    if (calls < 2) {
      var err = new Error("transient");
      err.code = "ECONNRESET";
      throw err;
    }
    return "ok";
  }, {
    baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0,
    onRetry: function () { throw new Error("observer crashed"); },
  });
  check("withRetry: onRetry throw does not break retry loop", r === "ok" && calls === 2);
}

async function testWithRetrySignalAbort() {
  var ac = new AbortController();
  var threw = null;
  // Abort 5ms after start; backoff is 1000ms so signal must short-circuit it.
  setTimeout(function () { ac.abort(); }, 5);
  var t0 = Date.now();
  try {
    await b.retry.withRetry(function () {
      var err = new Error("transient");
      err.code = "ECONNRESET";
      throw err;
    }, {
      maxAttempts: 5, baseDelayMs: 1000, maxDelayMs: 1000, jitterFactor: 0,
      signal: ac.signal,
    });
  } catch (e) { threw = e; }
  var elapsed = Date.now() - t0;
  check("withRetry: signal abort surfaces error",  threw !== null);
  check("withRetry: signal abort short-circuits backoff", elapsed < 500);
}

// ---- withRetry input validation (rejects bad opts at call site) ----

function _expectRetryThrow(label, opts, regex) {
  try {
    // Pass dummy fn; validation happens before fn invocation.
    var p = b.retry.withRetry(function () { return "ok"; }, opts);
    // withRetry is async — the throw is synchronous, but we still get a
    // rejected promise. await it inline via .catch in caller.
    return p.then(
      function () { check(label + " — should have thrown", false); },
      function (e) { check(label, regex.test(e.message)); }
    );
  } catch (e) {
    // Validation threw synchronously (depends on runtime); accept either.
    check(label, regex.test(e.message));
    return Promise.resolve();
  }
}

async function testWithRetryValidatesOpts() {
  await _expectRetryThrow("withRetry: rejects non-int maxAttempts",
        { maxAttempts: "five" }, /maxAttempts/);
  await _expectRetryThrow("withRetry: rejects 0 maxAttempts",
        { maxAttempts: 0 }, /maxAttempts/);
  await _expectRetryThrow("withRetry: rejects negative baseDelayMs",
        { baseDelayMs: -1 }, /baseDelayMs/);
  await _expectRetryThrow("withRetry: rejects NaN maxDelayMs",
        { maxDelayMs: NaN }, /maxDelayMs/);
  await _expectRetryThrow("withRetry: rejects jitterFactor > 1",
        { jitterFactor: 2 }, /jitterFactor/);
  await _expectRetryThrow("withRetry: rejects jitterFactor < 0",
        { jitterFactor: -0.1 }, /jitterFactor/);
  await _expectRetryThrow("withRetry: rejects non-fn isRetryable",
        { isRetryable: "yes" }, /isRetryable/);
  await _expectRetryThrow("withRetry: rejects non-fn onRetry",
        { onRetry: 42 }, /onRetry/);
  await _expectRetryThrow("withRetry: rejects non-AbortSignal signal",
        { signal: { aborted: false } }, /signal/);   // missing addEventListener

  var threw = null;
  try { await b.retry.withRetry("not a fn"); } catch (e) { threw = e; }
  check("withRetry: rejects non-function fn", threw && /fn must be a function/.test(threw.message));
}

// ---- CircuitBreaker ----

async function testBreakerClosedToOpen() {
  var br = new b.retry.CircuitBreaker("test-1", {
    failureThreshold: 3, cooldownMs: 1000, successThreshold: 1,
  });
  check("breaker: starts closed", br.getState() === "closed");
  for (var i = 0; i < 3; i++) {
    try { await br.wrap(function () { throw new Error("boom"); }); } catch (_e) {}
  }
  check("breaker: opens after threshold consecutive failures",
        br.getState() === "open");
  // Subsequent call fast-fails with CIRCUIT_OPEN
  var threw = null;
  try { await br.wrap(function () { return "ok"; }); } catch (e) { threw = e; }
  check("breaker: open state fast-fails with CIRCUIT_OPEN",
        threw && threw.code === "CIRCUIT_OPEN");
}

async function testBreakerOpenToHalfToClosed() {
  var br = new b.retry.CircuitBreaker("test-2", {
    failureThreshold: 2, cooldownMs: 30, successThreshold: 2,
  });
  for (var i = 0; i < 2; i++) {
    try { await br.wrap(function () { throw new Error("boom"); }); } catch (_e) {}
  }
  check("breaker: opened after threshold", br.getState() === "open");
  await new Promise(function (r) { setTimeout(r, 40); });
  // First successful call after cooldown → enters half-open via the wrap path
  var r1 = await br.wrap(function () { return "ok"; });
  check("breaker: half-open success #1 returns",  r1 === "ok");
  var r2 = await br.wrap(function () { return "ok"; });
  check("breaker: half-open success #2 returns",  r2 === "ok");
  check("breaker: closed after successThreshold probes", br.getState() === "closed");
}

async function testBreakerHalfToOpenOnFailure() {
  var br = new b.retry.CircuitBreaker("test-3", {
    failureThreshold: 1, cooldownMs: 10, successThreshold: 2,
  });
  try { await br.wrap(function () { throw new Error("boom"); }); } catch (_e) {}
  check("breaker: opened",                   br.getState() === "open");
  await new Promise(function (r) { setTimeout(r, 20); });
  // One probe failure → re-open
  try { await br.wrap(function () { throw new Error("still bad"); }); } catch (_e) {}
  check("breaker: re-opens on half-open failure", br.getState() === "open");
}

async function testBreakerIgnoresPermanent() {
  var br = new b.retry.CircuitBreaker("test-4", {
    failureThreshold: 2, cooldownMs: 1000, successThreshold: 1,
  });
  for (var i = 0; i < 5; i++) {
    try {
      await br.wrap(function () {
        var e = new Error("caller bug");
        e.permanent = true;
        throw e;
      });
    } catch (_e) {}
  }
  check("breaker: stays closed under permanent errors",
        br.getState() === "closed");
}

async function testBreakerGetStateAndReset() {
  var br = new b.retry.CircuitBreaker("test-5", {
    failureThreshold: 1, cooldownMs: 10000, successThreshold: 1,
  });
  try { await br.wrap(function () { throw new Error("boom"); }); } catch (_e) {}
  check("breaker: getState reports open", br.getState() === "open");
  br.reset();
  check("breaker: reset returns to closed", br.getState() === "closed");
}

function testBreakerValidatesOpts() {
  var threw = null;
  try { new b.retry.CircuitBreaker("", {}); } catch (e) { threw = e; }
  check("breaker: rejects empty name", threw && /name/.test(threw.message));

  threw = null;
  try { new b.retry.CircuitBreaker("ok", { failureThreshold: 0 }); } catch (e) { threw = e; }
  check("breaker: rejects 0 failureThreshold", threw && /failureThreshold/.test(threw.message));

  threw = null;
  try { new b.retry.CircuitBreaker("ok", { cooldownMs: -1 }); } catch (e) { threw = e; }
  check("breaker: rejects negative cooldownMs", threw && /cooldownMs/.test(threw.message));

  threw = null;
  try { new b.retry.CircuitBreaker("ok", { successThreshold: 1.5 }); } catch (e) { threw = e; }
  check("breaker: rejects non-int successThreshold", threw && /successThreshold/.test(threw.message));
}

async function testBreakerWrapValidatesFn() {
  var br = new b.retry.CircuitBreaker("test-6", {});
  var threw = null;
  try { await br.wrap("not a fn"); } catch (e) { threw = e; }
  check("breaker.wrap: rejects non-fn", threw && /fn must be a function/.test(threw.message));
}

// Regression — v0.9.12 and earlier: b.circuitBreaker.create({...}) called
// `new retry.CircuitBreaker(opts)` (single arg), so opts landed in the
// positional `name` slot of the (name, opts) constructor and the
// validator threw "name must be a non-empty string, got object." Every
// operator following the documented `create({ name, ...opts })` shape
// hit it. Fixed in v0.9.13 — caught by hermitstash-sync operator review.
function testCircuitBreakerCreateFactoryNamedOpts() {
  var cb = b.circuitBreaker.create({
    name:             "test-create-named",
    failureThreshold: 5,
    cooldownMs:       30000,
    successThreshold: 2,
  });
  check("circuitBreaker.create: returns CircuitBreaker instance",
        cb instanceof b.retry.CircuitBreaker);
  check("circuitBreaker.create: name carries through",
        cb.name === "test-create-named");
  check("circuitBreaker.create: opts.failureThreshold carries through",
        cb.opts.failureThreshold === 5);
  check("circuitBreaker.create: opts.cooldownMs carries through",
        cb.opts.cooldownMs === 30000);
  check("circuitBreaker.create: starts closed",
        cb.state === "closed");
}

function testCircuitBreakerCreateFactoryMissingName() {
  // Validator still refuses empty name — confirms the bug fix didn't
  // accidentally weaken the validation.
  var threw = null;
  try { b.circuitBreaker.create({}); } catch (e) { threw = e; }
  check("circuitBreaker.create: refuses empty name",
        threw && /name must be a non-empty string/.test(threw.message));
}

// withBreaker — composition of withRetry + a CircuitBreaker. Breaker
// observes the retry-loop OUTCOME (one breaker call per loop), not
// each intermediate retry attempt.
async function testWithBreakerHappyPath() {
  var cb = b.circuitBreaker.create({
    name: "wb-happy", failureThreshold: 5, cooldownMs: 60000,
  });
  var calls = 0;
  var result = await b.retry.withBreaker(async function () {
    calls += 1;
    return "ok";
  }, { retry: { maxAttempts: 3 }, breaker: cb });
  check("withBreaker: returns fn result on success",   result === "ok");
  check("withBreaker: fn called once when first attempt succeeds", calls === 1);
  check("withBreaker: breaker still closed after success", cb.state === "closed");
}

async function testWithBreakerOneBreakerCallPerRetryLoop() {
  var cb = b.circuitBreaker.create({
    name: "wb-counter", failureThreshold: 2, cooldownMs: 60000,
  });
  // First retry loop: retries-exhausted. ONE breaker failure.
  var threw = null;
  try {
    await b.retry.withBreaker(async function () {
      var e = new Error("transient ECONNRESET");
      e.code = "ECONNRESET";
      throw e;
    }, { retry: { maxAttempts: 3, baseDelayMs: 1 }, breaker: cb });
  } catch (e) { threw = e; }
  check("withBreaker: failed retry loop bubbles error",  threw && threw.code === "ECONNRESET");
  check("withBreaker: breaker counts 1 failure per loop, not 3",
        cb.consecutiveFailures === 1);
  check("withBreaker: breaker still closed after 1 failure (threshold 2)",
        cb.state === "closed");

  // Second retry loop: exhausts. SECOND breaker failure. Breaker opens.
  var threw2 = null;
  try {
    await b.retry.withBreaker(async function () {
      var e = new Error("transient ECONNRESET");
      e.code = "ECONNRESET";
      throw e;
    }, { retry: { maxAttempts: 3, baseDelayMs: 1 }, breaker: cb });
  } catch (e) { threw2 = e; }
  check("withBreaker: second failed loop bubbles error",  threw2 && threw2.code === "ECONNRESET");
  check("withBreaker: breaker opens after 2 failed loops (threshold)",
        cb.state === "open");
}

function testWithBreakerValidates() {
  var cb = b.circuitBreaker.create({ name: "wb-validate" });
  var threw = null;
  try { b.retry.withBreaker("not a fn", { breaker: cb }); } catch (e) { threw = e; }
  check("withBreaker: rejects non-fn",
        threw && /fn must be a function/.test(threw.message));
  var threw2 = null;
  try { b.retry.withBreaker(async function () {}, { breaker: null }); } catch (e) { threw2 = e; }
  check("withBreaker: rejects missing breaker",
        threw2 && /must be a CircuitBreaker instance/.test(threw2.message));
}

// ---- Run ----

async function run() {
  testRetrySurface();

  testIsRetryableHttpStatus();
  testIsRetryableUnknown5xx();
  testIsRetryableNetErrors();
  testIsRetryablePermanent();
  testIsRetryableEmpty();

  testBackoffDelayMonotonicAndCapped();
  testBackoffDelayJitterRange();
  testBackoffDelayRejectsBadAttempt();

  await testWithRetryFirstSuccess();
  await testWithRetryTransientThenSuccess();
  await testWithRetryStopsOnNonRetryable();
  await testWithRetryExhausts();
  await testWithRetryCustomClassifier();
  await testWithRetryOnRetryCallback();
  await testWithRetryOnRetryThrowSwallowed();
  await testWithRetrySignalAbort();
  testCircuitBreakerCreateFactoryNamedOpts();
  testCircuitBreakerCreateFactoryMissingName();
  await testWithBreakerHappyPath();
  await testWithBreakerOneBreakerCallPerRetryLoop();
  testWithBreakerValidates();
  await testWithRetryValidatesOpts();

  await testBreakerClosedToOpen();
  await testBreakerOpenToHalfToClosed();
  await testBreakerHalfToOpenOnFailure();
  await testBreakerIgnoresPermanent();
  await testBreakerGetStateAndReset();
  testBreakerValidatesOpts();
  await testBreakerWrapValidatesFn();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
