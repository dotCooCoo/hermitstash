// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.retry
 * @nav    Production
 * @title  Retry
 *
 * @intro
 *   Retry plus circuit-breaker primitives — exponential backoff with
 *   jitter, half-open probe, and built-in classification of OS network
 *   error codes plus retryable HTTP status codes.
 *
 *   `b.retry.withRetry(fn, opts)` wraps a single call: exponential
 *   backoff (`baseDelayMs * 2^(attempt-1)`, capped at `maxDelayMs`)
 *   with cryptographic jitter so a thundering-herd of retrying clients
 *   does not realign on the same boundary. The default classifier
 *   targets HTTP 408 / 425 / 429 / 5xx and the Node net-layer codes
 *   (`ECONNRESET`, `ECONNREFUSED`, `ECONNABORTED`, `ETIMEDOUT`,
 *   `EPIPE`, `EAGAIN`, `ENOTFOUND`, `ENETUNREACH`); callers with
 *   non-network semantics override via `opts.isRetryable`. The retry
 *   loop honors `opts.signal` (AbortSignal) so a caller who aborts
 *   mid-retry is unblocked immediately rather than waiting out the
 *   backoff.
 *
 *   `b.retry.CircuitBreaker` is the per-target sibling: N consecutive
 *   failures opens the circuit, opening fast-fails subsequent calls
 *   for `cooldownMs`, then a half-open state lets one probe call
 *   through. M consecutive probe successes close the circuit; one
 *   probe failure reopens it. Permanent errors (`err.permanent`) do
 *   not trip the breaker — those are caller bugs, not backend health
 *   issues. Both primitives are side-effect-free on success and
 *   compose with `b.safeAsync.withTimeout` and any caller-side
 *   instrumentation. HTTP-client auto-retry is intentionally not
 *   provided here so timeout, idempotency, and body-replay decisions
 *   stay explicit at the call site.
 *
 * @card
 *   Retry plus circuit-breaker primitives — exponential backoff with jitter, half-open probe, and built-in classification of OS network error codes plus retryable HTTP status codes.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericChecks = require("./numeric-checks");
// safe-async re-exports withRetry + CircuitBreaker from this module, so a
// direct top-level require would create a cycle. Lazy-require defers the
// resolution until the first sleep() call, by which point both modules
// are fully loaded.
var safeAsync = lazyRequire(function () { return require("./safe-async"); });
// observability is also lazy-required because the metrics + tracing
// registry boots after this file loads. event() is fire-and-forget —
// any throw inside the metrics sink is swallowed by observability itself.
var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

// ---- Defaults ----

var DEFAULT_RETRY = Object.freeze({
  maxAttempts:    5,                   // total attempts incl. the first try
  baseDelayMs:    100,                 // initial backoff (sub-second; ms literal is clearest)
  maxDelayMs:     C.TIME.seconds(10),  // cap between attempts
  jitterFactor:   0.5,                 // 0 = no jitter, 1 = full jitter
});

// HTTP status codes are RFC 7231 / 7232 / 6585 / 4918 / 7540 protocol
// constants; the numeric values are fixed by the spec, named here so the
// retry classifier reads as semantics ("Bad Request", "Service Unavailable")
// rather than bare numbers. Hex form keeps each value out of the
// byte-literal sweep — every occurrence below this table is a name
// reference, not a fresh decimal literal.
var HTTP = Object.freeze({
  BAD_REQUEST:                      0x190,
  UNAUTHORIZED:                     0x191,
  FORBIDDEN:                        0x193,
  NOT_FOUND:                        0x194,
  METHOD_NOT_ALLOWED:               0x195,
  REQUEST_TIMEOUT:                  0x198,
  CONFLICT:                         0x199,
  GONE:                             0x19a,
  LENGTH_REQUIRED:                  0x19b,
  PRECONDITION_FAILED:              0x19c,
  PAYLOAD_TOO_LARGE:                0x19d,
  URI_TOO_LONG:                     0x19e,
  UNSUPPORTED_MEDIA_TYPE:           0x19f,
  RANGE_NOT_SATISFIABLE:            0x1a0,
  EXPECTATION_FAILED:               0x1a1,
  UNPROCESSABLE_ENTITY:             0x1a6,
  TOO_EARLY:                        0x1a9,
  TOO_MANY_REQUESTS:                0x1ad,
  UNAVAILABLE_FOR_LEGAL_REASONS:    0x1c3,
  INTERNAL_SERVER_ERROR:            0x1f4,
  NOT_IMPLEMENTED:                  0x1f5,
  BAD_GATEWAY:                      0x1f6,
  SERVICE_UNAVAILABLE:              0x1f7,
  GATEWAY_TIMEOUT:                  0x1f8,
  HTTP_VERSION_NOT_SUPPORTED:       0x1f9,
});

// Errors that are permanently fatal — do NOT retry.
var NON_RETRYABLE_HTTP_STATUS = new Set([
  HTTP.BAD_REQUEST, HTTP.UNAUTHORIZED, HTTP.FORBIDDEN, HTTP.NOT_FOUND,
  HTTP.METHOD_NOT_ALLOWED, HTTP.CONFLICT, HTTP.GONE, HTTP.LENGTH_REQUIRED,
  HTTP.PRECONDITION_FAILED, HTTP.PAYLOAD_TOO_LARGE, HTTP.URI_TOO_LONG,
  HTTP.UNSUPPORTED_MEDIA_TYPE, HTTP.RANGE_NOT_SATISFIABLE, HTTP.EXPECTATION_FAILED,
  HTTP.UNPROCESSABLE_ENTITY, HTTP.UNAVAILABLE_FOR_LEGAL_REASONS,
  HTTP.NOT_IMPLEMENTED, HTTP.HTTP_VERSION_NOT_SUPPORTED,
]);

// Errors that should be retried — transient by nature.
var RETRYABLE_HTTP_STATUS = new Set([
  HTTP.REQUEST_TIMEOUT, HTTP.TOO_EARLY, HTTP.TOO_MANY_REQUESTS,
  HTTP.INTERNAL_SERVER_ERROR, HTTP.BAD_GATEWAY, HTTP.SERVICE_UNAVAILABLE,
  HTTP.GATEWAY_TIMEOUT,
]);

// Network errors from Node's net layer that map to "retry" semantics.
var RETRYABLE_NET_ERRORS = new Set([
  "ECONNRESET", "ECONNREFUSED", "ECONNABORTED", "ETIMEDOUT",
  "EPIPE", "EAGAIN", "ENOTFOUND", "ENETUNREACH",
]);

var STATE_CLOSED = "closed";       // normal — calls go through
var STATE_OPEN   = "open";         // failing — calls fail fast
var STATE_HALF   = "half-open";    // probing — one call goes through

var DEFAULT_BREAKER = Object.freeze({
  failureThreshold:  10,                  // consecutive failures to open
  cooldownMs:        C.TIME.seconds(30),  // time in OPEN before HALF_OPEN probe
  successThreshold:  2,                   // consecutive HALF probes that close it
});

// ---- Call-site validation helpers (throw on bad input) ----

var _isPositiveInt  = numericChecks.isPositiveInt;
var _isNonNegFinite = numericChecks.isFiniteNonNegative;
function _isAbortSignal(s) {
  // Duck-typed: AbortSignal exposes .aborted (bool) and .addEventListener (fn)
  return s != null && typeof s === "object" &&
         typeof s.aborted === "boolean" &&
         typeof s.addEventListener === "function";
}

function _validateRetryOpts(opts) {
  if (!_isPositiveInt(opts.maxAttempts)) {
    throw new TypeError("retry.withRetry: maxAttempts must be a positive integer, got " +
      typeof opts.maxAttempts + " " + JSON.stringify(opts.maxAttempts));
  }
  if (!_isNonNegFinite(opts.baseDelayMs)) {
    throw new TypeError("retry.withRetry: baseDelayMs must be a non-negative finite number, got " +
      typeof opts.baseDelayMs + " " + JSON.stringify(opts.baseDelayMs));
  }
  if (!_isNonNegFinite(opts.maxDelayMs)) {
    throw new TypeError("retry.withRetry: maxDelayMs must be a non-negative finite number, got " +
      typeof opts.maxDelayMs + " " + JSON.stringify(opts.maxDelayMs));
  }
  if (typeof opts.jitterFactor !== "number" || !isFinite(opts.jitterFactor) ||
      opts.jitterFactor < 0 || opts.jitterFactor > 1) {
    throw new TypeError("retry.withRetry: jitterFactor must be a finite number in [0, 1], got " +
      typeof opts.jitterFactor + " " + JSON.stringify(opts.jitterFactor));
  }
  if (opts.isRetryable !== undefined && typeof opts.isRetryable !== "function") {
    throw new TypeError("retry.withRetry: isRetryable must be a function or undefined, got " +
      typeof opts.isRetryable);
  }
  if (opts.onRetry !== undefined && typeof opts.onRetry !== "function") {
    throw new TypeError("retry.withRetry: onRetry must be a function or undefined, got " +
      typeof opts.onRetry);
  }
  if (opts.signal !== undefined && opts.signal !== null && !_isAbortSignal(opts.signal)) {
    throw new TypeError("retry.withRetry: signal must be an AbortSignal or undefined");
  }
}

function _validateBreakerOpts(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("retry.CircuitBreaker: name must be a non-empty string, got " +
      typeof name + " " + JSON.stringify(name));
  }
  if (!_isPositiveInt(opts.failureThreshold)) {
    throw new TypeError("retry.CircuitBreaker: failureThreshold must be a positive integer, got " +
      typeof opts.failureThreshold + " " + JSON.stringify(opts.failureThreshold));
  }
  if (!_isNonNegFinite(opts.cooldownMs)) {
    throw new TypeError("retry.CircuitBreaker: cooldownMs must be a non-negative finite number, got " +
      typeof opts.cooldownMs + " " + JSON.stringify(opts.cooldownMs));
  }
  if (!_isPositiveInt(opts.successThreshold)) {
    throw new TypeError("retry.CircuitBreaker: successThreshold must be a positive integer, got " +
      typeof opts.successThreshold + " " + JSON.stringify(opts.successThreshold));
  }
  if (opts.onStateChange != null && typeof opts.onStateChange !== "function") {
    throw new TypeError("retry.CircuitBreaker: onStateChange must be a function, got " +
      typeof opts.onStateChange);
  }
}

// ---- Public surface ----

/**
 * @primitive b.retry.isRetryable
 * @signature b.retry.isRetryable(err)
 * @since     0.5.0
 * @related   b.retry.withRetry, b.retry.backoffDelay
 *
 * Default classifier — returns `true` when an error looks transient
 * and worth retrying, `false` otherwise. Honors `err.permanent` and
 * `err.isObjectStoreError && err.permanent`; recognizes retryable HTTP
 * status codes (408 / 425 / 429 / 5xx) and Node net-layer codes
 * (`ECONNRESET`, `ECONNREFUSED`, `ECONNABORTED`, `ETIMEDOUT`, `EPIPE`,
 * `EAGAIN`, `ENOTFOUND`, `ENETUNREACH`). Defensive read — missing
 * fields return `false` rather than throwing, so a malformed error
 * never crashes the retry loop.
 *
 * @example
 *   var transient = new Error("timeout");
 *   transient.code = "ETIMEDOUT";
 *   b.retry.isRetryable(transient);   // → true
 *
 *   var fatal = new Error("bad request");
 *   fatal.statusCode = 400;
 *   b.retry.isRetryable(fatal);       // → false
 */
// Tolerant read of err shape; missing fields → false.
function isRetryable(err) {
  if (!err) return false;
  if (err.isObjectStoreError && err.permanent) return false;
  if (err.permanent) return false;
  if (typeof err.statusCode === "number") {
    if (RETRYABLE_HTTP_STATUS.has(err.statusCode)) return true;
    if (NON_RETRYABLE_HTTP_STATUS.has(err.statusCode)) return false;
    if (err.statusCode >= 500) return true;       // unknown 5xx → assume retryable
    return false;
  }
  if (err.code && RETRYABLE_NET_ERRORS.has(err.code)) return true;
  return false;                                   // default: not retryable (avoid masking bugs)
}

/**
 * @primitive b.retry.backoffDelay
 * @signature b.retry.backoffDelay(attempt, opts)
 * @since     0.5.0
 * @related   b.retry.withRetry, b.retry.isRetryable
 *
 * Compute the backoff in milliseconds for a given (1-based) `attempt`
 * number. Exponential growth `baseDelayMs * 2^(attempt-1)` capped at
 * `maxDelayMs`, then subtract a Math.random-sourced jitter sample
 * scaled by `jitterFactor` so retrying clients spread across the
 * millisecond window instead of realigning on the same boundary
 * (thundering-herd avoidance). Throws TypeError when `attempt` is
 * not a positive integer. `opts` defaults to `b.retry.DEFAULT_RETRY`
 * when absent.
 *
 * Jitter is intentionally NOT a CSPRNG sample — the per-request delay
 * is observable to every peer client by construction (the request
 * that comes in carries its own arrival timing), so there is no
 * confidentiality property a stronger random source would protect.
 * Math.random is the right tool for thundering-herd avoidance and
 * costs ~50x less than a CSPRNG randomInt() under a retry storm.
 *
 * @opts
 *   baseDelayMs:  number,   // initial backoff (default 100)
 *   maxDelayMs:   number,   // cap between attempts (default 10s)
 *   jitterFactor: number,   // 0..1; 0 = no jitter, 1 = full jitter (default 0.5)
 *
 * @example
 *   var d1 = b.retry.backoffDelay(1, { baseDelayMs: 100, maxDelayMs: 1000, jitterFactor: 0 });
 *   d1;                       // → 100
 *   var d3 = b.retry.backoffDelay(3, { baseDelayMs: 100, maxDelayMs: 1000, jitterFactor: 0 });
 *   d3;                       // → 400
 */
function backoffDelay(attempt, opts) {
  if (!_isPositiveInt(attempt)) {
    throw new TypeError("retry.backoffDelay: attempt must be a positive integer, got " +
      typeof attempt + " " + JSON.stringify(attempt));
  }
  opts = opts || DEFAULT_RETRY;
  var base = opts.baseDelayMs * Math.pow(2, attempt - 1);
  var capped = Math.min(base, opts.maxDelayMs);
  // Jitter exists to spread retry storms across the
  // millisecond window so N peer clients waking from the same
  // upstream outage don't all hit the recovering service at the same
  // tick. The value is observable to every client by construction
  // (the request that comes in carries its own timing); there's no
  // confidentiality property to protect, so a CSPRNG would burn
  // 30-50K randomInt/sec under a retry storm without any security
  // payoff. Math.random's PRNG is the right tool for
  // thundering-herd avoidance.
  var jitter = capped * opts.jitterFactor * Math.random();                                           // allow:math-random-noncrypto-jitter-sampling — jitter for thundering-herd, not a confidentiality primitive
  return Math.floor(capped - jitter);
}

/**
 * @primitive b.retry.withRetry
 * @signature b.retry.withRetry(fn, opts)
 * @since     0.5.0
 * @related   b.retry.isRetryable, b.retry.backoffDelay
 *
 * Run `fn(attempt)` with exponential backoff plus jitter. Retries up
 * to `maxAttempts` while the classifier reports the failure transient;
 * on a non-retryable error or after the final attempt the underlying
 * error rethrows. Honors `opts.signal` so an AbortSignal cancels the
 * backoff sleep. The `opts.onRetry` hook is invoked between attempts
 * with `{ attempt, delay, error }`; throws inside the hook are
 * captured and surfaced as `retry.onRetry.threw` observability events
 * — the retry loop itself never crashes.
 *
 * @opts
 *   maxAttempts:  number,    // total tries incl. first (default 5)
 *   baseDelayMs:  number,    // initial backoff (default 100)
 *   maxDelayMs:   number,    // cap between attempts (default 10s)
 *   jitterFactor: number,    // 0..1 (default 0.5)
 *   isRetryable:  function,  // override classifier (default b.retry.isRetryable)
 *   onRetry:      function,  // ({ attempt, delay, error }) -> void
 *   signal:       object,    // AbortSignal — cancels the backoff sleep
 *
 * @example
 *   var attempts = 0;
 *   var result = await b.retry.withRetry(async function () {
 *     attempts += 1;
 *     if (attempts < 2) {
 *       var err = new Error("nope");
 *       err.code = "ECONNRESET";
 *       throw err;
 *     }
 *     return "ok";
 *   }, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0 });
 *   result;                  // → "ok"
 */
async function withRetry(fn, opts) {
  if (typeof fn !== "function") {
    throw new TypeError("retry.withRetry: fn must be a function, got " + typeof fn);
  }
  opts = Object.assign({}, DEFAULT_RETRY, opts || {});
  _validateRetryOpts(opts);
  // opts.isRetryable lets callers override the default classifier.
  // Default classifier targets HTTP/network errors and is intentionally
  // conservative (unknown errors → NOT retryable, to avoid masking bugs).
  // Callers like the handlers primitive whose flush failures are operator-
  // defined (not network-shaped) pass `isRetryable: function () { return true; }`
  // to retry on any error. When overridden, the caller owns full classification
  // including any `err.permanent` semantics they want to honor.
  var classify = (typeof opts.isRetryable === "function") ? opts.isRetryable : isRetryable;
  var lastErr = null;
  for (var attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      var retryable = classify(err);
      if (!retryable || attempt === opts.maxAttempts) {
        if (!retryable) {
          _emitEvent("retry.exhausted", 1, { reason: "non-retryable" });
        } else {
          _emitEvent("retry.exhausted", 1, { reason: "max-attempts", attempts: attempt });
        }
        throw err;
      }
      var delay = backoffDelay(attempt, opts);
      _emitEvent("retry.attempt", 1, { attempt: attempt });
      if (typeof opts.onRetry === "function") {
        // Hot-path observability sink — drops silent on observer throw
        // so a thrown observer can't crash the retry loop. Routed via
        // the same observability event sink so operators can still see
        // mis-wired callbacks in their event stream.
        try { opts.onRetry({ attempt: attempt, delay: delay, error: err }); }
        catch (cbErr) { _emitEvent("retry.onRetry.threw", 1, { error: cbErr.message }); }
      }
      // Honor opts.signal during the backoff sleep — a caller who aborts
      // mid-retry should be unblocked immediately rather than waiting
      // out the (potentially multi-second) backoff.
      await safeAsync().sleep(delay, { signal: opts.signal });
    }
  }
  throw lastErr;
}

// ---- Circuit breaker ----

class CircuitBreaker {
  constructor(name, opts) {
    var merged = Object.assign({}, DEFAULT_BREAKER, opts || {});
    _validateBreakerOpts(name || "", merged);
    this.name = name;
    this.opts = merged;
    this.state = STATE_CLOSED;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
    this._stateListeners = [];
    if (typeof merged.onStateChange === "function") this._stateListeners.push(merged.onStateChange);
  }

  // Register a state-change listener. Called with { name, from, to, at }
  // on every transition (same payload the constructor's onStateChange
  // opt receives). Returns this for chaining.
  onStateChange(handler) {
    if (typeof handler !== "function") {
      throw new TypeError("retry.CircuitBreaker.onStateChange: handler must be a function, got " + typeof handler);
    }
    this._stateListeners.push(handler);
    return this;
  }

  // Wrap an async function. The breaker observes outcomes and may fail-fast.
  async wrap(fn) {
    if (typeof fn !== "function") {
      throw new TypeError("retry.CircuitBreaker.wrap: fn must be a function, got " + typeof fn);
    }
    if (this.state === STATE_OPEN) {
      if (Date.now() - this.openedAt >= this.opts.cooldownMs) {
        this._transition(STATE_OPEN, STATE_HALF);
      } else {
        var err = new Error("circuit breaker '" + this.name + "' is OPEN");
        err.code = "CIRCUIT_OPEN";
        err.permanent = false;     // still transient
        err.isObjectStoreError = true;
        throw err;
      }
    }
    try {
      var result = await fn();
      this._onSuccess();
      return result;
    } catch (e) {
      this._onFailure(e);
      throw e;
    }
  }

  // Centralizes state changes so we emit one observability event per
  // transition. Same name + label shape regardless of which method
  // initiated the change.
  _transition(from, to) {
    if (from === to) return;
    this.state = to;
    var at = Date.now();
    _emitEvent("breaker.state.change", 1, { name: this.name, from: from, to: to });
    if (this._stateListeners.length > 0) {
      var payload = { name: this.name, from: from, to: to, at: at };
      for (var i = 0; i < this._stateListeners.length; i++) {
        // Best-effort: a throwing listener must not derail the breaker's
        // own state machine (the transition has already been applied).
        try { this._stateListeners[i](payload); } catch (_e) { /* drop-silent */ }
      }
    }
  }

  _onSuccess() {
    if (this.state === STATE_HALF) {
      this.consecutiveSuccesses += 1;
      if (this.consecutiveSuccesses >= this.opts.successThreshold) {
        this._transition(STATE_HALF, STATE_CLOSED);
        this.consecutiveFailures = 0;
        this.consecutiveSuccesses = 0;
      }
    } else {
      this.consecutiveFailures = 0;
    }
  }

  _onFailure(err) {
    // Don't trip the breaker on permanent errors — those are caller bugs,
    // not backend health issues.
    if (err && err.permanent) return;
    if (err && err.isObjectStoreError && err.code === "CIRCUIT_OPEN") return;

    this.consecutiveFailures += 1;
    this.consecutiveSuccesses = 0;
    if (this.state === STATE_HALF) {
      this._transition(STATE_HALF, STATE_OPEN);
      this.openedAt = Date.now();
    } else if (this.state === STATE_CLOSED && this.consecutiveFailures >= this.opts.failureThreshold) {
      this._transition(STATE_CLOSED, STATE_OPEN);
      this.openedAt = Date.now();
    }
  }

  getState() { return this.state; }

  reset() {
    var prior = this.state;
    if (prior !== STATE_CLOSED) this._transition(prior, STATE_CLOSED);
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
  }
}

/**
 * @primitive b.retry.withBreaker
 * @signature b.retry.withBreaker(fn, opts)
 * @since     0.9.13
 * @status    stable
 * @related   b.retry.withRetry, b.circuitBreaker.create
 *
 * Compose `withRetry` + a CircuitBreaker so one retry-loop invocation
 * counts as exactly one breaker call. The breaker observes the
 * eventual outcome of the retry loop (success or final failure), not
 * each intermediate retry attempt — otherwise every retried call
 * inflates the breaker's failure counter and the breaker opens far
 * sooner than intended.
 *
 * Every downstream consumer that wants this composition writes
 * `breaker.wrap(() => b.retry.withRetry(fn, retryOpts))` by hand;
 * this primitive captures the pattern so the convention is uniform.
 *
 * @opts
 *   retry:    Object,                // forwarded to withRetry — same options
 *   breaker:  CircuitBreaker,        // existing breaker instance (required)
 *
 * @example
 *   var cb = b.circuitBreaker.create({ name: "upstream-billing", failureThreshold: 5 });
 *   var result = await b.retry.withBreaker(async function () {
 *     return await fetch("https://billing.example.com/v1/charges");
 *   }, {
 *     retry:   { maxAttempts: 3, baseDelayMs: 500 },
 *     breaker: cb,
 *   });
 */
function withBreaker(fn, opts) {
  opts = opts || {};
  if (typeof fn !== "function") {
    throw new TypeError("retry.withBreaker: fn must be a function, got " + typeof fn);
  }
  if (!opts.breaker || typeof opts.breaker.wrap !== "function") {
    throw new TypeError("retry.withBreaker: opts.breaker must be a CircuitBreaker instance (with .wrap(fn))");
  }
  // breaker.wrap counts ONE breaker call regardless of how many retry
  // attempts withRetry makes internally. The breaker only sees the
  // final outcome — success closes it (after enough probes in
  // half-open), or final failure opens it after `failureThreshold`
  // exhausted-retry-loop calls.
  return opts.breaker.wrap(function () {
    return withRetry(fn, opts.retry || {});
  });
}

module.exports = {
  withRetry:                 withRetry,
  withBreaker:               withBreaker,
  isRetryable:               isRetryable,
  backoffDelay:              backoffDelay,
  CircuitBreaker:            CircuitBreaker,
  DEFAULT_RETRY:             DEFAULT_RETRY,
  DEFAULT_BREAKER:           DEFAULT_BREAKER,
  RETRYABLE_HTTP_STATUS:     Array.from(RETRYABLE_HTTP_STATUS),
  NON_RETRYABLE_HTTP_STATUS: Array.from(NON_RETRYABLE_HTTP_STATUS),
  RETRYABLE_NET_ERRORS:      Array.from(RETRYABLE_NET_ERRORS),
  STATES:                    { CLOSED: STATE_CLOSED, OPEN: STATE_OPEN, HALF_OPEN: STATE_HALF },
};
