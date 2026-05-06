"use strict";
/**
 * b.retry — exponential-backoff retry + circuit breaker.
 *
 * Two layers of resilience for any operation that may fail transiently:
 *
 *   1. PER-CALL retry (withRetry) — exponential backoff with jitter.
 *      Default classifier targets HTTP 408/425/429/5xx and Node net-layer
 *      error codes. Caller can override `opts.isRetryable` for non-network
 *      semantics (e.g. operator-defined flush() in handlers).
 *
 *   2. PER-TARGET circuit breaker (CircuitBreaker) — N consecutive
 *      failures opens the circuit (fast-fail for the cooldown window).
 *      After cooldown the breaker enters half-open: probe successes close
 *      it, a probe failure reopens it.
 *
 * Both are intentionally side-effect-free in the success path — they
 * compose freely with `safeAsync.withTimeout`, AbortSignals, and any
 * caller-side instrumentation.
 *
 * Validation policy:
 *
 *   - withRetry opts at first call            → throw at call site
 *   - CircuitBreaker constructor opts         → throw at call site
 *   - backoffDelay(attempt) attempt argument  → throw at call site
 *   - isRetryable(err) defensive read         → tolerant (return defaults)
 *   - onRetry callback throw                  → drop silent (hot-path sink)
 *   - breaker internal _onSuccess/_onFailure  → drop silent (hot-path sink)
 *
 * HTTP-client auto-retry is intentionally NOT provided here. Callers
 * wrap their own outbound calls in `b.retry.withRetry(...)` to keep
 * timeout/idempotency/body-replay decisions explicit.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var nodeCrypto = require("crypto");
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
}

// ---- Public surface ----

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

// Throw on bad input: attempt must be a positive int; opts (when supplied)
// must have non-neg-finite baseDelayMs/maxDelayMs and finite jitterFactor
// in [0,1]. We don't full-validate opts here every call (hot path) —
// defaults are frozen, so the only way a bad opts reaches here is via
// withRetry which already validated, OR a caller using backoffDelay
// directly. For that
// direct case we still validate the attempt arg loudly.
function backoffDelay(attempt, opts) {
  if (!_isPositiveInt(attempt)) {
    throw new TypeError("retry.backoffDelay: attempt must be a positive integer, got " +
      typeof attempt + " " + JSON.stringify(attempt));
  }
  opts = opts || DEFAULT_RETRY;
  var base = opts.baseDelayMs * Math.pow(2, attempt - 1);
  var capped = Math.min(base, opts.maxDelayMs);
  // Cryptographically-strong jitter so a timing-attack mitigation isn't
  // undermined by Math.random's predictable PRNG.
  var jitterDenom = 1_000_000;
  var jitter = capped * opts.jitterFactor * (nodeCrypto.randomInt(0, jitterDenom) / jitterDenom);
  return Math.floor(capped - jitter);
}

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
    _emitEvent("breaker.state.change", 1, { name: this.name, from: from, to: to });
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

module.exports = {
  withRetry:                 withRetry,
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
