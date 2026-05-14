"use strict";
/**
 * @module b.circuitBreaker
 * @nav    Production
 * @title  Circuit Breaker
 *
 * @intro
 *   Top-level circuit-breaker primitive. Re-exports the CircuitBreaker
 *   class otherwise reachable as `b.retry.CircuitBreaker`, plus a
 *   `create(opts)` factory matching every other framework primitive's
 *   `create()` shape. The implementation lives in `lib/retry.js` so the
 *   retry classifier and the breaker share the `isRetryable` /
 *   observability emit conventions; this module is the operator-facing
 *   surface so callers don't have to know retry is the breaker's home.
 *
 *   State machine: `closed` (normal flow; failures count up to
 *   `failureThreshold`), `open` (every call fast-fails for `cooldownMs`),
 *   `half` (first probe closes the breaker on success or re-opens it
 *   on failure). Intended for per-target use — one instance per
 *   upstream service. Sharing a breaker across unrelated targets
 *   defeats the failure-threshold semantic.
 *
 * @card
 *   Top-level circuit-breaker primitive.
 */

var retryHelper = require("./retry");

/**
 * @primitive b.circuitBreaker.create
 * @signature b.circuitBreaker.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.retry, b.httpClient
 *
 * Build a circuit-breaker. Returns a CircuitBreaker instance with
 * `wrap(fn)` (executes `fn` if the breaker is closed; throws an
 * `Error` with `code: "CIRCUIT_OPEN"` + `isObjectStoreError: true` +
 * `permanent: false` when open), `state()`, `reset()`, and
 * `onStateChange(handler)` listener registration. Pass-through
 * factory: identical instance shape to `b.retry.CircuitBreaker`,
 * with the framework's `create(opts)` vocabulary.
 *
 * The `CIRCUIT_OPEN` error code is a pre-v1 artifact — every other
 * framework error class uses namespaced codes (`retry/...`). The
 * rename is deferred to v0.10 with a deprecation cycle so existing
 * operators who match `err.code === "CIRCUIT_OPEN"` aren't broken
 * in a patch.
 *
 * @opts
 *   name:             string,    // identifier used in audit + state-change events
 *   failureThreshold: number,    // failures in the closed state before opening
 *   cooldownMs:       number,    // milliseconds the breaker stays open before probing
 *   successThreshold: number,    // probe successes required to close from half-open
 *   audit:            Object,    // optional b.audit instance for state-change emission
 *   onStateChange:    Function,  // ({ name, from, to, at }) → void
 *
 * @example
 *   var cb = b.circuitBreaker.create({
 *     name:             "upstream-billing",
 *     failureThreshold: 5,
 *     cooldownMs:       30000,
 *     successThreshold: 2,
 *     onStateChange:    function (e) {
 *       // e = { name, from: "closed", to: "open", at: <ms> }
 *     },
 *   });
 *
 *   var result = await cb.wrap(async function () {
 *     return { ok: true, value: 42 };
 *   });
 *   result.value;     // → 42
 */
function create(opts) {
  // The CircuitBreaker class constructor is `(name, opts)` — passing a
  // single opts object lands it in the positional `name` slot, and the
  // validator throws "name must be a non-empty string, got object."
  // The factory's documented shape is `create({ name, ...opts })`;
  // split the name out of opts before invoking the constructor.
  // Caught by hermitstash-sync operator review against v0.9.12.
  opts = opts || {};
  var name = (opts && typeof opts.name === "string") ? opts.name : "";
  return new retryHelper.CircuitBreaker(name, opts);
}

module.exports = {
  create:         create,
  CircuitBreaker: retryHelper.CircuitBreaker,
  // Forward the error class so operators catching breaker rejections
  // can `instanceof` against the framework's RetryError without
  // requiring a separate b.retry import.
  RetryError:     retryHelper.RetryError,
};
