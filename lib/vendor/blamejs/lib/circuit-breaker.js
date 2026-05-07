"use strict";
/**
 * b.circuitBreaker — top-level circuit-breaker primitive.
 *
 * Re-exports the CircuitBreaker class previously only reachable as
 * b.retry.CircuitBreaker, plus a `create(opts)` factory that matches
 * every other framework primitive's `create()` shape. The
 * implementation lives in lib/retry.js to keep the retry-classifier
 * + CircuitBreaker close to each other (they share the
 * isRetryable / observability emit conventions). This module is the
 * top-level surface so operators don't have to know that retry
 * happens to be the home of the circuit-breaker class.
 *
 * State machine:
 *   closed   — normal flow; failures count up to failureThreshold
 *   open     — fast-fail every call for cooldownMs
 *   half     — first probe succeeds → close; first probe fails → re-open
 *
 *   var cb = b.circuitBreaker.create({
 *     name:                 "upstream-billing",
 *     failureThreshold:     5,
 *     cooldownMs:           b.constants.TIME.seconds(30),
 *     successThreshold:     2,
 *     audit:                b.audit,
 *     onStateChange:        function (event) {
 *       // event = { name, from, to, at }
 *       log("breaker " + event.name + " " + event.from + " -> " + event.to);
 *     },
 *   });
 *   await cb.wrap(function () { return upstream.callRiskyOp(); });
 *
 * The circuit-breaker is intended for per-target use (one instance
 * per upstream service); operators sharing a breaker across
 * unrelated targets defeat the failure-threshold semantic.
 */

var retry = require("./retry");

// Pass-through factory — operators get the same instance shape as
// b.retry.CircuitBreaker but with the framework's `create(opts)`
// vocabulary. The breaker class is unchanged; this is a thin
// surface re-export so b.circuitBreaker is operator-discoverable
// alongside b.retry.
function create(opts) {
  return new retry.CircuitBreaker(opts || {});
}

module.exports = {
  create:         create,
  CircuitBreaker: retry.CircuitBreaker,
  // Forward the error class so operators catching breaker rejections
  // can `instanceof` against the framework's RetryError without
  // requiring a separate b.retry import.
  RetryError:     retry.RetryError,
};
