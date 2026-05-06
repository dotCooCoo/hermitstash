"use strict";
/**
 * Async handler primitive — buffered emit + resilient drain.
 *
 * The framework has many "fire something off, don't block the request"
 * surfaces: audit emissions from middleware/log-stream/external-db
 * hooks, webhook deliveries, log lines being shipped to an external
 * sink. Without a shared primitive, each surface tends toward a
 * fire-and-forget Promise pattern, which has well-known failure modes:
 *
 *   - Errors disappear silently
 *   - Promises leak across test/shutdown boundaries
 *   - In cyclic dispatchers (storage emits about its own writes), the
 *     pattern is the only thing preventing infinite recursion, but at
 *     the cost of introducing a race
 *   - "Did the work complete?" is unanswerable
 *
 * AsyncHandler replaces the pattern with a uniform contract that bakes
 * resilience in by default — operators don't opt in to robustness; it
 * is the framework's posture and surfaces only what the operator
 * actively configures (DLQ destination, retry policy adjustments, etc).
 *
 * Public API:
 *
 *   handler.emit(item)           sync; buffers; never throws (errors go
 *                                to onError); never returns a Promise
 *   handler.drain(opts?)         async; flushes buffer to storage with
 *                                retry + circuit breaker + DLQ;
 *                                resolves when current backlog is done
 *                                or breaker is open. opts.signal aborts.
 *   handler.shutdown(opts?)      async; final drain with timeout (default
 *                                30s); subsequent emit() drops with
 *                                onError notification
 *   handler.getStats()           snapshot of operational metrics
 *
 * Resilience layers (all on by default):
 *
 *   Retry — batches that fail flush() are retried with exponential
 *           backoff + jitter (safeAsync.asyncRetry). Default 3 attempts.
 *           Transient external-db hiccups recover automatically.
 *
 *   Circuit breaker — if `failureThreshold` consecutive batches fail
 *           after retry exhaustion, the breaker OPENS. Subsequent
 *           emit() calls fast-fail (item goes to DLQ via onError);
 *           drain() returns immediately with a CIRCUIT_OPEN reason.
 *           After `cooldownMs` the breaker enters HALF_OPEN and one
 *           probe batch is allowed; success closes it, failure
 *           re-opens with another cooldown. Bounded recovery.
 *
 *   Dead-letter queue — items that fail every retry land in DLQ via
 *           the operator-supplied `deadLetter(items, error)` callback.
 *           If no DLQ is configured, items go to onError with a
 *           handler/dropped error. The DLQ is fire-and-forget from
 *           the handler's perspective — the operator can write to a
 *           file, an external queue, an audit row, anywhere durable.
 *
 *   Backpressure — buffer capped at `maxBufferSize` (default 10000);
 *           emit() over the cap goes to onError + DLQ. Operators
 *           sizing for high-throughput audit emit larger; default is
 *           sized for "audit emissions piggyback on request handling."
 *
 *   AbortSignal — drain(opts?) accepts opts.signal; aborting cancels
 *           the in-flight drain (current batch finishes; remaining
 *           items stay in buffer for next drain).
 *
 *   Bounded shutdown — shutdown(opts?) drains with a timeout (default
 *           30s). Items that don't flush in time go to DLQ or
 *           onError; the call resolves so process exit isn't blocked.
 *
 * Recursion safety: when a handler is flushing, downstream code MAY
 * emit MORE items into the same handler (e.g. audit.flush writes to
 * external-db, which would normally audit-emit). Those additional
 * items land in the buffer for the NEXT cycle (NOT the current batch),
 * keeping batch sizes bounded. The flush function can mark its own
 * writes with a sentinel (e.g. `{ skipAudit: true }`) so downstream
 * emitters know to skip — caller-controlled, not handler concern.
 *
 * Metrics (handler.getStats()):
 *   bufferSize, totalEmitted, totalFlushed, totalRetried,
 *   totalDeadLettered, lastFlushDurationMs, breakerState.
 *   Operators wire these to their monitoring; the handler does not
 *   ship metrics anywhere on its own.
 */

var safeAsync = require("./safe-async");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var { HandlerError } = require("./framework-error");
var { boot } = require("./log");

var DEFAULTS = {
  maxBatch:           100,
  maxAgeMs:           C.TIME.seconds(1),
  maxBufferSize:      C.BYTES.bytes(10000),
  shutdownTimeoutMs:  C.TIME.seconds(30),
  retry: {
    maxAttempts:    3,
    baseDelayMs:    100,
    maxDelayMs:     C.TIME.seconds(5),
    jitterFactor:   0.5,
  },
  breaker: {
    failureThreshold: 5,
    cooldownMs:       C.TIME.seconds(30),
    successThreshold: 1,
  },
};

var _err = HandlerError.factory;

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "name", "flush",
    "maxBatch", "maxAgeMs", "maxBufferSize", "shutdownTimeoutMs",
    "retry", "breaker",
    "deadLetter", "onError",
  ], "b.handlers");
  if (typeof opts.flush !== "function") {
    throw _err("handlers/invalid", "create requires { flush } async function");
  }

  var name              = opts.name || "anonymous";
  var flush             = opts.flush;
  var maxBatch          = (opts.maxBatch          != null) ? opts.maxBatch          : DEFAULTS.maxBatch;
  var maxAgeMs          = (opts.maxAgeMs          != null) ? opts.maxAgeMs          : DEFAULTS.maxAgeMs;
  var maxBufferSize     = (opts.maxBufferSize     != null) ? opts.maxBufferSize     : DEFAULTS.maxBufferSize;
  var shutdownTimeoutMs = (opts.shutdownTimeoutMs != null) ? opts.shutdownTimeoutMs : DEFAULTS.shutdownTimeoutMs;
  // Handler retry: any thrown error from operator-supplied flush() is
  // retried until exhaustion. The default isRetryable classifier is
  // network-shaped and would skip generic Errors; override to retry-
  // anything since flush failures are caller-defined, not network errors.
  var retryConfig = Object.assign(
    { isRetryable: function () { return true; } },
    DEFAULTS.retry,
    opts.retry || {}
  );
  var breakerConfig     = Object.assign({}, DEFAULTS.breaker, opts.breaker || {});
  var deadLetter        = (typeof opts.deadLetter === "function") ? opts.deadLetter : null;
  var handlerLog = boot("handlers/" + name);
  var onError           = (typeof opts.onError    === "function") ? opts.onError    : function (err) {
    handlerLog.error(err && err.message ? err.message : String(err));
  };

  // Buffer + drain coordination.
  var _buffer = [];
  var _drainPromise = null;
  var _ageTimer = null;
  var _oldestEnqueueAt = null;
  var _shutdown = false;
  var _drainMutex = new safeAsync.Mutex();
  var _breaker = new safeAsync.CircuitBreaker("handler:" + name, breakerConfig);

  // Metrics.
  var _totalEmitted = 0;
  var _totalFlushed = 0;
  var _totalRetried = 0;
  var _totalDeadLettered = 0;
  var _lastFlushDurationMs = 0;

  function _scheduleAgeFlush() {
    if (_ageTimer) return;
    _ageTimer = setTimeout(function () {
      _ageTimer = null;
      drain().catch(function (e) { onError(e, []); });
    }, maxAgeMs);
    if (typeof _ageTimer.unref === "function") _ageTimer.unref();
  }

  function _cancelAgeFlush() {
    if (_ageTimer) { clearTimeout(_ageTimer); _ageTimer = null; }
  }

  function _toDeadLetter(items, err) {
    _totalDeadLettered += items.length;
    if (deadLetter) {
      try { deadLetter(items, err); }
      catch (dlqErr) { onError(_err("handlers/dlq-failed",
        "DLQ callback for handler '" + name + "' threw", dlqErr), items); }
    } else {
      onError(_err("handlers/dropped",
        items.length + " item(s) dropped from handler '" + name + "' after retry exhaustion: " +
        (err && err.message ? err.message : String(err)), err), items);
    }
  }

  function emit(item) {
    if (_shutdown) {
      onError(_err("handlers/shutdown",
        "emit on shut-down handler '" + name + "' — item dropped"), [item]);
      _toDeadLetter([item], _err("handlers/shutdown", "handler is shutting down"));
      return;
    }
    if (_buffer.length >= maxBufferSize) {
      var dropErr = _err("handlers/buffer-full",
        "buffer for handler '" + name + "' exceeded maxBufferSize=" +
        maxBufferSize + " — flush is too slow / failing");
      onError(dropErr, [item]);
      _toDeadLetter([item], dropErr);
      return;
    }
    _totalEmitted += 1;
    _buffer.push(item);
    if (_oldestEnqueueAt === null) _oldestEnqueueAt = Date.now();

    if (_buffer.length >= maxBatch) {
      _cancelAgeFlush();
      drain().catch(function (e) { onError(e, []); });
    } else {
      _scheduleAgeFlush();
    }
  }

  // Drain the buffer with retry + breaker + DLQ. Items emitted DURING
  // a drain land in the buffer for the NEXT drain cycle (NOT the
  // current call) — see the recursion-safety note in this module's
  // header. Without this bound, a handler whose flush() emits MORE
  // items into the same handler (cluster-mode audit: writing an
  // audit row goes through externalDb.query, which emits a
  // system.externaldb.query audit event back into the buffer)
  // produces an unbounded loop where the buffer refills as fast as
  // it drains.
  //
  // Implementation: snapshot _buffer.length at start; process exactly
  // that many items (in batches of maxBatch). Items emitted during
  // the drain accrue at the tail of _buffer and are visible to the
  // next drain() call. Concurrent drain() calls share the in-flight
  // Promise.
  function drain(drainOpts) {
    if (_drainPromise) return _drainPromise;
    drainOpts = drainOpts || {};
    var signal = drainOpts.signal || null;

    _drainPromise = _drainMutex.runExclusive(async function () {
      _cancelAgeFlush();
      var remaining = _buffer.length;
      while (remaining > 0) {
        if (signal && signal.aborted) break;
        var take = Math.min(maxBatch, remaining);
        var batch = _buffer.splice(0, take);
        remaining -= batch.length;
        _oldestEnqueueAt = _buffer.length > 0 ? Date.now() : null;

        var t0 = Date.now();
        try {
          await _breaker.wrap(async function () {
            // Retry the entire batch on transient failures. Each retry
            // re-enters the operator's flush() with the same items; the
            // operator's flush() should be idempotent within a batch
            // (or accept the duplicate-write trade-off).
            //
            // The operator flush() receives an isShutdown() probe in its
            // second arg so it can early-exit between items if the
            // handler was shut down mid-batch (e.g. by a test reset).
            // Without that check, an in-flight flush keeps processing
            // batch[i++] items even after shutdown — and audit's
            // flush in particular writes those into whatever database
            // is currently bound, leaking rows into the next test's db.
            var attempts = 0;
            await safeAsync.asyncRetry(async function () {
              if (attempts > 0) _totalRetried += 1;
              attempts += 1;
              await flush(batch, { isShutdown: function () { return _shutdown; } });
            }, retryConfig);
          });
          _totalFlushed += batch.length;
        } catch (e) {
          // Retry exhausted OR breaker open. Items go to DLQ; loop
          // continues so other batches still attempt — unless the
          // breaker is open, in which case the next iteration's
          // _breaker.wrap will fail-fast immediately.
          _toDeadLetter(batch, e);
          if (e && e.code === "CIRCUIT_OPEN") {
            // Stop the drain; remaining buffered items will be tried
            // again on the next emit() / drain() call.
            break;
          }
        }
        _lastFlushDurationMs = Date.now() - t0;
      }
    }).then(function (v) { _drainPromise = null; return v; },
            function (e) { _drainPromise = null; throw e; });
    return _drainPromise;
  }

  async function shutdown(shutdownOpts) {
    shutdownOpts = shutdownOpts || {};
    var timeoutMs = (shutdownOpts.timeoutMs != null) ? shutdownOpts.timeoutMs : shutdownTimeoutMs;
    _shutdown = true;
    _cancelAgeFlush();
    try {
      await safeAsync.withTimeout(drain(), timeoutMs, { name: "handler:" + name + ".shutdown" });
    } catch (e) {
      // Timeout or breaker fail — DLQ whatever's left, then return.
      var leftover = _buffer.splice(0);
      if (leftover.length > 0) {
        _toDeadLetter(leftover, e);
      }
    }
  }

  // Synchronous "stop and drop" — for test resets and other cases
  // where draining buffered items would write to a stale or changing
  // backing store. Sets the shutdown flag, cancels the age timer, and
  // drops every buffered item to the DLQ. After this returns, no
  // setTimeout from this handler can fire and emit() drops every
  // future item with handlers/shutdown.
  function shutdownSync(reason) {
    _shutdown = true;
    _cancelAgeFlush();
    var dropped = _buffer.splice(0);
    if (dropped.length > 0) {
      _toDeadLetter(
        dropped,
        _err("handlers/shutdown-drop",
          "handler '" + name + "' shut down with " + dropped.length +
          " buffered item(s); items dropped: " + (reason || "no-drain shutdown"))
      );
    }
  }

  function getStats() {
    return {
      bufferSize:            _buffer.length,
      totalEmitted:          _totalEmitted,
      totalFlushed:          _totalFlushed,
      totalRetried:          _totalRetried,
      totalDeadLettered:     _totalDeadLettered,
      lastFlushDurationMs:   _lastFlushDurationMs,
      breakerState:          _breaker.getState ? _breaker.getState() : null,
      isShutdown:            _shutdown,
    };
  }

  function size() { return _buffer.length; }

  return {
    name:         name,
    emit:         emit,
    drain:        drain,
    shutdown:     shutdown,
    shutdownSync: shutdownSync,
    getStats:     getStats,
    size:         size,
  };
}

module.exports = {
  create: create,
};
