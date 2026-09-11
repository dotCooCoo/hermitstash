// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

  var _buffer = [];
  var _drainPromise = null;
  var _ageTimer = null;
  var _oldestEnqueueAt = null;
  var _shutdown = false;
  var _drainMutex = new safeAsync.Mutex();
  var _breaker = new safeAsync.CircuitBreaker("handler:" + name, breakerConfig);

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
            var attempts = 0;
            await safeAsync.asyncRetry(async function () {
              if (attempts > 0) _totalRetried += 1;
              attempts += 1;
              await flush(batch, { isShutdown: function () { return _shutdown; } });
            }, retryConfig);
          });
          _totalFlushed += batch.length;
        } catch (e) {
          _toDeadLetter(batch, e);
          if (e && e.code === "CIRCUIT_OPEN") {
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
      var leftover = _buffer.splice(0);
      if (leftover.length > 0) {
        _toDeadLetter(leftover, e);
      }
    }
  }

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
