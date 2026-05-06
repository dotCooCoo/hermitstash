"use strict";
/**
 * Generic webhook log sink — HTTP POST one event (or a batch) at a time.
 *
 * Covers most SIEM ingestion endpoints with simple HTTP POST + JSON body:
 *   Splunk HEC                  — { auth: 'header', headers: { Authorization: 'Splunk <token>' } }
 *   Datadog Logs                — { auth: 'header', headers: { 'DD-API-KEY': '<key>' } }
 *   Sumo Logic HTTP source      — no auth (URL is the secret)
 *   Grafana Loki push API       — { auth: 'basic' }
 *   Generic OpenTelemetry HTTP  — { headers: { 'Content-Type': 'application/x-protobuf' } } — caller controls body shape
 *
 * Streaming model: events accumulate in a per-sink queue; a worker drains
 * it in batches (default size 100, max age 5s) to balance throughput
 * against latency. On webhook 5xx / network errors the batch retries with
 * exponential backoff (via the framework's retry module). On permanent 4xx
 * the batch is dropped and an audit event is recorded.
 *
 * Config:
 *   {
 *     url:                    'https://siem.example.com/ingest'
 *     auth:                   'none'|'bearer'|'basic'|'header'
 *     token / username+password / headers
 *     batchSize:              100
 *     maxBatchAgeMs:          C.TIME.seconds(5)
 *     contentType:            'application/json'
 *     bodyShape:              'array' | 'ndjson' | 'singleEnvelope'
 *     timeoutMs:              C.TIME.seconds(30)
 *     retry:                  { maxAttempts, baseDelayMs, ... }
 *     bufferLimit:            10000   // ring-buffer cap; drops oldest on overflow
 *   }
 */
var C = require("./constants");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");
var safeAsync = require("./safe-async");
var safeUrl = require("./safe-url");
var authHeader = require("./auth-header");

// Webhook responses are ack-only (status + small body). 1 MiB cap is
// generous; misbehaving log-aggregator endpoints don't get to OOM us.
var MAX_RESPONSE_BYTES = C.BYTES.mib(1);

var DEFAULTS = {
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  contentType:   "application/json",
  bodyShape:     "array",
  timeoutMs:     C.TIME.seconds(30),
  bufferLimit:   C.BYTES.bytes(10000),
};

var _err = LogStreamError.factory;

// Auth-header construction is delegated to lib/auth-header for the
// none/bearer/basic triple. The "header" mode (pass-through arbitrary
// headers) is handled here — it's not an auth scheme, just header
// merging that's traditionally been bundled in the same config knob.
function _authHeaders(config) {
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  return authHeader.fromConfig(config);
}

function _post(url, body, headers, timeoutMs, allowedProtocols, allowInternal) {
  return httpClient.request({
    method:           "POST",
    url:              url,
    headers:          headers,
    body:             body,
    idleTimeoutMs:    timeoutMs,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    errorClass:       LogStreamError,
    allowedProtocols: allowedProtocols,
    allowInternal:    allowInternal,
  });
}

function _serializeBatch(records, shape) {
  if (shape === "ndjson") {
    return Buffer.from(records.map(function (r) { return JSON.stringify(r); }).join("\n") + "\n", "utf8");
  }
  if (shape === "singleEnvelope") {
    return Buffer.from(JSON.stringify({ events: records }), "utf8");
  }
  // default: array
  return Buffer.from(JSON.stringify(records), "utf8");
}

function create(config) {
  if (!config || !config.url) throw new Error("log-stream webhook requires { url }");
  var cfg = Object.assign({}, DEFAULTS, config);
  // Fail fast on misconfig — validate URL shape + scheme at create time
  // rather than at first emit. Default is HTTPS-only; operators with an
  // internal cleartext aggregator pass cfg.allowedProtocols
  // (safeUrl.ALLOW_HTTP_ALL).
  safeUrl.parse(cfg.url, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var headers = Object.assign({ "Content-Type": cfg.contentType }, _authHeaders(cfg));
  // onDrop callback: invoked when a batch is dropped, either by buffer
  // overflow ("overflow") or by retry exhaustion ("retry-exhausted").
  // Operator wiring this directly (without the framework's dispatcher
  // wrapping) needs visibility into permanent-drop events; the
  // dispatcher path emits its own audit, but a sink used in isolation
  // would otherwise lose drops silently. The callback is invoked
  // best-effort — a throw inside it is swallowed.
  var onDrop = typeof cfg.onDrop === "function" ? cfg.onDrop : null;
  var _emitDrop = safeAsync.makeDropCallback(onDrop);
  var buffer = [];
  var dropCount = 0;
  var inFlight = false;
  var closed = false;
  var flushScheduler = safeAsync.makeScheduledFlush(cfg.maxBatchAgeMs, function () { return _flush(); });

  // Track the in-flight flush as a promise so close() can await it.
  // Without this, a record arriving mid-flush gets buffered, the
  // emit-time _flush() early-returns on `if (inFlight) return`, and
  // the buffered record is stranded if shutdown fires before
  // flushScheduler.schedule() drains it.
  var inFlightPromise = null;
  async function _flush() {
    if (inFlight) return inFlightPromise;
    if (buffer.length === 0) return;
    inFlight = true;
    inFlightPromise = (async function () {
      try {
        while (buffer.length > 0 && !closed) {
          var batch = buffer.splice(0, cfg.batchSize);
          var body = _serializeBatch(batch, cfg.bodyShape);
          try {
            await retryHelper.withRetry(function () {
              return _post(cfg.url, body, headers, cfg.timeoutMs, cfg.allowedProtocols, cfg.allowInternal);
            }, cfg.retry);
          } catch (e) {
            // Batch permanently rejected — surface via dropCount AND the
            // operator-supplied onDrop callback. The dispatcher path
            // wraps its own audit hook around emit(); operators using
            // this sink directly rely on dropCount + onDrop.
            dropCount += batch.length;
            _emitDrop("retry-exhausted", batch, e);
            break;
          }
        }
      } finally {
        inFlight = false;
        inFlightPromise = null;
        if (buffer.length > 0) flushScheduler.schedule();
      }
    })();
    return inFlightPromise;
  }

  function emit(record) {
    if (closed) return Promise.resolve({ accepted: false, reason: "sink closed" });
    if (buffer.length >= cfg.bufferLimit) {
      var dropped = buffer.shift();   // drop oldest
      dropCount += 1;
      _emitDrop("overflow", [dropped], null);
    }
    buffer.push(record);
    if (buffer.length >= cfg.batchSize) {
      // Don't await — non-blocking flush. Caller's emit returns immediately.
      _flush().catch(function () {});
    } else {
      flushScheduler.schedule();
    }
    return Promise.resolve({ accepted: true, queued: buffer.length });
  }

  async function close() {
    // Drain BEFORE flipping closed=true. _flush()'s while loop bails on
    // !closed, so flipping the flag first leaves any buffered records
    // stranded — the very records the operator queued just before
    // calling shutdown(). Order: stop the timer, await any in-flight
    // flush so its records POST before we touch the buffer, drain
    // anything still queued, THEN refuse new enqueues.
    flushScheduler.cancel();
    if (inFlightPromise) {
      try { await inFlightPromise; } catch (_e) { /* surfaced via onDrop */ }
    }
    await _flush();
    closed = true;
  }

  function stats() {
    return { queued: buffer.length, dropped: dropCount, inFlight: inFlight };
  }

  return {
    protocol:  "webhook",
    emit:      emit,
    close:     close,
    stats:     stats,
    flush:     _flush,
  };
}

module.exports = { create: create };
