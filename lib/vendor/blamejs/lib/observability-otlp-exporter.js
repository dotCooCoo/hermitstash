"use strict";
/**
 * b.observability.otlpExporter — OTLP/HTTP JSON span exporter.
 *
 * Buffers spans produced by b.observability.tracer and ships them to
 * an OTLP-compatible HTTP collector. Implements the OpenTelemetry
 * Protocol (OTLP) §3 trace export wire shape over HTTP/JSON
 * (https://opentelemetry.io/docs/specs/otlp/#otlphttp).
 *
 *   var tracer = b.observability.tracer.create({ service: "api" });
 *   var exporter = b.observability.otlpExporter.create({
 *     endpoint:  "https://collector.example.com/v1/traces",
 *     headers:   { "Authorization": "Bearer ..." },
 *     batchSize: 200,
 *     flushIntervalMs: C.TIME.seconds(5),
 *     maxQueueSize: 4096,
 *   });
 *   tracer.start("...", { onEnd: exporter.queue });
 *   ...
 *   await exporter.shutdown();
 *
 * Failure modes:
 *   - HTTP 5xx / network failure → exponential-backoff retry, up to
 *     maxAttempts (default 3); spans dropped after that
 *   - Queue overflow → drops oldest unexported spans, increments the
 *     drop counter
 *   - Endpoint unreachable at boot → exporter is still constructed;
 *     queue retries on every flush tick
 *
 * Wire shape: OTLP/JSON resourceSpans envelope per §3.4.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var safeUrl = require("./safe-url");
var { defineClass } = require("./framework-error");

var OtlpExporterError = defineClass("OtlpExporterError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit         = lazyRequire(function () { return require("./audit"); });
var httpClient    = lazyRequire(function () { return require("./http-client"); });

// Default OTLP transport — uses the framework's own b.httpClient
// (node:https through the PQC-hybrid agent + cert-pinning + SSRF
// guard) rather than globalThis.fetch. Operators with a sidecar
// collector that must be addressed via fetch (Cloudflare Workers,
// Deno, fetch-only edge runtimes) override fetchImpl explicitly.
// Returning a fetch-shaped { ok, status } so the existing _post
// path stays the same regardless of which transport ran.
function _defaultFetchImpl(endpoint, init) {
  var hc = httpClient();
  return hc.request({
    url:           endpoint,
    method:        init && init.method  ? init.method  : "POST",
    headers:       init && init.headers ? init.headers : {},
    body:          init && init.body    ? init.body    : "",
    timeoutMs:     0,
    responseMode:  "always-resolve",
    allowInternal: true,
  }).then(function (res) {
    var status = res && res.statusCode;
    return {
      ok:     status >= 200 && status < 300,                                       // allow:raw-byte-literal — HTTP status ranges
      status: status,
    };
  });
}

var DEFAULT_BATCH_SIZE         = 200;                                              // allow:raw-byte-literal — OTLP recommended batch
var DEFAULT_MAX_QUEUE_SIZE     = 4096;                                             // allow:raw-byte-literal — operator-side queue cap
var DEFAULT_FLUSH_INTERVAL_MS  = C.TIME.seconds(5);
var DEFAULT_MAX_ATTEMPTS       = 3;                                                // allow:raw-byte-literal — retry attempt count
var DEFAULT_BACKOFF_INITIAL_MS = C.TIME.seconds(1);
var DEFAULT_BACKOFF_MAX_MS     = C.TIME.seconds(30);
var DEFAULT_TIMEOUT_MS         = C.TIME.seconds(30);

// OTLP severity numbers per §3.5 (logs); not used for traces but
// retained as a reference for future log-export support.
var STATUS_CODE_TO_OTLP = Object.freeze({
  unset: 0,                                                                        // allow:raw-byte-literal — OTLP STATUS_CODE_UNSET enum
  ok:    1,                                                                        // allow:raw-byte-literal — OTLP STATUS_CODE_OK enum
  error: 2,                                                                        // allow:raw-byte-literal — OTLP STATUS_CODE_ERROR enum
});

var KIND_TO_OTLP = Object.freeze({
  internal: 1,                                                                     // allow:raw-byte-literal — OTLP SPAN_KIND_INTERNAL
  server:   2,                                                                     // allow:raw-byte-literal — OTLP SPAN_KIND_SERVER
  client:   3,                                                                     // allow:raw-byte-literal — OTLP SPAN_KIND_CLIENT
  producer: 4,                                                                     // allow:raw-byte-literal — OTLP SPAN_KIND_PRODUCER
  consumer: 5,                                                                     // allow:raw-byte-literal — OTLP SPAN_KIND_CONSUMER
});

function _attrToOtlp(attrs) {
  // OTLP attribute shape: [{ key, value: { stringValue | intValue |
  // doubleValue | boolValue | arrayValue: { values: [...] } } }, ...]
  var out = [];
  if (!attrs || typeof attrs !== "object") return out;
  var keys = Object.keys(attrs);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = attrs[k];
    out.push({ key: k, value: _valueToOtlp(v) });
  }
  return out;
}

function _valueToOtlp(v) {
  var t = typeof v;
  if (t === "string")  return { stringValue: v };
  if (t === "boolean") return { boolValue: v };
  if (t === "number") {
    if (Number.isInteger(v)) return { intValue: String(v) };
    return { doubleValue: v };
  }
  if (Array.isArray(v)) {
    return {
      arrayValue: {
        values: v.map(function (el) { return _valueToOtlp(el); }),
      },
    };
  }
  return { stringValue: String(v) };
}

function _spanToOtlp(span) {
  return {
    traceId:           span.traceId,
    spanId:            span.spanId,
    parentSpanId:      span.parentSpanId || "",
    name:              span.name,
    kind:              KIND_TO_OTLP[span.kind] || KIND_TO_OTLP.internal,
    startTimeUnixNano: span.startTimeUnixNano,
    endTimeUnixNano:   span.endTimeUnixNano || span.startTimeUnixNano,
    attributes:        _attrToOtlp(span.attributes),
    droppedAttributesCount: span.droppedAttributesCount || 0,
    events: (span.events || []).map(function (e) {
      return {
        name:         e.name,
        timeUnixNano: e.timeUnixNano,
        attributes:   _attrToOtlp(e.attributes),
        droppedAttributesCount: 0,
      };
    }),
    droppedEventsCount: span.droppedEventsCount || 0,
    status: {
      code:    STATUS_CODE_TO_OTLP[span.status && span.status.code] || 0,
      message: (span.status && span.status.message) || "",
    },
  };
}

function _bundleSpans(spans) {
  // Group spans by resource → OTLP resourceSpans envelope. Spans that
  // share the same resource attributes get bundled together.
  if (spans.length === 0) return { resourceSpans: [] };
  var byResource = new Map();
  for (var i = 0; i < spans.length; i++) {
    var s = spans[i];
    var resKey = JSON.stringify(s.resource || {});
    var bucket = byResource.get(resKey);
    if (!bucket) {
      bucket = {
        resource: s.resource || {},
        scope:    s.scope || { name: "blamejs", version: null },
        spans:    [],
      };
      byResource.set(resKey, bucket);
    }
    bucket.spans.push(s);
  }
  var resourceSpans = [];
  for (var entry of byResource) {
    var b = entry[1];
    resourceSpans.push({
      resource: { attributes: _attrToOtlp(b.resource) },
      scopeSpans: [{
        scope:  {
          name:    b.scope.name,
          version: b.scope.version || "",
        },
        spans: b.spans.map(_spanToOtlp),
      }],
    });
  }
  return { resourceSpans: resourceSpans };
}

function create(opts) {
  validateOpts.requireObject(opts, "otlpExporter", OtlpExporterError);
  validateOpts(opts, [
    "endpoint", "headers", "batchSize", "maxQueueSize",
    "flushIntervalMs", "timeoutMs", "maxAttempts",
    "backoffInitialMs", "backoffMaxMs",
    "fetchImpl", "audit", "allowedProtocols",
  ], "otlpExporter.create");
  validateOpts.requireNonEmptyString(opts.endpoint,
    "otlpExporter.create: endpoint", OtlpExporterError, "otlp/bad-endpoint");
  // Validate that endpoint is an http(s) URL via the framework's safe-url.
  // Operators using cleartext (e.g. localhost dev collector) opt in to
  // ALLOW_HTTP_ALL; production deployments leave the default which
  // requires HTTPS for outbound telemetry.
  var allowedProtocols = opts.allowedProtocols || safeUrl.ALLOW_HTTPS_ONLY;
  try { safeUrl.parse(opts.endpoint, { allowedProtocols: allowedProtocols }); }
  catch (e) {
    throw new OtlpExporterError("otlp/bad-endpoint",
      "otlpExporter.create: endpoint must be a valid URL: " + e.message);
  }

  validateOpts.optionalPositiveFinite(opts.batchSize,
    "otlpExporter.create: batchSize", OtlpExporterError, "otlp/bad-opts");
  validateOpts.optionalPositiveFinite(opts.maxQueueSize,
    "otlpExporter.create: maxQueueSize", OtlpExporterError, "otlp/bad-opts");
  if (opts.flushIntervalMs !== undefined && opts.flushIntervalMs !== 0) {
    validateOpts.optionalPositiveFinite(opts.flushIntervalMs,
      "otlpExporter.create: flushIntervalMs", OtlpExporterError, "otlp/bad-opts");
  }
  validateOpts.optionalPositiveFinite(opts.timeoutMs,
    "otlpExporter.create: timeoutMs", OtlpExporterError, "otlp/bad-opts");
  validateOpts.optionalPositiveFinite(opts.maxAttempts,
    "otlpExporter.create: maxAttempts", OtlpExporterError, "otlp/bad-opts");

  var endpoint   = opts.endpoint;
  var headers    = Object.assign({
    "Content-Type": "application/json",
  }, opts.headers || {});
  var batchSize  = opts.batchSize     || DEFAULT_BATCH_SIZE;
  var maxQueue   = opts.maxQueueSize  || DEFAULT_MAX_QUEUE_SIZE;
  var flushIntervalMs = opts.flushIntervalMs || DEFAULT_FLUSH_INTERVAL_MS;
  var timeoutMs  = opts.timeoutMs     || DEFAULT_TIMEOUT_MS;
  var maxAttempts = opts.maxAttempts || DEFAULT_MAX_ATTEMPTS;
  var backoffInitial = opts.backoffInitialMs || DEFAULT_BACKOFF_INITIAL_MS;
  var backoffMax     = opts.backoffMaxMs     || DEFAULT_BACKOFF_MAX_MS;
  // Default transport is the framework's b.httpClient (node:https +
  // PQC-hybrid agent + SSRF guard). globalThis.fetch was the prior
  // default; it leaked an outbound network surface that supply-chain
  // scanners flagged because nothing in the framework's TLS posture
  // wired through it. Operators on fetch-only runtimes still override
  // by passing opts.fetchImpl.
  var fetchImpl  = opts.fetchImpl || _defaultFetchImpl;
  if (typeof fetchImpl !== "function") {
    throw new OtlpExporterError("otlp/no-fetch",
      "otlpExporter.create: opts.fetchImpl must be a function (override the framework default)");
  }

  var queue = [];
  var droppedQueueOverflow = 0;
  var droppedExportFailed  = 0;
  var inFlight = false;
  var stopping = false;

  var auditOn = opts.audit !== false;
  function _emitMetric(verb, n, labels) {
    try { observability().safeEvent("otlp.exporter." + verb, n || 1, labels || {}); }
    catch (_e) { /* drop-silent */ }
  }
  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "system.observability.otlp_exporter." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit is best-effort, never crashes the exporter */ }
  }

  function queue_(span) {
    if (stopping) { droppedExportFailed += 1; return; }
    if (!span || typeof span !== "object") return;
    if (queue.length >= maxQueue) {
      // Drop oldest, append newest — keeps the most-recent telemetry.
      queue.shift();
      droppedQueueOverflow += 1;
      _emitMetric("queue_overflow", 1, {});
    }
    queue.push(span);
    if (queue.length >= batchSize) {
      // Best-effort flush; don't block the caller.
      flush().catch(function () { /* drop-silent */ });
    }
  }

  function _backoffMs(attempt) {
    var ms = backoffInitial * Math.pow(2, Math.max(0, attempt - 1));               // allow:raw-byte-literal — exponential factor
    return Math.min(ms, backoffMax);
  }

  function _sleep(ms) {
    return safeAsync.sleep(ms);
  }

  async function _post(payload, attempt) {
    attempt = attempt || 1;
    var ac = (typeof AbortController === "function") ? new AbortController() : null;
    var t = ac ? setTimeout(function () { ac.abort(); }, timeoutMs) : null;
    try {
      var res = await fetchImpl(endpoint, {
        method:  "POST",
        headers: headers,
        body:    JSON.stringify(payload),
        signal:  ac ? ac.signal : undefined,
      });
      if (res && res.ok) return { ok: true, status: res.status };
      var status = res && res.status;
      // 5xx + 408/429 → retryable; everything else permanent
      var retryable = (status >= 500 && status < 600) || status === 408 || status === 429;  // allow:raw-byte-literal — HTTP status ranges
      if (retryable && attempt < maxAttempts) {
        await _sleep(_backoffMs(attempt));
        return await _post(payload, attempt + 1);
      }
      return { ok: false, status: status, retryable: retryable };
    } catch (e) {
      // Network error / abort. AbortController abort surfaces with
      // name=AbortError; tag the audit so operators can distinguish
      // a genuine network drop from "we timed out reaching the
      // collector". Both are retryable but the audit metadata helps
      // root-cause when collector latency is the issue.
      var abortReason = e && (e.name === "AbortError" || /aborted|timeout/i.test(e.message || ""));
      _emitAudit("post_failed", "failure", {
        attempt:    attempt,
        retryable:  attempt < maxAttempts,
        reason:     abortReason ? "timeout" : "network",
        error:      (e && e.message) || String(e),
      });
      if (abortReason) _emitMetric("export_timeout", 1, { attempt: String(attempt) });
      if (attempt < maxAttempts) {
        await _sleep(_backoffMs(attempt));
        return await _post(payload, attempt + 1);
      }
      return { ok: false, error: (e && e.message) || String(e), retryable: true };
    } finally {
      if (t) clearTimeout(t);
    }
  }

  async function flush() {
    if (inFlight) return { sent: 0, skipped: true };
    if (queue.length === 0) return { sent: 0 };
    inFlight = true;
    try {
      var batch = queue.splice(0, batchSize);
      var payload = _bundleSpans(batch);
      var result = await _post(payload, 1);
      if (result.ok) {
        _emitMetric("export_ok", batch.length, { http_status: String(result.status) });
        return { sent: batch.length };
      }
      droppedExportFailed += batch.length;
      _emitMetric("export_failed", batch.length, {
        http_status: String(result.status || "network"),
      });
      return { sent: 0, dropped: batch.length };
    } finally {
      inFlight = false;
    }
  }

  // Periodic flush worker
  var ticker = null;
  if (flushIntervalMs > 0) {
    ticker = safeAsync.repeating(function () {
      flush().catch(function () { /* drop-silent */ });
    }, flushIntervalMs, { name: "otlp-exporter-flush" });
  }

  async function shutdown() {
    stopping = true;
    if (ticker) { ticker.stop(); ticker = null; }
    // Drain remaining spans, best-effort
    while (queue.length > 0) {
      var r = await flush();
      if (!r || r.sent === 0) break;
    }
  }

  function stats() {
    var totalDropped = droppedQueueOverflow + droppedExportFailed;
    // Operator-facing dropped-count metric — fires every stats() call
    // so dashboards / probes that scrape stats can chart the running
    // total even when individual drop sites already emit per-event
    // metrics. The metric is monotonic for the lifetime of the
    // exporter; a process restart resets it (intended).
    _emitMetric("dropped_total", 0, {
      queue_overflow: String(droppedQueueOverflow),
      export_failed:  String(droppedExportFailed),
      total:          String(totalDropped),
    });
    return {
      queueLength:           queue.length,
      droppedQueueOverflow:  droppedQueueOverflow,
      droppedExportFailed:   droppedExportFailed,
      droppedTotal:          totalDropped,
    };
  }

  return {
    queue:    queue_,
    flush:    flush,
    shutdown: shutdown,
    stats:    stats,
    // Internal hook for tests
    _bundleForTest: _bundleSpans,
  };
}

module.exports = {
  create:                  create,
  STATUS_CODE_TO_OTLP:     STATUS_CODE_TO_OTLP,
  KIND_TO_OTLP:            KIND_TO_OTLP,
  OtlpExporterError:       OtlpExporterError,
  // Exported for tests
  _spanToOtlp:             _spanToOtlp,
  _bundleSpans:            _bundleSpans,
  _attrToOtlp:             _attrToOtlp,
  _BASE64URL_RE_REF:       safeBuffer.BASE64URL_RE,                                // not used; reserved for OTLP/protobuf shape upgrade
};
