// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var pb = require("./protobuf-encoder");
var boundedMap = require("./bounded-map");
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
      ok:     status >= 200 && status < 300,                                       // HTTP status ranges
      status: status,
    };
  });
}

var DEFAULT_BATCH_SIZE         = 200;                                              // OTLP recommended batch
var DEFAULT_MAX_QUEUE_SIZE     = 4096;                                             // operator-side queue cap
var DEFAULT_FLUSH_INTERVAL_MS  = C.TIME.seconds(5);
var DEFAULT_MAX_ATTEMPTS       = 3;                                                // retry attempt count
var DEFAULT_BACKOFF_INITIAL_MS = C.TIME.seconds(1);
var DEFAULT_BACKOFF_MAX_MS     = C.TIME.seconds(30);
var DEFAULT_TIMEOUT_MS         = C.TIME.seconds(30);

// OTLP severity numbers per §3.5 (logs); not used for traces but
// retained as a reference for future log-export support.
var STATUS_CODE_TO_OTLP = Object.freeze({
  unset: 0,                                                                        // OTLP STATUS_CODE_UNSET enum
  ok:    1,                                                                        // OTLP STATUS_CODE_OK enum
  error: 2,                                                                        // OTLP STATUS_CODE_ERROR enum
});

var KIND_TO_OTLP = Object.freeze({
  internal: 1,                                                                     // OTLP SPAN_KIND_INTERNAL
  server:   2,                                                                     // OTLP SPAN_KIND_SERVER
  client:   3,                                                                     // OTLP SPAN_KIND_CLIENT
  producer: 4,                                                                     // OTLP SPAN_KIND_PRODUCER
  consumer: 5,                                                                     // OTLP SPAN_KIND_CONSUMER
});

function _attrToOtlp(attrs) {
  // OTLP attribute shape: [{ key, value: { stringValue | intValue |
  // doubleValue | boolValue | arrayValue: { values: [...] } } }, ...]
  // Telemetry is a first-class EGRESS sink — scrub every value through the
  // active redactor BEFORE serialization so a secret/PII attribute never
  // reaches the collector (CWE-532). Redaction is baked into the encoder, not
  // the call site, so no span/event/resource path can forget it.
  attrs = observability().redactAttrs(attrs);
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

// Run a single wire STRING (span name / status message) through the telemetry
// redactor. These reach the collector exactly like attribute values, so a
// connection string / token / PII in an error message (the tracer's canonical
// `setStatus("error", e.message)`) must be scrubbed too (CWE-532). Routes
// through redactAttrs (the same chokepoint attributes use); fails toward an
// empty string on a redactor throw, matching redactAttrs' drop-on-error.
function _redactWireString(key, value) {
  if (typeof value !== "string" || value.length === 0) return value || "";
  try {
    var holder = {};
    holder[key] = value;
    return observability().redactAttrs(holder)[key];
  } catch (_e) { return ""; }
}

function _spanToOtlp(span) {
  return {
    traceId:           span.traceId,
    spanId:            span.spanId,
    parentSpanId:      span.parentSpanId || "",
    name:              _redactWireString("otel.span.name", span.name),
    kind:              KIND_TO_OTLP[span.kind] || KIND_TO_OTLP.internal,
    startTimeUnixNano: span.startTimeUnixNano,
    endTimeUnixNano:   span.endTimeUnixNano || span.startTimeUnixNano,
    attributes:        _attrToOtlp(span.attributes),
    droppedAttributesCount: span.droppedAttributesCount || 0,
    events: (span.events || []).map(function (e) {
      return {
        name:         _redactWireString("otel.event.name", e.name),
        timeUnixNano: e.timeUnixNano,
        attributes:   _attrToOtlp(e.attributes),
        droppedAttributesCount: 0,
      };
    }),
    droppedEventsCount: span.droppedEventsCount || 0,
    status: {
      code:    STATUS_CODE_TO_OTLP[span.status && span.status.code] || 0,
      message: _redactWireString("exception.message", (span.status && span.status.message) || ""),
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
    var bucket = boundedMap.getOrInsert(byResource, resKey, function () {
      return {
        resource: s.resource || {},
        scope:    s.scope || { name: "blamejs", version: null },
        spans:    [],
      };
    });
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

// ---- OTLP/protobuf encoder ------------------------------------------------
//
// OTLP §3 — `application/x-protobuf` body shape per the
// opentelemetry-proto repo's ExportTraceServiceRequest message.
//
// Wire-format encoding composes b.protobufEncoder. Fields are:
//
//   ExportTraceServiceRequest {
//     repeated ResourceSpans resource_spans = 1;
//   }
//   ResourceSpans {
//     Resource resource     = 1;
//     repeated ScopeSpans scope_spans = 2;
//     string schema_url     = 3;
//   }
//   Resource {
//     repeated KeyValue attributes        = 1;
//     uint32 dropped_attributes_count    = 2;
//   }
//   ScopeSpans {
//     InstrumentationScope scope = 1;
//     repeated Span spans        = 2;
//     string schema_url          = 3;
//   }
//   InstrumentationScope { string name = 1; string version = 2; ... }
//   Span {
//     bytes trace_id              = 1;  // 16 bytes
//     bytes span_id               = 2;  //  8 bytes
//     string trace_state          = 3;
//     bytes parent_span_id        = 4;  //  8 bytes or empty
//     string name                 = 5;
//     SpanKind kind               = 6;  // enum 0..5
//     fixed64 start_time_unix_nano = 7;
//     fixed64 end_time_unix_nano   = 8;
//     repeated KeyValue attributes = 9;
//     uint32 dropped_attributes_count = 10;
//     repeated Event events           = 11;
//     uint32 dropped_events_count     = 12;
//     repeated Link links             = 13;
//     uint32 dropped_links_count      = 14;
//     Status status                   = 15;
//   }
//   Event { fixed64 time_unix_nano = 1; string name = 2; repeated KeyValue attributes = 3; uint32 dropped_attributes_count = 4; }
//   Status { string message = 2; enum code = 3; }  // field 1 reserved
//   KeyValue { string key = 1; AnyValue value = 2; }
//   AnyValue {
//     oneof value {
//       string string_value = 1;
//       bool   bool_value   = 2;
//       int64  int_value    = 3;
//       double double_value = 4;
//       ArrayValue array_value = 5;
//     }
//   }
//   ArrayValue { repeated AnyValue values = 1; }
//
// AnyValue recursion is capped at MAX_ANYVALUE_DEPTH to defend the
// CVE-2024-7254 + CVE-2025-4565 protobuf nested-group DoS class.

var MAX_ANYVALUE_DEPTH = 100;                                                    // protobuf nested-message DoS cap

function _hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length === 0) return Buffer.alloc(0);
  // Tolerate odd-length hex by left-padding with zero; OTLP spec
  // requires fixed lengths but the exporter should not crash a request
  // with a malformed inbound trace_id — drop-silent and emit empty.
  if (hex.length % 2 !== 0) return Buffer.alloc(0);
  var out = Buffer.alloc(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) {
    var byte = parseInt(hex.substr(i, 2), 16);                                  // radix=16 for hex parse, not byte count
    if (!isFinite(byte)) return Buffer.alloc(0);
    out[i / 2] = byte;
  }
  return out;
}

var KIND_TEXT_TO_ENUM = {
  unspecified: 0, internal: 1, server: 2, client: 3, producer: 4, consumer: 5,
};

function _anyValueToProto(v, depth) {
  if (depth >= MAX_ANYVALUE_DEPTH) {
    // Refuse to descend further; emit empty AnyValue. Matches the spec's
    // "unknown wire type" tolerant-parser behaviour on the receive side.
    return Buffer.alloc(0);
  }
  var t = typeof v;
  if (t === "string")  return pb.string(1, v);
  if (t === "boolean") return pb.bool(2, v);
  if (t === "number") {
    if (Number.isInteger(v)) {
      // OTLP AnyValue field 3 is proto int64 — wire-type 0 varint, NOT
      // length-delimited. Negatives encode as the 64-bit two's-complement
      // reinterpret-cast (10-byte varint per the spec). Composes
      // `pb.int64` which carries the BigInt conversion + range check so
      // a negative attribute value (e.g. retry-after offset, signed
      // metric delta) doesn't poison the whole batch.
      return pb.int64(3, v);
    }
    return pb.double(4, v);
  }
  if (Array.isArray(v)) {
    var items = new Array(v.length);
    for (var i = 0; i < v.length; i += 1) {
      items[i] = _anyValueToProto(v[i], depth + 1);
    }
    var arrayInner = pb.repeatedMessage(1, items, function (b) { return b; });
    return pb.embeddedMessage(5, arrayInner);
  }
  // Unknown → coerce to string per the JSON path's behaviour.
  return pb.string(1, String(v));
}

function _keyValueToProto(kvObj) {
  // kvObj is { key, value: <plain-js> } from _attrToOtlp — but we
  // re-derive directly here so the protobuf path doesn't depend on
  // the JSON-shaped intermediate.
  return Buffer.concat([
    pb.string(1, kvObj.key),
    pb.embeddedMessage(2, _anyValueToProto(kvObj.rawValue, 0)),
  ]);
}

function _attrsToProto(attrs) {
  // attrs is the raw `{ key: value }` operator attribute object; OTLP
  // KeyValue gets emitted per entry with field 9 (attributes) on Span,
  // field 1 (attributes) on Resource, etc. Scrub every value through the
  // active redactor BEFORE building the wire intermediate — the protobuf path
  // is the same EGRESS sink as the JSON path and must not leak (CWE-532).
  attrs = observability().redactAttrs(attrs);
  if (!attrs || typeof attrs !== "object") return [];
  var keys = Object.keys(attrs);
  var out = new Array(keys.length);
  for (var i = 0; i < keys.length; i += 1) {
    out[i] = { key: keys[i], rawValue: attrs[keys[i]] };
  }
  return out;
}

function _spanToProto(span) {
  // Status code: 0=Unset, 1=Ok, 2=Error. Status field 1 is reserved.
  var statusBody = Buffer.concat([
    pb.string(2, _redactWireString("exception.message", (span.status && span.status.message) || "")),
    pb.uint32(3, STATUS_CODE_TO_OTLP[span.status && span.status.code] || 0),
  ]);
  var eventsRepeated = pb.repeatedMessage(11, span.events || [], function (e) {
    return Buffer.concat([
      pb.fixed64(1, e.timeUnixNano || 0),
      pb.string(2, _redactWireString("otel.event.name", e.name || "")),
      pb.repeatedMessage(3, _attrsToProto(e.attributes), _keyValueToProto),
      pb.uint32(4, 0),
    ]);
  });
  return Buffer.concat([
    pb.bytes(1,   _hexToBytes(span.traceId)),
    pb.bytes(2,   _hexToBytes(span.spanId)),
    pb.string(3,  ""),                                                          // trace_state (not yet propagated by the framework)
    pb.bytes(4,   _hexToBytes(span.parentSpanId || "")),
    pb.string(5,  _redactWireString("otel.span.name", span.name || "")),
    pb.uint32(6,  KIND_TEXT_TO_ENUM[span.kind] != null ? KIND_TEXT_TO_ENUM[span.kind] : KIND_TEXT_TO_ENUM.internal),
    pb.fixed64(7, span.startTimeUnixNano || 0),
    pb.fixed64(8, span.endTimeUnixNano || span.startTimeUnixNano || 0),         // proto field number 8, not bytes
    pb.repeatedMessage(9, _attrsToProto(span.attributes), _keyValueToProto),
    pb.uint32(10, span.droppedAttributesCount || 0),
    eventsRepeated,
    pb.uint32(12, span.droppedEventsCount || 0),
    pb.uint32(14, 0),                                                           // dropped_links_count (proto field 14); no links propagated yet
    Buffer.concat([
      pb._tag(15, 2),                                                           // WIRE_LDELIM tag for status
      pb._writeVarint(statusBody.length),
      statusBody,
    ]),
  ]);
}

// `bundle` is the value returned by _bundleSpans — { resourceSpans: [...] }
// where each entry has { resource, scopeSpans: [{ scope, spans: [...] }] }
// in the JSON-shape. We re-derive the proto bytes from the SAME pre-OTLP
// span list so the protobuf path doesn't double-transform the data.
function _bundleSpansToProto(spansArray) {
  if (spansArray.length === 0) return Buffer.alloc(0);
  var byResource = new Map();
  for (var i = 0; i < spansArray.length; i += 1) {
    var s = spansArray[i];
    var resKey = JSON.stringify(s.resource || {});
    var bucket = boundedMap.getOrInsert(byResource, resKey, function () {
      return {
        resource: s.resource || {},
        scope:    s.scope || { name: "blamejs", version: null },
        spans:    [],
      };
    });
    bucket.spans.push(s);
  }
  var resourceSpansPieces = [];
  for (var entry of byResource) {
    var b = entry[1];
    var resourceBody = pb.repeatedMessage(1, _attrsToProto(b.resource), _keyValueToProto);
    var scopeBody = Buffer.concat([
      pb.string(1, b.scope.name || "blamejs"),
      pb.string(2, b.scope.version || ""),
    ]);
    var spansRepeated = pb.repeatedMessage(2, b.spans, _spanToProto);
    var scopeSpansBody = Buffer.concat([
      pb.embeddedMessage(1, scopeBody),
      spansRepeated,
    ]);
    var resourceSpansBody = Buffer.concat([
      pb.embeddedMessage(1, resourceBody),
      pb.embeddedMessage(2, scopeSpansBody),
    ]);
    resourceSpansPieces.push(pb.embeddedMessage(1, resourceSpansBody));
  }
  return Buffer.concat(resourceSpansPieces);
}

function create(opts) {
  validateOpts.requireObject(opts, "otlpExporter", OtlpExporterError);
  validateOpts(opts, [
    "endpoint", "headers", "batchSize", "maxQueueSize",
    "flushIntervalMs", "timeoutMs", "maxAttempts",
    "backoffInitialMs", "backoffMaxMs",
    "fetchImpl", "audit", "allowedProtocols",
    "encoding",
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
  // OTLP §3 — operators with high-volume traces opt into the binary
  // `application/x-protobuf` encoding via `opts.encoding: "protobuf"`
  // (composes lib/protobuf-encoder.js for the wire-level emission).
  // Default stays `"json"` for backward compatibility with existing
  // collectors. The third encoding option (`"http/protobuf"` per the
  // OTLP spec wording) is an alias for "protobuf".
  var encoding = opts.encoding || "json";
  if (encoding === "http/protobuf") encoding = "protobuf";
  if (encoding !== "json" && encoding !== "protobuf") {
    throw new OtlpExporterError("otlp/bad-encoding",
      "otlpExporter.create: opts.encoding must be \"json\" or \"protobuf\" (got " +
      JSON.stringify(opts.encoding) + ")");
  }
  var contentType = encoding === "protobuf"
    ? "application/x-protobuf"
    : "application/json";
  var headers    = Object.assign({
    "Content-Type": contentType,
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

  var _emitMetric = observability().namespaced("otlp.exporter");
  var _emitAudit = audit().namespaced("system.observability.otlp_exporter", opts.audit);

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
    var ms = backoffInitial * Math.pow(2, Math.max(0, attempt - 1));               // exponential factor
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
      // The flush() path now passes EITHER a JSON-shape object (encoding
      // "json") OR an already-encoded Buffer (encoding "protobuf").
      // Stringify only the JSON path; pass the Buffer through.
      var body = Buffer.isBuffer(payload) ? payload : JSON.stringify(payload);
      var res = await fetchImpl(endpoint, {
        method:  "POST",
        headers: headers,
        body:    body,
        signal:  ac ? ac.signal : undefined,
      });
      if (res && res.ok) return { ok: true, status: res.status };
      var status = res && res.status;
      // 5xx + 408/429 → retryable; everything else permanent
      var retryable = (status >= 500 && status < 600) || status === 408 || status === 429;  // HTTP status ranges
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
      // OTLP §3 — JSON encoding emits the resourceSpans envelope as
      // JSON; protobuf encoding emits the same shape as binary
      // ExportTraceServiceRequest bytes.
      var payload = encoding === "protobuf"
        ? _bundleSpansToProto(batch)
        : _bundleSpans(batch);
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
  _spanToProto:            _spanToProto,
  _bundleSpans:            _bundleSpans,
  _attrToOtlp:             _attrToOtlp,
  _BASE64URL_RE_REF:       safeBuffer.BASE64URL_RE,                                // not used; reserved for OTLP/protobuf shape upgrade
};
