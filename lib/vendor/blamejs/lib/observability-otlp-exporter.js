// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var safeUrl = require("./safe-url");
var pb = require("./protobuf-encoder");
var boundedMap = require("./bounded-map");
var { defineClass } = require("./framework-error");

var OtlpExporterError = defineClass("OtlpExporterError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var audit         = lazyRequire(function () { return require("./audit"); });
var httpClient    = lazyRequire(function () { return require("./http-client"); });

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
      ok:     typeof status === "number" && C.HTTP.success(status),
      status: status,
    };
  });
}

var DEFAULT_BATCH_SIZE         = 200;
var DEFAULT_MAX_QUEUE_SIZE     = 4096;
var DEFAULT_FLUSH_INTERVAL_MS  = C.TIME.seconds(5);
var DEFAULT_MAX_ATTEMPTS       = 3;
var DEFAULT_BACKOFF_INITIAL_MS = C.TIME.seconds(1);
var DEFAULT_BACKOFF_MAX_MS     = C.TIME.seconds(30);
var DEFAULT_TIMEOUT_MS         = C.TIME.seconds(30);

var STATUS_CODE_TO_OTLP = Object.freeze({
  unset: 0,
  ok:    1,
  error: 2,
});

var KIND_TO_OTLP = Object.freeze({
  internal: 1,
  server:   2,
  client:   3,
  producer: 4,
  consumer: 5,
});

function _attrToOtlp(attrs) {
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

var MAX_ANYVALUE_DEPTH = 100;

function _hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length === 0) return Buffer.alloc(0);
  // with a malformed inbound trace_id — drop-silent and emit empty.
  if (hex.length % 2 !== 0) return Buffer.alloc(0);
  var out = Buffer.alloc(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) {
    var byte = parseInt(hex.substr(i, 2), 16);
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
    return Buffer.alloc(0);
  }
  var t = typeof v;
  if (t === "string")  return pb.string(1, v);
  if (t === "boolean") return pb.bool(2, v);
  if (t === "number") {
    if (Number.isInteger(v)) {
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
  return pb.string(1, String(v));
}

function _keyValueToProto(kvObj) {
  return Buffer.concat([
    pb.string(1, kvObj.key),
    pb.embeddedMessage(2, _anyValueToProto(kvObj.rawValue, 0)),
  ]);
}

function _attrsToProto(attrs) {
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
    pb.string(3,  ""),
    pb.bytes(4,   _hexToBytes(span.parentSpanId || "")),
    pb.string(5,  _redactWireString("otel.span.name", span.name || "")),
    pb.uint32(6,  KIND_TEXT_TO_ENUM[span.kind] != null ? KIND_TEXT_TO_ENUM[span.kind] : KIND_TEXT_TO_ENUM.internal),
    pb.fixed64(7, span.startTimeUnixNano || 0),
    pb.fixed64(8, span.endTimeUnixNano || span.startTimeUnixNano || 0),
    pb.repeatedMessage(9, _attrsToProto(span.attributes), _keyValueToProto),
    pb.uint32(10, span.droppedAttributesCount || 0),
    eventsRepeated,
    pb.uint32(12, span.droppedEventsCount || 0),
    pb.uint32(14, 0),
    Buffer.concat([
      pb._tag(15, 2),
      pb._writeVarint(statusBody.length),
      statusBody,
    ]),
  ]);
}

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
      queue.shift();
      droppedQueueOverflow += 1;
      _emitMetric("queue_overflow", 1, {});
    }
    queue.push(span);
    if (queue.length >= batchSize) {
      flush().catch(function () { /* drop-silent */ });
    }
  }

  function _backoffMs(attempt) {
    var ms = backoffInitial * Math.pow(2, Math.max(0, attempt - 1));
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
      var body = Buffer.isBuffer(payload) ? payload : JSON.stringify(payload);
      var res = await fetchImpl(endpoint, {
        method:  "POST",
        headers: headers,
        body:    body,
        signal:  ac ? ac.signal : undefined,
      });
      if (res && res.ok) return { ok: true, status: res.status };
      var status = res && res.status;
      var retryable = typeof status === "number" &&
        (C.HTTP.serverError(status) || status === C.HTTP.STATUS.REQUEST_TIMEOUT ||
         status === C.HTTP.STATUS.TOO_MANY_REQUESTS);
      if (retryable && attempt < maxAttempts) {
        await _sleep(_backoffMs(attempt));
        return await _post(payload, attempt + 1);
      }
      return { ok: false, status: status, retryable: retryable };
    } catch (e) {
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

  var ticker = null;
  if (flushIntervalMs > 0) {
    ticker = safeAsync.repeating(function () {
      flush().catch(function () { /* drop-silent */ });
    }, flushIntervalMs, { name: "otlp-exporter-flush" });
  }

  async function shutdown() {
    stopping = true;
    if (ticker) { ticker.stop(); ticker = null; }
    while (queue.length > 0) {
      var r = await flush();
      if (!r || r.sent === 0) break;
    }
  }

  function stats() {
    var totalDropped = droppedQueueOverflow + droppedExportFailed;
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
    _bundleForTest: _bundleSpans,
  };
}

module.exports = {
  create:                  create,
  STATUS_CODE_TO_OTLP:     STATUS_CODE_TO_OTLP,
  KIND_TO_OTLP:            KIND_TO_OTLP,
  OtlpExporterError:       OtlpExporterError,
  _spanToOtlp:             _spanToOtlp,
  _spanToProto:            _spanToProto,
  _bundleSpans:            _bundleSpans,
  _attrToOtlp:             _attrToOtlp,
};
