"use strict";
/**
 * b.observability.tracer — OTel-shaped distributed-tracing span builder.
 *
 * Builds OpenTelemetry-compatible spans without a vendored OTel SDK.
 * The span objects are JSON-serializable and have the OTLP/JSON wire
 * shape (Trace v1) so the operator can ship them to any OTLP-aware
 * collector (Jaeger, Tempo, Honeycomb, Lightstep, Datadog, etc.) via
 * b.observability.spanExporter or their own bridge.
 *
 *   var tracer = b.observability.tracer.create({
 *     service: "checkout-api",
 *     resource: { "service.version": "0.42.0",
 *                 "deployment.environment": "prod" },
 *     onEnd: function (span) { exporter.queue(span); },
 *   });
 *
 *   var span = tracer.start("checkout.process", {
 *     traceId: req.trace.traceId,         // optional — derive from context
 *     parentId: req.trace.parentId,
 *     sampled:  req.trace.sampled,
 *     attributes: {
 *       [SEMCONV.HTTP_REQUEST_METHOD]: "POST",
 *       [SEMCONV.URL_PATH]:            "/checkout",
 *     },
 *     kind: "server",
 *   });
 *
 *   try {
 *     // ... do the work
 *     span.setAttribute(SEMCONV.HTTP_RESPONSE_STATUS_CODE, 200);
 *     span.addEvent("payment.charged", { amount: 4200 });
 *     span.setStatus("ok");
 *   } catch (e) {
 *     span.recordException(e);
 *     span.setStatus("error", e.message);
 *     throw e;
 *   } finally {
 *     span.end();   // captures duration_ms, fires tracer.onEnd(span)
 *   }
 *
 * Span lifecycle:
 *   - start()       — captures startTime; assigns spanId; emits
 *                     span.start observability counter
 *   - setAttribute  — additive; rejects non-stable attribute names
 *                     when strict: true
 *   - addEvent      — appends { name, time, attributes }
 *   - recordException — addEvent with `exception.*` attributes
 *   - setStatus     — "unset" | "ok" | "error" with optional message
 *   - end()         — captures endTime; emits span.end observability
 *                     counter; calls tracer.onEnd(span) hook
 *
 * Span shape (OTLP/JSON-compatible):
 *   {
 *     traceId, spanId, parentSpanId, name, kind,
 *     startTimeUnixNano, endTimeUnixNano, durationNs, durationMs,
 *     attributes: { ... },
 *     events: [ { name, timeUnixNano, attributes } ],
 *     status: { code: "unset" | "ok" | "error", message? },
 *     resource: { ... },
 *     scope: { name: "blamejs", version },
 *     droppedAttributesCount, droppedEventsCount,
 *   }
 *
 * Attribute / event caps:
 *   - maxAttributes per span: 128 (OTLP default)
 *   - maxEvents per span:     128
 *   - maxAttributeValueLength: 1024 chars (truncated past)
 *
 * Excess additions silently increment droppedAttributesCount /
 * droppedEventsCount per OTLP convention; the span itself never
 * throws on cap overflow (hot-path observability is drop-silent).
 */

var bCrypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var TRACE_ID_BYTES = C.BYTES.bytes(16);                                    // W3C §3.2.2.3 — 128-bit trace-id
var SPAN_ID_BYTES  = C.BYTES.bytes(8);                                     // W3C §3.2.2.4 — 64-bit span-id

var TracerError = defineClass("TracerError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_MAX_ATTRIBUTES = 128;                                                  // OTLP default span attribute cap
var DEFAULT_MAX_EVENTS     = 128;                                                  // OTLP default span event cap
var DEFAULT_MAX_ATTR_VALUE_LEN = 1024;                                             // OTLP attribute value char cap

var VALID_KINDS = ["internal", "server", "client", "producer", "consumer"];
var VALID_STATUS_CODES = ["unset", "ok", "error"];

function _now() { return Date.now(); }

function _msToUnixNano(ms) {
  // OTLP timestamps are uint64 nanoseconds since Unix epoch. JS Date.now()
  // gives ms; multiply by 1e6 and stringify (OTLP/JSON uses string for
  // uint64 values per https://protobuf.dev/programming-guides/proto3/#json).
  return String(BigInt(ms) * 1000000n);                                            // ms→ns conversion factor (1e6)
}

function _truncateAttrValue(v, maxLen) {
  if (typeof v === "string" && v.length > maxLen) {
    return v.slice(0, maxLen);
  }
  return v;
}

function _validateKind(kind) {
  if (typeof kind !== "string") return "internal";
  if (VALID_KINDS.indexOf(kind) === -1) {
    throw new TracerError("tracer/bad-kind",
      "tracer.start: kind must be one of " + VALID_KINDS.join(", ") +
      " (got " + JSON.stringify(kind) + ")");
  }
  return kind;
}

function _validateAttrKey(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  // OTel attribute keys: ASCII printable, dot-separated, no spaces
  // beyond what the SEMCONV vocabulary uses.
  if (key.length > 255) return false;                                              // OTLP attribute key cap
  return true;
}

function _validateAttrValue(v) {
  // OTLP supports string / int / double / bool / array of those
  var t = typeof v;
  if (t === "string" || t === "boolean") return true;
  if (t === "number") return Number.isFinite(v);
  if (Array.isArray(v)) {
    for (var i = 0; i < v.length; i++) {
      var elT = typeof v[i];
      if (elT !== "string" && elT !== "boolean" && elT !== "number") return false;
      if (elT === "number" && !Number.isFinite(v[i])) return false;
    }
    return true;
  }
  return false;
}

function _spanId() {
  return bCrypto.generateBytes(SPAN_ID_BYTES).toString("hex");
}

function _traceId() {
  return bCrypto.generateBytes(TRACE_ID_BYTES).toString("hex");
}

function create(opts) {
  validateOpts.requireObject(opts, "tracer", TracerError);
  validateOpts(opts, [
    "service", "resource", "scope",
    "maxAttributes", "maxEvents", "maxAttributeValueLength",
    "onEnd", "onStart",
  ], "tracer.create");
  validateOpts.requireNonEmptyString(opts.service,
    "tracer.create: service", TracerError, "tracer/bad-service");
  validateOpts.optionalFunction(opts.onEnd,
    "tracer.create: onEnd", TracerError, "tracer/bad-opts");
  validateOpts.optionalFunction(opts.onStart,
    "tracer.create: onStart", TracerError, "tracer/bad-opts");

  var resource = Object.assign({
    "service.name": opts.service,
  }, opts.resource || {});
  var scope = opts.scope || { name: "blamejs", version: C.version || null };
  var maxAttributes = opts.maxAttributes || DEFAULT_MAX_ATTRIBUTES;
  var maxEvents     = opts.maxEvents     || DEFAULT_MAX_EVENTS;
  var maxAttrValLen = opts.maxAttributeValueLength || DEFAULT_MAX_ATTR_VALUE_LEN;

  function _newSpan(name, spanOpts) {
    spanOpts = spanOpts || {};
    var traceId = spanOpts.traceId;
    if (typeof traceId !== "string" || !safeBuffer.TRACE_ID_HEX_RE.test(traceId)) {  // allow:regex-no-length-cap — fixed-length hex constant from safe-buffer
      traceId = _traceId();
    }
    var parentSpanId = spanOpts.parentId || null;
    if (parentSpanId !== null && (typeof parentSpanId !== "string" || !safeBuffer.SPAN_ID_HEX_RE.test(parentSpanId))) {  // allow:regex-no-length-cap — fixed-length hex constant from safe-buffer
      parentSpanId = null;
    }
    var spanId = _spanId();
    var startMs = _now();
    var kind = _validateKind(spanOpts.kind);
    var sampled = spanOpts.sampled !== false;

    var attributes = Object.create(null);
    var droppedAttributesCount = 0;
    var events = [];
    var droppedEventsCount = 0;
    var status = { code: "unset", message: null };
    var ended = false;
    var endMs = null;

    function setAttribute(key, value) {
      if (ended) return span;
      if (!_validateAttrKey(key)) { droppedAttributesCount += 1; return span; }
      if (!_validateAttrValue(value)) { droppedAttributesCount += 1; return span; }
      var keyCount = Object.keys(attributes).length;
      if (!(key in attributes) && keyCount >= maxAttributes) {
        droppedAttributesCount += 1;
        return span;
      }
      attributes[key] = _truncateAttrValue(value, maxAttrValLen);
      return span;
    }

    function setAttributes(map) {
      if (!map || typeof map !== "object") return span;
      var keys = Object.keys(map);
      for (var i = 0; i < keys.length; i++) setAttribute(keys[i], map[keys[i]]);
      return span;
    }

    function addEvent(eventName, eventAttrs) {
      if (ended) return span;
      if (typeof eventName !== "string" || eventName.length === 0) {
        droppedEventsCount += 1;
        return span;
      }
      if (events.length >= maxEvents) { droppedEventsCount += 1; return span; }
      var eventTime = _now();
      var attrs = Object.create(null);
      if (eventAttrs && typeof eventAttrs === "object") {
        var ks = Object.keys(eventAttrs);
        for (var i = 0; i < ks.length; i++) {
          var k = ks[i], v = eventAttrs[k];
          if (_validateAttrKey(k) && _validateAttrValue(v)) {
            attrs[k] = _truncateAttrValue(v, maxAttrValLen);
          }
        }
      }
      events.push({
        name:         eventName,
        timeUnixNano: _msToUnixNano(eventTime),
        attributes:   attrs,
      });
      return span;
    }

    function recordException(err) {
      if (ended) return span;
      if (!err) return span;
      var name = (err.name || (err.constructor && err.constructor.name) || "Error");
      var message = (err.message || String(err));
      var stack = err.stack ? String(err.stack) : null;
      addEvent("exception", {
        "exception.type":       name,
        "exception.message":    message,
        "exception.stacktrace": stack || "",
      });
      return span;
    }

    function setStatus(code, message) {
      if (ended) return span;
      if (VALID_STATUS_CODES.indexOf(code) === -1) {
        throw new TracerError("tracer/bad-status",
          "span.setStatus: code must be one of " + VALID_STATUS_CODES.join(", "));
      }
      status.code = code;
      status.message = (typeof message === "string") ? message : null;
      return span;
    }

    function end(endTimestampMs) {
      if (ended) return span;
      ended = true;
      endMs = (typeof endTimestampMs === "number" && isFinite(endTimestampMs)) ? endTimestampMs : _now();
      if (typeof opts.onEnd === "function") {
        try { opts.onEnd(toJSON()); }
        catch (_e) { /* operator hook — drop-silent */ }
      }
      try { observability().safeEvent("tracer.span.end", 1, {
        kind: kind, status: status.code, sampled: sampled ? "1" : "0",
      }); } catch (_e) { /* drop-silent */ }
      return span;
    }

    function isRecording() { return !ended; }

    function toJSON() {
      var endNano = endMs !== null ? _msToUnixNano(endMs) : null;
      var durationMs = endMs !== null ? (endMs - startMs) : null;
      // OTLP/JSON shape (Trace v1)
      return {
        traceId:           traceId,
        spanId:            spanId,
        parentSpanId:      parentSpanId,
        name:              name,
        kind:              kind,
        startTimeUnixNano: _msToUnixNano(startMs),
        endTimeUnixNano:   endNano,
        durationNs:        endNano !== null ? String(BigInt(durationMs) * 1000000n) : null,  // ms→ns conversion factor (1e6)
        durationMs:        durationMs,
        attributes:        Object.assign({}, attributes),
        events:            events.slice(),
        status:            { code: status.code, message: status.message },
        resource:          Object.assign({}, resource),
        scope:             Object.assign({}, scope),
        droppedAttributesCount: droppedAttributesCount,
        droppedEventsCount:     droppedEventsCount,
        sampled:           sampled,
      };
    }

    var span = {
      traceId:           traceId,
      spanId:            spanId,
      parentSpanId:      parentSpanId,
      name:              name,
      kind:              kind,
      sampled:           sampled,
      setAttribute:      setAttribute,
      setAttributes:     setAttributes,
      addEvent:          addEvent,
      recordException:   recordException,
      setStatus:         setStatus,
      end:               end,
      isRecording:       isRecording,
      toJSON:            toJSON,
    };

    // Apply initial attributes
    if (spanOpts.attributes && typeof spanOpts.attributes === "object") {
      setAttributes(spanOpts.attributes);
    }

    if (typeof opts.onStart === "function") {
      try { opts.onStart(span); }
      catch (_e) { /* operator hook — drop-silent */ }
    }
    try { observability().safeEvent("tracer.span.start", 1, {
      kind: kind, sampled: sampled ? "1" : "0",
    }); } catch (_e) { /* drop-silent */ }

    return span;
  }

  function start(name, spanOpts) {
    if (typeof name !== "string" || name.length === 0) {
      throw new TracerError("tracer/bad-name",
        "tracer.start: name must be a non-empty string");
    }
    return _newSpan(name, spanOpts || {});
  }

  function startChildOf(parentSpan, name, spanOpts) {
    if (!parentSpan || typeof parentSpan.traceId !== "string") {
      throw new TracerError("tracer/bad-parent",
        "tracer.startChildOf: parentSpan must be a span object");
    }
    var childOpts = Object.assign({}, spanOpts || {}, {
      traceId:  parentSpan.traceId,
      parentId: parentSpan.spanId,
      sampled:  parentSpan.sampled,
    });
    return _newSpan(name, childOpts);
  }

  return {
    start:            start,
    startChildOf:     startChildOf,
    service:          opts.service,
    resource:         resource,
    scope:            scope,
    _attributeCaps:   {                                                            // exported for tests
      maxAttributes:           maxAttributes,
      maxEvents:                maxEvents,
      maxAttributeValueLength: maxAttrValLen,
    },
  };
}

// Pure helper: derive the canonical W3C `traceparent` header from a span.
function spanToTraceparent(span) {
  if (!span || typeof span.traceId !== "string" || typeof span.spanId !== "string") {
    throw new TracerError("tracer/bad-span",
      "spanToTraceparent: argument must be a span with traceId + spanId");
  }
  return "00-" + span.traceId + "-" + span.spanId + "-" + (span.sampled ? "01" : "00");
}

module.exports = {
  create:            create,
  spanToTraceparent: spanToTraceparent,
  TracerError:       TracerError,
  _BASE64URL_RE:     safeBuffer.BASE64URL_RE,                                      // not used directly — exposed for downstream tests
  VALID_KINDS:       VALID_KINDS,
  VALID_STATUS_CODES: VALID_STATUS_CODES,
};
