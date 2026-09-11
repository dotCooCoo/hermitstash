// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.tracing
 * @nav    Observability
 * @title  Tracing
 *
 * @intro
 *   Distributed-tracing seam — W3C trace-context propagation,
 *   OpenTelemetry-shaped span lifecycle, sampling routed through OTel
 *   when installed.
 *
 *   The framework keeps zero npm runtime deps, so the OTel SDK isn't
 *   bundled. `b.tracing.create()` detects `@opentelemetry/api` at
 *   first use: when it's installed, every span call flows into the
 *   operator's tracer (Jaeger / Zipkin / OTLP / console — whatever
 *   exporter they wired) and OTel's sampler decides per-span
 *   `sampled` flag from the configured `TraceIdRatioBased` /
 *   `ParentBased` rules. When OTel is absent every call falls through
 *   a pass-through tracer that still executes the wrapped function,
 *   propagates return values and exceptions, and emits no span data.
 *
 *   `contextHeaders()` and `extractContext()` always parse and emit
 *   the W3C `traceparent` format
 *   (`00-<32-hex traceId>-<16-hex spanId>-<2-hex flags>`) regardless
 *   of whether OTel is loaded — so operators get trace-ID per request
 *   as a free correlation baseline even without a tracer SDK. Span
 *   shape mirrors OTel: `setAttribute` / `addEvent` /
 *   `recordException` / `setStatus` / `end` / `updateName`.
 *
 *   `b.tracing.tap("audit.record", attributes, fn)` mirrors
 *   `b.metrics.tap` for tracing — wraps `fn` in a span if a registry
 *   is active, passes through otherwise. `requestMiddleware()` opens
 *   one span per inbound request, extracts any incoming
 *   `traceparent`, and promotes `http.route` to the matched route
 *   template at response time.
 *
 * @card
 *   Distributed-tracing seam — W3C trace-context propagation, OpenTelemetry-shaped span lifecycle, sampling routed through OTel when installed.
 */

var C = require("./constants");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var { resolveRoute, captureResponseStatus } = require("./request-helpers");

var W3C_TRACE_ID_BYTES = C.BYTES.bytes(16);
var W3C_SPAN_ID_BYTES  = C.BYTES.bytes(8);
var HEX_RADIX          = 0x10;

var TracingError = defineClass("TracingError", { alwaysPermanent: true });

var _otel = undefined;

function _getOtel() {
  if (_otel !== undefined) return _otel;
  try { _otel = require("@opentelemetry/api"); }
  catch (_e) { _otel = null; }
  return _otel;
}

function _setOtelForTest(value) { _otel = value === undefined ? undefined : value; }

var TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
var ZERO_TRACE_ID = "0".repeat(W3C_TRACE_ID_BYTES * 2);
var ZERO_SPAN_ID  = "0".repeat(W3C_SPAN_ID_BYTES * 2);

function _parseTraceparent(value) {
  if (typeof value !== "string") return null;
  var m = value.match(TRACEPARENT_RE);
  if (!m) return null;
  if (m[1] === ZERO_TRACE_ID || m[2] === ZERO_SPAN_ID) return null;
  return { traceId: m[1], spanId: m[2], flags: m[3] };
}

function _formatTraceparent(traceId, spanId, flags) {
  return "00-" + traceId + "-" + spanId + "-" + (flags || "01");
}

function _newTraceId() {
  return bCrypto.generateToken(W3C_TRACE_ID_BYTES);
}
function _newSpanId() {
  return bCrypto.generateToken(W3C_SPAN_ID_BYTES);
}

function _passthroughSpan(traceId, spanId, parentSpanId) {
  return {
    spanContext: function () {
      return { traceId: traceId, spanId: spanId, traceFlags: 1, isRemote: false };
    },
    setAttribute:   function () { return this; },
    setAttributes:  function () { return this; },
    addEvent:       function () { return this; },
    recordException: function () { return this; },
    setStatus:      function () { return this; },
    updateName:     function () { return this; },
    end:            function () { },
    _isPassthrough: true,
    _parentSpanId:  parentSpanId,
  };
}

function _passthroughTracer() {
  var stack = [];
  return {
    startSpan: function (_name, _opts) {
      var traceId = stack.length > 0 ? stack[stack.length - 1].spanContext().traceId : _newTraceId();
      var span = _passthroughSpan(traceId, _newSpanId(),
        stack.length > 0 ? stack[stack.length - 1].spanContext().spanId : null);
      return span;
    },
    _push: function (span) { stack.push(span); },
    _pop:  function () { return stack.pop(); },
    _peek: function () { return stack.length > 0 ? stack[stack.length - 1] : null; },
    _isPassthrough: true,
  };
}

/**
 * @primitive b.tracing.create
 * @signature b.tracing.create(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.tracing.tap, b.metrics.create, b.observability.tap
 *
 * Build a tracing registry. The returned registry exposes `span`,
 * `spanSync`, `currentSpan`, `setAttributes`, `recordException`,
 * `contextHeaders` / `extractContext` for W3C traceparent
 * propagation, `requestMiddleware()` for per-request auto-spans, and
 * `tap()` for framework hot-path wrapping. Detects
 * `@opentelemetry/api` once at first use; without OTel installed the
 * registry runs in pass-through mode but still propagates trace IDs
 * over HTTP.
 *
 * @opts
 *   instrumentationName:    string,  // OTel tracer name; default "blamejs"
 *   instrumentationVersion: string,  // OTel tracer version; default "0.0.0"
 *
 * @example
 *   var t = b.tracing.create({
 *     instrumentationName:    "myapp",
 *     instrumentationVersion: "1.2.3",
 *   });
 *
 *   var users = await t.span("load-users", async function (span) {
 *     span.setAttribute("user_id", "abc");
 *     span.addEvent("cache-miss");
 *     return await db.query("SELECT id, email FROM users");
 *   }, { kind: "internal", attributes: { route: "/users" } });
 *
 *   // Outbound — propagate the active trace.
 *   var headers = t.contextHeaders();
 *   // → { traceparent: "00-<32 hex>-<16 hex>-01" } when a span is active
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "instrumentationName", "instrumentationVersion",
  ], "b.tracing");
  var instrumentationName    = opts.instrumentationName    || "blamejs";
  var instrumentationVersion = opts.instrumentationVersion || "0.0.0";

  var _cachedPassthrough = null;
  function _tracer() {
    var otel = _getOtel();
    if (otel) return otel.trace.getTracer(instrumentationName, instrumentationVersion);
    if (!_cachedPassthrough) _cachedPassthrough = _passthroughTracer();
    return _cachedPassthrough;
  }

  function _isReal() { return _getOtel() !== null; }

  function span(name, fn, sopts) {
    if (typeof name !== "string" || name.length === 0) {
      throw new TracingError("tracing/bad-name",
        "span name must be a non-empty string");
    }
    if (typeof fn !== "function") {
      throw new TracingError("tracing/bad-fn",
        "span body must be a function");
    }
    sopts = sopts || {};
    var tracer = _tracer();
    var otel = _getOtel();

    if (otel) {
      var spanInst = tracer.startSpan(name, {
        kind:       _kindFromString(otel, sopts.kind),
        attributes: sopts.attributes,
      });
      var ctx = otel.trace.setSpan(otel.context.active(), spanInst);
      return otel.context.with(ctx, function () {
        try {
          var ret = fn(spanInst);
          if (ret && typeof ret.then === "function") {
            return ret.then(
              function (v) { spanInst.end(); return v; },
              function (e) {
                spanInst.recordException(e);
                spanInst.setStatus({ code: 2, message: (e && e.message) || String(e) });
                spanInst.end();
                throw e;
              }
            );
          }
          spanInst.end();
          return ret;
        } catch (e) {
          spanInst.recordException(e);
          spanInst.setStatus({ code: 2, message: (e && e.message) || String(e) });
          spanInst.end();
          throw e;
        }
      });
    }

    var pSpan = tracer.startSpan(name, sopts);
    if (sopts.attributes) pSpan.setAttributes(sopts.attributes);
    tracer._push(pSpan);
    var done = false;
    function _finish() { if (!done) { done = true; tracer._pop(); pSpan.end(); } }
    try {
      var res = fn(pSpan);
      if (res && typeof res.then === "function") {
        return res.then(
          function (v) { _finish(); return v; },
          function (e) { _finish(); throw e; }
        );
      }
      _finish();
      return res;
    } catch (e) {
      _finish();
      throw e;
    }
  }

  function spanSync(name, fn, sopts) {
    if (typeof fn !== "function") {
      throw new TracingError("tracing/bad-fn", "spanSync body must be a function");
    }
    return span(name, fn, sopts);
  }

  function manualSpan(name, sopts) {
    if (typeof name !== "string" || name.length === 0) {
      throw new TracingError("tracing/bad-name",
        "span name must be a non-empty string");
    }
    sopts = sopts || {};
    var tracer = _tracer();
    var otel = _getOtel();
    var spanInst = tracer.startSpan(name, otel ? {
      kind:       _kindFromString(otel, sopts.kind),
      attributes: sopts.attributes,
    } : sopts);
    if (sopts.attributes && typeof spanInst.setAttributes === "function") {
      try { spanInst.setAttributes(sopts.attributes); }
      catch (_e) { /* best-effort */ }
    }
    var ended = false;
    var origEnd = spanInst.end ? spanInst.end.bind(spanInst) : function () {};
    spanInst.end = function () {
      if (ended) return;
      ended = true;
      try { tracer._pop && tracer._pop(); }
      catch (_e) { /* best-effort */ }
      try { origEnd(); }
      catch (_e) { /* best-effort */ }
    };
    if (tracer._push) tracer._push(spanInst);
    return spanInst;
  }

  function currentSpan() {
    var otel = _getOtel();
    if (otel) {
      var s = otel.trace.getActiveSpan();
      return s || null;
    }
    var t = _tracer();
    return t._peek();
  }

  function setAttributes(attrs) {
    var s = currentSpan();
    if (s) s.setAttributes(attrs);
  }

  function recordException(err) {
    var s = currentSpan();
    if (s) {
      s.recordException(err);
      s.setStatus({ code: 2, message: (err && err.message) || String(err) });
    }
  }

  function contextHeaders() {
    var s = currentSpan();
    if (!s) return {};
    var sc = s.spanContext ? s.spanContext() : null;
    if (!sc || !sc.traceId || sc.traceId === ZERO_TRACE_ID) return {};
    return {
      traceparent: _formatTraceparent(sc.traceId, sc.spanId,
        (sc.traceFlags === undefined ? 1 : sc.traceFlags).toString(HEX_RADIX).padStart(2, "0")),
    };
  }

  function extractContext(headers) {
    if (!headers || typeof headers !== "object") return null;
    var raw = headers.traceparent || headers["Traceparent"] || headers["TRACEPARENT"];
    var parsed = _parseTraceparent(raw);
    if (!parsed) return null;
    return parsed;
  }

  function requestMiddleware() {
    return function tracingMiddleware(req, res, next) {
      var initialRoute = resolveRoute(req);
      var spanName = "HTTP " + (req.method || "GET") + " " + initialRoute;
      var attrs = {
        "http.method": req.method || "GET",
        "http.route":  initialRoute,
        "http.url":    req.url || "",
      };
      var parent = extractContext(req.headers);
      if (parent) {
        attrs["traceparent.parent"] = parent.traceId + "-" + parent.spanId;
      }
      span(spanName, function (s) {
        req.span = s;
        captureResponseStatus(res, function (status) {
          try {
            s.setAttribute("http.status_code", status);
            var finalRoute = resolveRoute(req);
            if (finalRoute !== initialRoute) {
              s.setAttribute("http.route", finalRoute);
              if (typeof s.updateName === "function") {
                s.updateName("HTTP " + (req.method || "GET") + " " + finalRoute);
              }
            }
          } catch (_e) { /* span attr write must not break the response */ }
        });
        return next();
      }, { attributes: attrs }).catch(function () {
        // Span error already recorded by span() wrapper; the next()
        // chain handles request-level error handling separately.
      });
    };
  }

  var _activeOnTap = null;

  function tap(name, attributes, fn) {
    if (typeof attributes === "function") {
      fn = attributes; attributes = null;
    }
    if (typeof fn !== "function") {
      throw new TracingError("tracing/bad-fn", "tap fn must be a function");
    }
    if (_activeOnTap !== this && registry._isActive !== true) {
      return fn(currentSpan());
    }
    return span(name, fn, { attributes: attributes });
  }

  function _kindFromString(otel, kindStr) {
    if (!otel || !otel.SpanKind) return undefined;
    if (kindStr === "server")    return otel.SpanKind.SERVER;
    if (kindStr === "client")    return otel.SpanKind.CLIENT;
    if (kindStr === "producer")  return otel.SpanKind.PRODUCER;
    if (kindStr === "consumer")  return otel.SpanKind.CONSUMER;
    return otel.SpanKind.INTERNAL;
  }

  var registry = {
    span:               span,
    spanSync:           spanSync,
    manualSpan:         manualSpan,
    currentSpan:        currentSpan,
    setAttributes:      setAttributes,
    recordException:    recordException,
    contextHeaders:     contextHeaders,
    extractContext:     extractContext,
    requestMiddleware:  requestMiddleware,
    tap:                tap,
    isReal:             _isReal,
    _isActive:          true,
    deactivate: function () {
      registry._isActive = false;
      if (_globalRegistry === registry) _globalRegistry = null;
    },
  };
  _globalRegistry = registry;
  return registry;
}

var _globalRegistry = null;

/**
 * @primitive b.tracing.tap
 * @signature b.tracing.tap(name, attributes, fn)
 * @since     0.4.0
 * @related   b.tracing.create, b.metrics.tap, b.observability.tap
 *
 * Framework hot-path tracing tap. Modules call
 * `tap("audit.record", { action: "login" }, fn)` without importing a
 * registry. Until `b.tracing.create()` runs the call passes `fn(null)`
 * through directly (zero overhead, no span); afterwards the active
 * registry wraps `fn` in a span named `name` with the supplied
 * attributes. The two-arg form `tap(name, fn)` is permitted when no
 * attributes are needed.
 *
 * @example
 *   // Module-level — passthrough until a registry exists.
 *   var rows = b.tracing.tap("db.query", { table: "users" }, function () {
 *     return db.queryAll("SELECT id FROM users");
 *   });
 *
 *   // Two-arg — no attributes:
 *   b.tracing.tap("queue.enqueue", function () { return enqueueJob(); });
 */
function tap(name, attributes, fn) {
  if (typeof attributes === "function") {
    fn = attributes; attributes = null;
  }
  if (typeof fn !== "function") {
    throw new TracingError("tracing/bad-fn", "tap fn must be a function");
  }
  if (_globalRegistry === null || _globalRegistry._isActive !== true) {
    return fn(null);
  }
  return _globalRegistry.span(name, fn, { attributes: attributes });
}

function _resetForTest() {
  _globalRegistry = null;
  _setOtelForTest(undefined);
}

module.exports = {
  create:            create,
  tap:               tap,
  TracingError:      TracingError,
  _setOtelForTest:   _setOtelForTest,
  _resetForTest:     _resetForTest,
  _parseTraceparent: _parseTraceparent,
  _formatTraceparent: _formatTraceparent,
  _newTraceId:       _newTraceId,
  _newSpanId:        _newSpanId,
  TRACEPARENT_RE:    TRACEPARENT_RE,
};
