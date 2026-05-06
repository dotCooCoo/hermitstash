"use strict";
/**
 * tracing — OpenTelemetry seam without an OTel runtime dependency.
 *
 * The framework doesn't bundle the OTel SDK — operators install
 * `@opentelemetry/api` (and an exporter) themselves when they want
 * tracing. This module:
 *
 *   - Detects if @opentelemetry/api is installed (try/catch require,
 *     cached). When it's there, every framework span call routes into
 *     OTel's real tracer and shows up in the operator's exporter
 *     (Jaeger, Zipkin, OTLP, console, whatever they wired).
 *   - When OTel ISN'T installed, every call is a pass-through. The
 *     wrapped function still executes, return values still propagate,
 *     thrown errors still escape — but no span is created and no
 *     overhead is paid beyond one cached lookup.
 *
 * Public API:
 *
 *   var t = b.tracing.create({
 *     instrumentationName:    "blamejs",
 *     instrumentationVersion: "1.0.0",
 *   });
 *
 *   // Wrap async work in a span. Returns whatever fn returns.
 *   var result = await t.span("my-op", async function (span) {
 *     span.setAttribute("user_id", "abc");
 *     span.addEvent("cache-miss");
 *     return await doWork();
 *   }, { kind: "internal", attributes: { route: "/users" } });
 *
 *   // Sync variant.
 *   var x = t.spanSync("compute", function (span) { ... return v; });
 *
 *   // Read / write the current active span.
 *   t.currentSpan();                          // null when no active span
 *   t.setAttributes({ user_id: "abc" });      // sets on current
 *   t.recordException(err);                   // records on current
 *
 *   // HTTP propagation. contextHeaders() returns headers to add to
 *   // outbound requests (W3C `traceparent`); extractContext(headers)
 *   // pulls a parent context from inbound headers.
 *   var headers = t.contextHeaders();
 *   var parentCtx = t.extractContext(req.headers);
 *
 *   // Auto-span request middleware — wraps each handler in a span
 *   // named after method + route pattern.
 *   router.use(t.requestMiddleware());
 *
 *   // Framework-internal hot-path tap — wraps fn in a span named
 *   // `name` if a registry is active; pass-through otherwise. Like
 *   // metrics.tap() but for tracing instead of counting.
 *   b.tracing.tap("audit.record", attributes, fn);
 *
 * Even WITHOUT @opentelemetry/api installed:
 *   - contextHeaders() / extractContext() still parse and emit the
 *     W3C traceparent format. So a framework process without OTel
 *     can still propagate trace IDs through logs and HTTP for
 *     correlation, even without span telemetry. Operators get the
 *     "trace ID per request" plumbing as a free baseline.
 *   - currentSpan() returns a minimal pass-through "span" object so
 *     operator code can call setAttribute / addEvent / recordException
 *     unconditionally — they're no-ops without OTel.
 *
 * Why no @otel runtime dep:
 *   - The framework keeps zero npm runtime deps. Apps that want tracing
 *     install OTel themselves; apps that don't pay nothing.
 *   - The OTel API is unstable enough that pinning a vendored version
 *     would create more churn than it saves.
 *
 * Out of scope (with structural reasons):
 *   - Vendoring the SDK: see above.
 *   - Sampling decisions: OTel handles this when wired; without OTel
 *     there's nothing to sample.
 *   - Exporter integration: belongs to the OTel SDK, not the framework.
 *   - Custom propagators: framework ships W3C traceparent only. OTel
 *     adds others (b3, jaeger) when wired by the operator.
 *   - Async-context propagation across setTimeout / setImmediate:
 *     OTel's NodeSDK auto-instrumentation handles this when installed;
 *     without OTel, framework code uses fn-passing rather than
 *     async-context, which is fine for the surfaces we instrument.
 */

var C = require("./constants");
var crypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var { resolveRoute, captureResponseStatus } = require("./request-helpers");

// W3C trace-context fixed widths (RFC TraceContext §3.2.2.2):
//   trace-id : 16 bytes / 32 hex chars
//   span-id  :  8 bytes / 16 hex chars
//   flags    :  1 byte  /  2 hex chars
var W3C_TRACE_ID_BYTES = C.BYTES.bytes(16);
var W3C_SPAN_ID_BYTES  = C.BYTES.bytes(8);
var HEX_RADIX          = 0x10;

var TracingError = defineClass("TracingError", { alwaysPermanent: true });

// ---- OTel API detection (cached) ----
//
// Tri-state: undefined=not yet checked, null=not available, object=available.
// We cache the lookup so the per-call cost is one === comparison after
// the first call.

var _otel = undefined;

function _getOtel() {
  if (_otel !== undefined) return _otel;
  try { _otel = require("@opentelemetry/api"); }
  catch (_e) { _otel = null; }
  return _otel;
}

// Test seam — letting tests force the OTel resolution. Pass `null` to
// simulate "not installed" or an object to simulate a vendored OTel API.
function _setOtelForTest(value) { _otel = value === undefined ? undefined : value; }

// ---- W3C traceparent parsing ----
//
// Format: 00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>
// Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
//
// We accept only version 00 (the only released W3C version). Future
// versions are technically forward-compatible but would extend the
// suffix; we ignore unrecognized versions to be safe.

var TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
// Special-case all-zeros: invalid per spec but malicious clients send them.
// (32 = W3C_TRACE_ID_BYTES * 2 hex chars; 16 = W3C_SPAN_ID_BYTES * 2.)
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
  return crypto.generateToken(W3C_TRACE_ID_BYTES);
}
function _newSpanId() {
  return crypto.generateToken(W3C_SPAN_ID_BYTES);
}

// ---- Pass-through span (used when OTel isn't installed) ----
//
// Operator code does span.setAttribute() / span.addEvent() /
// span.recordException() unconditionally. When OTel is absent these
// calls go to a minimal stub that no-ops but keeps the API shape
// compatible. Trace ID is still tracked so log correlation works.

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
    // Internal — used by the registry to thread parent context.
    _isPassthrough: true,
    _parentSpanId:  parentSpanId,
  };
}

// ---- Pass-through tracer (used when OTel isn't installed) ----
//
// Implements just enough of the OTel Tracer interface to drive the
// framework's span() / spanSync() helpers. Real OTel takes over when
// installed; the wrapper code below doesn't change.

function _passthroughTracer() {
  // Active-span stack. Single-threaded JS lets us use a process-level
  // stack rather than async-context. Pure synchronous span lifetimes
  // are correct; async work that spans suspension points won't have
  // currentSpan() right inside continuations — but the operator's fn
  // still receives the span as its first arg, so attribute/event
  // setting via that reference always works.
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

// ---- Registry factory ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "instrumentationName", "instrumentationVersion",
  ], "b.tracing");
  var instrumentationName    = opts.instrumentationName    || "blamejs";
  var instrumentationVersion = opts.instrumentationVersion || "0.0.0";

  // Resolve the tracer once. If @opentelemetry/api is installed, this
  // is a real Tracer; otherwise a passthrough. Cached per-registry so
  // the passthrough stack persists across span() and currentSpan() calls
  // (otherwise each call would see a fresh empty stack).
  var _cachedPassthrough = null;
  function _tracer() {
    var otel = _getOtel();
    if (otel) return otel.trace.getTracer(instrumentationName, instrumentationVersion);
    if (!_cachedPassthrough) _cachedPassthrough = _passthroughTracer();
    return _cachedPassthrough;
  }

  function _isReal() { return _getOtel() !== null; }

  // Wrap fn in a span. The span is automatically end()'d on return /
  // throw / promise rejection. exception is recorded on throw and
  // span status set to ERROR.
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

    // Real OTel path — use context.with so async-context propagation
    // works automatically once the SDK is wired.
    if (otel) {
      var spanInst = tracer.startSpan(name, {
        kind:       _kindFromString(otel, sopts.kind),
        attributes: sopts.attributes,
      });
      // Run fn inside the span's context so child spans nest.
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

    // Pass-through path — still wrap so operator code that calls
    // span.setAttribute / addEvent / recordException works, just
    // without telemetry output.
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
    // Same shape as span(); fn must return a non-Promise. We don't
    // enforce that, but we don't await either — async fn used here
    // ends the span before resolution.
    return span(name, fn, sopts);
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

  // ---- W3C propagation (works with or without OTel) ----

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

  // Parse traceparent from incoming headers. With OTel installed we
  // use its propagation API for correctness across propagator types
  // an operator might have configured; without OTel we fall back to
  // our own parser which always understands W3C.
  function extractContext(headers) {
    if (!headers || typeof headers !== "object") return null;
    var raw = headers.traceparent || headers["Traceparent"] || headers["TRACEPARENT"];
    var parsed = _parseTraceparent(raw);
    if (!parsed) return null;
    return parsed;
  }

  // ---- request middleware ----

  function requestMiddleware() {
    return function tracingMiddleware(req, res, next) {
      // Span starts BEFORE the router populates req.routePattern, so
      // initial name+http.route come from the URL fallback. We promote
      // both to the template form at res.end if the matcher set one.
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
            // Promote to route template if the router resolved one.
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

  // ---- framework auto-tap ----
  //
  // Like metrics.tap, the tracing tap routes framework hot-path calls
  // into spans when this registry is the active one.

  var _activeOnTap = null;

  function tap(name, attributes, fn) {
    if (typeof attributes === "function") {
      fn = attributes; attributes = null;
    }
    if (typeof fn !== "function") {
      throw new TracingError("tracing/bad-fn", "tap fn must be a function");
    }
    if (_activeOnTap !== this && registry._isActive !== true) {
      // No active registry — execute fn directly. Caller never knows.
      return fn(currentSpan());
    }
    return span(name, fn, { attributes: attributes });
  }

  // OTel SpanKind enum values (from @opentelemetry/api). When OTel
  // isn't installed, kind is just an attribute string.
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

// ---- Global tap stub for framework modules ----
//
// Same pattern as metrics.tap: framework modules call b.tracing.tap()
// at hot paths. Without an active registry the call is a pass-through
// that just executes fn. With one, it routes into span().

var _globalRegistry = null;

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
  // Internal helpers exposed for tests
  _parseTraceparent: _parseTraceparent,
  _formatTraceparent: _formatTraceparent,
  _newTraceId:       _newTraceId,
  _newSpanId:        _newSpanId,
  TRACEPARENT_RE:    TRACEPARENT_RE,
};
