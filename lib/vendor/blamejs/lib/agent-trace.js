"use strict";
/**
 * @module     b.agent.trace
 * @nav        Agent
 * @title      Agent Trace
 * @order      85
 *
 * @intro
 *   Distributed tracing through every agent boundary. Composes the
 *   existing `b.tracing` (W3C trace context) so operators get a full
 *   request waterfall across the agent stack without wiring spans
 *   per-handler.
 *
 *   The substrate at v0.9.29 ships the integration surface:
 *
 *     - `startSpan(name, opts)` — wrap an agent method call in a span
 *     - `injectIntoEnvelope(envelope, currentSpan)` — inject W3C
 *       `traceparent` + `tracestate` into queue / event-bus / sub-
 *       agent envelopes so the consumer can continue the trace
 *     - `extractFromEnvelope(envelope)` — parse the envelope's
 *       trace context (refused via `b.guardTraceContext` if
 *       malformed)
 *     - `recordResult(span, result, error?)` — close span with
 *       success / error status
 *     - `shouldSample(method)` — sampling decision (global +
 *       per-method override)
 *
 *   Span shape (per method call):
 *
 *     name:        "<agent-kind>.<method>"    // e.g. "mail.agent.search"
 *     attributes:
 *       agent.method:        method name
 *       agent.dispatch_mode: "local" | "queue" | "auto"
 *       agent.tenant_id:     from v0.9.26 tenant scope (if present)
 *       agent.posture:       JSON-array of v0.9.28 posture set
 *       agent.shard:         from v0.9.21 shard routing
 *       agent.result_status: "success" | "error" | "not_implemented"
 *       agent.elapsed_ms:    integer
 *
 *   ```js
 *   var trace = b.agent.trace.create({
 *     tracing:    b.tracing.create({ instrumentationName: "mail-agent" }),
 *     sampleRate: 1.0,
 *     perMethod:  { fetch: 0.1, search: 0.5, send: 1.0 },
 *   });
 *
 *   var span = trace.startSpan("mail.agent.fetch", { actor, method: "fetch" });
 *   try {
 *     var result = await agent.fetch(args);
 *     trace.recordResult(span, result);
 *   } catch (e) {
 *     trace.recordResult(span, null, e);
 *     throw e;
 *   }
 *   ```
 *
 * @card
 *   Distributed tracing through every agent boundary. W3C trace
 *   context injection at queue / event-bus / sub-agent envelopes;
 *   per-method sampling; integrated with existing b.tracing.
 */

var lazyRequire        = require("./lazy-require");
var { defineClass }    = require("./framework-error");
var guardTraceContext  = require("./guard-trace-context");

var audit              = lazyRequire(function () { return require("./audit"); });

var AgentTraceError = defineClass("AgentTraceError", { alwaysPermanent: true });

/**
 * @primitive b.agent.trace.create
 * @signature b.agent.trace.create(opts)
 * @since     0.9.29
 * @status    stable
 * @related   b.tracing.create, b.agent.orchestrator.create
 *
 * Create the trace facade. Composes operator-supplied `b.tracing`
 * instance (or stub if absent — spans become no-ops).
 *
 * @opts
 *   tracing:    b.tracing instance,       // required for live spans
 *   audit:      b.audit namespace,         // optional
 *   sampleRate: number in [0..1],          // default 1.0
 *   perMethod:  { <method>: number },      // override per-method
 *
 * @example
 *   var trace = b.agent.trace.create({ tracing: myTracing, sampleRate: 0.5 });
 *   var span = trace.startSpan("mail.agent.fetch", { actor });
 */
function create(opts) {
  opts = opts || {};
  if (!opts.tracing || typeof opts.tracing !== "object") {
    throw new AgentTraceError("agent-trace/bad-tracing",
      "create: opts.tracing is required (b.tracing.create() result)");
  }
  var sampleRate = typeof opts.sampleRate === "number" ? opts.sampleRate : 1.0;
  if (!isFinite(sampleRate) || sampleRate < 0 || sampleRate > 1) {
    throw new AgentTraceError("agent-trace/bad-sample-rate",
      "create: sampleRate must be in [0, 1]");
  }
  var perMethod = opts.perMethod || {};
  var auditImpl = opts.audit || audit();

  return {
    startSpan:           function (name, sopts)             { return _startSpan(opts.tracing, name, sopts || {}); },
    injectIntoEnvelope:  function (envelope, span)          { return _injectIntoEnvelope(opts.tracing, envelope, span); },
    extractFromEnvelope: function (envelope)                { return _extractFromEnvelope(envelope); },
    recordResult:        function (span, result, error)     { return _recordResult(span, result, error); },
    shouldSample:        function (method)                  { return _shouldSample(sampleRate, perMethod, method); },
    formatAttributes:    function (info)                    { return _formatAttributes(info); },
    AgentTraceError:     AgentTraceError,
    _ctx: { sampleRate: sampleRate, perMethod: perMethod, audit: auditImpl },
  };
}

function _startSpan(tracing, name, sopts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new AgentTraceError("agent-trace/bad-span-name",
      "startSpan: name required");
  }
  // Compose b.tracing's manual-lifetime span — sets the span as active
  // on the registry stack so tracing.contextHeaders() / currentSpan()
  // see it, then exposes end() so the agent boundary controls
  // lifetime across publish → consume.
  if (typeof tracing.manualSpan === "function") {
    return tracing.manualSpan(name, sopts);
  }
  // Operator passed a non-b.tracing object (operator-supplied OTel
  // tracer directly) — try its native startSpan. Refuse if neither.
  if (typeof tracing.startSpan === "function") {
    return tracing.startSpan(name, sopts);
  }
  throw new AgentTraceError("agent-trace/bad-tracing",
    "startSpan: opts.tracing must expose manualSpan() (b.tracing.create()) " +
    "or startSpan() (raw OTel tracer); neither found");
}

function _injectIntoEnvelope(tracing, envelope, span) {
  if (!envelope || typeof envelope !== "object") {
    throw new AgentTraceError("agent-trace/bad-envelope",
      "injectIntoEnvelope: envelope required");
  }
  // tracing.contextHeaders() returns { traceparent, tracestate? } when
  // a span is active. We pass through whatever's current.
  var headers = (typeof tracing.contextHeaders === "function") ? tracing.contextHeaders() : null;
  if (!headers || typeof headers.traceparent !== "string") return envelope;
  envelope._trace = {
    traceparent: headers.traceparent,
    tracestate:  headers.tracestate || "",
  };
  return envelope;
}

function _extractFromEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || !envelope._trace) return null;
  // Validate via guardTraceContext — refuses malformed traceparent
  // strings before the consumer side picks them up as a parent span.
  try {
    guardTraceContext.validate(envelope._trace);
  } catch (e) {
    throw new AgentTraceError("agent-trace/bad-envelope-trace",
      "extractFromEnvelope: " + ((e && e.message) || String(e)));
  }
  return {
    traceparent: envelope._trace.traceparent,
    tracestate:  envelope._trace.tracestate || "",
  };
}

function _recordResult(span, result, error) {
  if (!span || typeof span !== "object") return;
  if (error) {
    if (typeof span.recordException === "function") {
      try { span.recordException(error); } catch (_e) { /* best-effort */ }
    }
    if (typeof span.setStatus === "function") {
      try { span.setStatus({ code: 2, message: error.message || String(error) }); }
      catch (_e) { /* best-effort */ }
    }
  } else if (typeof span.setStatus === "function") {
    try { span.setStatus({ code: 1 }); } catch (_e) { /* best-effort */ }
  }
  if (typeof span.end === "function") {
    try { span.end(); } catch (_e) { /* best-effort */ }
  }
}

function _shouldSample(globalRate, perMethod, method) {
  if (typeof method === "string" && Object.prototype.hasOwnProperty.call(perMethod, method)) {
    var r = perMethod[method];
    if (typeof r === "number" && isFinite(r) && r >= 0 && r <= 1) {
      return Math.random() < r;                                                                       // allow:math-random-noncrypto — sampling is statistical, not security-sensitive
    }
  }
  return Math.random() < globalRate;                                                                  // allow:math-random-noncrypto — sampling is statistical, not security-sensitive
}

function _formatAttributes(info) {
  if (!info || typeof info !== "object") return {};
  var attrs = {};
  if (info.method)       attrs["agent.method"]        = info.method;
  if (info.dispatchMode) attrs["agent.dispatch_mode"] = info.dispatchMode;
  if (info.tenantId)     attrs["agent.tenant_id"]     = info.tenantId;
  if (Array.isArray(info.postureSet)) attrs["agent.posture"] = JSON.stringify(info.postureSet);
  if (typeof info.shard === "number")  attrs["agent.shard"]       = info.shard;
  if (info.resultStatus) attrs["agent.result_status"] = info.resultStatus;
  if (typeof info.elapsedMs === "number") attrs["agent.elapsed_ms"] = info.elapsedMs;
  return attrs;
}

module.exports = {
  create:           create,
  AgentTraceError:  AgentTraceError,
  guards: {
    context: guardTraceContext,
  },
};
