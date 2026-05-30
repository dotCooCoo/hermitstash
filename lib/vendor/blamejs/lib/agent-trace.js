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
 *     - `injectIntoEnvelope(envelope)` — inject the currently-active
 *       span's W3C `traceparent` + `tracestate` into queue / event-bus
 *       / sub-agent envelopes so the consumer can continue the trace
 *       (call inside the `startSpan` callback so the right span is live)
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
var agentAudit         = require("./agent-audit");

var audit              = lazyRequire(function () { return require("./audit"); });

var AgentTraceError = defineClass("AgentTraceError", { alwaysPermanent: true });

// SUBSTRATE-24 — once-per-process audit emit on the first tracer
// failure each install fires. Operators get the signal even when
// individual span calls are best-effort suppressed.
var _failureAuditEmittedFor = Object.create(null);
function _emitFirstFailureAudit(auditImpl, kind, message) {
  if (_failureAuditEmittedFor[kind]) return;
  _failureAuditEmittedFor[kind] = true;
  agentAudit.safeAudit(auditImpl, "agent.trace.tracer_failure", null, {
    kind: kind, message: message ? String(message).slice(0, 256) : "",                                  // allow:raw-byte-literal — audit-message char cap
    rateLimited: "first-occurrence-only",
  });
}

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
    startSpan:           function (name, sopts)             { return _startSpan(opts.tracing, name, sopts || {}, auditImpl); },
    injectIntoEnvelope:  function (envelope, span)          { return _injectIntoEnvelope(opts.tracing, envelope, span); },
    extractFromEnvelope: function (envelope)                { return _extractFromEnvelope(envelope); },
    recordResult:        function (span, result, error)     { return _recordResult(span, result, error, auditImpl); },
    // SUBSTRATE-17 — `shouldSample` now takes a traceId so the same
    // trace gets the same decision across hops. Operator-supplied
    // traceId comes from the W3C `traceparent` header at request-
    // entry; absent that, falls back to Math.random (start of trace).
    shouldSample:        function (method, traceId)         { return _shouldSample(sampleRate, perMethod, method, traceId); },
    formatAttributes:    function (info)                    { return _formatAttributes(info); },
    AgentTraceError:     AgentTraceError,
    _ctx: { sampleRate: sampleRate, perMethod: perMethod, audit: auditImpl },
  };
}

function _startSpan(tracing, name, sopts, auditImpl) {
  if (typeof name !== "string" || name.length === 0) {
    throw new AgentTraceError("agent-trace/bad-span-name",
      "startSpan: name required");
  }
  // Compose b.tracing's manual-lifetime span — sets the span as active
  // on the registry stack so tracing.contextHeaders() / currentSpan()
  // see it, then exposes end() so the agent boundary controls
  // lifetime across publish → consume.
  try {
    if (typeof tracing.manualSpan === "function") {
      return tracing.manualSpan(name, sopts);
    }
    if (typeof tracing.startSpan === "function") {
      return tracing.startSpan(name, sopts);
    }
  } catch (e) {
    // SUBSTRATE-24 — tracer failures should not crash the agent's
    // method call; surface the first failure to the audit chain
    // (rate-limited) so operators get the signal.
    _emitFirstFailureAudit(auditImpl, "startSpan", e && e.message);
    return _noopSpan();
  }
  throw new AgentTraceError("agent-trace/bad-tracing",
    "startSpan: opts.tracing must expose manualSpan() (b.tracing.create()) " +
    "or startSpan() (raw OTel tracer); neither found");
}

function _noopSpan() {
  // Returned when the tracer threw — caller can still call
  // recordException / setStatus / end without further errors.
  return {
    end:             function () {},
    setStatus:       function () {},
    recordException: function () {},
    isNoop:          true,
  };
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

function _recordResult(span, result, error, auditImpl) {
  if (!span || typeof span !== "object") return;
  // SUBSTRATE-24 — surface first occurrence of each span-op failure
  // via audit so the operator gets the signal. Subsequent failures
  // stay silent (best-effort) per the operational spec.
  if (error) {
    if (typeof span.recordException === "function") {
      try { span.recordException(error); }
      catch (e) { _emitFirstFailureAudit(auditImpl, "recordException", e && e.message); }
    }
    if (typeof span.setStatus === "function") {
      try { span.setStatus({ code: 2, message: error.message || String(error) }); }
      catch (e) { _emitFirstFailureAudit(auditImpl, "setStatus", e && e.message); }
    }
  } else if (typeof span.setStatus === "function") {
    try { span.setStatus({ code: 1 }); }
    catch (e) { _emitFirstFailureAudit(auditImpl, "setStatus", e && e.message); }
  }
  if (typeof span.end === "function") {
    try { span.end(); }
    catch (e) { _emitFirstFailureAudit(auditImpl, "end", e && e.message); }
  }
}

// SUBSTRATE-17 — deterministic sampling per W3C Trace Context §3.2.3.1.
// `Math.random` makes child-vs-parent sampling decisions non-coherent:
// a parent span sampled OUT can still have child spans sampled IN,
// producing orphaned spans operators can't correlate. Hashing the
// 16-byte trace-id deterministically routes every span in a trace to
// the same decision. When traceId is absent (start of a trace at
// request-entry boundary) we still use Math.random as the seeding
// roll; downstream callers pass the resulting traceId so children
// inherit the decision.
function _shouldSample(globalRate, perMethod, method, traceId) {
  var rate = globalRate;
  if (typeof method === "string" && Object.prototype.hasOwnProperty.call(perMethod, method)) {
    var r = perMethod[method];
    if (typeof r === "number" && isFinite(r) && r >= 0 && r <= 1) rate = r;
  }
  if (rate <= 0) return false;
  if (rate >= 1) return true;
  if (typeof traceId === "string" && /^[0-9a-fA-F]{32}$/.test(traceId)) {
    // Use the low 32 bits of the trace-id as the sampling roll
    // (W3C-compatible). Hash modulo 1e9 → divide by 1e9 puts the
    // result in [0,1) deterministically.
    var lo = parseInt(traceId.slice(-8), 16);                                                          // allow:raw-byte-literal — low 32 bits of trace-id hex
    var roll = (lo >>> 0) / 0x100000000;                                                                // allow:raw-byte-literal — 2^32 normalization divisor
    return roll < rate;
  }
  // No trace-id supplied — start of a new trace. Operators wire
  // shouldSample(method, ctx.traceId) on every downstream hop so
  // children inherit the decision deterministically.
  return Math.random() < rate;                                                                          // allow:math-random-noncrypto — start-of-trace seed only; downstream hops pass traceId for deterministic propagation
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
  _resetForTest:    function () { _failureAuditEmittedFor = Object.create(null); },
};
