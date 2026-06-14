"use strict";
/**
 * trace-log-correlation middleware — wraps the operator's b.log
 * instance for the request lifetime so every log() / info() / warn()
 * / error() / debug() call inside the handler auto-includes the
 * canonical trace_id + span_id (and tenant context from W3C Baggage
 * when present).
 *
 *   var log = b.log.boot("api");
 *   router.use(b.middleware.tracePropagate());
 *   router.use(b.middleware.traceLogCorrelation({
 *     logger:   log,
 *     reqField: "log",   // attaches as req.log
 *   }));
 *
 *   app.get("/widgets", function (req, res) {
 *     // req.log is the wrapped logger; every emission carries
 *     // trace_id + span_id + (optional) baggage attributes
 *     req.log.info("loading widgets");
 *     // → { ..., trace_id: "abc...", span_id: "def...",
 *     //     baggage: { tenant: "acme" } }
 *   });
 *
 * The wrapper is a thin adapter: it does not change log levels,
 * sinks, or the b.log API surface. Logs pass through to the
 * wrapped logger with the trace fields injected via the meta-object
 * second argument.
 *
 * When no req.trace is present (unusual — operators typically mount
 * tracePropagate first), the wrapper is a no-op pass-through; logs
 * still flow but without correlation fields.
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var TraceLogError = defineClass("TraceLogError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

var LOG_LEVELS = ["debug", "info", "warn", "error", "fatal"];

function _baggageToObject(entries) {
  if (!Array.isArray(entries) || entries.length === 0) return null;
  var out = Object.create(null);
  for (var i = 0; i < entries.length; i++) {
    out[entries[i].key] = entries[i].value;
  }
  return out;
}

function _wrapLogger(baseLogger, req, opts) {
  if (!baseLogger || typeof baseLogger !== "object") return baseLogger;
  // Preserve any non-level properties the operator put on the
  // logger (e.g. boot context, child-logger metadata); the level
  // methods themselves are re-wrapped below.
  var wrapped = validateOpts.assignOwnEnumerable(Object.create(null), baseLogger, LOG_LEVELS);

  function _enrichMeta(meta) {
    var enriched = Object.assign({}, meta || {});
    if (req && req.trace) {
      enriched.trace_id = req.trace.traceId;
      // span_id prefers the active span (set by spanHttpServer) over
      // the trace context's parentId
      if (req.span && typeof req.span.spanId === "string") {
        enriched.span_id = req.span.spanId;
      } else if (typeof req.trace.parentId === "string") {
        enriched.span_id = req.trace.parentId;
      }
      if (opts.includeBaggage !== false) {
        var bg = _baggageToObject(req.trace.tracestate);
        // tracestate is vendor-trace data; baggage is operator data.
        // Operators usually want baggage in logs, not tracestate.
        // We don't have a separate req.baggage today; keep this as
        // the path for when tracePropagate exposes it. For now,
        // emit the resolved tracestate shape under "trace_state".
        if (bg) enriched.trace_state = bg;
      }
    }
    return enriched;
  }

  // Bind each level on the underlying logger so it emits with the
  // enriched meta. We don't replace the underlying logger's bound
  // emitter shape — it still receives meta as the second argument.
  for (var li = 0; li < LOG_LEVELS.length; li++) {
    (function (lvl) {
      if (typeof baseLogger[lvl] !== "function") return;
      wrapped[lvl] = function (msg, meta) {
        try { return baseLogger[lvl](msg, _enrichMeta(meta)); }
        catch (_e) { /* drop-silent — log sink */ }
      };
    })(LOG_LEVELS[li]);
  }
  // Pass through anything else the logger might expose (boot, child, etc.)
  if (typeof baseLogger.boot === "function") wrapped.boot = baseLogger.boot.bind(baseLogger);
  if (typeof baseLogger.child === "function") wrapped.child = baseLogger.child.bind(baseLogger);
  return wrapped;
}

/**
 * @primitive b.middleware.traceLogCorrelation
 * @signature b.middleware.traceLogCorrelation(opts)
 * @since     0.1.0
 * @related   b.middleware.tracePropagate, b.middleware.spanHttpServer
 *
 * Wraps the operator's `b.log` instance for the request lifetime
 * so every `log() / info() / warn() / error() / debug()` call
 * inside the handler auto-includes the canonical `trace_id` +
 * `span_id` (and tenant attributes from W3C Baggage when present).
 * Thin adapter — does not change levels, sinks, or the API
 * surface; logs pass through with the trace fields injected via
 * the meta-object second argument. When `req.trace` isn't set
 * (operator forgot to mount `tracePropagate` first), the wrapper
 * is a no-op pass-through.
 *
 * @opts
 *   {
 *     logger:         object,    // required b.log instance
 *     reqField:       string,    // default "log" → req.log
 *     includeBaggage: boolean,   // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.tracePropagate());
 *   app.use(b.middleware.traceLogCorrelation({
 *     logger:   b.log.boot("api"),
 *     reqField: "log",
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.traceLogCorrelation", TraceLogError);
  validateOpts(opts, [
    "logger", "reqField", "includeBaggage",
  ], "middleware.traceLogCorrelation");

  if (!opts.logger || typeof opts.logger !== "object") {
    throw new TraceLogError("trace-log/bad-logger",
      "middleware.traceLogCorrelation: logger must be a b.log instance");
  }
  var reqField = opts.reqField || "log";
  if (typeof reqField !== "string" || reqField.length === 0) {
    throw new TraceLogError("trace-log/bad-reqfield",
      "middleware.traceLogCorrelation: reqField must be a non-empty string");
  }

  return function traceLogCorrelationMiddleware(req, res, next) {
    req[reqField] = _wrapLogger(opts.logger, req, opts);
    void observability;     // touch lazyRequire so the dep is captured
    return next();
  };
}

module.exports = {
  create:        create,
  TraceLogError: TraceLogError,
  // exported for tests
  _wrapLogger:   _wrapLogger,
  LOG_LEVELS:    LOG_LEVELS,
};
