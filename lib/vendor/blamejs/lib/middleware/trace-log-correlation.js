// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  var wrapped = validateOpts.assignOwnEnumerable(Object.create(null), baseLogger, LOG_LEVELS);

  function _enrichMeta(meta) {
    var enriched = Object.assign({}, meta || {});
    if (req && req.trace) {
      enriched.trace_id = req.trace.traceId;
      if (req.span && typeof req.span.spanId === "string") {
        enriched.span_id = req.span.spanId;
      } else if (typeof req.trace.parentId === "string") {
        enriched.span_id = req.trace.parentId;
      }
      if (opts.includeBaggage !== false) {
        var bg = _baggageToObject(req.trace.tracestate);
        if (bg) enriched.trace_state = bg;
      }
    }
    return enriched;
  }

  for (var li = 0; li < LOG_LEVELS.length; li++) {
    (function (lvl) {
      if (typeof baseLogger[lvl] !== "function") return;
      wrapped[lvl] = function (msg, meta) {
        try { return baseLogger[lvl](msg, _enrichMeta(meta)); }
        catch (_e) { /* drop-silent — log sink */ }
      };
    })(LOG_LEVELS[li]);
  }
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
    void observability;
    return next();
  };
}

module.exports = {
  create:        create,
  TraceLogError: TraceLogError,
  _wrapLogger:   _wrapLogger,
  LOG_LEVELS:    LOG_LEVELS,
};
