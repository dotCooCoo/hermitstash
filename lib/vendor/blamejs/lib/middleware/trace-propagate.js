// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var TracePropagateError = defineClass("TracePropagateError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });
var audit = lazyRequire(function () { return require("../audit"); });

/**
 * @primitive b.middleware.tracePropagate
 * @signature b.middleware.tracePropagate(opts)
 * @since     0.1.0
 * @related   b.middleware.traceLogCorrelation, b.middleware.spanHttpServer
 *
 * Consumes the inbound `traceparent` header per W3C Trace Context
 * and stamps `req.trace = { traceId, parentId, sampled,
 * hadUpstream, tracestate }` for downstream handlers and outbound
 * HTTP propagation. With `generateIfMissing: true` (default) the
 * middleware synthesizes a fresh trace when the inbound header is
 * absent or malformed, and stamps `hadUpstream: false` so downstream
 * code can tell locally-originated traces apart. `setResponseHeader:
 * true` echoes the resolved `traceparent` on the response so the
 * client sees what the server actually used.
 *
 * @opts
 *   {
 *     generateIfMissing: boolean,   // default true
 *     auditOnMissing:    boolean,   // default false
 *     setResponseHeader: boolean,   // default false
 *     audit:             boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.tracePropagate({
 *     generateIfMissing: true,
 *     setResponseHeader: true,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "generateIfMissing", "auditOnMissing",
    "setResponseHeader", "audit",
  ], "middleware.tracePropagate");

  var generateIfMissing = opts.generateIfMissing !== false;
  var auditOnMissing    = opts.auditOnMissing === true;
  var setResponseHeader = opts.setResponseHeader === true;
  var auditOn           = opts.audit !== false;

  return function tracePropagateMiddleware(req, res, next) {
    var tc = observability().traceContext;
    var inbound = req.headers && req.headers.traceparent;
    var parsed = (typeof inbound === "string") ? tc.parse(inbound) : null;
    var inboundTracestate = req.headers && req.headers.tracestate;
    var tracestateEntries = (typeof inboundTracestate === "string")
      ? tc.parseTracestate(inboundTracestate)
      : null;
    if (parsed) {
      req.trace = {
        traceId:     parsed.traceId,
        parentId:    parsed.parentId,
        sampled:     parsed.sampled,
        hadUpstream: true,
        tracestate:  tracestateEntries || [],
      };
    } else if (generateIfMissing) {
      req.trace = {
        traceId:     tc.newTraceId(),
        parentId:    tc.newParentId(),
        sampled:     true,
        hadUpstream: false,
        tracestate:  [],
      };
      if (auditOnMissing && auditOn) {
        try {
          audit().safeEmit({
            action:   "system.trace.synthesised",
            outcome:  "success",
            metadata: { route: req.url || "/", traceId: req.trace.traceId },
          });
        } catch (_e) { /* drop-silent — observability sink */ }
      }
    } else {
      req.trace = null;
    }

    if (setResponseHeader && req.trace && !res.headersSent) {
      try {
        res.setHeader("traceparent", tc.build({
          traceId:  req.trace.traceId,
          parentId: req.trace.parentId,
          sampled:  req.trace.sampled,
        }));
        if (req.trace.tracestate && req.trace.tracestate.length > 0) {
          res.setHeader("tracestate", tc.buildTracestate(req.trace.tracestate));
        }
      } catch (_e) { /* drop-silent — header set best-effort */ }
    }
    return next();
  };
}

module.exports = {
  create:               create,
  TracePropagateError:  TracePropagateError,
};
