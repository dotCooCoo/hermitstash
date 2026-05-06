"use strict";
/**
 * trace-propagate middleware — consumes the inbound `traceparent`
 * header per W3C Trace Context (https://www.w3.org/TR/trace-context-1/)
 * and stamps `req.trace = { traceId, parentId, sampled, hadUpstream }`
 * for downstream handlers + propagation into outbound HTTP calls.
 *
 *   router.use(b.middleware.tracePropagate({
 *     generateIfMissing: true,   // default — synthesise when absent
 *     auditOnMissing:    true,   // emit `system.trace.synthesised` event
 *     setResponseHeader: true,   // echo the resolved traceparent on res
 *   }));
 *
 *   app.get("/widgets", function (req, res) {
 *     // req.trace.traceId is the canonical id for this request
 *     b.observability.event("widgets.request", 1, {
 *       [b.observability.SEMCONV.HTTP_REQUEST_METHOD]: req.method,
 *     });
 *     // Propagate to an upstream call:
 *     fetch(upstreamUrl, {
 *       headers: {
 *         traceparent: b.observability.traceContext.build({
 *           traceId:  req.trace.traceId,
 *           parentId: b.observability.traceContext.newParentId(),
 *           sampled:  req.trace.sampled,
 *         }),
 *       },
 *     });
 *   });
 *
 * On bad / missing inbound traceparent:
 *   - generateIfMissing: true (default) → synthesise a fresh trace,
 *     stamp `hadUpstream: false` so downstream code knows this trace
 *     was originated locally
 *   - generateIfMissing: false → leave `req.trace = null`; downstream
 *     code that depends on a trace MUST handle the null case
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var TracePropagateError = defineClass("TracePropagateError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });
var audit = lazyRequire(function () { return require("../audit"); });

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "generateIfMissing", "auditOnMissing",
    "setResponseHeader", "audit",
  ], "middleware.tracePropagate");

  var generateIfMissing = opts.generateIfMissing !== false;     // default true
  var auditOnMissing    = opts.auditOnMissing === true;         // default false (every request that doesn't carry a trace is noisy)
  var setResponseHeader = opts.setResponseHeader === true;      // default false
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
            outcome:  "ok",
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
