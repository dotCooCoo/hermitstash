"use strict";
/**
 * Error-handler middleware — thin adapter over lib/error-page.
 *
 * Use this for the standard wiring path (`router.onError(b.middleware.
 * errorHandler())`). Constructs an error-page handler and forwards
 * the (err, req, res, next) router signature into it. Classification,
 * rendering, content negotiation, dev/prod gating, and audit
 * emission all live in `b.errorPage` — this file only wires the
 * router middleware convention plus the audit-action override that
 * preserves the `system.http.error` action name the framework's
 * audit log already uses for HTTP-layer failures.
 */
var errorPage = require("../error-page");

/**
 * @primitive b.middleware.errorHandler
 * @signature b.middleware.errorHandler(err, req, res, next)
 * @since     0.1.0
 * @related   b.errorPage.create
 *
 * Thin adapter over `lib/error-page`. Constructed via the factory
 * call `b.middleware.errorHandler(opts)`; the resulting middleware
 * has the `(err, req, res, next)` shape shown above. Forwards the
 * router signature into an errors-page handler.
 * Classification, rendering, content negotiation, and audit emission
 * live in `b.errorPage`; this middleware only sets the audit action
 * to `system.http.error` and defaults to JSON output (page-style
 * HTML negotiation is reachable via `b.errorPage.create` directly).
 *
 * @opts
 *   {
 *     auditAction:      string,             // default "system.http.error"
 *     defaultFormat:    "json"|"html"|"auto",// default "json"
 *     showStack:        boolean,            // dev-stack exposure
 *     exposeStackInDev: boolean,            // back-compat alias for showStack
 *     // ...all other b.errorPage.create opts forward unchanged
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.onError(b.middleware.errorHandler({ showStack: false }));
 */
function create(opts) {
  opts = opts || {};
  var pageOpts = Object.assign({}, opts);

  // Preserve the existing audit action name for HTTP-layer errors.
  if (pageOpts.auditAction  === undefined) pageOpts.auditAction  = "system.http.error";
  // The middleware path historically returned JSON regardless of Accept
  // (API-style). Page-style HTML rendering is reachable via the direct
  // errorPage.create() surface, where defaultFormat="auto" negotiates.
  if (pageOpts.defaultFormat === undefined) pageOpts.defaultFormat = "json";

  // Back-compat: middleware historically used `exposeStackInDev`;
  // errors-page uses `showStack`. Map when only the legacy name is set.
  if (pageOpts.showStack === undefined && pageOpts.exposeStackInDev !== undefined) {
    pageOpts.showStack = !!pageOpts.exposeStackInDev;
  }

  var pageHandler = errorPage.create(pageOpts);

  return function errorHandler(err, req, res, _next) {
    pageHandler(err, req, res);
  };
}

module.exports = { create: create };
