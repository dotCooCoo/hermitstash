"use strict";
/**
 * Error-handler middleware — thin adapter over lib/errors-page.
 *
 * Use this for the standard wiring path (`router.onError(b.middleware.
 * errorHandler())`). Constructs an errors-page handler and forwards
 * the (err, req, res, next) router signature into it. All classification,
 * rendering, content negotiation, dev/prod gating, and audit emission
 * lives in lib/errors-page — this file only wires the middleware
 * convention plus the audit-action override that preserves the
 * 'system.http.error' action name the framework's audit log already
 * uses for HTTP-layer failures.
 *
 * Options forward to errors-page.create with one default override:
 *   auditAction:        "system.http.error"   (vs errors-page default "request.error")
 *
 * Plus a back-compat alias:
 *   exposeStackInDev:   forwards to opts.showStack (true|false)
 */
var errorPage = require("../error-page");

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
