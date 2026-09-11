// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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

  if (pageOpts.auditAction  === undefined) pageOpts.auditAction  = "system.http.error";
  if (pageOpts.defaultFormat === undefined) pageOpts.defaultFormat = "json";

  if (pageOpts.showStack === undefined && pageOpts.exposeStackInDev !== undefined) {
    pageOpts.showStack = !!pageOpts.exposeStackInDev;
  }

  var pageHandler = errorPage.create(pageOpts);

  return function errorHandler(err, req, res, _next) {
    pageHandler(err, req, res);
  };
}

module.exports = { create: create };
