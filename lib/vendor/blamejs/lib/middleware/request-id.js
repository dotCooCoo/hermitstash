// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("../constants");
var { generateToken } = require("../crypto");
var guardRegex = require("../guard-regex");
var validateOpts = require("../validate-opts");
var log = require("../log");
var { defineClass } = require("../framework-error");

var RequestIdError = defineClass("RequestIdError", { alwaysPermanent: true });

var DEFAULT_FORMAT = /^[A-Za-z0-9._-]{8,128}$/;
var MAX_INBOUND_LEN = C.BYTES.bytes(256);

/**
 * @primitive b.middleware.requestId
 * @signature b.middleware.requestId(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.requestLog, b.middleware.traceLogCorrelation
 *
 * Sets a stable correlation id on every request. Constructed via
 * the factory call `b.middleware.requestId(opts)`; the resulting
 * middleware has the `(req, res, next)` shape shown above.
 * Propagates a trusted inbound `X-Request-Id` (or operator-named
 * header) when it matches the format regex; otherwise generates a
 * fresh 16-byte hex token. The id lands on `req.requestId` and on
 * the response header so downstream services + the framework's
 * audit log can correlate the request across hops. Mount FIRST in
 * the chain — every later primitive expects `req.requestId` to
 * be present for log lines and audit-record metadata.
 *
 * Pass `asyncContext: true` to additionally bind the id into the framework's
 * AsyncLocalStorage scope so `b.log.getRequestId()` (and every
 * `b.log.create`-built logger) returns it inside awaited route-handler code,
 * not just on `req.requestId`. The `b.router` dispatch model is boolean-`next`
 * — the route handler runs after this middleware returns — so the binding uses
 * `AsyncLocalStorage.enterWith` (it persists forward through the awaited
 * chain) rather than a callback wrap (which would close before the handler
 * runs). Each request runs in its own async context, so the binding is
 * request-scoped.
 *
 * `formatRegex` is matched against the inbound header on every request.
 * `create` throws `RequestIdError` with `request-id/bad-format-regex` when it
 * is not a RegExp, `request-id/unsafe-pattern` when `b.guardRegex.assertSafe`
 * refuses it, and `request-id/stateful-pattern` when it carries the `g` or
 * `y` flag. A `trustUpstream` that is not a boolean throws
 * `request-id/bad-opt`, so a deployment that meant to stop trusting the
 * inbound header is refused rather than going on trusting it.
 *
 * @opts
 *   {
 *     headerName:    string,    // default "X-Request-Id"
 *     trustUpstream: boolean,   // default true; false → always re-mint
 *     formatRegex:   RegExp,    // default /^[A-Za-z0-9._-]{8,128}$/
 *     asyncContext:  boolean,   // default false; true → bind into b.log ALS for awaited handler code
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.requestId({ asyncContext: true }));
 *   app.get("/health", async function (req, res) {
 *     await somethingAsync();
 *     res.end(b.log.getRequestId());   // → the request's id, even after await
 *   });
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "headerName", "trustUpstream", "formatRegex", "asyncContext",
  ], "middleware.requestId");
  var headerName = (opts.headerName || "X-Request-Id");
  var headerNameLower = headerName.toLowerCase();
  validateOpts.optionalBoolean(opts.trustUpstream,
    "middleware.requestId: opts.trustUpstream (whether an id supplied by the caller is " +
    "carried through rather than replaced; a value that is not a boolean was read as true, " +
    "so a deployment that meant to stop trusting the header went on trusting it)",
    RequestIdError, "request-id/bad-opt");
  var trustUpstream = opts.trustUpstream !== false;
  var format = DEFAULT_FORMAT;
  if (opts.formatRegex !== undefined && opts.formatRegex !== null) {
    if (!(opts.formatRegex instanceof RegExp)) {
      throw new RequestIdError("request-id/bad-format-regex",
        "middleware.requestId: formatRegex must be a RegExp; got " + typeof opts.formatRegex);
    }
    guardRegex.assertSafe(opts.formatRegex, "middleware.requestId: formatRegex",
      RequestIdError, "request-id/unsafe-pattern");
    guardRegex.assertStateless(opts.formatRegex, "middleware.requestId: formatRegex",
      RequestIdError, "request-id/stateful-pattern");
    format = opts.formatRegex;
  }
  var asyncContext = opts.asyncContext === true;

  return function requestId(req, res, next) {
    var inbound = req.headers && req.headers[headerNameLower];
    var id;
    if (trustUpstream && typeof inbound === "string" &&
        inbound.length > 0 && inbound.length <= MAX_INBOUND_LEN &&
        format.test(inbound)) {
      id = inbound;
    } else {
      id = generateToken(C.BYTES.bytes(16));
    }
    req.requestId = id;
    if (typeof res.setHeader === "function") {
      res.setHeader(headerName, id);
    }
    if (asyncContext) {
      log.enterRequestId(id);
    }
    next();
  };
}

module.exports = { create: create, RequestIdError: RequestIdError };
