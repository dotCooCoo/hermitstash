// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Request-ID middleware. Propagates an existing X-Request-Id header
 * when present and well-formed; otherwise generates a fresh 32-hex
 * value. Sets req.requestId AND emits the same value as a response
 * header so downstream services + auditors can correlate.
 */
var C = require("../constants");
var { generateToken } = require("../crypto");
var validateOpts = require("../validate-opts");
var log = require("../log");

var DEFAULT_FORMAT = /^[A-Za-z0-9._-]{8,128}$/;
// Hard cap on inbound header length. The DEFAULT_FORMAT regex caps at
// 128 chars, but operator-supplied formatRegex values may be looser;
// length-bound the candidate before .test() so a multi-megabyte header
// can't drive ReDoS even against a careless operator pattern.
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
  var trustUpstream = opts.trustUpstream !== false;
  var format = opts.formatRegex || DEFAULT_FORMAT;
  var asyncContext = opts.asyncContext === true;

  return function requestId(req, res, next) {
    var inbound = req.headers && req.headers[headerNameLower];
    var id;
    if (trustUpstream && typeof inbound === "string" &&
        inbound.length > 0 && inbound.length <= MAX_INBOUND_LEN &&
        format.test(inbound)) {
      id = inbound;
    } else {
      id = generateToken(C.BYTES.bytes(16));  // 32 hex chars
    }
    req.requestId = id;
    if (typeof res.setHeader === "function") {
      res.setHeader(headerName, id);
    }
    // Bind into the log ALS so awaited handler code reads the id via
    // b.log.getRequestId(). enterWith (not run-with-callback) because the
    // boolean-next dispatcher runs the handler after this returns.
    if (asyncContext) {
      log.enterRequestId(id);
    }
    next();
  };
}

module.exports = { create: create };
