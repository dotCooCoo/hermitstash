// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var { defineClass } = require("../framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var contextMod = lazyRequire(function () { return require("../flag-evaluation-context"); });
var requestHelpers = lazyRequire(function () { return require("../request-helpers"); });

/**
 * @primitive b.middleware.flagContext
 * @signature b.middleware.flagContext(opts)
 * @since     0.1.0
 * @related   b.flag.create
 *
 * Extracts an OpenFeature evaluation context onto `req.flagCtx` so
 * downstream handlers and multiple flag clients read a consistent
 * context without re-deriving it per call. The middleware itself
 * does NOT evaluate flags — pair with `flag.middleware()` for the
 * request-attached accessor, or pass `req.flagCtx` directly to a
 * flag client method when several clients with different providers
 * share the same context. `userKey` (literal) takes precedence over
 * `userKeyHeader`; `tenantKeyHeader` augments with tenantId; the
 * operator-supplied `extractAttributes(req)` adds arbitrary fields.
 *
 * @opts
 *   {
 *     userKey:           string,
 *     userKeyHeader:     string,
 *     tenantKeyHeader:   string,
 *     extractAttributes: function(req): object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.flagContext({
 *     userKeyHeader:    "x-user-id",
 *     extractAttributes: function (req) {
 *       return { environment: "prod" };
 *     },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "userKey", "userKeyHeader", "extractAttributes", "tenantKeyHeader",
    "trustedProxies", "forwardedHeaders", "clientIpResolver",
  ], "middleware.flagContext");
  if (opts.extractAttributes != null && typeof opts.extractAttributes !== "function") {
    throw new FlagError("flag/bad-opt",
      "flagContext: extractAttributes must be a function");
  }
  var userKeyHeader = (typeof opts.userKeyHeader === "string" && opts.userKeyHeader.length > 0)
    ? opts.userKeyHeader.toLowerCase()
    : null;
  var tenantKeyHeader = (typeof opts.tenantKeyHeader === "string" && opts.tenantKeyHeader.length > 0)
    ? opts.tenantKeyHeader.toLowerCase()
    : null;
  var explicitUserKey = (typeof opts.userKey === "string" && opts.userKey.length > 0)
    ? opts.userKey
    : null;
  var declaredTrust = opts.trustedProxies !== undefined ||
                      opts.forwardedHeaders !== undefined ||
                      opts.clientIpResolver !== undefined;
  var trustedIp = declaredTrust ? requestHelpers().trustedClientIp({
    trustedProxies:   opts.trustedProxies,
    forwardedHeaders: opts.forwardedHeaders,
    clientIpResolver: opts.clientIpResolver,
  }) : null;

  return function flagContextMiddleware(req, res, next) {
    var headers = req.headers || {};
    var headerKey = userKeyHeader && typeof headers[userKeyHeader] === "string"
      ? headers[userKeyHeader]
      : null;
    var fromReqOpts = {};
    if (explicitUserKey)            fromReqOpts.userKey = explicitUserKey;
    else if (headerKey)             fromReqOpts.userKey = headerKey;
    var augment = {};
    if (typeof opts.extractAttributes === "function") {
      try {
        var extra = opts.extractAttributes(req);
        if (extra && typeof extra === "object") augment = extra;
      } catch (_e) { /* drop-silent on extraction error */ }
    }
    if (tenantKeyHeader && typeof headers[tenantKeyHeader] === "string") {
      augment.tenantId = headers[tenantKeyHeader];
    }
    fromReqOpts.extra = augment;
    if (trustedIp) fromReqOpts.clientIpResolver = trustedIp.resolve;
    req.flagCtx = contextMod().fromRequest(req, fromReqOpts);
    return next();
  };
}

module.exports = { create: create };
