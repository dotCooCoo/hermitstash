"use strict";
/**
 * flag-context middleware — extracts an OpenFeature evaluation context
 * onto the request so downstream handlers and multiple flag clients
 * can read a consistent context without re-deriving it per call.
 *
 *   var attachCtx = b.middleware.flagContext({
 *     userKey: "x-user-id",                 // header to pull targetingKey from
 *     extractAttributes: function (req) {   // operator-supplied augmentation
 *       return { tenantId: req.tenantId, environment: process.env.NODE_ENV };
 *     },
 *   });
 *   router.use(attachCtx);
 *
 *   // Downstream:
 *   var ctx = req.flagCtx;                       // readonly Frozen object
 *   var enabled = b.flagClient.getBoolean("foo", ctx);
 *
 * The middleware does NOT evaluate flags — it only constructs the
 * context. Pair with `flag.middleware()` for the request-attached
 * convenience accessor; or pass `req.flagCtx` directly to a flag
 * client method for a more decoupled shape (e.g. when several flag
 * clients with different providers share the same context).
 */

var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var { defineClass } = require("../framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var contextMod = lazyRequire(function () { return require("../flag-evaluation-context"); });

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
    req.flagCtx = contextMod().fromRequest(req, fromReqOpts);
    return next();
  };
}

module.exports = { create: create };
