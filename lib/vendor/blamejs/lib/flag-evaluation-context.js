// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.flag.context
 * @nav        Tools
 * @title      Flag context
 * @order      101
 *
 * @intro
 *   The evaluation context a flag decision is made against: the principal
 *   the request acts for, the attributes a targeting rule reads, and the
 *   targeting key that places the principal in a percentage rollout.
 *
 * @card
 *   Build the evaluation context for a flag decision from a request, and
 *   merge operator-supplied attributes into it.
 */

var nodeCrypto    = require("node:crypto");
var pick          = require("./pick");
var validateOpts  = require("./validate-opts");
var lazyRequire   = require("./lazy-require");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var bCrypto = lazyRequire(function () { return require("./crypto"); });
var requestHelpers = lazyRequire(function () { return require("./request-helpers"); });

function _normalize(input, label) {
  if (input == null) return {};
  if (typeof input !== "object" || Array.isArray(input)) {
    throw new FlagError("flag/bad-context",
      (label || "context") + ": must be a plain object");
  }
  var out = {};
  for (var key in input) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) continue;
    if (pick.isPoisonedKey(key)) {
      continue;
    }
    out[key] = input[key];
  }
  return out;
}

function _rawIdentity(actor) {
  var present = requestHelpers().actorIdentityFields(actor);
  return present.length === 0 ? undefined : present[0].value;
}

/**
 * @primitive b.flag.context.create
 * @signature b.flag.context.create(input?)
 * @since     0.7.111
 * @status    stable
 * @related   b.flag.context.merge, b.flag.context.fromRequest
 *
 * Freeze an operator-built evaluation context. Copies the own enumerable keys
 * of `input`, dropping any key that would reach a prototype, and returns the
 * result frozen. Raises `flag/bad-context` when `input` is not a plain object
 * or when `targetingKey` is present and not a string.
 *
 * @example
 *   var b = require("blamejs");
 *   var ctx = b.flag.context.create({ targetingKey: "alice", role: "admin" });
 *   ctx.role;                 // → "admin"
 *   Object.isFrozen(ctx);     // → true
 */
function create(input) {
  var normalised = _normalize(input, "create");
  if (normalised.targetingKey != null &&
      typeof normalised.targetingKey !== "string") {
    throw new FlagError("flag/bad-context",
      "create: targetingKey must be a string");
  }
  return Object.freeze(normalised);
}

/**
 * @primitive b.flag.context.merge
 * @signature b.flag.context.merge(base, overlay)
 * @since     0.7.111
 * @status    stable
 * @related   b.flag.context.create, b.flag.context.fromRequest
 *
 * Layer one evaluation context over another and freeze the result. A key
 * present in `overlay` wins; a key only in `base` is carried through. Both
 * sides are read for own enumerable keys alone, so neither can reach a
 * prototype.
 *
 * @example
 *   var b = require("blamejs");
 *   var ctx = b.flag.context.merge({ role: "guest", locale: "en" },
 *                                  { role: "admin" });
 *   ctx.role;     // → "admin"
 *   ctx.locale;   // → "en"
 */
function merge(base, overlay) {
  var b = _normalize(base, "merge.base");
  var o = _normalize(overlay, "merge.overlay");
  var out = {};
  validateOpts.assignOwnEnumerable(out, b);
  validateOpts.assignOwnEnumerable(out, o);
  return Object.freeze(out);
}

/**
 * @primitive b.flag.context.fromRequest
 * @signature b.flag.context.fromRequest(req, opts?)
 * @since     0.7.111
 * @status    stable
 * @related   b.flag.context.create, b.flag.context.merge, b.requestHelpers.actorIdentityKey
 *
 * Build the evaluation context for a flag decision from a request. Reads the
 * principal from `req.user`, the locale from `Accept-Language` and the agent
 * from `User-Agent`, and returns a frozen context carrying `targetingKey`
 * alongside `userId`, `role`, `email`, `tenantId`, `locale` and `userAgent`
 * where the request supplies them. A targeting rule reads any path through
 * that context, so `attribute: "role"` resolves `role`.
 *
 * `targetingKey` places the principal in a percentage rollout and separates
 * one principal's cached decision from another's. It is
 * `b.requestHelpers.actorIdentityKey` of the actor, which tags the field the
 * name came from, so `{ id: "x" }` and `{ sub: "x" }` are two principals.
 * `opts.userKey` replaces it outright. An actor carrying no name that resolver
 * reads, and an unauthenticated request, are keyed by the client address
 * through `b.requestHelpers.trustedClientIp`, so a forwarded header moves that
 * key only where the operator declared the proxy it arrives through.
 *
 * @opts
 *   userKey:          string,     // use this as the targetingKey verbatim
 *   actorKey:         function,   // (actor) → the name, where the actor's shape is the operator's
 *   tenantKey:        string,     // overrides the tenant read from the actor
 *   extra:            object,     // merged into the context
 *   trustedProxies:   string[],   // CIDRs whose forwarded headers are honored
 *   forwardedHeaders: string[],   // named forwarded headers to read
 *   clientIpResolver: function,   // (req) → the client address
 *
 * @example
 *   var b = require("blamejs");
 *   var ctx = b.flag.context.fromRequest({
 *     user:    { sub: "alice", role: "admin" },
 *     headers: { "accept-language": "en-GB,en;q=0.9" },
 *   });
 *   ctx.userId;   // → "alice"
 *   ctx.role;     // → "admin"
 *   ctx.locale;   // → "en-GB"
 */
function fromRequest(req, opts) {
  opts = opts || {};
  validateOpts(opts, ["userKey", "tenantKey", "extra", "actorKey",
                      "trustedProxies", "forwardedHeaders", "clientIpResolver"],
               "flag.context.fromRequest");
  validateOpts.optionalFunction(opts.actorKey, "flag.context.fromRequest: opts.actorKey",
                                FlagError, "flag/bad-context");
  if (!req || typeof req !== "object") {
    return create({});
  }
  var ctx = {};
  if (req.user) {
    var named = _rawIdentity(req.user);
    if (named !== undefined)                ctx.userId = named;
    if (typeof req.user.role === "string")  ctx.role   = req.user.role;
    if (typeof req.user.email === "string") ctx.email  = req.user.email;
    if (req.user.tenantId != null)          ctx.tenantId = req.user.tenantId;
  }
  if (typeof opts.tenantKey === "string" && opts.tenantKey.length > 0) {
    ctx.tenantId = opts.tenantKey;
  }
  var headers = req.headers || {};
  if (typeof headers["accept-language"] === "string") {
    ctx.locale = headers["accept-language"].split(",")[0].split(";")[0].trim();
  }
  if (typeof headers["user-agent"] === "string") {
    ctx.userAgent = headers["user-agent"];
  }
  var tk = null;
  if (typeof opts.userKey === "string" && opts.userKey.length > 0) {
    tk = opts.userKey;
  } else if (req.user) {
    var keyed;
    try { keyed = requestHelpers().actorIdentityKey(req.user, { actorKey: opts.actorKey }); }
    catch (_e) { keyed = null; }
    if (typeof keyed === "string" && keyed !== requestHelpers().ANONYMOUS_ACTOR_KEY) {
      tk = keyed;
    }
  }
  if (tk === null) {
    var ip = requestHelpers().trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      forwardedHeaders: opts.forwardedHeaders,
      clientIpResolver: opts.clientIpResolver,
    }).resolve(req) || "";
    tk = "anon:" + bCrypto().sha3Hash(ip).slice(0, 16);
  }
  ctx.targetingKey = tk;

  if (opts.extra && typeof opts.extra === "object") {
    for (var k in opts.extra) {
      if (Object.prototype.hasOwnProperty.call(opts.extra, k)) {
        if (pick.isPoisonedKey(k)) continue;
        ctx[k] = opts.extra[k];
      }
    }
  }
  return create(ctx);
}

/**
 * @primitive b.flag.context.bucketOf
 * @signature b.flag.context.bucketOf(targetingKey, flagKey)
 * @since     0.7.111
 * @status    stable
 * @related   b.flag.context.fromRequest, b.flag.create
 *
 * Place a principal in a percentage rollout for one flag: a number from 0 up
 * to 100, two decimal places, from SHA3-512 over the flag key and the
 * targeting key together. The flag key participates, so a principal in the
 * first decile of one rollout is not thereby in the first decile of every
 * rollout. The same pair always answers the same number, and a rollout of
 * `p` percent admits the principal when the bucket is below `p`. Either
 * argument missing or empty answers 0.
 *
 * @example
 *   var b = require("blamejs");
 *   b.flag.context.bucketOf("alice", "beta");   // → 25.04
 *   b.flag.context.bucketOf("", "beta");        // → 0
 */
function bucketOf(targetingKey, flagKey) {
  if (typeof targetingKey !== "string" || typeof flagKey !== "string" ||
      targetingKey.length === 0 || flagKey.length === 0) {
    return 0;
  }
  var digest = nodeCrypto.createHash("sha3-512")
    .update(flagKey + ":" + targetingKey).digest();
  var n = digest.readUInt32BE(0);
  return (n % 10000) / 100;
}

module.exports = {
  create:       create,
  merge:        merge,
  fromRequest:  fromRequest,
  bucketOf:     bucketOf,
  FlagError:    FlagError,
};
