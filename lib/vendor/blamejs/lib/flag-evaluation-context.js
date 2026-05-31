"use strict";
/**
 * Flag evaluation context — the operator-supplied object describing
 * the subject of a flag evaluation: targeting key, user attributes,
 * tenant id, environment, custom attributes.
 *
 * Per the OpenFeature specification:
 *   - `targetingKey` is the canonical identity for percentage-bucket
 *     stickiness (so a 50% rollout consistently picks the SAME 50%
 *     of users across re-evaluations).
 *   - All other attributes flow through targeting rules.
 *
 * The framework's helper produces a frozen, normalised context object.
 * Operators compose contexts incrementally: start from `fromRequest`
 * (extracts user / tenant / locale from req), augment with `merge`,
 * then evaluate.
 */

var nodeCrypto    = require("node:crypto");
var validateOpts  = require("./validate-opts");
var lazyRequire   = require("./lazy-require");
var { defineClass } = require("./framework-error");
var FlagError = defineClass("FlagError", { alwaysPermanent: true });

var bCrypto = lazyRequire(function () { return require("./crypto"); });

function _normalize(input, label) {
  if (input == null) return {};
  if (typeof input !== "object" || Array.isArray(input)) {
    throw new FlagError("flag/bad-context",
      (label || "context") + ": must be a plain object");
  }
  var out = {};
  for (var key in input) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) continue;
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;                                          // poisoned-keys defense
    }
    out[key] = input[key];
  }
  return out;
}

function create(input) {
  var normalised = _normalize(input, "create");
  if (normalised.targetingKey != null &&
      typeof normalised.targetingKey !== "string") {
    throw new FlagError("flag/bad-context",
      "create: targetingKey must be a string");
  }
  return Object.freeze(normalised);
}

function merge(base, overlay) {
  var b = _normalize(base, "merge.base");
  var o = _normalize(overlay, "merge.overlay");
  var out = {};
  for (var k1 in b) {
    if (Object.prototype.hasOwnProperty.call(b, k1)) out[k1] = b[k1];
  }
  for (var k2 in o) {
    if (Object.prototype.hasOwnProperty.call(o, k2)) out[k2] = o[k2];
  }
  return Object.freeze(out);
}

function fromRequest(req, opts) {
  opts = opts || {};
  validateOpts(opts, ["userKey", "tenantKey", "extra"], "flag.context.fromRequest");
  if (!req || typeof req !== "object") {
    return create({});
  }
  var ctx = {};
  if (req.user) {
    if (typeof req.user.id === "string")    ctx.userId = req.user.id;
    if (typeof req.user.role === "string")  ctx.role   = req.user.role;
    if (typeof req.user.email === "string") ctx.email  = req.user.email;
    if (req.user.tenantId != null)          ctx.tenantId = req.user.tenantId;
  }
  var headers = req.headers || {};
  if (typeof headers["accept-language"] === "string") {
    ctx.locale = headers["accept-language"].split(",")[0].split(";")[0].trim();
  }
  if (typeof headers["user-agent"] === "string") {
    ctx.userAgent = headers["user-agent"];
  }
  // Targeting key: prefer explicit userKey opt, then user.id, then a
  // request-stable hash of (clientIp + userAgent) for anonymous flows.
  var tk = null;
  if (typeof opts.userKey === "string" && opts.userKey.length > 0) {
    tk = opts.userKey;
  } else if (req.user && typeof req.user.id === "string") {
    tk = req.user.id;
  } else {
    var ip = (typeof headers["x-forwarded-for"] === "string" &&
              headers["x-forwarded-for"].split(",")[0].trim()) ||
             (req.connection && req.connection.remoteAddress) || "";
    var ua = headers["user-agent"] || "";
    tk = "anon:" + bCrypto().sha3Hash(ip + ":" + ua).slice(0, 16);   // base16 prefix len
  }
  ctx.targetingKey = tk;

  if (opts.extra && typeof opts.extra === "object") {
    for (var k in opts.extra) {
      if (Object.prototype.hasOwnProperty.call(opts.extra, k)) {
        if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
        ctx[k] = opts.extra[k];
      }
    }
  }
  return create(ctx);
}

// Percentage-bucket helper — deterministic hash of (targetingKey +
// flagKey) into [0, 100) for percentage-based rollouts.
function bucketOf(targetingKey, flagKey) {
  if (typeof targetingKey !== "string" || typeof flagKey !== "string" ||
      targetingKey.length === 0 || flagKey.length === 0) {
    return 0;
  }
  var digest = nodeCrypto.createHash("sha3-512")
    .update(flagKey + ":" + targetingKey).digest();
  // Use first 4 bytes as a uint32, then mod 10000 → 0.00-99.99 with
  // sub-percent granularity.
  var n = digest.readUInt32BE(0);
  return (n % 10000) / 100;                                 // bucket-precision divisor
}

module.exports = {
  create:       create,
  merge:        merge,
  fromRequest:  fromRequest,
  bucketOf:     bucketOf,
  FlagError:    FlagError,
};
