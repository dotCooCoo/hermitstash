// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  validateOpts.assignOwnEnumerable(out, b);
  validateOpts.assignOwnEnumerable(out, o);
  return Object.freeze(out);
}

function fromRequest(req, opts) {
  opts = opts || {};
  validateOpts(opts, ["userKey", "tenantKey", "extra",
                      "trustedProxies", "forwardedHeaders", "clientIpResolver"],
               "flag.context.fromRequest");
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
  } else if (req.user && typeof req.user.id === "string") {
    tk = req.user.id;
  } else {
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
