// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var lazyRequire = require("../lazy-require");
var cookies = require("../cookies");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var codepointClass = require("../codepoint-class");
var session = lazyRequire(function () { return require("../session"); });
var audit   = lazyRequire(function () { return require("../audit"); });

function _readCookie(cookieHeader, name) {
  if (!cookieHeader || typeof cookieHeader !== "string") return null;
  var jar = cookies.parse(cookieHeader);
  return Object.prototype.hasOwnProperty.call(jar, name) ? jar[name] : null;
}

function _readBearer(authHeader, scheme) {
  if (!authHeader || typeof authHeader !== "string") return null;
  var schemeTok = (typeof scheme === "string" && scheme.length > 0) ? scheme : "Bearer";
  // allow:dynamic-regex — schemeTok is RegExp-escaped via codepointClass.escapeRegExp,
  var m = authHeader.match(new RegExp("^" + codepointClass.escapeRegExp(schemeTok) + "\\s+(\\S.*)$", "i"));
  return m ? m[1].trim() : null;
}

/**
 * @primitive b.middleware.attachUser
 * @signature b.middleware.attachUser(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.requireAuth, b.middleware.bearerAuth, b.session.verify
 *
 * Populates `req.user` and `req.session` from a verified session
 * token. Constructed via `b.middleware.attachUser(opts)`; the
 * resulting middleware has the `(req, res, next)` shape shown
 * above. Tries the configured cookie first, then `Authorization:
 * Bearer <token>`. Sealed cookies (vault-unwrapped) are supported so
 * the cookie isn't reachable via curl-with-arbitrary-cookies. The
 * framework can't know the operator's user schema; `userLoader`
 * receives the verified session and returns the user record. Always
 * calls `next()` — gating decisions live in
 * `b.middleware.requireAuth`. Optional fingerprint-drift / IP-UA pin
 * / anomaly-score enforcement threads through `session.verify`.
 *
 * @opts
 *   {
 *     userLoader:              async function(session): user|null,  // required
 *     cookieName:              string,    // default "blamejs_session"
 *     tokenFrom:               "both"|"cookie"|"header",  // default "both"
 *     bearerScheme:            string,    // default "Bearer" (RFC 6750); set "Token"/"DPoP"/etc. for a gateway scheme
 *     tokenExtractor:          function,  // (req) → token|null; fully owns header extraction when supplied
 *     sealed:                  boolean,
 *     vault:                   object,    // required when sealed
 *     requireFingerprintMatch: boolean,
 *     maxAnomalyScore:         number,
 *     scorer:                  function,
 *     fingerprintFields:       Array<string|function>,  // the basis the binding is computed from; defaults to session.verify's
 *     trustedProxies:          Array<string>,           // CIDRs whose forwarded-for is believed when resolving the client address
 *     clientIpResolver:        function,                // own the client-address resolution outright
 *     audit:                   boolean,   // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.attachUser({
 *     userLoader: async function (session) {
 *       return { id: session.userId, name: "alice" };
 *     },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "cookieName", "tokenFrom", "sealed", "vault", "userLoader", "audit",
    "requireFingerprintMatch", "maxAnomalyScore", "scorer",
    "bearerScheme", "tokenExtractor",
    "fingerprintFields", "trustedProxies", "clientIpResolver",
  ], "middleware.attachUser");
  if (opts.fingerprintFields !== undefined && opts.fingerprintFields !== null &&
      !Array.isArray(opts.fingerprintFields)) {
    throw new Error("middleware.attachUser: fingerprintFields must be an array of " +
      "field names or functions, got " + JSON.stringify(opts.fingerprintFields));
  }
  if (opts.trustedProxies !== undefined && opts.trustedProxies !== null &&
      !Array.isArray(opts.trustedProxies)) {
    throw new Error("middleware.attachUser: trustedProxies must be an array of CIDRs, got " +
      JSON.stringify(opts.trustedProxies));
  }
  if (opts.clientIpResolver !== undefined && opts.clientIpResolver !== null &&
      typeof opts.clientIpResolver !== "function") {
    throw new Error("middleware.attachUser: clientIpResolver must be a function, got " +
      JSON.stringify(opts.clientIpResolver));
  }
  if (typeof opts.userLoader !== "function") {
    throw new Error("middleware.attachUser: opts.userLoader is required " +
      "(async function (verifiedSession) → user | null)");
  }
  validateOpts.optionalNonEmptyString(opts.bearerScheme,
    "middleware.attachUser: opts.bearerScheme (the Authorization scheme token, " +
    "e.g. \"Bearer\", \"Token\", \"DPoP\")");
  validateOpts.optionalFunction(opts.tokenExtractor,
    "middleware.attachUser: opts.tokenExtractor (req) → token | null");
  var cookieName = opts.cookieName || "blamejs_session";
  var tokenFrom  = opts.tokenFrom  || "both";
  var auditOn    = opts.audit !== false;
  var sealed     = !!opts.sealed;
  var bearerScheme   = opts.bearerScheme || "Bearer";
  var tokenExtractor = typeof opts.tokenExtractor === "function" ? opts.tokenExtractor : null;
  var verifyOpts = {
    requireFingerprintMatch: opts.requireFingerprintMatch === true,
    maxAnomalyScore:         (typeof opts.maxAnomalyScore === "number") ? opts.maxAnomalyScore : null,
    scorer:                  (typeof opts.scorer === "function") ? opts.scorer : null,
    fingerprintFields:       Array.isArray(opts.fingerprintFields) ? opts.fingerprintFields.slice() : null,
    trustedProxies:          opts.trustedProxies || null,
    clientIpResolver:        (typeof opts.clientIpResolver === "function") ? opts.clientIpResolver : null,
  };
  if (sealed && (!opts.vault || typeof opts.vault.unseal !== "function")) {
    throw new Error("middleware.attachUser: opts.sealed requires opts.vault " +
      "with a .unseal method (typically b.vault)");
  }
  var cookieJar = sealed ? cookies.create({ vault: opts.vault }) : null;

  return async function attachUser(req, res, next) {
    req.user = null;
    req.session = null;

    var token = null;
    if (tokenFrom === "cookie" || tokenFrom === "both") {
      token = sealed
        ? cookieJar.readSealed(req, cookieName)
        : _readCookie(req.headers && req.headers.cookie, cookieName);
    }
    if (!token && (tokenFrom === "header" || tokenFrom === "both") &&
        !req._bearerAuthHandled) {
      if (tokenExtractor) {
        token = tokenExtractor(req) || null;
      } else {
        token = _readBearer(req.headers && req.headers.authorization, bearerScheme);
      }
    }
    if (!token) return next();

    var verified;
    try {
      var vo = {
        req: req,
        requireFingerprintMatch: verifyOpts.requireFingerprintMatch,
        maxAnomalyScore:         verifyOpts.maxAnomalyScore,
        scorer:                  verifyOpts.scorer,
      };
      if (verifyOpts.fingerprintFields) vo.fingerprintFields = verifyOpts.fingerprintFields;
      if (verifyOpts.trustedProxies)    vo.trustedProxies    = verifyOpts.trustedProxies;
      if (verifyOpts.clientIpResolver)  vo.clientIpResolver  = verifyOpts.clientIpResolver;
      verified = await session().verify(token, vo);
    } catch (_e) {
      return next();
    }
    if (!verified) return next();

    var user;
    try {
      user = await opts.userLoader(verified);
    } catch (e) {
      if (auditOn) {
        try {
          audit().emit({
            action:   "auth.session.user_loader_threw",
            outcome:  "failure",
            actor:    requestHelpers.extractActorContext(req, { userId: verified.userId }),
            reason:   (e && e.message) || String(e),
          });
        } catch (_ignored) { /* audit best-effort */ }
      }
      return next();
    }
    if (!user) {
      if (auditOn) {
        try {
          audit().emit({
            action:   "auth.session.user_unloadable",
            outcome:  "failure",
            actor:    requestHelpers.extractActorContext(req, { userId: verified.userId }),
          });
        } catch (_ignored) { /* audit best-effort */ }
      }
      return next();
    }

    req.user = user;
    req.session = verified;
    return next();
  };
}

module.exports = {
  create:       create,
  _readCookie:  _readCookie,
  _readBearer:  _readBearer,
};
