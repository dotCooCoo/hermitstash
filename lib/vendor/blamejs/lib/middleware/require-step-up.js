// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * require-step-up middleware — gate routes per RFC 9470 OAuth 2.0
 * Step-Up Authentication Challenge.
 *
 * Mounted AFTER attachUser / bearerAuth so the request carries the
 * already-verified token claims.
 *
 *   var sensitiveStepUp = b.middleware.requireStepUp({
 *     requirement: { acr: "high", maxAge: 300 },
 *     realm:       "billing-api",
 *   });
 *   router.use("/billing/transfer", sensitiveStepUp);
 *
 * Failure shape (per RFC 9470 §3):
 *   401 Unauthorized
 *   WWW-Authenticate: Bearer error="insufficient_user_authentication",
 *     error_description="...", acr_values="high", max_age="300"
 *   Content-Type: application/json
 *   { "error": "insufficient_user_authentication", "error_description": "..." }
 *
 * Operators with their own elevation grants pass `acceptGrant: true`
 * and `grantHeader: "X-Step-Up-Grant"` (default) — the middleware
 * checks for a valid b.auth.stepUp.grant token before evaluating the
 * normal claims-based requirement, so a multi-step flow doesn't get
 * step-up-prompted on every action.
 *
 * Options:
 *   {
 *     requirement:    { acr / acrValues / maxAge / requiredAmr / phishingResistant },
 *     getClaims:      function(req) { return req.user.claims; },
 *     realm:          "api",
 *     audit:          true,
 *     acceptGrant:    true,                         // default
 *     grantHeader:    "X-Step-Up-Grant",            // default
 *     grantScope:     null,                         // narrow grant by scope
 *   }
 *
 * NEVER weaken the security default to fix a broken caller. Operators
 * configure their IdP to emit `acr` / `auth_time` / `amr` correctly;
 * the middleware does not silently default these to "good enough" on a
 * missing claim.
 */

var lazyRequire    = require("../lazy-require");
var validateOpts   = require("../validate-opts");
var requestHelpers = require("../request-helpers");
var { AuthError }  = require("../framework-error");

var stepUp         = lazyRequire(function () { return require("../auth/step-up"); });
var elevation      = lazyRequire(function () { return require("../auth/elevation-grant"); });
var audit          = lazyRequire(function () { return require("../audit"); });

var DEFAULT_GRANT_HEADER = "x-step-up-grant";

function _defaultGetClaims(req) {
  if (!req || typeof req !== "object") return null;
  if (req.user && req.user.claims && typeof req.user.claims === "object") {
    return req.user.claims;
  }
  if (req.user && typeof req.user === "object") {
    return req.user;
  }
  return null;
}

// Resolve the authenticated principal an elevation grant must be bound to.
// The principal subject lives under different keys depending on the
// authenticator: a session populates req.user.id / req.user.userId, while
// bearerAuth with an external JWT verifier (auth.jwt.verifyExternal)
// populates req.user.claims.sub (or a flattened req.user.sub) — the same
// shapes _defaultGetClaims reads. Resolving all of them keeps a grant
// legitimately minted for a claims.sub principal from being silently
// dropped to a 401. Returns undefined when no principal is resolvable, in
// which case the caller refuses the grant path (fail-closed: an unbound or
// mismatched subject can only narrow what a grant satisfies, never widen).
function _resolveStepUpPrincipal(req) {
  if (!req || typeof req !== "object" || !req.user || typeof req.user !== "object") {
    return undefined;
  }
  var u = req.user;
  if (u.id != null)     return u.id;
  if (u.userId != null) return u.userId;
  if (u.claims && typeof u.claims === "object" && u.claims.sub != null) {
    return u.claims.sub;
  }
  if (u.sub != null)    return u.sub;
  return undefined;
}

function _writeChallenge(res, challenge, body, statusCode) {
  if (res.headersSent) return;
  var json = JSON.stringify(body);
  res.writeHead(statusCode, {                                                      // HTTP status passthrough
    "Content-Type":     "application/json; charset=utf-8",
    "Content-Length":   Buffer.byteLength(json),
    "WWW-Authenticate": challenge,
    // RFC 9111 §5.2.2.5 — auth-gated step-up challenge must not
    // be cached (CDN replay defense).
    "Cache-Control":    "no-store",
  });
  res.end(json);
}

/**
 * @primitive b.middleware.requireStepUp
 * @signature b.middleware.requireStepUp(opts)
 * @since     0.1.0
 * @related   b.middleware.requireAal, b.middleware.bearerAuth
 *
 * Gates routes per RFC 9470 OAuth 2.0 Step-Up Authentication
 * Challenge. Mount AFTER `attachUser` / `bearerAuth` so the
 * request carries verified token claims. Refuses with HTTP 401 +
 * `WWW-Authenticate: Bearer error="insufficient_user_authentication",
 * acr_values="...", max_age="..."`. With `acceptGrant: true`
 * (default) the middleware first checks for a fresh
 * `b.auth.stepUp.grant` token in `X-Step-Up-Grant` so a
 * multi-step flow doesn't re-prompt on every action. Never weakens
 * defaults to accommodate missing IdP claims — operators configure
 * the IdP to emit `acr` / `auth_time` / `amr` correctly.
 *
 * @opts
 *   {
 *     requirement: { acr, acrValues, maxAge, requiredAmr, phishingResistant },  // required
 *     getClaims:   function(req): object,
 *     realm:       string,
 *     acceptGrant: boolean,    // default true
 *     grantHeader: string,     // default "X-Step-Up-Grant"
 *     grantScope:  string,
 *     errorDescription: string,
 *     audit:       boolean,    // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/billing/transfer", b.middleware.requireStepUp({
 *     requirement: { acr: "high", maxAge: 300 },
 *     realm:       "billing-api",
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "requirement", "getClaims", "realm", "audit",
    "acceptGrant", "grantHeader", "grantScope", "errorDescription",
  ], "middleware.requireStepUp");

  if (!opts.requirement || typeof opts.requirement !== "object") {
    throw new AuthError("auth-step-up/bad-requirement",
      "middleware.requireStepUp: opts.requirement must be an object");
  }
  validateOpts.optionalFunction(opts.getClaims,
    "middleware.requireStepUp: getClaims", AuthError, "auth-step-up/bad-opt");

  var realm        = (typeof opts.realm === "string" && opts.realm.length > 0)
    ? opts.realm : "api";
  var auditOn      = opts.audit !== false;
  var getClaims    = (typeof opts.getClaims === "function")
    ? opts.getClaims : _defaultGetClaims;
  var acceptGrant  = opts.acceptGrant !== false;
  var grantHeader  = (typeof opts.grantHeader === "string" && opts.grantHeader.length > 0)
    ? opts.grantHeader.toLowerCase() : DEFAULT_GRANT_HEADER;
  var grantScope   = (typeof opts.grantScope === "string" && opts.grantScope.length > 0)
    ? opts.grantScope : null;
  var errorDesc    = (typeof opts.errorDescription === "string" && opts.errorDescription.length > 0)
    ? opts.errorDescription : null;

  // Pre-validate the requirement so operator typos surface at boot, not
  // on the first hot-path request.
  var probe = stepUp().evaluate({ claims: { acr: "0" }, requirement: opts.requirement });
  if (probe.error === "bad_requirement" || probe.error === "unknown_acr") {
    throw new AuthError("auth-step-up/bad-requirement",
      "middleware.requireStepUp: " + (probe.reason || probe.error));
  }

  return function requireStepUpMiddleware(req, res, next) {
    var headers = req.headers || {};

    // Path 1: operator-issued elevation grant — short-circuit success.
    if (acceptGrant) {
      var grantToken = headers[grantHeader] || null;
      if (typeof grantToken === "string" && grantToken.length > 0) {
        var verifyOpts = {};
        if (grantScope) verifyOpts.scope = grantScope;
        // Bind the grant to the authenticated principal: an elevation grant
        // carries its subject (payload.sub) and must only satisfy step-up for
        // THAT subject. Without this, a grant minted for one user (leaked via a
        // shared cache / log / kiosk) elevates ANY other authenticated user's
        // session — a cross-user step-up replay. When no principal is resolvable
        // the grant cannot be bound, so the grant path is refused (the request
        // falls through to the claims-based path / 401 challenge).
        var stepUpPrincipal = _resolveStepUpPrincipal(req);
        var grantResult;
        if (stepUpPrincipal == null) {
          grantResult = { ok: false, error: "no_principal",
                          reason: "step-up grant requires an authenticated principal to bind to" };
        } else {
          verifyOpts.subject = stepUpPrincipal;
          grantResult = elevation().verify(grantToken, verifyOpts);
        }
        if (grantResult.ok) {
          if (auditOn) {
            try {
              audit().safeEmit({
                action:  "auth.stepup.satisfied",
                outcome: "success",
                actor:   { userId: grantResult.payload.sub,
                           clientIp: requestHelpers.clientIp(req) },
                metadata: {
                  reason: "grant",
                  jti:    grantResult.payload.jti || null,
                  scope:  grantResult.payload.scope,
                  route:  req.url || null,
                },
              });
            } catch (_e) { /* drop-silent */ }
          }
          if (req.user) req.user.stepUp = { byGrant: true, payload: grantResult.payload };
          return next();
        }
        // Invalid grant — fall through to claims-based path; emit signal.
        if (auditOn) {
          try {
            audit().safeEmit({
              action:  "auth.stepup.grant.rejected",
              outcome: "denied",
              actor:   { clientIp: requestHelpers.clientIp(req) },
              metadata: { error: grantResult.error, reason: grantResult.reason },
            });
          } catch (_e) { /* drop-silent */ }
        }
      }
    }

    // Path 2: claims-based evaluation.
    var claims = getClaims(req);
    var result = stepUp().evaluate({ claims: claims, requirement: opts.requirement });

    if (result.ok) {
      if (auditOn) stepUp().emitAuditSatisfied("requireStepUp", opts.requirement, result.presented, req);
      if (req.user) req.user.stepUp = { byClaims: true, presented: result.presented };
      return next();
    }

    if (auditOn) stepUp().emitAuditRequired("requireStepUp", opts.requirement, result.presented, req);

    var challenge = stepUp().buildChallenge({
      requirement:      opts.requirement,
      realm:            realm,
      error:            stepUp().INSUFFICIENT_USER_AUTHENTICATION,
      errorDescription: errorDesc || undefined,
    });
    _writeChallenge(res,
      challenge,
      {
        error:             stepUp().INSUFFICIENT_USER_AUTHENTICATION,
        error_description: errorDesc || "A higher level of authentication is required",
      },
      401                                                                                  // HTTP 401
    );
  };
}

module.exports = { create: create };
