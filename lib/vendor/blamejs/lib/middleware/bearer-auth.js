// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var codepointClass = require("../codepoint-class");
var { AuthError } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

function _refuse(req, res, status, challenge, bodyObj, reason, problemExt, onDeny, problemMode) {
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        status,
    info:          Object.assign({ status: status, reason: reason }, problemExt || {}),
    problemCode:   "bearer-" + reason,
    problemTitle:  status === C.HTTP.STATUS.FORBIDDEN ? "Forbidden" : "Unauthorized",
    problemDetail: typeof bodyObj.error === "string" ? bodyObj.error : ("bearer authentication failed: " + reason),
    problemExt:    problemExt || null,
    headers:       { "WWW-Authenticate": challenge },
    contentType:   "application/json; charset=utf-8",
    body:          JSON.stringify(bodyObj),
  });
}

function _writeUnauthorized(req, res, scheme, message, realm, onDeny, problemMode) {
  var challenge = scheme + (realm ? ' realm="' + realm + '"' : "");
  _refuse(req, res, 401, challenge, { error: message }, "unauthorized", null, onDeny, problemMode);
}

function _extractToken(req, scheme) {
  var h = req.headers && req.headers.authorization;
  if (typeof h !== "string" || h.length === 0) return { state: "absent" };
  var prefix = scheme + " ";
  if (h.length <= prefix.length) return { state: "malformed" };
  if (h.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) {
    return { state: "absent" };
  }
  var token = h.slice(prefix.length).trim();
  if (token.length === 0) return { state: "malformed" };
  return { state: "ok", token: token };
}

/**
 * @primitive b.middleware.bearerAuth
 * @signature b.middleware.bearerAuth(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.attachUser, b.middleware.requireAuth
 *
 * Extracts `Authorization: Bearer <token>`, calls an operator-supplied
 * verifier, attaches the result to `req.user`. Constructed via
 * `b.middleware.bearerAuth(opts)`; the resulting middleware has
 * the `(req, res, next)` shape shown above. Distinct from
 * `attachUser` (cookie sessions) — this is the API-token / JWT /
 * OAuth-access-token path. When the header is absent the middleware
 * defers to downstream auth; when it IS present but invalid it
 * rejects with HTTP 401 + `WWW-Authenticate` immediately. Verifier
 * returns the user object on success, null/false on rejection, or
 * throws an Error with `code === "auth-bearer/expired"` to surface
 * a token-expired challenge. Emits `auth.bearer.success` /
 * `auth.bearer.failure` audit events with actor context.
 *
 * @opts
 *   {
 *     verify:         async function(token): user|null,  // required
 *     scheme:         string,    // default "Bearer"; some ops use "Token"
 *     realm:          string,
 *     requiredScopes: string[],  // RFC 6750 §3 — refuse 403 insufficient_scope when the verified token lacks one
 *     errorMessage:   string,
 *     tokenAttachKey: string,
 *     userAttachKey:  string,
 *     audit:          boolean,   // default true
 *     onDeny:         function(req, res, info): void,  // own the 401/403; info = { status, reason, ... }
 *     problemDetails: boolean,   // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/api", b.middleware.bearerAuth({
 *     verify: async function (token) {
 *       if (token === "valid-token") return { id: "user-1" };
 *       return null;
 *     },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "verify", "audit", "scheme", "errorMessage", "realm",
    "tokenAttachKey", "userAttachKey", "requiredScopes", "onDeny", "problemDetails",
  ], "middleware.bearerAuth");

  if (typeof opts.verify !== "function") {
    throw new AuthError("auth-bearer/missing-verify",
      "middleware.bearerAuth requires a verify(token) function — operators MUST supply " +
      "the verification path (b.apiKey.verify / b.auth.jwt.verifyExternal / custom)");
  }
  var auditOn       = opts.audit !== false;
  var onDeny        = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode   = opts.problemDetails === true;
  var scheme        = opts.scheme || "Bearer";
  var errorMessage  = opts.errorMessage || "Bearer token required.";
  var realm         = opts.realm || null;
  if (realm !== null) {
    if (typeof realm !== "string") {
      throw new AuthError("auth-bearer/bad-realm",
        "middleware.bearerAuth: realm must be a string");
    }
    for (var ri = 0; ri < realm.length; ri += 1) {
      var rcode = realm.charCodeAt(ri);
      if (codepointClass.isForbiddenControlChar(rcode, { forbidTab: true })) {
        throw new AuthError("auth-bearer/bad-realm",
          "realm contains control character at index " + ri);
      }
      var rchar = realm.charAt(ri);
      if (rchar === '"' || rchar === "\\") {
        throw new AuthError("auth-bearer/bad-realm",
          "realm contains illegal character " + JSON.stringify(rchar) + " at index " + ri);
      }
    }
  }
  var tokenAttach   = opts.tokenAttachKey || "bearerToken";
  var userAttach    = opts.userAttachKey || "user";

  function _emitAudit(action, outcome, req, reason) {
    if (!auditOn) return;
    try {
      var actor = requestHelpers.extractActorContext(req);
      audit().safeEmit({
        action: action, outcome: outcome,
        metadata: Object.assign({}, actor, {
          route:  req.url,
          method: req.method,
          reason: reason || null,
        }),
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _emitObs(metric, n, tags) {
    // it does not, so this threw a TypeError on every call and the drop-silent
    // itself drop-silent, so the catch stays as a belt on a working emitter
    try { observability().safeEvent(metric, n, tags || {}); }
    catch (_e) { /* best-effort */ }
  }

  return async function bearerAuth(req, res, next) {
    var extracted = _extractToken(req, scheme);
    if (extracted.state === "absent") {
      return next();
    }
    if (extracted.state === "malformed") {
      _emitAudit("auth.bearer.failure", "failure", req, "malformed-authorization");
      _emitObs("auth.bearer.rejected", 1, { reason: "malformed-authorization" });
      if (!res.headersSent) {
        var malformedChallenge = scheme + ' error="invalid_request"' +
          (realm ? ', realm="' + realm + '"' : "");
        _refuse(req, res, 401, malformedChallenge, { error: errorMessage },
          "malformed-authorization", null, onDeny, problemMode);
      }
      return;
    }
    var token = extracted.token;

    var user;
    try {
      user = await opts.verify(token);
    } catch (e) {
      var code = (e && e.code) || "auth-bearer/verify-failed";
      _emitAudit("auth.bearer.failure", "failure", req, code);
      _emitObs("auth.bearer.rejected", 1, { reason: code });
      var challenge = scheme + ' error="invalid_token"' +
        (realm ? ', realm="' + realm + '"' : "");
      if (!res.headersSent) {
        _refuse(req, res, 401, challenge, { error: errorMessage },
          "invalid-token", null, onDeny, problemMode);
      }
      return;
    }

    if (!user) {
      _emitAudit("auth.bearer.failure", "failure", req, "verifier-returned-null");
      _emitObs("auth.bearer.rejected", 1, { reason: "verifier-null" });
      _writeUnauthorized(req, res, scheme, errorMessage, realm, onDeny, problemMode);
      return;
    }

    if (Array.isArray(opts.requiredScopes) && opts.requiredScopes.length > 0) {
      var userScopes = Array.isArray(user.scopes) ? user.scopes :
        typeof user.scope === "string" ? user.scope.split(/\s+/).filter(function (s) { return s.length > 0; }) :
        [];
      var missing = opts.requiredScopes.filter(function (s) {
        return userScopes.indexOf(s) === -1;
      });
      if (missing.length > 0) {
        _emitAudit("auth.bearer.failure", "failure", req, "insufficient-scope:" + missing.join(","));
        _emitObs("auth.bearer.rejected", 1, { reason: "insufficient-scope" });
        if (!res.headersSent) {
          var scopeChallenge = scheme + ' error="insufficient_scope"' +
            ', scope="' + opts.requiredScopes.join(" ") + '"' +
            (realm ? ', realm="' + realm + '"' : "");
          _refuse(req, res, 403, scopeChallenge,
            { error: "insufficient_scope", required: opts.requiredScopes.slice() },
            "insufficient-scope", { required: opts.requiredScopes.slice() }, onDeny, problemMode);
        }
        return;
      }
    }

    req[tokenAttach] = token;
    req[userAttach]  = user;
    req._bearerAuthHandled = true;
    _emitAudit("auth.bearer.success", "success", req, null);
    _emitObs("auth.bearer.accepted", 1, {});
    next();
  };
}

module.exports = { create: create };
