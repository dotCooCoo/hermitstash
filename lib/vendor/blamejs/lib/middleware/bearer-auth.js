"use strict";
/**
 * bearer-auth middleware — extracts `Authorization: Bearer <token>`,
 * runs an operator-supplied verifier, and attaches the result to
 * `req.user`. Distinct from `attachUser` (which reads session cookies)
 * — this is the API-token / JWT / OAuth-access-token path.
 *
 * Mount this for routes that accept bearer tokens. Operators that
 * accept BOTH cookie sessions AND bearer tokens mount both: bearerAuth
 * runs first; if no Bearer header, it calls next() so attachUser /
 * requireAuth can take over. If a Bearer header IS present but invalid,
 * bearerAuth rejects with 401 immediately (avoids the
 * "is this a bearer or a cookie session?" collision in attach-user.js).
 *
 *   var bearer = b.middleware.bearerAuth({
 *     verify: async function (token) {
 *       // operator-supplied: return a user object or null/throw
 *       var rec = await b.apiKey.verify(token);
 *       return rec ? { id: rec.ownerId, scopes: rec.scopes } : null;
 *     },
 *     audit:        true,                  // default
 *     scheme:       "Bearer",              // default; some ops use "Token"
 *     errorMessage: "Bearer token required.",
 *   });
 *   router.use("/api", bearer);
 *
 * Verify result shape:
 *   - object truthy → req.user = result; next()
 *   - null / undefined / false → 401 (token invalid)
 *   - throws an Error with .code === "auth-bearer/expired" → 401 + WWW-Authenticate
 *
 * Audit: `auth.bearer.success` on accept; `auth.bearer.failure` with
 * reason on reject. Both carry actor context (clientIp, userAgent,
 * route).
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

function _writeUnauthorized(res, scheme, message, realm) {
  if (res.headersSent) return;
  var body = JSON.stringify({ error: message });
  var challenge = scheme + (realm ? ' realm="' + realm + '"' : "");
  res.writeHead(401, {                                                           // allow:raw-byte-literal — HTTP 401 status
    "Content-Type":     "application/json; charset=utf-8",
    "Content-Length":   Buffer.byteLength(body),
    "WWW-Authenticate": challenge,
  });
  res.end(body);
}

function _extractToken(req, scheme) {
  var h = req.headers && req.headers.authorization;
  if (typeof h !== "string" || h.length === 0) return null;
  var prefix = scheme + " ";
  if (h.length <= prefix.length) return null;
  if (h.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) return null;
  var token = h.slice(prefix.length).trim();
  return token.length > 0 ? token : null;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "verify", "audit", "scheme", "errorMessage", "realm",
    "tokenAttachKey", "userAttachKey",
  ], "middleware.bearerAuth");

  if (typeof opts.verify !== "function") {
    throw new AuthError("auth-bearer/missing-verify",
      "middleware.bearerAuth requires a verify(token) function — operators MUST supply " +
      "the verification path (b.apiKey.verify / b.auth.jwt.verifyExternal / custom)");
  }
  var auditOn       = opts.audit !== false;
  var scheme        = opts.scheme || "Bearer";
  var errorMessage  = opts.errorMessage || "Bearer token required.";
  var realm         = opts.realm || null;
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
    try { observability().count(metric, n, tags || {}); }
    catch (_e) { /* best-effort */ }
  }

  return async function bearerAuth(req, res, next) {
    var token = _extractToken(req, scheme);
    if (!token) {
      // No Bearer header — fall through. Cookie-based session middleware
      // running after this can attach a user via the cookie path.
      return next();
    }

    var user;
    try {
      user = await opts.verify(token);
    } catch (e) {
      var code = (e && e.code) || "auth-bearer/verify-failed";
      _emitAudit("auth.bearer.failure", "failure", req, code);
      _emitObs("auth.bearer.rejected", 1, { reason: code });
      // Per RFC 6750 §3 — `Bearer error="invalid_token"` is the
      // standardized challenge for verifier-rejected tokens.
      var challenge = scheme + ' error="invalid_token"' +
        (realm ? ', realm="' + realm + '"' : "");
      if (!res.headersSent) {
        var body = JSON.stringify({ error: errorMessage });
        res.writeHead(401, {                                                     // allow:raw-byte-literal — HTTP 401 status
          "Content-Type":     "application/json; charset=utf-8",
          "Content-Length":   Buffer.byteLength(body),
          "WWW-Authenticate": challenge,
        });
        res.end(body);
      }
      return;
    }

    if (!user) {
      _emitAudit("auth.bearer.failure", "failure", req, "verifier-returned-null");
      _emitObs("auth.bearer.rejected", 1, { reason: "verifier-null" });
      _writeUnauthorized(res, scheme, errorMessage, realm);
      return;
    }

    req[tokenAttach] = token;
    req[userAttach]  = user;
    _emitAudit("auth.bearer.success", "success", req, null);
    _emitObs("auth.bearer.accepted", 1, {});
    next();
  };
}

module.exports = { create: create };
