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

// Three-state extractor: { state: "absent" } when no Authorization
// header was sent, { state: "malformed" } when one is present but
// doesn't parse against this middleware's scheme, or { state: "ok",
// token } on success. The "malformed" case must NOT fall through to
// downstream auth (cookie-session) — operators relying on bearer-auth
// expect a 401 when a client deliberately sends `Authorization: ...`
// even if the value is unparseable.
function _extractToken(req, scheme) {
  var h = req.headers && req.headers.authorization;
  if (typeof h !== "string" || h.length === 0) return { state: "absent" };
  var prefix = scheme + " ";
  if (h.length <= prefix.length) return { state: "malformed" };
  if (h.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) {
    // Authorization header is for a different scheme (Basic, Digest,
    // Negotiate, etc.) — leave the request for the next middleware
    // that handles that scheme. From this middleware's perspective,
    // it's effectively "absent."
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
 *     errorMessage:   string,
 *     tokenAttachKey: string,
 *     userAttachKey:  string,
 *     audit:          boolean,   // default true
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
  // CRLF-injection defense on operator-supplied realm — without this,
  // a config-fed realm like `api\r\nX-Inject: 1` lands in the
  // WWW-Authenticate response header verbatim. RFC 7235 §2.2 quoted-
  // string excludes CTLs (codepoints < 0x20 and 0x7F) and the literal
  // `"` / `\` characters.
  if (realm !== null) {
    if (typeof realm !== "string") {
      throw new AuthError("auth-bearer/bad-realm",
        "middleware.bearerAuth: realm must be a string");
    }
    for (var ri = 0; ri < realm.length; ri += 1) {
      var rcode = realm.charCodeAt(ri);
      if (rcode < 32 || rcode === 127) {                                  // allow:raw-byte-literal — ASCII control codepoints
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
    try { observability().count(metric, n, tags || {}); }
    catch (_e) { /* best-effort */ }
  }

  return async function bearerAuth(req, res, next) {
    var extracted = _extractToken(req, scheme);
    if (extracted.state === "absent") {
      // No Bearer header — fall through. Cookie-based session middleware
      // running after this can attach a user via the cookie path.
      return next();
    }
    if (extracted.state === "malformed") {
      // Authorization header present but does not parse against this
      // scheme. Refuse with 401 — the request is unambiguously trying
      // to authenticate via bearer, and falling through to cookie-auth
      // would mask the operator's malformed-input bug.
      _emitAudit("auth.bearer.failure", "failure", req, "malformed-authorization");
      _emitObs("auth.bearer.rejected", 1, { reason: "malformed-authorization" });
      if (!res.headersSent) {
        var malformedChallenge = scheme + ' error="invalid_request"' +
          (realm ? ', realm="' + realm + '"' : "");
        var malformedBody = JSON.stringify({ error: errorMessage });
        res.writeHead(401, {                                                     // allow:raw-byte-literal — HTTP 401 status
          "Content-Type":     "application/json; charset=utf-8",
          "Content-Length":   Buffer.byteLength(malformedBody),
          "WWW-Authenticate": malformedChallenge,
        });
        res.end(malformedBody);
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

    // RFC 6750 §3 — `insufficient_scope` challenge with `scope=` when
    // the verified token is missing one or more required scopes.
    // Operators pass `requiredScopes: ["write", "admin"]` to enforce.
    // The verifier returns the user's scope list at `user.scope`
    // (string, space-separated) OR `user.scopes` (array). When the
    // request lacks a required scope, refuse with 403 + the standard
    // challenge (NOT 401 — token was valid).
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
          var scopeBody = JSON.stringify({
            error: "insufficient_scope",
            required: opts.requiredScopes.slice(),
          });
          res.writeHead(403, {                                                     // allow:raw-byte-literal — HTTP 403 status
            "Content-Type":     "application/json; charset=utf-8",
            "Content-Length":   Buffer.byteLength(scopeBody),
            "WWW-Authenticate": scopeChallenge,
          });
          res.end(scopeBody);
        }
        return;
      }
    }

    req[tokenAttach] = token;
    req[userAttach]  = user;
    // Signal to attach-user (and any other downstream auth middleware)
    // that this Authorization header has already been consumed and
    // verified — without this flag, attach-user would re-read the
    // header and try to parse it as a session token, producing a
    // confusing "session.verify-tried-and-failed" audit row alongside
    // the successful "auth.bearer.success" we just emitted.
    req._bearerAuthHandled = true;
    _emitAudit("auth.bearer.success", "success", req, null);
    _emitObs("auth.bearer.accepted", 1, {});
    next();
  };
}

module.exports = { create: create };
