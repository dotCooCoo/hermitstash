"use strict";
/**
 * attach-user middleware — populates req.user (and req.session) from a
 * verified session token.
 *
 * Token sources, tried in order:
 *   1. Cookie named opts.cookieName (default "blamejs_session")
 *   2. Authorization: Bearer <token> header
 * The first one that produces a verified session wins. Operators who
 * want only one path can disable the other via opts.tokenFrom.
 *
 * Sealed cookies (access-gated): when opts.sealed is true and opts.vault
 * is provided, the cookie value is read via cookies.readSealed (which
 * vault-unseals and recovers the original session token). Without the
 * framework's vault key no client can hand-craft a valid cookie, so the
 * API is unreachable via curl-with-arbitrary-cookies. Default off for
 * back-compat with apps that put the raw token in the cookie.
 *
 * The framework can't know the application's user schema, so the
 * middleware delegates user-record loading to opts.userLoader — an
 * async function `(verifiedSession) => user | null`. Operators
 * typically look up by userId in their own users table.
 *
 * Failure modes (none of which throw):
 *   - No token in either source → req.user = null, next()
 *   - Sealed cookie present but unsealable → req.user = null, next()
 *   - Token present but session.verify rejects → req.user = null, next()
 *   - Session valid but userLoader returns null/undefined → req.user
 *     = null, next() + audit emit (with outcome=failure)
 *
 * Always calls next() — the gating decision is downstream's job (use
 * middleware.requireAuth for that). This middleware only ATTACHES.
 *
 * Options:
 *   {
 *     cookieName:     'blamejs_session'              (cookie name to read)
 *     tokenFrom:      'both' | 'cookie' | 'header'   (default 'both')
 *     bearerScheme:   'Bearer'                       (Authorization scheme token; RFC 6750 §2.1)
 *     tokenExtractor: (req) => token | null          (overrides header extraction entirely)
 *     sealed:         false                          (use cookies.readSealed)
 *     vault:          b.vault                        (required when sealed)
 *     userLoader:     async (verifiedSession) => user (REQUIRED)
 *     audit:          true                           (emit user-load audits)
 *   }
 *
 * The Authorization-header path matches the `Bearer` scheme by default
 * (RFC 6750 §2.1). Operators behind a gateway that issues a different
 * scheme (e.g. `Token`, `DPoP` per RFC 9449) set bearerScheme, or pass
 * tokenExtractor(req) to read the credential from anywhere on the
 * request. The scheme match is case-insensitive (RFC 9110 §11.1).
 */
var lazyRequire = require("../lazy-require");
var cookies = require("../cookies");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var codepointClass = require("../codepoint-class");
var session = lazyRequire(function () { return require("../session"); });
var audit   = lazyRequire(function () { return require("../audit"); });

// Back-compat helper: read a single named cookie from a Cookie: header
// string. Delegates to cookies.parse so the parser is one place.
function _readCookie(cookieHeader, name) {
  if (!cookieHeader || typeof cookieHeader !== "string") return null;
  var jar = cookies.parse(cookieHeader);
  return Object.prototype.hasOwnProperty.call(jar, name) ? jar[name] : null;
}

// Read the credential after an Authorization scheme token. Default scheme
// is "Bearer" (RFC 6750 §2.1); operators fronted by a gateway that mints
// "Token", "DPoP" (RFC 9449), or a custom scheme pass that name so the
// header is consumed instead of silently ignored. The scheme match is
// case-insensitive per RFC 9110 §11.1 (auth-scheme is case-insensitive).
function _readBearer(authHeader, scheme) {
  if (!authHeader || typeof authHeader !== "string") return null;
  var schemeTok = (typeof scheme === "string" && scheme.length > 0) ? scheme : "Bearer";
  // allow:dynamic-regex — schemeTok is RegExp-escaped via codepointClass.escapeRegExp,
  // so the operator-supplied scheme matches literally and cannot inject a pattern
  var m = authHeader.match(new RegExp("^" + codepointClass.escapeRegExp(schemeTok) + "\\s+(.+)$", "i"));
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
  ], "middleware.attachUser");
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
  // Authorization-header scheme token (default "Bearer", RFC 6750 §2.1).
  // tokenExtractor, when supplied, fully owns header-token extraction so
  // gateway-specific schemes (a forwarded JWT in a non-standard header,
  // DPoP-bound tokens, etc.) work without the framework assuming the
  // RFC 6750 shape.
  var bearerScheme   = opts.bearerScheme || "Bearer";
  var tokenExtractor = typeof opts.tokenExtractor === "function" ? opts.tokenExtractor : null;
  // Fingerprint-drift / IP-UA pin / anomaly-score opts thread through
  // session.verify so the documented session.create({ req,
  // fingerprintFields }) defenses actually engage on every verify
  // through the standard middleware path. Without this they were inert
  // — an operator who set them at session.create only got the signal,
  // not enforcement, when the session was checked through attachUser.
  var verifyOpts = {
    requireFingerprintMatch: opts.requireFingerprintMatch === true,
    maxAnomalyScore:         (typeof opts.maxAnomalyScore === "number") ? opts.maxAnomalyScore : null,
    scorer:                  (typeof opts.scorer === "function") ? opts.scorer : null,
  };
  if (sealed && (!opts.vault || typeof opts.vault.unseal !== "function")) {
    throw new Error("middleware.attachUser: opts.sealed requires opts.vault " +
      "with a .unseal method (typically b.vault)");
  }
  // Cookie reader: instance bound to the operator's vault when sealed,
  // otherwise the stateless plain reader.
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
      // bearer-auth (when mounted upstream) sets req._bearerAuthHandled
      // after consuming + verifying the Authorization header. Skipping
      // the header re-read here avoids the duplicate verify and the
      // confusing "session.verify failed" audit row that would land
      // when the bearer token is a JWT or API key, not a session ID.
      if (tokenExtractor) {
        token = tokenExtractor(req) || null;
      } else {
        token = _readBearer(req.headers && req.headers.authorization, bearerScheme);
      }
    }
    if (!token) return next();

    var verified;
    try {
      verified = await session().verify(token, {
        req: req,
        requireFingerprintMatch: verifyOpts.requireFingerprintMatch,
        maxAnomalyScore:         verifyOpts.maxAnomalyScore,
        scorer:                  verifyOpts.scorer,
      });
    } catch (_e) {
      // session.verify is tolerant — shouldn't normally throw, but if it
      // does (DB hiccup), don't propagate; treat as "no user" and let
      // downstream require-auth produce a 401.
      return next();
    }
    if (!verified) return next();

    var user;
    try {
      user = await opts.userLoader(verified);
    } catch (e) {
      // userLoader threw — treat as "no user" but record so the
      // operator can investigate. Don't surface to the response.
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
      // Session valid but user record is gone (deleted) or rejected
      // (suspended, etc.). Record + don't attach.
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
  // Exported for tests and operator-side cookie reading
  _readCookie:  _readCookie,
  _readBearer:  _readBearer,
};
