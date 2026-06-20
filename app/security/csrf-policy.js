/**
 * CSRF Policy — thin composition over `b.middleware.csrfProtect`.
 *
 * The framework primitive enforces CSRF on POST/PUT/DELETE/PATCH by
 * comparing a header / body token against either a double-submit
 * cookie OR an operator-supplied lookup. HermitStash uses the
 * lookup mode — the expected token lives in `req.session._csrf`,
 * generated lazily on first request and persisted via `b.session.
 * updateData` (lib/session.js's res.end wrap).
 *
 * Strategy:
 *   - JSON requests: CSRF-safe via per-session XChaCha20-Poly1305
 *     encryption — the api-encrypt middleware validates the
 *     session-bound key, which serves as an implicit CSRF token (a
 *     cross-site attacker can't produce a valid encrypted body).
 *   - Form POSTs (multipart and url-encoded): validated via
 *     `b.middleware.csrfProtect` with our session-stored token.
 *   - Bearer-authed API key calls: skipped (no cookie session).
 *   - Operator-exempt paths: public uploads, OAuth callbacks, the
 *     login form's logout (validates in-handler).
 *
 * The `validateToken(session, req, body)` helper is preserved so
 * `routes/auth.js`'s POST /auth/logout can do its own check (it
 * runs inside the manual `req.on("end")` body parser, which is
 * outside the request-pipeline middleware chain).
 */
"use strict";
var b = require("../../lib/vendor/blamejs");
var { emitError } = require("../../middleware/respond-error");
var originPolicy = require("./origin-policy");

var EXEMPT_PREFIXES = [
  "/drop/",           // public uploads (init, file, chunk, finalize)
  "/auth/google",     // OAuth redirect/callback
  "/passkey/login",   // WebAuthn challenge-response (has its own CSRF via challenge)
];
var EXEMPT_EXACT = [
  "/drop/init",
  "/auth/logout",     // form POST — validates CSRF token in route handler
];

function isExempt(pathname) {
  if (!pathname) return false;
  for (var i = 0; i < EXEMPT_EXACT.length; i++) {
    if (pathname === EXEMPT_EXACT[i]) return true;
  }
  for (var j = 0; j < EXEMPT_PREFIXES.length; j++) {
    if (pathname.startsWith(EXEMPT_PREFIXES[j])) return true;
  }
  return false;
}

// Lazy-init the CSRF token in session.data. Read by templates +
// `b.middleware.csrfProtect`'s tokenLookup. session.js's res.end
// wrapper persists the mutation back to _blamejs_sessions on flush.
function generateToken(session) {
  if (!session) return null;
  if (!session._csrf) {
    session._csrf = b.crypto.generateBytes(32).toString("base64url");
  }
  return session._csrf;
}

// Manual validate for routes that handle their own body parsing
// (POST /auth/logout reads via req.on("end")). Token-source priority
// matches `b.middleware.csrfProtect`: header first, then body, then
// query — same constant-time compare via timingSafeEqual on equal-
// length string buffers.
function validateToken(session, req, body) {
  var expected = session && session._csrf;
  if (!expected) return false;
  var token = (req.headers && req.headers["x-csrf-token"])
           || (body && body._csrf)
           || (req.query && req.query._csrf);
  if (!token || typeof token !== "string") return false;
  if (token.length !== expected.length) return false;
  return b.crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

// `b.middleware.csrfProtect` instance — created once at module load
// with `tokenLookup` pointing at the session-stored token.
var bCsrf = b.middleware.csrfProtect({
  tokenLookup: function (req) { return req.session && req.session._csrf; },
  fieldName:   "_csrf",
  headerName:  "X-CSRF-Token",
  audit:       true,
});

function csrfMiddleware(req, res, next) {
  // Skip Bearer-authed clients — no cookie session, no double-submit
  // protection needed; mTLS + API-key transport security covers them.
  if (req.apiKey) return next();

  // Generate / surface the token on every request so views and AJAX
  // callers can read req.csrfToken regardless of method.
  if (req.session) req.csrfToken = generateToken(req.session);

  // Only state-changing methods need validation. The framework also
  // checks method, but bailing here saves the lookup + audit emit on
  // every GET.
  if (req.method !== "POST" && req.method !== "PUT" &&
      req.method !== "DELETE" && req.method !== "PATCH") {
    return next();
  }

  if (isExempt(req.pathname)) return next();

  // JSON cookie-session requests: the api-encrypt envelope is the intended
  // CSRF defense (a cross-site attacker can't produce a valid encrypted body),
  // but the encrypted body is not enforced — so also reject a cross-site Origin.
  // A browser sets Origin on every state-changing request and a forger can't
  // spoof or omit it cross-site; a same-origin request, or a non-browser client
  // with no Origin (which carries no ambient cookie), passes.
  var contentType = (req.headers && req.headers["content-type"]) || "";
  // JSON and multipart cookie-session POSTs both rely on the cross-site Origin
  // check: a browser sets Origin on every state-changing request, and a forger
  // cannot spoof or omit it cross-site. multipart/form-data is CORS-safelisted
  // (fires without preflight, with ambient cookies) but STILL carries Origin, so
  // the same check that backstops JSON is the primary CSRF defense for multipart.
  // The framework token check can't see a `_csrf` field inside HS's self-buffered
  // multipart stream, so the Origin gate is what protects admin multipart routes
  // (e.g. /admin/logo/upload). The genuinely token-bearing public upload portals
  // (/drop, /stash) are already exempt above (isExempt) and Bearer/API clients
  // skipped earlier, so the only non-exempt multipart routes are same-origin
  // admin mutations, which pass cleanly.
  if (contentType.includes("application/json") || contentType.includes("multipart/")) {
    var origin = (req.headers && req.headers.origin) || "";
    if (origin && origin !== originPolicy.getOrigin()) {
      // emitError routes problem+json through the encrypting res.json on an
      // api-encrypt cookie session — a direct b.problemDetails.send would ship
      // this 403 in CLEARTEXT on a session the client negotiated as encrypted
      // (Security Invariant #2). Mirrors require-admin's content-negotiated deny.
      emitError(req, res, { status: 403, code: "FORBIDDEN", detail: "Cross-origin request rejected." });
      return;
    }
    return next();
  }

  // Form-encoded or unknown content type → framework validates.
  return bCsrf(req, res, next);
}

module.exports = { csrfMiddleware: csrfMiddleware, generateToken: generateToken, validateToken: validateToken, isExempt: isExempt };
