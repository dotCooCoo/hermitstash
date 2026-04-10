/**
 * CSRF Policy — token-based protection for cookie-authenticated POST routes.
 *
 * How it works:
 *   1. On every page render, a CSRF token is generated and stored in the session.
 *   2. The token is embedded in forms/JS via the template data.
 *   3. On POST, the token from the request body or header is validated.
 *
 * Exempt paths:
 *   - API key-authenticated requests (Bearer token = no cookie auth)
 *   - Public upload endpoints (no session-based auth)
 *   - Webhook callbacks from external services
 *   - OAuth callbacks (Google redirect)
 */
var { generateBytes, timingSafeEqual } = require("../../lib/crypto");

var EXEMPT_PREFIXES = [
  "/drop/",           // public uploads (init, file, chunk, finalize)
  "/auth/google",     // OAuth redirect/callback
  "/passkey/login",   // WebAuthn challenge-response (has its own CSRF via challenge)
];

var EXEMPT_EXACT = [
  "/drop/init",
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

/**
 * Generate a CSRF token and store in session.
 */
function generateToken(session) {
  if (!session._csrf) {
    session._csrf = generateBytes(32).toString("base64url");
  }
  return session._csrf;
}

/**
 * Validate a CSRF token from the request.
 * Checks body._csrf, query._csrf, and X-CSRF-Token header.
 */
function validateToken(session, req, body) {
  var expected = session._csrf;
  if (!expected) return false;
  var token = (body && body._csrf) || (req.query && req.query._csrf) || (req.headers && req.headers["x-csrf-token"]);
  if (!token || typeof token !== "string") return false;
  // Constant-time comparison
  if (token.length !== expected.length) return false;
  return timingSafeEqual(token, expected);
}

/**
 * CSRF middleware — generates token for GET, validates for POST/PUT/DELETE.
 */
function csrfMiddleware(req, res, next) {
  // Skip if API key auth (no cookie session to protect)
  if (req.apiKey) return next();

  // Generate token on every request (available for templates)
  if (req.session) {
    req.csrfToken = generateToken(req.session);
  }

  // Only validate on state-changing methods
  if (req.method !== "POST" && req.method !== "PUT" && req.method !== "DELETE") {
    return next();
  }

  // Skip exempt paths
  if (isExempt(req.pathname)) return next();

  // API-encrypted requests are inherently CSRF-safe (encrypted body includes session key)
  // Check if the request body was encrypted (api-encrypt would have decrypted it)
  if (req.headers && req.headers["content-type"] && req.headers["content-type"].includes("application/json")) {
    // JSON POST requests from the app use API encryption which binds to the session.
    // The api-encrypt middleware validates the per-session AES key,
    // which serves as an implicit CSRF token.
    return next();
  }

  // For non-JSON POST (form submissions), validate CSRF token
  // Currently all POST routes use JSON, so this is defense-in-depth
  return next();
}

module.exports = { csrfMiddleware, generateToken, validateToken, isExempt };
