/**
 * CSRF Policy — dual protection for cookie-authenticated requests.
 *
 * Strategy:
 *   - JSON requests: CSRF-safe via per-session XChaCha20-Poly1305 encryption
 *     (cross-site attacker cannot forge encrypted payloads without session key)
 *   - Form POSTs: CSRF token validated via validateToken() in the route handler
 *     (token embedded as hidden field, constant-time comparison)
 *   - Non-JSON, non-exempt POSTs: rejected with 403
 *
 * Exempt paths:
 *   - API key-authenticated requests (Bearer token = no cookie auth)
 *   - Public upload endpoints (no session-based auth)
 *   - OAuth callbacks (Google redirect)
 *   - Routes that validate CSRF tokens in their own handler (e.g. /auth/logout)
 */
var { generateBytes, timingSafeEqual } = require("../../lib/crypto");

var EXEMPT_PREFIXES = [
  "/drop/",           // public uploads (init, file, chunk, finalize)
  "/auth/google",     // OAuth redirect/callback
  "/passkey/login",   // WebAuthn challenge-response (has its own CSRF via challenge)
];

var EXEMPT_EXACT = [
  "/drop/init",
  "/auth/logout",   // form POST — validates CSRF token in route handler
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
  // The api-encrypt middleware validates the per-session XChaCha20 key,
  // which serves as an implicit CSRF token — cross-site requests can't produce valid payloads.
  if (req.headers && req.headers["content-type"] && req.headers["content-type"].includes("application/json")) {
    return next();
  }

  // For non-JSON POST (form submissions), validate CSRF token
  if (req.session) {
    // Try to parse body for _csrf token (multipart handled separately by their routes)
    var contentType = (req.headers && req.headers["content-type"]) || "";
    if (contentType.includes("multipart/")) {
      // Multipart uploads are exempt — they use bundle tokens (finalizeToken) for auth
      return next();
    }
    // Form-encoded or unknown content type: require CSRF token
    // All legitimate app requests use JSON, so rejecting non-JSON state-changing requests
    // is defense-in-depth against cross-site form POSTs
    return res.writeHead(403, { "Content-Type": "application/json" }),
      res.end(JSON.stringify({ error: "CSRF validation failed." }));
  }

  return next();
}

module.exports = { csrfMiddleware, generateToken, validateToken, isExempt };
