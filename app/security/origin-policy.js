/**
 * Origin Policy — single canonical origin for all generated URLs.
 * Never trust Host header for absolute URL generation.
 */
var config = require("../../lib/config");

/**
 * Returns the canonical origin (scheme + host + optional port).
 * Fails hard if no rpOrigin is configured in production-like environments.
 */
function getOrigin() {
  if (config.rpOrigin) return config.rpOrigin;
  // Dev fallback only — not safe for production
  var port = config.port || 3000;
  if (process.env.NODE_ENV === "production") {
    console.error("  ⚠ SECURITY: rpOrigin not configured — falling back to localhost. Set RP_ORIGIN in admin settings.");
  }
  return "http://localhost:" + port;
}

/**
 * Build an absolute URL from a path using the canonical origin.
 * Always use this instead of req.headers.host.
 */
function absoluteUrl(pathname) {
  var origin = getOrigin();
  if (pathname && pathname[0] !== "/") pathname = "/" + pathname;
  return origin + (pathname || "");
}

// (isSafeRedirect was removed — it had no callers and its check missed
// backslash / control-char tricks, so keeping it was a latent open-redirect
// foot-gun. A redirect validator, if ever needed, should be reintroduced with
// full URL canonicalization and rejected on any non-"/" or control-char input.)

module.exports = { getOrigin, absoluteUrl };
