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
  // Dev fallback only — log warning
  var port = config.port || 3000;
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

/**
 * Validate that a redirect target is safe (relative path or canonical origin).
 */
function isSafeRedirect(url) {
  if (!url || typeof url !== "string") return false;
  // Relative paths starting with / (not //)
  if (url.startsWith("/") && !url.startsWith("//")) return true;
  // Same-origin absolute URLs
  var origin = getOrigin();
  if (origin && url.startsWith(origin + "/")) return true;
  if (origin && url === origin) return true;
  return false;
}

module.exports = { getOrigin, absoluteUrl, isSafeRedirect };
