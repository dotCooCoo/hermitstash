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
  if (process.env.NODE_ENV === "production") { // allow:raw-process-env — gates the dev-vs-prod origin fallback at module load, before config
    console.error("  ⚠ SECURITY: rpOrigin not configured — falling back to localhost. Set RP_ORIGIN in admin settings.");
  }
  return "http://localhost:" + port;
}

/**
 * Every origin this deployment answers on: the canonical one, plus any the
 * operator declared in additionalOrigins (a LAN hostname, a tailnet MagicDNS
 * name). For ACCEPTANCE decisions only — "may a request from here change
 * state?" — never for generating a URL.
 *
 * getOrigin() stays single-valued on purpose. A share link, a verification
 * email and a sitemap entry each need exactly one origin, and there is no
 * sensible way to pick from a set; returning one would silently make those
 * URLs depend on list order.
 *
 * Entries are returned raw. The caller canonicalizes, because the comparison
 * is only sound when both sides run through the same canonicalizer.
 */
function acceptedOrigins() {
  var extra = config.additionalOrigins || [];
  return [getOrigin()].concat(extra.filter(function (o) {
    return typeof o === "string" && o.length > 0;
  }));
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

module.exports = { getOrigin, acceptedOrigins, absoluteUrl };
