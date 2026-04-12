/**
 * Bot guard — blocks automated clients on public-facing routes.
 *
 * Uses request fingerprinting (not user-agent strings) to distinguish
 * real browsers from scanners and HTTP libraries. Real browsers send
 * headers that raw clients almost never replicate correctly:
 *
 *   - accept-language (locale negotiation)
 *   - sec-fetch-dest / sec-fetch-mode (Fetch metadata)
 *   - upgrade-insecure-requests (navigation indicator)
 *
 * This survives PQC TLS adoption — once scanners negotiate PQC groups,
 * they still won't send browser-specific headers unless they fully
 * emulate a browser engine.
 *
 * Exempt:
 *   - API key clients (Bearer token = programmatic, not a bot)
 *   - Static assets (CSS, JS, images, fonts)
 *   - Health check, sitemap, manifest, robots.txt
 *   - WebSocket upgrades (handled by their own auth)
 *   - POST/PUT/DELETE (form submissions and API calls have their own auth)
 *   - Stash upload routes (public uploads from branded portals)
 */
var rateLimit = require("../lib/rate-limit");
var audit = require("../lib/audit");

// Paths that should be accessible without browser fingerprinting
var EXEMPT_EXACT = [
  "/health",
  "/sitemap.xml",
  "/manifest.json",
  "/robots.txt",
  "/sync/enroll",
];

var EXEMPT_PREFIXES = [
  "/drop/",          // public upload endpoints (init, file, chunk, finalize)
  "/stash/",         // stash upload portal routes (POST handlers)
  "/auth/google",    // OAuth redirects
  "/sync/",          // sync endpoints (API key auth)
];

// Static asset extensions — no fingerprinting needed
var STATIC_RE = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|webp|map|json|txt)$/;

function isExempt(req) {
  var p = req.pathname || req.url;
  if (!p) return true;

  // Static assets
  if (STATIC_RE.test(p)) return true;

  // Exact matches
  for (var i = 0; i < EXEMPT_EXACT.length; i++) {
    if (p === EXEMPT_EXACT[i]) return true;
  }

  // Prefix matches
  for (var j = 0; j < EXEMPT_PREFIXES.length; j++) {
    if (p.startsWith(EXEMPT_PREFIXES[j])) return true;
  }

  return false;
}

/**
 * Check if the request looks like it came from a real browser.
 * Returns true for browser-like requests, false for likely automated clients.
 */
function looksLikeBrowser(req) {
  var h = req.headers;
  if (!h) return false;

  // Must have accept-language — every real browser sends this
  if (!h["accept-language"]) return false;

  // Must have accept header containing text/html for page navigation
  var accept = h["accept"];
  if (!accept || accept.indexOf("text/html") === -1) return false;

  // Fetch metadata (Chromium 80+, Firefox 90+, Safari 16.4+)
  // At least one of these should be present for any modern browser
  var secDest = h["sec-fetch-dest"];
  var secMode = h["sec-fetch-mode"];
  var upgrade = h["upgrade-insecure-requests"];

  if (!secDest && !secMode && !upgrade) return false;

  return true;
}

module.exports = function botGuard(req, res, next) {
  // Skip non-GET (POST/PUT/DELETE have their own auth)
  if (req.method !== "GET" && req.method !== "HEAD") return next();

  // Skip API key clients
  if (req.headers.authorization) return next();

  // Skip WebSocket upgrades
  if (req.headers.upgrade) return next();

  // Skip exempt paths
  if (isExempt(req)) return next();

  // Only fingerprint page navigations (sec-fetch-dest: document).
  // In-page fetches (XHR/fetch) send sec-fetch-dest: empty and are
  // protected by session auth + CSRF, not browser fingerprinting.
  var secDest = req.headers["sec-fetch-dest"];
  if (secDest && secDest !== "document") return next();

  // Fingerprint check
  if (!looksLikeBrowser(req)) {
    var ip = rateLimit.getIp(req);
    audit.log(audit.ACTIONS.BLOCKED, {
      details: "Bot guard: request missing browser fingerprint headers",
      ip: ip,
      path: req.pathname || req.url,
      ua: (req.headers["user-agent"] || "").substring(0, 120),
    });
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Access Denied");
  }

  next();
};
