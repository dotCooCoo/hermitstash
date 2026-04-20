/**
 * Security response headers — applied to every response.
 *
 * Generates a per-response CSP nonce so templates can allowlist specific
 * inline <script>/<style> blocks via `nonce="{{nonce}}"`. When a nonce is
 * present, CSP3 browsers ignore 'unsafe-inline'; we still emit it in the
 * header as a strict no-op fallback for CSP2-era clients.
 */
var config = require("../lib/config");
var { generateBytes } = require("../lib/crypto");

// Extract analytics domains (for script-src / connect-src / img-src) from the
// admin-configured analytics script snippet.
function resolveAnalyticsDomains() {
  if (config.analyticsCspDomains) {
    return config.analyticsCspDomains.split(",").map(function (d) { return d.trim(); }).filter(Boolean);
  }
  if (!config.analyticsScript) return [];
  var srcMatches = config.analyticsScript.match(/(?:src|href)=["']https?:\/\/([^"'\s\/]+)/gi) || [];
  var urlMatches = config.analyticsScript.match(/https?:\/\/([^"'\s\/\)]+)/gi) || [];
  var domains = new Set();
  srcMatches.concat(urlMatches).forEach(function (m) {
    try { var host = m.replace(/^.*?https?:\/\//i, "").split(/[/"'\s]/)[0]; if (host && host.includes(".")) domains.add("https://" + host); } catch (_e) { /* URL parse failure — skip this match */ }
  });
  return Array.from(domains);
}

// When Google OAuth is enabled, allow avatar + SDK hosts in img-src / connect-src.
// Intentionally DOES NOT include play.google.com telemetry (blocked = privacy win).
function googleImgDomains() {
  if (!config.google || !config.google.clientID) return [];
  return ["https://lh3.googleusercontent.com", "https://*.googleusercontent.com"];
}
function googleConnectDomains() {
  if (!config.google || !config.google.clientID) return [];
  return ["https://accounts.google.com", "https://oauth2.googleapis.com"];
}

module.exports = function securityHeaders(req, res, next) {
  // Per-response nonce. 16 random bytes → 22 base64url chars = ~128 bits entropy.
  // Expose on res so send.js can forward it into the template context.
  res._cspNonce = generateBytes(16).toString("base64url");

  var origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (_code) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("X-XSS-Protection", "0");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    // HSTS for HTTPS deployments (with preload)
    if (config.rpOrigin && config.rpOrigin.startsWith("https")) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }
    if (!res.getHeader("Content-Security-Policy")) {
      var domains = resolveAnalyticsDomains();
      var analyticsExtra = domains.length > 0 ? " " + domains.join(" ") : "";

      // NOTE ON CSP + NONCES:
      // A per-response nonce is generated (res._cspNonce) and threaded into the
      // template context so views can start adopting `nonce="{{nonce}}"` on inline
      // <script>/<style> tags. We intentionally DO NOT emit `'nonce-...'` in the
      // CSP header yet. Under CSP3, browsers that see a nonce source ignore
      // `'unsafe-inline'` entirely — which would break the ~169 inline event
      // handler attributes (onclick=, onchange=, etc.) still present in templates.
      // The infrastructure is ready; a future phase rewrites those handlers to
      // addEventListener in external JS, then this comment block is replaced with
      //     var nonceExpr = "'nonce-" + res._cspNonce + "'";
      //     var scriptSrc = "script-src 'self' " + nonceExpr + analyticsExtra;
      // and `'unsafe-inline'` is dropped.
      var googleImg = googleImgDomains();
      var googleConnect = googleConnectDomains();
      var googleImgExtra = googleImg.length > 0 ? " " + googleImg.join(" ") : "";
      var googleConnectExtra = googleConnect.length > 0 ? " " + googleConnect.join(" ") : "";

      var scriptSrc = "script-src 'self' 'unsafe-inline'" + analyticsExtra;
      var styleSrc  = "style-src 'self' 'unsafe-inline'";
      var connectSrc = "connect-src 'self'" + analyticsExtra + googleConnectExtra;
      // Tightened img-src: no longer accepts arbitrary https: images. data: is
      // still allowed for inline icons/previews. Analytics hosts included so
      // tracking pixels from the admin-configured script work. Google
      // googleusercontent hosts allowed when Google OAuth is configured (for
      // user avatars).
      var imgSrc = "img-src 'self' data:" + analyticsExtra + googleImgExtra;
      res.setHeader("Content-Security-Policy", "default-src 'self'; " + scriptSrc + "; " + styleSrc + "; font-src 'self'; " + imgSrc + "; " + connectSrc + "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    }
    // Prevent caching of authenticated/dynamic pages
    var isStatic = req.pathname && /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|webp)$/.test(req.pathname);
    if (!isStatic) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Vary", "Cookie");
      // nginx-specific: override proxy_cache even if nginx.conf enables it
      res.setHeader("X-Accel-Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    }
    return origWriteHead.apply(res, arguments);
  };
  next();
};
