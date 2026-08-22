/**
 * Wraps the framework's security headers with a per-request CSP and a
 * Cache-Control bolt-on for dynamic pages.
 *
 * The CSP is computed per request rather than declared once at boot, because
 * its allowlist depends on operator-configured analytics domains and the Google
 * OAuth hosts, both of which hot-reload through config.onReset.
 *
 * It keeps 'unsafe-inline' on script-src and style-src because the views still
 * carry inline event-handler attributes; moving to a nonce today would break
 * every page that fires one. res._cspNonce is populated regardless, so a view
 * migrated to `nonce="{{nonce}}"` finds it waiting.
 */
var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");
var clientIp = require("../lib/client-ip");

// A CSP source-expression is a single token, so a value carrying a `;` or
// whitespace would splice a whole new directive into the header — turning
// `script-src 'self'` into `script-src 'self' x; script-src *`. Returns the
// canonical `https://host…` form, or null to drop the entry.
function _safeCspSource(raw) {
  var s = String(raw || "").trim();
  if (!s) return null;
  if (!/^[A-Za-z0-9.:/*_-]+$/.test(s)) return null;   // no ; , whitespace ' " < >
  var host = s.replace(/^https?:\/\//i, "");
  if (!host || !host.includes(".")) return null;       // must be a real host, not a keyword
  return /^https?:\/\//i.test(s) ? s : "https://" + s;
}

function resolveAnalyticsDomains() {
  if (config.analyticsCspDomains) {
    var raw = config.analyticsCspDomains;
    // Declared as a list in the schema, which the settings store may persist
    // as an array or as a comma-separated string.
    var list = Array.isArray(raw) ? raw : String(raw).split(",");
    return list.map(_safeCspSource).filter(Boolean);
  }
  if (!config.analyticsScript) return [];
  var srcMatches = config.analyticsScript.match(/(?:src|href)=["']https?:\/\/([^"'\s/]+)/gi) || [];
  var urlMatches = config.analyticsScript.match(/https?:\/\/([^"'\s/)]+)/gi) || [];
  var domains = new Set();
  srcMatches.concat(urlMatches).forEach(function (m) {
    var host = m.replace(/^.*?https?:\/\//i, "").split(/[/"'\s]/)[0];
    var safe = _safeCspSource(host);
    if (safe) domains.add(safe);
  });
  return Array.from(domains);
}

// Avatar and SDK hosts only. play.google.com telemetry is deliberately absent.
function googleImgDomains() {
  if (!config.google || !config.google.clientID) return [];
  return ["https://lh3.googleusercontent.com", "https://*.googleusercontent.com"];
}
function googleConnectDomains() {
  if (!config.google || !config.google.clientID) return [];
  return ["https://accounts.google.com", "https://oauth2.googleapis.com"];
}

function buildCsp() {
  var analytics = resolveAnalyticsDomains();
  var googleImg = googleImgDomains();
  var googleConnect = googleConnectDomains();

  // Built rather than concatenated, so every source is validated and an
  // injection-bearing host is rejected instead of spliced in verbatim.
  // requireTrustedTypes is off because the views use innerHTML.
  return b.csp.build({
    "default-src":     ["'self'"],
    "script-src":      ["'self'", "'unsafe-inline'"].concat(analytics),
    "style-src":       ["'self'", "'unsafe-inline'"],
    "font-src":        ["'self'"],
    "img-src":         ["'self'", "data:"].concat(analytics, googleImg),
    "connect-src":     ["'self'"].concat(analytics, googleConnect),
    "object-src":      ["'none'"],
    "base-uri":        ["'none'"],
    "frame-ancestors": ["'none'"],
  }, { acknowledgeUnsafe: true, requireTrustedTypes: false, allowDataImages: true });
}

// Every header but the CSP stays at the framework default, HSTS included — its
// default is the posture HS wants, and it already withholds the header from a
// plain-HTTP request, which is RFC 6797 §8.1 read from the other side.
//
// protocolResolver rather than trustedProxies, because this instance is built
// once at module load and a captured list would go stale the moment an operator
// changed TRUST_PROXY. Going through clientIp also keeps one trusted-proxy list
// behind the client address, the session cookie's Secure flag and this header.
var bSecurityHeaders = b.middleware.securityHeaders({
  csp: false,
  protocolResolver: function (req) {
    return clientIp.isSecureRequest(req) ? "https" : "http";
  },
});

module.exports = function securityHeaders(req, res, next) {
  res._cspNonce = b.crypto.generateBytes(16).toString("base64url");

  res.setHeader("Content-Security-Policy", buildCsp());

  // Static assets are left alone: the static handler manages their cache
  // headers, and no-store would defeat the browser disk cache for the bundle.
  // Deferred to writeHead so a route that sets its own Cache-Control wins.
  var origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (statusCode, statusMessageOrHeaders, maybeHeaders) {
    var isStatic = req.pathname && /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|webp)$/.test(req.pathname);
    // A route can set Cache-Control through res.setHeader or inline in the
    // writeHead argument, and the inline form is not on res yet — so both are
    // checked, or no-store stacks on top of a route's cacheable directive.
    var inlineHeaders = (statusMessageOrHeaders && typeof statusMessageOrHeaders === "object")
      ? statusMessageOrHeaders : maybeHeaders;
    var hasInlineCacheControl = inlineHeaders && typeof inlineHeaders === "object" &&
      Object.keys(inlineHeaders).some(function (k) { return k.toLowerCase() === "cache-control"; });
    if (!isStatic && !res.getHeader("Cache-Control") && !hasInlineCacheControl) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Vary", "Cookie");
      // Overrides nginx proxy_cache even where nginx.conf enables it.
      res.setHeader("X-Accel-Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    }
    return origWriteHead.apply(res, arguments);
  };

  return bSecurityHeaders(req, res, next);
};

// Exposed so the CSP-source sanitizer can be tested directly.
module.exports._safeCspSource = _safeCspSource;
