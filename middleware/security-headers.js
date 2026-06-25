/**
 * Security response headers — wraps `b.middleware.securityHeaders` with
 * HermitStash-specific CSP composition (analytics + Google OAuth) and a
 * dynamic-page Cache-Control bolt-on.
 *
 * The framework primitive owns:
 *   Strict-Transport-Security (HSTS), X-Content-Type-Options,
 *   X-Frame-Options, Referrer-Policy, Permissions-Policy (RFC 9651
 *   validated), Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy,
 *   Origin-Agent-Cluster, X-DNS-Prefetch-Control, Document-Policy,
 *   Content-Security-Policy (with Trusted Types).
 *
 * HS supplies the CSP string per-request because the allowlist depends
 * on operator-configured analytics domains (admin → Branding) plus the
 * Google OAuth hosts when Google login is enabled. Those domains can't
 * be baked into a static `csp:` opt at boot since they hot-reload via
 * config.onReset. Compute on every request, hand to the framework.
 *
 * The CSP nonce primitive (`b.middleware.cspNonce`) is the better
 * long-term path for inline-script handling, but the templates still
 * carry ~169 inline event-handler attributes (onclick=, onchange=, ...).
 * Until those move to addEventListener, the CSP keeps `'unsafe-inline'`
 * on script-src + style-src; switching to nonces today would break
 * every page that fires an inline handler. The nonce stays attached to
 * res._cspNonce so views adopting `nonce="{{nonce}}"` find it.
 */
var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");

// Extract analytics domains (for script-src / connect-src / img-src)
// from the admin-configured analytics script snippet. Operators may
// also set `analyticsCspDomains` explicitly (comma-separated) when the
// auto-extract regex misses a host (e.g. dynamically loaded pixels).
// Validate one admin-supplied CSP host-source before it is concatenated into
// the policy. A CSP source-expression is a single token: a value containing a
// directive separator (`;`) or whitespace would splice a brand-new directive
// or source into the emitted header (CSP injection — the operator could turn
// `script-src 'self'` into `script-src 'self' x; script-src *`). Restrict to
// the characters that legitimately appear in a host-source — scheme, host,
// wildcard, port, path — and require a dotted host, dropping anything else.
// Returns the canonical `https://host…` form, or null to drop the entry.
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
    // settings-schema declares this as `type: "list"`, which the admin
    // settings store may persist as an array. Both shapes flow through.
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

// When Google OAuth is enabled, allow avatar + SDK hosts in img-src /
// connect-src. Intentionally DOES NOT include play.google.com telemetry
// (blocked = privacy win).
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

  // Build through b.csp.build instead of string concatenation: it validates every
  // source (rejecting an injection-bearing host the hand-concat would have spliced
  // in verbatim) and renders a well-formed directive set. Output is directive-
  // equivalent to the previous hand-built CSP (verified).
  //   - acknowledgeUnsafe: 'unsafe-inline' is retained for now (HS views carry
  //     inline handlers/styles); dropping it is the DOM-sink / nonce migration.
  //   - requireTrustedTypes:false: HS views use innerHTML, which Trusted Types
  //     would break — opt out until that migration lands.
  //   - allowDataImages:true: data: image URLs (inline SVG/icon data) are used.
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

// Stable framework middleware — created once at module load. Two
// opts diverge from the framework default:
//
//   csp: false — HS computes the CSP string per request (operator
//     hot-reloads analytics + Google OAuth config; framework's static
//     `csp:` opt can't represent that). The wrapper below sets the
//     header before delegating, so the framework primitive sees a
//     pre-set Content-Security-Policy and skips its own.
//
//   hsts: false — HS gates HSTS on `config.rpOrigin.startsWith("https")`
//     so HTTP deployments don't ship a useless-and-harmful header. The
//     framework default would emit on every response regardless of
//     scheme. The wrapper below adds HSTS only when the gate matches.
//
// Every other header the primitive owns stays at the framework default
// (Referrer-Policy: no-referrer, Permissions-Policy: 27-feature deny,
// COOP/CORP: same-origin, Origin-Agent-Cluster: ?1, X-DNS-Prefetch-
// Control: off, Document-Policy: document-write=?0 / unsized-media=?0
// / oversized-images=?0). Accepting these matches OWASP-strict.
var bSecurityHeaders = b.middleware.securityHeaders({
  csp:  false,
  hsts: false,
});

module.exports = function securityHeaders(req, res, next) {
  // Per-response nonce. 16 random bytes → 22 base64url chars = ~128 bits
  // entropy. Exposed on res so send.js can forward into template
  // context. The CSP doesn't currently emit `nonce-...` (would break
  // inline handlers — see header comment), but views adopting
  // `nonce="{{nonce}}"` find it ready.
  res._cspNonce = b.crypto.generateBytes(16).toString("base64url");

  // Compute CSP per request (hot-reloads with admin config changes).
  res.setHeader("Content-Security-Policy", buildCsp());

  // HSTS gate on rpOrigin scheme — only emit for HTTPS deployments.
  // 2-year max-age + includeSubDomains + preload matches the
  // framework's recommended posture and the hstspreload.org policy
  // (1-year was the older minimum; preload submission requires 2-year).
  // Sent only over HTTPS — emitting HSTS on a plain-HTTP origin is
  // useless (browsers ignore) and harmful (locks browsers into HTTPS
  // for an origin the operator hasn't yet TLS-enabled).
  if (config.rpOrigin && config.rpOrigin.startsWith("https")) {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }

  // Dynamic-page Cache-Control. Static assets (CSS/JS/images/fonts)
  // skip these because the static handler already manages cache headers
  // and adding no-store breaks browser disk-cache for the asset bundle.
  // Wrapped in writeHead so the headers land on the response right
  // before flush, after any middleware that might want to set its own
  // Cache-Control (e.g. /admin/backup/db's Content-Disposition).
  var origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (statusCode, statusMessageOrHeaders, maybeHeaders) {
    var isStatic = req.pathname && /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|webp)$/.test(req.pathname);
    // A route may set its own Cache-Control either via res.setHeader (visible to
    // res.getHeader) OR inline in the writeHead headers argument (NOT yet on res).
    // Check both — otherwise the no-store block stacks a contradictory directive on
    // top of a route's cacheable Cache-Control passed through writeHead.
    var inlineHeaders = (statusMessageOrHeaders && typeof statusMessageOrHeaders === "object")
      ? statusMessageOrHeaders : maybeHeaders;
    var hasInlineCacheControl = inlineHeaders && typeof inlineHeaders === "object" &&
      Object.keys(inlineHeaders).some(function (k) { return k.toLowerCase() === "cache-control"; });
    if (!isStatic && !res.getHeader("Cache-Control") && !hasInlineCacheControl) {
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

  return bSecurityHeaders(req, res, next);
};

// Exposed for unit testing of the CSP-source sanitizer (A5-2 injection guard).
module.exports._safeCspSource = _safeCspSource;
