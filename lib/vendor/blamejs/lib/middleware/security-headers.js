"use strict";
/**
 * Security headers middleware. Sets the headers every modern app should
 * send, regardless of content. Deliberately strict by default — operators
 * who need to soften a header opt in explicitly per option.
 *
 *   Strict-Transport-Security        — force HTTPS (HSTS); 2-year max-age + includeSubDomains + preload
 *   X-Content-Type-Options: nosniff  — block MIME sniffing
 *   X-Frame-Options: DENY            — prevent clickjacking via iframes
 *   Referrer-Policy: no-referrer     — don't leak full URL to outbound links
 *   Permissions-Policy               — disable common-attack APIs (camera, geolocation, payment, etc.)
 *   Cross-Origin-Opener-Policy: same-origin
 *   Cross-Origin-Embedder-Policy: require-corp   (off by default — breaks images from CDNs)
 *   Cross-Origin-Resource-Policy: same-origin
 *   Origin-Agent-Cluster: ?1        — origin-keyed agent cluster; extra process isolation
 *   X-DNS-Prefetch-Control: off     — don't pre-resolve DNS for off-page links
 *   Content-Security-Policy          — operator-supplied; framework provides a safe default that
 *                                       only allows same-origin and prevents inline scripts
 *
 * These are the OWASP-aligned defaults. Apps that need different policies
 * (e.g. allow-list for analytics scripts, embed iframes from a known
 * partner) override per-option without losing the others.
 *
 * Options:
 *   {
 *     hsts:                 '<value>' or false to disable
 *     contentTypeOptions:   'nosniff' or false
 *     frameOptions:         'DENY' | 'SAMEORIGIN' or false
 *     referrerPolicy:       '<value>' or false
 *     permissionsPolicy:    '<value>' or false
 *     coop / coep / corp:   '<value>' or false
 *     originAgentCluster:   '?1' (default) or '?0' or false
 *     dnsPrefetchControl:   'off' (default) or 'on' or false
 *     csp:                  '<full CSP string>' or false to disable
 *   }
 */

var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");

var DEFAULT_PERMISSIONS = [
  "accelerometer=()", "ambient-light-sensor=()", "autoplay=()",
  "camera=()", "display-capture=()", "encrypted-media=()", "fullscreen=()",
  "geolocation=()", "gyroscope=()", "magnetometer=()", "microphone=()",
  "midi=()", "payment=()", "picture-in-picture=()", "publickey-credentials-get=()",
  "screen-wake-lock=()", "sync-xhr=()", "usb=()", "web-share=()", "xr-spatial-tracking=()",
  // v0.8.33 expansion — newer Permissions-Policy feature names that
  // weren't deny-by-default before. interest-cohort (FLoC, deprecated
  // but still recognized), attribution-reporting (Privacy Sandbox),
  // bluetooth / hid / serial (Web USB-shaped APIs), idle-detection,
  // local-fonts (system-font fingerprinting), compute-pressure
  // (CPU-load-side-channel), window-management (multi-screen probe),
  // and the private-state-token-* family (Privacy-Pass-style anti-
  // fraud tokens). Operators wanting any of these explicitly opt in
  // by passing their own permissionsPolicy.
  "interest-cohort=()", "attribution-reporting=()",
  "bluetooth=()", "hid=()", "serial=()", "idle-detection=()",
  "local-fonts=()", "compute-pressure=()", "window-management=()",
  "private-state-token-issuance=()", "private-state-token-redemption=()",
  // v0.8.70 expansion — Privacy-Sandbox + Storage Access feature
  // names that landed in Chrome 119+/120+ stable. Default-deny:
  //   - storage-access — Storage Access API (cross-site cookie
  //     access flow under Privacy Sandbox); operators serving an
  //     embedded-iframe SaaS opt in explicitly.
  //   - browsing-topics — Topics API (replacement for FLoC);
  //     enabled by default in Chrome but trackable surface, so
  //     deny-by-default unless the operator opts in.
  //   - private-aggregation, attribution-reporting-cross-site —
  //     Privacy Sandbox aggregation APIs; deny-by-default.
  //   - controlled-frame, captured-surface-control — Web App
  //     embedding APIs; deny-by-default.
  "storage-access=()", "browsing-topics=()",
  "private-aggregation=()", "controlled-frame=()", "captured-surface-control=()",
];

// Strict CSP — no 'unsafe-inline' on script-src OR style-src.
// Trusted Types (require-trusted-types-for 'script') enables the
// browser's strongest XSS-mitigation primitive — DOM-sink writes via
// innerHTML / outerHTML / setHTML require typed values, surfacing
// every untrusted-string-to-DOM path at runtime so operators can audit
// + fix them. Compatible browsers (Chrome 83+, Edge 83+) enforce;
// Firefox + Safari ignore (no regression). Operators with inline
// scripts wire `b.middleware.cspNonce()` and use `{{ cspNonce }}` in
// views.
var DEFAULT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  // CSP3 fenced-frame-src: refuse <fencedframe> embeds entirely. The
  // Privacy-Sandbox-era element bypasses traditional frame controls;
  // operators wanting to embed a Privacy-Sandbox vendor opt in by
  // passing their own csp.
  "fenced-frame-src 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none'; " +
  "require-trusted-types-for 'script'; " +
  "trusted-types 'allow-duplicates' default;";

// Document-Policy default — denies the highest-risk DOM/JS surfaces
// that aren't otherwise covered by Permissions-Policy. `unsized-media`
// blocks layout-jank from images without explicit width/height,
// `oversized-images` caps the served-vs-displayed ratio, and the
// document-write feature disables the legacy synchronous DOM-injection
// API. Operators with a third-party widget that needs the legacy API
// override.
var DEFAULT_DOCUMENT_POLICY =
  "document-write=?0, " +
  "unsized-media=?0, " +
  "oversized-images=?0";

// RFC 9651 (Structured Field Values) Permissions-Policy validation —
// each policy is `feature=value-list` where value-list is `*` /
// `(self)` / `(self "https://...")` / `()` (empty = deny). Reject
// header values that don't conform; operators get a clear refusal at
// boot rather than a silently-broken header at runtime.
var PP_POLICY_RE =
  /^[a-z][a-z0-9-]*=(?:\*|\([^)]*\)|self)$/;
function _validatePermissionsPolicy(value) {
  if (typeof value !== "string" || value.length === 0) return;
  var parts = String(value).split(/\s*,\s*/);
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    if (!p) continue;
    if (!PP_POLICY_RE.test(p)) {  // allow:regex-no-length-cap — RFC 9651 SF entries are bounded by browser parsers; operator-supplied
      throw new TypeError(
        "middleware.securityHeaders: permissionsPolicy entry '" + p +
        "' is not a valid RFC 9651 structured field (expected " +
        "'feature=*' / 'feature=()' / 'feature=(self ...)')");
    }
  }
}

/**
 * @primitive b.middleware.securityHeaders
 * @signature b.middleware.securityHeaders(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.cspNonce, b.middleware.cspReport, b.middleware.cors
 *
 * Sets the OWASP-aligned response headers every modern app should
 * send. Constructed via `b.middleware.securityHeaders(opts)`; the
 * resulting middleware has the `(req, res, next)` shape shown above.
 * Headers include: HSTS (2-year max-age + includeSubDomains + preload), X-CTO
 * nosniff, X-Frame-Options DENY, Referrer-Policy no-referrer, an
 * extensive Permissions-Policy denylist (camera / geolocation /
 * payment / Privacy-Sandbox attribution-reporting / bluetooth /
 * etc.), COOP same-origin, CORP same-origin, Origin-Agent-Cluster
 * `?1`, and a strict default CSP with `require-trusted-types-for
 * 'script'`. Each header can be softened by passing the option
 * value or disabled by passing `false`. Mount FIRST (after
 * `requestId`) so headers are set before any response could be
 * partially sent.
 *
 * @opts
 *   {
 *     hsts:               string|false,
 *     contentTypeOptions: "nosniff"|false,
 *     frameOptions:       "DENY"|"SAMEORIGIN"|false,
 *     referrerPolicy:     string|false,
 *     permissionsPolicy:  string|false,
 *     coop:               string|false,
 *     coep:               string|false,
 *     corp:               string|false,
 *     originAgentCluster: "?1"|"?0"|false,
 *     dnsPrefetchControl: "off"|"on"|false,
 *     csp:                string|false,
 *     documentPolicy:     string|false,
 *     acceptCh:           string|false,
 *     criticalCh:         string|false,
 *     reportingEndpoints: object,
 *     trustProxy:         boolean|number,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.securityHeaders({
 *     hsts: "max-age=63072000; includeSubDomains; preload",
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "hsts", "contentTypeOptions", "frameOptions", "referrerPolicy",
    "permissionsPolicy", "coop", "coep", "corp",
    "originAgentCluster", "dnsPrefetchControl", "csp", "trustProxy",
    "reportingEndpoints", "documentPolicy", "criticalCh", "acceptCh",
  ], "middleware.securityHeaders");
  if (opts.permissionsPolicy && typeof opts.permissionsPolicy === "string") {
    _validatePermissionsPolicy(opts.permissionsPolicy);
  }
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var hsts = opts.hsts === undefined ? "max-age=63072000; includeSubDomains; preload" : opts.hsts;
  var ctOpts = opts.contentTypeOptions === undefined ? "nosniff" : opts.contentTypeOptions;
  var frameOpts = opts.frameOptions === undefined ? "DENY" : opts.frameOptions;
  var refPolicy = opts.referrerPolicy === undefined ? "no-referrer" : opts.referrerPolicy;
  var permPolicy = opts.permissionsPolicy === undefined ? DEFAULT_PERMISSIONS.join(", ") : opts.permissionsPolicy;
  var coop  = opts.coop === undefined ? "same-origin" : opts.coop;
  var coep  = opts.coep === undefined ? false : opts.coep;
  var corp  = opts.corp === undefined ? "same-origin" : opts.corp;
  var oac   = opts.originAgentCluster === undefined ? "?1" : opts.originAgentCluster;
  var dpc   = opts.dnsPrefetchControl === undefined ? "off" : opts.dnsPrefetchControl;
  var csp   = opts.csp === undefined ? DEFAULT_CSP : opts.csp;
  var docPolicy = opts.documentPolicy === undefined ? DEFAULT_DOCUMENT_POLICY : opts.documentPolicy;
  var criticalCh = opts.criticalCh && typeof opts.criticalCh === "string" ? opts.criticalCh : false;
  var acceptCh   = opts.acceptCh   && typeof opts.acceptCh   === "string" ? opts.acceptCh   : false;
  // Reporting-Endpoints (W3C Reporting API) — when operator passes a
  // map of endpoint-name → URL, we emit `Reporting-Endpoints: name="url",
  // name2="url2", ...` and (when default CSP is in force) append
  // `report-to default` to the CSP so violations route to the named
  // endpoint. Operators using a custom CSP add `report-to` to it
  // themselves.
  var reportingEndpoints = null;
  if (opts.reportingEndpoints && typeof opts.reportingEndpoints === "object") {
    var pairs = [];
    var keys = Object.keys(opts.reportingEndpoints);
    for (var i = 0; i < keys.length; i += 1) {
      var k = keys[i];
      var v = opts.reportingEndpoints[k];
      if (typeof v !== "string" || v.length === 0) continue;
      // Defensive — refuse CR/LF/NUL in either side (header injection).
      if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) continue;                   // allow:duplicate-regex — CR/LF/NUL header-injection rejection appears in cookies / mail / security-headers; each is the boundary primitive — extracting forces a shared module that hides the boundary check from each domain
      pairs.push(k + '="' + v + '"');
    }
    if (pairs.length > 0) reportingEndpoints = pairs.join(", ");
  }
  // Auto-append `report-to default` to the default CSP when operator
  // wires a `default` reporting endpoint and didn't override `csp`.
  if (csp === DEFAULT_CSP && reportingEndpoints &&
      opts.reportingEndpoints && opts.reportingEndpoints["default"]) {
    csp = csp.replace(/;\s*$/, "") + "; report-to default;";
  }

  return function securityHeaders(req, res, next) {
    if (typeof res.setHeader !== "function") return next();
    // RFC 6797 §7.2: HSTS over plain HTTP is meaningless (UAs ignore
    // it). Skip the header on non-TLS requests so dev-over-HTTP doesn't
    // surface confusing "Strict-Transport-Security on http://" lines.
    // requestProtocol respects trustProxy — operators behind a TLS
    // terminator opt in to read X-Forwarded-Proto.
    if (hsts && requestHelpers.requestProtocol(req, { trustProxy: trustProxy }) === "https") {
      res.setHeader("Strict-Transport-Security", hsts);
    }
    if (ctOpts)     res.setHeader("X-Content-Type-Options", ctOpts);
    if (frameOpts)  res.setHeader("X-Frame-Options", frameOpts);
    if (refPolicy)  res.setHeader("Referrer-Policy", refPolicy);
    if (permPolicy) res.setHeader("Permissions-Policy", permPolicy);
    if (coop)       res.setHeader("Cross-Origin-Opener-Policy", coop);
    if (coep)       res.setHeader("Cross-Origin-Embedder-Policy", coep);
    if (corp)       res.setHeader("Cross-Origin-Resource-Policy", corp);
    if (oac)        res.setHeader("Origin-Agent-Cluster", oac);
    if (dpc)        res.setHeader("X-DNS-Prefetch-Control", dpc);
    if (csp)                res.setHeader("Content-Security-Policy", csp);
    if (docPolicy)          res.setHeader("Document-Policy", docPolicy);
    if (acceptCh)           res.setHeader("Accept-CH", acceptCh);
    if (criticalCh)         res.setHeader("Critical-CH", criticalCh);
    if (reportingEndpoints) res.setHeader("Reporting-Endpoints", reportingEndpoints);
    next();
  };
}

module.exports = {
  create:                  create,
  DEFAULT_PERMISSIONS:     DEFAULT_PERMISSIONS,
  DEFAULT_CSP:             DEFAULT_CSP,
  DEFAULT_DOCUMENT_POLICY: DEFAULT_DOCUMENT_POLICY,
};
