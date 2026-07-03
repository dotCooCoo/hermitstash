// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   Cross-Origin-Embedder-Policy: credentialless   (default-on — with COOP
 *   same-origin this yields cross-origin isolation; credentialless is the
 *   relaxed enforcing mode that lets cross-origin no-cors requests load
 *   without CORP markers as long as they don't carry credentials, so CDN
 *   images/fonts keep working. Pass coep: "require-corp" to tighten, or
 *   coep: false to disable.)
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
 *
 * Monitor-mode opt-ins (all default-off; unset emits no new header):
 *
 *   coopReportOnly / coepReportOnly / documentPolicyReportOnly — set a
 *     policy string to emit the matching `*-Report-Only` header so the
 *     operator can roll out the enforcing policy in monitor mode first.
 *     The browser reports violations (to a Reporting-Endpoints group named
 *     in the value, e.g. `same-origin; report-to="coop"`) without blocking.
 *   requireDocumentPolicy — the embedder-required Document-Policy a
 *     subframe must advertise before this document will embed it.
 *   serviceWorkerAllowed — broadens the max scope a service worker
 *     registered from this script may claim (the operator opts in).
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
  // v0.8.77 expansion — remaining Privacy Sandbox + Browser-API
  // directives surfacing through Chrome 130+ / Firefox 132+ stable.
  // Default-deny: FedCM (identity-credentials-get), cross-site
  // attribution reporting, WebAuthn create flow (operators that need
  // it opt in explicitly), FLEDGE/Topics auction APIs (join-ad-
  // interest-group / run-ad-auction), Shared Storage API + selectURL,
  // Smart Card API, all-screens capture, deferred-fetch (background
  // resource sync).
  "identity-credentials-get=()", "attribution-reporting-cross-site=()",
  "publickey-credentials-create=()", "join-ad-interest-group=()",
  "run-ad-auction=()", "shared-storage=()", "shared-storage-select-url=()",
  "smartcard=()", "all-screens-capture=()", "deferred-fetch=()",
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
  // Split on the literal comma, then strip whitespace adjacent to each comma —
  // the semantics of /\s*,\s*/ without that pattern's O(n^2) backtracking on a
  // long comma-less run of whitespace. trimStart/trimEnd use the same Unicode
  // whitespace set as \s.
  var parts = String(value).split(",");
  for (var s = 0; s < parts.length; s += 1) {
    if (s > 0) parts[s] = parts[s].trimStart();
    if (s < parts.length - 1) parts[s] = parts[s].trimEnd();
  }
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
 * etc.), COOP same-origin, COEP credentialless (cross-origin isolation
 * on by default; pass `coep: false` to disable), CORP same-origin,
 * Origin-Agent-Cluster `?1`, and a strict default CSP with `require-trusted-types-for
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
 *     trustedProxies:     string|string[],  // CIDRs of your reverse proxies — peer-gates X-Forwarded-Proto for HSTS
 *     protocolResolver:   function(req): "http"|"https",  // own the HTTPS decision
 *     trustProxy:         boolean|number,    // legacy; refused unless paired with trustedProxies/protocolResolver (spoofable)
 *     coopReportOnly:           string,  // default: off — monitor-mode COOP
 *     coepReportOnly:           string,  // default: off — monitor-mode COEP
 *     documentPolicyReportOnly: string,  // default: off — monitor-mode Document-Policy
 *     requireDocumentPolicy:    string,  // default: off — embedder-required subframe policy
 *     serviceWorkerAllowed:     string,  // default: off — broadens SW registration scope
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
    "trustedProxies", "protocolResolver",
    "reportingEndpoints", "documentPolicy", "criticalCh", "acceptCh",
    "coopReportOnly", "coepReportOnly", "documentPolicyReportOnly",
    "requireDocumentPolicy", "serviceWorkerAllowed",
  ], "middleware.securityHeaders");
  if (opts.permissionsPolicy && typeof opts.permissionsPolicy === "string") {
    _validatePermissionsPolicy(opts.permissionsPolicy);
  }
  // HSTS is emitted only on HTTPS responses; behind a proxy that comes from
  // X-Forwarded-Proto. A bare trustProxy trusts the forgeable header from any
  // caller, so a direct request forging "http" could suppress HSTS on a real
  // HTTPS response (SSL-strip window). Peer-gate it via trustedProxies, or own
  // the decision via protocolResolver; a bare trustProxy is refused.
  var _proto;
  try {
    _proto = requestHelpers.trustedProtocol({
      trustedProxies:   opts.trustedProxies,
      protocolResolver: opts.protocolResolver,
    });
  } catch (e) { throw new TypeError("middleware.securityHeaders: " + e.message); }
  if ((opts.trustProxy === true || typeof opts.trustProxy === "number") && !_proto.peerGated) {
    throw new TypeError("middleware.securityHeaders: trustProxy is spoofable for the HSTS " +
      "decision — a direct caller could forge X-Forwarded-Proto to suppress HSTS. Declare your " +
      "reverse proxies via trustedProxies: [\"10.0.0.0/8\", …] or supply protocolResolver(req).");
  }
  var hsts = opts.hsts === undefined ? "max-age=63072000; includeSubDomains; preload" : opts.hsts;
  var ctOpts = opts.contentTypeOptions === undefined ? "nosniff" : opts.contentTypeOptions;
  var frameOpts = opts.frameOptions === undefined ? "DENY" : opts.frameOptions;
  var refPolicy = opts.referrerPolicy === undefined ? "no-referrer" : opts.referrerPolicy;
  var permPolicy = opts.permissionsPolicy === undefined ? DEFAULT_PERMISSIONS.join(", ") : opts.permissionsPolicy;
  var coop  = opts.coop === undefined ? "same-origin" : opts.coop;
  // COEP default-on (v0.15.0): emit Cross-Origin-Embedder-Policy:
  // credentialless. With COOP same-origin this completes cross-origin
  // isolation (crossOriginIsolated === true), re-enabling SharedArrayBuffer
  // / high-resolution timers while closing the Spectre-class cross-origin
  // read surface. `credentialless` (HTML spec, shipped Chrome 110+) is the
  // least-breaking enforcing mode: cross-origin no-cors subresources (CDN
  // images, fonts) still load — they're fetched WITHOUT credentials rather
  // than requiring an explicit CORP/CORS opt-in, so existing pages keep
  // working where `require-corp` would have broken them. Operators serving
  // credentialed cross-origin subresources pass coep: "require-corp" (and
  // add CORP/CORS headers), or coep: false to opt out of COEP entirely.
  var coep  = opts.coep === undefined ? "credentialless" : opts.coep;
  var corp  = opts.corp === undefined ? "same-origin" : opts.corp;
  var oac   = opts.originAgentCluster === undefined ? "?1" : opts.originAgentCluster;
  var dpc   = opts.dnsPrefetchControl === undefined ? "off" : opts.dnsPrefetchControl;
  var csp   = opts.csp === undefined ? DEFAULT_CSP : opts.csp;
  var docPolicy = opts.documentPolicy === undefined ? DEFAULT_DOCUMENT_POLICY : opts.documentPolicy;
  var criticalCh = opts.criticalCh && typeof opts.criticalCh === "string" ? opts.criticalCh : false;
  var acceptCh   = opts.acceptCh   && typeof opts.acceptCh   === "string" ? opts.acceptCh   : false;
  // Monitor-mode + scope opt-ins — all default-off. Each only emits its
  // header when the operator passes a non-empty string; unset = silent.
  //   coopReportOnly / coepReportOnly — WHATWG HTML cross-origin isolation
  //     report-only variants: the UA evaluates the policy and reports
  //     violations to the named Reporting-Endpoints group without
  //     enforcing, so an operator can verify a same-origin / require-corp
  //     rollout won't break embeds before flipping the enforcing header.
  //   documentPolicyReportOnly — W3C Document Policy report-only variant
  //     (same monitor-mode semantics for the Document-Policy feature set).
  //   requireDocumentPolicy — W3C Document Policy: the policy a subframe
  //     must itself advertise (via Document-Policy) before this document
  //     will embed it; the embedder declares its floor.
  //   serviceWorkerAllowed — W3C Service Workers §Service-Worker-Allowed:
  //     widens the max scope a worker registered from this script may
  //     claim beyond the script's own path. Operator opts in explicitly.
  var coopReportOnly = opts.coopReportOnly && typeof opts.coopReportOnly === "string" ? opts.coopReportOnly : false;
  var coepReportOnly = opts.coepReportOnly && typeof opts.coepReportOnly === "string" ? opts.coepReportOnly : false;
  var docPolicyReportOnly = opts.documentPolicyReportOnly && typeof opts.documentPolicyReportOnly === "string" ? opts.documentPolicyReportOnly : false;
  var requireDocPolicy = opts.requireDocumentPolicy && typeof opts.requireDocumentPolicy === "string" ? opts.requireDocumentPolicy : false;
  var serviceWorkerAllowed = opts.serviceWorkerAllowed && typeof opts.serviceWorkerAllowed === "string" ? opts.serviceWorkerAllowed : false;
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
    // Peer-gated protocol resolution — X-Forwarded-Proto honored only from a
    // trusted proxy (trustedProxies / protocolResolver), else the TLS socket.
    if (hsts && _proto.resolve(req) === "https") {
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
    // Monitor-mode + scope opt-ins — emitted only when the operator set
    // the corresponding opt; the enforcing COOP/COEP/Document-Policy
    // headers above are unaffected.
    if (coopReportOnly)       res.setHeader("Cross-Origin-Opener-Policy-Report-Only", coopReportOnly);
    if (coepReportOnly)       res.setHeader("Cross-Origin-Embedder-Policy-Report-Only", coepReportOnly);
    if (docPolicyReportOnly)  res.setHeader("Document-Policy-Report-Only", docPolicyReportOnly);
    if (requireDocPolicy)     res.setHeader("Require-Document-Policy", requireDocPolicy);
    if (serviceWorkerAllowed) res.setHeader("Service-Worker-Allowed", serviceWorkerAllowed);
    next();
  };
}

module.exports = {
  create:                  create,
  DEFAULT_PERMISSIONS:     DEFAULT_PERMISSIONS,
  DEFAULT_CSP:             DEFAULT_CSP,
  DEFAULT_DOCUMENT_POLICY: DEFAULT_DOCUMENT_POLICY,
};
