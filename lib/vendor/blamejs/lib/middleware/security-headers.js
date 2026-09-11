// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");

var DEFAULT_PERMISSIONS = [
  "accelerometer=()", "ambient-light-sensor=()", "autoplay=()",
  "camera=()", "display-capture=()", "encrypted-media=()", "fullscreen=()",
  "geolocation=()", "gyroscope=()", "magnetometer=()", "microphone=()",
  "midi=()", "payment=()", "picture-in-picture=()", "publickey-credentials-get=()",
  "screen-wake-lock=()", "sync-xhr=()", "usb=()", "web-share=()", "xr-spatial-tracking=()",
  "interest-cohort=()", "attribution-reporting=()",
  "bluetooth=()", "hid=()", "serial=()", "idle-detection=()",
  "local-fonts=()", "compute-pressure=()", "window-management=()",
  "private-state-token-issuance=()", "private-state-token-redemption=()",
  "storage-access=()", "browsing-topics=()",
  "private-aggregation=()", "controlled-frame=()", "captured-surface-control=()",
  "identity-credentials-get=()", "attribution-reporting-cross-site=()",
  "publickey-credentials-create=()", "join-ad-interest-group=()",
  "run-ad-auction=()", "shared-storage=()", "shared-storage-select-url=()",
  "smartcard=()", "all-screens-capture=()", "deferred-fetch=()",
];

var DEFAULT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "fenced-frame-src 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none'; " +
  "require-trusted-types-for 'script'; " +
  "trusted-types 'allow-duplicates' default;";

var DEFAULT_DOCUMENT_POLICY = false;

var PP_POLICY_RE =
  /^[a-z][a-z0-9-]*=(?:\*|\([^)]*\)|self)$/;
function _validatePermissionsPolicy(value) {
  if (typeof value !== "string" || value.length === 0) return;
  var parts = String(value).split(",");
  for (var s = 0; s < parts.length; s += 1) {
    if (s > 0) parts[s] = parts[s].trimStart();
    if (s < parts.length - 1) parts[s] = parts[s].trimEnd();
  }
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    if (!p) continue;
    if (!PP_POLICY_RE.test(p)) {  // allow:regex-no-length-cap — RFC 8941 SF entries are bounded by browser parsers; operator-supplied
      throw new TypeError(
        "middleware.securityHeaders: permissionsPolicy entry '" + p +
        "' is not a valid RFC 8941 structured field (expected " +
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
  var coep  = opts.coep === undefined ? "credentialless" : opts.coep;
  var corp  = opts.corp === undefined ? "same-origin" : opts.corp;
  var oac   = opts.originAgentCluster === undefined ? "?1" : opts.originAgentCluster;
  var dpc   = opts.dnsPrefetchControl === undefined ? "off" : opts.dnsPrefetchControl;
  var csp   = opts.csp === undefined ? DEFAULT_CSP : opts.csp;
  var docPolicy = opts.documentPolicy === undefined ? DEFAULT_DOCUMENT_POLICY : opts.documentPolicy;
  var criticalCh = opts.criticalCh && typeof opts.criticalCh === "string" ? opts.criticalCh : false;
  var acceptCh   = opts.acceptCh   && typeof opts.acceptCh   === "string" ? opts.acceptCh   : false;
  var coopReportOnly = opts.coopReportOnly && typeof opts.coopReportOnly === "string" ? opts.coopReportOnly : false;
  var coepReportOnly = opts.coepReportOnly && typeof opts.coepReportOnly === "string" ? opts.coepReportOnly : false;
  var docPolicyReportOnly = opts.documentPolicyReportOnly && typeof opts.documentPolicyReportOnly === "string" ? opts.documentPolicyReportOnly : false;
  var requireDocPolicy = opts.requireDocumentPolicy && typeof opts.requireDocumentPolicy === "string" ? opts.requireDocumentPolicy : false;
  var serviceWorkerAllowed = opts.serviceWorkerAllowed && typeof opts.serviceWorkerAllowed === "string" ? opts.serviceWorkerAllowed : false;
  var reportingEndpoints = null;
  if (opts.reportingEndpoints && typeof opts.reportingEndpoints === "object") {
    var pairs = [];
    var keys = Object.keys(opts.reportingEndpoints);
    for (var i = 0; i < keys.length; i += 1) {
      var k = keys[i];
      var v = opts.reportingEndpoints[k];
      if (typeof v !== "string" || v.length === 0) continue;
      if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) continue;                   // allow:duplicate-regex — CR/LF/NUL header-injection rejection appears in cookies / mail / security-headers; each is the boundary primitive — extracting forces a shared module that hides the boundary check from each domain
      pairs.push(k + '="' + v + '"');
    }
    if (pairs.length > 0) reportingEndpoints = pairs.join(", ");
  }
  if (csp === DEFAULT_CSP && reportingEndpoints &&
      opts.reportingEndpoints && opts.reportingEndpoints["default"]) {
    csp = csp.replace(/;\s*$/, "") + "; report-to default;";
  }

  return function securityHeaders(req, res, next) {
    if (typeof res.setHeader !== "function") return next();
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
