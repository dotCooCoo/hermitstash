"use strict";
/**
 * b.middleware.securityHeaders — v0.8.53 additions.
 *
 * Layer 0 primitive coverage for the new opts shipped in v0.8.53:
 *   - CSP3 fenced-frame-src 'none' in DEFAULT_CSP
 *   - Document-Policy header (default + custom + disable)
 *   - Accept-CH / Critical-CH UA Client Hints retry handshake
 *   - RFC 9651 Permissions-Policy structured-fields validation
 *
 * The pre-v0.8.53 surface (HSTS, CSP, COOP, etc.) is exercised in the
 * existing smoke tests at test/00-primitives.js — this file covers
 * only the new opts so the per-primitive test discipline is honored.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _mkRes() {
  var hdrs = {};
  return {
    _hdrs: hdrs,
    setHeader: function (k, v) { hdrs[k] = v; },
  };
}

function testFencedFrameSrcInDefaultCsp() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  var csp = res._hdrs["Content-Security-Policy"];
  check("DEFAULT_CSP includes fenced-frame-src 'none'",
    typeof csp === "string" && csp.indexOf("fenced-frame-src 'none'") !== -1);
}

function testDocumentPolicyDefault() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  var dp = res._hdrs["Document-Policy"];
  check("Document-Policy default emits document-write=?0",
    typeof dp === "string" && dp.indexOf("document-write=?0") !== -1);
  check("Document-Policy default emits unsized-media=?0",
    typeof dp === "string" && dp.indexOf("unsized-media=?0") !== -1);
  check("Document-Policy default emits oversized-images=?0",
    typeof dp === "string" && dp.indexOf("oversized-images=?0") !== -1);
}

function testDocumentPolicyOperatorOverride() {
  var mw = b.middleware.securityHeaders({ documentPolicy: "force-load-at-top=?0" });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Document-Policy override honored",
    res._hdrs["Document-Policy"] === "force-load-at-top=?0");
}

function testDocumentPolicyDisabled() {
  var mw = b.middleware.securityHeaders({ documentPolicy: false });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Document-Policy: false suppresses the header",
    res._hdrs["Document-Policy"] === undefined);
}

function testAcceptChAndCriticalCh() {
  var mw = b.middleware.securityHeaders({
    acceptCh:   "Sec-CH-UA, Sec-CH-UA-Mobile",
    criticalCh: "Sec-CH-UA",
  });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Accept-CH set when operator opts in",
    res._hdrs["Accept-CH"] === "Sec-CH-UA, Sec-CH-UA-Mobile");
  check("Critical-CH set when operator opts in (browser retries first response)",
    res._hdrs["Critical-CH"] === "Sec-CH-UA");
}

function testAcceptChDefaultOff() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Accept-CH: default off (opt-in surface)",
    res._hdrs["Accept-CH"] === undefined);
  check("Critical-CH: default off (opt-in surface)",
    res._hdrs["Critical-CH"] === undefined);
}

function testPermissionsPolicyStructuredFieldsAccepted() {
  var ok = false;
  try {
    b.middleware.securityHeaders({
      permissionsPolicy: "geolocation=(), camera=*, microphone=(self)",
    });
    ok = true;
  } catch (_e) { ok = false; }
  check("RFC 9651 Permissions-Policy: well-formed entries accepted at config-time", ok);
}

function testPermissionsPolicyMalformedRefused() {
  var threw = false;
  try {
    b.middleware.securityHeaders({
      permissionsPolicy: "geolocation",   // missing `=value`
    });
  } catch (e) {
    threw = e instanceof TypeError && /RFC 9651/.test(e.message);
  }
  check("RFC 9651 Permissions-Policy: malformed entry refused at config-time", threw);
}

function testPermissionsPolicyBareWordRefused() {
  var threw = false;
  try {
    b.middleware.securityHeaders({
      permissionsPolicy: "geolocation=yes",   // not a valid SF value-list
    });
  } catch (e) {
    threw = e instanceof TypeError;
  }
  check("RFC 9651 Permissions-Policy: bare-word value refused", threw);
}

function testPermissionsPolicyMultiEntryAccepted() {
  var ok = false;
  try {
    b.middleware.securityHeaders({
      permissionsPolicy: "camera=(), microphone=(), payment=()",
    });
    ok = true;
  } catch (_e) { ok = false; }
  check("RFC 9651 Permissions-Policy: comma-separated entries accepted", ok);
}

function testV0870PermissionsPolicyDefaults() {
  // v0.8.70: storage-access / browsing-topics / private-aggregation /
  // controlled-frame / captured-surface-control denied by default.
  var sec = require("../../lib/middleware/security-headers");
  var perms = sec.DEFAULT_PERMISSIONS.join(" ");
  check("DEFAULT_PERMISSIONS: storage-access denied",          perms.indexOf("storage-access=()") !== -1);
  check("DEFAULT_PERMISSIONS: browsing-topics denied",         perms.indexOf("browsing-topics=()") !== -1);
  check("DEFAULT_PERMISSIONS: private-aggregation denied",     perms.indexOf("private-aggregation=()") !== -1);
  check("DEFAULT_PERMISSIONS: controlled-frame denied",        perms.indexOf("controlled-frame=()") !== -1);
  check("DEFAULT_PERMISSIONS: captured-surface-control denied", perms.indexOf("captured-surface-control=()") !== -1);
}

function testDefaultDocumentPolicyExportedConstant() {
  var m = b.middleware._modules.securityHeaders;
  check("DEFAULT_DOCUMENT_POLICY exported for operator inspection",
    typeof m.DEFAULT_DOCUMENT_POLICY === "string" && m.DEFAULT_DOCUMENT_POLICY.length > 0);
}

function testReportOnlyHeadersEmittedWhenOptedIn() {
  var mw = b.middleware.securityHeaders({
    coopReportOnly:           'same-origin; report-to="coop"',
    coepReportOnly:           'require-corp; report-to="coep"',
    documentPolicyReportOnly: 'document-write=?0; report-to="docpol"',
  });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Cross-Origin-Opener-Policy-Report-Only emitted when coopReportOnly set",
    res._hdrs["Cross-Origin-Opener-Policy-Report-Only"] === 'same-origin; report-to="coop"');
  check("Cross-Origin-Embedder-Policy-Report-Only emitted when coepReportOnly set",
    res._hdrs["Cross-Origin-Embedder-Policy-Report-Only"] === 'require-corp; report-to="coep"');
  check("Document-Policy-Report-Only emitted when documentPolicyReportOnly set",
    res._hdrs["Document-Policy-Report-Only"] === 'document-write=?0; report-to="docpol"');
}

function testReportOnlyDoesNotTouchEnforcingHeaders() {
  // Monitor-mode opt-ins must not alter the enforcing COOP / COEP /
  // Document-Policy headers: COOP stays same-origin, the enforcing COEP
  // keeps its default-on `credentialless` value (the report-only opt is a
  // separate header), Document-Policy keeps its enforcing default.
  var mw = b.middleware.securityHeaders({
    coopReportOnly: "same-origin",
    coepReportOnly: "require-corp",
  });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("enforcing COOP unchanged by coopReportOnly",
    res._hdrs["Cross-Origin-Opener-Policy"] === "same-origin");
  check("enforcing COEP keeps its default-on value despite coepReportOnly",
    res._hdrs["Cross-Origin-Embedder-Policy"] === "credentialless");
  check("enforcing Document-Policy unchanged by report-only opts",
    res._hdrs["Document-Policy"] === b.middleware._modules.securityHeaders.DEFAULT_DOCUMENT_POLICY);
}

function testReportOnlyDefaultOff() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Cross-Origin-Opener-Policy-Report-Only default off",
    res._hdrs["Cross-Origin-Opener-Policy-Report-Only"] === undefined);
  check("Cross-Origin-Embedder-Policy-Report-Only default off",
    res._hdrs["Cross-Origin-Embedder-Policy-Report-Only"] === undefined);
  check("Document-Policy-Report-Only default off",
    res._hdrs["Document-Policy-Report-Only"] === undefined);
}

function testRequireDocumentPolicyEmittedWhenOptedIn() {
  var mw = b.middleware.securityHeaders({ requireDocumentPolicy: "unsized-media=?0" });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Require-Document-Policy emitted when opted in",
    res._hdrs["Require-Document-Policy"] === "unsized-media=?0");
}

function testRequireDocumentPolicyDefaultOff() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Require-Document-Policy default off",
    res._hdrs["Require-Document-Policy"] === undefined);
}

function testServiceWorkerAllowedEmittedWhenOptedIn() {
  var mw = b.middleware.securityHeaders({ serviceWorkerAllowed: "/" });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Service-Worker-Allowed emitted when opted in",
    res._hdrs["Service-Worker-Allowed"] === "/");
}

function testServiceWorkerAllowedDefaultOff() {
  var mw = b.middleware.securityHeaders();
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("Service-Worker-Allowed default off",
    res._hdrs["Service-Worker-Allowed"] === undefined);
}

function testNewOptsNonStringIgnored() {
  // Defensive reader: a non-string (truthy-but-wrong) value emits no
  // header rather than serializing an object into the response.
  var mw = b.middleware.securityHeaders({
    coopReportOnly:        { not: "a string" },
    serviceWorkerAllowed:  123,
    requireDocumentPolicy: [],
  });
  var res = _mkRes();
  mw({ headers: {} }, res, function () {});
  check("non-string coopReportOnly emits no header",
    res._hdrs["Cross-Origin-Opener-Policy-Report-Only"] === undefined);
  check("non-string serviceWorkerAllowed emits no header",
    res._hdrs["Service-Worker-Allowed"] === undefined);
  check("non-string requireDocumentPolicy emits no header",
    res._hdrs["Require-Document-Policy"] === undefined);
}

function testUnknownOptStillRefused() {
  var threw = false;
  try {
    b.middleware.securityHeaders({ coopReportOnlyy: "same-origin" });
  } catch (_e) { threw = true; }
  check("typo'd report-only opt refused at config-time", threw);
}

function testCoepDefaultOnAndOptOut() {
  // Default-on (v0.15.0): the enforcing Cross-Origin-Embedder-Policy is
  // emitted as `credentialless` with no operator action, so COOP+COEP
  // together yield cross-origin isolation out of the box.
  var resDefault = _mkRes();
  b.middleware.securityHeaders()({ headers: {} }, resDefault, function () {});
  check("COEP default-on: Cross-Origin-Embedder-Policy is credentialless",
    resDefault._hdrs["Cross-Origin-Embedder-Policy"] === "credentialless");
  check("COOP stays same-origin alongside the default COEP",
    resDefault._hdrs["Cross-Origin-Opener-Policy"] === "same-origin");

  // Tighten: operators serving only same-origin / CORP-marked subresources
  // pass coep: "require-corp" for the strict enforcing mode.
  var resStrict = _mkRes();
  b.middleware.securityHeaders({ coep: "require-corp" })({ headers: {} }, resStrict, function () {});
  check("COEP tighten: coep:'require-corp' overrides the default",
    resStrict._hdrs["Cross-Origin-Embedder-Policy"] === "require-corp");

  // Documented opt-out: coep:false disables COEP entirely (no header).
  var resOff = _mkRes();
  b.middleware.securityHeaders({ coep: false })({ headers: {} }, resOff, function () {});
  check("COEP opt-out: coep:false emits no Cross-Origin-Embedder-Policy header",
    resOff._hdrs["Cross-Origin-Embedder-Policy"] === undefined);
}

async function run() {
  testFencedFrameSrcInDefaultCsp();
  testDocumentPolicyDefault();
  testDocumentPolicyOperatorOverride();
  testDocumentPolicyDisabled();
  testAcceptChAndCriticalCh();
  testAcceptChDefaultOff();
  testPermissionsPolicyStructuredFieldsAccepted();
  testPermissionsPolicyMalformedRefused();
  testPermissionsPolicyBareWordRefused();
  testPermissionsPolicyMultiEntryAccepted();
  testV0870PermissionsPolicyDefaults();
  testDefaultDocumentPolicyExportedConstant();
  testReportOnlyHeadersEmittedWhenOptedIn();
  testReportOnlyDoesNotTouchEnforcingHeaders();
  testReportOnlyDefaultOff();
  testRequireDocumentPolicyEmittedWhenOptedIn();
  testRequireDocumentPolicyDefaultOff();
  testServiceWorkerAllowedEmittedWhenOptedIn();
  testServiceWorkerAllowedDefaultOff();
  testNewOptsNonStringIgnored();
  testUnknownOptStillRefused();
  testCoepDefaultOnAndOptOut();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
