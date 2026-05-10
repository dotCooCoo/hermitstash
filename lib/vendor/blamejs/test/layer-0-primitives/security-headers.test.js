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

function testDefaultDocumentPolicyExportedConstant() {
  var m = b.middleware._modules.securityHeaders;
  check("DEFAULT_DOCUMENT_POLICY exported for operator inspection",
    typeof m.DEFAULT_DOCUMENT_POLICY === "string" && m.DEFAULT_DOCUMENT_POLICY.length > 0);
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
  testDefaultDocumentPolicyExportedConstant();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
