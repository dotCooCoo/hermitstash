"use strict";
/**
 * b.fapi2 — FAPI 2.0 conformance posture assertion.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("fapi2.assertConformance is fn", typeof b.fapi2.assertConformance === "function");
  check("fapi2.assertOAuthConfig is fn", typeof b.fapi2.assertOAuthConfig === "function");
  check("fapi2.posture is fn",            typeof b.fapi2.posture === "function");
  check("fapi2.Fapi2Error is fn",         typeof b.fapi2.Fapi2Error === "function");
  check("SENDER_CONSTRAINTS",             Array.isArray(b.fapi2.SENDER_CONSTRAINTS) && b.fapi2.SENDER_CONSTRAINTS.length === 2);

  var rv = b.fapi2.assertConformance({ senderConstraint: "dpop" });
  check("conformant with dpop",       rv.conformant === true);
  check("findings cover all reqs",    rv.findings.length === 5);

  var rvMtls = b.fapi2.assertConformance({ senderConstraint: "mtls" });
  check("conformant with mtls",       rvMtls.conformant === true);

  var rvWaived = b.fapi2.assertConformance({
    senderConstraint: "dpop", parRequired: false,
  });
  check("PAR waived → non-conformant",  rvWaived.conformant === false);

  function rejects(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  rejects("refuses bad sender-constraint",
    function () { b.fapi2.assertConformance({ senderConstraint: "none" }); }, "BAD_SENDER_CONSTRAINT");
  rejects("refuses non-S256 PKCE",
    function () { b.fapi2.assertConformance({ senderConstraint: "dpop", pkceMethod: "plain" }); }, "BAD_PKCE");

  // assertOAuthConfig
  rejects("oauth: refuses pkce: false",
    function () { b.fapi2.assertOAuthConfig({ pkce: false, dpop: true, par: true }); }, "PKCE_DISABLED");
  rejects("oauth: refuses no sender-constraint",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, par: true }); }, "NO_SENDER_CONSTRAINT");
  rejects("oauth: refuses both sender-constraints",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, mtls: true, par: true }); }, "BOTH_SENDER_CONSTRAINTS");
  rejects("oauth: refuses par: false",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, par: false }); }, "PAR_DISABLED");

  // Clean call
  b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, par: true });
  check("oauth: passes a clean FAPI config", true);
}

module.exports = { run: run };
