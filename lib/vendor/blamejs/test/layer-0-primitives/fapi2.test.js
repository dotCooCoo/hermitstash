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
    function () { b.fapi2.assertConformance({ senderConstraint: "none" }); }, "fapi2/bad-sender-constraint");
  rejects("refuses non-S256 PKCE",
    function () { b.fapi2.assertConformance({ senderConstraint: "dpop", pkceMethod: "plain" }); }, "fapi2/bad-pkce");

  // assertOAuthConfig
  rejects("oauth: refuses pkce: false",
    function () { b.fapi2.assertOAuthConfig({ pkce: false, dpop: true, par: true }); }, "fapi2/pkce-disabled");
  rejects("oauth: refuses no sender-constraint",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, par: true }); }, "fapi2/no-sender-constraint");
  rejects("oauth: refuses both sender-constraints",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, mtls: true, par: true }); }, "fapi2/both-sender-constraints");
  rejects("oauth: refuses par: false",
    function () { b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, par: false }); }, "fapi2/par-disabled");

  // Clean call
  b.fapi2.assertOAuthConfig({ pkce: true, dpop: true, par: true });
  check("oauth: passes a clean FAPI config", true);

  // ---- v0.8.70 runtime enforcement helpers ----
  b.compliance.clear();
  b.fapi2.assertCallback({ code: "abc" });
  check("fapi2.assertCallback: no-op when posture not set",       true);

  b.compliance.set("fapi-2.0");
  var threw = false;
  try { b.fapi2.assertCallback({ code: "abc" }); }
  catch (e) { threw = /missing-iss/.test(e.code); }
  check("fapi2.assertCallback: refuses missing iss under FAPI 2.0", threw);

  b.fapi2.assertCallback({ code: "abc", iss: "https://idp.example" });
  check("fapi2.assertCallback: passes when iss present",           true);

  threw = false;
  try { b.fapi2.assertAuthzRequest({ response_type: "code", client_id: "x" }); }
  catch (e) { threw = /jar-required/.test(e.code); }
  check("fapi2.assertAuthzRequest: refuses bare-query under FAPI 2.0", threw);

  b.fapi2.assertAuthzRequest({ request: "eyJhbGc.eyJzdWI.sig" });
  b.fapi2.assertAuthzRequest({ request_uri: "urn:par:abc" });
  check("fapi2.assertAuthzRequest: accepts request OR request_uri", true);

  b.compliance.clear();
  b.compliance.set("fapi-2.0-message-signing");
  threw = false;
  try { b.fapi2.assertCallback({ code: "abc", iss: "https://idp" }); }
  catch (e) { threw = /jarm-required/.test(e.code); }
  check("fapi2.assertCallback: refuses bare-param under message-signing", threw);

  b.fapi2.assertCallback({ response: "<jarm-jwt>", iss: "https://idp" });
  check("fapi2.assertCallback: accepts JARM response under message-signing", true);

  b.compliance.clear();
}

module.exports = { run: run };
