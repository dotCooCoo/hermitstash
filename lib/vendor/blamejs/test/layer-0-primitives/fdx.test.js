"use strict";
/**
 * b.fdx — CFPB §1033 / FDX bind primitive.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("fdx.bind is fn",              typeof b.fdx.bind === "function");
  check("fdx.FdxError is fn",          typeof b.fdx.FdxError === "function");
  check("fdx.validateResponse is fn",  typeof b.fdx.validateResponse === "function");
  check("fdx.consentReceipt is fn",    typeof b.fdx.consentReceipt === "function");
  check("FDX_RESOURCES",               Array.isArray(b.fdx.FDX_RESOURCES) && b.fdx.FDX_RESOURCES.length === 6);

  // bind
  var binding = b.fdx.bind({
    authServer: {
      issuer:  "https://bank.example/auth",
      jwksUri: "https://bank.example/auth/jwks",
      fapi2:   { pkce: true, dpop: true, par: true },
    },
    resources: ["accounts", "transactions"],
  });
  check("bind returns shape", binding && binding.fapi2Posture === "fapi-2.0");
  check("bind exposes schema validator", typeof binding.schemaValidator === "function");
  check("bind exposes consent.receipt",  typeof binding.consent.receipt === "function");

  // validateResponse — clean accounts envelope
  var clean = b.fdx.validateResponse("accounts", {
    accounts: [{
      accountId: "acct-1", accountType: "DEPOSIT",
      accountNumberDisplay: "...1234", currency: "USD",
      currentBalance: 1000.00,
    }],
  });
  check("validateResponse clean", clean.valid === true);

  // missing required
  var dirty = b.fdx.validateResponse("accounts", {
    accounts: [{ accountId: "acct-1" }],
  });
  check("validateResponse missing required", dirty.valid === false && dirty.errors.length > 0);

  // consent receipt
  var receipt = b.fdx.consentReceipt({
    dataProvider: "https://bank.example",
    consumerRef:  "cust-12345",
    thirdParty:   "Acme Personal Finance",
    scopes:       ["accounts:read", "transactions:read"],
    revocationUrl: "https://bank.example/revoke",
    durationMs:   90 * 24 * 60 * 60 * 1000,
  });
  check("consent receipt fdx context", receipt["@context"].indexOf("financialdataexchange") !== -1);
  check("consent receipt cites 1033",  receipt.citations.indexOf("cfpb-1033") !== -1);
  check("consent receipt expires later than issued", receipt.expiresAt > receipt.issuedAt);

  // Validation — bad opts
  function rejects(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  rejects("bind refuses empty resources",
    function () { b.fdx.bind({ authServer: { issuer: "x", jwksUri: "y" }, resources: [] }); },
    "fdx/bad-resources");
  rejects("bind refuses unknown resource",
    function () { b.fdx.bind({
      authServer: { issuer: "x", jwksUri: "y", fapi2: { pkce: true, dpop: true, par: true } },
      resources: ["bogus"],
    }); }, "fdx/unknown-resource");
  rejects("consent receipt refuses missing thirdParty",
    function () { b.fdx.consentReceipt({
      dataProvider: "x", consumerRef: "y", scopes: ["a"], revocationUrl: "z",
    }); }, "BAD_THIRD_PARTY");
}

module.exports = { run: run };
