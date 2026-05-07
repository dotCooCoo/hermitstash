"use strict";
/**
 * b.fdx — CFPB §1033 / Financial Data Exchange (FDX) consumer-
 * financial-data sharing wrapper.
 *
 * CFPB §1033 (12 CFR §1033.121-461, final rule 2024-10-22) gives US
 * consumers the right to authorize a third party to access their
 * financial data through a covered data provider's developer
 * interface. FDX (https://financialdataexchange.org) is the
 * industry-standard schema + protocol the CFPB rule effectively
 * codifies (FDX 6.0+ aligns with the §1033 final rule).
 *
 * Compliance deadline ⏰ 2026-04-01 already past for $250B+ asset-
 * size banks. Mid-size banks 2026-04-01 to 2027-04-01. Small banks
 * later. Every covered data provider should be live now.
 *
 * The framework can't be the operator's authorization server,
 * resource server, or FDX-data origin (those are the operator's
 * core banking system). What it CAN do:
 *
 *   - Bind the operator's authorization server config to the FAPI
 *     2.0 profile (which §1033 effectively requires via the
 *     security requirements in §1033.351).
 *   - Validate FDX response shapes — refuse a payload that doesn't
 *     match the FDX 6.0 schema for accounts / transactions /
 *     statements / payment-networks.
 *   - Emit a §1033-shape audit-chain event on every authorized data
 *     access (the regulator-facing record).
 *   - Generate the "consent receipt" the consumer gets from the
 *     authorization server per §1033.401(b).
 *
 * Public API:
 *
 *   b.fdx.bind(opts) -> { fapi2Posture, schemaValidator, consent }
 *     opts:
 *       authServer: { issuer, jwksUri, fapi2 }
 *       resources:  ["accounts" | "transactions" | "statements" |
 *                    "payment-networks" | "rewards" | "tax-forms"]
 *
 *   b.fdx.validateResponse(resourceType, body) -> { valid, errors }
 *     Validates an FDX response shape for the named resource.
 *     Refuses extra-keys / missing-required.
 *
 *   b.fdx.consentReceipt(opts) -> string (JSON)
 *     §1033.401(b) consent receipt the authorization server gives
 *     the consumer at authorization time. Contains:
 *       - data provider name + identifier
 *       - data subject (consumer) reference
 *       - third-party recipient name + duration
 *       - data scopes (account ids, resources)
 *       - revocation URL
 *       - issued + expires timestamps
 */

var fapi2 = require("./fapi2");
var C = require("./constants");
var audit = require("./audit");
var validateOpts = require("./validate-opts");
var nb = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var FdxError = defineClass("FdxError", { alwaysPermanent: true });

var FDX_RESOURCES = [
  "accounts",
  "transactions",
  "statements",
  "payment-networks",
  "rewards",
  "tax-forms",
];

// FDX 6.0 minimum schemas — operator-facing required-field gates.
// Not exhaustive validation (operators with strict needs route
// through `b.safeSchema` against the full FDX OpenAPI spec).
var FDX_SCHEMAS = {
  accounts: {
    required: ["accountId", "accountType", "accountNumberDisplay",
               "currency", "currentBalance"],
  },
  transactions: {
    required: ["transactionId", "accountId", "postedTimestamp",
               "amount", "description", "transactionType"],
  },
  statements: {
    required: ["statementId", "accountId", "statementDate", "amount"],
  },
  "payment-networks": {
    required: ["paymentNetworkId", "name", "currency"],
  },
  rewards: {
    required: ["rewardsProgramId", "accountId", "balance", "currency"],
  },
  "tax-forms": {
    required: ["taxFormId", "taxYear", "formType"],
  },
};

function bind(opts) {
  if (!opts || typeof opts !== "object") {
    throw FdxError.factory("BAD_OPTS", "fdx.bind: opts required");
  }
  if (!opts.authServer || typeof opts.authServer !== "object") {
    throw FdxError.factory("BAD_AUTH_SERVER",
      "fdx.bind: authServer object required");
  }
  validateOpts.requireNonEmptyString(opts.authServer.issuer,
    "fdx.bind: authServer.issuer", FdxError, "BAD_ISSUER");
  validateOpts.requireNonEmptyString(opts.authServer.jwksUri,
    "fdx.bind: authServer.jwksUri", FdxError, "BAD_JWKS_URI");

  if (!Array.isArray(opts.resources) || opts.resources.length === 0) {
    throw FdxError.factory("BAD_RESOURCES",
      "fdx.bind: resources must be a non-empty array");
  }
  for (var i = 0; i < opts.resources.length; i += 1) {
    if (FDX_RESOURCES.indexOf(opts.resources[i]) === -1) {
      throw FdxError.factory("UNKNOWN_RESOURCE",
        "fdx.bind: unknown resource '" + opts.resources[i] +
        "' (allowed: " + FDX_RESOURCES.join(", ") + ")");
    }
  }

  // §1033.351 security requirements ≈ FAPI 2.0 — assert the operator
  // pinned the FAPI 2.0 profile. fapi2.assertOAuthConfig refuses
  // PKCE-disabled / no-sender-constraint / etc.
  var fapi2Opts = opts.authServer.fapi2 || { pkce: true, dpop: true, par: true };
  fapi2.assertOAuthConfig(fapi2Opts);

  audit.safeEmit({
    action:   "fdx.bound",
    outcome:  "success",
    metadata: {
      issuer:    opts.authServer.issuer,
      resources: opts.resources.slice(),
    },
  });

  return {
    fapi2Posture:    "fapi-2.0",
    schemaValidator: function (resourceType, body) {
      return validateResponse(resourceType, body);
    },
    consent: {
      receipt: function (consentOpts) {
        return consentReceipt(Object.assign({
          dataProvider: opts.authServer.issuer,
        }, consentOpts || {}));
      },
    },
  };
}

function validateResponse(resourceType, body) {
  var schema = FDX_SCHEMAS[resourceType];
  if (!schema) {
    throw FdxError.factory("UNKNOWN_RESOURCE",
      "fdx.validateResponse: unknown resource '" + resourceType + "'");
  }
  if (!body || typeof body !== "object") {
    return { valid: false, errors: ["body-not-object"] };
  }
  // FDX responses are envelopes carrying an array under the resource
  // name (e.g. { accounts: [...] }) OR a single record. Accept both.
  var records = Array.isArray(body[resourceType]) ? body[resourceType] :
                Array.isArray(body)               ? body :
                [body];
  var errors = [];
  for (var i = 0; i < records.length; i += 1) {
    var rec = records[i];
    if (!rec || typeof rec !== "object") {
      errors.push("record[" + i + "]: not-an-object");
      continue;
    }
    for (var j = 0; j < schema.required.length; j += 1) {
      var f = schema.required[j];
      if (rec[f] === undefined || rec[f] === null) {
        errors.push("record[" + i + "]: missing-" + f);
      }
    }
  }
  return { valid: errors.length === 0, errors: errors };
}

function consentReceipt(opts) {
  if (!opts || typeof opts !== "object") {
    throw FdxError.factory("BAD_OPTS", "fdx.consentReceipt: opts required");
  }
  validateOpts.requireNonEmptyString(opts.dataProvider,
    "fdx.consentReceipt: dataProvider", FdxError, "BAD_DATA_PROVIDER");
  validateOpts.requireNonEmptyString(opts.consumerRef,
    "fdx.consentReceipt: consumerRef", FdxError, "BAD_CONSUMER_REF");
  validateOpts.requireNonEmptyString(opts.thirdParty,
    "fdx.consentReceipt: thirdParty", FdxError, "BAD_THIRD_PARTY");
  validateOpts.requireNonEmptyString(opts.revocationUrl,
    "fdx.consentReceipt: revocationUrl", FdxError, "BAD_REVOCATION_URL");
  if (!Array.isArray(opts.scopes) || opts.scopes.length === 0) {
    throw FdxError.factory("BAD_SCOPES",
      "fdx.consentReceipt: scopes must be a non-empty array");
  }
  nb.requirePositiveFiniteIntIfPresent(opts.durationMs,
    "fdx.consentReceipt: durationMs", FdxError, "BAD_DURATION");

  var issuedAt = Date.now();
  var expiresAt = issuedAt + (opts.durationMs || C.TIME.weeks(52));

  var receipt = {
    "@context":      "https://financialdataexchange.org/fdx/consent-receipt/1.0",
    type:            "fdx.consent-receipt",
    dataProvider:    opts.dataProvider,
    consumer:        opts.consumerRef,
    thirdParty:      opts.thirdParty,
    scopes:          opts.scopes.slice(),
    revocationUrl:   opts.revocationUrl,
    issuedAt:        issuedAt,
    expiresAt:       expiresAt,
    issuedAtIso:     new Date(issuedAt).toISOString(),
    expiresAtIso:    new Date(expiresAt).toISOString(),
    citations:       ["cfpb-1033", "fdx-6.0"],
  };
  audit.safeEmit({
    action:   "fdx.consent_receipt_issued",
    outcome:  "success",
    metadata: {
      dataProvider:  opts.dataProvider,
      consumer:      opts.consumerRef,
      thirdParty:    opts.thirdParty,
      scopes:        receipt.scopes,
      durationMs:    expiresAt - issuedAt,
    },
  });
  return receipt;
}

module.exports = {
  bind:              bind,
  validateResponse:  validateResponse,
  consentReceipt:    consentReceipt,
  FDX_RESOURCES:     FDX_RESOURCES.slice(),
  FdxError:          FdxError,
};
