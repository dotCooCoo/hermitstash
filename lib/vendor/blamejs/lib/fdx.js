// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.fdx
 * @nav    Compliance
 * @title  FDX
 *
 * @intro
 *   Financial Data Exchange (FDX) US open-banking standard —
 *   consent records, SHA3 transaction hashes, data-recipient
 *   registry.
 *
 *   CFPB §1033 (12 CFR §1033.121-461, final rule 2024-10-22) gives
 *   US consumers the right to authorize a third party to access
 *   their financial data through a covered data provider's
 *   developer interface. FDX (https://financialdataexchange.org)
 *   is the industry-standard schema + protocol the CFPB rule
 *   effectively codifies (FDX 6.0+ aligns with the §1033 final
 *   rule). Compliance deadline 2026-04-01 already past for $250B+
 *   asset-size banks.
 *
 *   The framework can't be the operator's authorization server,
 *   resource server, or FDX-data origin — those are the operator's
 *   core banking system. What it can do: bind the operator's auth
 *   server to the FAPI 2.0 profile (which §1033.351 effectively
 *   requires), validate FDX response shapes, emit §1033-shape
 *   audit events on every authorized data access, and generate
 *   the §1033.401(b) consent receipt.
 *
 * @card
 *   Financial Data Exchange (FDX) US open-banking standard — consent records, SHA3 transaction hashes, data-recipient registry.
 */
/*
 * Original prose retained:
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
var numericBounds = require("./numeric-bounds");
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

/**
 * @primitive b.fdx.bind
 * @signature b.fdx.bind(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance fdx, fapi2
 * @related   b.fdx.validateResponse, b.fdx.consentReceipt, b.fapi2.assertOAuthConfig
 *
 * Bind an operator's authorization-server config to the FDX 6.0
 * data-sharing surface and the FAPI 2.0 security profile. Refuses
 * unknown FDX resources, refuses missing issuer/jwksUri, and runs
 * `b.fapi2.assertOAuthConfig` on the supplied FAPI opts so a
 * non-conformant deployment fails at boot. Returns a handle with
 * `schemaValidator(resource, body)` and `consent.receipt(opts)`.
 *
 * @opts
 *   authServer: {
 *     issuer:  string,        // required, non-empty
 *     jwksUri: string,        // required, non-empty
 *     fapi2:   { pkce, dpop?, mtls?, par },
 *   },
 *   resources: ["accounts" | "transactions" | "statements" |
 *               "payment-networks" | "rewards" | "tax-forms"],
 *
 * @example
 *   var fdx = b.fdx.bind({
 *     authServer: {
 *       issuer:  "https://auth.example-bank.com",
 *       jwksUri: "https://auth.example-bank.com/.well-known/jwks.json",
 *       fapi2:   { pkce: true, mtls: true, par: true },
 *     },
 *     resources: ["accounts", "transactions"],
 *   });
 *   fdx.fapi2Posture;
 *   // → "fapi-2.0"
 */
function bind(opts) {
  if (!opts || typeof opts !== "object") {
    throw FdxError.factory("fdx/bad-opts", "fdx.bind: opts required");
  }
  if (!opts.authServer || typeof opts.authServer !== "object") {
    throw FdxError.factory("fdx/bad-auth-server",
      "fdx.bind: authServer object required");
  }
  validateOpts.shape(opts.authServer, {
    issuer:  { rule: "required-string", code: "BAD_ISSUER",   label: "fdx.bind: authServer.issuer" },
    jwksUri: { rule: "required-string", code: "BAD_JWKS_URI", label: "fdx.bind: authServer.jwksUri" },
  }, "fdx.bind: authServer", FdxError, "fdx/bad-auth-server",
    // fapi2 is forwarded verbatim to fapi2.assertOAuthConfig, which owns
    // its shape ({ pkce, dpop?, mtls?, par }) — validated there, not here.
    { allow: ["fapi2"] });

  if (!Array.isArray(opts.resources) || opts.resources.length === 0) {
    throw FdxError.factory("fdx/bad-resources",
      "fdx.bind: resources must be a non-empty array");
  }
  for (var i = 0; i < opts.resources.length; i += 1) {
    if (FDX_RESOURCES.indexOf(opts.resources[i]) === -1) {
      throw FdxError.factory("fdx/unknown-resource",
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

/**
 * @primitive b.fdx.validateResponse
 * @signature b.fdx.validateResponse(resourceType, body)
 * @since     0.8.0
 * @status    stable
 * @compliance fdx
 * @related   b.fdx.bind
 *
 * Validate an FDX response payload against the framework's FDX 6.0
 * minimum-required-field schema. Accepts both envelope form
 * (`{ accounts: [...] }`) and bare-array / single-record form.
 * Returns `{ valid, errors }` so the operator can decide whether
 * to refuse, redact, or pass through. Throws `FdxError` only when
 * `resourceType` is unknown.
 *
 * @example
 *   var result = b.fdx.validateResponse("accounts", {
 *     accounts: [{
 *       accountId:            "acct-1",
 *       accountType:          "DEPOSIT",
 *       accountNumberDisplay: "****1234",
 *       currency:             "USD",
 *       currentBalance:       1234.56,
 *     }],
 *   });
 *   result.valid;
 *   // → true
 *   result.errors.length;
 *   // → 0
 */
function validateResponse(resourceType, body) {
  var schema = FDX_SCHEMAS[resourceType];
  if (!schema) {
    throw FdxError.factory("fdx/unknown-resource",
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

/**
 * @primitive b.fdx.consentReceipt
 * @signature b.fdx.consentReceipt(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance fdx
 * @related   b.fdx.bind
 *
 * Mint the §1033.401(b) consent receipt the authorization server
 * gives the consumer at authorization time. Required fields:
 * dataProvider, consumerRef, thirdParty, revocationUrl, scopes.
 * Optional `durationMs` defaults to 52 weeks. Emits
 * `fdx.consent_receipt_issued` to the audit chain so the regulator
 * sees a record per receipt.
 *
 * @opts
 *   dataProvider:  string,         // issuer / data provider name
 *   consumerRef:   string,         // operator-side consumer identifier
 *   thirdParty:    string,         // recipient name
 *   revocationUrl: string,         // public revocation endpoint
 *   scopes:        [string, ...],  // data scopes (account ids, resources)
 *   durationMs:    number,         // optional; defaults to 52 weeks
 *
 * @example
 *   var receipt = b.fdx.consentReceipt({
 *     dataProvider:  "https://auth.example-bank.com",
 *     consumerRef:   "consumer-42",
 *     thirdParty:    "Aggregator Inc.",
 *     revocationUrl: "https://example-bank.com/consent/revoke/abc",
 *     scopes:        ["accounts", "transactions"],
 *     durationMs:    365 * 86400 * 1000,
 *   });
 *   receipt.type;
 *   // → "fdx.consent-receipt"
 */
function consentReceipt(opts) {
  if (!opts || typeof opts !== "object") {
    throw FdxError.factory("fdx/bad-opts", "fdx.consentReceipt: opts required");
  }
  validateOpts.shape(opts, {
    dataProvider:  { rule: "required-string", code: "BAD_DATA_PROVIDER" },
    consumerRef:   { rule: "required-string", code: "BAD_CONSUMER_REF" },
    thirdParty:    { rule: "required-string", code: "BAD_THIRD_PARTY" },
    revocationUrl: { rule: "required-string", code: "BAD_REVOCATION_URL" },
    scopes: function (value) {
      if (!Array.isArray(value) || value.length === 0) {
        throw FdxError.factory("fdx/bad-scopes",
          "fdx.consentReceipt: scopes must be a non-empty array");
      }
    },
    durationMs: function (value, label) {
      numericBounds.requirePositiveFiniteIntIfPresent(value, label, FdxError, "BAD_DURATION");
    },
  }, "fdx.consentReceipt", FdxError, "fdx/bad-opts");

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
