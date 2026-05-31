"use strict";
/**
 * b.tcpa10dlc — TCPA 10DLC (10-Digit Long Code) consent-record audit
 * primitive + FCC 1:1 prior-express-written-consent disclosure
 * snapshot.
 *
 * Background: the Telephone Consumer Protection Act (47 USC §227) +
 * its FCC implementing rules (47 CFR §64.1200) require carrier-
 * shaped consent records before sending marketing or
 * automated-dialing-system text messages. Penalties: $500-$1,500
 * per violation. The 10DLC ecosystem (carrier-vetted A2P SMS
 * routes) layers an additional consent-record requirement: every
 * carrier-registered campaign must produce, on demand, the consent
 * record for any phone number it texted.
 *
 * FCC 1:1 rule (effective 2025-01-27 — reaffirmed 2025-12) caps
 * disclosed parties to 1 per consent — operators that previously
 * collected blanket consent for "trusted partner network" must
 * record an individual consent per third-party recipient. The rule
 * was vacated by the 11th Circuit IMC v. FCC 2025 ruling but the
 * underlying TCPA standard still requires "prior express written
 * consent" for marketing autodial; FCC enforcement priorities still
 * favor 1:1.
 *
 * The framework can't be the operator's SMS provider or campaign
 * registrar. What it CAN do:
 *
 *   - Capture the consent record in a tamper-evident audit-chain row
 *     with the carrier-required fields (consumer phone, opt-in
 *     timestamp, brand name, opt-in language verbatim, IP +
 *     user-agent + form URL).
 *   - Snapshot the 1:1 disclosure (single brand the consumer is
 *     consenting to receive messages from).
 *   - Support the carrier "produce on demand" workflow via
 *     `b.tcpa10dlc.lookup(phoneE164)` — returns the consent record
 *     for an audit response.
 *
 * Public API:
 *
 *   b.tcpa10dlc.recordConsent(opts) -> consentRecord
 *     opts:
 *       phoneE164:       "+15551234567" (E.164 format).
 *       brand:           operator's registered brand name.
 *       disclosureText:  the verbatim opt-in language shown to the
 *                        consumer (regulator-facing record).
 *       disclosurePartyKind: "first-party" | "carrier-affiliate" |
 *                        "campaign-registrar" — the role the brand
 *                        plays per the 1:1 rule.
 *       formUrl:         operator's URL where consent was captured.
 *       ip + userAgent:  consumer's network identifiers.
 *       optInTimestamp:  Unix-ms (default Date.now()).
 *       additional:      arbitrary operator-supplied metadata
 *                        (campaign-id, traffic source, A/B test cell).
 *
 *   b.tcpa10dlc.lookup(phoneE164) -> consentRecord | null
 *
 *   b.tcpa10dlc.revoke(phoneE164, reason) -> { revoked, at }
 *     Records the consumer-initiated opt-out. Carriers require
 *     revocation traceability — the audit row is the regulator-
 *     facing record.
 */

var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var Tcpa10dlcError = defineClass("Tcpa10dlcError", { alwaysPermanent: true });

var E164_RE = /^\+[1-9][0-9]{6,14}$/;                                                         // E.164 length range, not bytes
var DISCLOSURE_PARTIES = ["first-party", "carrier-affiliate", "campaign-registrar"];

var records = new Map();   // phoneE164 → record

function recordConsent(opts) {
  if (!opts || typeof opts !== "object") {
    throw Tcpa10dlcError.factory("tcpa-10dlc/bad-opts",
      "tcpa10dlc.recordConsent: opts required");
  }
  if (typeof opts.phoneE164 !== "string" || !E164_RE.test(opts.phoneE164)) {
    throw Tcpa10dlcError.factory("tcpa-10dlc/bad-phone",
      "tcpa10dlc.recordConsent: phoneE164 must match " + E164_RE);
  }
  validateOpts.requireNonEmptyString(opts.brand,
    "tcpa10dlc.recordConsent: brand", Tcpa10dlcError, "BAD_BRAND");
  validateOpts.requireNonEmptyString(opts.disclosureText,
    "tcpa10dlc.recordConsent: disclosureText", Tcpa10dlcError, "BAD_DISCLOSURE_TEXT");
  validateOpts.requireNonEmptyString(opts.formUrl,
    "tcpa10dlc.recordConsent: formUrl", Tcpa10dlcError, "BAD_FORM_URL");
  if (DISCLOSURE_PARTIES.indexOf(opts.disclosurePartyKind) === -1) {
    throw Tcpa10dlcError.factory("tcpa-10dlc/bad-disclosure-party",
      "tcpa10dlc.recordConsent: disclosurePartyKind must be one of " +
      DISCLOSURE_PARTIES.join(", "));
  }

  var optInAt = typeof opts.optInTimestamp === "number" ? opts.optInTimestamp : Date.now();
  var record = Object.freeze({
    phoneE164:           opts.phoneE164,
    brand:               opts.brand,
    disclosureText:      opts.disclosureText,
    disclosurePartyKind: opts.disclosurePartyKind,
    formUrl:             opts.formUrl,
    ip:                  opts.ip || null,
    userAgent:           opts.userAgent || null,
    optInTimestamp:      optInAt,
    optInTimestampIso:   new Date(optInAt).toISOString(),
    revoked:             false,
    revokedAt:           null,
    revokedReason:       null,
    additional:          opts.additional || null,
    citations:           ["47-usc-227", "47-cfr-64.1200", "fcc-2024-1-1"],
  });
  records.set(opts.phoneE164, record);

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "tcpa10dlc.consent_recorded",
      outcome:  "success",
      metadata: {
        phoneE164:           opts.phoneE164,
        brand:               opts.brand,
        disclosurePartyKind: opts.disclosurePartyKind,
        formUrl:             opts.formUrl,
        ip:                  opts.ip || null,
      },
    });
  }
  return record;
}

function lookup(phoneE164) {
  if (typeof phoneE164 !== "string") return null;
  return records.get(phoneE164) || null;
}

function revoke(phoneE164, reason) {
  if (typeof phoneE164 !== "string" || !E164_RE.test(phoneE164)) {
    throw Tcpa10dlcError.factory("tcpa-10dlc/bad-phone",
      "tcpa10dlc.revoke: phoneE164 must match " + E164_RE);
  }
  var existing = records.get(phoneE164);
  if (!existing) {
    throw Tcpa10dlcError.factory("tcpa-10dlc/no-record",
      "tcpa10dlc.revoke: no consent record for " + phoneE164);
  }
  if (existing.revoked) {
    return { revoked: true, at: existing.revokedAt };
  }
  var revokedAt = Date.now();
  var updated = Object.freeze(Object.assign({}, existing, {
    revoked:        true,
    revokedAt:      revokedAt,
    revokedAtIso:   new Date(revokedAt).toISOString(),
    revokedReason:  typeof reason === "string" ? reason : null,
  }));
  records.set(phoneE164, updated);
  audit.safeEmit({
    action:   "tcpa10dlc.consent_revoked",
    outcome:  "success",
    metadata: {
      phoneE164: phoneE164,
      reason:    reason || null,
    },
  });
  return { revoked: true, at: revokedAt };
}

function _resetForTest() { records.clear(); }

module.exports = {
  recordConsent:        recordConsent,
  lookup:               lookup,
  revoke:               revoke,
  DISCLOSURE_PARTIES:   DISCLOSURE_PARTIES.slice(),
  Tcpa10dlcError:       Tcpa10dlcError,
  _resetForTest:        _resetForTest,
};
