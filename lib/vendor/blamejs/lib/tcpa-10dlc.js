// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var Tcpa10dlcError = defineClass("Tcpa10dlcError", { alwaysPermanent: true });

var E164_RE = /^\+[1-9][0-9]{6,14}$/;
var DISCLOSURE_PARTIES = ["first-party", "carrier-affiliate", "campaign-registrar"];

var records = new Map();

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
    "tcpa10dlc.recordConsent: brand", Tcpa10dlcError, "tcpa-10dlc/bad-brand");
  validateOpts.requireNonEmptyString(opts.disclosureText,
    "tcpa10dlc.recordConsent: disclosureText", Tcpa10dlcError, "tcpa-10dlc/bad-disclosure-text");
  validateOpts.requireNonEmptyString(opts.formUrl,
    "tcpa10dlc.recordConsent: formUrl", Tcpa10dlcError, "tcpa-10dlc/bad-form-url");
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
