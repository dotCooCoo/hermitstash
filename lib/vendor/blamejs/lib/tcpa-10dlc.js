// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.tcpa10dlc
 * @nav    Communication
 * @title  TCPA 10DLC
 * @slug   tcpa-10dlc
 *
 * @intro
 *   The consent record a 10DLC campaign has to be able to produce. Under the
 *   TCPA the question in a dispute is not whether a number opted in but
 *   whether the sender can show it, so the record keeps what the proof needs:
 *   the exact disclosure text shown, the form it was shown on, who the
 *   disclosure named as the sending party, and when.
 *
 *   The disclosure party is one of first-party, carrier-affiliate or
 *   campaign-registrar, because the registrar asks which it was and a free
 *   string cannot answer that. The number has to be E.164, since a record
 *   against a locally-formatted number cannot be matched to the number that
 *   was messaged.
 *
 *   Each record is frozen once written, and the store holds one per number:
 *   revoking replaces it with a new frozen record carrying the revocation time
 *   and reason, and recording consent again replaces it with a fresh grant,
 *   which is how a number that opted back in is recorded. The record as it
 *   stood before is not retrievable here afterwards.
 *
 *   The store is in process memory and does not survive a restart. The grant
 *   and the revocation each write an audit row, so a sequence over time is in
 *   the audit chain, carrying the number, the brand, the named party, the form
 *   and the reason, and not the disclosure text. A deployment that has to
 *   produce the disclosure text in a dispute keeps it somewhere durable of its
 *   own.
 *
 * @card
 *   The TCPA consent record a 10DLC campaign must be able to produce: the
 *   disclosure text, the form, the named sending party and the timestamp, held
 *   frozen per number and audited through revocation.
 */

var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var Tcpa10dlcError = defineClass("Tcpa10dlcError", { alwaysPermanent: true });

var E164_RE = /^\+[1-9][0-9]{6,14}$/;
var DISCLOSURE_PARTIES = ["first-party", "carrier-affiliate", "campaign-registrar"];

var records = new Map();

/**
 * @primitive b.tcpa10dlc.recordConsent
 * @signature b.tcpa10dlc.recordConsent(opts)
 * @since     0.8.35
 * @status    stable
 * @related   b.tcpa10dlc.lookup, b.tcpa10dlc.revoke
 *
 * Record one number's messaging consent and return the frozen record.
 *
 * `phoneE164`, `brand`, `disclosureText`, `formUrl` and `disclosurePartyKind`
 * are all required, each with its own refusal code, because a record missing
 * any of them is not evidence of consent. `disclosurePartyKind` has to be
 * `first-party`, `carrier-affiliate` or `campaign-registrar`.
 *
 * `ip` and `userAgent` are optional and recorded when given, since they are
 * what ties the opt-in to the session that performed it. The record carries
 * its own citations to 47 U.S.C. 227, 47 CFR 64.1200 and the FCC's 2024
 * one-to-one consent order, so the basis travels with the record.
 *
 * `optInTimestamp` defaults to now and is stored alongside its ISO form.
 *
 * The store keeps one record per number, so recording a number that already
 * has one replaces it, including a revoked one, whose replacement reads
 * `revoked: false` again. Check `lookup` first if a re-opt-in has to be
 * treated differently from a first one.
 *
 * @opts
 *   phoneE164:           string,   // required; E.164, e.g. "+15551234567"
 *   brand:               string,   // required; the brand the disclosure named
 *   disclosureText:      string,   // required; the exact text shown
 *   formUrl:             string,   // required; where it was shown
 *   disclosurePartyKind: string,   // required; first-party | carrier-affiliate | campaign-registrar
 *   ip:                  string,   // the opting-in session's address
 *   userAgent:           string,   // the opting-in session's user agent
 *   optInTimestamp:      number,   // epoch ms; default: now
 *   additional:          object,   // anything else the campaign keeps
 *   audit:               boolean,  // false silences the audit event
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rec = b.tcpa10dlc.recordConsent({
 *     phoneE164:           "+15551234567",
 *     brand:               "Acme Clinic",
 *     disclosureText:      "Acme Clinic may text you appointment reminders…",
 *     formUrl:             "https://example.com/signup",
 *     disclosurePartyKind: "first-party",
 *   });
 *   rec.optInTimestampIso;        // → when consent was given
 */
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

  validateOpts.optionalBoolean(opts.audit,
    "tcpa10dlc.recordConsent: audit", Tcpa10dlcError, "tcpa-10dlc/bad-opts");

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

/**
 * @primitive b.tcpa10dlc.lookup
 * @signature b.tcpa10dlc.lookup(phoneE164)
 * @since     0.8.35
 * @status    stable
 * @related   b.tcpa10dlc.recordConsent, b.tcpa10dlc.revoke
 *
 * Answer the consent record for a number, or `null` when there is none.
 *
 * It answers `null` rather than raising, including for a non-string, because
 * this is the check made before sending: "no record" is the answer the caller
 * acts on, not an error. A revoked number still has a record, carrying
 * `revoked: true`, so the caller checks that field rather than treating a
 * present record as permission.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rec = b.tcpa10dlc.lookup("+15551234567");
 *   var maySend = rec !== null && rec.revoked === false;
 */
function lookup(phoneE164) {
  if (typeof phoneE164 !== "string") return null;
  return records.get(phoneE164) || null;
}

/**
 * @primitive b.tcpa10dlc.revoke
 * @signature b.tcpa10dlc.revoke(phoneE164, reason?)
 * @since     0.8.35
 * @status    stable
 * @related   b.tcpa10dlc.recordConsent, b.tcpa10dlc.lookup
 *
 * Mark a number's consent revoked and answer `{ revoked, at }`.
 *
 * A new frozen record is written carrying the revocation time, its ISO form
 * and the reason, and it takes the old one's place in the store, so `lookup`
 * answers the revoked record from then on. It copies the grant's fields
 * forward, so the opt-in timestamp and the disclosure that was shown are
 * still on it. There is no second entry and no call that answers the record as
 * it stood before the revocation; the revocation row in the audit chain
 * records the moment it ended.
 *
 * A number that is not E.164 raises `tcpa-10dlc/bad-phone`, and a number with
 * no record raises `tcpa-10dlc/no-record`, since revoking consent that was
 * never recorded would create a record of a revocation with nothing behind
 * it. Revoking an already-revoked number answers with the
 * original revocation time rather than moving it, so a repeated opt-out does
 * not look like a later one.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.tcpa10dlc.revoke("+15551234567", "replied STOP");
 *   b.tcpa10dlc.lookup("+15551234567").revoked;   // → true
 */
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
