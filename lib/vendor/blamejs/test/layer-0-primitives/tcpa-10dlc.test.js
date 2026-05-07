"use strict";
/**
 * b.tcpa10dlc — TCPA 10DLC consent record + FCC 1:1 disclosure.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("recordConsent is fn",      typeof b.tcpa10dlc.recordConsent === "function");
  check("lookup is fn",             typeof b.tcpa10dlc.lookup === "function");
  check("revoke is fn",             typeof b.tcpa10dlc.revoke === "function");
  check("Tcpa10dlcError is fn",     typeof b.tcpa10dlc.Tcpa10dlcError === "function");
  check("DISCLOSURE_PARTIES",       Array.isArray(b.tcpa10dlc.DISCLOSURE_PARTIES) &&
                                     b.tcpa10dlc.DISCLOSURE_PARTIES.length === 3);

  b.tcpa10dlc._resetForTest();

  var rec = b.tcpa10dlc.recordConsent({
    phoneE164:           "+15551234567",
    brand:               "Acme Inc.",
    disclosureText:      "I agree to receive promotional messages from Acme Inc. at this number. Msg & data rates may apply. Reply STOP to opt out.",
    disclosurePartyKind: "first-party",
    formUrl:             "https://acme.example/signup",
    ip:                  "203.0.113.5",
    userAgent:           "Mozilla/5.0",
    audit:               false,
  });
  check("record is frozen",         Object.isFrozen(rec));
  check("record cites TCPA",        rec.citations.indexOf("47-usc-227") !== -1);
  check("record cites FCC 1:1",     rec.citations.indexOf("fcc-2024-1-1") !== -1);
  check("record has ISO timestamp", typeof rec.optInTimestampIso === "string");

  var found = b.tcpa10dlc.lookup("+15551234567");
  check("lookup returns record", found && found.phoneE164 === "+15551234567");
  check("lookup miss returns null", b.tcpa10dlc.lookup("+19990000000") === null);

  var rv = b.tcpa10dlc.revoke("+15551234567", "STOP-keyword");
  check("revoke returns true", rv.revoked === true);
  var afterRevoke = b.tcpa10dlc.lookup("+15551234567");
  check("revoked record marked",  afterRevoke.revoked === true);
  check("revokedReason recorded", afterRevoke.revokedReason === "STOP-keyword");

  function rejects(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  rejects("refuses bad phone",
    function () { b.tcpa10dlc.recordConsent({
      phoneE164: "5551234567", brand: "Acme",
      disclosureText: "x", disclosurePartyKind: "first-party",
      formUrl: "https://x", audit: false,
    }); }, "BAD_PHONE");
  rejects("refuses bad disclosure-party-kind",
    function () { b.tcpa10dlc.recordConsent({
      phoneE164: "+15551111111", brand: "Acme",
      disclosureText: "x", disclosurePartyKind: "trusted-network",
      formUrl: "https://x", audit: false,
    }); }, "BAD_DISCLOSURE_PARTY");
  rejects("revoke unknown number",
    function () { b.tcpa10dlc.revoke("+19998887777"); }, "NO_RECORD");
}

module.exports = { run: run };
