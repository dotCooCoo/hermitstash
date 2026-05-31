"use strict";
/**
 * b.iabTcf — TCF v2.3 consent string + disclosedVendors validator.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("iabTcf.parseString is fn",         typeof b.iabTcf.parseString === "function");
  check("iabTcf.requireV23Disclosed is fn", typeof b.iabTcf.requireV23Disclosed === "function");
  check("iabTcf.checkVendor is fn",         typeof b.iabTcf.checkVendor === "function");
  check("iabTcf.IabTcfError is fn",         typeof b.iabTcf.IabTcfError === "function");
  check("TCF_V23 const present",            b.iabTcf.TCF_V23_CORE_VERSION === 4);

  // Bad inputs
  function rejects(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  rejects("refuses non-string",          function () { b.iabTcf.parseString(null); }, "iab-tcf/bad-input");
  rejects("refuses empty string",        function () { b.iabTcf.parseString(""); }, "iab-tcf/bad-input");
  // Garbage-input rejection — could be BAD_BASE64 (decode failure) or
  // BAD_LENGTH (decoded buffer too short for the core's bit reads).
  // Both surface from the core parse and are equivalent operator
  // signals.
  var threw = null;
  try { b.iabTcf.parseString("not-base64-!"); } catch (e) { threw = e; }
  check("refuses garbage core",  threw && (threw.code === "iab-tcf/bad-base64" || threw.code === "iab-tcf/bad-length"));

  // Construct a minimal TC string with v=2 (NOT v2.3) — should fail
  // requireV23Disclosed.
  // Build a v=2 core: 6-bit version field at the top.
  // Version=2 → bits 000010, 6 bits. Then enough zero bytes to
  // satisfy the parser's bit reads.
  function _makeMinimalCore(version) {
    // We need ~234 bits (the core through vendor sections, simplest
    // case: empty bitmaps). Let's emit exactly the parser-required
    // bytes with a zero pad.
    var totalBits = 6 + 36 + 36 + 12 + 12 + 6 + 6 + 6 + 12 + 6 + 1 + 1 +
                    12 + 24 + 24 + 1 + 6 + 6 +
                    16 + 1 + 16 + 1 + // two empty vendor sections
                    12;               // NumPubRestrictions (mandatory, =0)
    var byteLen = Math.ceil(totalBits / 8);                                                   // allow:raw-byte-literal — bits-per-byte
    var buf = Buffer.alloc(byteLen);
    // Set version field (top 6 bits of byte 0).
    buf[0] = (version & 0x3f) << 2;                                                            // allow:raw-byte-literal — top 6 bits
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  var v22Core = _makeMinimalCore(2);
  rejects("requireV23 refuses v=2", function () { b.iabTcf.requireV23Disclosed(v22Core, { audit: false }); },
    "iab-tcf/wrong-core-version");

  // v=4 core but missing DisclosedVendors → MISSING_DISCLOSED_VENDORS
  var v23OnlyCore = _makeMinimalCore(4);
  // First need to set policyVersion to 4 too; hard to do without a
  // full bit-writer. The minimal-core helper produces policyVersion=0.
  // Test that v=4 + bad-policy raises WRONG_POLICY_VERSION instead.
  rejects("requireV23 refuses bad policy version",
    function () { b.iabTcf.requireV23Disclosed(v23OnlyCore, { audit: false }); },
    "iab-tcf/wrong-policy-version");

  // checkVendor on a parsed object
  var parsed = b.iabTcf.parseString(v23OnlyCore);
  check("parseString returns object", parsed && parsed.core && typeof parsed.core.version === "number");
  check("core version=4",             parsed.core.version === 4);
  check("checkVendor handles bare core",
        b.iabTcf.checkVendor(parsed, 755).consented === false);

  // ---- encode + isValid + completed parse --------------------------------
  check("iabTcf.encode is fn",  typeof b.iabTcf.encode === "function");
  check("iabTcf.isValid is fn", typeof b.iabTcf.isValid === "function");

  // Independent oracle: the worked-example string from the IAB Tech Lab
  // "Consent string and vendor list formats v2" specification.
  var SPEC = "CQSbk4AQSbk4ANwAAAENAwCgAAAAAAAAAAYgACPAAAAA.IDKQA4AAgAKAGQAygAAA.YAAAAAAAAAAA";
  var SPEC_CORE = "CQSbk4AQSbk4ANwAAAENAwCgAAAAAAAAAAYgACPAAAAA";
  var sp = b.iabTcf.parseString(SPEC);
  check("spec core version 2",            sp.core.version === 2);
  check("spec cmpId 880",                 sp.core.cmpId === 880);
  check("spec vendorListVersion 48",      sp.core.vendorListVersion === 48);
  check("spec created 2025-06-03",        new Date(sp.core.createdAt).toISOString() === "2025-06-03T00:00:00.000Z");
  check("spec vendorConsents [1,2,3,4]",  JSON.stringify(Array.from(sp.core.vendorConsents.ids)) === "[1,2,3,4]");
  check("spec disclosedVendors decoded",  JSON.stringify(Array.from(sp.disclosedVendors.vendorIds)) === "[1,2,3,4,5,100,404]");
  check("spec publisherTC fully parsed",  sp.publisherTC && sp.publisherTC.present === true && typeof sp.publisherTC.numCustomPurposes === "number");
  check("core.publisherRestrictions array", Array.isArray(sp.core.publisherRestrictions));
  // Strong oracle: re-encoding the parsed core reproduces the spec Core
  // segment byte-for-byte.
  check("re-encoded core is byte-identical to the spec", b.iabTcf.encode({ core: sp.core }) === SPEC_CORE);
  // Disclosed content round-trips (the encoder writes the minimal valid form).
  var rt = b.iabTcf.parseString(b.iabTcf.encode({ core: sp.core, disclosedVendors: sp.disclosedVendors }));
  check("disclosed content round-trips", JSON.stringify(Array.from(rt.disclosedVendors.vendorIds)) === "[1,2,3,4,5,100,404]");

  // 36-bit timestamp regression: a real date (deciseconds > 2^31) must survive
  // parse → encode unchanged. Guards the reader's `* 2` (not `<< 1`)
  // accumulation, without which Created / LastUpdated truncate at 32 bits.
  var bigCreated = Date.UTC(2026, 4, 26);
  var encTs = b.iabTcf.encode({ core: { version: 2, createdAt: bigCreated, lastUpdatedAt: bigCreated, cmpId: 300, vendorListVersion: 100, consentLanguage: "EN", publisherCC: "DE", vendorConsents: [], vendorLIs: [] } });
  var decTs = b.iabTcf.parseString(encTs);
  check("36-bit timestamp survives round-trip", decTs.core.createdAt === bigCreated);
  check("cmpId survives round-trip",            decTs.core.cmpId === 300);
  check("consentLanguage survives round-trip",  decTs.core.consentLanguage === "EN");

  // Vendor-section round-trip across range-favouring and sparse sets.
  [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [12, 37, 199, 755], [1]].forEach(function (vc, idx) {
    var s = b.iabTcf.encode({ core: { version: 2, createdAt: bigCreated, lastUpdatedAt: bigCreated, cmpId: 5, vendorListVersion: 10, consentLanguage: "EN", publisherCC: "FR", purposesConsent: [1, 2, 3], vendorConsents: vc, vendorLIs: [] } });
    var d = b.iabTcf.parseString(s);
    check("vendorConsents round-trip " + idx,  JSON.stringify(Array.from(d.core.vendorConsents.ids)) === JSON.stringify(vc));
    check("purposesConsent round-trip " + idx, JSON.stringify(Array.from(d.core.purposesConsent)) === "[1,2,3]");
  });

  // Publisher restrictions round-trip.
  var prDec = b.iabTcf.parseString(b.iabTcf.encode({ core: { version: 2, createdAt: bigCreated, lastUpdatedAt: bigCreated, cmpId: 9, vendorListVersion: 1, consentLanguage: "IT", publisherCC: "IT", vendorConsents: [], vendorLIs: [], publisherRestrictions: [{ purposeId: 2, restrictionType: 1, vendorIds: [5, 6, 7, 50] }] } }));
  check("publisher restriction round-trips",
        prDec.core.publisherRestrictions.length === 1 &&
        prDec.core.publisherRestrictions[0].purposeId === 2 &&
        JSON.stringify(prDec.core.publisherRestrictions[0].vendorIds) === "[5,6,7,50]");

  check("isValid true for the spec vector", b.iabTcf.isValid(SPEC) === true);
  check("isValid false for garbage",        b.iabTcf.isValid("nonsense!!") === false);
  // A truncated core (a dropped trailing character cuts into the mandatory
  // NumPubRestrictions field) must NOT validate — the reader's bounds check
  // rejects it rather than treating the gap as "no restrictions".
  check("isValid false for a truncated core", b.iabTcf.isValid(SPEC_CORE.slice(0, -1)) === false);
  rejects("encode without core throws", function () { b.iabTcf.encode({}); }, "iab-tcf/bad-input");
  rejects("encode rejects a non-positive id",
    function () { b.iabTcf.encode({ core: { consentLanguage: "EN", publisherCC: "DE", vendorConsents: [0], vendorLIs: [] } }); }, "iab-tcf/bad-value");
}

module.exports = { run: run };
