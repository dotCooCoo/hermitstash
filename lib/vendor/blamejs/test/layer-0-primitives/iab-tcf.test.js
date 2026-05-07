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
  rejects("refuses non-string",          function () { b.iabTcf.parseString(null); }, "BAD_INPUT");
  rejects("refuses empty string",        function () { b.iabTcf.parseString(""); }, "BAD_INPUT");
  // Garbage-input rejection — could be BAD_BASE64 (decode failure) or
  // BAD_LENGTH (decoded buffer too short for the core's bit reads).
  // Both surface from the core parse and are equivalent operator
  // signals.
  var threw = null;
  try { b.iabTcf.parseString("not-base64-!"); } catch (e) { threw = e; }
  check("refuses garbage core",  threw && (threw.code === "BAD_BASE64" || threw.code === "BAD_LENGTH"));

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
                    16 + 1 + 16 + 1; // two empty vendor sections
    var byteLen = Math.ceil(totalBits / 8);                                                   // allow:raw-byte-literal — bits-per-byte
    var buf = Buffer.alloc(byteLen);
    // Set version field (top 6 bits of byte 0).
    buf[0] = (version & 0x3f) << 2;                                                            // allow:raw-byte-literal — top 6 bits
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  var v22Core = _makeMinimalCore(2);
  rejects("requireV23 refuses v=2", function () { b.iabTcf.requireV23Disclosed(v22Core, { audit: false }); },
    "WRONG_CORE_VERSION");

  // v=4 core but missing DisclosedVendors → MISSING_DISCLOSED_VENDORS
  var v23OnlyCore = _makeMinimalCore(4);
  // First need to set policyVersion to 4 too; hard to do without a
  // full bit-writer. The minimal-core helper produces policyVersion=0.
  // Test that v=4 + bad-policy raises WRONG_POLICY_VERSION instead.
  rejects("requireV23 refuses bad policy version",
    function () { b.iabTcf.requireV23Disclosed(v23OnlyCore, { audit: false }); },
    "WRONG_POLICY_VERSION");

  // checkVendor on a parsed object
  var parsed = b.iabTcf.parseString(v23OnlyCore);
  check("parseString returns object", parsed && parsed.core && typeof parsed.core.version === "number");
  check("core version=4",             parsed.core.version === 4);
  check("checkVendor handles bare core",
        b.iabTcf.checkVendor(parsed, 755).consented === false);
}

module.exports = { run: run };
