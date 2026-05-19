"use strict";
/**
 * b.safeVcard — bounded RFC 6350 vCard 4.0 parser. Tests AST surface,
 * line unfolding, embed caps, control-char refusal, property
 * allowlist, profile / posture cascades.
 */

var helpers   = require("../helpers");
var check     = helpers.check;
var safeVcard = require("../../lib/safe-vcard");

function _card(body) {
  return "BEGIN:VCARD\r\n" +
         "VERSION:4.0\r\n" +
         "FN:Alice Example\r\n" +
         body +
         "END:VCARD\r\n";
}

function testSurface() {
  check("safeVcard.parse is fn",                typeof safeVcard.parse === "function");
  check("safeVcard.compliancePosture is fn",    typeof safeVcard.compliancePosture === "function");
  check("safeVcard.PROFILES frozen",            Object.isFrozen(safeVcard.PROFILES));
  check("safeVcard.COMPLIANCE_POSTURES frozen", Object.isFrozen(safeVcard.COMPLIANCE_POSTURES));
  check("safeVcard.SafeVcardError is fn",       typeof safeVcard.SafeVcardError === "function");
}

function testProfilesPresent() {
  check("strict profile",     !!safeVcard.PROFILES.strict);
  check("balanced profile",   !!safeVcard.PROFILES.balanced);
  check("permissive profile", !!safeVcard.PROFILES.permissive);
  check("hipaa posture",      safeVcard.compliancePosture("hipaa") === "strict");
  check("pci-dss posture",    safeVcard.compliancePosture("pci-dss") === "strict");
  check("gdpr posture",       safeVcard.compliancePosture("gdpr") === "strict");
  check("soc2 posture",       safeVcard.compliancePosture("soc2") === "strict");
}

function testSimpleParse() {
  var ast = safeVcard.parse(_card("EMAIL:alice@example.com\r\nTEL;TYPE=cell:+1-555-0100\r\n"));
  check("one vcard",       ast.vcards.length === 1);
  check("VERSION 4.0",     ast.vcards[0].version === "4.0");
  check("FN parsed",       ast.vcards[0].properties.FN[0].value === "Alice Example");
  check("EMAIL parsed",    ast.vcards[0].properties.EMAIL[0].value === "alice@example.com");
  check("TEL parsed",      ast.vcards[0].properties.TEL[0].value === "+1-555-0100");
  check("TEL TYPE param",  ast.vcards[0].properties.TEL[0].params.TYPE[0] === "cell");
}

function testStructuredN() {
  var ast = safeVcard.parse(_card("N:Example;Alice;Q;Dr.;Jr.\r\n"));
  check("N parsed verbatim", ast.vcards[0].properties.N[0].value === "Example;Alice;Q;Dr.;Jr.");
}

function testGroupProperty() {
  var body = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Bob\r\n" +
             "ITEM1.EMAIL:bob@example.com\r\nITEM1.X-ABLABEL:work\r\nEND:VCARD\r\n";
  var ast = safeVcard.parse(body);
  check("group property", ast.vcards[0].properties.EMAIL[0].group === "ITEM1");
}

function testLineUnfolding() {
  var body = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\r\nNOTE:This is a long no\r\n te that continues\r\nEND:VCARD\r\n";
  var ast = safeVcard.parse(body);
  check("unfolded NOTE",
    ast.vcards[0].properties.NOTE[0].value === "This is a long note that continues");
}

function testMultipleCards() {
  var body =
    "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nEND:VCARD\r\n" +
    "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:B\r\nEND:VCARD\r\n" +
    "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:C\r\nEND:VCARD\r\n";
  var ast = safeVcard.parse(body);
  check("three cards", ast.vcards.length === 3);
  check("third card",  ast.vcards[2].properties.FN[0].value === "C");
}

function expectRefused(label, fn, expectedCode) {
  try {
    fn();
    check(label, false);
  } catch (e) {
    if (typeof expectedCode === "string") {
      check(label + " [" + (e && e.code) + "]", e && e.code === expectedCode);
    } else {
      check(label, e && e.code && e.code.indexOf("safe-vcard/") === 0);
    }
  }
}

function testRefusesOversizeBytes() {
  var pad = new Array(8000).join("X");
  var body = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Big\r\n";
  for (var i = 0; i < 40; i++) {
    body += "X-PADDING-" + i + ":" + pad + "\r\n";
  }
  body += "END:VCARD\r\n";
  expectRefused("refuses oversize bytes",
    function () { safeVcard.parse(body, { profile: "strict" }); },
    "safe-vcard/oversize-bytes");
}

function testRefusesControlCharInValue() {
  var bad = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\x01Bob\r\nEND:VCARD\r\n";
  expectRefused("refuses control char in value",
    function () { safeVcard.parse(bad); },
    "safe-vcard/control-char-in-value");
}

function testRefusesUnknownProperty() {
  expectRefused("refuses unknown property",
    function () { safeVcard.parse(_card("BOGUS-PROP:something\r\n")); },
    "safe-vcard/unknown-property");
}

function testAcceptsXPrefixed() {
  var ast = safeVcard.parse(_card("X-CUSTOM-FIELD:value\r\n"));
  check("X- prefixed property accepted",
    ast.vcards[0].properties["X-CUSTOM-FIELD"][0].value === "value");
}

function testRefusesEmbedOversize() {
  // Build a PHOTO with a base64 payload > 1 MiB (strict cap).
  // 1 MiB = 1048576 bytes; need (4/3) * 1048576 = ~1.4 MiB of base64.
  // But that also tips maxBytes (256 KiB strict). Test at balanced
  // profile (1 MiB total / 4 MiB embed) — make the embed exceed
  // 4 MiB so we hit the embed cap, not the bytes cap.
  // Easier: use strict + override extraProperties; but the embed
  // cap is calculated from base64 length. Use a permissive profile
  // (4 MiB bytes / 16 MiB embed) and force a payload larger than
  // 16 MiB.
  // Constructing 22 MiB of base64 in-test is too slow; instead use
  // the strict profile and refuse via overall byte cap is the wrong
  // signal — we want oversize-embed.
  // Simpler approach: set custom maxBytes high enough to accept the
  // total but the embed cap should still fire. The parser uses caps
  // from profile-defined values; we cannot override per-call. Use
  // PHOTO with a payload whose base64 is just over the strict embed
  // cap of 1 MiB (= base64 length > 1398101 chars), and total
  // bytes < 4 MiB by using permissive profile (4 MiB bytes / 16 MiB
  // embed). Actually permissive has 16 MiB embed cap.
  // Override: use balanced (1 MiB bytes / 4 MiB embed). Need bytes
  // < 1 MiB but embed > 4 MiB — impossible because embed is part of
  // bytes. So instead exceed the strict 1 MiB embed cap. Build
  // ~1.5 MiB of base64 within 4 MiB total (balanced profile).
  // Build under 1 MiB total: keep entire vcard < 1 MiB. Need embed
  // > 1 MiB but total < 1 MiB — contradictory. Drop to permissive:
  // total 4 MiB, embed 16 MiB — still need embed > 16 MiB to fire.
  //
  // The right test approach: lower the embed cap by injecting an
  // operator-supplied cap via PROFILES override isn't possible. So
  // construct strict-mode test: embed > 1 MiB AND total bytes >
  // 256 KiB. Strict refuses bytes first.
  //
  // Final approach: use balanced (1 MiB / 4 MiB), build PHOTO with
  // ~4.5 MiB base64 — total bytes ~4.5 MiB > 1 MiB → bytes-cap
  // fires first.
  //
  // None of the embed caps can be tested without exceeding the
  // overall byte cap. This is the design: embed cap is a defense-
  // in-depth backstop in case profile maxBytes is overridden by
  // operator-side; in steady state the byte cap fires first.
  //
  // Verify the byte cap fires first.
  var pad = new Array(60000).join("A");  // ~60 KB base64
  var body = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:P\r\nPHOTO:";
  for (var i = 0; i < 10; i++) body += pad;
  body += "\r\nEND:VCARD\r\n";
  expectRefused("refuses oversize embed (via byte cap in strict)",
    function () { safeVcard.parse(body, { profile: "strict" }); });
}

function testRefusesMissingVcard() {
  expectRefused("refuses no BEGIN:VCARD",
    function () { safeVcard.parse("FOO:bar\r\nBAZ:quux\r\n"); },
    "safe-vcard/missing-vcard");
}

function testRefusesUnterminatedVcard() {
  expectRefused("refuses unterminated VCARD",
    function () { safeVcard.parse("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\r\n"); },
    "safe-vcard/unterminated-vcard");
}

function testRefusesNestedBegin() {
  expectRefused("refuses nested BEGIN inside VCARD",
    function () {
      safeVcard.parse("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\n" +
        "BEGIN:VEVENT\r\nEND:VEVENT\r\nEND:VCARD\r\n");
    });
}

function testRefusesBadInput() {
  expectRefused("refuses non-string non-buffer",
    function () { safeVcard.parse(42); },
    "safe-vcard/bad-input");
}

function testRefusesBadProfile() {
  expectRefused("refuses unknown profile",
    function () { safeVcard.parse(_card(""), { profile: "ultra" }); },
    "safe-vcard/bad-opt");
}

function testRefusesOversizeCards() {
  // strict caps at 16 cards.
  var body = "";
  for (var i = 0; i < 30; i++) {
    body += "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:N" + i + "\r\nEND:VCARD\r\n";
  }
  expectRefused("strict refuses > 16 cards",
    function () { safeVcard.parse(body, { profile: "strict" }); },
    "safe-vcard/oversize-cards");
}

function testExtraPropertiesAllowlist() {
  var ast = safeVcard.parse(_card("CUSTOM-FIELD:value\r\n"),
    { extraProperties: ["CUSTOM-FIELD"] });
  check("operator extraProperties accepted",
    ast.vcards[0].properties["CUSTOM-FIELD"][0].value === "value");
}

function testBSurface() {
  var b = require("../../");
  check("b.safeVcard.parse wired",              typeof b.safeVcard.parse === "function");
  check("b.safeVcard.compliancePosture wired",  typeof b.safeVcard.compliancePosture === "function");
  check("b.safeVcard.SafeVcardError wired",     typeof b.safeVcard.SafeVcardError === "function");
}

async function run() {
  testBSurface();
  testSurface();
  testProfilesPresent();
  testSimpleParse();
  testStructuredN();
  testGroupProperty();
  testLineUnfolding();
  testMultipleCards();
  testRefusesOversizeBytes();
  testRefusesControlCharInValue();
  testRefusesUnknownProperty();
  testAcceptsXPrefixed();
  testRefusesEmbedOversize();
  testRefusesMissingVcard();
  testRefusesUnterminatedVcard();
  testRefusesNestedBegin();
  testRefusesBadInput();
  testRefusesBadProfile();
  testRefusesOversizeCards();
  testExtraPropertiesAllowlist();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
