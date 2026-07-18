// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeIcal — bounded RFC 5545 iCalendar parser. Tests the AST
 * surface, line unfolding, RRULE caps (calendar-bomb defense),
 * control-char refusal, property allowlist, profile / posture
 * cascades.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var safeIcal = require("../../lib/safe-ical");

function _ical(body) {
  return "BEGIN:VCALENDAR\r\n" +
         "VERSION:2.0\r\n" +
         "PRODID:-//Example//1.0//EN\r\n" +
         body +
         "END:VCALENDAR\r\n";
}

function _event(extra) {
  return "BEGIN:VEVENT\r\n" +
         "UID:abc@example.com\r\n" +
         "DTSTAMP:20260101T120000Z\r\n" +
         "DTSTART:20260101T130000Z\r\n" +
         "SUMMARY:Team meeting\r\n" +
         (extra || "") +
         "END:VEVENT\r\n";
}

function testSurface() {
  check("safeIcal.parse is fn",                typeof safeIcal.parse === "function");
  check("safeIcal.compliancePosture is fn",    typeof safeIcal.compliancePosture === "function");
  check("safeIcal.PROFILES frozen",            Object.isFrozen(safeIcal.PROFILES));
  check("safeIcal.COMPLIANCE_POSTURES frozen", Object.isFrozen(safeIcal.COMPLIANCE_POSTURES));
  check("safeIcal.SafeIcalError is fn",        typeof safeIcal.SafeIcalError === "function");
}

function testProfilesPresent() {
  check("strict profile",     !!safeIcal.PROFILES.strict);
  check("balanced profile",   !!safeIcal.PROFILES.balanced);
  check("permissive profile", !!safeIcal.PROFILES.permissive);
  check("hipaa posture",      safeIcal.compliancePosture("hipaa") === "strict");
  check("pci-dss posture",    safeIcal.compliancePosture("pci-dss") === "strict");
  check("gdpr posture",       safeIcal.compliancePosture("gdpr") === "strict");
  check("soc2 posture",       safeIcal.compliancePosture("soc2") === "strict");
  check("unknown posture",    safeIcal.compliancePosture("loose") === null);
}

function testSimpleParse() {
  var ast = safeIcal.parse(_ical(_event()));
  check("vcalendar exists",         !!ast.vcalendar);
  check("VERSION property",         ast.vcalendar.properties.VERSION[0].value === "2.0");
  check("vevent length 1",          ast.vcalendar.vevent.length === 1);
  check("vevent UID",               ast.vcalendar.vevent[0].properties.UID[0].value === "abc@example.com");
  check("vevent SUMMARY",           ast.vcalendar.vevent[0].properties.SUMMARY[0].value === "Team meeting");
  check("vevent DTSTART",           ast.vcalendar.vevent[0].properties.DTSTART[0].value === "20260101T130000Z");
}

function testVtodoVjournal() {
  var body = "BEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Buy milk\r\nEND:VTODO\r\n" +
             "BEGIN:VJOURNAL\r\nUID:j1\r\nSUMMARY:Daily log\r\nEND:VJOURNAL\r\n";
  var ast = safeIcal.parse(_ical(body));
  check("vtodo present",    ast.vcalendar.vtodo.length === 1);
  check("vtodo SUMMARY",    ast.vcalendar.vtodo[0].properties.SUMMARY[0].value === "Buy milk");
  check("vjournal present", ast.vcalendar.vjournal.length === 1);
}

function testNestedValarm() {
  var body = _event("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n");
  var ast = safeIcal.parse(_ical(body));
  check("valarm nested in vevent", ast.vcalendar.vevent[0].children.length === 1);
  check("valarm name",             ast.vcalendar.vevent[0].children[0].name === "VALARM");
}

function testLineUnfolding() {
  var body = "BEGIN:VEVENT\r\n" +
             "UID:long@example.com\r\n" +
             "DTSTAMP:20260101T120000Z\r\n" +
             "DTSTART:20260101T130000Z\r\n" +
             "DESCRIPTION:This is a long descript\r\n ion that continues across lines\r\n" +
             "END:VEVENT\r\n";
  var ast = safeIcal.parse(_ical(body));
  check("unfolded line joined",
    ast.vcalendar.vevent[0].properties.DESCRIPTION[0].value ===
    "This is a long description that continues across lines");
}

function testPropertyParams() {
  var body = "BEGIN:VEVENT\r\n" +
             "UID:p@example.com\r\n" +
             "DTSTAMP:20260101T120000Z\r\n" +
             "DTSTART;TZID=America/New_York:20260101T130000\r\n" +
             "ATTENDEE;CN=\"Alice Example\";ROLE=REQ-PARTICIPANT:mailto:alice@example.com\r\n" +
             "END:VEVENT\r\n";
  var ast = safeIcal.parse(_ical(body));
  var dtstart = ast.vcalendar.vevent[0].properties.DTSTART[0];
  check("TZID param parsed", dtstart.params.TZID[0] === "America/New_York");
  var attendee = ast.vcalendar.vevent[0].properties.ATTENDEE[0];
  check("CN param parsed",   attendee.params.CN[0] === "Alice Example");
  check("ROLE param parsed", attendee.params.ROLE[0] === "REQ-PARTICIPANT");
}

function expectRefused(label, fn, expectedCode) {
  try {
    fn();
    check(label, false);
  } catch (e) {
    if (typeof expectedCode === "string") {
      check(label + " [" + (e && e.code) + "]", e && e.code === expectedCode);
    } else {
      check(label, e && e.code && e.code.indexOf("safe-ical/") === 0);
    }
  }
}

function testRefusesOversizeBytes() {
  // Use a tight strict-mode profile: build a calendar over 256 KiB by
  // stacking many small properties. Each line stays under the
  // 8 KiB per-line cap so only the total-byte cap fires.
  var pad = new Array(5000).join("X");   // ~5 KB per line, under 8 KiB line cap
  var body = "BEGIN:VEVENT\r\nUID:big@example.com\r\nDTSTAMP:20260101T120000Z\r\n" +
             "DTSTART:20260101T130000Z\r\n";
  for (var i = 0; i < 80; i++) {
    body += "X-PADDING-" + i + ":" + pad + "\r\n";
  }
  body += "END:VEVENT\r\n";
  expectRefused("refuses oversize bytes",
    function () { safeIcal.parse(_ical(body)); },
    "safe-ical/oversize-bytes");
}

function testRefusesRecursiveRrule() {
  // Calendar-bomb defense: RRULE COUNT > 10000 refused regardless of profile.
  expectRefused("refuses RRULE COUNT > 10000",
    function () {
      safeIcal.parse(_ical(_event("RRULE:FREQ=DAILY;COUNT=999999\r\n")));
    },
    "safe-ical/oversize-rrule-count");
  // RRULE BYDAY list-length > 24 refused.
  var manyDays = [];
  for (var i = 0; i < 50; i++) manyDays.push("MO");
  expectRefused("refuses RRULE BYDAY list > 24",
    function () {
      safeIcal.parse(_ical(_event("RRULE:FREQ=WEEKLY;BYDAY=" + manyDays.join(",") + "\r\n")));
    },
    "safe-ical/oversize-rrule-by");
}

function testAcceptsValidRrule() {
  var ast = safeIcal.parse(_ical(_event("RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=52\r\n")));
  check("valid RRULE accepted",
    ast.vcalendar.vevent[0].properties.RRULE[0].value === "FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=52");
}

function testRefusesControlCharInValue() {
  var bad = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Bad//\r\n" +
            "BEGIN:VEVENT\r\nUID:cc@example.com\r\nDTSTAMP:20260101T120000Z\r\n" +
            "DTSTART:20260101T130000Z\r\n" +
            "SUMMARY:Hello\x01World\r\n" +
            "END:VEVENT\r\nEND:VCALENDAR\r\n";
  expectRefused("refuses control char in value",
    function () { safeIcal.parse(bad); },
    "safe-ical/control-char-in-value");
}

function testRefusesUnknownProperty() {
  expectRefused("refuses unknown property",
    function () {
      safeIcal.parse(_ical(_event("BOGUS-PROPERTY:something\r\n")));
    },
    "safe-ical/unknown-property");
}

function testAcceptsXPrefixedProperty() {
  var ast = safeIcal.parse(_ical(_event("X-MICROSOFT-EVENTID:abc123\r\n")));
  check("X- prefixed property accepted",
    !!ast.vcalendar.vevent[0].properties["X-MICROSOFT-EVENTID"]);
}

function testExtraPropertiesAllowlist() {
  var ast = safeIcal.parse(_ical(_event("CUSTOM-FIELD:value\r\n")),
    { extraProperties: ["CUSTOM-FIELD"] });
  check("operator extraProperties accepted",
    ast.vcalendar.vevent[0].properties["CUSTOM-FIELD"][0].value === "value");
}

function testRefusesMissingVcalendar() {
  // A well-formed content line that is not BEGIN:VCALENDAR — parser
  // walks past it looking for BEGIN and runs out.
  expectRefused("refuses no BEGIN:VCALENDAR",
    function () { safeIcal.parse("FOO:bar\r\nBAZ:quux\r\n"); },
    "safe-ical/missing-vcalendar");
}

function testRefusesUnterminatedComponent() {
  expectRefused("refuses unterminated VEVENT",
    function () {
      safeIcal.parse("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//X//\r\n" +
        "BEGIN:VEVENT\r\nUID:u\r\nDTSTAMP:20260101T120000Z\r\n" +
        "DTSTART:20260101T130000Z\r\nEND:VCALENDAR\r\n");
    },
    "safe-ical/unterminated-component");
}

function testRefusesBadInput() {
  expectRefused("refuses non-string non-buffer",
    function () { safeIcal.parse(42); },
    "safe-ical/bad-input");
}

function testRefusesBadProfile() {
  expectRefused("refuses unknown profile",
    function () { safeIcal.parse(_ical(_event()), { profile: "ultra" }); },
    "safe-ical/bad-opt");
}

function testProfileBalancedAcceptsLargerInput() {
  // Build ical that exceeds strict's 256 KiB cap but stays under
  // balanced's 1 MiB cap.
  var pad = new Array(8000).join("A");
  var lines = [];
  for (var i = 0; i < 40; i++) {
    lines.push("X-PADDING-" + i + ":" + pad);
  }
  var body = "BEGIN:VEVENT\r\nUID:big@example.com\r\nDTSTAMP:20260101T120000Z\r\n" +
             "DTSTART:20260101T130000Z\r\n" + lines.join("\r\n") + "\r\nEND:VEVENT\r\n";
  var ical = _ical(body);
  // Strict refuses
  expectRefused("strict refuses 300+ KiB",
    function () { safeIcal.parse(ical, { profile: "strict" }); },
    "safe-ical/oversize-bytes");
  // Balanced accepts
  var ast = safeIcal.parse(ical, { profile: "balanced" });
  check("balanced accepts 300+ KiB",
    ast.vcalendar.vevent[0].properties["X-PADDING-0"][0].value === pad);
}

function testProtoKeyProfileRejected() {
  // A prototype-member name as the profile must be refused, not resolved to an
  // inherited member ("constructor" -> Object.prototype.constructor,
  // "__proto__" -> Object.prototype, "toString" -> a Function). The own-property
  // guard in _resolveCaps rejects it; a bare `if (!PROFILES[name])` truthiness
  // check would pass the inherited member as a known profile (fail-open).
  expectRefused("refuses prototype-key profile 'constructor'",
    function () { safeIcal.parse(_ical(_event()), { profile: "constructor" }); },
    "safe-ical/bad-opt");
  expectRefused("refuses prototype-key profile '__proto__'",
    function () { safeIcal.parse(_ical(_event()), { profile: "__proto__" }); },
    "safe-ical/bad-opt");
  expectRefused("refuses prototype-key profile 'toString'",
    function () { safeIcal.parse(_ical(_event()), { profile: "toString" }); },
    "safe-ical/bad-opt");
  // A prototype-member name as the compliancePosture must not resolve to an
  // inherited member either. The own-property guard skips the unknown posture
  // and falls back to the strict profile, parsing cleanly — a bare
  // `COMPLIANCE_POSTURES[name] || "strict"` read would surface a Function as
  // the profile name and refuse spuriously (or, without the profile guard,
  // run under it). Assert the secure fall-back holds.
  var postureThrew = null, ast = null;
  try { ast = safeIcal.parse(_ical(_event()), { compliancePosture: "toString" }); }
  catch (e) { postureThrew = e; }
  check("prototype-key posture falls back to strict (no fail-open)",
    postureThrew === null && !!(ast && ast.vcalendar));
  // A valid profile still parses.
  var ok = safeIcal.parse(_ical(_event()), { profile: "balanced" });
  check("valid profile 'balanced' still parses", !!ok.vcalendar);
}

function testHipaaPosture() {
  // hipaa posture maps to strict.
  expectRefused("hipaa posture refuses oversize (mapped to strict)",
    function () {
      var pad = new Array(8000).join("A");
      var lines = [];
      for (var i = 0; i < 40; i++) lines.push("X-PADDING-" + i + ":" + pad);
      var body = "BEGIN:VEVENT\r\nUID:h@x\r\nDTSTAMP:20260101T120000Z\r\n" +
                 "DTSTART:20260101T130000Z\r\n" + lines.join("\r\n") + "\r\nEND:VEVENT\r\n";
      safeIcal.parse(_ical(body), { compliancePosture: "hipaa" });
    },
    "safe-ical/oversize-bytes");
}

function testBSurface() {
  var b = require("../../");
  check("b.safeIcal.parse wired",              typeof b.safeIcal.parse === "function");
  check("b.safeIcal.compliancePosture wired",  typeof b.safeIcal.compliancePosture === "function");
  check("b.safeIcal.SafeIcalError wired",      typeof b.safeIcal.SafeIcalError === "function");
}

async function run() {
  testBSurface();
  testSurface();
  testProfilesPresent();
  testSimpleParse();
  testVtodoVjournal();
  testNestedValarm();
  testLineUnfolding();
  testPropertyParams();
  testRefusesOversizeBytes();
  testRefusesRecursiveRrule();
  testAcceptsValidRrule();
  testRefusesControlCharInValue();
  testRefusesUnknownProperty();
  testAcceptsXPrefixedProperty();
  testExtraPropertiesAllowlist();
  testRefusesMissingVcalendar();
  testRefusesUnterminatedComponent();
  testRefusesBadInput();
  testRefusesBadProfile();
  testProtoKeyProfileRejected();
  testProfileBalancedAcceptsLargerInput();
  testHipaaPosture();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
