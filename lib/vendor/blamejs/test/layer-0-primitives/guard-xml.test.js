"use strict";
/**
 * guard-xml — XML content-safety primitive (b.guardXml).
 *
 * Covers: surface; registry parity; DOCTYPE rejection; ENTITY +
 * parameter-entity rejection; external-entity (file:// / http://
 * SYSTEM/PUBLIC) detection; XInclude detection; xsi:schemaLocation;
 * processing-instruction detection (skipping standard <?xml?>
 * declaration); CDATA detection; XML signature detection (audit);
 * bidi/null/control char detection; element-count + depth caps;
 * sanitize discipline (refuses on critical even with strip-able
 * options); profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardXmlSurface() {
  check("guardXml is an object",                    typeof b.guardXml === "object");
  check("guardXml.NAME === 'xml'",                  b.guardXml.NAME === "xml");
  check("guardXml.KIND === 'content'",              b.guardXml.KIND === "content");
  check("guardXml.MIME_TYPES has application/xml",  b.guardXml.MIME_TYPES.indexOf("application/xml") !== -1);
  check("guardXml.EXTENSIONS has .xml",             b.guardXml.EXTENSIONS.indexOf(".xml") !== -1);
  check("guardXml.PROFILES has strict",             !!b.guardXml.PROFILES["strict"]);
  check("guardXml.PROFILES has balanced",           !!b.guardXml.PROFILES["balanced"]);
  check("guardXml.PROFILES has permissive",         !!b.guardXml.PROFILES["permissive"]);
  check("guardXml.COMPLIANCE_POSTURES has hipaa",   !!b.guardXml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardXml.validate is a function",          typeof b.guardXml.validate === "function");
  check("guardXml.sanitize is a function",          typeof b.guardXml.sanitize === "function");
  check("guardXml.gate is a function",              typeof b.guardXml.gate === "function");
  check("frameworkError.GuardXmlError exposed",     typeof b.frameworkError.GuardXmlError === "function");
}

function testGuardXmlRegistryParity() {
  check("guardXml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "xml"; }));
}

function testGuardXmlDoctype() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?>\n<!DOCTYPE root>\n<root/>',
    { profile: "strict" });
  check("DOCTYPE detected (XXE / billion-laughs vector)",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "doctype"; }));
}

function testGuardXmlEntityDeclaration() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>',
    { profile: "strict" });
  check("<!ENTITY> declaration detected",
        rv.issues.some(function (i) { return i.kind === "entity-declaration"; }));
}

function testGuardXmlParameterEntity() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p "v">]><r/>',
    { profile: "strict" });
  check("parameter entity (% prefix) detected",
        rv.issues.some(function (i) { return i.kind === "parameter-entity"; }));
}

function testGuardXmlExternalEntity() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    { profile: "strict" });
  check("external SYSTEM file:// entity detected (XXE)",
        rv.issues.some(function (i) { return i.kind === "external-entity"; }));

  var rvHttp = b.guardXml.validate(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/x">]><r/>',
    { profile: "strict" });
  check("external SYSTEM http:// entity detected (XXE OOB exfil)",
        rvHttp.issues.some(function (i) { return i.kind === "external-entity"; }));
}

function testGuardXmlXInclude() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="x"/></r>',
    { profile: "strict" });
  check("XInclude detected (CVE-2024-25062 class)",
        rv.issues.some(function (i) { return i.kind === "xinclude"; }));
}

function testGuardXmlSchemaLocation() {
  var rv = b.guardXml.validate(
    '<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://attacker/s.xsd">x</r>',
    { profile: "strict" });
  check("xsi:schemaLocation detected",
        rv.issues.some(function (i) { return i.kind === "schema-location"; }));
}

function testGuardXmlProcessingInstruction() {
  var rv = b.guardXml.validate(
    '<?xml-stylesheet type="text/css" href="x.css"?><r/>',
    { profile: "strict" });
  check("xml-stylesheet processing-instruction detected (CSS injection vector)",
        rv.issues.some(function (i) { return i.kind === "processing-instruction"; }));

  // Standard <?xml?> declaration should NOT be flagged.
  var rvStd = b.guardXml.validate('<?xml version="1.0"?><r/>', { profile: "strict" });
  check("standard <?xml?> declaration NOT flagged",
        !rvStd.issues.some(function (i) { return i.kind === "processing-instruction"; }));
}

function testGuardXmlCdata() {
  var rv = b.guardXml.validate(
    '<r><![CDATA[hidden payload]]></r>',
    { profile: "strict" });
  check("CDATA section detected",
        rv.issues.some(function (i) { return i.kind === "cdata"; }));
}

function testGuardXmlBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardXml.validate("<r>a" + bidi + "b</r>", { profile: "strict" });
  check("bidi override detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardXml.validate("<r>a" + nb + "b</r>", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testGuardXmlElementCap() {
  var src = "<root>";
  for (var i = 0; i < 10000; i++) src += "<x/>";
  src += "</root>";
  var rv = b.guardXml.validate(src, { profile: "strict" });
  check("element cap detected (strict 8192)",
        rv.issues.some(function (i) { return i.kind === "element-cap"; }));
}

function testGuardXmlByteCap() {
  // The cap is named in BYTES; it must measure UTF-8 bytes, not UTF-16
  // code units. "é" is one .length unit but two UTF-8 bytes, so a string
  // whose .length is under the cap can still exceed it in bytes.
  var multibyte = "é".repeat(40); // .length === 40, Buffer.byteLength === 80
  var rv = b.guardXml.validate(multibyte, { profile: "strict", maxBytes: 50 });
  var cap = rv.issues.filter(function (i) { return i.kind === "too-large"; });
  check("multibyte input over the byte cap is refused",
        rv.ok === false && cap.length === 1 &&
        cap[0].ruleId === "xml.too-large" &&
        /80 bytes exceeds maxBytes 50/.test(cap[0].snippet));

  // ASCII under the cap must NOT trip too-large.
  var underAscii = "a".repeat(40);
  var rvUnder = b.guardXml.validate(underAscii, { profile: "strict", maxBytes: 50 });
  check("ASCII input under the byte cap is not flagged too-large",
        !rvUnder.issues.some(function (i) { return i.kind === "too-large"; }));

  // ASCII over the cap still trips too-large.
  var overAscii = "a".repeat(60);
  var rvOver = b.guardXml.validate(overAscii, { profile: "strict", maxBytes: 50 });
  check("ASCII input over the byte cap is refused",
        rvOver.issues.some(function (i) { return i.kind === "too-large"; }));
}

function testGuardXmlBadInputRuleId() {
  var rv = b.guardXml.validate(12345, { profile: "strict" });
  check("non-string input carries xml.bad-input ruleId",
        rv.issues.some(function (i) {
          return i.kind === "bad-input" && i.ruleId === "xml.bad-input";
        }));
}

function testGuardXmlClean() {
  var rv = b.guardXml.validate(
    '<?xml version="1.0"?><root><name>alice</name><age>30</age></root>',
    { profile: "strict" });
  check("clean XML → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardXmlSanitizeRefusesCritical() {
  var threw = null;
  try { b.guardXml.sanitize(
    '<?xml version="1.0"?><!DOCTYPE r><r/>', { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses DOCTYPE (no safe sanitization)",
        threw && /doctype/.test(threw.code || threw.message || ""));
}

async function testGuardXmlGate() {
  var g = b.guardXml.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/xml",
    bytes:       Buffer.from("<r>safe</r>", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/xml",
    bytes:       Buffer.from(
      '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r/>', "utf8"),
  });
  check("gate XXE → action !== serve",
        hostile.action !== "serve");
}

function testGuardXmlCompliancePosture() {
  var hipaa = b.guardXml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.doctypePolicy === "reject" && hipaa.entityPolicy === "reject");
  var threw = null;
  try { b.guardXml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

async function run() {
  testGuardXmlSurface();
  testGuardXmlRegistryParity();
  testGuardXmlDoctype();
  testGuardXmlEntityDeclaration();
  testGuardXmlParameterEntity();
  testGuardXmlExternalEntity();
  testGuardXmlXInclude();
  testGuardXmlSchemaLocation();
  testGuardXmlProcessingInstruction();
  testGuardXmlCdata();
  testGuardXmlBidiNull();
  testGuardXmlElementCap();
  testGuardXmlByteCap();
  testGuardXmlBadInputRuleId();
  testGuardXmlClean();
  testGuardXmlSanitizeRefusesCritical();
  testGuardXmlCompliancePosture();
  await testGuardXmlGate();
}

module.exports = { run: run };
