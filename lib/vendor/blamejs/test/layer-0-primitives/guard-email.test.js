"use strict";
/**
 * guard-email — Email content-safety primitive (b.guardEmail).
 *
 * Covers: surface; registry parity; SMTP smuggling (bare CR / bare LF
 * + smuggled SMTP verbs per CVE-2023-51764 / 51765 / 51766 class);
 * CRLF header injection; multi-@ rejection; IDN homograph (mixed-
 * script) detection; punycode flag; display-name spoofing; IP literal
 * detection; address-comment rejection; RFC 5321 length caps (local-
 * part 64 / domain 255 / address 320); RFC 5322 line cap (998); BOM
 * detection; bidi/null/control char detection; sanitize discipline;
 * gate composition; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardEmailSurface() {
  check("guardEmail is an object",                       typeof b.guardEmail === "object");
  check("guardEmail.NAME === 'email'",                   b.guardEmail.NAME === "email");
  check("guardEmail.KIND === 'content'",                 b.guardEmail.KIND === "content");
  check("guardEmail.MIME_TYPES has message/rfc822",      b.guardEmail.MIME_TYPES.indexOf("message/rfc822") !== -1);
  check("guardEmail.EXTENSIONS has .eml",                b.guardEmail.EXTENSIONS.indexOf(".eml") !== -1);
  check("guardEmail.PROFILES has strict",                !!b.guardEmail.PROFILES["strict"]);
  check("guardEmail.PROFILES has balanced",              !!b.guardEmail.PROFILES["balanced"]);
  check("guardEmail.PROFILES has permissive",            !!b.guardEmail.PROFILES["permissive"]);
  check("guardEmail.COMPLIANCE_POSTURES has hipaa",      !!b.guardEmail.COMPLIANCE_POSTURES["hipaa"]);
  check("guardEmail.validate is a function",             typeof b.guardEmail.validate === "function");
  check("guardEmail.validateAddress is a function",      typeof b.guardEmail.validateAddress === "function");
  check("guardEmail.validateMessage is a function",      typeof b.guardEmail.validateMessage === "function");
  check("guardEmail.sanitize is a function",             typeof b.guardEmail.sanitize === "function");
  check("guardEmail.gate is a function",                 typeof b.guardEmail.gate === "function");
  check("frameworkError.GuardEmailError exposed",        typeof b.frameworkError.GuardEmailError === "function");
}

function testGuardEmailRegistryParity() {
  check("guardEmail registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "email"; }));
}

function testGuardEmailCleanAddress() {
  var rv = b.guardEmail.validateAddress("alice@example.com", { profile: "strict" });
  check("clean address → ok=true",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardEmailMultiAt() {
  var rv = b.guardEmail.validateAddress("a@b@c.com", { profile: "strict" });
  check("multi-@ detected (RFC 5322 violation)",
        rv.issues.some(function (i) { return i.kind === "multi-at"; }));
}

function testGuardEmailLengthCaps() {
  var local = new Array(67).join("a");                                            // 66 chars
  var rv = b.guardEmail.validateAddress(local + "@example.com", { profile: "strict" });
  check("local-part > 64 detected",
        rv.issues.some(function (i) { return i.kind === "local-part-cap"; }));

  var longDomain = "x@" + new Array(60).join("aaaaa") + ".com";                   // > 255 bytes
  var rvD = b.guardEmail.validateAddress(longDomain, { profile: "strict" });
  check("domain > 255 OR address > 320 detected",
        rvD.issues.some(function (i) {
          return i.kind === "domain-cap" || i.kind === "address-cap";
        }));
}

function testGuardEmailIpLiteral() {
  var rv = b.guardEmail.validateAddress("user@[1.2.3.4]", { profile: "strict" });
  check("IP literal address detected (DMARC alignment bypass)",
        rv.issues.some(function (i) { return i.kind === "ip-literal"; }));
}

function testGuardEmailAddressComment() {
  var rv = b.guardEmail.validateAddress("alice(comment)@example.com", { profile: "strict" });
  check("RFC 5322 comment in address detected",
        rv.issues.some(function (i) {
          return i.kind === "address-comment" || i.kind === "address-syntax";
        }));
}

function testGuardEmailPunycode() {
  var rv = b.guardEmail.validateAddress("user@xn--ample-c0a.com", { profile: "strict" });
  check("Punycode/IDN domain detected (homograph spoofing risk)",
        rv.issues.some(function (i) { return i.kind === "punycode-domain"; }));
}

function testGuardEmailMixedScript() {
  // Cyrillic 'а' (U+0430) inside an otherwise-Latin domain.
  var domain = "user@exa" + String.fromCharCode(0x0430) + "mple.com";
  var rv = b.guardEmail.validateAddress(domain, { profile: "strict" });
  check("mixed-script Cyrillic-in-Latin domain detected (IDN homograph)",
        rv.issues.some(function (i) { return i.kind === "mixed-script-domain"; }));
}

function testGuardEmailSyntaxReject() {
  var rv = b.guardEmail.validateAddress("not an email", { profile: "strict" });
  check("malformed address → multi-at or address-syntax issue",
        rv.issues.some(function (i) {
          return i.kind === "multi-at" || i.kind === "address-syntax";
        }));
}

function testGuardEmailBareLfSmuggling() {
  // Bare LF in body — SMTP smuggling vector (CVE-2023-51765 / 51766).
  var msg = "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody\nMAIL FROM: <evil@x>\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("bare LF detected (SMTP smuggling vector class)",
        rv.issues.some(function (i) { return i.kind === "bare-lf"; }));
  check("smuggled SMTP verb after bare LF detected",
        rv.issues.some(function (i) { return i.kind === "smtp-smuggling"; }));
}

function testGuardEmailCrlfHeaderInjection() {
  // Build a header value that contains an embedded CRLF — header injection.
  // The unfolder collapses adjacent line; we simulate by injecting raw `\r\n`
  // into the value space without folding whitespace following it.
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nReply-To: a@x.com\rEvil-Header: x\r\n" +
            "\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("bare CR or CRLF-injected header detected",
        rv.issues.some(function (i) {
          return i.kind === "bare-cr" || i.kind === "crlf-header-injection";
        }));
}

function testGuardEmailDisplayNameSpoof() {
  var msg = 'From: "support@apple.com" <attacker@evil.com>\r\n' +
            "To: bob@example.com\r\nSubject: x\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("display-name spoofing (impersonating apple.com) detected",
        rv.issues.some(function (i) { return i.kind === "display-name-spoof"; }));
}

function testGuardEmailBom() {
  var msg = String.fromCharCode(0xfeff) +
            "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: x\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("BOM at start of message detected",
        rv.issues.some(function (i) { return i.kind === "bom"; }));
}

function testGuardEmailHeaderLineCap() {
  var bigSubject = "Subject: " + new Array(1010).join("x");                       // > 998 bytes
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            bigSubject + "\r\n\r\nbody\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("header-line cap (RFC 5322 998) detected",
        rv.issues.some(function (i) { return i.kind === "header-line-cap"; }));
}

function testGuardEmailBidiInAddress() {
  var bidi = String.fromCharCode(0x202e);
  var rv = b.guardEmail.validateAddress("a" + bidi + "b@example.com", { profile: "strict" });
  check("bidi override in address detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

function testGuardEmailCleanMessage() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\n" +
            "Hello.\r\n";
  var rv = b.guardEmail.validateMessage(msg, { profile: "strict" });
  check("clean RFC 5322 message → ok=true",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardEmailSanitizeRefusesCritical() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: x\r\n\r\nbody\nMAIL FROM: <evil@x>\r\n";
  var threw = null;
  try { b.guardEmail.sanitize(msg, { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses SMTP smuggling pattern",
        threw && /smuggling|bare-lf|refused/.test(threw.code || threw.message || ""));
}

async function testGuardEmailGate() {
  var g = b.guardEmail.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "message/rfc822",
    bytes:       Buffer.from("From: a@x.com\r\nTo: b@y.com\r\nSubject: ok\r\n" +
                             "Date: Mon, 5 May 2026 00:00:00 +0000\r\n\r\nbody\r\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "message/rfc822",
    bytes:       Buffer.from("From: a@x.com\r\nTo: b@y.com\r\nSubject: x\r\n\r\n" +
                             "body\nMAIL FROM: <evil@x>\r\n", "utf8"),
  });
  check("gate SMTP smuggling → action !== serve",
        hostile.action !== "serve");
}

function testGuardEmailCompliancePosture() {
  var hipaa = b.guardEmail.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.smtpSmugglingPolicy === "reject" &&
        hipaa.crlfHeaderInjectionPolicy === "reject");
  var threw = null;
  try { b.guardEmail.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

async function run() {
  testGuardEmailSurface();
  testGuardEmailRegistryParity();
  testGuardEmailCleanAddress();
  testGuardEmailMultiAt();
  testGuardEmailLengthCaps();
  testGuardEmailIpLiteral();
  testGuardEmailAddressComment();
  testGuardEmailPunycode();
  testGuardEmailMixedScript();
  testGuardEmailSyntaxReject();
  testGuardEmailBareLfSmuggling();
  testGuardEmailCrlfHeaderInjection();
  testGuardEmailDisplayNameSpoof();
  testGuardEmailBom();
  testGuardEmailHeaderLineCap();
  testGuardEmailBidiInAddress();
  testGuardEmailCleanMessage();
  testGuardEmailSanitizeRefusesCritical();
  testGuardEmailCompliancePosture();
  await testGuardEmailGate();
}

module.exports = { run: run };
