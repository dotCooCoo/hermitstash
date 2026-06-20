"use strict";
/**
 * mail-arf — RFC 5965 Abuse Reporting Format ingest.
 *
 * Run standalone: `node test/layer-0-primitives/mail-arf.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// RFC 5965 §A.1 — the canonical example. Inlined as the
// shipping fixture so the test is self-contained.
var ARF_RFC5965_SAMPLE =
  "From: <abusedesk@example.com>\r\n" +
  "Date: Thu, 8 Mar 2005 17:40:36 EDT\r\n" +
  "Subject: FW: Earn money\r\n" +
  "To: <abuse@example.net>\r\n" +
  "MIME-Version: 1.0\r\n" +
  'Content-Type: multipart/report; report-type=feedback-report;\r\n' +
  '\tboundary="part1_13d.2e68ed54_boundary"\r\n' +
  "\r\n" +
  "--part1_13d.2e68ed54_boundary\r\n" +
  "Content-Type: text/plain; charset=\"US-ASCII\"\r\n" +
  "\r\n" +
  "This is an email abuse report for an email message received from\r\n" +
  "IP 192.0.2.1 on Thu, 8 Mar 2005 14:00:00 EDT.\r\n" +
  "\r\n" +
  "--part1_13d.2e68ed54_boundary\r\n" +
  "Content-Type: message/feedback-report\r\n" +
  "\r\n" +
  "Feedback-Type: abuse\r\n" +
  "User-Agent: SomeGenerator/1.0\r\n" +
  "Version: 1\r\n" +
  "Original-Mail-From: <somespammer@example.net>\r\n" +
  "Original-Rcpt-To: <user@example.com>\r\n" +
  "Received-Date: Thu, 8 Mar 2005 14:00:00 EDT\r\n" +
  "Source-IP: 192.0.2.1\r\n" +
  "Authentication-Results: mail.example.com; spf=fail smtp.mail=somespammer@example.net\r\n" +
  "Reported-Domain: example.net\r\n" +
  "Reported-Uri: http://example.net/earn_money.html\r\n" +
  "Reported-Uri: mailto:user@example.com\r\n" +
  "Removal-Recipient: user@example.com\r\n" +
  "\r\n" +
  "--part1_13d.2e68ed54_boundary\r\n" +
  "Content-Type: message/rfc822\r\n" +
  "\r\n" +
  "From: <somespammer@example.net>\r\n" +
  "Received: from mailserver.example.net (mailserver.example.net [192.0.2.1])\r\n" +
  "  by example.com with SMTP id M63d4137594e46;\r\n" +
  "  Thu, 08 Mar 2005 14:00:00 -0400\r\n" +
  "To: <user@example.com>\r\n" +
  "Subject: Earn money\r\n" +
  "MIME-Version: 1.0\r\n" +
  "\r\n" +
  "Spam Spam Spam\r\n" +
  "Spam Spam Spam\r\n" +
  "Spam Spam Spam\r\n" +
  "Spam Spam Spam\r\n" +
  "--part1_13d.2e68ed54_boundary--\r\n";

function testSurface() {
  check("b.mailArf is exposed",                 typeof b.mailArf === "object");
  check("b.mailArf.parse is a function",        typeof b.mailArf.parse === "function");
  check("b.frameworkError.MailArfError is a class",
        typeof b.frameworkError.MailArfError === "function");
  check("b.mailArf.MailArfError is the same class (re-exported on the namespace)",
        b.mailArf.MailArfError === b.frameworkError.MailArfError);
}

function testParseRfc5965Sample() {
  var event = b.mailArf.parse(ARF_RFC5965_SAMPLE, { audit: false });
  check("arf.parse: feedbackType=abuse",
        event.feedbackType === "abuse");
  check("arf.parse: userAgent=SomeGenerator/1.0",
        event.userAgent === "SomeGenerator/1.0");
  check("arf.parse: version=1",
        event.version === "1");
  check("arf.parse: originalFrom carries angle-bracketed address",
        event.originalFrom === "<somespammer@example.net>");
  check("arf.parse: originalRcptTo collects every header",
        Array.isArray(event.originalRcptTo) &&
        event.originalRcptTo.length === 1 &&
        event.originalRcptTo[0] === "<user@example.com>");
  check("arf.parse: sourceIp=192.0.2.1",
        event.sourceIp === "192.0.2.1");
  check("arf.parse: reportedDomain=example.net",
        event.reportedDomain === "example.net");
  check("arf.parse: authenticationResults captured",
        typeof event.authenticationResults === "string" &&
        event.authenticationResults.indexOf("spf=fail") !== -1);
  check("arf.parse: reportedUri captured (last header wins on duplicate)",
        typeof event.reportedUri === "string" &&
        event.reportedUri.indexOf("example.net") !== -1 ||
        event.reportedUri.indexOf("mailto:") !== -1);
  check("arf.parse: originalMessage includes the spam content",
        typeof event.originalMessage === "string" &&
        event.originalMessage.indexOf("Spam Spam Spam") !== -1);
  check("arf.parse: extraFields captures non-normalized tags",
        event.extraFields && event.extraFields["received-date"] !== undefined &&
        event.extraFields["removal-recipient"] !== undefined);
}

function testParseMissingRequired() {
  // Drop User-Agent — missing required field.
  var msg = ARF_RFC5965_SAMPLE.replace(/User-Agent:[^\r]+\r\n/, "");
  var threw = null;
  try { b.mailArf.parse(msg, { audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: missing User-Agent → missing-required-field",
        threw && /missing-required-field/.test(threw.code || ""));
}

function testParseMissingFeedbackType() {
  var msg = ARF_RFC5965_SAMPLE.replace(/Feedback-Type:[^\r]+\r\n/, "");
  var threw = null;
  try { b.mailArf.parse(msg, { audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: missing Feedback-Type → missing-required-field",
        threw && /missing-required-field/.test(threw.code || ""));
}

function testParseWrongContentType() {
  var msg = "From: x\r\nContent-Type: text/plain\r\n\r\nbody\r\n";
  var threw = null;
  try { b.mailArf.parse(msg, { audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: wrong top-level Content-Type → parse-failed",
        threw && /parse-failed/.test(threw.code || ""));
}

function testParseMissingFeedbackPart() {
  // Multipart/report with NO message/feedback-report subpart.
  var msg =
    "MIME-Version: 1.0\r\n" +
    'Content-Type: multipart/report; report-type=feedback-report;\r\n' +
    '\tboundary="b"\r\n' +
    "\r\n" +
    "--b\r\n" +
    "Content-Type: text/plain\r\n\r\n" +
    "human description\r\n" +
    "--b--\r\n";
  var threw = null;
  try { b.mailArf.parse(msg, { audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: missing feedback-report subpart → parse-failed",
        threw && /parse-failed/.test(threw.code || "") &&
        /message\/feedback-report/.test(threw.message || ""));
}

function testParseBadInput() {
  var threw = null;
  try { b.mailArf.parse(123, { audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: number input → parse-failed",
        threw && /parse-failed/.test(threw.code || ""));
}

function testParseMaxBytes() {
  var threw = null;
  try { b.mailArf.parse(ARF_RFC5965_SAMPLE, { maxBytes: 100, audit: false }); }
  catch (e) { threw = e; }
  check("arf.parse: tiny maxBytes → parse-failed (exceeds)",
        threw && /parse-failed/.test(threw.code || "") &&
        /exceeds/.test(threw.message || ""));
}

function testParseBufferInput() {
  var event = b.mailArf.parse(Buffer.from(ARF_RFC5965_SAMPLE, "utf8"), { audit: false });
  check("arf.parse: Buffer input parses identically",
        event.feedbackType === "abuse" &&
        event.userAgent === "SomeGenerator/1.0");
}

function testParseAuthFailureType() {
  var msg = ARF_RFC5965_SAMPLE
    .replace("Feedback-Type: abuse", "Feedback-Type: auth-failure")
    .replace(
      "Original-Mail-From: <somespammer@example.net>\r\n",
      "Original-Mail-From: <somespammer@example.net>\r\nAuth-Failure: dmarc\r\n"
    );
  var event = b.mailArf.parse(msg, { audit: false });
  check("arf.parse: feedbackType=auth-failure",
        event.feedbackType === "auth-failure");
  check("arf.parse: authFailure=dmarc",
        event.authFailure === "dmarc");
}

function testByteCapMultibyte() {
  // maxBytes is a BYTE cap (regression for byte-cap-vs-char-length).
  var report = String.fromCharCode(0x4e2d).repeat(20); // 20 chars / 60 UTF-8 bytes; cap 30
  var threw = null;
  try { b.mailArf.parse(report, { maxBytes: 30 }); } catch (e) { threw = e; }
  check("mailArf byte-cap: multibyte report over byte cap refused",
    threw && threw.message.indexOf("exceeds 30 bytes") !== -1);
}

async function run() {
  testByteCapMultibyte();
  testSurface();
  testParseRfc5965Sample();
  testParseMissingRequired();
  testParseMissingFeedbackType();
  testParseWrongContentType();
  testParseMissingFeedbackPart();
  testParseBadInput();
  testParseMaxBytes();
  testParseBufferInput();
  testParseAuthFailureType();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
