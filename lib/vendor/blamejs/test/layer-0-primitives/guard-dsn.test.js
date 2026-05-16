"use strict";
/**
 * b.guardDsn — RFC 3464 Delivery Status Notification parser.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _dsn(lines) {
  return lines.join("\r\n");
}

function _basicDsn() {
  return _dsn([
    "Reporting-MTA: dns; mail.example.com",
    "",
    "Final-Recipient: rfc822; alice@example.com",
    "Action: failed",
    "Status: 5.1.1",
    "Diagnostic-Code: smtp; 550 5.1.1 User unknown",
    "",
  ]);
}

function testSurface() {
  check("parse is fn",             typeof b.guardDsn.parse === "function");
  check("compliancePosture is fn", typeof b.guardDsn.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.guardDsn.PROFILES));
  check("KNOWN_ACTIONS frozen",    Object.isFrozen(b.guardDsn.KNOWN_ACTIONS));
  check("GuardDsnError is fn",     typeof b.guardDsn.GuardDsnError === "function");
  check("NAME=dsn",                b.guardDsn.NAME === "dsn");
}

function testParsesBasicBounce() {
  var r = b.guardDsn.parse(_basicDsn());
  check("perMessage.reportingMta",  r.perMessage.reportingMta === "dns; mail.example.com");
  check("perRecipients count 1",    r.perRecipients.length === 1);
  check("finalRecipient stripped",  r.perRecipients[0].finalRecipient === "alice@example.com");
  check("action failed",            r.perRecipients[0].action === "failed");
  check("status 5.1.1",             r.perRecipients[0].status === "5.1.1");
  check("statusClass permanent",    r.perRecipients[0].statusClass === "permanent");
  check("worstStatusClass",         r.worstStatusClass === "permanent");
  check("action invalidate",        r.action === "invalidate");
  check("diagnostic code",          r.perRecipients[0].diagnosticCode.indexOf("550") !== -1);
}

function testParsesTemporaryFailure() {
  var dsn = _dsn([
    "Reporting-MTA: dns; mail.example.com",
    "",
    "Final-Recipient: rfc822; alice@example.com",
    "Action: delayed",
    "Status: 4.2.2",
    "",
  ]);
  var r = b.guardDsn.parse(dsn);
  check("4xx → temporary",         r.perRecipients[0].statusClass === "temporary");
  check("worstStatusClass",         r.worstStatusClass === "temporary");
  check("action retry",             r.action === "retry");
}

function testParsesSuccessDelivery() {
  var dsn = _dsn([
    "Reporting-MTA: dns; mail.example.com",
    "",
    "Final-Recipient: rfc822; alice@example.com",
    "Action: delivered",
    "Status: 2.0.0",
    "",
  ]);
  var r = b.guardDsn.parse(dsn);
  check("2xx → success",            r.perRecipients[0].statusClass === "success");
  check("action deliver",           r.action === "deliver");
}

function testMultipleRecipientsWorstWins() {
  var dsn = _dsn([
    "Reporting-MTA: dns; mail.example.com",
    "",
    "Final-Recipient: rfc822; alice@example.com",
    "Action: delivered",
    "Status: 2.0.0",
    "",
    "Final-Recipient: rfc822; bob@example.com",
    "Action: failed",
    "Status: 5.1.1",
    "",
  ]);
  var r = b.guardDsn.parse(dsn);
  check("multi: 2 recipients",      r.perRecipients.length === 2);
  check("multi: worst = permanent", r.worstStatusClass === "permanent");
  check("multi: action invalidate", r.action === "invalidate");
}

function testRefusesMissingReportingMta() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Final-Recipient: rfc822; alice@example.com",
      "Action: failed",
      "Status: 5.1.1",
      "",
    ]));
  } catch (e) { threw = e; }
  check("missing reporting-mta refused", threw && threw.code === "guard-dsn/missing-reporting-mta");
}

function testRefusesMissingFinalRecipient() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Action: failed",
      "Status: 5.1.1",
      "",
    ]));
  } catch (e) { threw = e; }
  check("missing final-recipient refused", threw && threw.code === "guard-dsn/missing-final-recipient");
}

function testRefusesMissingAction() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Final-Recipient: rfc822; alice@example.com",
      "Status: 5.1.1",
      "",
    ]));
  } catch (e) { threw = e; }
  check("missing action refused",   threw && threw.code === "guard-dsn/missing-action");
}

function testRefusesMissingStatus() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Final-Recipient: rfc822; alice@example.com",
      "Action: failed",
      "",
    ]));
  } catch (e) { threw = e; }
  check("missing status refused",   threw && threw.code === "guard-dsn/missing-status");
}

function testRefusesBadStatus() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Final-Recipient: rfc822; alice@example.com",
      "Action: failed",
      "Status: NOT-A-CODE",
      "",
    ]));
  } catch (e) { threw = e; }
  check("bad status refused",       threw && threw.code === "guard-dsn/bad-status");
}

function testRefusesUnknownAction() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Final-Recipient: rfc822; alice@example.com",
      "Action: explosion",
      "Status: 5.1.1",
      "",
    ]));
  } catch (e) { threw = e; }
  check("unknown action refused",   threw && threw.code === "guard-dsn/bad-action");
}

function testRefusesOversizeBody() {
  var big = "Reporting-MTA: dns; mail.example.com\r\n" + "X-Pad: " + "a".repeat(300000) + "\r\n\r\n" +
    "Final-Recipient: rfc822; alice@example.com\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n";
  var threw = null;
  try { b.guardDsn.parse(big); }
  catch (e) { threw = e; }
  check("oversize body refused",    threw && (threw.code === "guard-dsn/oversize-body" || threw.code === "guard-dsn/oversize-header-line"));
}

function testRefusesControlChar() {
  var threw = null;
  try {
    b.guardDsn.parse([
      "Reporting-MTA: dns; mail.example.com",
      "",
      "Final-Recipient: rfc822; aliceinjected@example.com",
      "Action: failed",
      "Status: 5.1.1",
      "",
    ].join("\r\n"));
  } catch (e) { threw = e; }
  check("control char refused",     threw && threw.code === "guard-dsn/control-char");
}

function testHandlesContinuationLines() {
  // RFC 5322 §2.2 — continuation lines start with whitespace.
  var dsn = _dsn([
    "Reporting-MTA: dns;",
    "  mail.example.com",
    "",
    "Final-Recipient: rfc822; alice@example.com",
    "Action: failed",
    "Status: 5.1.1",
    "Diagnostic-Code: smtp;",
    "  550 5.1.1 User unknown",
    "  (additional context)",
    "",
  ]);
  var r = b.guardDsn.parse(dsn);
  check("continuation lines merged", r.perMessage.reportingMta === "dns; mail.example.com");
  check("multi-line diagnostic",     r.perRecipients[0].diagnosticCode === "smtp; 550 5.1.1 User unknown (additional context)");
}

function testRefusesEmptyBody() {
  var threw = null;
  try { b.guardDsn.parse(""); }
  catch (e) { threw = e; }
  check("empty body refused",       threw && threw.code === "guard-dsn/missing-reporting-mta");
}

function testRefusesNoRecipients() {
  var threw = null;
  try {
    b.guardDsn.parse(_dsn([
      "Reporting-MTA: dns; mail.example.com",
      "",
    ]));
  } catch (e) { threw = e; }
  check("no recipients refused",    threw && threw.code === "guard-dsn/no-recipients");
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardDsn.compliancePosture("hipaa") === "strict");
  check("unknown → null",     b.guardDsn.compliancePosture("foo") === null);
}

function testProfileBadRefused() {
  var threw = null;
  try { b.guardDsn.parse(_basicDsn(), { profile: "yolo" }); }
  catch (e) { threw = e; }
  check("bad profile refused", threw && threw.code === "guard-dsn/bad-profile");
}

function testTooManyRecipientsRefused() {
  // Build a DSN with 300 recipients — strict cap is 256.
  var lines = ["Reporting-MTA: dns; mail.example.com", ""];
  for (var i = 0; i < 300; i += 1) {
    lines.push("Final-Recipient: rfc822; user" + i + "@example.com");
    lines.push("Action: failed");
    lines.push("Status: 5.1.1");
    lines.push("");
  }
  var threw = null;
  try { b.guardDsn.parse(_dsn(lines)); }
  catch (e) { threw = e; }
  check("recipient count cap refused", threw && threw.code === "guard-dsn/too-many-recipients");
}

function run() {
  testSurface();
  testParsesBasicBounce();
  testParsesTemporaryFailure();
  testParsesSuccessDelivery();
  testMultipleRecipientsWorstWins();
  testRefusesMissingReportingMta();
  testRefusesMissingFinalRecipient();
  testRefusesMissingAction();
  testRefusesMissingStatus();
  testRefusesBadStatus();
  testRefusesUnknownAction();
  testRefusesOversizeBody();
  testRefusesControlChar();
  testHandlesContinuationLines();
  testRefusesEmptyBody();
  testRefusesNoRecipients();
  testCompliancePosture();
  testProfileBadRefused();
  testTooManyRecipientsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
