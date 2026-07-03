// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mail-bounce — vendor-shaped intake for bounce / complaint /
 * delivery webhooks (postmark / ses / resend / custom).
 *
 * Run standalone: `node test/layer-0-primitives/mail-bounce.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var _bodyReq       = helpers._bodyReq;
var _bodyRes       = helpers._bodyRes;

function _waitFinish(res) {
  return new Promise(function (resolve) { res.on("finish", resolve); });
}

async function testSurface() {
  check("b.mailBounce is exposed",                  typeof b.mailBounce === "object");
  check("b.mailBounce.parse is a function",         typeof b.mailBounce.parse === "function");
  check("b.mailBounce.handler is a function",       typeof b.mailBounce.handler === "function");
  check("b.mailBounce.MailBounceError is a class",  typeof b.mailBounce.MailBounceError === "function");
  check("b.mailBounce.vendors has postmark / ses / resend",
        typeof b.mailBounce.vendors.postmark === "function" &&
        typeof b.mailBounce.vendors.ses === "function" &&
        typeof b.mailBounce.vendors.resend === "function");
}

async function testParsePostmarkBounce() {
  var event = b.mailBounce.parse({
    RecordType:  "Bounce",
    Type:        "HardBounce",
    Email:       "user@example.com",
    MessageID:   "abc-123",
    Description: "Smtp server returned an error",
    Details:     "550 5.1.1 Recipient address rejected",
    BouncedAt:   "2026-04-28T12:00:00Z",
  }, { vendor: "postmark" });
  check("postmark hard bounce: vendor",        event.vendor === "postmark");
  check("postmark hard bounce: type",          event.type === "bounce");
  check("postmark hard bounce: subType=hard",  event.subType === "hard");
  check("postmark hard bounce: recipient",     event.recipient === "user@example.com");
  check("postmark hard bounce: messageId",     event.messageId === "abc-123");
  check("postmark hard bounce: reason captures Details",
        event.reason === "550 5.1.1 Recipient address rejected");
  check("postmark hard bounce: timestamp",     event.timestamp === "2026-04-28T12:00:00Z");
}

async function testParsePostmarkSpam() {
  var event = b.mailBounce.parse({
    RecordType: "SpamComplaint",
    Email:      "noisy@example.com",
    MessageID:  "spam-1",
    BouncedAt:  "2026-04-28T13:00:00Z",
  }, { vendor: "postmark" });
  check("postmark spam: type=complaint",    event.type === "complaint");
  check("postmark spam: subType=spam",      event.subType === "spam");
  check("postmark spam: recipient",         event.recipient === "noisy@example.com");
}

async function testParsePostmarkDelivery() {
  var event = b.mailBounce.parse({
    RecordType:  "Delivery",
    Email:       "ok@example.com",
    MessageID:   "del-1",
    DeliveredAt: "2026-04-28T14:00:00Z",
  }, { vendor: "postmark" });
  check("postmark delivery: type=delivery",  event.type === "delivery");
  check("postmark delivery: subType=null",   event.subType === null);
}

async function testParseSesWithSnsEnvelope() {
  var sesMessage = {
    notificationType: "Bounce",
    mail: {
      messageId:   "ses-msg-1",
      destination: ["user@example.com"],
    },
    bounce: {
      bounceType:    "Permanent",
      bounceSubType: "General",
      bouncedRecipients: [{
        emailAddress:    "user@example.com",
        diagnosticCode:  "smtp; 550 5.1.1 user unknown",
        action:          "failed",
        status:          "5.1.1",
      }],
      timestamp: "2026-04-28T15:00:00Z",
    },
  };
  var sns = {
    Type:      "Notification",
    MessageId: "sns-id",
    Message:   JSON.stringify(sesMessage),
  };
  var event = b.mailBounce.parse(sns, { vendor: "ses" });
  check("ses (SNS-wrapped): vendor",          event.vendor === "ses");
  check("ses (SNS-wrapped): type=bounce",     event.type === "bounce");
  check("ses (SNS-wrapped): subType=hard",    event.subType === "hard");
  check("ses (SNS-wrapped): recipient",       event.recipient === "user@example.com");
  check("ses (SNS-wrapped): messageId",       event.messageId === "ses-msg-1");
  check("ses (SNS-wrapped): reason carries diagnosticCode",
        /550 5.1.1/.test(event.reason));
}

async function testParseSesUnwrappedComplaint() {
  // Operator strips the SNS layer at LB; raw SES message goes through.
  var event = b.mailBounce.parse({
    notificationType: "Complaint",
    mail: { messageId: "msg-2", destination: ["abc@example.com"] },
    complaint: {
      complainedRecipients:   [{ emailAddress: "abc@example.com" }],
      complaintFeedbackType:  "abuse",
      timestamp:              "2026-04-28T16:00:00Z",
    },
  }, { vendor: "ses" });
  check("ses unwrapped: type=complaint",      event.type === "complaint");
  check("ses unwrapped: subType=abuse",       event.subType === "abuse");
  check("ses unwrapped: recipient",           event.recipient === "abc@example.com");
}

async function testParseSesDelivery() {
  var event = b.mailBounce.parse({
    notificationType: "Delivery",
    mail: { messageId: "msg-3", destination: ["dest@example.com"] },
    delivery: {
      timestamp:  "2026-04-28T17:00:00Z",
      recipients: ["dest@example.com"],
    },
  }, { vendor: "ses" });
  check("ses delivery: type=delivery",        event.type === "delivery");
  check("ses delivery: recipient",            event.recipient === "dest@example.com");
}

async function testParseResendBounced() {
  var event = b.mailBounce.parse({
    type:       "email.bounced",
    created_at: "2026-04-28T18:00:00Z",
    data: {
      id: "res-1",
      to: ["fail@example.com"],
      bounce: { type: "Permanent", subType: "General", message: "550 user unknown" },
    },
  }, { vendor: "resend" });
  check("resend bounced: vendor",             event.vendor === "resend");
  check("resend bounced: type=bounce",        event.type === "bounce");
  check("resend bounced: subType=hard",       event.subType === "hard");
  check("resend bounced: recipient",          event.recipient === "fail@example.com");
  check("resend bounced: reason",             event.reason === "550 user unknown");
}

async function testParseResendComplained() {
  var event = b.mailBounce.parse({
    type:       "email.complained",
    created_at: "2026-04-28T19:00:00Z",
    data: { id: "res-2", to: "spammed@example.com" },
  }, { vendor: "resend" });
  check("resend complained: type=complaint",  event.type === "complaint");
  check("resend complained: subType=abuse",   event.subType === "abuse");
}

async function testParseResendDelivered() {
  var event = b.mailBounce.parse({
    type:       "email.delivered",
    created_at: "2026-04-28T20:00:00Z",
    data: { id: "res-3", to: "ok@example.com" },
  }, { vendor: "resend" });
  check("resend delivered: type=delivery",    event.type === "delivery");
}

async function testCustomParserHook() {
  // Operator with a private vendor supplies their own parser. The
  // framework runs it then validates the returned shape.
  var event = b.mailBounce.parse({ to: "custom@example.com", verdict: "hardfail" }, {
    parser: function (p) {
      return {
        vendor:    "internal-mta",
        type:      "bounce",
        subType:   p.verdict === "hardfail" ? "hard" : "soft",
        recipient: p.to,
        messageId: null,
        reason:    null,
        timestamp: new Date().toISOString(),
        raw:       p,
      };
    },
  });
  check("custom parser: vendor passes through", event.vendor === "internal-mta");
  check("custom parser: subType derived",       event.subType === "hard");
  check("custom parser: recipient",             event.recipient === "custom@example.com");
}

async function testCustomParserShapeValidated() {
  // Custom parser returns malformed shape — framework rejects.
  var threw = null;
  try {
    b.mailBounce.parse({}, { parser: function () { return { vendor: "x", type: "garbage" }; } });
  } catch (e) { threw = e; }
  check("custom parser: bad type rejected",
        threw && /'bounce' \| 'complaint' \| 'delivery'/.test(threw.message));
}

async function testParseRejectsUnknownVendor() {
  var threw = null;
  try { b.mailBounce.parse({}, { vendor: "mailgun" }); } catch (e) { threw = e; }
  check("parse rejects unknown vendor",
        threw && /unknown vendor 'mailgun'/.test(threw.message));
  threw = null;
  try { b.mailBounce.parse({}, {}); } catch (e) { threw = e; }
  check("parse rejects missing vendor",
        threw && /requires \{ vendor \}/.test(threw.message));
}

async function testHandlerHappyPath() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mb-"));
  try {
    await setupTestDb(tmpDir);
    var seen = null;
    var handler = b.mailBounce.handler({
      vendor:   "postmark",
      onBounce: function (event) { seen = event; },
    });
    var payload = {
      RecordType: "Bounce", Type: "HardBounce", Email: "u@e.com",
      MessageID: "m1", BouncedAt: "2026-04-28T00:00:00Z",
    };
    var req = _bodyReq("POST", { "content-type": "application/json" },
                       JSON.stringify(payload));
    var res = _bodyRes();
    handler(req, res);
    await _waitFinish(res);

    check("handler: 200 on success",          res._endedStatus === 200);
    check("handler: onBounce invoked",        seen && seen.recipient === "u@e.com");
    check("handler: onBounce sees normalized event",
                                              seen.subType === "hard");

    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.mail.bounce" });
    check("handler: audit row written",       rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("handler: audit carries vendor",    meta.vendor === "postmark");
    check("handler: audit carries recipient", meta.recipient === "u@e.com");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testHandlerVerifyAccepts() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mb-"));
  try {
    await setupTestDb(tmpDir);
    var verifyCalls = 0;
    var handler = b.mailBounce.handler({
      vendor: "postmark",
      verify: function (req, body, raw) {
        verifyCalls++;
        return req.headers["x-test-token"] === "valid";
      },
    });
    var req = _bodyReq("POST",
      { "content-type": "application/json", "x-test-token": "valid" },
      JSON.stringify({ RecordType: "Delivery", Email: "ok@e.com", MessageID: "x" }));
    var res = _bodyRes();
    handler(req, res);
    await _waitFinish(res);
    check("handler verify: called",            verifyCalls === 1);
    check("handler verify: 200 on accept",     res._endedStatus === 200);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testHandlerVerifyRejects() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mb-"));
  try {
    await setupTestDb(tmpDir);
    var onBounceCalled = false;
    var handler = b.mailBounce.handler({
      vendor:   "postmark",
      verify:   function () { return false; },
      onBounce: function () { onBounceCalled = true; },
    });
    var req = _bodyReq("POST", { "content-type": "application/json" },
      JSON.stringify({ RecordType: "Bounce", Type: "HardBounce", Email: "u@e.com" }));
    var res = _bodyRes();
    handler(req, res);
    await _waitFinish(res);
    check("handler verify reject: 401",        res._endedStatus === 401);
    check("handler verify reject: onBounce skipped",  onBounceCalled === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testHandlerRejectsBadJson() {
  var handler = b.mailBounce.handler({ vendor: "postmark", audit: false });
  var req = _bodyReq("POST", { "content-type": "application/json" }, "not-json");
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler bad json: 400",               res._endedStatus === 400);
  check("handler bad json: error mentions JSON", /invalid JSON/.test(res._captured));
}

async function testHandlerRejectsTooLarge() {
  var handler = b.mailBounce.handler({
    vendor:   "postmark",
    maxBytes: 100,
    audit:    false,
  });
  var bigBody = JSON.stringify({ Email: "x", padding: "X".repeat(500) });
  var req = _bodyReq("POST", { "content-type": "application/json" }, bigBody);
  var res = _bodyRes();
  handler(req, res);
  await _waitFinish(res);
  check("handler too large: 413",              res._endedStatus === 413);
}

async function testHandlerOnBounceErrorBecomes500() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mb-"));
  try {
    await setupTestDb(tmpDir);
    var handler = b.mailBounce.handler({
      vendor:   "postmark",
      onBounce: function () { return Promise.reject(new Error("repo down")); },
    });
    var req = _bodyReq("POST", { "content-type": "application/json" },
      JSON.stringify({ RecordType: "Bounce", Type: "HardBounce", Email: "u@e.com" }));
    var res = _bodyRes();
    handler(req, res);
    await _waitFinish(res);
    check("handler onBounce throw: 500",        res._endedStatus === 500);
    check("handler onBounce throw: error reflected",  /repo down/.test(res._captured));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testHandlerBadConfigRejected() {
  var threw = null;
  try { b.mailBounce.handler({ vendor: "fake" }); } catch (e) { threw = e; }
  check("handler: unknown vendor rejected at create()",
        threw && threw.code === "handler/bad-config");
}

// ---- RFC 3464 / RFC 3461 / RFC 6533 generic DSN ----

async function testDsnSurface() {
  check("b.mailBounce.dsn is exposed",         typeof b.mailBounce.dsn === "object");
  check("b.mailBounce.dsn.parse is a function", typeof b.mailBounce.dsn.parse === "function");
  check("b.mailBounce.dsn.build is a function", typeof b.mailBounce.dsn.build === "function");
  check("b.mailBounce.dsn.ACTIONS includes failed/delayed/delivered",
        b.mailBounce.dsn.ACTIONS.failed === true &&
        b.mailBounce.dsn.ACTIONS.delayed === true &&
        b.mailBounce.dsn.ACTIONS.delivered === true);
}

async function testDsnParseHardBounce() {
  // RFC 3464 Appendix B-shaped sample — multipart/report with the
  // canonical text + delivery-status + rfc822 trio.
  var dsn = [
    'MIME-Version: 1.0',
    'Content-Type: multipart/report; report-type=delivery-status; boundary="bnd-x"',
    'Message-ID: <dsn-1@mta.example.com>',
    '',
    '--bnd-x',
    'Content-Type: text/plain; charset=us-ascii',
    '',
    'Your message could not be delivered.',
    '',
    '--bnd-x',
    'Content-Type: message/delivery-status',
    '',
    'Reporting-MTA: dns; mta.example.com',
    'Arrival-Date: Mon, 28 Apr 2026 12:00:00 +0000',
    '',
    'Original-Recipient: rfc822;user@example.com',
    'Final-Recipient: rfc822;user@example.com',
    'Action: failed',
    'Status: 5.1.1',
    'Remote-MTA: dns; mx.example.com',
    'Diagnostic-Code: smtp; 550 5.1.1 No such user',
    '',
    '--bnd-x',
    'Content-Type: message/rfc822',
    '',
    'From: sender@example.com',
    'Subject: original',
    '',
    'body of original message',
    '',
    '--bnd-x--',
    '',
  ].join('\r\n');

  var event = b.mailBounce.dsn.parse(dsn);
  check("dsn parse: vendor=rfc3464",        event.vendor === "rfc3464");
  check("dsn parse: type=bounce",           event.type === "bounce");
  check("dsn parse: subType=hard",          event.subType === "hard");
  check("dsn parse: recipient",             event.recipient === "user@example.com");
  check("dsn parse: messageId from header", event.messageId === "<dsn-1@mta.example.com>");
  check("dsn parse: reason carries 550",    /550 5.1.1 No such user/.test(event.reason));
  check("dsn parse: arrivalDate timestamp", event.timestamp.indexOf("28 Apr 2026") !== -1);
  check("dsn parse: raw.status",            event.raw.status === "5.1.1");
  check("dsn parse: raw.action",            event.raw.action === "failed");
  check("dsn parse: original message attached",
        typeof event.raw.originalMessage === "string" &&
        /Subject: original/.test(event.raw.originalMessage));
}

async function testDsnParseSoftBounce() {
  var dsn = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'temporarily deferred',
    '',
    '--b1',
    'Content-Type: message/delivery-status',
    '',
    'Reporting-MTA: dns; mta.example.com',
    '',
    'Final-Recipient: rfc822;u@e.com',
    'Action: delayed',
    'Status: 4.4.1',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var event = b.mailBounce.dsn.parse(dsn);
  check("dsn soft: subType=soft",  event.subType === "soft");
  check("dsn soft: type=bounce",   event.type === "bounce");
}

async function testDsnParseDelivery() {
  var dsn = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'success',
    '',
    '--b1',
    'Content-Type: message/delivery-status',
    '',
    'Reporting-MTA: dns; mta.example.com',
    '',
    'Final-Recipient: rfc822;u@e.com',
    'Action: delivered',
    'Status: 2.0.0',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var event = b.mailBounce.dsn.parse(dsn);
  check("dsn delivered: type=delivery", event.type === "delivery");
  check("dsn delivered: subType=null",  event.subType === null);
}

async function testDsnParseUtf8Address() {
  // RFC 6533 SMTPUTF8 — utf-8 address-type. The framework strips the
  // type prefix and surfaces the raw bytes through.
  var dsn = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'eai bounce',
    '',
    '--b1',
    'Content-Type: message/delivery-status',
    '',
    'Reporting-MTA: dns; mta.example.com',
    '',
    'Final-Recipient: utf-8;üser@example.com',
    'Action: failed',
    'Status: 5.1.1',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var event = b.mailBounce.dsn.parse(dsn);
  check("dsn utf-8 recipient stripped of type prefix",
        event.recipient === "üser@example.com");
}

async function testDsnParseRejectsNonReport() {
  var threw = null;
  try {
    b.mailBounce.dsn.parse('Content-Type: text/plain\r\n\r\nhello');
  } catch (e) { threw = e; }
  check("dsn parse: rejects non-multipart/report",
        threw && threw.code === "bounce/dsn-malformed");
}

async function testDsnParseRejectsEmpty() {
  var threw = null;
  try { b.mailBounce.dsn.parse(""); } catch (e) { threw = e; }
  check("dsn parse: rejects empty input",
        threw && threw.code === "bounce/dsn-parse-failed");
}

async function testDsnParseRejectsBadAction() {
  var dsn = [
    'Content-Type: multipart/report; report-type=delivery-status; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'x',
    '',
    '--b1',
    'Content-Type: message/delivery-status',
    '',
    'Reporting-MTA: dns; m',
    '',
    'Final-Recipient: rfc822;u@e.com',
    'Action: bogus',
    'Status: 5.1.1',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var threw = null;
  try { b.mailBounce.dsn.parse(dsn); } catch (e) { threw = e; }
  check("dsn parse: rejects non-RFC3464 Action token",
        threw && threw.code === "bounce/dsn-malformed");
}

async function testDsnBuildMinimal() {
  var raw = b.mailBounce.dsn.build({
    finalRecipient: "user@example.com",
    action:         "failed",
    status:         "5.1.1",
    diagnosticCode: "smtp; 550 5.1.1 No such user",
  });
  check("dsn build: returns a string",        typeof raw === "string");
  check("dsn build: top Content-Type",        /multipart\/report/.test(raw));
  check("dsn build: report-type",             /report-type=delivery-status/.test(raw));
  check("dsn build: message/delivery-status part",
                                              /message\/delivery-status/.test(raw));
  check("dsn build: Final-Recipient",         /Final-Recipient: rfc822;user@example.com/.test(raw));
  check("dsn build: Action",                  /Action: failed/.test(raw));
  check("dsn build: Status",                  /Status: 5\.1\.1/.test(raw));
}

async function testDsnBuildRejectsCrlfInjection() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }

  // Diagnostic-Code echoes the remote server's SMTP reply — free text,
  // legitimately multi-line, so it is folded to one line: an embedded
  // CR/LF cannot start a new delivery-status field or a report part.
  var folded = b.mailBounce.dsn.build({
    finalRecipient: "user@example.com",
    action:         "failed",
    status:         "5.1.1",
    diagnosticCode: "smtp; 550 no user\r\nX-Injected: evil\r\nBcc: victim@evil.test",
  });
  check("dsn build: folded diagnosticCode cannot start a header line",
    !/^X-Injected:/m.test(folded) && !/^Bcc:/m.test(folded));

  // A NUL in the free-text diagnosticCode is stripped by the fold, not
  // serialized into the Diagnostic-Code header line.
  var nulDsn = b.mailBounce.dsn.build({
    finalRecipient: "user@example.com", action: "failed", status: "5.1.1",
    diagnosticCode: "smtp; 550 no user" + String.fromCharCode(0) + "evil",
  });
  check("dsn build: NUL in diagnosticCode stripped from output",
    nulDsn.indexOf(String.fromCharCode(0)) === -1);

  // Structured fields (recipients, MTA names, RFC 5322 envelope headers)
  // fail closed on CR / LF / NUL.
  var e1 = threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "user@example.com\r\nBcc: victim@evil.test",
      action: "failed", status: "5.1.1" });
  });
  check("dsn build: CRLF in finalRecipient throws bounce/bad-dsn-field",
    e1 && e1.code === "bounce/bad-dsn-field");
  var e2 = threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "user@example.com", action: "failed",
      status: "5.1.1", reportingMta: "mta.x\r\nX-Evil: 1" });
  });
  check("dsn build: CRLF in reportingMta throws bounce/bad-dsn-field",
    e2 && e2.code === "bounce/bad-dsn-field");
  var e3 = threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "user@example.com", action: "failed",
      status: "5.1.1", from: "mailer@x\r\nBcc: victim@evil.test" });
  });
  check("dsn build: CRLF in From throws bounce/bad-dsn-field",
    e3 && e3.code === "bounce/bad-dsn-field");
  var e4 = threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "user@example.com", action: "failed",
      status: "5.1.1", subject: "hi\r\nX-Evil: 1" });
  });
  check("dsn build: CRLF in Subject throws bounce/bad-dsn-field",
    e4 && e4.code === "bounce/bad-dsn-field");
  var e5 = threw(function () {
    b.mailBounce.dsn.build({ finalRecipient: "user@example.com", action: "failed",
      status: "5.1.1", remoteMta: "relay\r\nX-Evil: 1" });
  });
  check("dsn build: CRLF in remoteMta throws bounce/bad-dsn-field",
    e5 && e5.code === "bounce/bad-dsn-field");
}

async function testDsnBuildRoundtrip() {
  var raw = b.mailBounce.dsn.build({
    originalRecipient: "alias@example.com",
    finalRecipient:    "user@example.com",
    action:            "failed",
    status:            "5.1.1",
    diagnosticCode:    "smtp; 550 5.1.1 No such user",
    reportingMta:      "dns; mta.example.com",
    remoteMta:         "dns; mx.example.com",
    originalMessage:   "From: sender@example.com\r\nSubject: x\r\n\r\nbody",
  });
  var event = b.mailBounce.dsn.parse(raw);
  check("dsn roundtrip: vendor",            event.vendor === "rfc3464");
  check("dsn roundtrip: subType=hard",      event.subType === "hard");
  check("dsn roundtrip: recipient",         event.recipient === "user@example.com");
  check("dsn roundtrip: status",            event.raw.status === "5.1.1");
  check("dsn roundtrip: original message preserved",
        typeof event.raw.originalMessage === "string" &&
        /Subject: x/.test(event.raw.originalMessage));
}

async function testDsnBuildUtf8() {
  // RFC 6533 — non-ASCII in the recipient flips the address-type to utf-8.
  var raw = b.mailBounce.dsn.build({
    finalRecipient: "üser@example.com",
    action:         "failed",
    status:         "5.1.1",
  });
  check("dsn build: utf-8 address type",
        /Final-Recipient: utf-8;/.test(raw));
}

async function testDsnBuildRejectsBadAction() {
  var threw = null;
  try {
    b.mailBounce.dsn.build({ finalRecipient: "u@e.com", action: "bogus", status: "5.1.1" });
  } catch (e) { threw = e; }
  check("dsn build: rejects non-RFC3464 action",
        threw && threw.code === "bounce/dsn-malformed");
}

async function testDsnBuildRejectsBadStatus() {
  var threw = null;
  try {
    b.mailBounce.dsn.build({ finalRecipient: "u@e.com", action: "failed", status: "5xx" });
  } catch (e) { threw = e; }
  check("dsn build: rejects non-RFC3463 status",
        threw && threw.code === "bounce/dsn-malformed");
}

async function testDsnBuildRejectsMissingRecipient() {
  var threw = null;
  try {
    b.mailBounce.dsn.build({ action: "failed", status: "5.1.1" });
  } catch (e) { threw = e; }
  check("dsn build: rejects missing finalRecipient",
        threw && threw.code === "bounce/dsn-malformed");
}

async function testDsnBuildHeadersOnly() {
  // RFC 3461 RET=HDRS — operators that requested only headers in the
  // returned DSN can pass `originalMessage: { headersOnly: true,
  // headers }` and the framework emits a text/rfc822-headers part.
  var raw = b.mailBounce.dsn.build({
    finalRecipient:  "u@e.com",
    action:          "failed",
    status:          "5.1.1",
    originalMessage: { headersOnly: true, headers: "From: x@y\r\nSubject: hdrs-only\r\n" },
  });
  check("dsn build: text/rfc822-headers when headersOnly",
        /Content-Type: text\/rfc822-headers/.test(raw));
  check("dsn build: omits message/rfc822 when headersOnly",
        !/Content-Type: message\/rfc822\r\n/.test(raw));
}

async function run() {
  await testSurface();
  await testParsePostmarkBounce();
  await testParsePostmarkSpam();
  await testParsePostmarkDelivery();
  await testParseSesWithSnsEnvelope();
  await testParseSesUnwrappedComplaint();
  await testParseSesDelivery();
  await testParseResendBounced();
  await testParseResendComplained();
  await testParseResendDelivered();
  await testCustomParserHook();
  await testCustomParserShapeValidated();
  await testParseRejectsUnknownVendor();
  await testHandlerHappyPath();
  await testHandlerVerifyAccepts();
  await testHandlerVerifyRejects();
  await testHandlerRejectsBadJson();
  await testHandlerRejectsTooLarge();
  await testHandlerOnBounceErrorBecomes500();
  await testHandlerBadConfigRejected();
  await testDsnSurface();
  await testDsnParseHardBounce();
  await testDsnParseSoftBounce();
  await testDsnParseDelivery();
  await testDsnParseUtf8Address();
  await testDsnParseRejectsNonReport();
  await testDsnParseRejectsEmpty();
  await testDsnParseRejectsBadAction();
  await testDsnBuildMinimal();
  await testDsnBuildRejectsCrlfInjection();
  await testDsnBuildRoundtrip();
  await testDsnBuildUtf8();
  await testDsnBuildRejectsBadAction();
  await testDsnBuildRejectsBadStatus();
  await testDsnBuildRejectsMissingRecipient();
  await testDsnBuildHeadersOnly();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
