// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mail-mdn — RFC 3798 / RFC 8098 Message Disposition Notification
 * builder + parser. Auto-generation refusal when the inbound message
 * demanded user confirmation.
 *
 * Run standalone: `node test/layer-0-primitives/mail-mdn.test.js`
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

async function testSurface() {
  check("b.mailMdn is exposed",                  typeof b.mailMdn === "object");
  check("b.mailMdn.build is a function",         typeof b.mailMdn.build === "function");
  check("b.mailMdn.parse is a function",         typeof b.mailMdn.parse === "function");
  check("b.mailMdn.MailMdnError is a class",     typeof b.mailMdn.MailMdnError === "function");
  check("b.mailMdn.DISPOSITION_TYPES list",      Array.isArray(b.mailMdn.DISPOSITION_TYPES));
  check("b.mailMdn.DISPOSITION_TYPES has displayed",
        b.mailMdn.DISPOSITION_TYPES.indexOf("displayed") !== -1);
}

async function testBuildMinimal() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<orig-1@sender.example>",
    finalRecipient:          "user@example.com",
    disposition:             "displayed",
    requireUserConfirmation: false,
  });
  check("build: returns a string",                       typeof raw === "string");
  check("build: top Content-Type",                       /multipart\/report/.test(raw));
  check("build: report-type=disposition-notification",   /report-type=disposition-notification/.test(raw));
  check("build: message/disposition-notification part",  /message\/disposition-notification/.test(raw));
  check("build: Final-Recipient",                        /Final-Recipient: rfc822;user@example\.com/.test(raw));
  check("build: Original-Message-ID",                    /Original-Message-ID: <orig-1@sender\.example>/.test(raw));
  check("build: Disposition manual + displayed",
        /Disposition: manual-action\/MDN-sent-manually; displayed/.test(raw));
}

async function testBuildRejectsCrlfInjection() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var base = { originalMessageId: "<orig-1@sender.example>", finalRecipient: "user@example.com",
    disposition: "displayed", requireUserConfirmation: false };
  function withField(k, v) { var o = {}; for (var kk in base) o[kk] = base[kk]; o[k] = v; return o; }

  // Every structured MDN header field (recipients, message-id, envelope
  // headers, reporting UA) fails closed on CR / LF / NUL — an inbound
  // message must not be able to smuggle headers into the return receipt.
  var cases = [
    ["finalRecipient",     "user@example.com\r\nBcc: victim@evil.test"],
    ["originalMessageId",  "<x>\r\nX-Evil: 1"],
    ["from",               "mailer@x\r\nBcc: victim@evil.test"],
    ["to",                 "rcpt@x\r\nBcc: victim@evil.test"],
    ["subject",            "hi\r\nX-Evil: 1"],
    ["reportingUserAgent", "UA\r\nX-Evil: 1"],
    ["originalRecipient",  "u@x\r\nX-Evil: 1"],
  ];
  for (var i = 0; i < cases.length; i++) {
    var k = cases[i][0], v = cases[i][1];
    var e = threw((function (kk, vv) { return function () { b.mailMdn.build(withField(kk, vv)); }; })(k, v));
    check("mdn build: CRLF in " + k + " throws mdn/bad-header-field",
      e && e.code === "mdn/bad-header-field");
  }
}

async function testBuildAutomaticAction() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<m@x>",
    finalRecipient:          "u@e.com",
    disposition:             "processed",
    actionMode:              "automatic-action",
    sendingMode:             "MDN-sent-automatically",
    requireUserConfirmation: false,
  });
  check("build automatic: Disposition reflects automatic mode",
        /Disposition: automatic-action\/MDN-sent-automatically; processed/.test(raw));
}

async function testBuildAttachesOriginalMessage() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<m@x>",
    finalRecipient:          "u@e.com",
    disposition:             "displayed",
    originalMessage:         "From: sender@example.com\r\nSubject: x\r\n\r\nbody",
    requireUserConfirmation: false,
  });
  check("build: original message attached as message/rfc822",
        /Content-Type: message\/rfc822\r\n\r\nFrom: sender@example\.com/.test(raw));
}

async function testBuildRefusesAutoWhenImportantRequired() {
  // RFC 3798 §2.1 — Disposition-Notification-Options demands user
  // confirmation. Default behavior: refuse.
  var threw = null;
  try {
    b.mailMdn.build({
      originalMessageId: "<m@x>",
      finalRecipient:    "u@e.com",
      disposition:       "displayed",
      dispositionNotificationOptions: "signed-receipt-protocol=optional, important=required",
    });
  } catch (e) { threw = e; }
  check("build: refuses auto-generation when important=required",
        threw && threw.code === "mdn/auto-generation-refused");
}

async function testBuildAcceptsExplicitOverride() {
  // Same as above but operator explicitly opts out of the gate.
  var raw = b.mailMdn.build({
    originalMessageId:                "<m@x>",
    finalRecipient:                   "u@e.com",
    disposition:                      "displayed",
    dispositionNotificationOptions:   "important=required",
    requireUserConfirmation:          false,
  });
  check("build: explicit opt-out bypasses the gate",
        typeof raw === "string" && /Disposition:/.test(raw));
}

async function testBuildRejectsBadDisposition() {
  var threw = null;
  try {
    b.mailMdn.build({
      originalMessageId:       "<m@x>",
      finalRecipient:          "u@e.com",
      disposition:             "bogus",
      requireUserConfirmation: false,
    });
  } catch (e) { threw = e; }
  check("build: rejects bogus disposition",
        threw && threw.code === "mdn/missing-required-field");
}

async function testBuildRejectsMissingRecipient() {
  var threw = null;
  try {
    b.mailMdn.build({
      originalMessageId:       "<m@x>",
      disposition:             "displayed",
      requireUserConfirmation: false,
    });
  } catch (e) { threw = e; }
  check("build: rejects missing finalRecipient",
        threw && threw.code === "mdn/missing-required-field");
}

async function testBuildRejectsMissingMessageId() {
  var threw = null;
  try {
    b.mailMdn.build({
      finalRecipient:          "u@e.com",
      disposition:             "displayed",
      requireUserConfirmation: false,
    });
  } catch (e) { threw = e; }
  check("build: rejects missing originalMessageId",
        threw && threw.code === "mdn/missing-required-field");
}

async function testParseRoundtrip() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<orig-1@sender.example>",
    finalRecipient:          "user@example.com",
    originalRecipient:       "alias@example.com",
    disposition:             "displayed",
    reportingUserAgent:      "blamejs/0.8.53",
    requireUserConfirmation: false,
  });
  var p = b.mailMdn.parse(raw);
  check("parse: finalRecipient",         p.finalRecipient === "user@example.com");
  check("parse: originalRecipient",      p.originalRecipient === "alias@example.com");
  check("parse: originalMessageId",      p.originalMessageId === "<orig-1@sender.example>");
  check("parse: reportingUserAgent",     p.reportingUserAgent === "blamejs/0.8.53");
  check("parse: disposition.type",       p.disposition.type === "displayed");
  check("parse: disposition.actionMode", p.disposition.actionMode === "manual-action");
  check("parse: disposition.sendingMode", p.disposition.sendingMode === "mdn-sent-manually");
}

async function testParseAutomaticAction() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<m@x>",
    finalRecipient:          "u@e.com",
    disposition:             "processed",
    actionMode:              "automatic-action",
    sendingMode:             "MDN-sent-automatically",
    requireUserConfirmation: false,
  });
  var p = b.mailMdn.parse(raw);
  check("parse automatic: actionMode",  p.disposition.actionMode === "automatic-action");
  check("parse automatic: sendingMode", p.disposition.sendingMode === "mdn-sent-automatically");
  check("parse automatic: type",        p.disposition.type === "processed");
}

async function testParseRejectsNonReport() {
  var threw = null;
  try {
    b.mailMdn.parse("Content-Type: text/plain\r\n\r\nhello");
  } catch (e) { threw = e; }
  check("parse: rejects non-multipart/report",
        threw && threw.code === "mdn/parse-failed");
}

async function testParseRejectsEmpty() {
  var threw = null;
  try { b.mailMdn.parse(""); } catch (e) { threw = e; }
  check("parse: rejects empty input",
        threw && threw.code === "mdn/parse-failed");
}

async function testParseRejectsMissingFinalRecipient() {
  // Build a valid multipart/report frame but strip Final-Recipient.
  var bad = [
    'Content-Type: multipart/report; report-type=disposition-notification; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'x',
    '',
    '--b1',
    'Content-Type: message/disposition-notification',
    '',
    'Reporting-UA: blamejs',
    'Disposition: manual-action/MDN-sent-manually; displayed',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var threw = null;
  try { b.mailMdn.parse(bad); } catch (e) { threw = e; }
  check("parse: rejects missing Final-Recipient",
        threw && threw.code === "mdn/missing-required-field");
}

async function testParseRejectsBadDispositionToken() {
  var bad = [
    'Content-Type: multipart/report; report-type=disposition-notification; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'x',
    '',
    '--b1',
    'Content-Type: message/disposition-notification',
    '',
    'Final-Recipient: rfc822;u@e.com',
    'Disposition: manual-action/MDN-sent-manually; bogus',
    '',
    '--b1--',
    '',
  ].join('\r\n');
  var threw = null;
  try { b.mailMdn.parse(bad); } catch (e) { threw = e; }
  check("parse: rejects non-RFC3798 disposition type",
        threw && threw.code === "mdn/parse-failed");
}

async function testParseAttachedOriginalMessage() {
  var raw = b.mailMdn.build({
    originalMessageId:       "<m@x>",
    finalRecipient:          "u@e.com",
    disposition:             "displayed",
    originalMessage:         "From: sender@example.com\r\nSubject: original\r\n\r\nbody",
    requireUserConfirmation: false,
  });
  var p = b.mailMdn.parse(raw);
  check("parse: originalMessage carried through",
        typeof p.originalMessage === "string" &&
        /Subject: original/.test(p.originalMessage));
}

async function testAuditEmissionGenerated() {
  // The build() path emits a `mailmdn.generated` audit row when an MDN
  // is successfully constructed.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mdn-"));
  try {
    await setupTestDb(tmpDir);
    b.mailMdn.build({
      originalMessageId:       "<m@x>",
      finalRecipient:          "u@e.com",
      disposition:             "displayed",
      requireUserConfirmation: false,
    });
    await b.audit.flush();
    var rows = await b.audit.query({ action: "mailmdn.generated" });
    check("audit: mailmdn.generated row written", rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit: carries finalRecipient", meta.finalRecipient === "u@e.com");
    check("audit: carries disposition",    meta.disposition === "displayed");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditEmissionSuppressed() {
  // When auto-generation is refused, mailmdn.suppressed lands in the
  // audit chain (so operators see the refusal even though build() throws).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mdn-"));
  try {
    await setupTestDb(tmpDir);
    var threw = null;
    try {
      b.mailMdn.build({
        originalMessageId:               "<m@x>",
        finalRecipient:                  "u@e.com",
        disposition:                     "displayed",
        dispositionNotificationOptions:  "important=required",
      });
    } catch (e) { threw = e; }
    check("auto-refusal: build threw", threw !== null);
    await b.audit.flush();
    var rows = await b.audit.query({ action: "mailmdn.suppressed" });
    check("audit: mailmdn.suppressed row written", rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit: suppressed carries reason",
          typeof meta.reason === "string" && /auto-generation refused/.test(meta.reason));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSurface();
  await testBuildMinimal();
  await testBuildRejectsCrlfInjection();
  await testBuildAutomaticAction();
  await testBuildAttachesOriginalMessage();
  await testBuildRefusesAutoWhenImportantRequired();
  await testBuildAcceptsExplicitOverride();
  await testBuildRejectsBadDisposition();
  await testBuildRejectsMissingRecipient();
  await testBuildRejectsMissingMessageId();
  await testParseRoundtrip();
  await testParseAutomaticAction();
  await testParseRejectsNonReport();
  await testParseRejectsEmpty();
  await testParseRejectsMissingFinalRecipient();
  await testParseRejectsBadDispositionToken();
  await testParseAttachedOriginalMessage();
  await testAuditEmissionGenerated();
  await testAuditEmissionSuppressed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
