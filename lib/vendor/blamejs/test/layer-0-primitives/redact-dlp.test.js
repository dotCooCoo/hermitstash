// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.redact.installOutboundDlp + b.redact.classifyDefaults — outbound
 * DLP scanner + interceptor wiring.
 *
 * Run standalone: `node test/layer-0-primitives/redact-dlp.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (event) { captured.push(event); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

function _fakeHttpClient() {
  var sent = [];
  return {
    sent:    sent,
    request: function (opts) {
      sent.push(opts);
      return Promise.resolve({ statusCode: 200, headers: {}, body: Buffer.from("ok") });
    },
  };
}

function _fakeMail() {
  var sent = [];
  return {
    sent: sent,
    send: function (msg) {
      sent.push(msg);
      return Promise.resolve({ accepted: true });
    },
  };
}

function _fakeWebhookSigner() {
  var sent = [];
  return {
    sent: sent,
    send: function (input) {
      sent.push(input);
      return Promise.resolve({ statusCode: 200 });
    },
  };
}

function testSurface() {
  check("b.redact.classifyDefaults is a function", typeof b.redact.classifyDefaults === "function");
  check("b.redact.installOutboundDlp is a function", typeof b.redact.installOutboundDlp === "function");
  check("b.redact.CLASSIFIER_PATTERNS frozen", Object.isFrozen(b.redact.CLASSIFIER_PATTERNS));
  check("CLASSIFIER_PATTERNS includes pan", typeof b.redact.CLASSIFIER_PATTERNS.pan === "object");
  check("CLASSIFIER_PATTERNS includes phi-shape", typeof b.redact.CLASSIFIER_PATTERNS["phi-shape"] === "object");
  check("DlpError class exposed", typeof b.redact.DlpError === "function");
}

function testClassifierRejectsBadOpts() {
  var threw;
  threw = false;
  try { b.redact.classifyDefaults({ patterns: [] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects empty patterns", threw);

  threw = false;
  try { b.redact.classifyDefaults({ patterns: ["nonexistent"] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects unknown pattern", threw);

  threw = false;
  try { b.redact.classifyDefaults({ patterns: [123] }); } catch (_e) { threw = true; }
  check("classifyDefaults rejects non-string pattern", threw);
}

function testClassifyPan() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan", "credit-card"] });
  // 4111-1111-1111-1111 is a valid Luhn-passing test PAN.
  var result = classify({ body: { card: "4111-1111-1111-1111" } });
  check("classify detects valid PAN", result.verdict === "refuse");
  check("classify hits include pan or credit-card",
    result.hits.some(function (h) { return h.label === "pan" || h.label === "credit-card"; }));

  var clean = classify({ body: { card: "4111-1111-1111-1112" } });  // bad luhn
  check("classify ignores invalid PAN", clean.verdict === "clean");
}

function testClassifySsn() {
  var classify = b.redact.classifyDefaults({ patterns: ["ssn"] });
  var result = classify({ body: { note: "patient ssn 123-45-6789 confirmed" } });
  check("classify detects SSN", result.verdict === "redact");
  check("classify redacted body scrubs SSN",
    String(result.redactedBody.note).indexOf("123-45-6789") === -1);
}

function testClassifyJwtAndAwsKey() {
  var classify = b.redact.classifyDefaults({ patterns: ["jwt", "aws-access-key"] });
  // Build a JWS-shaped token at runtime so no hard-coded literal lands
  // in source. The shape eyJ... . eyJ... . sig matches the detector.
  var jwt = ["eyJ", "ABCDef0_-", "."].join("") +
            ["eyJ", "QRSTuv1_-", "."].join("") +
            "signaturepart";
  // AWS access-key shape: AKIA + 16 [A-Z0-9].
  var aws = "AKIA" + "BCDEFGHIJKLMNOPQ";
  check("classify flags JWT", classify({ body: { tok: jwt } }).verdict === "redact");
  check("classify flags AWS access key", classify({ body: { secret: aws } }).verdict === "refuse");
}

function testClassifyHeaders() {
  var classify = b.redact.classifyDefaults({ patterns: ["pan"] });
  var r = classify({ body: { ok: true }, headers: { "x-card-number": "4111-1111-1111-1111" } });
  check("classify scans headers", r.verdict === "refuse");
  check("classify hit reports header location",
    r.hits.some(function (h) { return h.where && h.where.indexOf("headers.") === 0; }));
}

async function testInstallHttpClientRefuse() {
  var client = _fakeHttpClient();
  var auditMock = _captureAudit();
  // Patch global audit to capture (the redact module uses lazyRequire(audit)).
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { auditMock.captured.push(e); };

  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  check("install registers httpClient", handle.installed.httpClient === true);

  var threw = false;
  try {
    await client.request({ url: "https://example.com/x", body: { card: "4111111111111111" } });
  } catch (e) { threw = e; }
  b.audit.safeEmit = origAudit;
  check("httpClient.request refuses on PAN", threw && threw.code === "redact-dlp/refused");
  check("audit emitted dlp.outbound.refused",
    auditMock.captured.some(function (e) { return e.action === "dlp.outbound.refused"; }));
  check("audit emitted dlp.outbound.installed",
    auditMock.captured.some(function (e) { return e.action === "dlp.outbound.installed"; }));
  handle.uninstall();
  // After uninstall, the request should pass through.
  await client.request({ url: "https://example.com/x", body: { card: "4111111111111111" } });
  check("after uninstall, request passes through", client.sent.length === 1);
}

async function testInstallHttpClientRedact() {
  var client = _fakeHttpClient();
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    classifier: b.redact.classifyDefaults({ patterns: ["ssn"] }),
  });
  await client.request({ url: "https://example.com/x", body: { note: "ssn 123-45-6789" } });
  check("redacted body sent to httpClient", client.sent.length === 1);
  var sentBody = client.sent[0].body;
  check("sent body scrubs SSN",
    JSON.stringify(sentBody).indexOf("123-45-6789") === -1);
  handle.uninstall();
}

async function testInstallMail() {
  var mail = _fakeMail();
  var handle = b.redact.installOutboundDlp({
    mail: mail,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  var threw = false;
  try {
    await mail.send({ to: "x@y", subject: "card", text: "use 4111-1111-1111-1111", html: "<p>4111-1111-1111-1111</p>" });
  } catch (e) { threw = e; }
  check("mail.send refuses on PAN", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();
}

async function testInstallWebhook() {
  var signer = _fakeWebhookSigner();
  var handle = b.redact.installOutboundDlp({
    webhook: signer,
    classifier: b.redact.classifyDefaults({ patterns: ["pan"] }),
  });
  var threw = false;
  try {
    await signer.send({ url: "https://example.com/hook", body: JSON.stringify({ card: "4111-1111-1111-1111" }) });
  } catch (e) { threw = e; }
  check("webhook.send refuses on PAN in JSON body", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();
}

async function testPostureWiring() {
  var client = _fakeHttpClient();
  var handle = b.redact.installOutboundDlp({
    httpClient: client,
    posture: "pci-dss",
  });
  check("posture install succeeds", handle.installed.httpClient === true);
  var threw = false;
  try { await client.request({ url: "https://x", body: { card: "4111111111111111" } }); }
  catch (e) { threw = e; }
  check("pci-dss posture refuses PAN", threw && threw.code === "redact-dlp/refused");
  handle.uninstall();

  var threwUnknown = false;
  try { b.redact.installOutboundDlp({ httpClient: _fakeHttpClient(), posture: "no-such" }); }
  catch (_e) { threwUnknown = true; }
  check("unknown posture rejected", threwUnknown);
}

async function testIdempotentInstall() {
  var client = _fakeHttpClient();
  var h1 = b.redact.installOutboundDlp({ httpClient: client, posture: "pci-dss" });
  var h2 = b.redact.installOutboundDlp({ httpClient: client, posture: "pci-dss" });
  check("second install on same instance no-ops",
    h1.installed.httpClient === true && h2.installed.httpClient === false);
  h1.uninstall();
}

// Bug A — installForPosture is NOT auto-called by b.compliance.set; the
// install tracking + the boot warning replace the false advertisement.
function testIsOutboundDlpInstalledSurface() {
  b.redact._resetForTest();
  check("b.redact.isOutboundDlpInstalled is a function",
    typeof b.redact.isOutboundDlpInstalled === "function");
  check("isOutboundDlpInstalled false before any install",
    b.redact.isOutboundDlpInstalled() === false);
  var http = _fakeHttpClient();
  var dlp = b.redact.installForPosture("hipaa", { httpClient: http });
  check("isOutboundDlpInstalled true after installForPosture",
    b.redact.isOutboundDlpInstalled() === true);
  dlp.uninstall();
  check("isOutboundDlpInstalled false after uninstall",
    b.redact.isOutboundDlpInstalled() === false);
}

function testComplianceSetWarnsWhenDlpUnwired() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.compliance.set("hipaa");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('hipaa') warns when no outbound DLP wired",
    warns.length === 1 && warns[0].outcome === "warning" && warns[0].metadata.posture === "hipaa");
  b.compliance._resetForTest();
}

function testComplianceSetNoWarnWhenDlpWired() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  // Wire DLP first, then pin the posture — set() must NOT warn.
  var http = _fakeHttpClient();
  var dlp = b.redact.installForPosture("pci-dss", { httpClient: http });
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    b.compliance.set("pci-dss");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('pci-dss') does not warn when DLP wired",
    warns.length === 0);
  dlp.uninstall();
  b.compliance._resetForTest();
}

function testComplianceSetNoWarnForNonDlpPosture() {
  b.compliance._resetForTest();
  b.redact._resetForTest();
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  try {
    // sox is regulated but has no outbound-DLP classifier preset.
    b.compliance.set("sox");
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "compliance.posture.outbound_dlp_unwired";
  });
  check("compliance.set('sox') (non-DLP-floor posture) does not warn",
    warns.length === 0);
  b.compliance._resetForTest();
}

async function run() {
  testSurface();
  testClassifierRejectsBadOpts();
  testClassifyPan();
  testClassifySsn();
  testClassifyJwtAndAwsKey();
  testClassifyHeaders();
  await testInstallHttpClientRefuse();
  await testInstallHttpClientRedact();
  await testInstallMail();
  await testInstallWebhook();
  await testPostureWiring();
  await testIdempotentInstall();
  testIsOutboundDlpInstalledSurface();
  testComplianceSetWarnsWhenDlpUnwired();
  testComplianceSetNoWarnWhenDlpWired();
  testComplianceSetNoWarnForNonDlpPosture();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK redact-dlp — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };
