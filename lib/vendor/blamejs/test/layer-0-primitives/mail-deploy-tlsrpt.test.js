"use strict";
/**
 * b.mail.deploy TLS-RPT receiver — RFC 8460 aggregate-report ingest.
 * Covers parser §4.4 schema validation, gzip path, refusal classes,
 * HTTP handler status codes, idempotency posture, and bomb defenses.
 */

var nodeZlib = require("node:zlib");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function _goldenReport() {
  // RFC 8460 §B.1 golden-shape report.
  return {
    "organization-name": "Company-X",
    "contact-info":      "sts-reporting@company-x.example",
    "report-id":         "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
    "date-range":        {
      "start-datetime":  "2026-05-17T00:00:00Z",
      "end-datetime":    "2026-05-18T00:00:00Z",
    },
    "policies":          [{
      policy:  {
        "policy-type":    "sts",
        "policy-string":  ["version: STSv1", "mode: testing", "mx: *.mail.company-y.example", "max_age: 86400"],
        "policy-domain":  "company-y.example",
        "mx-host":        ["*.mail.company-y.example"],
      },
      summary: {
        "total-successful-session-count": 5326,
        "total-failure-session-count":    303,
      },
      "failure-details": [{
        "result-type":               "certificate-expired",
        "sending-mta-ip":            "2001:db8:abcd:0012::1",
        "receiving-mx-hostname":     "mx1.mail.company-y.example",
        "failed-session-count":      100,
      }, {
        "result-type":               "starttls-not-supported",
        "sending-mta-ip":            "2001:db8:abcd:0013::1",
        "receiving-mx-hostname":     "mx2.mail.company-y.example",
        "failed-session-count":      200,
      }],
    }],
  };
}

function _jsonBytes(obj)  { return Buffer.from(JSON.stringify(obj), "utf8"); }
function _gzipBytes(obj)  { return nodeZlib.gzipSync(_jsonBytes(obj)); }

function testGoldenReportParses() {
  var parsed = b.mail.deploy.parseTlsRptReport(_jsonBytes(_goldenReport()));
  check("golden parses: reporter",         parsed["organization-name"] === "Company-X");
  check("golden parses: report-id",        parsed["report-id"] === "5065427c-23d3-47ca-b6e0-946ea0e8c4be");
  check("golden parses: policy count",     parsed.policies.length === 1);
  check("golden parses: policy-domain",    parsed.policies[0].policy["policy-domain"] === "company-y.example");
  check("golden parses: success total",    parsed.sessionTotals.success === 5326);
  check("golden parses: failure total",    parsed.sessionTotals.failure === 303);
  check("golden parses: wasCompressed=false", parsed.wasCompressed === false);
}

function testGzipPath() {
  var parsed = b.mail.deploy.parseTlsRptReport(_gzipBytes(_goldenReport()));
  check("gzip-encoded report decompresses + parses",
    parsed["report-id"] === "5065427c-23d3-47ca-b6e0-946ea0e8c4be");
  check("gzip path marks wasCompressed=true", parsed.wasCompressed === true);
}

function testGzipContentTypeRouting() {
  // When opts.contentType names gzip, the parser tries gunzip even
  // without magic-byte detection (covers edge cases where bytes have
  // been chunked / re-buffered).
  var gz = _gzipBytes(_goldenReport());
  var parsed = b.mail.deploy.parseTlsRptReport(gz, { contentType: "application/tlsrpt+gzip" });
  check("explicit gzip content-type also works", parsed.wasCompressed === true);
}

function testRefusesNonBufferInput() {
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(12345); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-input"; }
  check("non-Buffer / non-string input refused", threw);
}

function testRefusesBadJson() {
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(Buffer.from("not json {")); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-json"; }
  check("malformed JSON refused", threw);
}

function testRefusesMissingRequiredField() {
  var r = _goldenReport();
  delete r["report-id"];
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r)); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-schema" && /report-id/.test(e.message); }
  check("missing report-id refused with bad-schema", threw);
}

function testRefusesPoliciesNotArray() {
  // RFC 8460 §4.4 erratum: policies MUST be an array, even for
  // single-policy reports. Bare-object form must refuse.
  var r = _goldenReport();
  r.policies = r.policies[0];
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r)); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-schema" && /must be an array/.test(e.message); }
  check("policies as bare object refused (RFC 8460 §4.4 erratum)", threw);
}

function testRefusesEmptyPolicies() {
  var r = _goldenReport();
  r.policies = [];
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r)); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-schema" && /non-empty/.test(e.message); }
  check("empty policies[] refused", threw);
}

function testRefusesBadPolicyType() {
  var r = _goldenReport();
  r.policies[0].policy["policy-type"] = "made-up";
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r)); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-policy" && /policy-type/.test(e.message); }
  check("unknown policy-type refused", threw);
}

function testRefusesOversizeCompressed() {
  // 5 MiB payload — exceeds 4 MiB default compressed cap.
  var big = Buffer.alloc(5 * 1024 * 1024, 0x20);
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(big); }
  catch (e) { threw = e.code === "mail-tlsrpt/oversize-compressed"; }
  check("oversize compressed refused at 4 MiB default cap", threw);
}

function testRefusesGunzipBomb() {
  // 1 KiB compressed → 100 MiB decompressed (over 32 MiB cap).
  var bomb = Buffer.alloc(100 * 1024 * 1024, 0x41);
  var compressed = nodeZlib.gzipSync(bomb);
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(compressed); }
  catch (e) { threw = (e.code === "mail-tlsrpt/gunzip-bomb" || e.code === "mail-tlsrpt/ratio-bomb"); }
  check("gunzip bomb refused (output > 32 MiB cap)", threw);
}

function testRefusesRatioBomb() {
  // 100 KiB of zeros compresses to ~100 bytes — ratio ~1000:1 > 50 default.
  var bigZeros = Buffer.alloc(100 * 1024, 0x00);
  var compressed = nodeZlib.gzipSync(bigZeros);
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(compressed); }
  catch (e) { threw = (e.code === "mail-tlsrpt/ratio-bomb" || e.code === "mail-tlsrpt/bad-json"); }
  check("ratio bomb refused (decompression ratio > 50:1)", threw);
}

function testSchemaShape() {
  var schema = b.mail.deploy.tlsRptReportSchema();
  check("schema names RFC 8460 §4.4",     schema.rfc === "RFC 8460 §4.4");
  check("schema lists required fields",   Array.isArray(schema.required) && schema.required.length === 5);
  check("schema names report-id required",schema.required.indexOf("report-id") !== -1);
  check("schema policyTypes complete",    schema.policyTypes.length === 3);
  check("schema resultTypes nonempty",    schema.resultTypes.length > 5);
}

function testHttpFactoryShape() {
  var handler = b.mail.deploy.tlsRptIngestHttp({});
  check("tlsRptIngestHttp returns a (req,res) function",
    typeof handler === "function" && handler.length === 2);
}

function testHttpRejectsNonPost() {
  var handler = b.mail.deploy.tlsRptIngestHttp({});
  var req = { method: "GET", headers: {}, on: function () {} };
  var status = 0, allow = null;
  var res = {
    writeHead: function (s, h) { status = s; allow = h && h["Allow"]; },
    end:       function () {},
    headersSent: false,
  };
  handler(req, res);
  check("HTTP GET → 405 Method Not Allowed", status === 405);
  check("HTTP GET → Allow: POST",            allow === "POST");
}

function testHttpRejectsBadMediaType() {
  var handler = b.mail.deploy.tlsRptIngestHttp({});
  var req = { method: "POST", headers: { "content-type": "application/xml" }, on: function () {} };
  var status = 0;
  var res = {
    writeHead: function (s) { status = s; },
    end:       function () {},
    headersSent: false,
  };
  handler(req, res);
  check("HTTP POST application/xml → 415", status === 415);
}

function testHttpHappyPath() {
  var got = null;
  var handler = b.mail.deploy.tlsRptIngestHttp({
    onAccept: function (report) { got = report; },
  });
  // Drive the handler via a fake req that emits data + end synchronously.
  var listeners = {};
  var req = {
    method: "POST",
    headers: { "content-type": "application/tlsrpt+json" },
    on: function (event, fn) { listeners[event] = fn; },
    destroy: function () {},
  };
  var status = 0, body = null;
  var res = {
    writeHead: function (s) { status = s; },
    end:       function (b) { body = b; },
    headersSent: false,
  };
  handler(req, res);
  listeners["data"](_jsonBytes(_goldenReport()));
  listeners["end"]();
  check("HTTP POST happy path → 201", status === 201);
  check("HTTP happy path invokes onAccept", got && got["report-id"] === "5065427c-23d3-47ca-b6e0-946ea0e8c4be");
  check("HTTP happy path response body names accept", body && body.indexOf("accepted") !== -1);
}

function testHttpRefusesUntrustedReporter() {
  var refused = null;
  var handler = b.mail.deploy.tlsRptIngestHttp({
    trustedReporters: ["only-this-org"],
    onRefuse:         function (code, _msg) { refused = code; },
  });
  var listeners = {};
  var req = {
    method: "POST",
    headers: { "content-type": "application/tlsrpt+json" },
    on: function (event, fn) { listeners[event] = fn; },
    destroy: function () {},
  };
  var status = 0;
  var res = { writeHead: function (s) { status = s; }, end: function () {}, headersSent: false };
  handler(req, res);
  listeners["data"](_jsonBytes(_goldenReport()));
  listeners["end"]();
  check("untrusted reporter → 403", status === 403);
  check("untrusted reporter → onRefuse called with mail-tlsrpt/untrusted-reporter",
    refused === "mail-tlsrpt/untrusted-reporter");
}

function testHttpRefusesOnSizeOverflow() {
  var refused = null;
  var handler = b.mail.deploy.tlsRptIngestHttp({
    maxCompressedBytes: 100,
    onRefuse:           function (code) { refused = code; },
  });
  var listeners = {};
  var req = {
    method: "POST",
    headers: { "content-type": "application/tlsrpt+json" },
    on: function (event, fn) { listeners[event] = fn; },
    destroy: function () {},
  };
  var status = 0;
  var res = { writeHead: function (s) { status = s; }, end: function () {}, headersSent: false };
  handler(req, res);
  listeners["data"](Buffer.alloc(150));
  // Verify status hits 413 before end() fires
  check("oversize body → 413", status === 413);
  check("oversize → onRefuse names mail-tlsrpt/oversize-compressed",
    refused === "mail-tlsrpt/oversize-compressed");
}

function testRefusesNonFiniteSummary() {
  // Codex P2 (v0.10.15) — Infinity / NaN / negative / string in
  // summary counts must refuse, not coerce silently.
  var r = _goldenReport();
  r.policies[0].summary["total-successful-session-count"] = "Infinity";
  var threw = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r)); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-summary"; }
  check("string 'Infinity' as summary count refused", threw);

  var r2 = _goldenReport();
  r2.policies[0].summary["total-failure-session-count"] = -5;
  var threw2 = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r2)); }
  catch (e) { threw2 = e.code === "mail-tlsrpt/bad-summary"; }
  check("negative summary count refused", threw2);

  var r3 = _goldenReport();
  r3.policies[0].summary["total-successful-session-count"] = 1.5;
  var threw3 = false;
  try { b.mail.deploy.parseTlsRptReport(_jsonBytes(r3)); }
  catch (e) { threw3 = e.code === "mail-tlsrpt/bad-summary"; }
  check("non-integer summary count refused", threw3);
}

function testHttpAuthenticateHookSyncFalsy() {
  // Codex P2 (v0.10.15) — authenticate(req) returns falsy → 401
  // before body parse.
  var refused = null;
  var handler = b.mail.deploy.tlsRptIngestHttp({
    authenticate: function (_req) { return false; },
    onRefuse:     function (code) { refused = code; },
  });
  var listeners = {};
  var req = {
    method:  "POST",
    headers: { "content-type": "application/tlsrpt+json" },
    on:      function (event, fn) { listeners[event] = fn; },
    destroy: function () {},
  };
  var status = 0;
  var res = { writeHead: function (s) { status = s; }, end: function () {}, headersSent: false };
  handler(req, res);
  // authenticate runs async via Promise.resolve — let it settle.
  return new Promise(function (resolve) { setImmediate(function () {
    check("authenticate falsy → 401", status === 401);
    check("authenticate falsy → onRefuse 'mail-tlsrpt/unauthenticated'",
      refused === "mail-tlsrpt/unauthenticated");
    resolve();
  }); });
}

function testHttpAuthenticateHookValidatesType() {
  var threw = false;
  try { b.mail.deploy.tlsRptIngestHttp({ authenticate: "not-a-function" }); }
  catch (e) { threw = e.code === "mail-tlsrpt/bad-opts"; }
  check("authenticate non-function refused at construct", threw);
}

function testTlsRptParseErrorClassExported() {
  check("b.mail.deploy.TlsRptParseError is a constructor",
    typeof b.mail.deploy.TlsRptParseError === "function");
}

async function run() {
  testGoldenReportParses();
  testGzipPath();
  testGzipContentTypeRouting();
  testRefusesNonBufferInput();
  testRefusesBadJson();
  testRefusesMissingRequiredField();
  testRefusesPoliciesNotArray();
  testRefusesEmptyPolicies();
  testRefusesBadPolicyType();
  testRefusesOversizeCompressed();
  testRefusesGunzipBomb();
  testRefusesRatioBomb();
  testSchemaShape();
  testHttpFactoryShape();
  testHttpRejectsNonPost();
  testHttpRejectsBadMediaType();
  testHttpHappyPath();
  testHttpRefusesUntrustedReporter();
  testHttpRefusesOnSizeOverflow();
  testRefusesNonFiniteSummary();
  await testHttpAuthenticateHookSyncFalsy();
  testHttpAuthenticateHookValidatesType();
  testTlsRptParseErrorClassExported();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
