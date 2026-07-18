// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var zlib       = require("node:zlib");
var EventEmitter = require("events");

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyReq  = helpers._bodyReq;
var _bodyRes  = helpers._bodyRes;
var waitUntil = helpers.waitUntil;

// ---- shared negative-test helpers ----

function _expectPrefix(label, fn, prefix) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(prefix) === 0);
}

function _expectCode(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && threw.code === code);
}

// ---- fixtures ----

// A canonical RFC 8460 §4.4 aggregate report the parser accepts. Tests
// clone + mutate this to drive individual schema-rejection branches.
function _validReport() {
  return {
    "organization-name": "Reporter Inc",
    "contact-info":      "postmaster@reporter.example",
    "report-id":         "2026-07-11T00:00:00Z_example.com",
    "date-range": {
      "start-datetime": "2026-07-10T00:00:00Z",
      "end-datetime":   "2026-07-11T00:00:00Z",
    },
    "policies": [
      {
        "policy": {
          "policy-type":   "sts",
          "policy-domain": "example.com",
          "policy-string": ["version: STSv1", "mode: enforce"],
          "mx-host":       ["mx1.example.com"],
        },
        "summary": {
          "total-successful-session-count": 100,
          "total-failure-session-count":    2,
        },
        "failure-details": [
          { "result-type": "certificate-expired", "failed-session-count": 2 },
        ],
      },
    ],
  };
}

function _reportWithPolicies(policies) {
  var r = _validReport();
  r.policies = policies;
  return r;
}

// Mint a real RSA self-signed cert + matching key PEM via the vendored
// pki bundle (node:crypto exposes no cert generator). Lets the DANE
// generator exercise its real SPKI / full-DER hash path instead of only
// the input-validation guards.
async function _makeSelfSignedCert() {
  var pki  = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(
    { name:           "RSASSA-PKCS1-v1_5",
      modulusLength:  2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash:           "SHA-256" },
    true, ["sign", "verify"]);
  var now  = new Date();
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=mx1.example.com",
    notBefore:        now,
    notAfter:         new Date(now.getTime() + 7 * 86400000),
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys:             keys,
  });
  return cert.toString("pem");
}

// ---- existing surface / happy-path coverage ----

function testSurface() {
  check("b.mail.deploy.mtaStsPublish",     typeof b.mail.deploy.mtaStsPublish     === "function");
  check("b.mail.deploy.danePublish",       typeof b.mail.deploy.danePublish       === "function");
  check("b.mail.deploy.autoConfigXml",     typeof b.mail.deploy.autoConfigXml     === "function");
  check("b.mail.deploy.autoDiscoverXml",   typeof b.mail.deploy.autoDiscoverXml   === "function");
  check("b.mail.deploy.parseTlsRptReport", typeof b.mail.deploy.parseTlsRptReport === "function");
  check("b.mail.deploy.tlsRptReportSchema", typeof b.mail.deploy.tlsRptReportSchema === "function");
  check("b.mail.deploy.tlsRptIngestHttp",  typeof b.mail.deploy.tlsRptIngestHttp  === "function");
}

function testMtaStsHappy() {
  var rv = b.mail.deploy.mtaStsPublish({
    domain:    "example.com",
    mode:      "enforce",
    mxHosts:   ["mx1.example.com", "*.mx.example.com"],
    maxAgeSec: 604800,
  });
  check("mta-sts policy starts with version line",
    /^version: STSv1\r\n/.test(rv.policyText));
  check("mta-sts mode embedded",  rv.policyText.indexOf("mode: enforce") !== -1);
  check("mta-sts wildcard mx preserved",
    rv.policyText.indexOf("mx: *.mx.example.com") !== -1);
  check("mta-sts policyPath canonical",
    rv.policyPath === "/.well-known/mta-sts.txt");
  check("mta-sts dnsTxtName carries _mta-sts prefix",
    rv.dnsTxtName === "_mta-sts.example.com");
  check("mta-sts TXT record carries STSv1 + id",
    /^v=STSv1; id=[A-Za-z0-9_-]+;$/.test(rv.dnsTxtRecord));
}

// Operator-supplied policyId (valid token shape) is embedded verbatim
// rather than replaced by the ISO-timestamp default.
function testMtaStsExplicitPolicyId() {
  var rv = b.mail.deploy.mtaStsPublish({
    domain:    "example.com",
    mode:      "testing",
    mxHosts:   ["mx1.example.com"],
    maxAgeSec: 86400,
    policyId:  "policy-2026-07",
  });
  check("mta-sts honours explicit policyId", rv.policyId === "policy-2026-07");
  check("mta-sts TXT record carries explicit id",
    rv.dnsTxtRecord === "v=STSv1; id=policy-2026-07;");
}

function testMtaStsBadInput() {
  _expectPrefix("refuses bad domain",       function () { b.mail.deploy.mtaStsPublish({ domain: "", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100 }); }, "mail-deploy/");
  _expectPrefix("refuses bad mode",         function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "fake", mxHosts: ["x.com"], maxAgeSec: 100 }); }, "mail-deploy/");
  _expectPrefix("refuses empty mx list",    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: [], maxAgeSec: 100 }); }, "mail-deploy/");
  _expectPrefix("refuses max-age > 1 year", function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 99999999 }); }, "mail-deploy/");
  _expectPrefix("refuses CR in domain",     function () { b.mail.deploy.mtaStsPublish({ domain: "x.com\r\nFAKE", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100 }); }, "mail-deploy/");
  _expectPrefix("refuses bad policyId",     function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100, policyId: "with space" }); }, "mail-deploy/");
}

// The mxHosts array + per-entry validation branches: non-array, cap,
// wrong element type, over-length entry, wildcard whose bare host is
// invalid, and a non-integer maxAgeSec.
function testMtaStsMxAndMaxAgeBranches() {
  var big = [];
  for (var i = 0; i < 65; i++) big.push("mx" + i + ".example.com");
  _expectCode("refuses mxHosts over 64-entry cap",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: big, maxAgeSec: 100 }); },
    "mail-deploy/bad-mx");
  _expectCode("refuses non-string mx entry",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: [123], maxAgeSec: 100 }); },
    "mail-deploy/bad-mx");
  _expectCode("refuses over-length mx entry",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["a".repeat(254)], maxAgeSec: 100 }); },
    "mail-deploy/bad-mx");
  _expectCode("refuses wildcard mx whose bare host is invalid",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["*.bad\r\nhost.com"], maxAgeSec: 100 }); },
    "mail-deploy/bad-mx");
  _expectCode("refuses non-integer maxAgeSec",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["mx.x.com"], maxAgeSec: 1.5 }); },
    "mail-deploy/bad-max-age");
  _expectCode("refuses negative maxAgeSec",
    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["mx.x.com"], maxAgeSec: -1 }); },
    "mail-deploy/bad-max-age");
  _expectCode("refuses non-object opts",
    function () { b.mail.deploy.mtaStsPublish("nope"); },
    "mail-deploy/bad-opts");
}

// ---- DANE ----

function testAutoConfigHappy() {
  var xml = b.mail.deploy.autoConfigXml({
    domain:      "example.com",
    displayName: "Example Mail",
    imap:        { host: "imap.example.com", port: 993, socketType: "SSL" },
    smtp:        { host: "smtp.example.com", port: 587, socketType: "STARTTLS" },
  });
  check("autoconfig declares XML prolog", xml.indexOf("<?xml") === 0);
  check("autoconfig carries imap host",   xml.indexOf("<hostname>imap.example.com</hostname>") !== -1);
  check("autoconfig carries smtp STARTTLS", xml.indexOf("<socketType>STARTTLS</socketType>") !== -1);
  check("autoconfig carries displayName", xml.indexOf("<displayName>Example Mail</displayName>") !== -1);
}

// socketType "plain" + explicit username exercise the non-default
// socket-type and custom-username branches of the _server builder.
function testAutoConfigPlainSocketAndUsername() {
  var xml = b.mail.deploy.autoConfigXml({
    domain: "example.com",
    imap:   { host: "imap.example.com", port: 143, socketType: "plain", username: "alice" },
  });
  check("autoconfig honours socketType=plain",
    xml.indexOf("<socketType>plain</socketType>") !== -1);
  check("autoconfig embeds explicit username",
    xml.indexOf("<username>alice</username>") !== -1);
}

function testAutoConfigEscape() {
  var xml = b.mail.deploy.autoConfigXml({
    domain:      "example.com",
    displayName: "<bad>&\"'</bad>",
    imap:        { host: "imap.example.com", port: 993 },
  });
  check("autoconfig escapes XML metachars",
    xml.indexOf("<displayName>&lt;bad&gt;&amp;&quot;&apos;&lt;/bad&gt;</displayName>") !== -1);
}

function testAutoConfigProtocolTypeAttr() {
  var xml = b.mail.deploy.autoConfigXml({
    domain: "example.com",
    imap:   { host: "imap.example.com", port: 993 },
    pop3:   { host: "pop3.example.com", port: 995 },
    smtp:   { host: "smtp.example.com", port: 587, socketType: "STARTTLS" },
  });
  check("autoconfig incomingServer type=imap",
    xml.indexOf("<incomingServer type=\"imap\">") !== -1);
  check("autoconfig incomingServer type=pop3",
    xml.indexOf("<incomingServer type=\"pop3\">") !== -1);
  check("autoconfig outgoingServer type=smtp",
    xml.indexOf("<outgoingServer type=\"smtp\">") !== -1);
}

function testAutoConfigJmap() {
  var xml = b.mail.deploy.autoConfigXml({
    domain: "example.com",
    jmap:   { url: "https://jmap.example.com/.well-known/jmap" },
  });
  check("autoconfig JMAP-only succeeds + emits incomingServer type=jmap",
    xml.indexOf("<incomingServer type=\"jmap\">") !== -1);
  check("autoconfig JMAP URL embedded",
    xml.indexOf("<url>https://jmap.example.com/.well-known/jmap</url>") !== -1);
  _expectCode("autoconfig refuses CR/LF in jmap URL",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", jmap: { url: "bad\r\nurl" } }); },
    "mail-deploy/bad-jmap-url");
}

function testAutoConfigBadInput() {
  _expectPrefix("refuses no incoming server",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com" }); }, "mail-deploy/");
  _expectPrefix("refuses bad imap host",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", imap: { host: "", port: 993 } }); }, "mail-deploy/");
  _expectPrefix("refuses bad imap port",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", imap: { host: "x.com", port: 99999 } }); }, "mail-deploy/");
}

// Bad top-level domain, over-length displayName, and the two remaining
// jmap-url rejection shapes (empty string, over-length).
function testAutoConfigMoreBranches() {
  _expectCode("autoconfig refuses bad top-level domain",
    function () { b.mail.deploy.autoConfigXml({ domain: "bad\r\ndomain", imap: { host: "x.com", port: 1 } }); },
    "mail-deploy/bad-domain");
  _expectCode("autoconfig refuses over-length displayName",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", displayName: "d".repeat(257), imap: { host: "x.com", port: 1 } }); },
    "mail-deploy/bad-displayName");
  _expectCode("autoconfig refuses empty jmap url",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", jmap: { url: "" } }); },
    "mail-deploy/bad-jmap-url");
  _expectCode("autoconfig refuses over-length jmap url",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", jmap: { url: "https://x/" + "a".repeat(1024) } }); },
    "mail-deploy/bad-jmap-url");
}

function testAutoDiscoverHappy() {
  var xml = b.mail.deploy.autoDiscoverXml({
    email: "alice@example.com",
    imap:  { host: "imap.example.com", port: 993, ssl: true },
    smtp:  { host: "smtp.example.com", port: 587, ssl: false },
  });
  check("autodiscover declares Microsoft schema",
    xml.indexOf("xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"") !== -1);
  check("autodiscover carries IMAP proto", xml.indexOf("<Type>IMAP</Type>") !== -1);
  check("autodiscover carries SMTP proto", xml.indexOf("<Type>SMTP</Type>") !== -1);
  check("autodiscover SSL on / off mapping",
    xml.indexOf("<SSL>on</SSL>") !== -1 && xml.indexOf("<SSL>off</SSL>") !== -1);
}

// POP3 protocol block + the per-proto host/port rejection branches, plus
// the email length/type guard (distinct from the control-byte scanner).
function testAutoDiscoverMoreBranches() {
  var xml = b.mail.deploy.autoDiscoverXml({
    email: "bob@example.com",
    pop3:  { host: "pop3.example.com", port: 995, ssl: true },
  });
  check("autodiscover emits POP3 proto block", xml.indexOf("<Type>POP3</Type>") !== -1);

  _expectCode("autodiscover refuses missing email",
    function () { b.mail.deploy.autoDiscoverXml({ imap: { host: "x.com", port: 1 } }); },
    "mail-deploy/bad-email");
  _expectCode("autodiscover refuses over-length email",
    function () { b.mail.deploy.autoDiscoverXml({ email: "a".repeat(255) + "@x.com", imap: { host: "x.com", port: 1 } }); },
    "mail-deploy/bad-email");
  _expectCode("autodiscover refuses bad proto host",
    function () { b.mail.deploy.autoDiscoverXml({ email: "a@x.com", imap: { host: "", port: 1 } }); },
    "mail-deploy/bad-host");
  _expectCode("autodiscover refuses bad proto port",
    function () { b.mail.deploy.autoDiscoverXml({ email: "a@x.com", imap: { host: "x.com", port: 99999 } }); },
    "mail-deploy/bad-port");
}

function testAutoDiscoverXmlInjection() {
  _expectPrefix("refuses CR/LF in email",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com\r\n<inject/>", imap: { host: "x.com", port: 1 } }); }, "mail-deploy/");
  _expectPrefix("refuses NUL in email",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com\x00", imap: { host: "x.com", port: 1 } }); }, "mail-deploy/");
  _expectPrefix("refuses missing protos",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com" }); }, "mail-deploy/");
}

// Input-validation guards that gate BEFORE the cert parse: too-large PEM,
// bad mxHost, out-of-range port, and each RFC 6698 code enum.
function testDanePublishInputGuards() {
  _expectCode("danePublish refuses bad pem",
    function () { b.mail.deploy.danePublish({ certPem: "not a pem", mxHost: "mx.x.com" }); }, "mail-deploy/bad-cert");
  _expectCode("danePublish refuses empty pem",
    function () { b.mail.deploy.danePublish({ certPem: "", mxHost: "mx.x.com" }); }, "mail-deploy/bad-cert");
  _expectCode("danePublish refuses over-size pem",
    function () { b.mail.deploy.danePublish({ certPem: "x".repeat(65537), mxHost: "mx.x.com" }); }, "mail-deploy/bad-cert");
  _expectCode("danePublish refuses bad mxHost",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "bad\r\nhost" }); }, "mail-deploy/bad-mx-host");
  _expectCode("danePublish refuses out-of-range port",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "mx.x.com", port: 70000 }); }, "mail-deploy/bad-port");
  _expectCode("danePublish refuses bad usage",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "mx.x.com", usage: 7 }); }, "mail-deploy/bad-usage");
  _expectCode("danePublish refuses bad selector",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "mx.x.com", selector: 5 }); }, "mail-deploy/bad-selector");
  _expectCode("danePublish refuses bad matchType",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "mx.x.com", matchType: 0 }); }, "mail-deploy/bad-match-type");
}

// Real-cert deep path — SPKI (selector 1) SHA-256 default AND full-DER
// (selector 0) SHA-512 with a non-default usage + port.
async function testDanePublishDeepHash() {
  var certPem = await _makeSelfSignedCert();
  var rv1 = b.mail.deploy.danePublish({ certPem: certPem, mxHost: "mx1.example.com" });
  check("dane default record is DANE-EE / SPKI / SHA-256", /^3 1 1 [0-9a-f]{64}$/.test(rv1.record));
  check("dane dnsName defaults to port 25", rv1.dnsName === "_25._tcp.mx1.example.com");
  check("dane zoneLine composes name + TLSA record",
    rv1.zoneLine === "_25._tcp.mx1.example.com. IN TLSA " + rv1.record);

  var rv0 = b.mail.deploy.danePublish({
    certPem: certPem, mxHost: "mx1.example.com",
    selector: 0, matchType: 2, usage: 2, port: 465,
  });
  check("dane full-DER / SHA-512 record", /^2 0 2 [0-9a-f]{128}$/.test(rv0.record));
  check("dane honours explicit port in dnsName", rv0.dnsName === "_465._tcp.mx1.example.com");
  check("dane echoes usage/selector/matchType",
    rv0.usage === 2 && rv0.selector === 0 && rv0.matchType === 2);
}

// ---- TLS-RPT parser ----

function testTlsRptHappy() {
  var rv = b.mail.deploy.parseTlsRptReport(JSON.stringify(_validReport()));
  check("tlsrpt parse returns organization-name", rv["organization-name"] === "Reporter Inc");
  check("tlsrpt parse sums session totals", rv.sessionTotals.success === 100 && rv.sessionTotals.failure === 2);
  check("tlsrpt parse marks uncompressed", rv.wasCompressed === false);
  check("tlsrpt parse preserves policies array", Array.isArray(rv.policies) && rv.policies.length === 1);

  // Buffer input path + typed-error class identity.
  var rvBuf = b.mail.deploy.parseTlsRptReport(Buffer.from(JSON.stringify(_validReport())));
  check("tlsrpt parse accepts Buffer input", rvBuf["report-id"] === "2026-07-11T00:00:00Z_example.com");

  var threw = null;
  try { b.mail.deploy.parseTlsRptReport(42); } catch (e) { threw = e; }
  check("tlsrpt bad-input throws TlsRptParseError",
    threw instanceof b.mail.deploy.TlsRptParseError && threw.code === "mail-tlsrpt/bad-input");
}

function testTlsRptOptsAndSize() {
  _expectCode("tlsrpt refuses bad opts (negative maxRatio)",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_validReport()), { maxRatio: -1 }); },
    "mail-tlsrpt/bad-opts");
  _expectCode("tlsrpt refuses oversize compressed payload",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_validReport()), { maxCompressedBytes: 4 }); },
    "mail-tlsrpt/oversize-compressed");
  _expectCode("tlsrpt refuses malformed JSON",
    function () { b.mail.deploy.parseTlsRptReport("{not json"); },
    "mail-tlsrpt/bad-json");
}

function testTlsRptGzipBranches() {
  var gz = zlib.gzipSync(Buffer.from(JSON.stringify(_validReport())));
  var rv = b.mail.deploy.parseTlsRptReport(gz, { contentType: "application/tlsrpt+gzip" });
  check("tlsrpt gzip auto-detect marks compressed", rv.wasCompressed === true);
  check("tlsrpt gzip decodes report body", rv["organization-name"] === "Reporter Inc");

  var gzBig = zlib.gzipSync(Buffer.from("x".repeat(50000)));
  _expectCode("tlsrpt refuses gunzip bomb (decompressed cap)",
    function () { b.mail.deploy.parseTlsRptReport(gzBig, { maxDecompressedBytes: 100 }); },
    "mail-tlsrpt/gunzip-bomb");
  _expectCode("tlsrpt refuses ratio bomb",
    function () { b.mail.deploy.parseTlsRptReport(gzBig, { maxRatio: 2 }); },
    "mail-tlsrpt/ratio-bomb");
  _expectCode("tlsrpt refuses malformed gzip",
    function () { b.mail.deploy.parseTlsRptReport(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef])); },
    "mail-tlsrpt/gunzip-failed");
}

function testTlsRptSchemaRejections() {
  _expectCode("tlsrpt refuses non-object top level",
    function () { b.mail.deploy.parseTlsRptReport("[]"); }, "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses missing organization-name",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify({ "contact-info": "x", "report-id": "y", "date-range": { "start-datetime": "a", "end-datetime": "b" }, "policies": [] })); },
    "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses missing contact-info", function () {
    var r = _validReport(); delete r["contact-info"];
    b.mail.deploy.parseTlsRptReport(JSON.stringify(r));
  }, "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses missing report-id", function () {
    var r = _validReport(); delete r["report-id"];
    b.mail.deploy.parseTlsRptReport(JSON.stringify(r));
  }, "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses malformed date-range", function () {
    var r = _validReport(); r["date-range"] = { "start-datetime": "a" };
    b.mail.deploy.parseTlsRptReport(JSON.stringify(r));
  }, "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses non-array policies", function () {
    var r = _validReport(); r.policies = { "policy-type": "sts" };
    b.mail.deploy.parseTlsRptReport(JSON.stringify(r));
  }, "mail-tlsrpt/bad-schema");
  _expectCode("tlsrpt refuses empty policies array",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([]))); },
    "mail-tlsrpt/bad-schema");

  var many = [];
  for (var i = 0; i < 1001; i++) many.push({ policy: { "policy-type": "sts", "policy-domain": "e" + i + ".example" } });
  _expectCode("tlsrpt refuses too many policies",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies(many))); },
    "mail-tlsrpt/too-many-policies");
}

function testTlsRptPolicyRejections() {
  _expectCode("tlsrpt refuses non-object policy entry",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([null]))); },
    "mail-tlsrpt/bad-policy");
  _expectCode("tlsrpt refuses policy missing .policy",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{}]))); },
    "mail-tlsrpt/bad-policy");
  // Prototype-shadowing: an inherited member name must NOT resolve as a
  // valid policy-type through the plain-object allowlist.
  _expectCode("tlsrpt refuses prototype-shadowed policy-type",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "constructor", "policy-domain": "x" } }]))); },
    "mail-tlsrpt/bad-policy");
  _expectCode("tlsrpt refuses out-of-vocabulary policy-type",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "made-up", "policy-domain": "x" } }]))); },
    "mail-tlsrpt/bad-policy");
  _expectCode("tlsrpt refuses policy missing policy-domain",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "tlsa" } }]))); },
    "mail-tlsrpt/bad-policy");
  _expectCode("tlsrpt refuses non-integer success count",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "sts", "policy-domain": "x" }, summary: { "total-successful-session-count": -5 } }]))); },
    "mail-tlsrpt/bad-summary");
  _expectCode("tlsrpt refuses non-integer failure count",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "sts", "policy-domain": "x" }, summary: { "total-failure-session-count": "lots" } }]))); },
    "mail-tlsrpt/bad-summary");
  _expectCode("tlsrpt refuses non-array failure-details",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "sts", "policy-domain": "x" }, "failure-details": {} }]))); },
    "mail-tlsrpt/bad-policy");
  _expectCode("tlsrpt refuses non-object failure-detail entry",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "sts", "policy-domain": "x" }, "failure-details": [null] }]))); },
    "mail-tlsrpt/bad-failure-detail");

  // Per-policy failure-details cardinality cap (10000).
  var fds = [];
  for (var f = 0; f < 10001; f++) fds.push({ "result-type": "validation-failure" });
  _expectCode("tlsrpt refuses over-cap failure-details",
    function () { b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([{ policy: { "policy-type": "sts", "policy-domain": "x" }, "failure-details": fds }]))); },
    "mail-tlsrpt/too-many-failures");

  // Unknown result-type is tolerated (IANA registry can grow) — surfaced,
  // not refused.
  var rv = b.mail.deploy.parseTlsRptReport(JSON.stringify(_reportWithPolicies([
    { policy: { "policy-type": "no-policy-found", "policy-domain": "x" },
      "failure-details": [{ "result-type": "future-iana-type" }] },
  ])));
  check("tlsrpt tolerates unknown result-type", rv.policies.length === 1);
}

function testTlsRptSchemaDescriptor() {
  var schema = b.mail.deploy.tlsRptReportSchema();
  check("tlsrpt schema names RFC 8460 §4.4", schema.rfc === "RFC 8460 §4.4");
  check("tlsrpt schema requires report-id", schema.required.indexOf("report-id") !== -1);
  check("tlsrpt schema lists policy field descriptors", typeof schema.policyFields.policy === "object");
  check("tlsrpt schema enumerates policy types", schema.policyTypes.indexOf("sts") !== -1);
  check("tlsrpt schema enumerates result types", schema.resultTypes.indexOf("certificate-expired") !== -1);
}

// ---- TLS-RPT HTTP ingest handler ----

var _CT_JSON = "application/tlsrpt+json";

// Drive a handler with a mock req/res pair and resolve once the response
// has been written. Polls res.statusCode rather than sleeping.
function _driveIngest(handler, req, res) {
  handler(req, res);
  return waitUntil(function () { return res.statusCode !== null; }, {
    timeoutMs: 4000,
    label:     "tlsRptIngestHttp: response written",
  }).then(function () { return res; });
}

// An onRefuse hook that records the code then throws — every refusal
// path wraps the operator hook in try/catch and must stay drop-silent
// (a buggy hook must not change the response the peer receives).
function _throwingRefuse(sink) {
  return function (code) { sink.push(code); throw new Error("onRefuse hook bug"); };
}

function testTlsRptIngestOptsValidation() {
  _expectCode("ingest refuses non-function authenticate",
    function () { b.mail.deploy.tlsRptIngestHttp({ authenticate: 5 }); }, "mail-tlsrpt/bad-opts");
  _expectCode("ingest refuses non-string trustedReporters entry",
    function () { b.mail.deploy.tlsRptIngestHttp({ trustedReporters: [5] }); }, "mail-tlsrpt/bad-opts");
  _expectCode("ingest refuses non-integer maxCompressedBytes",
    function () { b.mail.deploy.tlsRptIngestHttp({ maxCompressedBytes: -1 }); }, "mail-tlsrpt/bad-opts");
  // Zero-arg construction defaults opts to {} and returns a usable handler.
  check("ingest builds a handler with no opts",
    typeof b.mail.deploy.tlsRptIngestHttp() === "function");
}

async function testTlsRptIngestMethodAndContentType() {
  var refusals = [];
  // A deliberately-throwing hook: the 415 refusal must still be written.
  var handler = b.mail.deploy.tlsRptIngestHttp({ onRefuse: _throwingRefuse(refusals) });

  var res405 = await _driveIngest(handler, _bodyReq("GET", { "content-type": _CT_JSON }, ""), _bodyRes());
  check("ingest non-POST returns 405", res405.statusCode === 405);
  check("ingest 405 advertises Allow: POST", res405._headers.Allow === "POST");

  var res415 = await _driveIngest(handler, _bodyReq("POST", { "content-type": "text/plain" }, "x"), _bodyRes());
  check("ingest bad content-type returns 415 despite throwing onRefuse", res415.statusCode === 415);
  check("ingest 415 advertises Accept media types",
    (res415._headers.Accept || "").indexOf("application/tlsrpt+json") !== -1);
  check("ingest 415 fires onRefuse with typed code",
    refusals.indexOf("mail-tlsrpt/bad-content-type") !== -1);

  // A POST with NO content-type header falls into the same 415 path (the
  // header defaults to "").
  var resNoCt = await _driveIngest(handler, _bodyReq("POST", {}, "x"), _bodyRes());
  check("ingest missing content-type returns 415", resNoCt.statusCode === 415);
}

async function testTlsRptIngestAuthBoundary() {
  var refusals = [];
  var res401 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({
      authenticate: function () { return false; },
      onRefuse:     _throwingRefuse(refusals),
    }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest falsy authenticate returns 401", res401.statusCode === 401);
  check("ingest 401 carries unauthenticated Error-Type",
    res401._headers["Error-Type"] === "mail-tlsrpt/unauthenticated");
  check("ingest 401 fires onRefuse with unauthenticated code",
    refusals.indexOf("mail-tlsrpt/unauthenticated") !== -1);

  var res500 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({
      authenticate: function () { throw new Error("auth backend down"); },
      onRefuse:     _throwingRefuse(refusals),
    }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest throwing authenticate returns 500", res500.statusCode === 500);
  check("ingest 500 carries auth-error Error-Type",
    res500._headers["Error-Type"] === "mail-tlsrpt/auth-error");
  check("ingest 500 fires onRefuse with auth-error code",
    refusals.indexOf("mail-tlsrpt/auth-error") !== -1);
}

async function testTlsRptIngestAcceptPaths() {
  var audits = [];
  var fakeAudit = { safeEmit: function (e) { audits.push(e); } };

  // authenticate true + sync onAccept → 201
  var accepted = [];
  var res201 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({
      audit:        fakeAudit,
      authenticate: function () { return true; },
      onAccept:     function (report) { accepted.push(report["report-id"]); },
    }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest authenticated + accepted returns 201", res201.statusCode === 201);
  check("ingest passes parsed report to onAccept",
    accepted[0] === "2026-07-11T00:00:00Z_example.com");
  check("ingest emits a success audit event",
    audits.some(function (e) { return e.outcome === "success"; }));

  // async onAccept resolved → 201
  var resAsync = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ onAccept: function () { return Promise.resolve(); } }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest async onAccept resolve returns 201", resAsync.statusCode === 201);

  // async onAccept rejected → 500
  var resReject = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ onAccept: function () { return Promise.reject(new Error("store down")); } }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest async onAccept reject returns 500", resReject.statusCode === 500);

  // sync onAccept throw → best-effort, still 201
  var resThrow = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ onAccept: function () { throw new Error("hook bug"); } }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest sync onAccept throw still returns 201", resThrow.statusCode === 201);

  // no onAccept configured → 201 (uses the framework's default audit, not
  // an injected handle — exercises the fallback branch of _safeAuditEmit)
  var resNoHook = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({}),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest without onAccept returns 201", resNoHook.statusCode === 201);

  // A throwing audit handle must not block ingest — _safeAuditEmit is
  // drop-silent by design.
  var resAuditThrows = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ audit: { safeEmit: function () { throw new Error("audit sink down"); } } }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest survives a throwing audit sink", resAuditThrows.statusCode === 201);
}

async function testTlsRptIngestRefusalStatuses() {
  var refusals = [];
  var onRefuse = _throwingRefuse(refusals);

  // parse failure → 400 with Error-Type
  var res400 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ onRefuse: onRefuse }),
    _bodyReq("POST", { "content-type": _CT_JSON }, "{not json"), _bodyRes());
  check("ingest parse failure returns 400", res400.statusCode === 400);
  check("ingest 400 carries the parser's Error-Type",
    res400._headers["Error-Type"] === "mail-tlsrpt/bad-json");
  check("ingest 400 fires onRefuse with parser code",
    refusals.indexOf("mail-tlsrpt/bad-json") !== -1);

  // gunzip bomb via the handler → 413
  var gzBig = zlib.gzipSync(Buffer.from("x".repeat(50000)));
  var res413 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ maxDecompressedBytes: 100 }),
    _bodyReq("POST", { "content-type": "application/tlsrpt+gzip" }, gzBig), _bodyRes());
  check("ingest gunzip bomb returns 413", res413.statusCode === 413);
  check("ingest 413 carries gunzip-bomb Error-Type",
    res413._headers["Error-Type"] === "mail-tlsrpt/gunzip-bomb");

  // ratio bomb via the handler → 413 (distinct status-map branch)
  var resRatio = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ maxRatio: 2 }),
    _bodyReq("POST", { "content-type": "application/tlsrpt+gzip" }, gzBig), _bodyRes());
  check("ingest ratio bomb returns 413", resRatio.statusCode === 413);
  check("ingest 413 carries ratio-bomb Error-Type",
    resRatio._headers["Error-Type"] === "mail-tlsrpt/ratio-bomb");

  // oversize compressed body (collector cap) → 413
  var resOversize = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ maxCompressedBytes: 16, onRefuse: onRefuse }),
    _bodyReq("POST", { "content-type": _CT_JSON }, "y".repeat(500)), _bodyRes());
  check("ingest oversize body returns 413", resOversize.statusCode === 413);
  check("ingest oversize body fires onRefuse",
    refusals.indexOf("mail-tlsrpt/oversize-compressed") !== -1);
}

async function testTlsRptIngestTrustedReporters() {
  // Advisory content filter: report.organization-name not in the
  // allowlist → 403.
  var refusals = [];
  var res403 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ trustedReporters: ["Other Org"], onRefuse: _throwingRefuse(refusals) }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest untrusted reporter returns 403", res403.statusCode === 403);
  check("ingest 403 carries untrusted-reporter Error-Type",
    res403._headers["Error-Type"] === "mail-tlsrpt/untrusted-reporter");
  check("ingest 403 fires onRefuse with untrusted-reporter code",
    refusals.indexOf("mail-tlsrpt/untrusted-reporter") !== -1);

  // matching reporter → 201
  var res201 = await _driveIngest(
    b.mail.deploy.tlsRptIngestHttp({ trustedReporters: ["Reporter Inc"] }),
    _bodyReq("POST", { "content-type": _CT_JSON }, JSON.stringify(_validReport())), _bodyRes());
  check("ingest trusted reporter returns 201", res201.statusCode === 201);
}

async function testTlsRptIngestRequestError() {
  var req = new EventEmitter();
  req.method  = "POST";
  req.headers = { "content-type": _CT_JSON };
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock */ };
  var res = _bodyRes();
  b.mail.deploy.tlsRptIngestHttp({})(req, res);
  // Emit a stream error after listeners attach (handler registers them
  // synchronously since no authenticate hook is configured).
  setImmediate(function () { req.emit("error", new Error("connection reset")); });
  await waitUntil(function () { return res.statusCode !== null; }, {
    timeoutMs: 4000, label: "tlsRptIngestHttp: req-error response",
  });
  check("ingest request-stream error returns 400", res.statusCode === 400);
}

async function run() {
  testSurface();
  testMtaStsHappy();
  testMtaStsExplicitPolicyId();
  testMtaStsBadInput();
  testMtaStsMxAndMaxAgeBranches();
  testAutoConfigHappy();
  testAutoConfigPlainSocketAndUsername();
  testAutoConfigEscape();
  testAutoConfigProtocolTypeAttr();
  testAutoConfigJmap();
  testAutoConfigBadInput();
  testAutoConfigMoreBranches();
  testAutoDiscoverHappy();
  testAutoDiscoverMoreBranches();
  testAutoDiscoverXmlInjection();
  testDanePublishInputGuards();
  await testDanePublishDeepHash();
  testTlsRptHappy();
  testTlsRptOptsAndSize();
  testTlsRptGzipBranches();
  testTlsRptSchemaRejections();
  testTlsRptPolicyRejections();
  testTlsRptSchemaDescriptor();
  testTlsRptIngestOptsValidation();
  await testTlsRptIngestMethodAndContentType();
  await testTlsRptIngestAuthBoundary();
  await testTlsRptIngestAcceptPaths();
  await testTlsRptIngestRefusalStatuses();
  await testTlsRptIngestTrustedReporters();
  await testTlsRptIngestRequestError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("OK — mail-deploy " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
    process.exit(1);
  });
}
