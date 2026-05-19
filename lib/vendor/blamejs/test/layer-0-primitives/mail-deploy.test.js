"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Note: node:crypto doesn't expose a cert generator, so the DANE
// test exercises only the input-validation paths below (negative
// tests); the deep SPKI-hash path is covered by an upcoming
// integration test that fixtures a real letsencrypt cert.

function testSurface() {
  check("b.mail.deploy.mtaStsPublish",   typeof b.mail.deploy.mtaStsPublish   === "function");
  check("b.mail.deploy.danePublish",     typeof b.mail.deploy.danePublish     === "function");
  check("b.mail.deploy.autoConfigXml",   typeof b.mail.deploy.autoConfigXml   === "function");
  check("b.mail.deploy.autoDiscoverXml", typeof b.mail.deploy.autoDiscoverXml === "function");
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

function testMtaStsBadInput() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-deploy/") === 0);
  }
  expectThrow("refuses bad domain",      function () { b.mail.deploy.mtaStsPublish({ domain: "", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100 }); });
  expectThrow("refuses bad mode",        function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "fake", mxHosts: ["x.com"], maxAgeSec: 100 }); });
  expectThrow("refuses empty mx list",   function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: [], maxAgeSec: 100 }); });
  expectThrow("refuses max-age > 1 year", function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 99999999 }); });
  expectThrow("refuses CR in domain",    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com\r\nFAKE", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100 }); });
  expectThrow("refuses bad policyId",    function () { b.mail.deploy.mtaStsPublish({ domain: "x.com", mode: "enforce", mxHosts: ["x.com"], maxAgeSec: 100, policyId: "with space" }); });
}

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

function testAutoConfigEscape() {
  // Operator-supplied displayName may carry XML metacharacters. Validate
  // they get escaped, not echoed raw.
  var xml = b.mail.deploy.autoConfigXml({
    domain:      "example.com",
    displayName: "<bad>&\"'</bad>",
    imap:        { host: "imap.example.com", port: 993 },
  });
  check("autoconfig escapes XML metachars",
    xml.indexOf("<displayName>&lt;bad&gt;&amp;&quot;&apos;&lt;/bad&gt;</displayName>") !== -1);
}

function testAutoConfigProtocolTypeAttr() {
  // Per Mozilla config-v1.1 spec, `type` is the protocol (imap/pop3/smtp),
  // not the direction. Regression for Codex P1.
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
  // Regression for Codex P2: JMAP-only configuration must be accepted.
  var xml = b.mail.deploy.autoConfigXml({
    domain: "example.com",
    jmap:   { url: "https://jmap.example.com/.well-known/jmap" },
  });
  check("autoconfig JMAP-only succeeds + emits incomingServer type=jmap",
    xml.indexOf("<incomingServer type=\"jmap\">") !== -1);
  check("autoconfig JMAP URL embedded",
    xml.indexOf("<url>https://jmap.example.com/.well-known/jmap</url>") !== -1);
  // Refuse bad URL
  var threw = null;
  try {
    b.mail.deploy.autoConfigXml({ domain: "x.com", jmap: { url: "bad\r\nurl" } });
  } catch (e) { threw = e; }
  check("autoconfig refuses CR/LF in jmap URL",
    threw && threw.code === "mail-deploy/bad-jmap-url");
}

function testAutoConfigBadInput() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-deploy/") === 0);
  }
  expectThrow("refuses no incoming server",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com" }); });
  expectThrow("refuses bad imap host",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", imap: { host: "", port: 993 } }); });
  expectThrow("refuses bad imap port",
    function () { b.mail.deploy.autoConfigXml({ domain: "x.com", imap: { host: "x.com", port: 99999 } }); });
}

function testAutoDiscoverHappy() {
  var xml = b.mail.deploy.autoDiscoverXml({
    email: "alice@example.com",
    imap:  { host: "imap.example.com", port: 993, ssl: true },
    smtp:  { host: "smtp.example.com", port: 587, ssl: false },
  });
  // Match the full xmlns attribute value (anchored both sides) — using
  // indexOf on the bare host alone trips CodeQL's `js/incomplete-url-
  // substring-sanitization` query (false positive in a test assertion
  // context, but the anchored shape is the right test anyway because
  // we want to verify the canonical xmlns declaration, not just any
  // mention of the string).
  check("autodiscover declares Microsoft schema",
    xml.indexOf("xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"") !== -1);
  check("autodiscover carries IMAP proto", xml.indexOf("<Type>IMAP</Type>") !== -1);
  check("autodiscover carries SMTP proto", xml.indexOf("<Type>SMTP</Type>") !== -1);
  check("autodiscover SSL on / off mapping",
    xml.indexOf("<SSL>on</SSL>") !== -1 && xml.indexOf("<SSL>off</SSL>") !== -1);
}

function testAutoDiscoverXmlInjection() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-deploy/") === 0);
  }
  expectThrow("refuses CR/LF in email",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com\r\n<inject/>", imap: { host: "x.com", port: 1 } }); });
  expectThrow("refuses NUL in email",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com\x00", imap: { host: "x.com", port: 1 } }); });
  expectThrow("refuses missing protos",
    function () { b.mail.deploy.autoDiscoverXml({ email: "alice@x.com" }); });
}

function testDanePublishSelectorSpki() {
  // Generate self-signed cert via openssl-style — node:crypto doesn't
  // build certs directly; use the test fixture or a vendored helper.
  // Skip the deep DANE test if we can't get a PEM; verify only the
  // input-validation paths.
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-deploy/") === 0);
  }
  expectThrow("danePublish refuses bad pem",
    function () { b.mail.deploy.danePublish({ certPem: "not a pem", mxHost: "mx.x.com" }); });
  expectThrow("danePublish refuses empty pem",
    function () { b.mail.deploy.danePublish({ certPem: "", mxHost: "mx.x.com" }); });
  expectThrow("danePublish refuses bad usage",
    function () { b.mail.deploy.danePublish({ certPem: "x", mxHost: "mx.x.com", usage: 7 }); });
}

function run() {
  testSurface();
  testMtaStsHappy();
  testMtaStsBadInput();
  testAutoConfigHappy();
  testAutoConfigEscape();
  testAutoConfigProtocolTypeAttr();
  testAutoConfigJmap();
  testAutoConfigBadInput();
  testAutoDiscoverHappy();
  testAutoDiscoverXmlInjection();
  testDanePublishSelectorSpki();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-deploy] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
