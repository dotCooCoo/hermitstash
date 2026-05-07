"use strict";
/**
 * b.network.smtp.policy — MTA-STS + DANE + TLS-RPT operator surface.
 *
 * Live HTTPS / DNS lookups are not exercised in smoke (network-bound
 * tests live in test/integration). What's covered here is the parser
 * shape, MX-match logic, TLSA decode, and TLS-RPT JSON shape generator.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("network.smtp.mtaSts exposed", typeof b.network.smtp.mtaSts === "object");
  check("network.smtp.dane exposed",   typeof b.network.smtp.dane === "object");
  check("network.smtp.tlsRpt exposed", typeof b.network.smtp.tlsRpt === "object");
  check("frameworkError.SmtpPolicyError exposed",
        typeof b.frameworkError.SmtpPolicyError === "function");
}

function testMtaStsParse() {
  var text = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mx.example.com\nmax_age: 86400\n";
  var policy = b.network.smtp.mtaSts.parsePolicy(text);
  check("parsePolicy returns version + mode + mx + max_age",
        policy.version === "STSv1" && policy.mode === "enforce" &&
        policy.mx.length === 2 && policy.max_age === 86400);
}

function testMtaStsParseRejectsBadVersion() {
  var threw = null;
  try { b.network.smtp.mtaSts.parsePolicy("version: STSv2\nmode: enforce\n"); }
  catch (e) { threw = e; }
  check("parsePolicy throws on bad version",
        threw && /bad-version/.test(threw.code || ""));
}

function testMtaStsMatchMx() {
  var mxList = ["mx1.example.com", "*.mail.example.com"];
  check("exact match",
        b.network.smtp.mtaSts.matchMx("mx1.example.com", mxList) === true);
  check("wildcard single-label match",
        b.network.smtp.mtaSts.matchMx("alpha.mail.example.com", mxList) === true);
  check("wildcard does NOT match deeper",
        b.network.smtp.mtaSts.matchMx("a.b.mail.example.com", mxList) === false);
  check("wildcard does NOT match parent",
        b.network.smtp.mtaSts.matchMx("mail.example.com", mxList) === false);
  check("non-listed host → false",
        b.network.smtp.mtaSts.matchMx("attacker.example.com", mxList) === false);
}

function testDaneVerifyChainRejectsBadInput() {
  var threw = null;
  try { b.network.smtp.dane.verifyChain([], []); }
  catch (e) { threw = e; }
  check("dane.verifyChain refuses empty cert chain",
        threw && /dane-bad-chain/.test(threw.code || ""));

  var threw2 = null;
  try { b.network.smtp.dane.verifyChain([Buffer.from("x")], "not-an-array"); }
  catch (e) { threw2 = e; }
  check("dane.verifyChain refuses non-array tlsaRecords",
        threw2 && /dane-bad-tlsa/.test(threw2.code || ""));

  var threw3 = null;
  try { b.network.smtp.dane.verifyChain(["string"], []); }
  catch (e) { threw3 = e; }
  check("dane.verifyChain refuses non-Buffer chain entries",
        threw3 && /dane-bad-chain/.test(threw3.code || ""));
}

function testDaneVerifyChainNoMatch() {
  // Random buffer doesn't match any TLSA record.
  var fakeCert = Buffer.from("not a real cert");
  var rec = { usage: 3, selector: 0, mtype: 1, dataHex: "deadbeef" };
  var rv = b.network.smtp.dane.verifyChain([fakeCert], [rec]);
  check("dane.verifyChain no-match → ok=false, matches=[]",
        rv.ok === false && rv.matches.length === 0);
}

function testDaneVerifyChainDaneEeFullCert() {
  // DANE-EE / Cert / Full — exact DER match against the leaf cert.
  // The leaf cert can be any DER because mtype=0 (Full) does a
  // byte-identical comparison.
  var dummyLeaf = Buffer.from("any bytes at all", "utf8");
  var rec = {
    usage:    3,                                                                 // DANE-EE
    selector: 0,                                                                 // Cert (full DER)
    mtype:    0,                                                                 // Full
    dataHex:  dummyLeaf.toString("hex"),
  };
  var rv = b.network.smtp.dane.verifyChain([dummyLeaf, Buffer.from("ca")], [rec]);
  check("dane.verifyChain DANE-EE/Cert/Full matches leaf",
        rv.ok === true && rv.matches.length === 1 &&
        rv.matches[0].usage === "DANE-EE" && rv.matches[0].certIndex === 0);
}

function testDaneVerifyChainDaneEeSha256() {
  var nc = require("crypto");
  var dummyLeaf = Buffer.from("predictable cert bytes for test", "utf8");
  var sha256Hex = nc.createHash("sha256").update(dummyLeaf).digest("hex");
  var rec = { usage: 3, selector: 0, mtype: 1, dataHex: sha256Hex };
  var rv = b.network.smtp.dane.verifyChain([dummyLeaf], [rec]);
  check("dane.verifyChain DANE-EE/Cert/SHA-256 matches via hash",
        rv.ok === true && rv.matches[0].mtype === "SHA-256");
}

function testDaneVerifyChainDaneTaMatchesIntermediate() {
  var nc = require("crypto");
  var leaf = Buffer.from("leaf-bytes", "utf8");
  var intermediate = Buffer.from("ca-bytes", "utf8");
  var sha256Hex = nc.createHash("sha256").update(intermediate).digest("hex");
  var rec = { usage: 2, selector: 0, mtype: 1, dataHex: sha256Hex };
  var rv = b.network.smtp.dane.verifyChain([leaf, intermediate], [rec]);
  check("dane.verifyChain DANE-TA matches non-leaf cert in chain",
        rv.ok === true && rv.matches[0].usage === "DANE-TA" && rv.matches[0].certIndex === 1);
}

function testDaneVerifyChainPkixModeRejectedByDefault() {
  var fake = Buffer.from("anything");
  var rec = { usage: 1, selector: 0, mtype: 1, dataHex: "abc" };                 // PKIX-EE
  var rv = b.network.smtp.dane.verifyChain([fake], [rec]);
  check("PKIX modes refused by default with structured error",
        rv.ok === false && rv.errors[0] && rv.errors[0].reason === "pkix-modes-not-allowed");
}

function testDaneRecordShape() {
  var rec = { usage: 3, selector: 1, mtype: 1, dataHex: "abcd" };
  var shaped = b.network.smtp.dane.recordShape(rec);
  check("DANE-EE/SPKI/SHA-256 labels resolve",
        shaped.usageLabel === "DANE-EE" &&
        shaped.selectorLabel === "SPKI" &&
        shaped.mtypeLabel === "SHA-256");
}

function testTlsRptRecordShape() {
  var rpt = b.network.smtp.tlsRpt.recordShape({
    organization: "example.com",
    contact:      "tls-reports@example.com",
    policies: [
      {
        type:        "sts",
        domain:      "example.com",
        mxHosts:     ["mx1.example.com"],
        successCount: 100,
        failureCount: 2,
      },
    ],
  });
  check("tlsRpt.recordShape produces RFC 8460 JSON",
        rpt["organization-name"] === "example.com" &&
        Array.isArray(rpt.policies) &&
        rpt.policies[0].summary["total-successful-session-count"] === 100);
}

async function testTlsRptFetchPolicyParsesRua() {
  // dnsLookup mock returns the published TXT record.
  var mockedTxt = [["v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://reports.example.com/v1"]];
  var dnsLookup = async function () { return mockedTxt; };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy returns version", rv && rv.version === "TLSRPTv1");
  check("fetchPolicy parses both rua endpoints",
        rv.rua.length === 2 && /mailto:/.test(rv.rua[0]) && /https:/.test(rv.rua[1]));
}

async function testTlsRptFetchPolicyMissing() {
  var dnsLookup = async function () {
    var e = new Error("not found"); e.code = "ENOTFOUND"; throw e;
  };
  var rv = await b.network.smtp.tlsRpt.fetchPolicy("nope.example.com", { dnsLookup: dnsLookup });
  check("fetchPolicy returns null when no TXT record", rv === null);
}

async function testTlsRptSubmitMixedRua() {
  var report = b.network.smtp.tlsRpt.recordShape({
    organization: "example.com",
    policies: [{ type: "sts", domain: "example.com" }],
  });
  // Mock httpClient — capture the request rather than going to the wire.
  var captured = null;
  var fakeHttp = {
    request: async function (req) {
      captured = req;
      return { status: 202, body: Buffer.from("") };
    },
  };
  var rv = await b.network.smtp.tlsRpt.submit(report, {
    rua:        ["mailto:tls@example.com", "https://reports.example.com/submit"],
    httpClient: fakeHttp,
  });
  check("submit returns one entry per rua", rv.submitted === 2 && rv.results.length === 2);
  check("mailto entry is ok with prepared body",
        rv.results[0].kind === "mailto" && rv.results[0].ok === true &&
        Buffer.isBuffer(rv.results[0].mailto.body));
  check("https entry POSTed with content-type tlsrpt+gzip",
        rv.results[1].kind === "https" && rv.results[1].ok === true &&
        captured.headers["content-type"] === "application/tlsrpt+gzip");
  check("https body is gzip-compressed",
        Buffer.isBuffer(captured.body) && captured.body[0] === 0x1f && captured.body[1] === 0x8b);
}

async function testTlsRptSubmitRejectsEmptyRua() {
  var threw = null;
  try { await b.network.smtp.tlsRpt.submit({}, { rua: [] }); }
  catch (e) { threw = e; }
  check("submit rejects empty rua", threw && /tls-rpt-bad-rua/.test(threw.code || ""));
}

async function run() {
  testSurface();
  testMtaStsParse();
  testMtaStsParseRejectsBadVersion();
  testMtaStsMatchMx();
  testDaneRecordShape();
  testDaneVerifyChainRejectsBadInput();
  testDaneVerifyChainNoMatch();
  testDaneVerifyChainDaneEeFullCert();
  testDaneVerifyChainDaneEeSha256();
  testDaneVerifyChainDaneTaMatchesIntermediate();
  testDaneVerifyChainPkixModeRejectedByDefault();
  testTlsRptRecordShape();
  await testTlsRptFetchPolicyParsesRua();
  await testTlsRptFetchPolicyMissing();
  await testTlsRptSubmitMixedRua();
  await testTlsRptSubmitRejectsEmptyRua();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
