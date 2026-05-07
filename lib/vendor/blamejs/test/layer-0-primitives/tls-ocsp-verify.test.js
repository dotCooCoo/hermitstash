"use strict";
/**
 * b.network.tls.ocsp.parseResponse + .evaluate + .requireGood — RFC 6960
 * OCSP response parser + signature verifier. Live-server round-trip
 * tests live in test/integration/; this layer-0 suite exercises the
 * parser's malformed-input rejection + the surface contract.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("ocsp.parseResponse is a function",
        typeof b.network.tls.ocsp.parseResponse === "function");
  check("ocsp.evaluate is a function",
        typeof b.network.tls.ocsp.evaluate === "function");
  check("ocsp.requireGood is a function",
        typeof b.network.tls.ocsp.requireGood === "function");
  check("ocsp.requireStapled (presence-only) is a function",
        typeof b.network.tls.ocsp.requireStapled === "function");
}

function testParseRejectsBadInput() {
  var threw = null;
  try { b.network.tls.ocsp.parseResponse("not a buffer"); }
  catch (e) { threw = e; }
  check("parseResponse(non-buffer) throws ocsp-bad-input",
        threw && /ocsp-bad-input/.test(threw.code || ""));
}

function testParseRejectsNonSequence() {
  // 0x02 = INTEGER, not a SEQUENCE.
  var threw = null;
  try { b.network.tls.ocsp.parseResponse(Buffer.from([0x02, 0x01, 0x05])); }
  catch (e) { threw = e; }
  check("parseResponse(non-SEQUENCE) throws ocsp-bad-shape",
        threw && /ocsp-bad-shape|ocsp-bad-input|asn1\/wrong/.test(threw.code || threw.message || ""));
}

function testParseTryLater() {
  // OCSPResponse { responseStatus 3 } — "tryLater". No responseBytes.
  // Hand-crafted DER: 0x30 0x03 0x0a 0x01 0x03
  //                   SEQ  len  ENUM len status=3
  var rv = b.network.tls.ocsp.parseResponse(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03]));
  check("parseResponse: tryLater (status 3)",
        rv.status === "tryLater" && rv.basic === undefined);
}

function testParseUnauthorized() {
  // Status 6 = unauthorized.
  var rv = b.network.tls.ocsp.parseResponse(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x06]));
  check("parseResponse: unauthorized (status 6)",
        rv.status === "unauthorized");
}

function testEvaluateRequiresIssuerPem() {
  var threw = null;
  try { b.network.tls.ocsp.evaluate(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03])); }
  catch (e) { threw = e; }
  check("evaluate without issuerPem throws ocsp-missing-issuer",
        threw && /ocsp-missing-issuer/.test(threw.code || ""));
}

function testEvaluateNonSuccessful() {
  // Status=tryLater — evaluate returns ok:false with the status surfaced.
  var rv = b.network.tls.ocsp.evaluate(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x03]),
                                       { issuerPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n" });
  check("evaluate: non-successful response surfaces status without verify",
        rv.ok === false && rv.status === "tryLater");
}

function testEvaluateMalformed() {
  var rv = b.network.tls.ocsp.evaluate(Buffer.from([0x99, 0x99]),
                                       { issuerPem: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n" });
  check("evaluate: malformed bytes → ok:false, status:'parse-error'",
        rv.ok === false && rv.status === "parse-error");
}

async function testRequireGoodRequiresIssuerPem() {
  var threw = null;
  try { await b.network.tls.ocsp.requireGood({ host: "127.0.0.1", port: 1 }); }
  catch (e) { threw = e; }
  check("requireGood without issuerPem throws ocsp-missing-issuer",
        threw && /ocsp-missing-issuer/.test(threw.code || ""));
}

async function run() {
  testSurface();
  testParseRejectsBadInput();
  testParseRejectsNonSequence();
  testParseTryLater();
  testParseUnauthorized();
  testEvaluateRequiresIssuerPem();
  testEvaluateNonSuccessful();
  testEvaluateMalformed();
  await testRequireGoodRequiresIssuerPem();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
