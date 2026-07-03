// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ocsp + b.network.tls.ct — surface tests.
 *
 * The protocol-side OCSP request/response and SCT signature
 * verification are deferred (need ASN.1 parsing). What ships here is
 * the operator surface — connect/requireGood wrappers + cert
 * inspection + requireScts predicate factory. Live-network tests are
 * gated behind operator-supplied integration runs.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testOcspSurface() {
  check("network.tls.ocsp.connect is a function",
        typeof b.network.tls.ocsp.connect === "function");
  check("network.tls.ocsp.requireStapled is a function",
        typeof b.network.tls.ocsp.requireStapled === "function");
  check("network.tls.ocsp.inspectMustStaple is a function",
        typeof b.network.tls.ocsp.inspectMustStaple === "function");
  check("network.tls.ocsp.requireMustStaple is a function",
        typeof b.network.tls.ocsp.requireMustStaple === "function");
  check("network.tls.ocsp.buildRequest is a function",
        typeof b.network.tls.ocsp.buildRequest === "function");
}

// Synthesize a minimal RFC 5280-shaped X.509 cert via the framework
// ASN.1 writers — enough for buildRequest's _extractIssuerNameDerAnd-
// KeyBitString and _extractLeafSerial walks. Not cryptographically
// signed; verifies only that the SHAPE is read correctly.
function _synthesizeMinimalCert(serialBytes, issuerCnBytes, pubKeyBytes) {
  var asn1 = require("../../lib/asn1-der");
  // Name ::= SEQUENCE OF RDN; RDN ::= SET OF AttributeTypeAndValue;
  // Use a single CN attribute for simplicity.
  var cnOid = asn1.writeOid("2.5.4.3");
  var cnValue = asn1.writeNode(0x0c, issuerCnBytes);                            // UTF8String
  var atv = asn1.writeSequence([cnOid, cnValue]);
  var rdn = asn1.writeNode(0x31, atv);                                           // SET OF
  var name = asn1.writeSequence([rdn]);
  // Validity ::= SEQUENCE { notBefore, notAfter } — use UTCTime.
  var notBefore = asn1.writeNode(0x17, Buffer.from("260101000000Z"));
  var notAfter  = asn1.writeNode(0x17, Buffer.from("270101000000Z"));
  var validity = asn1.writeSequence([notBefore, notAfter]);
  // SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  var algId = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  // BIT STRING wraps: [unusedBits=0x00, ...keyBytes]
  var spkiBits = asn1.writeNode(0x03, Buffer.concat([Buffer.from([0]), pubKeyBytes]));
  var spki = asn1.writeSequence([algId, spkiBits]);
  // version [0] EXPLICIT INTEGER 2 (= v3)
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  // tbsCertificate
  var tbs = asn1.writeSequence([
    version,
    asn1.writeInteger(serialBytes),
    algId,                                                                       // signature algorithm
    name,                                                                        // issuer
    validity,
    name,                                                                        // subject (= issuer for self-signed)
    spki,
  ]);
  var sigBits = asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]));                 // BIT STRING placeholder
  var cert = asn1.writeSequence([tbs, algId, sigBits]);
  return cert;
}

function testOcspBuildRequestDefaultIncludesNonce() {
  // Default is nonce ON — security-defaults-on rule.
  var cert = _synthesizeMinimalCert(Buffer.from([0x12, 0x34, 0x56, 0x78]),
    Buffer.from("Test CA"), Buffer.from("public-key-bytes-go-here-aaaaaaaaaa"));
  var rv = b.network.tls.ocsp.buildRequest({
    leafCertDer:   cert,
    issuerCertDer: cert,
  });
  check("buildRequest returns Buffer",  Buffer.isBuffer(rv.requestDer));
  check("buildRequest default includes nonce (16 bytes)",
        Buffer.isBuffer(rv.nonce) && rv.nonce.length === 16);
  // Parse it back via the same ASN.1 walker.
  var asn1 = require("../../lib/asn1-der");
  var top = asn1.readNode(rv.requestDer);
  check("buildRequest output is a SEQUENCE", top.tag === asn1.TAG.SEQUENCE);
}

function testOcspBuildRequestExplicitOptOut() {
  // Operators talking to nonce-ignoring responders opt out via nonce: false.
  var cert = _synthesizeMinimalCert(Buffer.from([0xab, 0xcd]),
    Buffer.from("Test CA 2"), Buffer.from("public-key-bytes-2-aaaaaaaaaaaaaa"));
  var rv = b.network.tls.ocsp.buildRequest({
    leafCertDer:   cert,
    issuerCertDer: cert,
    nonce:         false,
  });
  check("buildRequest({ nonce: false }) returns null nonce", rv.nonce === null);
}

function testOcspBuildRequestNonceLenOutOfRange() {
  var cert = _synthesizeMinimalCert(Buffer.from([0x01]),
    Buffer.from("X"), Buffer.from("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"));
  var threw = null;
  try {
    b.network.tls.ocsp.buildRequest({
      leafCertDer: cert, issuerCertDer: cert,
      nonce: true, nonceLen: 64,
    });
  } catch (e) { threw = e; }
  check("buildRequest refuses RFC 8954 out-of-range nonceLen",
        threw && /ocsp-bad-nonce-len/.test(threw.code || ""));
}

function testOcspBuildRequestRejectsBadInput() {
  var threw = null;
  try { b.network.tls.ocsp.buildRequest({ leafCertDer: "not-a-buffer", issuerCertDer: Buffer.from("x") }); }
  catch (e) { threw = e; }
  check("buildRequest refuses non-Buffer leafCertDer",
        threw && /ocsp-bad-input/.test(threw.code || ""));
}

function testMustStapleInspectMalformed() {
  var fake = Buffer.from("not a real cert");
  var rv = b.network.tls.ocsp.inspectMustStaple(fake);
  check("inspectMustStaple on malformed buffer → mustStaple=false",
        rv.mustStaple === false);
  check("inspectMustStaple returns features array",
        Array.isArray(rv.features));
}

function testMustStapleInspectRejectsNonBuffer() {
  var threw = null;
  try { b.network.tls.ocsp.inspectMustStaple("nope"); }
  catch (e) { threw = e; }
  check("inspectMustStaple rejects non-Buffer",
        threw && /ocsp-bad-input/.test(threw.code || ""));
}

function testRequireMustStaplePredicateNoCert() {
  var pred = b.network.tls.ocsp.requireMustStaple();
  var err = pred(null, {});
  check("requireMustStaple(null) → ocsp-no-cert",
        err && /ocsp-no-cert/.test(err.code || ""));
}

function testRequireMustStaplePredicateNoExtensionPasses() {
  // Cert without must-staple extension + no staple → predicate returns
  // null (operator did not opt into enforceUnconditional).
  var pred = b.network.tls.ocsp.requireMustStaple();
  var err = pred({ raw: Buffer.from("not a real cert") }, {});
  check("requireMustStaple on cert without must-staple → null (default)",
        err === null);
}

function testRequireMustStapleEnforceUnconditional() {
  var pred = b.network.tls.ocsp.requireMustStaple({ enforceUnconditional: true });
  var err = pred({ raw: Buffer.from("not a real cert") }, {});
  check("requireMustStaple({ enforceUnconditional }) refuses no-staple",
        err && /ocsp-staple-required/.test(err.code || ""));
}

function testCtSurface() {
  check("network.tls.ct.inspect is a function",
        typeof b.network.tls.ct.inspect === "function");
  check("network.tls.ct.parseScts is a function",
        typeof b.network.tls.ct.parseScts === "function");
  check("network.tls.ct.verifyScts is a function",
        typeof b.network.tls.ct.verifyScts === "function");
  check("network.tls.ct.requireScts is a function",
        typeof b.network.tls.ct.requireScts === "function");
}

function testCtParseSctsNoExtension() {
  // Buffer with no SCT OID — parseScts returns [].
  var fake = Buffer.from("not a real cert");
  var rv = b.network.tls.ct.parseScts(fake);
  check("parseScts on cert without SCT extension → []",
        Array.isArray(rv) && rv.length === 0);
}

function testCtVerifyNoSctExtension() {
  var fake = Buffer.from("not a real cert");
  var rv = b.network.tls.ct.verifyScts(fake, { logKeys: {}, minScts: 2 });
  check("verifyScts: no SCT extension → ok=false, reason=no-sct-extension",
        rv.ok === false && rv.reason === "no-sct-extension");
}

function testCtVerifyParseError() {
  // Mock a "cert" that has the SCT OID byte sequence but malformed ASN.1
  // around it — parseScts will fail to walk it.
  var fake = Buffer.alloc(100);                                                  // not a real cert
  var rv = b.network.tls.ct.verifyScts(fake, { logKeys: {} });
  check("verifyScts: malformed cert → ok=false (no-sct-extension or parse-error)",
        rv.ok === false && (rv.reason === "no-sct-extension" || rv.reason === "parse-error"));
}

function testCtInspectRejectsNonBuffer() {
  var threw = null;
  try { b.network.tls.ct.inspect("not a buffer"); }
  catch (e) { threw = e; }
  check("ct.inspect rejects non-Buffer",
        threw && /ct-bad-input/.test(threw.code || ""));
}

function testCtInspectFakeCertNoExtension() {
  // A buffer that doesn't contain the SCT OID bytes.
  var fake = Buffer.from("not a real cert", "utf8");
  var rv = b.network.tls.ct.inspect(fake);
  check("ct.inspect on non-SCT cert → hasSctExtension = false",
        rv.hasSctExtension === false);
}

function testCtInspectFakeCertWithOid() {
  // Embed the SCT OID bytes inside an arbitrary buffer.
  var oid = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  var fake = Buffer.concat([Buffer.alloc(50), oid, Buffer.alloc(50)]);
  var rv = b.network.tls.ct.inspect(fake);
  check("ct.inspect on cert with SCT OID → hasSctExtension = true",
        rv.hasSctExtension === true);
}

function testRequireSctsPredicate() {
  var pred = b.network.tls.ct.requireScts({ minScts: 2 });
  check("requireScts returns a function",
        typeof pred === "function");
  // Missing cert → error.
  var err1 = pred(null);
  check("requireScts(null) → ct-no-cert error",
        err1 && /ct-no-cert/.test(err1.code || ""));
  // Cert with no SCT OID → ct-no-sct-extension error (real verifier
  // walks ASN.1 and finds no extension, not just OID byte presence).
  var noScts = { raw: Buffer.from("nope") };
  var err2 = pred(noScts);
  check("requireScts(non-SCT cert) → ct-no-sct-extension error",
        err2 && /ct-no-sct-extension/.test(err2.code || ""));
  // Cert with embedded OID bytes but no valid ASN.1 structure → still
  // refused (real verifier can't extract a parseable SCT list). Old
  // OID-presence heuristic would have passed this; the upgraded
  // verifier correctly distinguishes "looks like the OID is in there"
  // from "actually has a verified SCT list".
  var oid = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  var withFakeOid = { raw: Buffer.concat([Buffer.alloc(20), oid]) };
  var err3 = pred(withFakeOid);
  check("requireScts(malformed cert with OID bytes) → still refused",
        err3 !== null);
}

async function run() {
  testOcspSurface();
  testCtSurface();
  testCtInspectRejectsNonBuffer();
  testCtInspectFakeCertNoExtension();
  testCtInspectFakeCertWithOid();
  testCtParseSctsNoExtension();
  testCtVerifyNoSctExtension();
  testCtVerifyParseError();
  testRequireSctsPredicate();
  testMustStapleInspectMalformed();
  testMustStapleInspectRejectsNonBuffer();
  testRequireMustStaplePredicateNoCert();
  testRequireMustStaplePredicateNoExtensionPasses();
  testRequireMustStapleEnforceUnconditional();
  testOcspBuildRequestDefaultIncludesNonce();
  testOcspBuildRequestExplicitOptOut();
  testOcspBuildRequestNonceLenOutOfRange();
  testOcspBuildRequestRejectsBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
