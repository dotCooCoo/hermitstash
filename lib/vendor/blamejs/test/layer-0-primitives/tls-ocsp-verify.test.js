// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ocsp.parseResponse + .evaluate + .requireGood — RFC 6960
 * OCSP response parser + signature verifier. Live-server round-trip
 * tests live in test/integration/; this layer-0 suite exercises the
 * parser's malformed-input rejection + the surface contract.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");

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

// ---- CertID issuer binding (RFC 6960 §4.1.1) ----------------------------
// A "good" SingleResponse whose serial matches the cert under validation but
// whose issuerNameHash/issuerKeyHash belong to a DIFFERENT issuer must be
// REFUSED — a serial is unique only per issuer, so a delegated responder /
// shared CA key could otherwise have a "good" for serial-S under issuer-Y
// accepted as proof for serial-S under issuer-X.

// Minimal RFC 5280-shaped X.509 cert (issuer DN = one CN + the given key bytes).
// Shape only — the binding hashes its DN + SPKI BIT STRING, never verifies its
// own signature.
function _synthCert(serialBytes, cnBytes, pubKeyBytes) {
  var algId    = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cn       = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, cnBytes)]);
  var name     = asn1.writeSequence([asn1.writeNode(0x31, cn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("260101000000Z")),
    asn1.writeNode(0x17, Buffer.from("270101000000Z")),
  ]);
  var spki     = asn1.writeSequence([algId,
    asn1.writeNode(0x03, Buffer.concat([Buffer.from([0]), pubKeyBytes]))]);
  var version  = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbs = asn1.writeSequence([version, asn1.writeInteger(serialBytes), algId,
                                name, validity, name, spki]);
  return asn1.writeSequence([tbs, algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
}

// Build a signed "good" OCSP response for `serial`, embedding a CertID whose
// issuer hashes come from `certIdIssuerDer` (SHA-1, what buildRequest emits).
// The response signer key is INDEPENDENT of the issuer — the delegated /
// shared-key model the binding defends.
function _buildSignedOcspWithCertIdIssuer(serial, certIdIssuerDer) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var issuerPem = kp.publicKey.export({ type: "spki", format: "pem" });

  // Reuse buildRequest to obtain the exact CertID for certIdIssuerDer; pull the
  // certID SEQUENCE out (request → tbs → requestList → request → certId).
  var req = b.network.tls.ocsp.buildRequest({
    leafCertDer:   _synthCert(serial, Buffer.from("Leaf"), Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa")),
    issuerCertDer: certIdIssuerDer,
    nonce:         false,
  });
  var reqTop  = asn1.readNode(req.requestDer);
  var reqTbs  = asn1.readSequence(reqTop.value)[0];
  var reqList = asn1.readSequence(reqTbs.value)[0];
  var reqOne  = asn1.readSequence(reqList.value)[0];
  var certId  = asn1.readSequence(reqOne.value)[0];   // the CertID SEQUENCE node

  var certStatusGood = asn1.writeContextImplicit(0, Buffer.alloc(0));   // [0] IMPLICIT NULL
  var thisU = asn1.writeNode(0x18, Buffer.from("20250615000000Z"));
  var nextU = asn1.writeContextExplicit(0, asn1.writeNode(0x18, Buffer.from("20991231000000Z")));
  var singleResponse = asn1.writeSequence([certId.raw, certStatusGood, thisU, nextU]);

  var responderId = asn1.writeContextExplicit(2, asn1.writeOctetString(Buffer.alloc(20, 0xcc)));
  var producedAt  = asn1.writeNode(0x18, Buffer.from("20250615000000Z"));
  var responses   = asn1.writeSequence([singleResponse]);
  var tbs = asn1.writeSequence([responderId, producedAt, responses]);

  var sig    = nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);   // ecdsa-with-SHA256
  var basic  = asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig)]);
  var rbInner = asn1.writeSequence([asn1.writeOid("1.3.6.1.5.5.7.48.1.1"), asn1.writeOctetString(basic)]);
  var der = asn1.writeSequence([asn1.writeNode(0x0a, Buffer.from([0])),
                                asn1.writeContextExplicit(0, rbInner)]);
  return { der: der, issuerPem: issuerPem };
}

var _OCSP_SERIAL = Buffer.from([0x12, 0x34, 0x56, 0x78]);
var _OCSP_NOW    = Date.parse("2025-06-15T00:00:01Z");

// Positive control — CertID issuer == cert-under-validation issuer → accepted.
function testCertIdIssuerMatchAccepted() {
  var issuer = _synthCert(Buffer.from([0x01]), Buffer.from("Real CA"),
                          Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa"));
  var fx = _buildSignedOcspWithCertIdIssuer(_OCSP_SERIAL, issuer);
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem:     fx.issuerPem,
    issuerCertDer: issuer,
    serialHex:     _OCSP_SERIAL.toString("hex"),
    now:           _OCSP_NOW,
  });
  check("certID match: accepted (ok=true)", rv.ok === true);
  check("certID match: no errors", Array.isArray(rv.errors) && rv.errors.length === 0);
}

// RED today — CertID issuer is a DIFFERENT CA than the cert under validation
// but the serial collides. Bound only by serial → accepted today; must be
// REFUSED for the wrong-issuer reason after the fix.
function testCrossIssuerCertIdRefused() {
  var realIssuer = _synthCert(Buffer.from([0x01]), Buffer.from("Real CA"),
                              Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa"));
  var otherIssuer = _synthCert(Buffer.from([0x02]), Buffer.from("Evil CA"),
                               Buffer.from("evil-ca-key-bytes-bbbbbbbbbbbbbb"));
  var fx = _buildSignedOcspWithCertIdIssuer(_OCSP_SERIAL, otherIssuer);
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem:     fx.issuerPem,
    issuerCertDer: realIssuer,                  // the issuer we actually asked about
    serialHex:     _OCSP_SERIAL.toString("hex"), // same serial → matches on serial alone
    now:           _OCSP_NOW,
  });
  check("cross-issuer: REFUSED (ok=false) — not bound on serial alone", rv.ok === false);
  check("cross-issuer: signature still verified (reached the binding gate)",
        rv.signatureValid === true);
  check("cross-issuer: refused for the wrong-issuer reason",
        /issuerNameHash|issuerKeyHash|wrong-issuer/i.test((rv.errors || []).join(" ; ")));
}

// Without issuerCertDer the binding is not enforced (serial-only legacy path).
function testNoIssuerCertDerStaysSerialBound() {
  var otherIssuer = _synthCert(Buffer.from([0x02]), Buffer.from("Evil CA"),
                               Buffer.from("evil-ca-key-bytes-bbbbbbbbbbbbbb"));
  var fx = _buildSignedOcspWithCertIdIssuer(_OCSP_SERIAL, otherIssuer);
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: _OCSP_SERIAL.toString("hex"), now: _OCSP_NOW,
  });
  check("no issuerCertDer: serial-only bind still resolves (ok=true)", rv.ok === true);
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
  testCertIdIssuerMatchAccepted();
  testCrossIssuerCertIdRefused();
  testNoIssuerCertDerStaysSerialBound();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
