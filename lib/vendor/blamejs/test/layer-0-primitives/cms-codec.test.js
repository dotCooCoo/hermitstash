"use strict";
/**
 * b.cms — RFC 5652 CMS codec roundtrip + refusal paths. Encode
 * SignedData (ML-DSA-65 signer) + EnvelopedData (ML-KEM-1024
 * recipient) and confirm the ContentInfo decodes to the expected
 * OID. Cover the input-shape refusals and the PQC-only sig-alg gate.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = require("../../index");
var pqcSoftware = require("../../lib/pqc-software");
var asn1    = require("../../lib/asn1-der");

function _minimalCertDer() {
  // SEQUENCE {
  //   tbsCertificate SEQUENCE { serialNumber INTEGER, signature AlgId, issuer SEQUENCE },
  //   signatureAlgorithm SEQUENCE, signatureValue BIT STRING
  // } — just enough to drive _issuerAndSerialNumber.
  var serial   = asn1.writeInteger(Buffer.from([0x01]));
  var sigAlg   = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));   // ML-DSA-65 OID
  var issuer   = asn1.writeNode(0x30, asn1.writeOid("2.5.4.3"));                    // bogus RDN
  var tbs      = asn1.writeNode(0x30, Buffer.concat([serial, sigAlg, issuer]));
  var outerSig = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var sigVal   = asn1.writeNode(0x03, Buffer.from([0x00, 0x00, 0x01]));             // BIT STRING placeholder
  return asn1.writeNode(0x30, Buffer.concat([tbs, outerSig, sigVal]));
}

function testSignedDataRoundtripMlDsa65() {
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("payload"),
    digestAlg:    "sha3-512",
    signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
  check("SignedData encode produces a non-empty Buffer",
    Buffer.isBuffer(sd) && sd.length > 100);
  var dec = b.cms.decode(sd);
  check("SignedData decodes to signedData OID",
    dec.contentType === "1.2.840.113549.1.7.2");
  check("SignedData inner content is a SEQUENCE",
    dec.content && dec.content.tag === asn1.TAG.SEQUENCE && dec.content.constructed);
}

function testSignedDataRoundtripMlDsa87() {
  var kp   = pqcSoftware.ml_dsa_87.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("a longer payload that gets digested"),
    digestAlg:    "sha3-256",
    signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-87" }],
  });
  check("SignedData ML-DSA-87 encode produces a non-empty Buffer",
    Buffer.isBuffer(sd) && sd.length > 100);
  var dec = b.cms.decode(sd);
  check("SignedData ML-DSA-87 decodes to signedData OID",
    dec.contentType === "1.2.840.113549.1.7.2");
}

function testSignedDataSlhDsa() {
  var kp   = pqcSoftware.slh_dsa_shake_256f.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("hash-based-signature payload"),
    signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "SLH-DSA-SHAKE-256f" }],
  });
  check("SLH-DSA SignedData decodes to signedData OID",
    b.cms.decode(sd).contentType === "1.2.840.113549.1.7.2");
}

function testEnvelopedDataRoundtrip() {
  var kp = pqcSoftware.ml_kem_1024.keygen();
  var ed = b.cms.encodeEnvelopedData({
    plaintext:  Buffer.from("secret data"),
    recipients: [{
      type:        "kem-mlkem-1024",
      publicKey:   kp.publicKey,
      recipientId: Buffer.from([0x42, 0x43, 0x44]),
    }],
  });
  check("EnvelopedData encode produces a non-empty Buffer",
    Buffer.isBuffer(ed) && ed.length > 200);
  var dec = b.cms.decode(ed);
  check("EnvelopedData decodes to envelopedData OID",
    dec.contentType === "1.2.840.113549.1.7.3");
}

function testRefuseSignedDataNoSigners() {
  var threw = false;
  try {
    b.cms.encodeSignedData({ encapContent: Buffer.from("p"), signers: [] });
  } catch (e) { threw = e.code === "cms/no-signers"; }
  check("empty signers refused with cms/no-signers", threw);
}

function testRefuseSignedDataBadSigAlg() {
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var threw = false;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "RSA-PSS-SHA256" }],
    });
  } catch (e) { threw = e.code === "cms/bad-sig-alg"; }
  check("non-PQC sigAlg refused with cms/bad-sig-alg", threw);
}

function testRefuseSignedDataBadDigest() {
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var threw = false;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      digestAlg:    "sha256",
      signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code === "cms/bad-digest"; }
  check("SHA-2 digestAlg refused with cms/bad-digest", threw);
}

function testRefuseEnvelopedDataBadRecipientType() {
  var threw = false;
  try {
    b.cms.encodeEnvelopedData({
      plaintext:  Buffer.from("p"),
      recipients: [{ type: "rsa-oaep", publicKey: new Uint8Array(32), recipientId: Buffer.from([0]) }],
    });
  } catch (e) { threw = e.code === "cms/bad-recipient-type"; }
  check("non-ML-KEM recipient refused with cms/bad-recipient-type", threw);
}

function testRefuseEnvelopedDataNoRecipients() {
  var threw = false;
  try {
    b.cms.encodeEnvelopedData({ plaintext: Buffer.from("p"), recipients: [] });
  } catch (e) { threw = e.code === "cms/no-recipients"; }
  check("empty recipients refused with cms/no-recipients", threw);
}

function testDecodeRefusesNonSequence() {
  var threw = false;
  try { b.cms.decode(Buffer.from([0x02, 0x01, 0x05])); }    // INTEGER, not SEQUENCE
  catch (e) { threw = e.code === "cms/bad-content-info"; }
  check("non-SEQUENCE top-level refused", threw);
}

function testDecodeRefusesOversize() {
  var threw = false;
  try { b.cms.decode(Buffer.alloc(1024), { maxBytes: 100 }); }
  catch (e) { threw = e.code === "cms/oversize"; }
  check("oversize input refused via maxBytes", threw);
}

function testDecodeRefusesNonBuffer() {
  var threw = false;
  try { b.cms.decode("not a buffer"); }
  catch (e) { threw = e.code === "cms/bad-input"; }
  check("non-Buffer input refused", threw);
}

function testCmsCodecErrorClassExported() {
  // The CmsCodecError class is exposed so operators can `instanceof`-
  // dispatch in catch blocks; this test confirms the class export is
  // present and behaves like a constructor.
  check("b.cms.CmsCodecError is a constructor",
    typeof b.cms.CmsCodecError === "function");
}

function testOidTableShape() {
  check("signedData OID matches RFC 5652",
    b.cms.OID.signedData === "1.2.840.113549.1.7.2");
  check("envelopedData OID matches RFC 5652",
    b.cms.OID.envelopedData === "1.2.840.113549.1.7.3");
  check("ML-DSA-65 OID matches NIST registry",
    b.cms.OID.mldsa65 === "2.16.840.1.101.3.4.3.18");
  check("ML-KEM-1024 OID matches NIST registry",
    b.cms.OID.mlkem1024 === "2.16.840.1.101.3.4.4.3");
  check("KEMRecipientInfo type OID matches RFC 9629",
    b.cms.OID.kemri === "1.2.840.113549.1.9.16.13.3");
}

function run() {
  testSignedDataRoundtripMlDsa65();
  testSignedDataRoundtripMlDsa87();
  testSignedDataSlhDsa();
  testEnvelopedDataRoundtrip();
  testRefuseSignedDataNoSigners();
  testRefuseSignedDataBadSigAlg();
  testRefuseSignedDataBadDigest();
  testRefuseEnvelopedDataBadRecipientType();
  testRefuseEnvelopedDataNoRecipients();
  testDecodeRefusesNonSequence();
  testDecodeRefusesOversize();
  testDecodeRefusesNonBuffer();
  testCmsCodecErrorClassExported();
  testOidTableShape();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
