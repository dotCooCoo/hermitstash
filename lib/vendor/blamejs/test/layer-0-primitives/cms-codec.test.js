// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
    Buffer.isBuffer(sd) && sd.length > 100);                                                       // allow:raw-byte-literal — non-empty CMS sentinel
  var dec = b.cms.decode(sd);
  check("SignedData decodes to signedData OID",
    dec.contentType === "1.2.840.113549.1.7.2");
  check("SignedData inner content is a SEQUENCE",
    dec.content && dec.content.tag === asn1.TAG.SEQUENCE && dec.content.constructed);
}

function testParseSignedDataWalker() {
  // parseSignedData walks the SignedData ContentInfo we just encoded
  // and returns the structured shape downstream verifiers consume.
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("payload"),
    digestAlg:    "sha3-512",
    certificates: [cert],                                                                          // [0] IMPLICIT CertificateSet
    signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
  var parsed = b.cms.parseSignedData(sd);
  check("parseSignedData exposes signerInfos",
    Array.isArray(parsed.signerInfos) && parsed.signerInfos.length === 1);
  check("parseSignedData exposes certificates",
    Array.isArray(parsed.certificates) && parsed.certificates.length === 1);
  check("parseSignedData exposes encapContent struct",
    parsed.encapContent && typeof parsed.encapContent === "object" &&
    typeof parsed.encapContent.eContentType === "string");
  check("parseSignedData encapContent.eContent is the cleartext bytes",
    Buffer.isBuffer(parsed.encapContent.eContent) &&
    parsed.encapContent.eContent.toString("utf8") === "payload");
  // Refuses non-SignedData input.
  var threw = null;
  try { b.cms.parseSignedData(Buffer.from("garbage")); }
  catch (e) { threw = e.code; }
  check("parseSignedData refuses non-SignedData input",
    typeof threw === "string" && threw.indexOf("cms/") === 0);
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

var SIGNED_DATA_OID = "1.2.840.113549.1.7.2";

function _wrapContentInfo(oidStr, innerDer) {
  // Build a ContentInfo SEQUENCE { contentType OID, [0] EXPLICIT innerDer }
  // directly so we can hand-craft SignedData bodies that the encoder would
  // never emit — driving parseSignedData's structural-refusal branches.
  return asn1.writeNode(0x30, Buffer.concat([
    asn1.writeOid(oidStr),
    asn1.writeContextExplicit(0, innerDer),
  ]));
}

// ---- encodeSignedData entry-point / opts validation --------------------

function testEncodeSignedDataRefusesMissingOpts() {
  var threw = null;
  try { b.cms.encodeSignedData(); }
  catch (e) { threw = e.code; }
  check("encodeSignedData() with no opts refused with cms/bad-opts",
    threw === "cms/bad-opts");
  var threw2 = null;
  try { b.cms.encodeSignedData("nope"); }
  catch (e) { threw2 = e.code; }
  check("encodeSignedData(non-object) refused with cms/bad-opts",
    threw2 === "cms/bad-opts");
}

function testEncodeSignedDataRefusesNonBufferEncap() {
  var kp = pqcSoftware.ml_dsa_65.keygen();
  var threw = null;
  try {
    b.cms.encodeSignedData({
      encapContent: "not a buffer",
      signers: [{ certificate: _minimalCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code; }
  check("encodeSignedData with non-Buffer encapContent refused with cms/bad-encap",
    threw === "cms/bad-encap");
}

function testEncodeSignedDataRefusesNonObjectSigner() {
  var threw = null;
  try {
    b.cms.encodeSignedData({ encapContent: Buffer.from("p"), signers: [null] });
  } catch (e) { threw = e.code; }
  check("encodeSignedData with a non-object signer refused with cms/bad-signer",
    threw === "cms/bad-signer");
}

function testEncodeSignedDataRefusesSignerWithoutCert() {
  var kp = pqcSoftware.ml_dsa_65.keygen();
  var threw = null;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      signers: [{ secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code; }
  check("signer missing certificate Buffer refused with cms/bad-signer-cert",
    threw === "cms/bad-signer-cert");
}

function testEncodeSignedDataRefusesNonUint8SecretKey() {
  var threw = null;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      signers: [{ certificate: _minimalCertDer(), secretKey: [1, 2, 3], sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code; }
  check("signer.secretKey not a Uint8Array refused with cms/bad-signer-key",
    threw === "cms/bad-signer-key");
}

function testEncodeSignedDataRefusesNonBufferCertificate() {
  var kp = pqcSoftware.ml_dsa_65.keygen();
  var threw = null;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      certificates: ["not a buffer"],
      signers: [{ certificate: _minimalCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code; }
  check("non-Buffer certificates[] entry refused with cms/bad-cert",
    threw === "cms/bad-cert");
}

function testEncodeSignedDataSignFailsOnShortKey() {
  // A Uint8Array that passes the type gate but is the wrong length makes
  // the noble ML-DSA signer throw — the module must surface cms/sign-failed
  // rather than leaking the raw noble error.
  var threw = null;
  try {
    b.cms.encodeSignedData({
      encapContent: Buffer.from("p"),
      signers: [{ certificate: _minimalCertDer(), secretKey: new Uint8Array(5), sigAlg: "ML-DSA-65" }],
    });
  } catch (e) { threw = e.code; }
  check("wrong-length secretKey surfaces cms/sign-failed",
    threw === "cms/sign-failed");
}

function testEncodeSignedDataDetachedOmitsContent() {
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("detached payload"),
    detached:     true,
    signers: [{ certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
  var parsed = b.cms.parseSignedData(sd);
  check("detached SignedData omits eContent (null)",
    parsed.encapContent.eContent === null);
}

function testEncodeSignedDataGeneralizedTimeBranch() {
  // signingTime past 2049 forces the GeneralizedTime encode branch in
  // _encodeTime instead of UTCTime — the roundtrip must still decode.
  var kp   = pqcSoftware.ml_dsa_65.keygen();
  var cert = _minimalCertDer();
  var sd   = b.cms.encodeSignedData({
    encapContent: Buffer.from("future-dated"),
    signers: [{
      certificate: cert, secretKey: kp.secretKey, sigAlg: "ML-DSA-65",
      signingTime: new Date(Date.UTC(2050, 0, 1, 0, 0, 0)),
    }],
  });
  check("GeneralizedTime-dated SignedData decodes to signedData OID",
    b.cms.decode(sd).contentType === SIGNED_DATA_OID);
}

// ---- _issuerAndSerialNumber malformed-certificate branches -------------

function _encodeWithCert(certBuf) {
  var kp = pqcSoftware.ml_dsa_65.keygen();
  return b.cms.encodeSignedData({
    encapContent: Buffer.from("p"),
    signers: [{ certificate: certBuf, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
}

function testCertNonSequenceRefused() {
  var threw = null;
  try { _encodeWithCert(Buffer.from([0x02, 0x01, 0x05])); }   // INTEGER, not SEQUENCE
  catch (e) { threw = e.code; }
  check("non-SEQUENCE certificate refused with cms/bad-cert", threw === "cms/bad-cert");
}

function testCertMissingTbsRefused() {
  var threw = null;
  try { _encodeWithCert(asn1.writeNode(0x30, Buffer.alloc(0))); }   // empty SEQUENCE
  catch (e) { threw = e.code; }
  check("certificate with no tbsCertificate refused with cms/bad-cert",
    threw === "cms/bad-cert");
}

function testCertMissingSerialRefused() {
  // tbsCertificate whose first element is an OID, not the serialNumber INTEGER.
  var tbs  = asn1.writeNode(0x30, asn1.writeOid("2.5.4.3"));
  var cert = asn1.writeNode(0x30, Buffer.concat([tbs, tbs]));
  var threw = null;
  try { _encodeWithCert(cert); }
  catch (e) { threw = e.code; }
  check("tbsCertificate with no serialNumber refused with cms/bad-cert",
    threw === "cms/bad-cert");
}

function testCertMissingSignatureAlgIdRefused() {
  var serial = asn1.writeInteger(Buffer.from([0x01]));
  var tbs    = asn1.writeNode(0x30, serial);   // serial only, no signature AlgId
  var cert   = asn1.writeNode(0x30, tbs);
  var threw = null;
  try { _encodeWithCert(cert); }
  catch (e) { threw = e.code; }
  check("tbsCertificate with no signature AlgorithmIdentifier refused with cms/bad-cert",
    threw === "cms/bad-cert");
}

function testCertMissingIssuerRefused() {
  var serial = asn1.writeInteger(Buffer.from([0x01]));
  var sigAlg = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var tbs    = asn1.writeNode(0x30, Buffer.concat([serial, sigAlg]));   // no issuer
  var cert   = asn1.writeNode(0x30, tbs);
  var threw = null;
  try { _encodeWithCert(cert); }
  catch (e) { threw = e.code; }
  check("tbsCertificate with no issuer Name refused with cms/bad-cert",
    threw === "cms/bad-cert");
}

function testCertWithVersionTagAccepted() {
  // tbsCertificate with a leading [0] EXPLICIT version — the idx-skip
  // branch in _issuerAndSerialNumber must consume it and still resolve
  // serial + issuer.
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([0x02])));
  var serial  = asn1.writeInteger(Buffer.from([0x0a]));
  var sigAlg  = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var issuer  = asn1.writeNode(0x30, asn1.writeOid("2.5.4.3"));
  var tbs     = asn1.writeNode(0x30, Buffer.concat([version, serial, sigAlg, issuer]));
  var outerSig = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var sigVal   = asn1.writeNode(0x03, Buffer.from([0x00, 0x00, 0x01]));
  var cert     = asn1.writeNode(0x30, Buffer.concat([tbs, outerSig, sigVal]));
  var sd = _encodeWithCert(cert);
  check("certificate carrying a [0] version tag encodes SignedData",
    b.cms.decode(sd).contentType === SIGNED_DATA_OID);
}

// ---- encodeEnvelopedData entry-point / recipient validation ------------

function testEncodeEnvelopedDataRefusesMissingOpts() {
  var threw = null;
  try { b.cms.encodeEnvelopedData(); }
  catch (e) { threw = e.code; }
  check("encodeEnvelopedData() with no opts refused with cms/bad-opts",
    threw === "cms/bad-opts");
}

function testEncodeEnvelopedDataRefusesNonBufferPlaintext() {
  var kp = pqcSoftware.ml_kem_1024.keygen();
  var threw = null;
  try {
    b.cms.encodeEnvelopedData({
      plaintext: "nope",
      recipients: [{ type: "kem-mlkem-1024", publicKey: kp.publicKey, recipientId: Buffer.from([1]) }],
    });
  } catch (e) { threw = e.code; }
  check("encodeEnvelopedData with non-Buffer plaintext refused with cms/bad-plaintext",
    threw === "cms/bad-plaintext");
}

function testEncodeEnvelopedDataRefusesNonObjectRecipient() {
  var threw = null;
  try {
    b.cms.encodeEnvelopedData({ plaintext: Buffer.from("p"), recipients: [null] });
  } catch (e) { threw = e.code; }
  check("non-object recipient refused with cms/bad-recipient",
    threw === "cms/bad-recipient");
}

function testEncodeEnvelopedDataRefusesNonUint8PublicKey() {
  var threw = null;
  try {
    b.cms.encodeEnvelopedData({
      plaintext: Buffer.from("p"),
      recipients: [{ type: "kem-mlkem-1024", publicKey: [1, 2, 3], recipientId: Buffer.from([1]) }],
    });
  } catch (e) { threw = e.code; }
  check("recipient.publicKey not a Uint8Array refused with cms/bad-recipient-key",
    threw === "cms/bad-recipient-key");
}

function testEncodeEnvelopedDataRefusesNonBufferRecipientId() {
  var kp = pqcSoftware.ml_kem_1024.keygen();
  var threw = null;
  try {
    b.cms.encodeEnvelopedData({
      plaintext: Buffer.from("p"),
      recipients: [{ type: "kem-mlkem-1024", publicKey: kp.publicKey, recipientId: "not-a-buffer" }],
    });
  } catch (e) { threw = e.code; }
  check("recipient.recipientId not a Buffer refused with cms/bad-recipient-id",
    threw === "cms/bad-recipient-id");
}

function testEncodeEnvelopedDataKemEncapFailsOnShortKey() {
  // A Uint8Array of the wrong length passes the type gate but makes the
  // noble ML-KEM encapsulate throw — surfaced as cms/kem-encap-failed.
  var threw = null;
  try {
    b.cms.encodeEnvelopedData({
      plaintext: Buffer.from("p"),
      recipients: [{ type: "kem-mlkem-1024", publicKey: new Uint8Array(8), recipientId: Buffer.from([1]) }],
    });
  } catch (e) { threw = e.code; }
  check("wrong-length recipient publicKey surfaces cms/kem-encap-failed",
    threw === "cms/kem-encap-failed");
}

// ---- decode() malformed-DER branches -----------------------------------

function testDecodeRefusesBadAsn1() {
  // SEQUENCE with a long-form length that overruns the buffer — readNode
  // itself throws, surfaced as cms/bad-asn1.
  var threw = null;
  try { b.cms.decode(Buffer.from([0x30, 0x82, 0xff, 0xff])); }
  catch (e) { threw = e.code; }
  check("un-parseable ASN.1 refused with cms/bad-asn1", threw === "cms/bad-asn1");
}

function testDecodeRefusesTruncatedBody() {
  // Outer SEQUENCE parses, but its body is a truncated INTEGER (claims 5
  // content bytes, has 1) so readSequence throws → cms/bad-content-info.
  var threw = null;
  try { b.cms.decode(Buffer.from([0x30, 0x03, 0x02, 0x05, 0x01])); }
  catch (e) { threw = e.code; }
  check("truncated ContentInfo body refused with cms/bad-content-info",
    threw === "cms/bad-content-info");
}

function testDecodeRefusesTooFewChildren() {
  // A SEQUENCE with a single child (only the OID, no [0] content).
  var ci = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var threw = null;
  try { b.cms.decode(ci); }
  catch (e) { threw = e.code; }
  check("ContentInfo with <2 children refused with cms/bad-content-info",
    threw === "cms/bad-content-info");
}

function testDecodeRefusesNonOidContentType() {
  // First child is an INTEGER where the contentType OID is required.
  var ci = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x05])),
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([0x01]))),
  ]));
  var threw = null;
  try { b.cms.decode(ci); }
  catch (e) { threw = e.code; }
  check("non-OID contentType refused with cms/bad-oid", threw === "cms/bad-oid");
}

function testDecodeRefusesNonExplicitContent() {
  // Second child is a bare INTEGER, not the required [0] EXPLICIT wrapper.
  var ci = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeOid("1.2.840.113549.1.7.1"),
    asn1.writeInteger(Buffer.from([0x01])),
  ]));
  var threw = null;
  try { b.cms.decode(ci); }
  catch (e) { threw = e.code; }
  check("missing [0] EXPLICIT content refused with cms/bad-explicit-content",
    threw === "cms/bad-explicit-content");
}

// ---- parseSignedData structural-refusal branches -----------------------

function testParseSignedDataRefusesNonSignedDataOid() {
  // A valid EnvelopedData ContentInfo carries the wrong contentType.
  var kp = pqcSoftware.ml_kem_1024.keygen();
  var ed = b.cms.encodeEnvelopedData({
    plaintext:  Buffer.from("secret"),
    recipients: [{ type: "kem-mlkem-1024", publicKey: kp.publicKey, recipientId: Buffer.from([1]) }],
  });
  var threw = null;
  try { b.cms.parseSignedData(ed); }
  catch (e) { threw = e.code; }
  check("EnvelopedData passed to parseSignedData refused with cms/not-signed-data",
    threw === "cms/not-signed-data");
}

function testParseSignedDataRefusesNonSequenceInner() {
  // SignedData OID but the [0] EXPLICIT content is an INTEGER, not a SEQUENCE.
  var ci = _wrapContentInfo(SIGNED_DATA_OID, asn1.writeInteger(Buffer.from([0x01])));
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("non-SEQUENCE SignedData body refused with cms/bad-signed-data",
    threw === "cms/bad-signed-data");
}

function testParseSignedDataRefusesTooFewChildren() {
  var inner = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    asn1.writeNode(0x31, Buffer.alloc(0)),
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("SignedData with <4 children refused with cms/bad-signed-data",
    threw === "cms/bad-signed-data");
}

function testParseSignedDataRefusesNonSetDigestAlgs() {
  // 4 children but digestAlgorithms is an INTEGER, not a SET.
  var algId  = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10"));
  var encap  = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var inner  = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    asn1.writeInteger(Buffer.from([0x09])),   // should be a SET
    encap,
    asn1.writeNode(0x31, algId),
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("non-SET digestAlgorithms refused with cms/bad-signed-data",
    threw === "cms/bad-signed-data");
}

function testParseSignedDataRefusesBadAlgIdInDigestSet() {
  // digestAlgorithms is a SET whose member is an INTEGER, not an
  // AlgorithmIdentifier SEQUENCE → _readAlgIdOid throws cms/bad-alg-id.
  var digestSet = asn1.writeNode(0x31, asn1.writeInteger(Buffer.from([0x01])));
  var encap     = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var inner     = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    encap,
    asn1.writeNode(0x31, Buffer.alloc(0)),
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("non-SEQUENCE AlgorithmIdentifier in digest SET refused with cms/bad-alg-id",
    threw === "cms/bad-alg-id");
}

function testParseSignedDataRefusesNonSequenceEncapInfo() {
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var inner     = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    asn1.writeInteger(Buffer.from([0x07])),   // encapContentInfo should be a SEQUENCE
    asn1.writeNode(0x31, Buffer.alloc(0)),
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("non-SEQUENCE encapContentInfo refused with cms/bad-signed-data",
    threw === "cms/bad-signed-data");
}

function testParseSignedDataRefusesEmptyEncapInfo() {
  // encapContentInfo SEQUENCE is empty → _readEncapContent throws cms/bad-encap.
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var inner     = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    asn1.writeNode(0x30, Buffer.alloc(0)),   // empty encapContentInfo
    asn1.writeNode(0x31, Buffer.alloc(0)),
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("empty encapContentInfo refused with cms/bad-encap", threw === "cms/bad-encap");
}

function testParseSignedDataRefusesNonSetSignerInfos() {
  // 4 children, valid digest + encap, but signerInfos slot is an INTEGER.
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var encap     = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var inner     = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    encap,
    asn1.writeInteger(Buffer.from([0x09])),   // signerInfos should be a SET
  ]));
  var ci = _wrapContentInfo(SIGNED_DATA_OID, inner);
  var threw = null;
  try { b.cms.parseSignedData(ci); }
  catch (e) { threw = e.code; }
  check("non-SET signerInfos refused with cms/bad-signed-data",
    threw === "cms/bad-signed-data");
}

function testParseSignedDataWalksCrlsAndCraftedSignerInfo() {
  // Hand-crafted SignedData exercising the certs [0] + crls [1] skip
  // branches and a minimal _readSignerInfo (no signedAttrs) in one walk.
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var encap     = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var certsBlk  = asn1.writeNode(0xa0, _minimalCertDer());
  var crlsBlk   = asn1.writeNode(0xa1, asn1.writeNode(0x30, asn1.writeInteger(Buffer.from([0x01]))));

  var si = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),                                  // version
    asn1.writeInteger(Buffer.from([0x07])),                                  // sid placeholder
    asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")),          // digestAlgId
    asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18")),          // sigAlgId
    asn1.writeOctetString(Buffer.from([0x01, 0x02, 0x03])),                  // signature
  ]));
  var signerInfos = asn1.writeNode(0x31, si);

  var inner = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    encap,
    certsBlk,
    crlsBlk,
    signerInfos,
  ]));
  var parsed = b.cms.parseSignedData(_wrapContentInfo(SIGNED_DATA_OID, inner));
  check("crafted SignedData exposes one signerInfo with the sigAlg OID",
    parsed.signerInfos.length === 1 &&
    parsed.signerInfos[0].sigAlgOid === "2.16.840.1.101.3.4.3.18");
  check("crafted SignedData walks certs [0] into certificates[]",
    parsed.certificates.length === 1);
  check("crafted SignedData signerInfo has null signedAttrsRaw when absent",
    parsed.signerInfos[0].signedAttrsRaw === null);
}

function testParseSignedDataRefusesShortSignerInfo() {
  // signerInfos SET member with <5 children → cms/bad-signer-info.
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var encap     = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var shortSi   = asn1.writeNode(0x30, asn1.writeInteger(Buffer.from([0x01])));   // 1 child only
  var inner     = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    encap,
    asn1.writeNode(0x31, shortSi),
  ]));
  var threw = null;
  try { b.cms.parseSignedData(_wrapContentInfo(SIGNED_DATA_OID, inner)); }
  catch (e) { threw = e.code; }
  check("short SignerInfo refused with cms/bad-signer-info",
    threw === "cms/bad-signer-info");
}

function testParseSignedDataRefusesNonOctetStringSignature() {
  // A 5-child SignerInfo whose signature slot is an INTEGER, not OCTET STRING.
  var digestSet = asn1.writeNode(0x31, asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")));
  var encap     = asn1.writeNode(0x30, asn1.writeOid("1.2.840.113549.1.7.1"));
  var si = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    asn1.writeInteger(Buffer.from([0x07])),
    asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.2.10")),
    asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18")),
    asn1.writeInteger(Buffer.from([0x09])),   // signature should be OCTET STRING
  ]));
  var inner = asn1.writeNode(0x30, Buffer.concat([
    asn1.writeInteger(Buffer.from([0x01])),
    digestSet,
    encap,
    asn1.writeNode(0x31, si),
  ]));
  var threw = null;
  try { b.cms.parseSignedData(_wrapContentInfo(SIGNED_DATA_OID, inner)); }
  catch (e) { threw = e.code; }
  check("non-OCTET-STRING signature refused with cms/bad-signer-info",
    threw === "cms/bad-signer-info");
}

function run() {
  testEncodeSignedDataRefusesMissingOpts();
  testEncodeSignedDataRefusesNonBufferEncap();
  testEncodeSignedDataRefusesNonObjectSigner();
  testEncodeSignedDataRefusesSignerWithoutCert();
  testEncodeSignedDataRefusesNonUint8SecretKey();
  testEncodeSignedDataRefusesNonBufferCertificate();
  testEncodeSignedDataSignFailsOnShortKey();
  testEncodeSignedDataDetachedOmitsContent();
  testEncodeSignedDataGeneralizedTimeBranch();
  testCertNonSequenceRefused();
  testCertMissingTbsRefused();
  testCertMissingSerialRefused();
  testCertMissingSignatureAlgIdRefused();
  testCertMissingIssuerRefused();
  testCertWithVersionTagAccepted();
  testEncodeEnvelopedDataRefusesMissingOpts();
  testEncodeEnvelopedDataRefusesNonBufferPlaintext();
  testEncodeEnvelopedDataRefusesNonObjectRecipient();
  testEncodeEnvelopedDataRefusesNonUint8PublicKey();
  testEncodeEnvelopedDataRefusesNonBufferRecipientId();
  testEncodeEnvelopedDataKemEncapFailsOnShortKey();
  testDecodeRefusesBadAsn1();
  testDecodeRefusesTruncatedBody();
  testDecodeRefusesTooFewChildren();
  testDecodeRefusesNonOidContentType();
  testDecodeRefusesNonExplicitContent();
  testParseSignedDataRefusesNonSignedDataOid();
  testParseSignedDataRefusesNonSequenceInner();
  testParseSignedDataRefusesTooFewChildren();
  testParseSignedDataRefusesNonSetDigestAlgs();
  testParseSignedDataRefusesBadAlgIdInDigestSet();
  testParseSignedDataRefusesNonSequenceEncapInfo();
  testParseSignedDataRefusesEmptyEncapInfo();
  testParseSignedDataRefusesNonSetSignerInfos();
  testParseSignedDataWalksCrlsAndCraftedSignerInfo();
  testParseSignedDataRefusesShortSignerInfo();
  testParseSignedDataRefusesNonOctetStringSignature();
  testSignedDataRoundtripMlDsa65();
  testParseSignedDataWalker();
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
