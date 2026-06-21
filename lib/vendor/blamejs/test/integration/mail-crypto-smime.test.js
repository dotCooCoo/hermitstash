"use strict";
/**
 * Live S/MIME sign + verify round-trip using a real X.509 chain.
 *
 * Composes:
 *   - b.mtlsCa to bootstrap a CA + issue a leaf cert
 *   - b.mail.crypto.smime.sign to wrap the message in RFC 8551
 *     multipart/signed with PQC signers (ML-DSA-65)
 *   - b.mail.crypto.smime.verify to walk the SignedData payload and
 *     refuse tamper / signature mismatch / untrusted chain
 *
 * This exercises the v0.11.0 surface: trust-anchor chain validation
 * via node:crypto.X509Certificate walking the chain leaf-to-root
 * against the operator-supplied trustAnchorCertsPem set, with notBefore/
 * notAfter checks. The pure-PQC sign path means no classical RSA/ECDSA
 * cert is involved on the signer side; the CA is the only classical
 * piece (the framework's mtlsCa issues classical certs by default
 * because ML-DSA in X.509 is still draft).
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");
var asn1 = require("../../lib/asn1-der");
var cms  = require("../../lib/cms-codec");

// The S/MIME signer is pure-PQC (ML-DSA-65). Trust-chain validation in
// b.mail.crypto.smime.verify (since v0.13.42) binds the chain leaf to the
// key that actually verified the signature: it refuses unless a cert in
// SignedData.certificates carries that exact public key. b.mtlsCa issues
// classical (RSA/EC) leaf certs, whose key can never equal the ML-DSA
// signer key — so the chain leaf has to be an X.509 cert that embeds the
// ML-DSA-65 public key in its SubjectPublicKeyInfo. The framework has no
// ML-DSA X.509 issuer (ML-DSA in X.509 is still draft), so this builds a
// minimal RFC 5280 cert over the b.asn1Der writer + b.cms ML-DSA OID and
// signs the TBS with ML-DSA-65. node:crypto.X509Certificate parses it,
// exports the SPKI, and verifies the ML-DSA signature natively.
function _x509Name(cn) {
  var atv = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)]);
  return asn1.writeSequence([asn1.writeSet([atv])]);
}
function _x509GeneralizedTime(d) {
  function pad2(n) { return String(n).length >= 2 ? String(n) : "0" + n; }
  var s = d.getUTCFullYear() +
    pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate()) +
    pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + "Z";
  return asn1.writeNode(0x18, Buffer.from(s, "ascii"));   // 0x18 = GeneralizedTime
}
function _buildMlDsaCert(opts) {
  // opts: { subjectCn, subjectPubKey, issuerCn, issuerSecretKey, serial,
  //         notBefore, notAfter, isCa }. signatureAlgorithm == subject key
  // alg (ML-DSA-65) for both self-signed (CA) and issued (leaf) shapes.
  // isCa: true emits a critical basicConstraints cA:TRUE extension so the
  // cert is accepted as a chain issuer (a CA cert without it is rejected
  // by the cA-enforcing chain walk — RFC 5280 §4.2.1.9 / CVE-2002-0862).
  var algId = asn1.writeSequence([asn1.writeOid(cms.OID.mldsa65)]);
  var spki  = asn1.writeSequence([algId, asn1.writeBitString(Buffer.from(opts.subjectPubKey), 0)]);
  var tbsFields = [
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),   // version v3
    asn1.writeInteger(Buffer.from([opts.serial])),                       // serialNumber
    algId,                                                               // signature AlgorithmIdentifier
    _x509Name(opts.issuerCn),                                            // issuer
    asn1.writeSequence([_x509GeneralizedTime(opts.notBefore),
                        _x509GeneralizedTime(opts.notAfter)]),           // validity
    _x509Name(opts.subjectCn),                                           // subject
    spki,                                                                // SubjectPublicKeyInfo
  ];
  if (opts.isCa) {
    var bcValue = asn1.writeSequence([asn1.writeBoolean(true)]);         // BasicConstraints { cA TRUE }
    var bcExt = asn1.writeSequence([
      asn1.writeOid("2.5.29.19"),                                        // basicConstraints
      asn1.writeBoolean(true),                                           // critical
      asn1.writeOctetString(Buffer.from(bcValue)),                       // extnValue
    ]);
    tbsFields.push(asn1.writeContextExplicit(3, asn1.writeSequence([bcExt]))); // [3] EXPLICIT Extensions
  }
  var tbs = asn1.writeSequence(tbsFields);
  var sig = b.pqcSoftware.ml_dsa_65.sign(new Uint8Array(tbs), opts.issuerSecretKey);
  return asn1.writeSequence([tbs, algId, asn1.writeBitString(Buffer.from(sig), 0)]);
}
function _derToPem(der) {
  // 64-char line wrap. A regex replace adds a trailing newline when the
  // base64 length is an exact multiple of 64, which (combined with the
  // closing newline) yields a blank line mid-block that OpenSSL's PEM
  // reader treats as end-of-data — silently truncating the cert. Slice
  // explicitly so every line is full except the last.
  var b64 = Buffer.from(der).toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) { lines.push(b64.slice(i, i + 64)); }
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

async function run() {
  // ---- Spin up an isolated mTLS CA (caKeySealedMode=disabled keeps
  //      the CA private key on disk in plaintext — fine for the test
  //      fixture; production wires opts.vault for sealed-at-rest).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smime-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: tmpDir, caKeySealedMode: "disabled" });
    var caBundle = await ca.initCA();
    check("mtlsCa: caCertPem present", typeof caBundle.caCertPem === "string");

    // Issue a signer leaf cert. The leaf is RSA-2048 from b.mtlsCa
    // (which issues classical certs by default); we use its DER bytes
    // as the SignerInfo's issuerAndSerialNumber source.
    var leaf = await ca.generateClientCert({
      cn:           "smime-signer.blamejs-test.example",
      validityDays: 7,
    });
    var leafCertDer = Buffer.from(
      leaf.cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
      "base64");

    // ---- PQC signer for the SignerInfo. The cert's issuer/serial
    //      uniquely identifies which key signed the SignedData; the
    //      actual sign + verify uses ML-DSA-65.
    var pq = require("../../lib/pqc-software");
    var signerKp = pq.ml_dsa_65.keygen();

    // ---- Compose b.mail.crypto.smime.sign — produces an RFC 8551
    //      multipart/signed envelope with the CMS SignedData attached.
    var message = "From: signer@example\r\n" +
                  "To: alice@example\r\n" +
                  "Subject: live S/MIME roundtrip\r\n" +
                  "\r\n" +
                  "Live S/MIME roundtrip body.\r\n";

    var signed = b.mail.crypto.smime.sign({
      message:     message,
      certificate: leafCertDer,
      secretKey:   signerKp.secretKey,
      sigAlg:      "ML-DSA-65",
      digestAlg:   "sha3-512",
    });
    check("smime.sign: returns multipart envelope",
      typeof signed.multipart === "string" &&
      signed.multipart.indexOf("multipart/signed") !== -1);
    check("smime.sign: micalg names sha3-512",
      /micalg=("?)sha3-512\1/.test(signed.multipart));
    check("smime.sign: returns raw CMS signature DER",
      Buffer.isBuffer(signed.signature) && signed.signature.length > 0);

    // ---- Verify against the signer's public key. This walks the
    //      signed-attrs, extracts messageDigest, recomputes the digest
    //      of the message, refuses tamper, and PQC-verifies the
    //      signature.
    var verified = b.mail.crypto.smime.verify({
      message:         Buffer.from(message, "utf8"),
      signature:       signed.signature,
      signerPublicKey: signerKp.publicKey,
    });
    check("smime.verify: valid roundtrip",
      verified && verified.valid === true);
    check("smime.verify: sigAlg surfaced",
      verified && verified.sigAlg === "ML-DSA-65");

    // ---- Tamper test: flip a byte in the message; verify must refuse.
    var tampered = message.replace("Live", "Damn");
    var threw = null;
    try {
      b.mail.crypto.smime.verify({
        message:         Buffer.from(tampered, "utf8"),
        signature:       signed.signature,
        signerPublicKey: signerKp.publicKey,
      });
    } catch (e) { threw = e.code; }
    check("smime.verify: refuses tampered message body",
      threw === "mail-crypto/smime/message-digest-mismatch");

    // ---- Wrong-key test: verify with a different ML-DSA-65 key fails.
    var otherKp = pq.ml_dsa_65.keygen();
    threw = null;
    try {
      b.mail.crypto.smime.verify({
        message:         Buffer.from(message, "utf8"),
        signature:       signed.signature,
        signerPublicKey: otherKp.publicKey,
      });
    } catch (e) { threw = e.code; }
    check("smime.verify: refuses wrong signer public key",
      threw === "mail-crypto/smime/signature-mismatch");

    // ---- Trust-anchor chain validation — opts.trustAnchorCertsPem.
    //      verify() walks leaf → CA against the operator's trust anchor
    //      AND binds the leaf to the key that verified the signature
    //      (since v0.13.42): the chain leaf must be the cert carrying
    //      signerPublicKey, else the chain-validated result would assert
    //      a cert↔signer binding the code never made. The signer is
    //      ML-DSA-65, so the chain leaf must embed that ML-DSA key in its
    //      SubjectPublicKeyInfo — build a real ML-DSA cert chain (CA →
    //      leaf) carrying signerKp.publicKey, with the CA PEM as the
    //      trust anchor. The leaf goes into SignedData.certificates so
    //      verify() can locate + bind it.
    var caKp = b.pqcSoftware.ml_dsa_65.keygen();
    var nowD = new Date();
    var notBefore = new Date(nowD.getTime() - 60 * 60 * 1000);
    var notAfter  = new Date(nowD.getTime() + 7 * 24 * 60 * 60 * 1000);
    var caCertDer = _buildMlDsaCert({
      subjectCn:      "smime-pqc-ca.blamejs-test.example",
      subjectPubKey:  caKp.publicKey,
      issuerCn:       "smime-pqc-ca.blamejs-test.example",
      issuerSecretKey: caKp.secretKey,                                    // self-signed
      serial:         1,
      notBefore:      notBefore,
      notAfter:       notAfter,
      isCa:           true,                                               // trust anchor must assert cA:TRUE
    });
    var pqcLeafCertDer = _buildMlDsaCert({
      subjectCn:      "smime-signer.blamejs-test.example",
      subjectPubKey:  signerKp.publicKey,                                 // == the verified signer key
      issuerCn:       "smime-pqc-ca.blamejs-test.example",
      issuerSecretKey: caKp.secretKey,                                    // issued by the CA
      serial:         2,
      notBefore:      notBefore,
      notAfter:       notAfter,
    });
    var caCertPem = _derToPem(caCertDer);

    var signedWithCerts = b.cms.encodeSignedData({
      encapContent: Buffer.from(message, "utf8"),
      digestAlg:    "sha3-512",
      certificates: [pqcLeafCertDer],
      signers: [{
        certificate: pqcLeafCertDer,
        secretKey:   signerKp.secretKey,
        sigAlg:      "ML-DSA-65",
      }],
    });
    var verifiedChain = b.mail.crypto.smime.verify({
      message:             Buffer.from(message, "utf8"),
      signature:           signedWithCerts,
      signerPublicKey:     signerKp.publicKey,
      trustAnchorCertsPem: [caCertPem],
    });
    check("smime.verify: chain validates against trust anchor",
      verifiedChain && verifiedChain.valid === true &&
      verifiedChain.chainVerified === true);

    // ---- Untrusted-chain refusal: supply an UNRELATED trust anchor.
    //      A second, independent ML-DSA CA did not issue the leaf, so no
    //      chain link reaches it.
    var otherCaKp = b.pqcSoftware.ml_dsa_65.keygen();
    var unrelatedCaDer = _buildMlDsaCert({
      subjectCn:      "smime-pqc-other-ca.blamejs-test.example",
      subjectPubKey:  otherCaKp.publicKey,
      issuerCn:       "smime-pqc-other-ca.blamejs-test.example",
      issuerSecretKey: otherCaKp.secretKey,
      serial:         1,
      notBefore:      notBefore,
      notAfter:       notAfter,
    });
    threw = null;
    try {
      b.mail.crypto.smime.verify({
        message:             Buffer.from(message, "utf8"),
        signature:           signedWithCerts,
        signerPublicKey:     signerKp.publicKey,
        trustAnchorCertsPem: [_derToPem(unrelatedCaDer)],
      });
    } catch (eC) { threw = eC.code; }
    check("smime.verify: refuses unrelated trust anchor",
      threw === "mail-crypto/smime/untrusted-chain");

    // ---- Binding refusal: a validly-chained cert for a DIFFERENT key
    //      must NOT pass chain validation when the signature was verified
    //      under signerKp. Build a leaf carrying an UNRELATED ML-DSA key
    //      but properly issued by the trusted CA; verify() must refuse
    //      because no cert in the chain carries the verified signer key.
    var strangerKp = b.pqcSoftware.ml_dsa_65.keygen();
    var strangerLeafDer = _buildMlDsaCert({
      subjectCn:      "smime-stranger.blamejs-test.example",
      subjectPubKey:  strangerKp.publicKey,
      issuerCn:       "smime-pqc-ca.blamejs-test.example",
      issuerSecretKey: caKp.secretKey,
      serial:         3,
      notBefore:      notBefore,
      notAfter:       notAfter,
    });
    var signedWithStrangerCert = b.cms.encodeSignedData({
      encapContent: Buffer.from(message, "utf8"),
      digestAlg:    "sha3-512",
      certificates: [strangerLeafDer],
      signers: [{
        certificate: pqcLeafCertDer,
        secretKey:   signerKp.secretKey,
        sigAlg:      "ML-DSA-65",
      }],
    });
    threw = null;
    try {
      b.mail.crypto.smime.verify({
        message:             Buffer.from(message, "utf8"),
        signature:           signedWithStrangerCert,
        signerPublicKey:     signerKp.publicKey,
        trustAnchorCertsPem: [caCertPem],
      });
    } catch (eB) { threw = eB.code; }
    check("smime.verify: refuses chain leaf bound to a different key",
      threw === "mail-crypto/smime/signer-not-in-chain");

    // ---- X.509 sanity — confirm node:crypto can parse the leaf and
    //      verify its issuer matches the CA subject.
    var leafX509 = new nodeCrypto.X509Certificate(leaf.cert);
    var caX509   = new nodeCrypto.X509Certificate(caBundle.caCertPem);
    check("X509: leaf issuer == CA subject (chain shape valid)",
      leafX509.issuer === caX509.subject);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

run().then(
  function () { console.log("[mail-crypto-smime] OK"); },
  function (e) { console.error("[mail-crypto-smime] FAIL:", e.stack || e); process.exit(1); }
);
