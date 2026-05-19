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
    //      The CMS SignedData carries the leaf cert (we embedded it
    //      via the encodeSignedData certificates field). With the CA
    //      PEM as the trust anchor, verify walks leaf → CA.
    //
    //      For this composition to work we need to re-encode the
    //      SignedData with the leaf cert in the certificates [0]
    //      block — the sign() path above only embedded it via the
    //      SignerInfo's issuerAndSerialNumber pointer. Re-encode
    //      manually here to exercise the chain path.
    var signedWithCerts = b.cms.encodeSignedData({
      encapContent: Buffer.from(message, "utf8"),
      digestAlg:    "sha3-512",
      certificates: [leafCertDer],
      signers: [{
        certificate: leafCertDer,
        secretKey:   signerKp.secretKey,
        sigAlg:      "ML-DSA-65",
      }],
    });
    var verifiedChain = b.mail.crypto.smime.verify({
      message:             Buffer.from(message, "utf8"),
      signature:           signedWithCerts,
      signerPublicKey:     signerKp.publicKey,
      trustAnchorCertsPem: [caBundle.caCertPem],
    });
    check("smime.verify: chain validates against trust anchor",
      verifiedChain && verifiedChain.valid === true &&
      verifiedChain.chainVerified === true);

    // ---- Untrusted-chain refusal: supply an UNRELATED trust anchor.
    var unrelatedCa = b.mtlsCa.create({
      dataDir:           fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smime-other-")),
      caKeySealedMode:   "disabled",
    });
    var unrelatedBundle = await unrelatedCa.initCA();
    threw = null;
    try {
      b.mail.crypto.smime.verify({
        message:             Buffer.from(message, "utf8"),
        signature:           signedWithCerts,
        signerPublicKey:     signerKp.publicKey,
        trustAnchorCertsPem: [unrelatedBundle.caCertPem],
      });
    } catch (eC) { threw = eC.code; }
    check("smime.verify: refuses unrelated trust anchor",
      threw === "mail-crypto/smime/untrusted-chain");

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
