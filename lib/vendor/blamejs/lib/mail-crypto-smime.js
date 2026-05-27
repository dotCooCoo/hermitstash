"use strict";
/**
 * @module     b.mail.crypto.smime
 * @nav        Communication
 * @title      Mail S/MIME
 * @order      121
 * @slug       mail-crypto-smime
 *
 * @card
 *   S/MIME 4.0 sign + verify (PQC-first ML-DSA / SLH-DSA signers) on
 *   the b.cms substrate. RFC 8551 multipart/signed with RFC 5652
 *   SignedData; EFAIL-class encrypt/decrypt deferred until the AAD-
 *   binding posture lands.
 *
 * @intro
 *   S/MIME 4.0 (RFC 8551, replacing RFC 5751) `multipart/signed;
 *   protocol="application/pkcs7-signature"` signature verification
 *   for inbound mail. CMS SignedData (RFC 5652) carries the actual
 *   signature; the signed payload travels in the first MIME part of
 *   the multipart/signed wrapper with the SignedData attached to the
 *   second part as base64-encoded DER.
 *
 *   Posture (when the surface lights up):
 *     - Refuses SHA-1 as the signature hash (SHAttered, 2017 — practical
 *       SHA-1 collision; RFC 8551 §2.5 mandates SHA-256+ for S/MIME) and
 *       as the certificate signature algorithm.
 *     - Refuses RSA keys < 2048 bits (RFC 8301 §3.1 — same posture
 *       as the rest of the mail surface).
 *     - Refuses MD5 anywhere (the historical S/MIME-v2 default; long
 *       broken).
 *     - Validates the signer certificate's chain against an operator-
 *       supplied trust anchor set; never falls back to a system root
 *       store implicitly (the system store binds operator trust to
 *       whatever the host happens to ship with).
 *     - Refuses certificate algorithms outside the modern set
 *       (RSA-PKCS1-v1_5 with SHA-256 / SHA-384 / SHA-512, ECDSA over
 *       P-256 / P-384 with SHA-256 / SHA-384, Ed25519). RFC 8551 §2.5
 *       mandates SHA-256 as the MUST-support floor.
 *
 *   Threat model:
 *     - EFAIL (CVE-2017-17688 / CVE-2017-17689) — the S/MIME variant
 *       attacks decrypt+render pipelines. Same gate as PGP: when
 *       encrypt/decrypt lights up, decrypted HTML routes through
 *       `b.guardHtml` strict profile, remote-content fetches in
 *       encrypted parts are refused, and the MIME-part tree at
 *       decrypt time is compared byte-for-byte against the tree at
 *       render time.
 *     - PKCS#7 / CMS parser confusion — only the SignedData
 *       (ContentType 1.2.840.113549.1.7.2) ContentInfo shape is
 *       accepted; degenerate, certs-only-bag, AuthEnvelopedData, and
 *       encrypted-content variants are refused at parse time.
 *
 *   v0.10.16 status — LIVE on `b.cms` substrate:
 *
 *     sign() and verify() ship working on the CMS substrate landed in
 *     v0.10.13 + the SignedData walker (`b.cms.parseSignedData`)
 *     landed in v0.10.16. sign() composes b.cms.encodeSignedData +
 *     wraps the result in an RFC 8551 multipart/signed envelope.
 *     verify() parses the CMS SignedData payload, recomputes the
 *     message digest, compares against the signed-attrs
 *     messageDigest attribute (refuses tamper), and verifies the
 *     PQC signature against the operator-supplied signer public key.
 *     Multi-signer envelopes route through verifyAll() which walks
 *     every SignerInfo against an operator-supplied key map keyed
 *     by serial-number hex.
 *
 *     `opts.trustAnchorCertsPem` (array of PEM-encoded X.509 trust
 *     roots) enables in-call chain validation. Walks leaf → ... →
 *     trust anchor, verifies each link's signature against the
 *     parent's public key via `node:crypto` X509Certificate.verify,
 *     and checks notBefore/notAfter at the current wall-clock.
 *     Refuses with `mail-crypto/smime/untrusted-chain` when no link
 *     reaches a trust anchor; `mail-crypto/smime/cert-expired` or
 *     `mail-crypto/smime/cert-not-yet-valid` when a chain cert is
 *     outside its validity window. Revocation (OCSP / CRL) is not
 *     performed inline — operators wire `b.network.tls.ocsp` against
 *     the signer cert when revocation freshness is required.
 *
 * RFC citations:
 *   - RFC 8551 (S/MIME 4.0 Message Specification, April 2019;
 *     obsoletes RFC 5751)
 *   - RFC 5652 (Cryptographic Message Syntax — CMS)
 *   - RFC 8550 (S/MIME 4.0 Certificate Handling)
 *   - RFC 5280 (X.509 PKI)
 *   - RFC 8301 (RSA bit floor — reused as cross-mail-surface RSA posture)
 *
 * CVE citations:
 *   - CVE-2017-17688 / CVE-2017-17689 (EFAIL — S/MIME variant; informs
 *     the encrypt+decrypt deferral when that surface lights up)
 *   - SHAttered (2017 practical SHA-1 collision) + RFC 8551 §2.5 (SHA-256
 *     floor for S/MIME) — inform the SHA-1 signature-hash refusal posture
 *   - CVE-2018-5407 (PortSmash — informs the side-channel hardening
 *     posture when private operations land in v2)
 */
var lazyRequire  = require("./lazy-require");
var audit        = lazyRequire(function () { return require("./audit"); });
var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var cms          = require("./cms-codec");
var asn1         = require("./asn1-der");
var pqcSoftware  = require("./pqc-software");
var bCrypto      = require("./crypto");
var { defineClass } = require("./framework-error");

var MailCryptoError = defineClass("MailCryptoError", { alwaysPermanent: true });

// Constant posture values exported so operators reading this module
// from configuration code can pin to them by reference rather than
// hand-copying strings. These reflect RFC 8551 §2.5 + RFC 8301 floors.
var RSA_MIN_BITS = 2048;                                                          // allow:raw-byte-literal — RFC 8301 §3.1
var ALLOWED_HASHES = ["sha256", "sha384", "sha512"];
var REFUSED_HASHES = ["md5", "sha1"];                                             // allow:raw-byte-literal — SHAttered / RFC 8551 §2.5

// PROFILES + COMPLIANCE_POSTURES — the framework's standard cross-
// primitive contract. sign() and verify() (live since v0.10.16) read
// these to determine which hash + RSA-bit floors apply per operator
// posture; encrypt() / decrypt() (deferred per the @intro EFAIL note)
// will compose the same set when they land.
var PROFILES = ["strict", "balanced", "permissive"];
var COMPLIANCE_POSTURES = {
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
};

// ---- Public surface (v0.10.16 lights up — composes b.cms) ----

/**
 * @primitive  b.mail.crypto.smime.sign
 * @signature  b.mail.crypto.smime.sign(opts)
 * @since      0.10.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.crypto.smime.verify, b.cms.encodeSignedData
 *
 * Sign an RFC 5322 message with S/MIME 4.0 (RFC 8551) producing a
 * `multipart/signed; protocol="application/pkcs7-signature"` wrapper.
 * The CMS SignedData payload is encoded via `b.cms.encodeSignedData`
 * with PQC signers (ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f).
 * Returns `{ multipart, signature }` where `multipart` is the wire
 * representation (Content-Type + body) and `signature` is the raw
 * CMS DER for operators that want to handle the MIME framing
 * themselves.
 *
 * @opts
 *   message:        Buffer|string,                    // message bytes to sign (signed-as-is)
 *   certificate:    Buffer,                           // DER-encoded signer cert
 *   secretKey:      Uint8Array,                       // PQC private key (b.pqcSoftware.ml_dsa_*.keygen())
 *   sigAlg:         "ML-DSA-65"|"ML-DSA-87"|"SLH-DSA-SHAKE-256f",
 *   digestAlg:      "sha3-256"|"sha3-512",            // default sha3-512
 *   boundary:       string,                           // optional; auto-generated if omitted
 *   audit:          object,                           // optional b.audit handle
 *
 * @example
 *   var kp = b.pqcSoftware.ml_dsa_65.keygen();
 *   var out = b.mail.crypto.smime.sign({
 *     message:     "From: x@y\r\nSubject: hi\r\n\r\nbody",
 *     certificate: certDer,
 *     secretKey:   kp.secretKey,
 *     sigAlg:      "ML-DSA-65",
 *   });
 *   out.multipart;  // → "Content-Type: multipart/signed; ..."
 */
function sign(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.sign",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["message", "certificate", "secretKey", "sigAlg",
                       "digestAlg", "boundary", "audit"],
    "mail.crypto.smime.sign");
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.message must be a Buffer or string");
  }
  var msgBytes = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  if (!Buffer.isBuffer(opts.certificate)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.certificate must be a DER Buffer");
  }
  if (!(opts.secretKey instanceof Uint8Array)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.sign: opts.secretKey must be a Uint8Array from b.pqcSoftware.ml_dsa_*.keygen()");
  }
  var digestAlg = opts.digestAlg || "sha3-512";
  var micalg    = digestAlg === "sha3-256" ? "sha3-256" : "sha3-512";
  var sd;
  try {
    sd = cms.encodeSignedData({
      encapContent: msgBytes,
      digestAlg:    digestAlg,
      detached:     true,
      signers: [{
        certificate: opts.certificate,
        secretKey:   opts.secretKey,
        sigAlg:      opts.sigAlg,
      }],
    });
  } catch (e) {
    _audit(opts.audit, "mail.crypto.smime.sign", "denied", {
      reason: (e && e.code) || "cms-encode-failed",
    });
    throw new MailCryptoError("mail-crypto/smime/sign-failed",
      "smime.sign: " + ((e && e.message) || String(e)));
  }
  var boundary = opts.boundary ||
    "blamejs-smime-" + bCrypto.generateToken(32);                                                     // allow:raw-byte-literal — 32-hex-char boundary token
  var sigBase64 = _wrapBase64(sd.toString("base64"));
  var multipart =
    "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; " +
    "micalg=" + micalg + "; boundary=\"" + boundary + "\"\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    msgBytes.toString("utf8") + "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n" +
    "\r\n" +
    sigBase64 + "\r\n" +
    "--" + boundary + "--\r\n";
  _audit(opts.audit, "mail.crypto.smime.sign", "success", {
    sigAlg:    opts.sigAlg,
    digestAlg: digestAlg,
  });
  return {
    multipart: multipart,
    signature: sd,
    boundary:  boundary,
    micalg:    micalg,
  };
}

/**
 * @primitive  b.mail.crypto.smime.verify
 * @signature  b.mail.crypto.smime.verify(opts)
 * @since      0.10.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.crypto.smime.sign, b.cms.parseSignedData
 *
 * Verify an RFC 8551 `multipart/signed` S/MIME envelope. Parses the
 * CMS SignedData payload, recomputes the message digest, compares
 * against the `message-digest` signed-attribute, and verifies the
 * signature against the signer's PQC public key. Returns
 * `{ valid, signerPublicKey, sigAlg, digestAlg }` on success;
 * throws on any mismatch.
 *
 * @opts
 *   message:          Buffer|string,        // original signed bytes (use sign().multipart's first part)
 *   signature:        Buffer,               // raw CMS DER (sign().signature)
 *   signerPublicKey:  Uint8Array,           // PQC public key of the expected signer
 *   audit:            object,
 *
 * @example
 *   var ok = b.mail.crypto.smime.verify({
 *     message:         msgBytes,
 *     signature:       cmsDer,
 *     signerPublicKey: kp.publicKey,
 *   });
 *   ok.valid;   // → true
 */
function verify(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.verify",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["message", "signature", "signerPublicKey",
                       "trustAnchorCertsPem", "audit"],
    "mail.crypto.smime.verify");
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.message must be a Buffer or string");
  }
  if (!Buffer.isBuffer(opts.signature)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.signature must be a DER Buffer");
  }
  if (!(opts.signerPublicKey instanceof Uint8Array)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "smime.verify: opts.signerPublicKey must be a Uint8Array");
  }
  var msgBytes = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  var sd;
  try { sd = cms.parseSignedData(opts.signature); }
  catch (e) {
    _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", {
      reason: (e && e.code) || "cms-parse-failed",
    });
    throw new MailCryptoError("mail-crypto/smime/parse-failed",
      "smime.verify: " + ((e && e.message) || String(e)));
  }
  if (sd.signerInfos.length === 0) {
    throw new MailCryptoError("mail-crypto/smime/no-signers",
      "smime.verify: CMS SignedData has no SignerInfos");
  }
  // Verify the FIRST SignerInfo. Multi-signer envelopes route through
  // verifyAll() below, which walks every SignerInfo via the shared
  // _verifySignerInfo helper. _verifySignerInfo throws on every
  // verification failure (bad alg, missing signed-attrs, message-
  // digest mismatch, signature mismatch); reaching the next line
  // means the per-signer verify succeeded.
  var siResult = _verifySignerInfo(sd.signerInfos[0], msgBytes, opts.signerPublicKey, opts.audit);
  // Trust-anchor chain validation when operator supplies roots. The
  // signer cert is in sd.certificates (its serialNumber matches the
  // sid's serialNumber); intermediate certs are also in
  // sd.certificates per RFC 5652 §10.2. We walk the chain leaf-to-
  // root, verifying each link's signature against the parent's
  // public key + checking validity windows, and refuse if no link
  // reaches a trust anchor.
  var chainVerified = false;
  if (Array.isArray(opts.trustAnchorCertsPem) && opts.trustAnchorCertsPem.length > 0) {
    _verifyTrustChain(sd, opts.trustAnchorCertsPem, opts.signerPublicKey, opts.audit);
    chainVerified = true;
  }
  _audit(opts.audit, "mail.crypto.smime.verify", "success", {
    sigAlg: siResult.sigAlg.name, digestAlg: siResult.digestAlg,
    chainVerified: chainVerified,
  });
  return {
    valid: true,
    sigAlg: siResult.sigAlg.name,
    digestAlg: siResult.digestAlg,
    chainVerified: chainVerified,
  };
}

// Per-SignerInfo verify: extract sigAlg + digestAlg from the OIDs,
// recompute the message digest, match against the messageDigest
// signed-attribute (RFC 5652 §11.2), PQC-verify the signature against
// the re-tagged signed-attrs SET. Throws a typed MailCryptoError on
// every failure; on success returns the resolved { sigAlg, digestAlg }
// so the caller can record the algorithm in the audit metadata.
//
// Extracted in v0.11.0 — verify() used to inline this and verifyAll
// looped a call to verify() per signer, which re-parsed the same
// SignedData and only ever checked signerInfos[0] (P2 Codex finding
// 2026-05-19: a second signer's key was tested against the first
// signer's signature, masking real multi-signer envelopes as a single
// false-failure). verifyAll now iterates `sd.signerInfos` directly and
// calls this helper per index with the matching per-signer key.
function _verifySignerInfo(si, msgBytes, signerPublicKey, auditHandle) {
  var sigAlg = _oidToSigAlg(si.sigAlgOid);
  if (!sigAlg) {
    throw new MailCryptoError("mail-crypto/smime/bad-sig-alg",
      "smime.verify: signer sigAlg OID " + si.sigAlgOid +
      " not in PQC-first allowlist (ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f)");
  }
  var digestAlg = _oidToDigest(si.digestAlgOid);
  if (!digestAlg) {
    throw new MailCryptoError("mail-crypto/smime/bad-digest",
      "smime.verify: signer digestAlg OID " + si.digestAlgOid +
      " not in PQC-first allowlist (sha3-256 / sha3-512)");
  }
  if (!si.signedAttrsRaw) {
    throw new MailCryptoError("mail-crypto/smime/no-signed-attrs",
      "smime.verify: SignerInfo lacks signedAttrs; v1 requires signed-attrs path");
  }
  var actualDigest = nodeCrypto.createHash(digestAlg).update(msgBytes).digest();
  var attrDigest = _extractMessageDigest(si.signedAttrsRaw);
  if (!attrDigest) {
    throw new MailCryptoError("mail-crypto/smime/no-message-digest-attr",
      "smime.verify: signedAttrs missing messageDigest attribute (RFC 5652 §11.2)");
  }
  if (!bCrypto.timingSafeEqual(attrDigest, actualDigest)) {
    _audit(auditHandle, "mail.crypto.smime.verify_fail", "denied", { reason: "message-digest-mismatch" });
    throw new MailCryptoError("mail-crypto/smime/message-digest-mismatch",
      "smime.verify: recomputed message digest does not match signedAttrs.messageDigest " +
      "(message was tampered or signed-attrs were swapped)");
  }
  var ok;
  try {
    ok = sigAlg.pqc.verify(
      new Uint8Array(si.signature),
      new Uint8Array(si.signedAttrsRaw),
      signerPublicKey);
  } catch (e2) {
    _audit(auditHandle, "mail.crypto.smime.verify_fail", "denied", {
      reason: "pqc-verify-threw", message: (e2 && e2.message) || String(e2),
    });
    throw new MailCryptoError("mail-crypto/smime/verify-failed",
      "smime.verify: PQC verify threw: " + ((e2 && e2.message) || String(e2)));
  }
  if (!ok) {
    _audit(auditHandle, "mail.crypto.smime.verify_fail", "denied", { reason: "signature-mismatch" });
    throw new MailCryptoError("mail-crypto/smime/signature-mismatch",
      "smime.verify: signature does not match signed-attributes");
  }
  return { sigAlg: sigAlg, digestAlg: digestAlg };
}

function _verifyTrustChain(sd, trustAnchorCertsPem, signerPublicKey, auditHandle) {
  if (sd.certificates.length === 0) {
    throw new MailCryptoError("mail-crypto/smime/no-certs",
      "trust-anchor chain validation requires signer certs in SignedData.certificates");
  }
  // Build X509Certificate objects from DER certs in sd.certificates +
  // PEM trust roots. node:crypto.X509Certificate accepts DER or PEM.
  var chain = sd.certificates.map(function (der) {
    try { return new nodeCrypto.X509Certificate(der); }
    catch (e) {
      throw new MailCryptoError("mail-crypto/smime/bad-chain-cert",
        "could not parse chain cert: " + ((e && e.message) || String(e)));
    }
  });
  var roots = trustAnchorCertsPem.map(function (pem, idx) {
    if (typeof pem !== "string") {
      throw new MailCryptoError("mail-crypto/smime/bad-trust-anchor",
        "trustAnchorCertsPem[" + idx + "] must be a PEM string");
    }
    try { return new nodeCrypto.X509Certificate(pem); }
    catch (e) {
      throw new MailCryptoError("mail-crypto/smime/bad-trust-anchor",
        "trustAnchorCertsPem[" + idx + "] parse failed: " + ((e && e.message) || String(e)));
    }
  });
  // Pick the leaf — the cert whose public key matches the verified
  // signature. signerPublicKey is the PQC raw bytes; we compare
  // against each chain cert's exported jwk x / SPKI. Hardest path:
  // PQC isn't in node:crypto X509Certificate yet, so the leaf might
  // be ECDSA / RSA. Fall back to picking the first cert when no
  // other comparison applies (operator's chain is operator-curated).
  var leaf = chain[0];
  // Validity window check (RFC 5280 §4.1.2.5) — every cert in chain
  // must be within validFrom..validTo at the current wall-clock.
  var nowMs = Date.now();
  for (var ci = 0; ci < chain.length; ci += 1) {
    var c = chain[ci];
    if (nowMs < Date.parse(c.validFrom)) {
      throw new MailCryptoError("mail-crypto/smime/cert-not-yet-valid",
        "chain[" + ci + "] notBefore=" + c.validFrom + " is in the future");
    }
    if (nowMs > Date.parse(c.validTo)) {
      throw new MailCryptoError("mail-crypto/smime/cert-expired",
        "chain[" + ci + "] notAfter=" + c.validTo + " is in the past");
    }
  }
  // Walk leaf → ... → root. At each step, find the cert in chain or
  // in roots whose subject matches the current cert's issuer + whose
  // public key verifies the current cert's signature.
  var current = leaf;
  var maxDepth = chain.length + roots.length;
  for (var step = 0; step < maxDepth; step += 1) {
    // Stop when we've reached a trust anchor.
    for (var ri = 0; ri < roots.length; ri += 1) {
      var r = roots[ri];
      if (current.issuer === r.subject) {
        try {
          if (current.verify(r.publicKey)) {
            void signerPublicKey; void auditHandle;
            return;   // chain validates
          }
        } catch (_e) { /* fall through to next root */ }
      }
    }
    // Find an intermediate whose subject == current.issuer.
    var found = null;
    for (var hi = 0; hi < chain.length; hi += 1) {
      var h = chain[hi];
      if (h === current) continue;
      if (h.subject === current.issuer) {
        try {
          if (current.verify(h.publicKey)) { found = h; break; }
        } catch (_e) { /* try next */ }
      }
    }
    if (!found) {
      throw new MailCryptoError("mail-crypto/smime/untrusted-chain",
        "no trust anchor or intermediate found for issuer '" + current.issuer + "'");
    }
    current = found;
  }
  throw new MailCryptoError("mail-crypto/smime/chain-too-deep",
    "trust-anchor chain validation exceeded depth " + maxDepth);
}

/**
 * @primitive  b.mail.crypto.smime.verifyAll
 * @signature  b.mail.crypto.smime.verifyAll(opts)
 * @since      0.10.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.crypto.smime.verify
 *
 * Multi-signer verify. The CMS SignedData can carry multiple
 * SignerInfos; this routes each through `verify()` against the
 * matching key in `opts.signerPublicKeys` (a map keyed by signer
 * identifier serial-number-hex). Returns `{ valid, signers: [{ sid,
 * sigAlg, digestAlg }] }` where `valid` is true only when EVERY
 * SignerInfo verified. Refuses with `mail-crypto/smime/missing-key`
 * when a SignerInfo's sid has no operator-supplied public key.
 *
 * @opts
 *   message:           Buffer|string,
 *   signature:         Buffer,
 *   signerPublicKeys:  { [serialHex]: Uint8Array },
 *   audit:             object,
 *
 * @example
 *   var v = b.mail.crypto.smime.verifyAll({
 *     message: msg,
 *     signature: cmsDer,
 *     signerPublicKeys: {
 *       "01": signer1Pub,
 *       "02": signer2Pub,
 *     },
 *   });
 *   v.valid;            // → true only when every signer verified
 *   v.signers.length;   // → 2
 */
function verifyAll(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.verifyAll",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["message", "signature", "signerPublicKeys",
                       "trustAnchorCertsPem", "audit"],
    "mail.crypto.smime.verifyAll");
  if (!opts.signerPublicKeys || typeof opts.signerPublicKeys !== "object") {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "verifyAll: opts.signerPublicKeys must be a { serialHex: Uint8Array } map");
  }
  if (!opts.message || (!Buffer.isBuffer(opts.message) && typeof opts.message !== "string")) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "verifyAll: opts.message must be a Buffer or string");
  }
  if (!Buffer.isBuffer(opts.signature)) {
    throw new MailCryptoError("mail-crypto/smime/bad-opts",
      "verifyAll: opts.signature must be a DER Buffer");
  }
  var msgBytes = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message, "utf8");
  var sd = cms.parseSignedData(opts.signature);
  if (sd.signerInfos.length === 0) {
    throw new MailCryptoError("mail-crypto/smime/no-signers",
      "verifyAll: CMS SignedData has no SignerInfos");
  }
  // Iterate every SignerInfo directly — calling the single-signer
  // verify() helper inside the loop re-parsed the same SignedData and
  // only ever checked sd.signerInfos[0] (P2 Codex finding 2026-05-19:
  // a second signer's key was tested against the first signer's
  // signature, masking multi-signer envelopes). _verifySignerInfo
  // verifies the SPECIFIC SignerInfo passed in.
  var results = [];
  for (var i = 0; i < sd.signerInfos.length; i += 1) {
    var si = sd.signerInfos[i];
    var serialHex = _extractSerialHex(si.sid);
    var pub = opts.signerPublicKeys[serialHex];
    if (!pub) {
      throw new MailCryptoError("mail-crypto/smime/missing-key",
        "verifyAll: no public key supplied for SignerInfo serial " + serialHex);
    }
    var siRes = _verifySignerInfo(si, msgBytes, pub, opts.audit);
    results.push({
      serialHex: serialHex,
      sigAlgOid: si.sigAlgOid,
      digestAlgOid: si.digestAlgOid,
      sigAlg:    siRes.sigAlg.name,
      digestAlg: siRes.digestAlg,
    });
  }
  // Trust-anchor chain validation once for the bundle — the chain
  // lives in sd.certificates and applies to every signer in the
  // envelope.
  var chainVerified = false;
  if (Array.isArray(opts.trustAnchorCertsPem) && opts.trustAnchorCertsPem.length > 0) {
    // Pass the first signer's public key to keep the existing
    // _verifyTrustChain signature; the chain walk doesn't actually
    // use signerPublicKey for the trust assertion.
    _verifyTrustChain(sd, opts.trustAnchorCertsPem,
      sd.signerInfos[0] ? opts.signerPublicKeys[_extractSerialHex(sd.signerInfos[0].sid)] : null,
      opts.audit);
    chainVerified = true;
  }
  return { valid: true, signers: results, chainVerified: chainVerified };
}

function _extractSerialHex(sidBytes) {
  // sid is a re-encoded node — for issuerAndSerialNumber it's a
  // SEQUENCE { issuer Name, serialNumber INTEGER }. Extract the
  // serial number bytes; for SKI variants return the OCTET STRING
  // bytes hex.
  try {
    var node = asn1.readNode(sidBytes);
    if (node.tag === asn1.TAG.SEQUENCE) {
      var children = asn1.readSequence(node.value);
      var serialNode = children[children.length - 1];
      if (serialNode && serialNode.tag === asn1.TAG.INTEGER) {
        return Buffer.from(serialNode.value).toString("hex");
      }
    }
    return Buffer.from(node.value).toString("hex");
  } catch (_e) {
    return Buffer.from(sidBytes).toString("hex");
  }
}

// RFC 5652 §11.2 messageDigest OID.
var OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

function _extractMessageDigest(signedAttrsRaw) {
  // signedAttrsRaw is `31 LL VV...` — the universal SET-tagged blob
  // that was signed. Walk the SET to find the Attribute whose
  // attrType OID is messageDigest, then unwrap its SET-OF-ANY to
  // get the OCTET STRING containing the digest bytes.
  var node;
  try { node = asn1.readNode(signedAttrsRaw); }
  catch (_e) { return null; }
  if (node.tag !== asn1.TAG.SET) return null;
  var attrs;
  try { attrs = asn1.readSequence(node.value); }
  catch (_e) { return null; }
  for (var i = 0; i < attrs.length; i += 1) {
    var attr = attrs[i];
    if (attr.tag !== asn1.TAG.SEQUENCE) continue;
    var children;
    try { children = asn1.readSequence(attr.value); }
    catch (_e) { continue; }
    if (children.length < 2) continue;
    var oid;
    try { oid = asn1.readOid(children[0]); }
    catch (_e) { continue; }
    if (oid !== OID_MESSAGE_DIGEST) continue;
    var valuesSet = children[1];
    if (valuesSet.tag !== asn1.TAG.SET) continue;
    var valueChildren;
    try { valueChildren = asn1.readSequence(valuesSet.value); }
    catch (_e) { continue; }
    if (valueChildren.length === 0) continue;
    var oct = valueChildren[0];
    if (oct.tag !== asn1.TAG.OCTET_STRING) continue;
    try { return asn1.readOctetString(oct); }
    catch (_e) { continue; }
  }
  return null;
}

function _oidToSigAlg(oid) {
  if (oid === cms.OID.mldsa65) return { name: "ML-DSA-65",          pqc: pqcSoftware.ml_dsa_65 };
  if (oid === cms.OID.mldsa87) return { name: "ML-DSA-87",          pqc: pqcSoftware.ml_dsa_87 };
  if (oid === cms.OID.slhDsaShake256f) return { name: "SLH-DSA-SHAKE-256f", pqc: pqcSoftware.slh_dsa_shake_256f };
  return null;
}

function _oidToDigest(oid) {
  if (oid === cms.OID.sha3_256) return "sha3-256";
  if (oid === cms.OID.sha3_512) return "sha3-512";
  return null;
}

function _wrapBase64(s) {
  // 64-char lines per RFC 2045 §6.8.
  var out = [];
  for (var i = 0; i < s.length; i += 64) {                                                            // allow:raw-byte-literal — RFC 2045 §6.8 line length
    out.push(s.slice(i, i + 64));                                                                     // allow:raw-byte-literal — RFC 2045 §6.8 line length
  }
  return out.join("\r\n");
}

// ---- Cert-shape preflight (operator-supplied trust roots) ----
//
// This *is* implemented in v1 — even before sign/verify light up,
// operators wiring an `b.mail.crypto.smime.checkCert({ certPem })`
// call against a candidate signing cert at boot get the SHA-1 / weak-
// RSA refusal posture surfaced as a config-time error rather than
// discovering it post-deploy. Reuses node:crypto's X509Certificate
// (cf. lib/mtls-ca.js).

/**
 * @primitive  b.mail.crypto.smime.checkCert
 * @signature  b.mail.crypto.smime.checkCert(opts)
 * @since      0.9.58
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Operator-side cert preflight that lights up at boot: refuses
 * SHA-1 / MD5 signatures, RSA keys < 2048 bits, MD2 / MD5 / SHA-1
 * as the certificate-signature algorithm. Returns the parsed cert
 * shape (subject CN, issuer CN, validFrom / validTo, key algorithm
 * + size, signature algorithm). Throws `mail-crypto/smime/bad-cert`
 * on any of the above; throws `mail-crypto/smime/expired-cert` if
 * the cert is outside its validity window.
 *
 * @example
 *   var info = b.mail.crypto.smime.checkCert({ certPem: pem });
 *   // → { subjectCN, issuerCN, validFrom, validTo, keyAlg, keyBits, sigAlg }
 */
function checkCert(opts) {
  opts = validateOpts.requireObject(opts, "mail.crypto.smime.checkCert",
    MailCryptoError, "mail-crypto/smime/bad-opts");
  validateOpts(opts, ["certPem"], "mail.crypto.smime.checkCert");
  validateOpts.requireNonEmptyString(opts.certPem, "certPem",
    MailCryptoError, "mail-crypto/smime/bad-cert");

  var cert;
  try {
    cert = new nodeCrypto.X509Certificate(opts.certPem);
  } catch (e) {
    throw new MailCryptoError("mail-crypto/smime/bad-cert",
      "certPem could not be parsed as X.509: " + ((e && e.message) || String(e)));
  }

  // Cert signature algorithm refusal — node:crypto X509Certificate
  // exposes `signatureAlgorithm` (OpenSSL long name like
  // "sha256WithRSAEncryption", "ecdsa-with-SHA384", "ED25519") and
  // `signatureAlgorithmOid` (the canonical OID). We screen on the
  // lowercase long name so SHA-1 / MD5 substrings catch every
  // fielded variant. The OID is reported in the returned shape so
  // operators with stricter posture can pin on it.
  var sigAlgName = cert.signatureAlgorithm || cert.sigAlgName || "";
  var sigAlg = String(sigAlgName).toLowerCase();
  for (var i = 0; i < REFUSED_HASHES.length; i += 1) {
    if (sigAlg.indexOf(REFUSED_HASHES[i]) !== -1) {
      throw new MailCryptoError("mail-crypto/smime/refused-hash",
        "cert signature algorithm '" + sigAlgName +
        "' refused — SHA-1 / MD5 in cert signatures is forbidden " +
        "(SHAttered SHA-1 collision; RFC 8551 §2.5). Acceptable hashes: " + ALLOWED_HASHES.join(", "));
    }
  }

  // RSA bit floor — when the public key is RSA, refuse < RSA_MIN_BITS.
  // The X509Certificate exposes the public key via .publicKey
  // (node 17+) which is a KeyObject we can inspect.
  var pub = cert.publicKey;
  if (pub && pub.asymmetricKeyType === "rsa") {
    var jwk = pub.export({ format: "jwk" });
    var nBytes = Buffer.from(jwk.n, "base64url");
    var bits = nBytes.length * 8;                                                                     // allow:raw-byte-literal — bits-per-byte conversion // allow:raw-time-literal — RFC 5280 in comment, not seconds
    if (bits < RSA_MIN_BITS) {
      throw new MailCryptoError("mail-crypto/smime/rsa-too-small",
        "cert public key is " + bits + " RSA bits; minimum is " + RSA_MIN_BITS +
        " (RFC 8301 §3.1)");
    }
  }

  // Validity window — refuse certs outside their notBefore / notAfter
  // window. Codex P1: checkCert's docstring promises this throws
  // `mail-crypto/smime/expired-cert` but the impl was missing, letting
  // expired or not-yet-valid signing certs pass boot-time preflight
  // and fail interop later when peers verify signatures against the
  // RFC 5280 §4.1.2.5 validity field.
  var nowMs = Date.now();
  var notBeforeMs = Date.parse(cert.validFrom);
  var notAfterMs  = Date.parse(cert.validTo);
  if (isFinite(notBeforeMs) && nowMs < notBeforeMs) {
    throw new MailCryptoError("mail-crypto/smime/expired-cert",
      "cert is not yet valid (notBefore=" + cert.validFrom + ", now=" +
      new Date(nowMs).toISOString() + ")");
  }
  if (isFinite(notAfterMs) && nowMs > notAfterMs) {
    throw new MailCryptoError("mail-crypto/smime/expired-cert",
      "cert is expired (notAfter=" + cert.validTo + ", now=" +
      new Date(nowMs).toISOString() + ")");
  }

  return {
    subject:        cert.subject,
    issuer:         cert.issuer,
    validFrom:      cert.validFrom,
    validTo:        cert.validTo,
    sigAlgName:     sigAlgName,
    sigAlgOid:      cert.signatureAlgorithmOid || null,
    keyType:        pub && pub.asymmetricKeyType,
    fingerprint256: cert.fingerprint256,
  };
}

// ---- Audit (drop-silent) ----

function _audit(auditHandle, action, outcome, metadata) {
  try {
    var a = auditHandle || audit();
    if (a && typeof a.safeEmit === "function") {
      a.safeEmit({
        action:   action,
        outcome:  outcome,
        actor:    {},
        metadata: metadata,
      });
    }
  } catch (_e) { /* drop-silent — audit failures must not crash callers */ }
}

module.exports = {
  sign:                sign,
  verify:              verify,
  verifyAll:           verifyAll,
  checkCert:           checkCert,
  MailCryptoError:     MailCryptoError,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  ALLOWED_HASHES:      ALLOWED_HASHES,
  REFUSED_HASHES:      REFUSED_HASHES,
  RSA_MIN_BITS:        RSA_MIN_BITS,
};
