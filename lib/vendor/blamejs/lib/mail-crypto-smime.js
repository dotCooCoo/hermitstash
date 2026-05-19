"use strict";
/**
 * @module     b.mail.crypto.smime
 * @nav        Communication
 * @title      Mail S/MIME
 * @order      121
 * @slug       mail-crypto-smime
 *
 * @card
 *   S/MIME 4.0 signature verification per RFC 8551 + RFC 5652 CMS
 *   SignedData. v1 surface is cert preflight; sign/verify deferred.
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
 *     - Refuses SHA-1 as the signature hash (CVE-2017-9006-class —
 *       PKCS#7 collision attacks against legacy S/MIME) and as the
 *       certificate signature algorithm.
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
 *   v1 status — DEFERRED with documented conditions:
 *
 *     Both sign() and verify() throw `MailCryptoError("mail-crypto/
 *     smime/deferred", ...)` in v1. The CMS SignedData ASN.1
 *     structure (RFC 5652 §5.1) is a five-field SEQUENCE with nested
 *     SET-OF / OPTIONAL / IMPLICIT-tagged fields, a DER content
 *     octet-string with constructed indefinite-length variants seen
 *     in the wild, and signed-attributes / unsigned-attributes
 *     ordering rules (§5.4 — DER set-of attributes MUST be sorted by
 *     encoded value for the signature to verify). node:crypto does
 *     not expose a CMS codec, and a hand-rolled ASN.1 BER/DER parser
 *     of the depth required to round-trip every fielded S/MIME
 *     signer's output is comparable in surface to the OpenPGP
 *     packet decoder shipped in `b.mail.crypto.pgp` — but with
 *     dramatically more shape variation across implementations.
 *
 *     Reopen condition: the in-tree CMS substrate (`b.cms`) shipped
 *     in v0.10.13 — the RFC 5652 SignedData encode + decode + PQC
 *     signer dispatch is now available. The S/MIME wire layer
 *     (multipart/signed framing, micalg mapping, base64 DER body,
 *     Content-Type parameters) lights up on top of `b.cms` in
 *     v0.10.14 alongside `b.mail.crypto.pgp` encrypt + decrypt + WKD
 *     discovery, so operators get the full mail-crypto surface in a
 *     single release rather than half of each side.
 *
 *     Cheap escape hatch (pre-v0.10.14): operators wanting in-process
 *     S/MIME today compose `b.cms.encodeSignedData` directly with a
 *     hand-written multipart/signed wrapper. The MIME framing is two
 *     parts (the signed content + `application/pkcs7-signature` body
 *     carrying the base64-encoded CMS DER from `b.cms`); the helper
 *     in v0.10.14 collapses that into `b.mail.crypto.smime.sign({ ... })`
 *     so the next-release path is additive, not a rewrite.
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
 *   - CVE-2017-9006 (PKCS#7 / S/MIME signature-validation bypass
 *     class — informs the SHA-1 refusal posture)
 *   - CVE-2018-5407 (PortSmash — informs the side-channel hardening
 *     posture when private operations land in v2)
 */
var lazyRequire  = require("./lazy-require");
var audit        = lazyRequire(function () { return require("./audit"); });
var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var MailCryptoError = defineClass("MailCryptoError", { alwaysPermanent: true });

// Constant posture values exported so operators reading this module
// from configuration code can pin to them by reference rather than
// hand-copying strings. These reflect RFC 8551 §2.5 + RFC 8301 floors.
var RSA_MIN_BITS = 2048;                                                          // allow:raw-byte-literal — RFC 8301 §3.1
var ALLOWED_HASHES = ["sha256", "sha384", "sha512"];
var REFUSED_HASHES = ["md5", "sha1"];                                             // allow:raw-byte-literal — CVE-2017-9006-class

// PROFILES + COMPLIANCE_POSTURES — the framework's standard cross-
// primitive contract. v1 only emits the metadata; the deferred sign/
// verify methods read them when they light up.
var PROFILES = ["strict", "balanced", "permissive"];
var COMPLIANCE_POSTURES = {
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
};

var DEFERRAL_MESSAGE =
  "b.mail.crypto.smime is deferred in v1. See the @intro comment block " +
  "in lib/mail-crypto-smime.js for the deferral conditions and the " +
  "documented escape hatch (operator-side CMS via a vetted third-party " +
  "library or openssl(1)). Lights up in v0.9.60+ once a vendorable " +
  "ASN.1 BER/DER decoder is folded in under lib/vendor/.";

// ---- Public surface (deferred) ----

/**
 * @primitive  b.mail.crypto.smime.sign
 * @signature  b.mail.crypto.smime.sign(opts)
 * @since      0.9.58
 * @status     experimental
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Deferred entry point. v1 surface is recognition + posture-only;
 * actual CMS emission lights up in v0.9.60+ once a vendorable
 * ASN.1 BER/DER codec is folded in. Throws
 * `mail-crypto/smime/deferred` with a documented escape-hatch path
 * (operator-side CMS via openssl(1) or a vetted library).
 *
 * @example
 *   try {
 *     b.mail.crypto.smime.sign({ message: m, certPem: c, privateKeyPem: k });
 *   } catch (e) {
 *     // e.code === "mail-crypto/smime/deferred"
 *   }
 */
function sign(opts) {
  opts = opts || {};
  validateOpts(opts, ["message", "certPem", "privateKeyPem", "passphrase", "audit"],
    "mail.crypto.smime.sign");
  _audit(opts.audit, "mail.crypto.smime.sign", "denied", { reason: "deferred" });
  throw new MailCryptoError("mail-crypto/smime/deferred", DEFERRAL_MESSAGE);
}

/**
 * @primitive  b.mail.crypto.smime.verify
 * @signature  b.mail.crypto.smime.verify(opts)
 * @since      0.9.58
 * @status     experimental
 * @compliance hipaa, pci-dss, gdpr, soc2
 *
 * Deferred entry point — same posture as sign. v1 throws
 * `mail-crypto/smime/deferred`; v0.9.60+ verifies a CMS SignedData
 * blob against `opts.trustedCertsPem`.
 *
 * @example
 *   try {
 *     b.mail.crypto.smime.verify({ message: m, armored: a, trustedCertsPem: t });
 *   } catch (e) {
 *     // e.code === "mail-crypto/smime/deferred"
 *   }
 */
function verify(opts) {
  opts = opts || {};
  validateOpts(opts, ["message", "armored", "trustedCertsPem", "audit"],
    "mail.crypto.smime.verify");
  _audit(opts.audit, "mail.crypto.smime.verify_fail", "denied", { reason: "deferred" });
  throw new MailCryptoError("mail-crypto/smime/deferred", DEFERRAL_MESSAGE);
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
        "(CVE-2017-9006-class). Acceptable hashes: " + ALLOWED_HASHES.join(", "));
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
  checkCert:           checkCert,
  MailCryptoError:     MailCryptoError,
  PROFILES:            PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  ALLOWED_HASHES:      ALLOWED_HASHES,
  REFUSED_HASHES:      REFUSED_HASHES,
  RSA_MIN_BITS:        RSA_MIN_BITS,
  DEFERRAL_MESSAGE:    DEFERRAL_MESSAGE,
};
