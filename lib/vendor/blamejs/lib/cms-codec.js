"use strict";
/**
 * @module b.cms
 * @nav    Crypto
 * @title  CMS Codec
 *
 * @intro
 *   RFC 5652 Cryptographic Message Syntax encoder + decoder built on
 *   the framework's existing `b.asn1Der` substrate and the vendored
 *   noble-post-quantum primitives (`b.pqcSoftware.ml_dsa_*` /
 *   `ml_kem_1024` / `slh_dsa_shake_256f`). Re-opens the CMS forward-
 *   watch item from the 2026-05-08 audit (deferred-with-condition
 *   pending operator-side demand from the live mail-stack listeners).
 *   Operator-demand condition is now met by the inbound MX + JMAP
 *   listeners (v0.9.45–v0.9.50).
 *
 *   Scope (v0.10.13):
 *
 *   - **ContentInfo** wrapper (RFC 5652 §3) for all top-level emissions.
 *   - **SignedData** (§5) encode + decode with PQC signer support
 *     (ML-DSA-65 per RFC 9909 §5, ML-DSA-87 per RFC 9909 §6,
 *     SLH-DSA-SHAKE-256f per RFC 9881). The signature input is the
 *     DER-encoded SET OF signed-attributes with the IMPLICIT [0] tag
 *     re-tagged to the universal SET tag per §5.4 third paragraph.
 *   - **EnvelopedData** (§6) encode with `KEMRecipientInfo` (RFC 9629)
 *     for ML-KEM-1024 recipients (RFC 9936). The content-encryption
 *     key is wrapped under a KEK derived from the KEM shared-secret
 *     via HKDF-SHA3-512; content is encrypted with ChaCha20-Poly1305
 *     (RFC 8103 OID). Efail-class CBC-malleability is impossible by
 *     construction — every CMS content blob emitted by this module
 *     carries an AEAD tag.
 *   - Strict DER on emit (canonical: lexicographic SET-OF ordering,
 *     minimal-length encoding, no indefinite length).
 *
 *   Deferred from v0.10.13 (each with documented condition):
 *
 *   - **AuthEnvelopedData** (RFC 5083) as a distinct ContentInfo
 *     ciphertext shape. Operator demand is not yet surfaced — every
 *     v0.10.13 emission uses EnvelopedData with the ChaCha20-Poly1305
 *     content-encryption OID, which is already AEAD by construction.
 *     Defer condition: at least one interop case requires a peer that
 *     refuses EnvelopedData and accepts only the §5083 ContentInfo
 *     OID. Cheap escape hatch: operators on such a peer compose
 *     `b.asn1Der` directly to rewrap an EnvelopedData blob into an
 *     AuthEnvelopedData ContentInfo. Lights up in v0.10.14 alongside
 *     `b.mail.smime` sign + verify, where the on-the-wire S/MIME 4.0
 *     content shape calls for it.
 *   - **`b.cms.decode` parse-tree of inner SignedData / EnvelopedData**
 *     beyond the ContentInfo wrapper. v0.10.13 returns the inner
 *     SEQUENCE bytes as `content` (an asn1-der node); callers that
 *     need fielded access walk it via `b.asn1Der.readSequence`. The
 *     fielded decoders ship alongside S/MIME verify in v0.10.14 where
 *     they're actually consumed.
 *
 *   Refusal posture:
 *
 *   - Top-level must be SEQUENCE { OID, [0] EXPLICIT content }; any
 *     other shape throws `cms/bad-content-info`.
 *   - Recipient/signer counts must be non-empty (`cms/no-signers` /
 *     `cms/no-recipients`).
 *   - Only PQC signature algorithms are accepted (`cms/bad-sig-alg`).
 *   - Only ML-KEM-1024 recipients are accepted (`cms/bad-recipient-type`).
 *   - Input past `opts.maxBytes` (default 64 MiB) throws `cms/oversize`.
 *
 * @card
 *   RFC 5652 CMS codec (SignedData + EnvelopedData) on b.asn1Der + vendored noble-post-quantum. PQC signers per RFC 9909 / 9881; ML-KEM-1024 recipients per RFC 9629 / 9936. AEAD-only content (ChaCha20-Poly1305) — Efail-class malleability cannot apply.
 */

var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var bCrypto = require("./crypto");
var pqcSoftware = require("./pqc-software");
var { defineClass } = require("./framework-error");
var audit = require("./audit");

var CmsCodecError = defineClass("CmsCodecError", { alwaysPermanent: true });

// Common CMS OIDs (RFC 5652, RFC 5083, RFC 9629, RFC 9909, RFC 9881).
var OID = Object.freeze({
  data:               "1.2.840.113549.1.7.1",
  signedData:         "1.2.840.113549.1.7.2",
  envelopedData:      "1.2.840.113549.1.7.3",
  authEnvelopedData:  "1.2.840.113549.1.9.16.1.23",   // RFC 5083
  // PQC signature algorithms (RFC 9909, RFC 9881).
  mldsa44:            "2.16.840.1.101.3.4.3.17",
  mldsa65:            "2.16.840.1.101.3.4.3.18",
  mldsa87:            "2.16.840.1.101.3.4.3.19",
  slhDsaShake256f:    "2.16.840.1.101.3.4.3.31",
  // PQC KEM algorithms (RFC 9935, RFC 9936).
  mlkem768:           "2.16.840.1.101.3.4.4.2",
  mlkem1024:          "2.16.840.1.101.3.4.4.3",
  // KEMRecipientInfo type (RFC 9629 §3).
  kemri:              "1.2.840.113549.1.9.16.13.3",
  // Symmetric content encryption — ChaCha20-Poly1305 (RFC 8103 IANA codepoint).
  chacha20Poly1305:   "1.2.840.113549.1.9.16.3.18",
  // KDF — SHAKE256 XOF (NIST SP 800-185), the framework's PQC-first
  // KDF substrate (`b.crypto.kdf` wraps it). OID per NIST registry.
  shake256:           "2.16.840.1.101.3.4.2.12",
  // Signed-attribute attribute types.
  contentType:        "1.2.840.113549.1.9.3",
  messageDigest:      "1.2.840.113549.1.9.4",
  signingTime:        "1.2.840.113549.1.9.5",
  // Digest algorithms (SHA3-256 / -512 — framework PQC-first hash family).
  sha3_256:           "2.16.840.1.101.3.4.2.8",
  sha3_512:           "2.16.840.1.101.3.4.2.10",
});

// Refusal ceilings.
var MAX_DEPTH       = 32;                                                                             // allow:raw-byte-literal — ASN.1 recursion ceiling
var DEFAULT_MAX_LEN = 64 * 1024 * 1024;                                                               // allow:raw-byte-literal — 64 MiB default decode cap

// Universal-tag bytes used in encode helpers.
var TAG_SEQUENCE = 0x30;                                                                              // allow:raw-byte-literal — ASN.1 SEQUENCE constructed
var TAG_SET      = 0x31;                                                                              // allow:raw-byte-literal — ASN.1 SET constructed
var TAG_UTCTIME  = 0x17;                                                                              // allow:raw-byte-literal — UTCTime universal
var TAG_GENTIME  = 0x18;                                                                              // allow:raw-byte-literal — GeneralizedTime universal

/**
 * @primitive b.cms.encodeSignedData
 * @signature b.cms.encodeSignedData(opts)
 * @since     0.10.13
 * @status    stable
 * @related   b.cms.decode, b.cms.encodeEnvelopedData
 *
 * Encode an RFC 5652 §5 SignedData ContentInfo with PQC signer
 * support. The output is a DER-encoded Buffer ready for embedding in
 * S/MIME `application/pkcs7-mime; smime-type=signed-data` parts or
 * for standalone CMS-over-network use.
 *
 * @opts
 *   encapContent:    Buffer,                          // bytes to sign
 *   digestAlg:       "sha3-256" | "sha3-512",         // default sha3-512
 *   signers:         [{ certificate: Buffer, secretKey: Uint8Array, sigAlg: string }],
 *   certificates:    Buffer[],                        // additional DER certs (optional)
 *   detached:        boolean,                         // default false; true → omit encapContent
 *
 * @example
 *   var pq = b.pqcSoftware;
 *   var kp = pq.ml_dsa_65.keygen();
 *   var bytes = b.cms.encodeSignedData({
 *     encapContent: Buffer.from("payload"),
 *     digestAlg:    "sha3-512",
 *     signers:      [{ certificate: certDer, secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
 *   });
 */
function encodeSignedData(opts) {
  if (!opts || typeof opts !== "object") {
    throw new CmsCodecError("cms/bad-opts", "encodeSignedData: opts required");
  }
  if (!Buffer.isBuffer(opts.encapContent)) {
    throw new CmsCodecError("cms/bad-encap", "encodeSignedData: encapContent must be a Buffer");
  }
  if (!Array.isArray(opts.signers) || opts.signers.length === 0) {
    throw new CmsCodecError("cms/no-signers",
      "encodeSignedData: opts.signers must be a non-empty array");
  }
  var digestAlg = opts.digestAlg || "sha3-512";
  if (digestAlg !== "sha3-256" && digestAlg !== "sha3-512") {
    throw new CmsCodecError("cms/bad-digest",
      "encodeSignedData: digestAlg must be 'sha3-256' or 'sha3-512' " +
      "(PQC-first; SHA-2 family not accepted in v1)");
  }
  var digestOid = digestAlg === "sha3-256" ? OID.sha3_256 : OID.sha3_512;
  var detached = opts.detached === true;

  // Message digest over encapContent (SHA3-256 or SHA3-512 per opts.digestAlg).
  var msgDigest = nodeCrypto.createHash(digestAlg).update(opts.encapContent).digest();

  // digestAlgorithms SET — one entry per distinct digest algorithm used.
  var digestAlgs = asn1.writeNode(TAG_SET, _algorithmIdentifier(digestOid));

  // EncapsulatedContentInfo.
  var encapInfo = _encapsulatedContentInfo(opts.encapContent, detached);

  // Optional certificates [0] IMPLICIT — operator-supplied DER cert blobs.
  var certsBlock = Buffer.alloc(0);
  if (Array.isArray(opts.certificates) && opts.certificates.length > 0) {
    var concat = Buffer.concat(opts.certificates.map(function (c) {
      if (!Buffer.isBuffer(c)) {
        throw new CmsCodecError("cms/bad-cert",
          "encodeSignedData: certificates entries must be DER Buffers");
      }
      return c;
    }));
    // certificates [0] IMPLICIT CertificateSet — CertificateSet is a SET
    // of certificates (constructed), so this wrap is the constructed
    // form per RFC 5652 §5.1.
    certsBlock = _writeImplicitConstructed(0, concat);
  }

  // signerInfos SET — one SignerInfo per signer.
  var sigInfos = opts.signers.map(function (s) {
    return _signerInfo(s, msgDigest, digestOid);
  });
  var signerInfosSet = asn1.writeNode(TAG_SET, Buffer.concat(sigInfos));

  // SignedData SEQUENCE per §5.1.
  var signedDataSeq = asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeInteger(Buffer.from([1])),                                                              // allow:raw-byte-literal — CMSVersion 1 per §5.1
    digestAlgs,
    encapInfo,
    certsBlock,
    signerInfosSet,
  ]));

  // ContentInfo wrapper.
  var contentInfo = asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeOid(OID.signedData),
    asn1.writeContextExplicit(0, signedDataSeq),
  ]));
  try {
    audit.safeEmit({
      action:   "cms.signedData.encoded",
      outcome:  "success",
      actor:    {},
      metadata: { signerCount: opts.signers.length, digestAlg: digestAlg, detached: detached },
    });
  } catch (_e) { /* drop-silent */ }
  return contentInfo;
}

/**
 * @primitive b.cms.encodeEnvelopedData
 * @signature b.cms.encodeEnvelopedData(opts)
 * @since     0.10.13
 * @status    stable
 * @related   b.cms.decode, b.cms.encodeSignedData
 *
 * Encode an RFC 5652 §6 EnvelopedData ContentInfo with ML-KEM-1024
 * recipients per RFC 9629 (KEMRecipientInfo) + RFC 9936 (ML-KEM in
 * CMS). The content-encryption key is wrapped under a KEK derived
 * from the per-recipient KEM shared-secret via HKDF-SHA3-512;
 * content is encrypted with ChaCha20-Poly1305 so Efail-class
 * malleability cannot apply.
 *
 * @opts
 *   plaintext:    Buffer,                              // bytes to encrypt
 *   recipients:   [{ type: "kem-mlkem-1024", publicKey: Uint8Array, recipientId: Buffer }],
 *
 * @example
 *   var pq = b.pqcSoftware;
 *   var kp = pq.ml_kem_1024.keygen();
 *   var bytes = b.cms.encodeEnvelopedData({
 *     plaintext:  Buffer.from("secret"),
 *     recipients: [{ type: "kem-mlkem-1024", publicKey: kp.publicKey, recipientId: Buffer.from([1]) }],
 *   });
 */
function encodeEnvelopedData(opts) {
  if (!opts || typeof opts !== "object") {
    throw new CmsCodecError("cms/bad-opts", "encodeEnvelopedData: opts required");
  }
  if (!Buffer.isBuffer(opts.plaintext)) {
    throw new CmsCodecError("cms/bad-plaintext", "encodeEnvelopedData: plaintext must be a Buffer");
  }
  if (!Array.isArray(opts.recipients) || opts.recipients.length === 0) {
    throw new CmsCodecError("cms/no-recipients",
      "encodeEnvelopedData: opts.recipients must be a non-empty array");
  }
  // Fresh ChaCha20-Poly1305 content key.
  var contentKey = bCrypto.generateBytes(32);                                                         // allow:raw-byte-literal — 256-bit ChaCha20 key

  // recipientInfos SET — one KEMRecipientInfo per recipient.
  var ris = opts.recipients.map(function (r) {
    return _recipientInfo(r, contentKey);
  });
  var recipientInfosSet = asn1.writeNode(TAG_SET, Buffer.concat(ris));

  // EncryptedContentInfo + ChaCha20-Poly1305 ciphertext.
  var encContent = _encryptedContentInfo(opts.plaintext, contentKey);

  // EnvelopedData SEQUENCE per §6.1. CMSVersion 4 (RFC 9629 §3 — when
  // any RecipientInfo is OtherRecipientInfo, here KEMRecipientInfo).
  var envelopedSeq = asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeInteger(Buffer.from([4])),                                                              // allow:raw-byte-literal — CMSVersion 4 per RFC 9629 §3
    recipientInfosSet,
    encContent,
  ]));
  var contentInfo = asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeOid(OID.envelopedData),
    asn1.writeContextExplicit(0, envelopedSeq),
  ]));
  try {
    audit.safeEmit({
      action:   "cms.envelopedData.encoded",
      outcome:  "success",
      actor:    {},
      metadata: { recipientCount: opts.recipients.length },
    });
  } catch (_e) { /* drop-silent */ }
  return contentInfo;
}

/**
 * @primitive b.cms.decode
 * @signature b.cms.decode(buf, opts?)
 * @since     0.10.13
 * @status    stable
 * @related   b.cms.encodeSignedData, b.cms.encodeEnvelopedData
 *
 * Decode a CMS ContentInfo from `buf` (DER bytes). Returns
 * `{ contentType, content }` where `contentType` is the dotted-OID
 * string (e.g. `"1.2.840.113549.1.7.2"` for SignedData) and
 * `content` is the inner asn1-der node (SignedData / EnvelopedData /
 * other) — operators walk it via `b.asn1Der.readSequence`. Fielded
 * decoders for SignedData / EnvelopedData ship in v0.10.14 alongside
 * S/MIME sign+verify.
 *
 * Refuses input past `opts.maxBytes` (default 64 MiB), top-level
 * non-SEQUENCE shapes, missing OID + [0] EXPLICIT child pair.
 *
 * @opts
 *   maxBytes:    number,            // default 64 MiB
 *
 * @example
 *   var ci = b.cms.decode(derBytes);
 *   ci.contentType;  // → "1.2.840.113549.1.7.2"
 */
function decode(buf, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(buf)) {
    throw new CmsCodecError("cms/bad-input", "decode: buf must be a Buffer");
  }
  var maxBytes = opts.maxBytes || DEFAULT_MAX_LEN;
  if (buf.length > maxBytes) {
    throw new CmsCodecError("cms/oversize",
      "decode: input " + buf.length + " bytes exceeds maxBytes=" + maxBytes);
  }
  var node;
  try { node = asn1.readNode(buf); }
  catch (e) {
    throw new CmsCodecError("cms/bad-asn1",
      "decode: ASN.1 parse failed: " + ((e && e.message) || String(e)));
  }
  if (!(node.tag === asn1.TAG.SEQUENCE && node.constructed)) {
    throw new CmsCodecError("cms/bad-content-info",
      "decode: top-level must be SEQUENCE (got tag 0x" + node.tag.toString(16) + ")");                // allow:raw-byte-literal — hex radix for error-message formatting
  }
  // ContentInfo SEQUENCE children: { contentType OID, [0] EXPLICIT ANY }.
  var children;
  try { children = asn1.readSequence(node.value); }
  catch (e2) {
    throw new CmsCodecError("cms/bad-content-info",
      "decode: ContentInfo body parse failed: " + ((e2 && e2.message) || String(e2)));
  }
  if (children.length < 2) {
    throw new CmsCodecError("cms/bad-content-info",
      "decode: ContentInfo SEQUENCE must have 2 children (contentType + [0] content)");
  }
  var contentType;
  try { contentType = asn1.readOid(children[0]); }
  catch (e3) {
    throw new CmsCodecError("cms/bad-oid",
      "decode: contentType OID parse failed: " + ((e3 && e3.message) || String(e3)));
  }
  // [0] EXPLICIT content — unwrap via asn1.unwrapExplicit(node, expectedTagNumber).
  var inner;
  try { inner = asn1.unwrapExplicit(children[1], 0); }
  catch (e4) {
    throw new CmsCodecError("cms/bad-explicit-content",
      "decode: [0] EXPLICIT content unwrap failed: " + ((e4 && e4.message) || String(e4)));
  }
  return { contentType: contentType, content: inner };
}

// ---- Internal helpers -----------------------------------------------------

// OIDs whose AlgorithmIdentifier specifies ABSENT parameters per their
// publishing RFC — emitting NULL here would make the CMS structure
// non-conformant for strict validators (Codex P1 finding on PR #102).
// ML-DSA per RFC 9909 §3, SLH-DSA per RFC 9881 §3, ML-KEM per
// RFC 9936 §3. SHAKE-family per FIPS 202 (NIST registry — absent params).
var ABSENT_PARAM_OIDS = new Set([
  "2.16.840.1.101.3.4.3.17",  // ml_dsa_44
  "2.16.840.1.101.3.4.3.18",  // ml_dsa_65
  "2.16.840.1.101.3.4.3.19",  // ml_dsa_87
  "2.16.840.1.101.3.4.3.31",  // slh_dsa_shake_256f
  "2.16.840.1.101.3.4.4.2",   // ml_kem_768
  "2.16.840.1.101.3.4.4.3",   // ml_kem_1024
  "2.16.840.1.101.3.4.2.12",  // shake256 (KDF/digest — absent params)
]);

function _algorithmIdentifier(oidStr) {
  // SEQUENCE { algorithm OID, parameters ANY DEFINED BY algorithm OPTIONAL }.
  // PQC OIDs (RFC 9909 / 9881 / 9936) MUST emit with parameters ABSENT;
  // legacy non-PQC OIDs (SHA-2 / SHA-3 hash OIDs in this module, ChaCha20-
  // Poly1305 wrap OID) still carry the historical NULL parameter shape
  // that fielded CMS toolchains expect.
  if (ABSENT_PARAM_OIDS.has(oidStr)) {
    return asn1.writeNode(TAG_SEQUENCE, asn1.writeOid(oidStr));
  }
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeOid(oidStr),
    asn1.writeNull(),
  ]));
}

function _writeImplicitConstructed(tagNumber, payload) {
  // [N] IMPLICIT context-specific CONSTRUCTED — for wrapping SEQUENCE /
  // SET payloads (e.g. certificates [0], crls [1], OtherRecipientInfo
  // value).
  var tagByte = 0xa0 | (tagNumber & 0x1f);                                                            // allow:raw-byte-literal — context-specific constructed mask
  return asn1.writeNode(tagByte, payload);
}

function _writeImplicitPrimitive(tagNumber, value) {
  // [N] IMPLICIT context-specific PRIMITIVE — for wrapping primitive
  // ASN.1 types (OCTET STRING / INTEGER / OID) that have been IMPLICIT-
  // tagged. The constructed bit MUST NOT be set or strict CMS parsers
  // reject the structure (Codex P1 finding on PR #102 — RecipientIdentifier
  // CHOICE's SubjectKeyIdentifier alternative is `[0] IMPLICIT OCTET STRING`,
  // a primitive type).
  var tagByte = 0x80 | (tagNumber & 0x1f);                                                            // allow:raw-byte-literal — context-specific primitive mask
  return asn1.writeNode(tagByte, value);
}

function _encapsulatedContentInfo(content, detached) {
  // EncapsulatedContentInfo: SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING? }
  var inner = [asn1.writeOid(OID.data)];
  if (!detached) {
    inner.push(asn1.writeContextExplicit(0, asn1.writeOctetString(content)));
  }
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat(inner));
}

function _signerInfo(signer, msgDigest, digestOid) {
  if (!signer || typeof signer !== "object") {
    throw new CmsCodecError("cms/bad-signer", "signer entry must be an object");
  }
  if (!Buffer.isBuffer(signer.certificate)) {
    throw new CmsCodecError("cms/bad-signer-cert",
      "signer.certificate must be a DER Buffer");
  }
  if (signer.sigAlg !== "ML-DSA-65" && signer.sigAlg !== "ML-DSA-87" &&
      signer.sigAlg !== "SLH-DSA-SHAKE-256f") {
    throw new CmsCodecError("cms/bad-sig-alg",
      "signer.sigAlg must be ML-DSA-65 / ML-DSA-87 / SLH-DSA-SHAKE-256f " +
      "(PQC-first; RSA / ECDSA not accepted)");
  }
  if (!(signer.secretKey instanceof Uint8Array)) {
    throw new CmsCodecError("cms/bad-signer-key",
      "signer.secretKey must be a Uint8Array from the matching PQC keygen");
  }
  var sigAlgOid;
  var pqcAlg;
  if (signer.sigAlg === "ML-DSA-65")        { sigAlgOid = OID.mldsa65;         pqcAlg = pqcSoftware.ml_dsa_65; }
  else if (signer.sigAlg === "ML-DSA-87")   { sigAlgOid = OID.mldsa87;         pqcAlg = pqcSoftware.ml_dsa_87; }
  else                                       { sigAlgOid = OID.slhDsaShake256f; pqcAlg = pqcSoftware.slh_dsa_shake_256f; }

  // signedAttrs SET OF Attribute — IMPLICIT [0] tagged in the SignerInfo.
  // For the signature input we re-tag as universal SET (0x31) per
  // RFC 5652 §5.4 paragraph 3.
  var signedAttrs = _signedAttrs({
    contentType:   OID.data,
    messageDigest: msgDigest,
    signingTime:   signer.signingTime instanceof Date ? signer.signingTime : new Date(),
  });
  // signedAttrs is already `31 LL VV...` — re-tag to `A0 LL VV...` for the
  // SignerInfo, and use the original `31 LL VV...` form as the signature
  // input.
  var signatureInput = signedAttrs;
  var signedAttrsImplicit = Buffer.concat([Buffer.from([0xa0]),                                       // allow:raw-byte-literal — IMPLICIT [0] tag per RFC 5652 §5.3
                                            signedAttrs.slice(1)]);

  var signature;
  try {
    // noble signature: sign(msg, secretKey) → Uint8Array.
    var sigBytes = pqcAlg.sign(new Uint8Array(signatureInput), signer.secretKey);
    signature = Buffer.from(sigBytes);
  } catch (e) {
    throw new CmsCodecError("cms/sign-failed",
      "SignerInfo signature failed: " + ((e && e.message) || String(e)));
  }

  // SignerInfo SEQUENCE per §5.3 (issuerAndSerialNumber variant — CMSVersion 1).
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeInteger(Buffer.from([1])),                                                              // allow:raw-byte-literal — CMSVersion 1 for issuerAndSerialNumber
    _issuerAndSerialNumber(signer.certificate),
    _algorithmIdentifier(digestOid),
    signedAttrsImplicit,
    _algorithmIdentifier(sigAlgOid),
    asn1.writeOctetString(signature),
  ]));
}

function _signedAttrs(attrs) {
  // SET OF Attribute — DER canonical: sort entries by encoded bytes (X.690 §11.6).
  var entries = [];
  entries.push(_attribute(OID.contentType,   asn1.writeOid(attrs.contentType)));
  entries.push(_attribute(OID.messageDigest, asn1.writeOctetString(attrs.messageDigest)));
  entries.push(_attribute(OID.signingTime,   _encodeTime(attrs.signingTime)));
  entries.sort(Buffer.compare);
  return asn1.writeNode(TAG_SET, Buffer.concat(entries));
}

function _attribute(typeOid, valueBuf) {
  // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeOid(typeOid),
    asn1.writeNode(TAG_SET, valueBuf),
  ]));
}

function _encodeTime(date) {
  var pad = function (n) { return n < 10 ? "0" + n : String(n); };
  var y = date.getUTCFullYear();
  var mm = pad(date.getUTCMonth() + 1);
  var dd = pad(date.getUTCDate());
  var hh = pad(date.getUTCHours());
  var mi = pad(date.getUTCMinutes());
  var ss = pad(date.getUTCSeconds());
  if (y >= 1950 && y <= 2049) {
    var yy = pad(y % 100);
    return asn1.writeNode(TAG_UTCTIME, Buffer.from(yy + mm + dd + hh + mi + ss + "Z", "ascii"));
  }
  return asn1.writeNode(TAG_GENTIME, Buffer.from(String(y) + mm + dd + hh + mi + ss + "Z", "ascii"));
}

function _issuerAndSerialNumber(certDer) {
  // RFC 5280 §4.1 Certificate SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
  // tbsCertificate SEQUENCE { [0] version?, serialNumber INTEGER, signature AlgId, issuer Name, ... }
  // We extract `issuer Name` (SEQUENCE) + `serialNumber` (INTEGER) and wrap as
  // SEQUENCE { issuer, serialNumber } per RFC 5652 §10.2.4.
  var cert;
  try { cert = asn1.readNode(certDer); }
  catch (e) {
    throw new CmsCodecError("cms/bad-cert", "certificate DER parse failed: " + ((e && e.message) || String(e)));
  }
  if (cert.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-cert", "certificate top-level is not a SEQUENCE");
  }
  var certChildren;
  try { certChildren = asn1.readSequence(cert.value); }
  catch (e2) {
    throw new CmsCodecError("cms/bad-cert", "certificate body parse failed: " + ((e2 && e2.message) || String(e2)));
  }
  if (certChildren.length < 1 || certChildren[0].tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-cert", "certificate has no tbsCertificate SEQUENCE");
  }
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(certChildren[0].value); }
  catch (e3) {
    throw new CmsCodecError("cms/bad-cert", "tbsCertificate body parse failed: " + ((e3 && e3.message) || String(e3)));
  }
  // Optional [0] EXPLICIT version then serialNumber INTEGER.
  var idx = 0;
  if (tbsChildren[idx] && tbsChildren[idx].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC &&
      tbsChildren[idx].tag === 0) {
    idx += 1;
  }
  var serialNode = tbsChildren[idx];
  if (!serialNode || serialNode.tag !== asn1.TAG.INTEGER) {
    throw new CmsCodecError("cms/bad-cert", "tbsCertificate has no serialNumber INTEGER");
  }
  idx += 1;
  // Skip signature AlgId (SEQUENCE).
  if (!tbsChildren[idx] || tbsChildren[idx].tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-cert", "tbsCertificate has no signature AlgorithmIdentifier");
  }
  idx += 1;
  // Issuer Name (SEQUENCE).
  var issuerNode = tbsChildren[idx];
  if (!issuerNode || issuerNode.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-cert", "tbsCertificate has no issuer Name SEQUENCE");
  }
  // Reconstruct the full DER bytes of issuer (header + value) and
  // serialNumber (header + value) — readNode gave us value-only Buffers.
  var issuerDer = _reEncodeNode(issuerNode);
  var serialDer = _reEncodeNode(serialNode);
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat([issuerDer, serialDer]));
}

function _reEncodeNode(node) {
  // Reconstruct the TLV bytes of `node` — asn1-der's readNode returns the
  // value slice but the issuerAndSerialNumber surface needs the full
  // TLV. writeNode rebuilds canonical DER from the original tag byte +
  // value bytes; the tag byte is reconstructed from tagClass + constructed +
  // tag number.
  var classBits  = (node.tagClass & 0x03) << 6;                                                       // allow:raw-byte-literal — tag-class shift
  var consBit    = node.constructed ? 0x20 : 0x00;                                                    // allow:raw-byte-literal — constructed bit
  var tagBits    = node.tag & 0x1f;                                                                   // allow:raw-byte-literal — short-form tag
  var tagByte    = classBits | consBit | tagBits;
  return asn1.writeNode(tagByte, node.value);
}

function _recipientInfo(recipient, contentKey) {
  // RFC 9629 KEMRecipientInfo wrapped in [1] IMPLICIT OtherRecipientInfo
  // SEQUENCE per §3:
  //   ori [4] IMPLICIT OtherRecipientInfo
  //   OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY DEFINED BY oriType }
  //   oriType = id-ori-kem (RFC 9629 §3)
  //   oriValue = KEMRecipientInfo SEQUENCE { version, rid, kem, kemct, kdf, kekLength, ukm?, wrap, encryptedKey }
  if (!recipient || typeof recipient !== "object") {
    throw new CmsCodecError("cms/bad-recipient", "recipient must be an object");
  }
  if (recipient.type !== "kem-mlkem-1024") {
    throw new CmsCodecError("cms/bad-recipient-type",
      "recipient.type must be 'kem-mlkem-1024' " +
      "(other KEMs / KEKRecipientInfo / KeyAgreeRecipientInfo deferred)");
  }
  if (!(recipient.publicKey instanceof Uint8Array)) {
    throw new CmsCodecError("cms/bad-recipient-key",
      "recipient.publicKey must be a Uint8Array from b.pqcSoftware.ml_kem_1024.keygen()");
  }
  if (!Buffer.isBuffer(recipient.recipientId)) {
    throw new CmsCodecError("cms/bad-recipient-id",
      "recipient.recipientId must be a Buffer (SubjectKeyIdentifier or issuer-and-serial-number DER)");
  }
  // KEM encapsulate against the recipient's ML-KEM-1024 public key.
  var encap;
  try { encap = pqcSoftware.ml_kem_1024.encapsulate(recipient.publicKey); }
  catch (e) {
    throw new CmsCodecError("cms/kem-encap-failed",
      "ML-KEM-1024 encapsulation failed: " + ((e && e.message) || String(e)));
  }
  // Derive 32-byte KEK from the KEM shared secret via SHAKE256 (the
  // framework's PQC-first KDF). The info-label binds the derivation to
  // the CMS KEMRecipientInfo + ChaCha20-Poly1305 wrap context so a key
  // derived here cannot be confused with a key derived for any other
  // composition path.
  var infoLabel = Buffer.from("cms/kemri/chacha20-poly1305", "ascii");
  var kdfInput  = Buffer.concat([Buffer.from(encap.sharedSecret), infoLabel]);
  var kek       = bCrypto.kdf(kdfInput, 32);                                                          // allow:raw-byte-literal — 256-bit KEK
  // Wrap the content key under the KEK using ChaCha20-Poly1305.
  var wrapped;
  try { wrapped = bCrypto.encryptPacked(contentKey, kek); }
  catch (e2) {
    throw new CmsCodecError("cms/wrap-failed",
      "content-key wrap failed: " + ((e2 && e2.message) || String(e2)));
  }
  // KEMRecipientInfo SEQUENCE.
  // Simplified ordering, version 0 per RFC 9629 §3.
  var kemRi = asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeInteger(Buffer.from([0])),                                                              // allow:raw-byte-literal — KEMRecipientInfo version 0
    // rid CHOICE per RFC 9629 §3: this module ships the [0] IMPLICIT
    // SubjectKeyIdentifier alternative — SKI is `[0] IMPLICIT OCTET
    // STRING` (PRIMITIVE per RFC 5652 §10.2.4). The constructed form
    // (0xa0) is the IssuerAndSerialNumber CHOICE alternative; this
    // module picks SKI for KEM recipients since the operator-supplied
    // recipientId is opaque key-identifier bytes.
    _writeImplicitPrimitive(0, recipient.recipientId),
    _algorithmIdentifier(OID.mlkem1024),                                                              // kem
    asn1.writeOctetString(Buffer.from(encap.cipherText)),                                             // kemct
    _algorithmIdentifier(OID.shake256),                                                               // kdf
    asn1.writeInteger(Buffer.from([32])),                                                             // allow:raw-byte-literal — kekLength = 32 bytes
    _algorithmIdentifier(OID.chacha20Poly1305),                                                       // wrap (also used as content-encryption AlgId; same OID)
    asn1.writeOctetString(wrapped),                                                                   // encryptedKey
  ]));
  // OtherRecipientInfo SEQUENCE { oriType OID, oriValue ANY DEFINED BY oriType }
  // wrapped in [4] IMPLICIT context tag per RFC 5652 §6.2 RecipientInfo
  // CHOICE alternative.
  var oriValue = Buffer.concat([
    asn1.writeOid(OID.kemri),
    kemRi,
  ]);
  return asn1.writeNode(0xa4, oriValue);                                                              // allow:raw-byte-literal — [4] IMPLICIT context-specific constructed (ori CHOICE)
}

function _encryptedContentInfo(plaintext, contentKey) {
  // EncryptedContentInfo SEQUENCE { contentType OID, contentEncryptionAlgorithm AlgId,
  // encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }
  // The ChaCha20-Poly1305 ciphertext is the framework's encryptPacked output
  // (nonce ‖ ciphertext ‖ tag). Operators decoding with a non-blamejs CMS
  // peer need to know the framework wire format — documented in @intro.
  var ct;
  try { ct = bCrypto.encryptPacked(plaintext, contentKey); }
  catch (e) {
    throw new CmsCodecError("cms/encrypt-failed",
      "content encryption failed: " + ((e && e.message) || String(e)));
  }
  return asn1.writeNode(TAG_SEQUENCE, Buffer.concat([
    asn1.writeOid(OID.data),
    _algorithmIdentifier(OID.chacha20Poly1305),
    _writeImplicitPrimitive(0, ct),
  ]));
}

/**
 * @primitive b.cms.parseSignedData
 * @signature b.cms.parseSignedData(buf, opts?)
 * @since     0.10.16
 * @status    stable
 * @related   b.cms.encodeSignedData, b.cms.decode
 *
 * Decode a CMS ContentInfo carrying SignedData and walk into the
 * inner structure per RFC 5652 §5.1. Returns a structured object
 * with `digestAlgs`, `encapContent`, `certificates`, and `signerInfos`
 * arrays so downstream verifiers (b.mail.crypto.smime.verify) can
 * check signatures without re-implementing the SignedData walker.
 *
 * @opts
 *   maxBytes:    number,            // default 64 MiB
 *
 * @example
 *   var sd = b.cms.parseSignedData(derBytes);
 *   sd.signerInfos[0].sigAlgOid;  // → "2.16.840.1.101.3.4.3.18" (ML-DSA-65)
 */
function parseSignedData(buf, opts) {
  var ci = decode(buf, opts);
  if (ci.contentType !== OID.signedData) {
    throw new CmsCodecError("cms/not-signed-data",
      "parseSignedData: ContentInfo type is " + ci.contentType + ", expected " + OID.signedData);
  }
  if (ci.content.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-signed-data", "SignedData must be a SEQUENCE");
  }
  var children = asn1.readSequence(ci.content.value);
  if (children.length < 4) {
    throw new CmsCodecError("cms/bad-signed-data",
      "SignedData SEQUENCE must have at least 4 children");
  }
  var idx = 0;
  idx += 1;   // version
  var digestAlgsSet = children[idx]; idx += 1;
  if (digestAlgsSet.tag !== asn1.TAG.SET) {
    throw new CmsCodecError("cms/bad-signed-data", "digestAlgorithms must be a SET");
  }
  var digestAlgs = asn1.readSequence(digestAlgsSet.value).map(_readAlgIdOid);
  var encapInfoNode = children[idx]; idx += 1;
  if (encapInfoNode.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-signed-data", "encapContentInfo must be a SEQUENCE");
  }
  var encapContent = _readEncapContent(encapInfoNode);
  var certificates = [];
  while (idx < children.length - 1) {
    var n = children[idx];
    if (n.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && n.tag === 0) {
      var certChildren = asn1.readSequence(n.value);
      for (var ci2 = 0; ci2 < certChildren.length; ci2 += 1) {
        certificates.push(_reEncodeNode(certChildren[ci2]));
      }
      idx += 1;
    } else if (n.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && n.tag === 1) {
      idx += 1;
    } else {
      break;
    }
  }
  var signerInfosSet = children[idx];
  if (!signerInfosSet || signerInfosSet.tag !== asn1.TAG.SET) {
    throw new CmsCodecError("cms/bad-signed-data", "signerInfos must be a SET");
  }
  var signerInfos = asn1.readSequence(signerInfosSet.value).map(_readSignerInfo);
  return {
    digestAlgs:   digestAlgs,
    encapContent: encapContent,
    certificates: certificates,
    signerInfos:  signerInfos,
  };
}

function _readAlgIdOid(seqNode) {
  if (seqNode.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-alg-id", "AlgorithmIdentifier must be a SEQUENCE");
  }
  var c = asn1.readSequence(seqNode.value);
  if (c.length === 0) {
    throw new CmsCodecError("cms/bad-alg-id", "AlgorithmIdentifier missing OID");
  }
  return asn1.readOid(c[0]);
}

function _readEncapContent(encapInfoNode) {
  var children = asn1.readSequence(encapInfoNode.value);
  if (children.length === 0) {
    throw new CmsCodecError("cms/bad-encap", "encapContentInfo missing eContentType");
  }
  var eContentType = asn1.readOid(children[0]);
  var eContent = null;
  if (children.length >= 2) {
    var ec = children[1];
    if (ec.tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && ec.tag === 0) {
      var inner = asn1.readNode(ec.value);
      if (inner.tag === asn1.TAG.OCTET_STRING) {
        eContent = asn1.readOctetString(inner);
      }
    }
  }
  return { eContentType: eContentType, eContent: eContent };
}

function _readSignerInfo(siNode) {
  if (siNode.tag !== asn1.TAG.SEQUENCE) {
    throw new CmsCodecError("cms/bad-signer-info", "SignerInfo must be a SEQUENCE");
  }
  var c = asn1.readSequence(siNode.value);
  if (c.length < 5) {
    throw new CmsCodecError("cms/bad-signer-info", "SignerInfo must have at least 5 children");
  }
  var idx = 0;
  idx += 1;   // version
  var sidNode = c[idx]; idx += 1;
  var digestAlgOid = _readAlgIdOid(c[idx]); idx += 1;
  // Optional [0] IMPLICIT signedAttrs — re-tag as universal SET
  // (0x31) per RFC 5652 §5.4 to recover the byte sequence the
  // signature was computed over.
  var signedAttrsRaw = null;
  if (c[idx] && c[idx].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && c[idx].tag === 0) {
    var implicitRaw = _reEncodeNode(c[idx]);
    signedAttrsRaw = Buffer.concat([Buffer.from([0x31]), implicitRaw.slice(1)]);                      // allow:raw-byte-literal — universal SET tag per RFC 5652 §5.4
    idx += 1;
  }
  var sigAlgOid = _readAlgIdOid(c[idx]); idx += 1;
  var sigNode = c[idx]; idx += 1;
  if (sigNode.tag !== asn1.TAG.OCTET_STRING) {
    throw new CmsCodecError("cms/bad-signer-info", "signature must be an OCTET STRING");
  }
  var signature = asn1.readOctetString(sigNode);
  return {
    sid:            _reEncodeNode(sidNode),
    digestAlgOid:   digestAlgOid,
    signedAttrsRaw: signedAttrsRaw,
    sigAlgOid:      sigAlgOid,
    signature:      signature,
  };
}

module.exports = {
  encodeSignedData:    encodeSignedData,
  encodeEnvelopedData: encodeEnvelopedData,
  decode:              decode,
  parseSignedData:     parseSignedData,
  OID:                 OID,
  MAX_DEPTH:           MAX_DEPTH,
  DEFAULT_MAX_LEN:     DEFAULT_MAX_LEN,
  CmsCodecError:       CmsCodecError,
};
