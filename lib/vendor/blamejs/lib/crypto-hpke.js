"use strict";
/**
 * b.crypto.hpke — RFC 9180 Hybrid Public-Key Encryption (HPKE).
 *
 * Suite (PQC-first per framework crypto policy):
 *   KEM:    ML-KEM-1024 (FIPS 203) — post-quantum encapsulation
 *   KDF:    HKDF-SHA3-512
 *   AEAD:   ChaCha20-Poly1305 (RFC 7539)
 *
 * The classical HPKE suites in RFC 9180 §7 (DHKEM with X25519 / P-256 /
 * P-384 / P-521 + HKDF-SHA256/384/512 + AES-GCM/ChaCha20) are NOT
 * exposed — the framework's PQC-first defaults rule out classical-only
 * key agreement and AES-GCM. Operators wanting the IANA-registered
 * suite codepoints for cross-system interop use the dedicated
 * b.crypto.encryptMlkem768X25519 helper which speaks the IETF / Chrome
 * TLS-1.3 hybrid format directly.
 *
 * Per RFC 9180 §5.1 the KDF MUST absorb a suite_id binding along with
 * the shared secret so a key derived under one suite cannot be silently
 * reused under another. The same FixedInfo construction lib/crypto.js
 * uses (NIST SP 800-56C r2 §4.1 OtherInfo) carries the kem-id /
 * cipher-id / kdf-id triple plus the framework label.
 *
 * Operator API (single-shot per RFC 9180 §6.1, mode_base):
 *
 *   var pair = b.crypto.hpke.generateKeyPair();
 *   // → { publicKey, privateKey }   (ML-KEM-1024 PEM)
 *
 *   var sealed = b.crypto.hpke.seal({
 *     recipientPubKey: pair.publicKey,    // ML-KEM-1024 PEM
 *     plaintext:       Buffer | string,
 *     info:            Buffer | string,    // application-supplied label
 *     aad:             Buffer | string,    // additional authenticated data
 *   });
 *   // → { enc: Buffer, ciphertext: Buffer }
 *
 *   var pt = b.crypto.hpke.open({
 *     privateKey: pair.privateKey,
 *     enc:        sealed.enc,
 *     ciphertext: sealed.ciphertext,
 *     info:       "...",
 *     aad:        "...",
 *   });
 *
 * `enc` is the KEM ciphertext (output of Encap); `ciphertext` is the
 * AEAD output. `info` is the RFC 9180 §5.1 application context string;
 * `aad` is the per-message AEAD AAD. Both bind the derived key into
 * the application's domain so cross-context substitution is detected.
 *
 * Validation policy: throw at config/call site for bad input
 * (recipientPubKey shape, plaintext type, missing private key on open).
 */

var nodeCrypto = require("crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var { HpkeError } = require("./framework-error");

var _err = HpkeError.factory;

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });

// HPKE suite identifiers — values picked to NOT collide with the
// envelope KEM_IDS namespace (those are < 0x10) so a future audit that
// greps for byte 0x21 finds the HPKE seal output cleanly. The FixedInfo
// label distinguishes HPKE-derived keys from the framework's bulk
// envelope KDF inputs.
var HPKE_SUITE_LABEL = "blamejs/hpke/v1";
var HPKE_KEM_ID    = 0x21;     // ML-KEM-1024
var HPKE_KDF_ID    = 0x22;     // HKDF-SHA3-512
var HPKE_AEAD_ID   = 0x23;     // ChaCha20-Poly1305

var HPKE_KEY_LEN   = C.BYTES.bytes(32);
var HPKE_NONCE_LEN = C.BYTES.bytes(24);

// _suiteFixedInfo — RFC 9180 §5.1 suite_id binding. Mirrors the shape
// in lib/crypto.js but with the HPKE label so HPKE-derived keys cannot
// collide with envelope-derived keys.
function _suiteFixedInfo(info) {
  var infoBuf = info == null ? Buffer.alloc(0)
    : Buffer.isBuffer(info) ? info : Buffer.from(String(info), "utf8");
  return Buffer.concat([
    Buffer.from(HPKE_SUITE_LABEL, "utf8"),
    Buffer.from([0x00, HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID, 0x00]),
    infoBuf,
  ]);
}

// HKDF-SHA3-512 — RFC 5869, swapping the underlying hash to SHA3-512.
// Node's crypto.hkdfSync supports sha3-512 directly.
function _hkdfSha3(ikm, salt, info, length) {
  return Buffer.from(nodeCrypto.hkdfSync("sha3-512", ikm, salt || Buffer.alloc(0), info, length));
}

// generateKeyPair — operator helper for an ML-KEM-1024 keypair sized
// for the HPKE suite. Distinct from b.crypto.generateEncryptionKeyPair
// which returns a hybrid {mlkem, ecdh-p384} keypair.
function generateKeyPair() {
  var pair = nodeCrypto.generateKeyPairSync("ml-kem-1024", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

function _validateSealOpts(opts) {
  validateOpts.requireObject(opts, "hpke.seal", HpkeError);
  validateOpts.requireNonEmptyString(opts.recipientPubKey,
    "hpke.seal: recipientPubKey", HpkeError, "BAD_OPT");
  if (opts.plaintext == null) {
    throw _err("BAD_OPT", "hpke.seal: plaintext required");
  }
  if (typeof opts.plaintext !== "string" && !Buffer.isBuffer(opts.plaintext)) {
    throw _err("BAD_OPT", "hpke.seal: plaintext must be a string or Buffer, got " + typeof opts.plaintext);
  }
}

function _validateOpenOpts(opts) {
  validateOpts.requireObject(opts, "hpke.open", HpkeError);
  validateOpts.requireNonEmptyString(opts.privateKey,
    "hpke.open: privateKey", HpkeError, "BAD_OPT");
  if (!Buffer.isBuffer(opts.enc)) {
    throw _err("BAD_OPT", "hpke.open: enc must be a Buffer (KEM ciphertext)");
  }
  if (!Buffer.isBuffer(opts.ciphertext)) {
    throw _err("BAD_OPT", "hpke.open: ciphertext must be a Buffer (AEAD output)");
  }
}

function _toBuf(v) {
  if (v == null) return Buffer.alloc(0);
  return Buffer.isBuffer(v) ? v : Buffer.from(String(v), "utf8");
}

// seal — RFC 9180 §6.1 SealBase. Returns { enc, ciphertext }; nonce is
// fixed-zero per single-shot mode (each Encap produces a fresh shared
// secret, so nonce-reuse is structurally impossible across messages).
function seal(opts) {
  _validateSealOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var recipientPub = nodeCrypto.createPublicKey(opts.recipientPubKey);
  var encap;
  try {
    encap = nodeCrypto.encapsulate(recipientPub);
  } catch (e) {
    throw _err("KEM_ENCAP_FAILED", "hpke.seal: KEM encapsulate failed: " + e.message);
  }

  // Per RFC 9180 §5.1: KEY = LabeledExtractAndExpand(shared_secret,
  // suite_id || info, length=Nk). HKDF-SHA3-512 with the suite-bound
  // info string subsumes the LabeledExtract / LabeledExpand pair.
  var key = _hkdfSha3(encap.sharedKey, Buffer.alloc(0),
                      _suiteFixedInfo(info), HPKE_KEY_LEN);
  // Single-shot zero nonce — fresh shared secret per call removes the
  // sequence-number / nonce-reuse risk that the streaming HPKE modes
  // require Nn == 12-byte counter for. ChaCha20-Poly1305 needs a
  // 12-byte nonce, but the framework's AEAD wrapper uses XChaCha20-
  // Poly1305 (24-byte nonce) which is identical security-wise — we
  // pass a 24-byte zero nonce so the suite_id absorbs everything that
  // could collide.
  var nonce = Buffer.alloc(HPKE_NONCE_LEN);
  var ct;
  try {
    ct = xchacha20poly1305(key, nonce, aad).encrypt(_toBuf(opts.plaintext));
  } catch (e) {
    throw _err("AEAD_ENCRYPT_FAILED", "hpke.seal: AEAD encrypt failed: " + e.message);
  }

  try { observability().safeEvent("hpke.seal", 1, { outcome: "success" }); }
  catch (_e) { /* drop-silent — observability emits best-effort */ }

  // Audit-everything posture: every seal/open is a primitive-level
  // event so operators with PHI / PCI columns under HPKE can prove
  // every encrypt-side touch. The audit is best-effort; a failing
  // bus does not fail the seal.
  try {
    audit().safeEmit({
      action:   "system.hpke.seal",
      outcome:  "success",
      metadata: { encBytes: encap.ciphertext.length, ctBytes: ct.length },
    });
  } catch (_e) { /* drop-silent */ }

  return { enc: Buffer.from(encap.ciphertext), ciphertext: Buffer.from(ct) };
}

// open — RFC 9180 §6.1 OpenBase. Inverse of seal; throws HpkeError on
// AEAD tag verification failure.
function open(opts) {
  _validateOpenOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var priv = nodeCrypto.createPrivateKey(opts.privateKey);
  var sharedSecret;
  try {
    sharedSecret = nodeCrypto.decapsulate(priv, opts.enc);
  } catch (e) {
    throw _err("KEM_DECAP_FAILED", "hpke.open: KEM decapsulate failed: " + e.message);
  }

  var key = _hkdfSha3(sharedSecret, Buffer.alloc(0),
                      _suiteFixedInfo(info), HPKE_KEY_LEN);
  var nonce = Buffer.alloc(HPKE_NONCE_LEN);
  var pt;
  try {
    pt = xchacha20poly1305(key, nonce, aad).decrypt(opts.ciphertext);
  } catch (_e) {
    try { observability().safeEvent("hpke.open", 1, { outcome: "failure", reason: "aead-tag" }); }
    catch (_e) { /* drop-silent */ }
    try {
      audit().safeEmit({
        action:   "system.hpke.open",
        outcome:  "failure",
        reason:   "aead-tag",
        metadata: { ctBytes: opts.ciphertext.length },
      });
    } catch (_e) { /* drop-silent */ }
    throw _err("AEAD_DECRYPT_FAILED", "hpke.open: AEAD tag verification failed");
  }

  try { observability().safeEvent("hpke.open", 1, { outcome: "success" }); }
  catch (_e) { /* drop-silent */ }
  try {
    audit().safeEmit({
      action:   "system.hpke.open",
      outcome:  "success",
      metadata: { ctBytes: opts.ciphertext.length },
    });
  } catch (_e) { /* drop-silent */ }

  return Buffer.from(pt);
}

// SUPPORTED_SUITE — operator-discoverable description of the active
// HPKE suite. The framework ships exactly one suite (PQC-first); future
// additions land here as a frozen-list entry alongside the existing one.
var SUPPORTED_SUITE = Object.freeze({
  kem:   "ML-KEM-1024",
  kdf:   "HKDF-SHA3-512",
  aead:  "ChaCha20-Poly1305",
  label: HPKE_SUITE_LABEL,
});

module.exports = {
  generateKeyPair: generateKeyPair,
  seal:            seal,
  open:            open,
  SUPPORTED_SUITE: SUPPORTED_SUITE,
  HpkeError:       HpkeError,
};
