// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.crypto.hpke
 * @nav        Crypto
 * @title      HPKE envelope
 * @slug       crypto-hpke
 *
 * @intro
 *   A blamejs public-key sealing format: ML-KEM-1024 encapsulation,
 *   HKDF-SHA3-512 key derivation and XChaCha20-Poly1305 encryption. The
 *   format is specific to blamejs and does not interoperate with RFC 9180
 *   HPKE or with any HPKE draft: the key is one HKDF-SHA3-512 output over
 *   the context `"blamejs/hpke/v1" || 00 21 22 23 00 || info`, there is no
 *   RFC 9180 key schedule, and XChaCha20-Poly1305 has no HPKE AEAD
 *   identifier. The bytes `21 22 23` are blamejs domain-separation bytes,
 *   not HPKE registry values. Envelopes sealed here open only with
 *   `b.crypto.hpke.open`.
 *
 *   For RFC 9180 HPKE with ML-KEM-1024 under the registered codepoints, use
 *   `b.crypto.hpke.pq.connolly` or `b.crypto.hpke.pq.wg`.
 *
 *   `seal` and `open` accept only ML-KEM-1024 keys and refuse a key of any
 *   other type with `crypto-hpke/bad-key`.
 *
 *   Each `seal` encapsulates a fresh ML-KEM-1024 shared secret, so every
 *   envelope has its own key and the all-zero 24-byte nonce is used once
 *   per key. `info` and `aad` are bound: a different value on `open` fails
 *   the Poly1305 tag. `seal` and `open` emit `system.hpke.seal` and
 *   `system.hpke.open` audit rows.
 *
 * @card
 *   blamejs ML-KEM-1024 + HKDF-SHA3-512 + XChaCha20-Poly1305 sealing format; for RFC 9180 interop use b.crypto.hpke.pq.
 */

var nodeCrypto = require("node:crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var { HpkeError } = require("./framework-error");

var _err = HpkeError.factory;

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });

var FORMAT_LABEL      = "blamejs/hpke/v1";
var FORMAT_KEM_BYTE   = 0x21;
var FORMAT_KDF_BYTE   = 0x22;
var FORMAT_AEAD_BYTE  = 0x23;
var KEM_KEY_TYPE      = "ml-kem-1024";

var HPKE_KEY_LEN   = C.BYTES.bytes(32);
var HPKE_NONCE_LEN = C.BYTES.bytes(24);

function _formatContext(info) {
  var infoBuf = info == null ? Buffer.alloc(0)
    : Buffer.isBuffer(info) ? info : Buffer.from(String(info), "utf8");
  return Buffer.concat([
    Buffer.from(FORMAT_LABEL, "utf8"),
    Buffer.from([0x00, FORMAT_KEM_BYTE, FORMAT_KDF_BYTE, FORMAT_AEAD_BYTE, 0x00]),
    infoBuf,
  ]);
}

function _hkdfSha3(ikm, salt, info, length) {
  return Buffer.from(nodeCrypto.hkdfSync("sha3-512", ikm, salt || Buffer.alloc(0), info, length));
}

/**
 * @primitive b.crypto.hpke.generateKeyPair
 * @signature b.crypto.hpke.generateKeyPair()
 * @since     0.8.44
 * @status    stable
 * @related   b.crypto.hpke.seal, b.crypto.hpke.open, b.crypto.hpke.pq.wg.generateKeyPair
 *
 * Generate an ML-KEM-1024 key pair as PEM strings: `{ publicKey, privateKey }`,
 * an SPKI public key and a PKCS#8 private key. The pair also works with
 * `b.crypto.hpke.pq.connolly` and `b.crypto.hpke.pq.wg` under their
 * ML-KEM-1024 suites.
 *
 * @example
 *   var pair = b.crypto.hpke.generateKeyPair();
 *   pair.publicKey.indexOf("-----BEGIN PUBLIC KEY-----");   // → 0
 */
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
    "hpke.seal: recipientPubKey", HpkeError, "crypto-hpke/bad-opt");
  if (opts.plaintext == null) {
    throw _err("crypto-hpke/bad-opt", "hpke.seal: plaintext required");
  }
  if (typeof opts.plaintext !== "string" && !Buffer.isBuffer(opts.plaintext)) {
    throw _err("crypto-hpke/bad-opt", "hpke.seal: plaintext must be a string or Buffer, got " + typeof opts.plaintext);
  }
}

function _validateOpenOpts(opts) {
  validateOpts.requireObject(opts, "hpke.open", HpkeError);
  validateOpts.requireNonEmptyString(opts.privateKey,
    "hpke.open: privateKey", HpkeError, "crypto-hpke/bad-opt");
  if (!Buffer.isBuffer(opts.enc)) {
    throw _err("crypto-hpke/bad-opt", "hpke.open: enc must be a Buffer (KEM ciphertext)");
  }
  if (!Buffer.isBuffer(opts.ciphertext)) {
    throw _err("crypto-hpke/bad-opt", "hpke.open: ciphertext must be a Buffer (AEAD output)");
  }
}

function _toBuf(v) {
  if (v == null) return Buffer.alloc(0);
  return Buffer.isBuffer(v) ? v : Buffer.from(String(v), "utf8");
}

/**
 * @primitive b.crypto.hpke.seal
 * @signature b.crypto.hpke.seal(opts)
 * @since     0.8.44
 * @status    stable
 * @related   b.crypto.hpke.open, b.crypto.hpke.generateKeyPair, b.crypto.hpke.pq.wg.seal
 *
 * Seal `plaintext` to an ML-KEM-1024 public key in the blamejs envelope
 * format and return `{ enc, ciphertext }`: `enc` is the 1568-byte ML-KEM-1024
 * ciphertext and `ciphertext` is the XChaCha20-Poly1305 output, the
 * plaintext followed by a 16-byte tag. The envelope opens only with
 * `b.crypto.hpke.open`; it is not an RFC 9180 message.
 *
 * Throws `validate-opts/bad-object` when `opts` is not an object,
 * `crypto-hpke/bad-opt` for a missing `recipientPubKey` or `plaintext`,
 * `crypto-hpke/bad-key` for a `recipientPubKey` that is not a readable
 * public key or is a key of any type other than ML-KEM-1024 (RSA, EC,
 * X25519, X448, ML-KEM-512 and ML-KEM-768 keys are refused),
 * `crypto-hpke/kem-encap-failed` when encapsulation fails, and
 * `crypto-hpke/aead-encrypt-failed` when encryption fails.
 *
 * @opts
 *   recipientPubKey: string,        // ML-KEM-1024 SPKI PEM
 *   plaintext:       Buffer|string,
 *   info:            Buffer|string, // bound into the key derivation
 *   aad:             Buffer|string, // additional authenticated data
 *
 * @example
 *   var pair   = b.crypto.hpke.generateKeyPair();
 *   var sealed = b.crypto.hpke.seal({
 *     recipientPubKey: pair.publicKey,
 *     plaintext:       "hello",
 *     info:            "session-1",
 *   });
 *   sealed.ciphertext.length;   // → 21
 */
function seal(opts) {
  _validateSealOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var recipientPub;
  try {
    recipientPub = nodeCrypto.createPublicKey(opts.recipientPubKey);
  } catch (e) {
    throw _err("crypto-hpke/bad-key", "hpke.seal: recipientPubKey is not a readable public key: " + e.message);
  }
  if (recipientPub.asymmetricKeyType !== KEM_KEY_TYPE) {
    throw _err("crypto-hpke/bad-key", "hpke.seal: recipientPubKey must be an ML-KEM-1024 key, got " +
      recipientPub.asymmetricKeyType);
  }
  var encap;
  try {
    encap = nodeCrypto.encapsulate(recipientPub);
  } catch (e) {
    throw _err("crypto-hpke/kem-encap-failed", "hpke.seal: KEM encapsulate failed: " + e.message);
  }

  var key = _hkdfSha3(encap.sharedKey, Buffer.alloc(0),
                      _formatContext(info), HPKE_KEY_LEN);
  var nonce = Buffer.alloc(HPKE_NONCE_LEN);
  var ct;
  try {
    ct = xchacha20poly1305(key, nonce, aad).encrypt(_toBuf(opts.plaintext));
  } catch (e) {
    throw _err("crypto-hpke/aead-encrypt-failed", "hpke.seal: AEAD encrypt failed: " + e.message);
  }

  try { observability().safeEvent("hpke.seal", 1, { outcome: "success" }); }
  catch (_e) { /* drop-silent — observability emits best-effort */ }

  try {
    audit().safeEmit({
      action:   "system.hpke.seal",
      outcome:  "success",
      metadata: { encBytes: encap.ciphertext.length, ctBytes: ct.length },
    });
  } catch (_e) { /* drop-silent */ }

  return { enc: Buffer.from(encap.ciphertext), ciphertext: Buffer.from(ct) };
}

/**
 * @primitive b.crypto.hpke.open
 * @signature b.crypto.hpke.open(opts)
 * @since     0.8.44
 * @status    stable
 * @related   b.crypto.hpke.seal, b.crypto.hpke.pq.wg.open
 *
 * Open an envelope produced by `b.crypto.hpke.seal` and return the
 * plaintext as a Buffer. `info` and `aad` must equal the values given to
 * `seal`. A failed tag emits a `system.hpke.open` audit row with outcome
 * `failure`.
 *
 * Throws `validate-opts/bad-object` when `opts` is not an object,
 * `crypto-hpke/bad-opt` for a missing `privateKey` or a non-Buffer `enc`
 * or `ciphertext`, `crypto-hpke/bad-key` for a `privateKey` that is not a
 * readable private key or is a key of any type other than ML-KEM-1024,
 * `crypto-hpke/kem-decap-failed` when decapsulation fails, and
 * `crypto-hpke/aead-decrypt-failed` when the tag does not verify.
 *
 * @opts
 *   privateKey:  string,         // ML-KEM-1024 PKCS#8 PEM
 *   enc:         Buffer,
 *   ciphertext:  Buffer,
 *   info:        Buffer|string,
 *   aad:         Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.generateKeyPair();
 *   var sealed = b.crypto.hpke.seal({ recipientPubKey: pair.publicKey, plaintext: "hello" });
 *   var pt = b.crypto.hpke.open({
 *     privateKey: pair.privateKey, enc: sealed.enc, ciphertext: sealed.ciphertext,
 *   });
 *   pt.toString("utf8");   // → "hello"
 */
function open(opts) {
  _validateOpenOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var priv;
  try {
    priv = nodeCrypto.createPrivateKey(opts.privateKey);
  } catch (e) {
    throw _err("crypto-hpke/bad-key", "hpke.open: privateKey is not a readable private key: " + e.message);
  }
  if (priv.type !== "private" || priv.asymmetricKeyType !== KEM_KEY_TYPE) {
    throw _err("crypto-hpke/bad-key", "hpke.open: privateKey must be an ML-KEM-1024 private key, got " +
      priv.asymmetricKeyType);
  }
  var sharedSecret;
  try {
    sharedSecret = nodeCrypto.decapsulate(priv, opts.enc);
  } catch (e) {
    throw _err("crypto-hpke/kem-decap-failed", "hpke.open: KEM decapsulate failed: " + e.message);
  }

  var key = _hkdfSha3(sharedSecret, Buffer.alloc(0),
                      _formatContext(info), HPKE_KEY_LEN);
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
    throw _err("crypto-hpke/aead-decrypt-failed", "hpke.open: AEAD tag verification failed");
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

var SUPPORTED_SUITE = Object.freeze({
  kem:   "ML-KEM-1024",
  kdf:   "HKDF-SHA3-512",
  aead:  "XChaCha20-Poly1305",
  label: FORMAT_LABEL,
});

module.exports = {
  generateKeyPair: generateKeyPair,
  seal:            seal,
  open:            open,
  SUPPORTED_SUITE: SUPPORTED_SUITE,
  HpkeError:       HpkeError,
};
