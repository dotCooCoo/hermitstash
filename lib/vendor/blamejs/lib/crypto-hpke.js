// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var { HpkeError } = require("./framework-error");

var _err = HpkeError.factory;

var observability = lazyRequire(function () { return require("./observability"); });
var audit = lazyRequire(function () { return require("./audit"); });

var HPKE_SUITE_LABEL = "blamejs/hpke/v1";
var HPKE_KEM_ID    = 0x21;
var HPKE_KDF_ID    = 0x22;
var HPKE_AEAD_ID   = 0x23;

var HPKE_KEY_LEN   = C.BYTES.bytes(32);
var HPKE_NONCE_LEN = C.BYTES.bytes(24);

function _suiteFixedInfo(info) {
  var infoBuf = info == null ? Buffer.alloc(0)
    : Buffer.isBuffer(info) ? info : Buffer.from(String(info), "utf8");
  return Buffer.concat([
    Buffer.from(HPKE_SUITE_LABEL, "utf8"),
    Buffer.from([0x00, HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID, 0x00]),
    infoBuf,
  ]);
}

function _hkdfSha3(ikm, salt, info, length) {
  return Buffer.from(nodeCrypto.hkdfSync("sha3-512", ikm, salt || Buffer.alloc(0), info, length));
}

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

function seal(opts) {
  _validateSealOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var recipientPub = nodeCrypto.createPublicKey(opts.recipientPubKey);
  var encap;
  try {
    encap = nodeCrypto.encapsulate(recipientPub);
  } catch (e) {
    throw _err("crypto-hpke/kem-encap-failed", "hpke.seal: KEM encapsulate failed: " + e.message);
  }

  var key = _hkdfSha3(encap.sharedKey, Buffer.alloc(0),
                      _suiteFixedInfo(info), HPKE_KEY_LEN);
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

function open(opts) {
  _validateOpenOpts(opts);
  var info = _toBuf(opts.info);
  var aad = _toBuf(opts.aad);

  var priv = nodeCrypto.createPrivateKey(opts.privateKey);
  var sharedSecret;
  try {
    sharedSecret = nodeCrypto.decapsulate(priv, opts.enc);
  } catch (e) {
    throw _err("crypto-hpke/kem-decap-failed", "hpke.open: KEM decapsulate failed: " + e.message);
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
