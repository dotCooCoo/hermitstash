// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * lib/_test/crypto-fixtures.js — test-only fixtures for crypto round-
 * trip coverage. Not part of the public `b.*` surface; not loaded by
 * `index.js`. Operator code never reaches here — the only callers are
 * tests under `test/layer-0-primitives/crypto-*.test.js` and
 * fuzz harnesses that exercise the legacy-envelope read path.
 *
 * The leading underscore in the directory name signals "internal" to
 * downstream consumers walking the tree; the `_test` segment makes the
 * intent explicit. `package.json#files` MUST NOT include `lib/_test/`
 * so the published tarball doesn't ship these mints to operators.
 */

var nodeCrypto = require("node:crypto");
var { xchacha20poly1305 } = require("../vendor/noble-ciphers.cjs");
var C = require("../constants");
var bCrypto = require("../crypto");

/**
 * mintLegacyEnvelope0xE1 — produce a pre-bump 0xE1-shape envelope
 * sealing `plaintext` against `recipient = { publicKey, ecPublicKey }`.
 * The 0xE1 wire shape matches 0xE2 except the magic byte is 0xE1 AND
 * the KDF input concatenates only (mlkemSs || ecSs), omitting the
 * NIST SP 800-56C r2 §4.1 FixedInfo suite-binding bytes the v0.7.16
 * bump introduced. Used by crypto-envelope tests to round-trip a
 * known-shape 0xE1 blob through `b.crypto.decrypt(..., { allowLegacy: true })`.
 *
 * Production code NEVER calls this — operators with at-rest 0xE1 data
 * sealed those bytes pre-bump and the framework's only contract today
 * is READING them, never producing them.
 */
function mintLegacyEnvelope0xE1(plaintext, recipient) {
  var mlkemPub = nodeCrypto.createPublicKey(recipient.publicKey);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "P-384",
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey:  nodeCrypto.createPublicKey(recipient.ecPublicKey),
  });
  // KDF input: NO FixedInfo — that's the 0xE1 → 0xE2 difference.
  var key = bCrypto.kdf(Buffer.concat([kem.sharedKey, ecSs]), C.BYTES.bytes(32));
  var nonce = bCrypto.generateBytes(C.BYTES.bytes(24));
  // Legacy 0xE1 envelope header — 4 bytes: magic, kemId, cipherId, kdfId.
  var headerAad = Buffer.from([
    0xE1,                                                                                            // legacy 0xE1 envelope magic byte
    C.KEM_IDS.ML_KEM_1024_P384,
    C.CIPHER_IDS.XCHACHA20_POLY1305,
    C.KDF_IDS.SHAKE256,
  ]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);                     // 16-bit length-prefix field
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);                           // 16-bit length-prefix field
  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

module.exports = {
  mintLegacyEnvelope0xE1: mintLegacyEnvelope0xE1,
};
