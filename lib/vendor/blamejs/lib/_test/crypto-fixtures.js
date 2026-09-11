// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var { xchacha20poly1305 } = require("../vendor/noble-ciphers.cjs");
var C = require("../constants");
var bCrypto = require("../crypto");

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
  var key = bCrypto.kdf(Buffer.concat([kem.sharedKey, ecSs]), C.BYTES.bytes(32));
  var nonce = bCrypto.generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([
    0xE1,
    C.KEM_IDS.ML_KEM_1024_P384,
    C.CIPHER_IDS.XCHACHA20_POLY1305,
    C.KDF_IDS.SHAKE256,
  ]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);
  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

module.exports = {
  mintLegacyEnvelope0xE1: mintLegacyEnvelope0xE1,
};
