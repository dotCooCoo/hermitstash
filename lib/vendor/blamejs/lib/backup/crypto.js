// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var C = require("../constants");
var safeBuffer = require("../safe-buffer");
var { xchacha20poly1305 } = require("../vendor/noble-ciphers.cjs");
var argon2 = require("../argon2-builtin");
var { FrameworkError } = require("../framework-error");

class BackupCryptoError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "BackupCryptoError";
    this.permanent = true;
    this.isBackupCryptoError = true;
  }
}

var ARGON2_OPTS = Object.freeze({
  type:        2,
  memoryCost:  C.BYTES.kib(64),
  timeCost:    3,
  parallelism: 4,
  hashLength:  C.BYTES.bytes(32),
  raw:         true,
});

var SALT_BYTES  = C.BYTES.bytes(32);
var NONCE_BYTES = C.BYTES.bytes(24);

function checksum(buf) {
  if (!Buffer.isBuffer(buf) && typeof buf !== "string") {
    throw new BackupCryptoError("backup-crypto/bad-input",
      "checksum: argument must be a Buffer or string");
  }
  return nodeCrypto.createHash("sha3-512").update(buf).digest("hex");
}

function _validateSaltHex(saltHex) {
  if (!safeBuffer.isHex(saltHex) || saltHex.length % 2 !== 0) {
    throw new BackupCryptoError("backup-crypto/bad-salt",
      "saltHex must be a non-empty hex string with even length");
  }
}

function _validatePassphrase(p) {
  if (!Buffer.isBuffer(p) && typeof p !== "string") {
    throw new BackupCryptoError("backup-crypto/bad-passphrase",
      "passphrase must be a Buffer or string");
  }
  if (Buffer.isBuffer(p) ? p.length === 0 : p.length === 0) {
    throw new BackupCryptoError("backup-crypto/bad-passphrase",
      "passphrase must be non-empty");
  }
}

async function deriveKey(passphrase, saltHex, opts) {
  _validatePassphrase(passphrase);
  _validateSaltHex(saltHex);
  var argonOpts = Object.assign({}, ARGON2_OPTS, opts || {}, {
    salt: Buffer.from(saltHex, "hex"),
  });
  var hash = await argon2.hash(passphrase, argonOpts);
  if (!Buffer.isBuffer(hash) || hash.length !== ARGON2_OPTS.hashLength) {
    throw new BackupCryptoError("backup-crypto/derive-failed",
      "argon2 hash returned unexpected output (expected " + ARGON2_OPTS.hashLength +
      "-byte Buffer, got " + (hash && hash.length) + ")");
  }
  return hash;
}

function _aadBytes(aad) {
  if (aad === undefined || aad === null) return undefined;
  if (Buffer.isBuffer(aad)) return new Uint8Array(aad);
  if (typeof aad === "string") return new Uint8Array(Buffer.from(aad, "utf8"));
  throw new BackupCryptoError("backup-crypto/bad-aad",
    "associated data must be a Buffer or string");
}

async function encryptWithPassphrase(plaintext, passphrase, saltHex, aad) {
  if (!Buffer.isBuffer(plaintext) && typeof plaintext !== "string") {
    throw new BackupCryptoError("backup-crypto/bad-plaintext",
      "encryptWithPassphrase: plaintext must be a Buffer or string");
  }
  var plainBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8");
  var key = await deriveKey(passphrase, saltHex);
  var nonce = nodeCrypto.randomBytes(NONCE_BYTES);
  var ct = xchacha20poly1305(new Uint8Array(key), nonce, _aadBytes(aad)).encrypt(new Uint8Array(plainBuf));
  return Buffer.concat([nonce, Buffer.from(ct)]);
}

async function decryptWithPassphrase(encrypted, passphrase, saltHex, aad) {
  if (!Buffer.isBuffer(encrypted)) {
    throw new BackupCryptoError("backup-crypto/bad-input",
      "decryptWithPassphrase: encrypted must be a Buffer");
  }
  if (encrypted.length <= NONCE_BYTES) {
    throw new BackupCryptoError("backup-crypto/bad-input",
      "decryptWithPassphrase: encrypted buffer is too short to contain nonce + tag");
  }
  var key = await deriveKey(passphrase, saltHex);
  var nonce = encrypted.subarray(0, NONCE_BYTES);
  var ct    = encrypted.subarray(NONCE_BYTES);
  var plain;
  try {
    plain = xchacha20poly1305(new Uint8Array(key), new Uint8Array(nonce), _aadBytes(aad))
      .decrypt(new Uint8Array(ct));
  } catch (e) {
    throw new BackupCryptoError("backup-crypto/decrypt-failed",
      "XChaCha20-Poly1305 decryption failed (wrong passphrase, tampered ciphertext, or blob remapped to a different path): " +
      ((e && e.message) || String(e)));
  }
  return Buffer.from(plain);
}

async function encryptWithFreshSalt(plaintext, passphrase, aad) {
  var salt = nodeCrypto.randomBytes(SALT_BYTES);
  var saltHex = salt.toString("hex");
  var encrypted = await encryptWithPassphrase(plaintext, passphrase, saltHex, aad);
  return { encrypted: encrypted, salt: saltHex };
}

module.exports = {
  deriveKey:             deriveKey,
  encryptWithPassphrase: encryptWithPassphrase,
  decryptWithPassphrase: decryptWithPassphrase,
  encryptWithFreshSalt:  encryptWithFreshSalt,
  checksum:              checksum,
  ARGON2_OPTS:           ARGON2_OPTS,
  SALT_BYTES:            SALT_BYTES,
  NONCE_BYTES:           NONCE_BYTES,
  BackupCryptoError:     BackupCryptoError,
};
