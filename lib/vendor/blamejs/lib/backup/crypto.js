// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * backup-crypto — passphrase-based symmetric crypto for backup files.
 *
 * The primitive layer used by lib/backup.js and the backup/restore
 * workers. Argon2id key derivation + XChaCha20-Poly1305 AEAD. Salt is
 * managed alongside the ciphertext so backups carry their KDF input
 * with them — restoring a backup needs the bundle's salt + the
 * operator passphrase, nothing else.
 *
 *   var bc = b.backupCrypto;
 *
 *   bc.ARGON2_OPTS                      // baseline KDF parameters
 *
 *   await bc.deriveKey(passphrase, saltHex)
 *     → Buffer(32)                      // raw key bytes for AEAD
 *
 *   await bc.encryptWithPassphrase(plain, passphrase, saltHex)
 *     → Buffer (24-byte nonce + ciphertext+tag)
 *   await bc.decryptWithPassphrase(buf, passphrase, saltHex)
 *     → Buffer (plaintext)
 *
 *   await bc.encryptWithFreshSalt(plain, passphrase)
 *     → { encrypted: Buffer, salt: hexString }
 *
 *   bc.checksum(buf)                    // sha3-512 hex; bundle integrity
 *
 * Argon2id parameters match lib/vault-wrap defaults — backup integrity
 * tracks the framework's at-rest discipline. Operators with stricter
 * requirements (longer passphrases, higher memoryCost) bypass these
 * defaults by passing a full Argon2 opts object to deriveKey.
 *
 * Algorithm choices are deliberate and locked:
 *   - KDF:  Argon2id (RFC 9106) — memory-hard, the only KDF the
 *           framework uses for password-derived keys
 *   - AEAD: XChaCha20-Poly1305 — 24-byte random nonce per message
 *           means we never need to track per-passphrase nonce counters
 *
 * Operators with non-standard cipher needs build their own primitive;
 * this one's whole point is "do the framework's PQC-aligned crypto
 * correctly without per-call decisions".
 */

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

// Baseline Argon2id parameters. Identical to vault-wrap's defaults so
// operators see one set of numbers across the framework's password-
// derivation surfaces. Tuned for: ~64 MiB memory, 3 passes, 4 lanes,
// 32-byte raw output (matches XChaCha20-Poly1305 key length).
var ARGON2_OPTS = Object.freeze({
  type:        2,                       // 2 = argon2id
  memoryCost:  C.BYTES.kib(64),         // 64 MiB expressed in argon2's KiB units
  timeCost:    3,
  parallelism: 4,
  hashLength:  C.BYTES.bytes(32),       // matches XChaCha20-Poly1305 key length
  raw:         true,
});

var SALT_BYTES  = C.BYTES.bytes(32);    // 256 bits — comfortable margin for global uniqueness
var NONCE_BYTES = C.BYTES.bytes(24);    // XChaCha20 nonce length

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
  // Argon2 raw mode returns a Buffer of hashLength bytes. Defensive
  // length check — better to fail loudly than ship a short key into
  // XChaCha20 and trip a later cryptic error.
  if (!Buffer.isBuffer(hash) || hash.length !== ARGON2_OPTS.hashLength) {
    throw new BackupCryptoError("backup-crypto/derive-failed",
      "argon2 hash returned unexpected output (expected " + ARGON2_OPTS.hashLength +
      "-byte Buffer, got " + (hash && hash.length) + ")");
  }
  return hash;
}

// Normalize optional associated-authenticated-data (AAD) into the
// Uint8Array the AEAD expects, or undefined when none. AAD is NOT encrypted
// but IS authenticated: ciphertext sealed under one AAD fails the Poly1305
// tag when decrypted under a different AAD. Backup file blobs pass their
// canonical relativePath so a blob remapped to a different manifest entry is
// cryptographically rejected (the blob-remap / restore-corruption defense).
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

// Convenience for the common "encrypt this with a fresh salt" pattern.
// Returns the salt as hex so callers can store it alongside the
// ciphertext in the bundle manifest. `aad` (optional) is bound as AEAD
// associated data (see _aadBytes).
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
