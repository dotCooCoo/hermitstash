"use strict";

/**
 * Shared crypto utilities for backup and restore workers.
 *
 * Argon2id key derivation + XChaCha20-Poly1305 symmetric encryption,
 * used to encrypt/decrypt vault.key and backup manifests.
 */

var crypto = require("crypto");
var fs = require("fs/promises");
var path = require("path");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var argon2 = require("./vendor/argon2");

// Argon2id parameters (consistent across backup + restore)
var ARGON2_OPTS = { type: 2, memoryCost: 65536, timeCost: 3, parallelism: 4, hashLength: 32, raw: true };

// ---- Hashing ----

function sha3Hash(data) {
  return crypto.createHash("sha3-512").update(data).digest("hex");
}

function bufferChecksum(buf) { return sha3Hash(buf); }

// ---- Symmetric encrypt/decrypt ----

async function deriveKey(passphrase, saltHex) {
  return argon2.hash(passphrase, Object.assign({}, ARGON2_OPTS, { salt: Buffer.from(saltHex, "hex") }));
}

async function encryptWithPassphrase(plaintext, passphrase, saltHex) {
  var hash = await deriveKey(passphrase, saltHex);
  var nonce = crypto.randomBytes(24);
  var ct = xchacha20poly1305(new Uint8Array(hash), nonce).encrypt(new Uint8Array(plaintext));
  return Buffer.concat([nonce, Buffer.from(ct)]);
}

async function decryptWithPassphrase(encrypted, passphrase, saltHex) {
  if (!saltHex) throw new Error("Salt required for decryption");
  var nonce = encrypted.subarray(0, 24);
  var ct = encrypted.subarray(24);
  var hash = await deriveKey(passphrase, saltHex);
  var plain = xchacha20poly1305(new Uint8Array(hash), new Uint8Array(nonce)).decrypt(new Uint8Array(ct));
  return Buffer.from(plain);
}

// ---- Vault key encrypt/decrypt ----

async function encryptVaultKey(passphrase, dataDir) {
  var vaultKeyPath = path.join(dataDir, "vault.key");
  var fsSync = require("fs");
  if (!fsSync.existsSync(vaultKeyPath)) {
    throw new Error("vault.key not found — complete the setup wizard before running backups.");
  }
  var vaultKeyData = await fs.readFile(vaultKeyPath, "utf8");
  var salt = crypto.randomBytes(32);
  var saltHex = salt.toString("hex");
  var nonce = crypto.randomBytes(24);
  var hash = await deriveKey(passphrase, saltHex);
  var plaintext = Buffer.from(vaultKeyData, "utf8");
  var ct = xchacha20poly1305(new Uint8Array(hash), nonce).encrypt(new Uint8Array(plaintext));
  return {
    encrypted: Buffer.concat([nonce, Buffer.from(ct)]),
    salt: saltHex,
  };
}

async function decryptVaultKey(encrypted, passphrase, saltHex) {
  var decrypted = await decryptWithPassphrase(encrypted, passphrase, saltHex);
  var json = decrypted.toString("utf8");
  var parsed = JSON.parse(json);
  if (!parsed.ecPublicKey || !parsed.ecPrivateKey) {
    throw new Error("Invalid vault key — missing ecPublicKey or ecPrivateKey");
  }
  if (!parsed.publicKey || !parsed.privateKey) {
    throw new Error("Invalid vault key — missing ML-KEM publicKey or privateKey");
  }
  return json;
}

// ---- Shared constants ----

var TLS_FILES = [
  { local: "tls/fullchain.pem", key: "tls-fullchain.pem.enc" },
  { local: "tls/privkey.pem", key: "tls-privkey.pem.enc" },
  { local: "ca.key", key: "ca.key.enc" },
  { local: "ca.crt", key: "ca.crt.enc" },
];

module.exports = {
  sha3Hash: sha3Hash,
  bufferChecksum: bufferChecksum,
  encryptWithPassphrase: encryptWithPassphrase,
  decryptWithPassphrase: decryptWithPassphrase,
  encryptVaultKey: encryptVaultKey,
  decryptVaultKey: decryptVaultKey,
  TLS_FILES: TLS_FILES,
};
