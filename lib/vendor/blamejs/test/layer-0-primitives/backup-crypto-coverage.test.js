// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backupCrypto input-refusal coverage.
 *
 * The passphrase/salt/plaintext/AAD guards each fail closed with a typed
 * BackupCryptoError before any key derivation runs, and the derived-key
 * length is checked rather than trusted — a short key would otherwise reach
 * XChaCha20 and surface as an opaque error much later.
 *
 * Also pins the AEAD associated-data binding: a blob sealed under one path
 * must not decrypt under another (the blob-remap defence).
 */

var helpers = require("../helpers");

var b = helpers.b;
var check = helpers.check;

var VALID_SALT = "00112233445566778899aabbccddeeff";
var PASSPHRASE = "correct horse battery staple";

async function _refusesAsync(label, fn, code) {
  var err = null;
  try { await fn(); } catch (e) { err = e; }
  check(label, !!err && err.name === "BackupCryptoError" && err.code === code);
}

function _refusesSync(label, fn, code) {
  var err = null;
  try { fn(); } catch (e) { err = e; }
  check(label, !!err && err.name === "BackupCryptoError" && err.code === code);
}

function testChecksumInputGuard() {
  _refusesSync("checksum: a number is refused",
    function () { b.backupCrypto.checksum(123); }, "backup-crypto/bad-input");
  _refusesSync("checksum: null is refused",
    function () { b.backupCrypto.checksum(null); }, "backup-crypto/bad-input");
  _refusesSync("checksum: a plain object is refused",
    function () { b.backupCrypto.checksum({}); }, "backup-crypto/bad-input");

  // Both accepted input shapes hash identically — the digest is over bytes,
  // not over the JavaScript type.
  var fromString = b.backupCrypto.checksum("payload");
  var fromBuffer = b.backupCrypto.checksum(Buffer.from("payload", "utf8"));
  check("checksum: a string and its Buffer hash identically", fromString === fromBuffer);
  check("checksum: emits a 128-char sha3-512 hex digest",
    /^[0-9a-f]{128}$/.test(fromString));
}

async function testPassphraseAndSaltGuards() {
  // Non-string, non-Buffer passphrases are refused by type before length.
  await _refusesAsync("deriveKey: a numeric passphrase is refused",
    function () { return b.backupCrypto.deriveKey(123, VALID_SALT); },
    "backup-crypto/bad-passphrase");
  await _refusesAsync("deriveKey: a null passphrase is refused",
    function () { return b.backupCrypto.deriveKey(null, VALID_SALT); },
    "backup-crypto/bad-passphrase");
  await _refusesAsync("deriveKey: an object passphrase is refused",
    function () { return b.backupCrypto.deriveKey({ pass: "x" }, VALID_SALT); },
    "backup-crypto/bad-passphrase");

  // Right type, no entropy.
  await _refusesAsync("deriveKey: an empty string passphrase is refused",
    function () { return b.backupCrypto.deriveKey("", VALID_SALT); },
    "backup-crypto/bad-passphrase");
  await _refusesAsync("deriveKey: an empty Buffer passphrase is refused",
    function () { return b.backupCrypto.deriveKey(Buffer.alloc(0), VALID_SALT); },
    "backup-crypto/bad-passphrase");

  // Salt must be whole bytes of hex.
  await _refusesAsync("deriveKey: a non-hex salt is refused",
    function () { return b.backupCrypto.deriveKey(PASSPHRASE, "zzzz"); },
    "backup-crypto/bad-salt");
  await _refusesAsync("deriveKey: an odd-length hex salt is refused",
    function () { return b.backupCrypto.deriveKey(PASSPHRASE, "abc"); },
    "backup-crypto/bad-salt");
  await _refusesAsync("deriveKey: an empty salt is refused",
    function () { return b.backupCrypto.deriveKey(PASSPHRASE, ""); },
    "backup-crypto/bad-salt");
}

async function testDerivedKeyLengthIsVerified() {
  // The derived-key length is checked rather than assumed: an override that
  // yields anything but a full-length key fails loudly here instead of
  // producing a short key that XChaCha20 rejects much later.
  await _refusesAsync("deriveKey: a short-key override is refused rather than passed on",
    function () { return b.backupCrypto.deriveKey(PASSPHRASE, VALID_SALT, { hashLength: 16 }); },
    "backup-crypto/derive-failed");

  // The unoverridden path yields a key of exactly the AEAD's key length.
  var key = await b.backupCrypto.deriveKey(PASSPHRASE, VALID_SALT);
  check("deriveKey: the default derivation yields a 32-byte key",
    Buffer.isBuffer(key) && key.length === 32);

  // Derivation is deterministic for a given passphrase + salt, and the salt
  // actually participates (a different salt yields a different key).
  var again = await b.backupCrypto.deriveKey(PASSPHRASE, VALID_SALT);
  check("deriveKey: the same passphrase and salt derive the same key",
    key.equals(again));
  var otherSalt = await b.backupCrypto.deriveKey(PASSPHRASE, "ffeeddccbbaa99887766554433221100");
  check("deriveKey: a different salt derives a different key", !key.equals(otherSalt));
}

async function testEncryptDecryptInputGuards() {
  await _refusesAsync("encryptWithPassphrase: a numeric plaintext is refused",
    function () { return b.backupCrypto.encryptWithPassphrase(123, PASSPHRASE, VALID_SALT); },
    "backup-crypto/bad-plaintext");
  await _refusesAsync("encryptWithPassphrase: a null plaintext is refused",
    function () { return b.backupCrypto.encryptWithPassphrase(null, PASSPHRASE, VALID_SALT); },
    "backup-crypto/bad-plaintext");

  await _refusesAsync("decryptWithPassphrase: a string ciphertext is refused",
    function () { return b.backupCrypto.decryptWithPassphrase("not-a-buffer", PASSPHRASE, VALID_SALT); },
    "backup-crypto/bad-input");

  // Anything at or below the nonce length cannot also carry a tag.
  await _refusesAsync("decryptWithPassphrase: a nonce-length buffer is refused as too short",
    function () { return b.backupCrypto.decryptWithPassphrase(Buffer.alloc(24), PASSPHRASE, VALID_SALT); },
    "backup-crypto/bad-input");
  await _refusesAsync("decryptWithPassphrase: an empty buffer is refused as too short",
    function () { return b.backupCrypto.decryptWithPassphrase(Buffer.alloc(0), PASSPHRASE, VALID_SALT); },
    "backup-crypto/bad-input");
}

async function testAssociatedDataBinding() {
  // AAD must be bytes or text; anything else is a caller error, not a
  // silently-ignored argument.
  await _refusesAsync("encryptWithFreshSalt: a numeric AAD is refused",
    function () { return b.backupCrypto.encryptWithFreshSalt("payload", PASSPHRASE, 123); },
    "backup-crypto/bad-aad");
  await _refusesAsync("encryptWithFreshSalt: an object AAD is refused",
    function () { return b.backupCrypto.encryptWithFreshSalt("payload", PASSPHRASE, { path: "x" }); },
    "backup-crypto/bad-aad");

  // A blob sealed under one path must not open under another. This is the
  // blob-remap defence: moving a bundle blob to a different manifest entry
  // fails the AEAD tag rather than silently restoring to the wrong path.
  var sealed = await b.backupCrypto.encryptWithFreshSalt("secret-bytes", PASSPHRASE, "files/db.enc");
  var opened = await b.backupCrypto.decryptWithPassphrase(
    sealed.encrypted, PASSPHRASE, sealed.salt, "files/db.enc");
  check("AAD: a blob decrypts under the path it was sealed with",
    opened.toString("utf8") === "secret-bytes");

  await _refusesAsync("AAD: the same blob is refused under a different path (blob-remap defence)",
    function () {
      return b.backupCrypto.decryptWithPassphrase(
        sealed.encrypted, PASSPHRASE, sealed.salt, "files/other.enc");
    },
    "backup-crypto/decrypt-failed");

  await _refusesAsync("AAD: the same blob is refused with the binding dropped entirely",
    function () {
      return b.backupCrypto.decryptWithPassphrase(sealed.encrypted, PASSPHRASE, sealed.salt);
    },
    "backup-crypto/decrypt-failed");

  // A Buffer AAD and its string form are the same associated data.
  var viaBuffer = await b.backupCrypto.decryptWithPassphrase(
    sealed.encrypted, PASSPHRASE, sealed.salt, Buffer.from("files/db.enc", "utf8"));
  check("AAD: a Buffer AAD binds identically to the equivalent string",
    viaBuffer.toString("utf8") === "secret-bytes");

  // Wrong passphrase fails the tag just like a remapped blob.
  await _refusesAsync("AAD: a wrong passphrase is refused",
    function () {
      return b.backupCrypto.decryptWithPassphrase(
        sealed.encrypted, "wrong passphrase", sealed.salt, "files/db.enc");
    },
    "backup-crypto/decrypt-failed");

  // Each seal draws a fresh salt, so the same plaintext never yields the same
  // ciphertext — an attacker cannot tell two blobs hold identical bytes.
  var again = await b.backupCrypto.encryptWithFreshSalt("secret-bytes", PASSPHRASE, "files/db.enc");
  check("AAD: a second seal of the same bytes uses a fresh salt",
    again.salt !== sealed.salt);
  check("AAD: a second seal of the same bytes yields different ciphertext",
    !again.encrypted.equals(sealed.encrypted));
}

async function run() {
  testChecksumInputGuard();
  await testPassphraseAndSaltGuards();
  await testDerivedKeyLengthIsVerified();
  await testEncryptDecryptInputGuards();
  await testAssociatedDataBinding();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-crypto-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
