// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.backupCrypto
 * @nav    Production
 * @title  Backup Crypto
 * @slug   backup-crypto
 *
 * @intro
 *   The encryption a backup bundle is built from: Argon2id to turn the
 *   operator's passphrase into a key, HKDF-SHA3-512 to derive a per-file
 *   subkey from it, and XChaCha20-Poly1305 over the bytes.
 *
 *   Deriving per file matters. One key over every entry means a single
 *   ciphertext-reuse mistake reaches the whole bundle, and it also means the
 *   expensive passphrase derivation would have to run per file. A bundle key
 *   derived once and a cheap subkey per file gives separation without paying
 *   Argon2id again.
 *
 *   The subkey's label is derived from the file's path, so a blob moved to a
 *   different path inside the bundle no longer decrypts. That is deliberate:
 *   it makes the manifest's idea of what a file is part of what the ciphertext
 *   is bound to, and the decryption failure says so.
 *
 *   A derived key is zeroed as soon as the operation using it returns, so a
 *   bundle written in one pass does not leave a key reachable in the heap for
 *   the life of the process.
 *
 * @card
 *   The backup bundle's encryption: Argon2id from the passphrase, an
 *   HKDF-SHA3-512 subkey per file bound to its path, XChaCha20-Poly1305 over
 *   the bytes, and keys zeroed on the way out.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("../crypto");
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
var TAG_BYTES   = C.BYTES.bytes(16);
var MIN_SEALED_BYTES = NONCE_BYTES + TAG_BYTES;

function _assertSealedLength(encrypted, callerLabel) {
  if (!Buffer.isBuffer(encrypted)) {
    throw new BackupCryptoError("backup-crypto/bad-input",
      callerLabel + ": encrypted must be a Buffer");
  }
  if (encrypted.length < MIN_SEALED_BYTES) {
    throw new BackupCryptoError("backup-crypto/bad-input",
      callerLabel + ": encrypted buffer is " + encrypted.length +
      " bytes, under the " + MIN_SEALED_BYTES + " a " + NONCE_BYTES +
      "-byte nonce and a " + TAG_BYTES + "-byte tag need");
  }
}

/**
 * @primitive b.backupCrypto.checksum
 * @signature b.backupCrypto.checksum(buf)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupCrypto.fileKeyLabel, b.backupManifest.create
 *
 * The SHA3-512 digest of a Buffer or string, as hex. This is the digest a
 * manifest records per file, so a restore can tell a truncated or altered
 * entry from an intact one before trying to decrypt it.
 *
 * Anything that is not a Buffer or a string raises
 * `backup-crypto/bad-input`, rather than digesting a coerced value and
 * recording a checksum of something that was never written.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.backupCrypto.checksum("contents").length;   // → 128 hex characters
 */
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

/**
 * @primitive b.backupCrypto.deriveKey
 * @signature b.backupCrypto.deriveKey(passphrase, saltHex, opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupCrypto.deriveSubkey, b.backupCrypto.newSalt, b.auth.password.gate
 *
 * Derive the 32-byte bundle key from the operator's passphrase with Argon2id,
 * at 64 MiB, three passes and four lanes.
 *
 * The derivation runs through the Argon2id gate, so it is bounded by the same
 * concurrency limit and cost ceiling as a login. A backup started while the
 * gate is full is refused as `argon2/busy` rather than queuing without limit.
 *
 * The caller owns the returned Buffer and should zero it. Everything in this
 * module that derives internally zeroes its own copy on the way out.
 *
 * An empty or non-string passphrase raises `backup-crypto/bad-passphrase`, a
 * salt that is not even-length hex raises `backup-crypto/bad-salt`, and a
 * derivation answering with anything other than 32 bytes raises
 * `backup-crypto/derive-failed` rather than returning a key of the wrong
 * length.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 65536
 *   timeCost:    number,   // passes; default 3
 *   parallelism: number,   // lanes; default 4
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var salt = b.backupCrypto.newSalt();
 *   var key = await b.backupCrypto.deriveKey("the passphrase", salt);
 *   try { key.length; } finally { key.fill(0); }
 */
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

var VAULT_KEY_LABEL = "blamejs-backup/vault-key";

/**
 * @primitive b.backupCrypto.fileKeyLabel
 * @signature b.backupCrypto.fileKeyLabel(relativePath)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.deriveSubkey, b.backupCrypto.encryptUnderSubkey
 *
 * The HKDF label for one file's subkey, derived from the file's path inside
 * the bundle.
 *
 * Binding the label to the path is what makes a blob undecryptable after it is
 * moved to another path in the bundle: the subkey for the new path is a
 * different key. A restore that finds a remapped blob therefore fails to
 * decrypt rather than restoring one file's contents under another file's name.
 *
 * The path is digested rather than used directly, so a label is a fixed length
 * whatever the path is, and a path containing characters HKDF would otherwise
 * carry through is reduced to hex.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.backupCrypto.fileKeyLabel("db/app.db");
 *   // → "blamejs-backup/file:<digest of the path>"
 */
function fileKeyLabel(relativePath) {
  return "blamejs-backup/file:" + checksum(String(relativePath));
}

function _validateKey(key, label) {
  if (!Buffer.isBuffer(key) || key.length !== ARGON2_OPTS.hashLength) {
    throw new BackupCryptoError("backup-crypto/bad-key",
      label + ": key must be a " + ARGON2_OPTS.hashLength + "-byte Buffer");
  }
}

/**
 * @primitive b.backupCrypto.deriveSubkey
 * @signature b.backupCrypto.deriveSubkey(bundleKey, saltHex, label)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.deriveKey, b.backupCrypto.fileKeyLabel
 *
 * Derive a 32-byte subkey from the bundle key with HKDF-SHA3-512, using the
 * bundle salt and a label.
 *
 * This is the cheap half of the scheme: the bundle key costs one Argon2id
 * derivation, and every file's key comes from here, so a bundle of a thousand
 * files does not cost a thousand passphrase derivations.
 *
 * `bundleKey` has to be a 32-byte Buffer (`backup-crypto/bad-key`), `saltHex`
 * even-length hex (`backup-crypto/bad-salt`) and `label` a non-empty string
 * (`backup-crypto/bad-label`). An empty label would give every file the same
 * subkey, which is the property the scheme exists to avoid.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sub = b.backupCrypto.deriveSubkey(bundleKey, salt,
 *     b.backupCrypto.fileKeyLabel("db/app.db"));
 *   try { sub.length; } finally { sub.fill(0); }
 */
function deriveSubkey(bundleKey, saltHex, label) {
  _validateKey(bundleKey, "deriveSubkey");
  _validateSaltHex(saltHex);
  if (typeof label !== "string" || label.length === 0) {
    throw new BackupCryptoError("backup-crypto/bad-label", "deriveSubkey: label must be a non-empty string");
  }
  return Buffer.from(nodeCrypto.hkdfSync("sha3-512", bundleKey, Buffer.from(saltHex, "hex"),
    Buffer.from(label, "utf8"), ARGON2_OPTS.hashLength));
}

/**
 * @primitive b.backupCrypto.encryptWithKey
 * @signature b.backupCrypto.encryptWithKey(plaintext, key, aad?)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.decryptWithKey, b.backupCrypto.encryptUnderSubkey
 *
 * Encrypt with XChaCha20-Poly1305 under a 32-byte key and return the nonce
 * followed by the ciphertext in one Buffer.
 *
 * A fresh 24-byte nonce is generated per call and prepended, so the caller
 * never chooses one and cannot reuse one. XChaCha20's nonce is large enough
 * that random generation is safe for the number of entries a bundle holds.
 *
 * `aad` is authenticated but not encrypted, which is how a ciphertext is bound
 * to its context: the same bytes under the same key with different `aad` will
 * not decrypt.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sealed = b.backupCrypto.encryptWithKey("contents", key, "db/app.db");
 *   sealed.length > b.backupCrypto.NONCE_BYTES;   // → true
 */
function encryptWithKey(plaintext, key, aad) {
  if (!Buffer.isBuffer(plaintext) && typeof plaintext !== "string") {
    throw new BackupCryptoError("backup-crypto/bad-plaintext",
      "encryptWithKey: plaintext must be a Buffer or string");
  }
  _validateKey(key, "encryptWithKey");
  var plainBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8");
  var nonce = nodeCrypto.randomBytes(NONCE_BYTES);
  var ct = xchacha20poly1305(new Uint8Array(key), nonce, _aadBytes(aad)).encrypt(new Uint8Array(plainBuf));
  return Buffer.concat([nonce, Buffer.from(ct)]);
}

/**
 * @primitive b.backupCrypto.decryptWithKey
 * @signature b.backupCrypto.decryptWithKey(encrypted, key, aad?)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.encryptWithKey, b.backupCrypto.decryptUnderSubkey
 *
 * Decrypt what `encryptWithKey` produced, reading the nonce from the front of
 * the buffer.
 *
 * A buffer under `MIN_SEALED_BYTES`, the 24-byte nonce plus the 16-byte
 * Poly1305 tag, cannot hold a sealed value at all, so it raises
 * `backup-crypto/bad-input` before any key material is touched. A key that is
 * not 32 bytes raises `backup-crypto/bad-key`, and an `aad` that is neither a
 * string nor a Buffer raises `backup-crypto/bad-aad` rather than being
 * coerced, since a coerced `aad` would authenticate different bytes than the
 * caller meant.
 *
 * A failed tag raises `backup-crypto/decrypt-failed`, and the message names
 * all three causes it cannot distinguish: a wrong passphrase, tampered
 * ciphertext, or a blob remapped to a different path. They are
 * indistinguishable because the AEAD only reports that the tag did not verify,
 * and saying so is more useful than picking one.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var plain = b.backupCrypto.decryptWithKey(sealed, key, "db/app.db");
 *   plain.toString("utf8");        // → "contents"
 */
function decryptWithKey(encrypted, key, aad) {
  _assertSealedLength(encrypted, "decryptWithKey");
  _validateKey(key, "decryptWithKey");
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

function _withKey(key, fn) {
  try { return fn(key); }
  finally { key.fill(0); }
}

/**
 * @primitive b.backupCrypto.encryptUnderSubkey
 * @signature b.backupCrypto.encryptUnderSubkey(plaintext, bundleKey, saltHex, label, aad?)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.decryptUnderSubkey, b.backupCrypto.fileKeyLabel
 *
 * Derive the subkey for `label`, encrypt under it, and zero the subkey before
 * returning. This is how a bundle encrypts one file.
 *
 * The subkey never leaves this call, so a caller writing a thousand files
 * leaves no derived keys reachable afterwards. The zeroing happens whether the
 * encryption succeeded or threw.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sealed = b.backupCrypto.encryptUnderSubkey(bytes, bundleKey, salt,
 *     b.backupCrypto.fileKeyLabel("db/app.db"));
 */
function encryptUnderSubkey(plaintext, bundleKey, saltHex, label, aad) {
  return _withKey(deriveSubkey(bundleKey, saltHex, label), function (subkey) {
    return encryptWithKey(plaintext, subkey, aad);
  });
}

/**
 * @primitive b.backupCrypto.decryptUnderSubkey
 * @signature b.backupCrypto.decryptUnderSubkey(encrypted, bundleKey, saltHex, label, aad?)
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.encryptUnderSubkey, b.restoreBundle.extract
 *
 * Derive the subkey for `label`, decrypt under it, and zero the subkey before
 * returning. This is how a restore reads one file.
 *
 * The label comes from the path the manifest records, so a blob that has been
 * moved within the bundle produces a different subkey and fails to decrypt.
 * That failure is the protection, not a malfunction.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var plain = b.backupCrypto.decryptUnderSubkey(sealed, bundleKey, salt,
 *     b.backupCrypto.fileKeyLabel("db/app.db"));
 */
function decryptUnderSubkey(encrypted, bundleKey, saltHex, label, aad) {
  return _withKey(deriveSubkey(bundleKey, saltHex, label), function (subkey) {
    return decryptWithKey(encrypted, subkey, aad);
  });
}

/**
 * @primitive b.backupCrypto.encryptWithPassphrase
 * @signature b.backupCrypto.encryptWithPassphrase(plaintext, passphrase, saltHex, aad?)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupCrypto.decryptWithPassphrase, b.backupCrypto.encryptWithFreshSalt
 *
 * Derive a key from the passphrase and encrypt under it, zeroing the key
 * before returning.
 *
 * This is the form for the one thing a bundle seals under the passphrase
 * itself, the vault key. Everything else goes through a subkey, because this
 * pays a full Argon2id derivation per call.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var salt = b.backupCrypto.newSalt();
 *   var sealed = await b.backupCrypto.encryptWithPassphrase(
 *     vaultKeyJson, passphrase, salt, b.backupCrypto.VAULT_KEY_LABEL);
 */
async function encryptWithPassphrase(plaintext, passphrase, saltHex, aad) {
  if (!Buffer.isBuffer(plaintext) && typeof plaintext !== "string") {
    throw new BackupCryptoError("backup-crypto/bad-plaintext",
      "encryptWithPassphrase: plaintext must be a Buffer or string");
  }
  return _withKey(await deriveKey(passphrase, saltHex), function (key) {
    return encryptWithKey(plaintext, key, aad);
  });
}

/**
 * @primitive b.backupCrypto.decryptWithPassphrase
 * @signature b.backupCrypto.decryptWithPassphrase(encrypted, passphrase, saltHex, aad?)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupCrypto.encryptWithPassphrase, b.restoreBundle.extract
 *
 * Derive a key from the passphrase and decrypt under it, zeroing the key
 * before returning.
 *
 * A buffer under `MIN_SEALED_BYTES`, the 24-byte nonce plus the 16-byte
 * Poly1305 tag, raises `backup-crypto/bad-input` before the derivation runs,
 * so a truncated input does not cost an Argon2id pass first. The 25-to-39
 * byte range used to pass this gate and fail as `backup-crypto/decrypt-failed`
 * after the derivation. The derivation's own refusals reach
 * the caller unchanged: `backup-crypto/bad-passphrase` for an empty or
 * non-string passphrase, `backup-crypto/bad-salt` for a salt that is not
 * even-length hex, and `backup-crypto/derive-failed` for a derivation that
 * answers with the wrong length.
 *
 * Because the derivation is gated, this can be refused with `argon2/busy`
 * under load. That refusal is transient and the read may be retried; the
 * passphrase is not consumed by the attempt.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var vaultKeyJson = await b.backupCrypto.decryptWithPassphrase(
 *     sealed, passphrase, manifest.vaultKeySalt, b.backupCrypto.VAULT_KEY_LABEL);
 */
async function decryptWithPassphrase(encrypted, passphrase, saltHex, aad) {
  _assertSealedLength(encrypted, "decryptWithPassphrase");
  return _withKey(await deriveKey(passphrase, saltHex), function (key) {
    return decryptWithKey(encrypted, key, aad);
  });
}

/**
 * @primitive b.backupCrypto.newSalt
 * @signature b.backupCrypto.newSalt()
 * @since     0.20.31
 * @status    stable
 * @related   b.backupCrypto.deriveKey, b.backupCrypto.encryptWithFreshSalt
 *
 * A fresh 32-byte salt as hex, for one bundle's key derivation.
 *
 * A bundle records its salt in the manifest, so a restore derives the same key
 * from the same passphrase. Reusing a salt across bundles would mean one
 * precomputation applies to all of them, which is what a per-bundle salt
 * prevents.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.backupCrypto.newSalt().length;   // → 64 hex characters
 */
function newSalt() {
  return bCrypto.generateBytes(SALT_BYTES).toString("hex");
}

/**
 * @primitive b.backupCrypto.encryptWithFreshSalt
 * @signature b.backupCrypto.encryptWithFreshSalt(plaintext, passphrase, aad?)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupCrypto.encryptWithPassphrase, b.backupCrypto.newSalt
 *
 * Generate a salt, encrypt under a key derived from the passphrase and that
 * salt, and resolve with `{ encrypted, salt }`.
 *
 * Returning the salt alongside the ciphertext is the point: the salt is not a
 * secret and is useless to lose, so handing both back together is what keeps a
 * caller from storing one without the other and producing a bundle nothing can
 * open.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var out = await b.backupCrypto.encryptWithFreshSalt(vaultKeyJson, passphrase);
 *   out.salt;                      // → record this in the manifest
 */
async function encryptWithFreshSalt(plaintext, passphrase, aad) {
  var saltHex = newSalt();
  var encrypted = await encryptWithPassphrase(plaintext, passphrase, saltHex, aad);
  return { encrypted: encrypted, salt: saltHex };
}

module.exports = {
  deriveKey:             deriveKey,
  deriveSubkey:          deriveSubkey,
  fileKeyLabel:          fileKeyLabel,
  VAULT_KEY_LABEL:       VAULT_KEY_LABEL,
  encryptWithKey:        encryptWithKey,
  decryptWithKey:        decryptWithKey,
  encryptUnderSubkey:    encryptUnderSubkey,
  decryptUnderSubkey:    decryptUnderSubkey,
  encryptWithPassphrase: encryptWithPassphrase,
  decryptWithPassphrase: decryptWithPassphrase,
  encryptWithFreshSalt:  encryptWithFreshSalt,
  newSalt:               newSalt,
  checksum:              checksum,
  ARGON2_OPTS:           ARGON2_OPTS,
  SALT_BYTES:            SALT_BYTES,
  NONCE_BYTES:           NONCE_BYTES,
  TAG_BYTES:             TAG_BYTES,
  MIN_SEALED_BYTES:      MIN_SEALED_BYTES,
  BackupCryptoError:     BackupCryptoError,
};
