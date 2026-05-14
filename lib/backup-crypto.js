"use strict";

/**
 * HermitStash-specific helpers for the backup / restore workers.
 *
 * Symmetric crypto (Argon2id + XChaCha20-Poly1305) and the SHA3-512
 * checksum are imported directly from `b.backupCrypto.*` at every
 * call site. This file is the home of:
 *
 *   - encryptVaultKey / decryptVaultKey   — vault-keypair JSON shape
 *     check + wrapped-mode disk-vs-memory fallback (HS-specific because
 *     blamejs's b.vault has its own keypair shape)
 *   - TLS_FILES                            — the explicit list of TLS
 *     and mTLS files HermitStash backs up alongside the DB; entries
 *     point at relative paths under DATA_DIR
 */

var b = require("./vendor/blamejs");
var C = require("./constants");
var fs = require("fs/promises");
var nodePath = require("path");

// ---- Vault key encrypt/decrypt ----

/**
 * Encrypt the vault keypair JSON for backup storage.
 *
 * Two input modes:
 *   1. vaultKeyJson (preferred, required for wrapped mode): caller passes the
 *      in-memory plaintext vault key JSON directly. The backup worker in
 *      lib/backup.js obtains this via vault.getKeysJson().
 *   2. Fallback: if vaultKeyJson is null/undefined, read the plaintext
 *      vault.key file from disk. FAILS in wrapped mode because vault.key
 *      doesn't exist on disk there.
 */
async function encryptVaultKey(passphrase, dataDir, vaultKeyJson) {
  var vaultKeyData;
  if (vaultKeyJson) {
    vaultKeyData = String(vaultKeyJson);
  } else {
    var vaultKeyPath = nodePath.join(dataDir, "vault.key");
    var nodeFs = require("fs");
    if (!nodeFs.existsSync(vaultKeyPath)) {
      throw new Error("vault.key not found — complete the setup wizard before running backups. (In wrapped mode, the backup caller must pass vaultKeyJson — see lib/backup.js runBackup.)");
    }
    vaultKeyData = await fs.readFile(vaultKeyPath, "utf8");
  }
  var saltHex = b.crypto.generateToken(C.BYTES.bytes(32));
  var encrypted = await b.backupCrypto.encryptWithPassphrase(
    Buffer.from(vaultKeyData, "utf8"),
    passphrase,
    saltHex,
  );
  return { encrypted: encrypted, salt: saltHex };
}

async function decryptVaultKey(encrypted, passphrase, saltHex) {
  var decrypted = await b.backupCrypto.decryptWithPassphrase(encrypted, passphrase, saltHex);
  var json = decrypted.toString("utf8");
  var parsed = b.safeJson.parse(json);
  if (!parsed.ecPublicKey || !parsed.ecPrivateKey) {
    throw new Error("Invalid vault key — missing ecPublicKey or ecPrivateKey");
  }
  if (!parsed.publicKey || !parsed.privateKey) {
    throw new Error("Invalid vault key — missing ML-KEM publicKey or privateKey");
  }
  return json;
}

// ---- Shared constants ----

// Files included in TLS-scope backups. Each entry is optional — backup
// skips entries whose `local` doesn't exist on disk. v1.9.4 added the
// .sealed variants for ca.key and tls/privkey.pem; deployments may have
// either the sealed or plaintext form depending on operator opt-in.
var TLS_FILES = [
  { local: "tls/fullchain.pem", key: "tls-fullchain.pem.enc" },
  { local: "tls/privkey.pem", key: "tls-privkey.pem.enc" },
  { local: "tls/privkey.pem.sealed", key: "tls-privkey.pem.sealed.enc" },
  { local: "ca.key", key: "ca.key.enc" },
  { local: "ca.key.sealed", key: "ca.key.sealed.enc" },
  { local: "ca.crt", key: "ca.crt.enc" },
];

module.exports = {
  encryptVaultKey: encryptVaultKey,
  decryptVaultKey: decryptVaultKey,
  TLS_FILES: TLS_FILES,
};
