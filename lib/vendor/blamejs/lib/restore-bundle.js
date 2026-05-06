"use strict";
/**
 * restore-bundle — extract an encrypted backup bundle to a staging dir.
 *
 * The mirror of backup-bundle. Reads manifest.json from a bundle
 * directory, decrypts each per-file blob via backup-crypto, verifies
 * each plaintext's sha3-512 checksum matches the manifest, and writes
 * the recovered files to a staging directory the caller then atomically
 * swaps into place. The bundle directory itself is read-only throughout.
 *
 *   var r = await b.restoreBundle.extract({
 *     bundleDir:    "./backups/2026-04-27.bundle",
 *     stagingDir:   "./data.staging",       // must NOT exist
 *     passphrase:   Buffer.from("operator passphrase"),
 *     filter:       function (entry) { return true; },  // optional
 *     progressCallback: function (event) { ... },
 *   });
 *   // → { manifest, vaultKeyJson, fileCount, totalBytes,
 *   //     stagingDir, durationMs }
 *
 * vaultKeyJson is the decrypted vault keypair JSON the bundle carried
 * in manifest.vaultKeyEnc. The caller decides what to do with it:
 * write to stagingDir/vault.key for a fresh framework boot, hand to
 * vault.init for an in-process load, etc. — restore-bundle's job ends
 * at recovery; vault-key placement is operator policy.
 *
 * filter: optional predicate that lets a caller pull a subset (only
 * the DB, only the TLS keys, etc.). The vault key is always recovered
 * regardless of filter so the operator can read sealed values from a
 * partial restore.
 *
 * Defense:
 *   - Wrong passphrase → AEAD tag check fails on first blob →
 *     restore-bundle/decrypt-failed (no plaintext leaked, no staging
 *     left behind)
 *   - Tampered blob (single byte flip in ciphertext) → same path
 *   - encryptedSize mismatch → restore-bundle/size-mismatch (cheap
 *     pre-decrypt check)
 *   - Plaintext sha3-512 != manifest.checksum → restore-bundle/
 *     checksum-mismatch (post-decrypt integrity guard)
 *   - Missing blob file → restore-bundle/missing-blob (manifest
 *     references a path the bundle dir doesn't have)
 *   - On any failure, the partially-built stagingDir is removed so a
 *     subsequent retry isn't blocked by a stale dir
 */

var fs = require("fs");
var path = require("path");
var atomicFile = require("./atomic-file");
var backupCrypto = require("./backup/crypto");
var backupManifest = require("./backup/manifest");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var RestoreBundleError = defineClass("RestoreBundleError", { alwaysPermanent: true });

function _emit(cb, ev) {
  if (typeof cb === "function") {
    try { cb(ev); } catch (_e) { /* progress-callback errors are non-fatal */ }
  }
}

function _cleanupStaging(stagingDir) {
  // Best-effort recursive remove — if cleanup fails, surface that to
  // the caller via stderr but never override the original error
  // we're already throwing.
  try { fs.rmSync(stagingDir, { recursive: true, force: true }); }
  catch (_e) { /* best-effort */ }
}

async function extract(opts) {
  var t0 = Date.now();
  opts = opts || {};
  if (typeof opts.bundleDir !== "string" || !fs.existsSync(opts.bundleDir)) {
    throw new RestoreBundleError("restore-bundle/no-bundle",
      "extract: opts.bundleDir is required and must exist");
  }
  validateOpts.requireNonEmptyString(opts.stagingDir, "extract: opts.stagingDir", RestoreBundleError, "restore-bundle/no-staging");
  if (fs.existsSync(opts.stagingDir)) {
    throw new RestoreBundleError("restore-bundle/staging-exists",
      "extract: stagingDir already exists: " + opts.stagingDir +
      " (refusing to merge into existing directory — pick a fresh path)");
  }
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new RestoreBundleError("restore-bundle/no-passphrase",
      "extract: opts.passphrase is required (Buffer or string)");
  }
  var passphrase = opts.passphrase;
  var bundleDir = opts.bundleDir;
  var stagingDir = opts.stagingDir;
  var filter = typeof opts.filter === "function" ? opts.filter : null;
  var progress = opts.progressCallback;

  // 1. Read + parse + validate manifest
  _emit(progress, { phase: "read_manifest" });
  var manifestPath = path.join(bundleDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new RestoreBundleError("restore-bundle/missing-manifest",
      "extract: bundleDir has no manifest.json — bundle is incomplete or not a blamejs backup");
  }
  var manifest;
  try {
    manifest = backupManifest.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (e) {
    if (e && e.isBackupManifestError) throw e;
    throw new RestoreBundleError("restore-bundle/bad-manifest",
      "extract: manifest could not be parsed: " + ((e && e.message) || String(e)));
  }

  // 2. Recover the vault key (always, regardless of filter — the
  // operator may need it to unseal post-restore even on partial
  // restores)
  _emit(progress, { phase: "unwrap_vault_key" });
  var vaultKeyJson;
  try {
    var vkBuf = await backupCrypto.decryptWithPassphrase(
      Buffer.from(manifest.vaultKeyEnc, "base64"),
      passphrase,
      manifest.vaultKeySalt);
    vaultKeyJson = vkBuf.toString("utf8");
  } catch (e) {
    if (e && e.isBackupCryptoError && e.code === "backup-crypto/decrypt-failed") {
      throw new RestoreBundleError("restore-bundle/decrypt-failed",
        "extract: passphrase rejected (vault key did not decrypt). " +
        "If you have multiple backup passphrases, double-check the one supplied.");
    }
    throw new RestoreBundleError("restore-bundle/vault-key-recovery-failed",
      "extract: could not recover vault key from manifest: " + ((e && e.message) || String(e)));
  }

  atomicFile.ensureDir(stagingDir);

  // 3. Walk manifest.files; decrypt + verify + write each that passes filter
  var fileCount = 0;
  var totalBytes = 0;

  try {
    for (var i = 0; i < manifest.files.length; i++) {
      var entry = manifest.files[i];
      if (filter && !filter(entry)) {
        _emit(progress, { phase: "skip_filtered", relativePath: entry.relativePath });
        continue;
      }

      var blobPath = path.join(bundleDir, entry.encryptedPath);
      if (!fs.existsSync(blobPath)) {
        throw new RestoreBundleError("restore-bundle/missing-blob",
          "extract: manifest references '" + entry.encryptedPath +
          "' but the bundle has no such file");
      }
      var blob = fs.readFileSync(blobPath);
      if (blob.length !== entry.encryptedSize) {
        throw new RestoreBundleError("restore-bundle/size-mismatch",
          "extract: blob '" + entry.encryptedPath + "' has size " + blob.length +
          " but manifest expected " + entry.encryptedSize);
      }

      _emit(progress, {
        phase: "decrypt", relativePath: entry.relativePath,
        encryptedSize: entry.encryptedSize,
      });

      var plaintext;
      try {
        plaintext = await backupCrypto.decryptWithPassphrase(blob, passphrase, entry.salt);
      } catch (e) {
        if (e && e.isBackupCryptoError && e.code === "backup-crypto/decrypt-failed") {
          throw new RestoreBundleError("restore-bundle/decrypt-failed",
            "extract: blob '" + entry.encryptedPath + "' did not decrypt — " +
            "passphrase rejected or ciphertext tampered");
        }
        throw e;
      }
      if (plaintext.length !== entry.size) {
        throw new RestoreBundleError("restore-bundle/size-mismatch",
          "extract: decrypted '" + entry.relativePath +
          "' has " + plaintext.length + " bytes but manifest expected " + entry.size);
      }
      var actualChecksum = backupCrypto.checksum(plaintext);
      if (actualChecksum !== entry.checksum) {
        throw new RestoreBundleError("restore-bundle/checksum-mismatch",
          "extract: decrypted '" + entry.relativePath + "' has checksum " + actualChecksum +
          " but manifest declared " + entry.checksum +
          " — bundle is corrupted or manifest tampered");
      }

      var destPath = path.join(stagingDir, entry.relativePath);
      atomicFile.ensureDir(path.dirname(destPath));
      atomicFile.writeSync(destPath, plaintext, { fileMode: 0o600 });

      fileCount++;
      totalBytes += plaintext.length;
    }
  } catch (e) {
    _cleanupStaging(stagingDir);
    throw e;
  }

  var durationMs = Date.now() - t0;
  _emit(progress, {
    phase: "done",
    fileCount: fileCount,
    totalBytes: totalBytes,
    durationMs: durationMs,
  });
  return {
    manifest:     manifest,
    vaultKeyJson: vaultKeyJson,
    fileCount:    fileCount,
    totalBytes:   totalBytes,
    stagingDir:   stagingDir,
    durationMs:   durationMs,
  };
}

// Inspect a bundle without decrypting — read the manifest and return
// it. Useful for dashboards and pre-flight UI: list files, sizes,
// timestamps, kinds without prompting for the passphrase.
function inspect(opts) {
  opts = opts || {};
  if (typeof opts.bundleDir !== "string" || !fs.existsSync(opts.bundleDir)) {
    throw new RestoreBundleError("restore-bundle/no-bundle",
      "inspect: opts.bundleDir is required and must exist");
  }
  var manifestPath = path.join(opts.bundleDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new RestoreBundleError("restore-bundle/missing-manifest",
      "inspect: bundleDir has no manifest.json");
  }
  return backupManifest.parse(fs.readFileSync(manifestPath, "utf8"));
}

module.exports = {
  extract:             extract,
  inspect:             inspect,
  RestoreBundleError:  RestoreBundleError,
};
