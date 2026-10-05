// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.restoreBundle
 * @nav    Production
 * @title  Restore Bundle
 *
 * @intro
 *   Backup-bundle reader — verify the manifest signature, list bundle
 *   contents without decrypting, and cherry-pick a restore subset to a
 *   staging directory the caller atomically swaps into place.
 *
 *   The mirror of `b.backupBundle`. `b.restoreBundle.inspect` reads
 *   `manifest.json` and returns the parsed object — useful for
 *   dashboards and pre-flight UI that want to list files, sizes,
 *   timestamps, and kinds before prompting the operator for the
 *   passphrase. `b.restoreBundle.extract` decrypts each per-file blob
 *   via `b.backup/crypto`, verifies the SHA3-512 plaintext checksum
 *   against the manifest, and writes the recovered files into a
 *   fresh `stagingDir`. The bundle directory itself stays read-only
 *   throughout.
 *
 *   `extract` always recovers the wrapped vault key (decrypted JSON
 *   returned on `vaultKeyJson`) so the operator can unseal columns
 *   from a partial restore. The `filter` predicate lets the caller
 *   pull a subset — only the DB, only TLS keys, only the consent
 *   log — without producing every blob.
 *
 *   Defense surface:
 *
 *   - Wrong passphrase / tampered blob → AEAD tag failure →
 *     `restore-bundle/decrypt-failed` (no plaintext leak, no staging
 *     left behind)
 *   - Pre-decrypt `encryptedSize` mismatch → `restore-bundle/
 *     size-mismatch`
 *   - Post-decrypt SHA3-512 ≠ manifest checksum →
 *     `restore-bundle/checksum-mismatch`
 *   - Missing blob file → `restore-bundle/missing-blob`
 *   - Bad manifest signature → `restore-bundle/bad-signature`;
 *     `requireSignature: true` upgrades a missing signature to
 *     `restore-bundle/missing-signature`
 *   - On any failure the partially-built `stagingDir` is removed so a
 *     subsequent retry is not blocked by a stale directory
 *
 * @card
 *   Backup-bundle reader — verify the manifest signature, list bundle contents without decrypting, and cherry-pick a restore subset to a staging directory the caller atomically swaps into place.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var argon2 = require("./argon2-builtin");
var atomicFile = require("./atomic-file");
var safePath = require("./safe-path");
var C = require("./constants");
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

function _readManifest(bundleDir, who) {
  try {
    return backupManifest.readFile(nodePath.join(bundleDir, "manifest.json"), {
      errorFor: function (kind, detail) {
        if (kind === "enoent") {
          return new RestoreBundleError("restore-bundle/missing-manifest",
            who + ": bundleDir has no manifest.json; the bundle is incomplete or is not a blamejs backup");
        }
        if (kind === "too-large") {
          return new RestoreBundleError("restore-bundle/bad-manifest",
            who + ": manifest.json is " + detail.size + " bytes, above the " + detail.max + "-byte limit");
        }
        return new RestoreBundleError("restore-bundle/bad-manifest", who + ": manifest.json unreadable: " + kind);
      },
    });
  } catch (e) {
    if (e && e.isBackupManifestError) {
      throw new RestoreBundleError("restore-bundle/bad-manifest",
        who + ": manifest.json is not a valid backup manifest: " + e.message);
    }
    throw e;
  }
}

function _cleanupStaging(stagingDir) {
  try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); }
  catch (_e) { /* best-effort */ }
}

/**
 * @primitive b.restoreBundle.extract
 * @signature b.restoreBundle.extract(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.restoreBundle.inspect, b.backupBundle.create, b.vault.init
 *
 * Decrypt every blob the manifest references (or the subset
 * `opts.filter` accepts), verify each plaintext's checksum, and write
 * the recovered files into `opts.stagingDir`. Returns
 * `{ manifest, vaultKeyJson, fileCount, totalBytes, stagingDir,
 * durationMs }`.
 *
 * `stagingDir` MUST NOT exist: extract throws
 * `restore-bundle/staging-exists` rather than merge into an existing
 * directory, so a half-finished prior restore can never get silently
 * overlaid. On any failure the partial `stagingDir` is removed.
 *
 * Before reading anything it throws `restore-bundle/no-bundle` when
 * `bundleDir` is absent or does not exist, `restore-bundle/no-staging`
 * when `stagingDir` is absent or empty, and
 * `restore-bundle/no-passphrase` when `passphrase` is neither a Buffer
 * nor a string.
 *
 * Signature handling: when the manifest carries a signature it is
 * verified with `b.backupManifest.verifySignature`. The signing key must
 * match `expectedFingerprint`, or be the active or a rotated
 * `b.auditSign` key; a signature under any other key fails with
 * `restore-bundle/bad-signature`. A process that restores without
 * running `b.auditSign.init()` passes `expectedFingerprint`. Pass
 * `requireSignature: true` to fail closed on a bundle missing a
 * signature, which then throws `restore-bundle/missing-signature`.
 * `verifySignature: false` skips the check, and `requireSignature: true`
 * with `verifySignature: false` throws `restore-bundle/bad-opts`.
 *
 * When the manifest records `keyScheme: "argon2id-hkdf-sha3-512-path-digest"`, each
 * blob is encrypted under a key derived from that bundle's `bundleSalt`,
 * so a blob copied in from another bundle fails with
 * `restore-bundle/decrypt-failed` whether or not the manifest is signed.
 * A manifest without `keyScheme` is read with one Argon2id key per file.
 *
 * Reading the manifest throws `restore-bundle/bad-manifest` when it is
 * unreadable or over its size limit. Each decrypted file is then checked against
 * what the manifest recorded: `restore-bundle/checksum-mismatch` when the
 * plaintext hashes differently and `restore-bundle/size-mismatch` when its
 * length differs, so a tampered blob never reaches the staging directory. A
 * manifest entry naming a blob the bundle does not hold, or one it holds but
 * cannot read, throws `restore-bundle/missing-blob`. A
 * manifest whose vault key cannot be recovered throws
 * `restore-bundle/vault-key-recovery-failed`.
 *
 * @opts
 *   bundleDir:           string,                   // read-only bundle dir (required)
 *   stagingDir:          string,                   // fresh output dir (required, must not exist)
 *   passphrase:          Buffer | string,          // unwrap key (required)
 *   filter:              function (entry): boolean,// subset predicate
 *   progressCallback:    function (ev): void,      // phase events: read_manifest / decrypt / done
 *   verifySignature:     boolean,                  // default: true
 *   requireSignature:    boolean,                  // fail closed on a missing signature
 *   expectedFingerprint: string,                   // trust only the key with this fingerprint
 *
 * @example
 *   try {
 *     var report = await b.restoreBundle.extract({
 *       bundleDir:        "/srv/backups/2026-04-27.bundle",
 *       stagingDir:       "/srv/restore/data.staging",
 *       passphrase:       Buffer.from("operator-passphrase"),
 *       requireSignature: true,
 *       filter:           function (entry) { return entry.kind === "db"; },
 *     });
 *     report.fileCount;            // → 1
 *     typeof report.vaultKeyJson;  // → "string"
 *   } catch (e) {
 *     e.code; // → "restore-bundle/decrypt-failed"
 *   }
 */
async function extract(opts) {
  var t0 = Date.now();
  opts = opts || {};
  validateOpts.optionalBoolean(opts.requireSignature,
    "extract: opts.requireSignature (whether a bundle carrying no signature from a known " +
    "key is refused; anything other than a boolean was read as false, which extracted an " +
    "unsigned bundle under a caller that asked for the opposite)",
    RestoreBundleError, "restore-bundle/bad-opts");
  if (typeof opts.bundleDir !== "string" || !nodeFs.existsSync(opts.bundleDir)) {
    throw new RestoreBundleError("restore-bundle/no-bundle",
      "extract: opts.bundleDir is required and must exist");
  }
  validateOpts.requireNonEmptyString(opts.stagingDir, "extract: opts.stagingDir", RestoreBundleError, "restore-bundle/no-staging");
  if (nodeFs.existsSync(opts.stagingDir)) {
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

  _emit(progress, { phase: "read_manifest" });
  var manifest = _readManifest(bundleDir, "extract");

  var verifySig = opts.verifySignature !== false;
  if (opts.requireSignature === true && !verifySig) {
    throw new RestoreBundleError("restore-bundle/bad-opts",
      "extract: requireSignature: true cannot be combined with verifySignature: false");
  }
  if (verifySig && manifest.signature) {
    var sigResult = backupManifest.verifySignature(manifest, {
      expectedFingerprint: opts.expectedFingerprint || undefined,
    });
    if (!sigResult.ok) {
      throw new RestoreBundleError("restore-bundle/bad-signature",
        "extract: manifest signature invalid: " + sigResult.reason);
    }
  } else if (opts.requireSignature === true && !manifest.signature) {
    throw new RestoreBundleError("restore-bundle/missing-signature",
      "extract: manifest has no signature but opts.requireSignature=true");
  }

  _emit(progress, { phase: "unwrap_vault_key" });
  var bundleKey = manifest.keyScheme === backupManifest.KEY_SCHEME_BUNDLE
    ? await backupCrypto.deriveKey(passphrase, manifest.bundleSalt)
    : null;
  var decrypted;
  try {
    decrypted = await _decryptBundle(manifest, bundleKey, passphrase, bundleDir, stagingDir, filter, progress);
  } finally {
    if (bundleKey) bundleKey.fill(0);
  }

  var durationMs = Date.now() - t0;
  _emit(progress, {
    phase: "done",
    fileCount: decrypted.fileCount,
    totalBytes: decrypted.totalBytes,
    durationMs: durationMs,
  });
  return {
    manifest:     manifest,
    vaultKeyJson: decrypted.vaultKeyJson,
    fileCount:    decrypted.fileCount,
    totalBytes:   decrypted.totalBytes,
    stagingDir:   stagingDir,
    durationMs:   durationMs,
  };
}

async function _decryptBundle(manifest, bundleKey, passphrase, bundleDir, stagingDir, filter, progress) {
  var vaultKeyJson;
  try {
    var vaultKeyEnc = Buffer.from(manifest.vaultKeyEnc, "base64");
    var vkBuf = bundleKey
      ? backupCrypto.decryptUnderSubkey(vaultKeyEnc, bundleKey, manifest.vaultKeySalt,
          backupCrypto.VAULT_KEY_LABEL, backupCrypto.VAULT_KEY_LABEL)
      : await backupCrypto.decryptWithPassphrase(vaultKeyEnc, passphrase, manifest.vaultKeySalt);
    vaultKeyJson = vkBuf.toString("utf8");
  } catch (e) {
    if (e && e.isBackupCryptoError && e.code === "backup-crypto/decrypt-failed") {
      throw new RestoreBundleError("restore-bundle/decrypt-failed",
        "extract: passphrase rejected (vault key did not decrypt). " +
        "If you have multiple backup passphrases, double-check the one supplied.");
    }
    if (argon2.isGateRefusal(e)) throw e;
    throw new RestoreBundleError("restore-bundle/vault-key-recovery-failed",
      "extract: could not recover vault key from manifest: " + ((e && e.message) || String(e)));
  }

  atomicFile.ensureDir(stagingDir);

  var fileCount = 0;
  var totalBytes = 0;

  try {
    for (var i = 0; i < manifest.files.length; i++) {
      var entry = manifest.files[i];
      if (filter && !filter(entry)) {
        _emit(progress, { phase: "skip_filtered", relativePath: entry.relativePath });
        continue;
      }

      var blobPath = safePath.resolve(bundleDir, entry.encryptedPath);
      var blobCap = (typeof entry.encryptedSize === "number" && entry.encryptedSize > 0)
        ? entry.encryptedSize : C.BYTES.gib(8);
      var blob = atomicFile.fdSafeReadSync(blobPath, {
        maxBytes: blobCap,
        errorFor: function (kind, detail) {
          if (kind === "enoent") return new RestoreBundleError("restore-bundle/missing-blob", "extract: manifest references '" + entry.encryptedPath + "' but the bundle has no such file");
          if (kind === "too-large") return new RestoreBundleError("restore-bundle/size-mismatch", "extract: blob '" + entry.encryptedPath + "' has size " + detail.size + " but manifest expected " + entry.encryptedSize);
          return new RestoreBundleError("restore-bundle/missing-blob", "extract: blob '" + entry.encryptedPath + "' unreadable: " + kind);
        },
      });
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
        var blobAad = manifest.aadBound === true ? Buffer.from(entry.relativePath, "utf8") : undefined;
        plaintext = bundleKey
          ? backupCrypto.decryptUnderSubkey(blob, bundleKey, entry.salt, backupCrypto.fileKeyLabel(entry.relativePath), blobAad)
          : await backupCrypto.decryptWithPassphrase(blob, passphrase, entry.salt, blobAad);
      } catch (e) {
        if (e && e.isBackupCryptoError && e.code === "backup-crypto/decrypt-failed") {
          throw new RestoreBundleError("restore-bundle/decrypt-failed",
            "extract: blob '" + entry.encryptedPath + "' did not decrypt — " +
            "passphrase rejected, ciphertext tampered, or blob remapped to a different path");
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

      var destPath = safePath.resolve(stagingDir, entry.relativePath);
      atomicFile.ensureDir(nodePath.dirname(destPath));
      atomicFile.writeSync(destPath, plaintext, { fileMode: 0o600 });

      fileCount++;
      totalBytes += plaintext.length;
    }
  } catch (e) {
    _cleanupStaging(stagingDir);
    throw e;
  }
  return { vaultKeyJson: vaultKeyJson, fileCount: fileCount, totalBytes: totalBytes };
}

/**
 * @primitive b.restoreBundle.inspect
 * @signature b.restoreBundle.inspect(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.restoreBundle.extract, b.backupBundle.create
 *
 * Read `manifest.json` from `opts.bundleDir` and return the parsed
 * object — files, sizes, timestamps, kinds, signature presence —
 * without prompting for the passphrase or decrypting anything. Useful
 * for dashboards, pre-flight UI, and "what's in this bundle?" checks
 * before kicking off a long extract.
 *
 * Throws `RestoreBundleError("restore-bundle/no-bundle")` when
 * `bundleDir` is missing, and
 * `RestoreBundleError("restore-bundle/missing-manifest")` when the
 * directory exists but has no `manifest.json` (the bundle is
 * incomplete or not a blamejs bundle). A `manifest.json` that is
 * unreadable, or larger than the limit `b.backupManifest.serialize`
 * enforces, throws `restore-bundle/bad-manifest`.
 *
 * @opts
 *   bundleDir: string,   // bundle directory (required, must exist)
 *
 * @example
 *   try {
 *     var manifest = b.restoreBundle.inspect({
 *       bundleDir: "/srv/backups/2026-04-27.bundle",
 *     });
 *     manifest.files.length;    // → 12
 *     typeof manifest.signature; // → "string"
 *   } catch (e) {
 *     e.code; // → "restore-bundle/missing-manifest"
 *   }
 */
function inspect(opts) {
  opts = opts || {};
  if (typeof opts.bundleDir !== "string" || !nodeFs.existsSync(opts.bundleDir)) {
    throw new RestoreBundleError("restore-bundle/no-bundle",
      "inspect: opts.bundleDir is required and must exist");
  }
  return _readManifest(opts.bundleDir, "inspect");
}

module.exports = {
  extract:             extract,
  inspect:             inspect,
  RestoreBundleError:  RestoreBundleError,
};
