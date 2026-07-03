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
var atomicFile = require("./atomic-file");
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

function _cleanupStaging(stagingDir) {
  // Best-effort recursive remove — if cleanup fails, surface that to
  // the caller via stderr but never override the original error
  // we're already throwing.
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
 * `stagingDir` MUST NOT exist — extract refuses to merge into an
 * existing directory so a half-finished prior restore can never get
 * silently overlaid. On any failure the partial `stagingDir` is
 * removed.
 *
 * Signature handling: when the manifest carries a signature it is
 * verified with `b.backup/manifest`'s public-key check. Pass
 * `verifySignature: false` for cold restores from an org whose
 * audit-sign keypair the framework cannot reach; pass
 * `requireSignature: true` to fail-closed on bundles missing a
 * signature; pass `expectedFingerprint` to pin a specific signing
 * key.
 *
 * @opts
 *   bundleDir:           string,                   // read-only bundle dir (required)
 *   stagingDir:          string,                   // fresh output dir (required, must not exist)
 *   passphrase:          Buffer | string,          // unwrap key (required)
 *   filter:              function (entry): boolean,// subset predicate
 *   progressCallback:    function (ev): void,      // phase events: read_manifest / decrypt / done
 *   verifySignature:     boolean,                  // default: true
 *   requireSignature:    boolean,                  // fail-closed on missing signature
 *   expectedFingerprint: string,                   // pin specific signing key
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

  // 1. Read + parse + validate manifest
  _emit(progress, { phase: "read_manifest" });
  var manifestPath = nodePath.join(bundleDir, "manifest.json");
  // Capped fd-bound read OUTSIDE the parse try/catch, so a missing / oversized
  // bundle manifest surfaces the precise restore-bundle code (not a generic
  // parse error). A backup manifest is small JSON; 4 MiB bounds a hostile one
  // before backupManifest.parse materializes it.
  var manifestRaw = atomicFile.fdSafeReadSync(manifestPath, {
    maxBytes: C.BYTES.mib(4), encoding: "utf8",
    errorFor: function (kind, detail) {
      if (kind === "enoent") return new RestoreBundleError("restore-bundle/missing-manifest", "extract: bundleDir has no manifest.json — bundle is incomplete or not a blamejs backup");
      if (kind === "too-large") return new RestoreBundleError("restore-bundle/bad-manifest", "extract: manifest.json exceeds " + detail.max + " bytes");
      return new RestoreBundleError("restore-bundle/bad-manifest", "extract: manifest unreadable: " + kind);
    },
  });
  var manifest;
  try {
    manifest = backupManifest.parse(manifestRaw);
  } catch (e) {
    if (e && e.isBackupManifestError) throw e;
    throw new RestoreBundleError("restore-bundle/bad-manifest",
      "extract: manifest could not be parsed: " + ((e && e.message) || String(e)));
  }

  // Verify the manifest signature when present. Operators can pass
  // `requireSignature: true` to fail-closed on missing signatures
  // (HIPAA/PCI-DSS), `expectedFingerprint` to pin a specific signing
  // key, or pass `verifySignature: false` to skip verification when
  // the signing key is genuinely unavailable (cold-restore from a
  // separate org with their own audit-sign keypair the framework
  // can't reach).
  var verifySig = opts.verifySignature !== false;
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

      var blobPath = nodePath.join(bundleDir, entry.encryptedPath);
      // Cap the read to the manifest's declared encryptedSize so an oversize-on-
      // disk blob is refused BEFORE it is read into memory (was: read fully, then
      // compare → an OOM window for a huge swapped blob). A valid blob is exactly
      // encryptedSize; the post-read compare still catches the under-size case.
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
        // Bundles written with manifest.aadBound sealed each blob with its
        // relativePath as AEAD associated data — pass the SAME path so a blob
        // remapped to a different manifest entry fails the tag here (the
        // blob-remap / restore-corruption defense). Legacy bundles without
        // the flag decrypt with no AAD (backward compatible).
        var blobAad = manifest.aadBound === true ? Buffer.from(entry.relativePath, "utf8") : undefined;
        plaintext = await backupCrypto.decryptWithPassphrase(blob, passphrase, entry.salt, blobAad);
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

      var destPath = nodePath.join(stagingDir, entry.relativePath);
      atomicFile.ensureDir(nodePath.dirname(destPath));
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
 * incomplete or not a blamejs bundle).
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
  var manifestPath = nodePath.join(opts.bundleDir, "manifest.json");
  // Capped fd-bound read (no-passphrase preview path, reachable with only read
  // access to the bundle): bound a hostile manifest before parse.
  return backupManifest.parse(atomicFile.fdSafeReadSync(manifestPath, {
    maxBytes: C.BYTES.mib(4), encoding: "utf8",
    errorFor: function (kind) {
      if (kind === "enoent") return new RestoreBundleError("restore-bundle/missing-manifest", "inspect: bundleDir has no manifest.json");
      if (kind === "too-large") return new RestoreBundleError("restore-bundle/bad-manifest", "inspect: manifest.json too large");
      return new RestoreBundleError("restore-bundle/missing-manifest", "inspect: manifest unreadable: " + kind);
    },
  }));
}

module.exports = {
  extract:             extract,
  inspect:             inspect,
  RestoreBundleError:  RestoreBundleError,
};
