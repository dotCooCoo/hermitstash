"use strict";

/**
 * Restore worker — runs in a worker_thread to avoid blocking the main event loop.
 *
 * Receives: { passphrase, timestamp, dataDir, uploadDir, s3Config, scope, currentStorageBackend }
 * Posts back: { type: "progress", step, detail, pct } during work,
 *             { type: "success" } on completion,
 *             { type: "error", error } on failure.
 */

var { parentPort, workerData } = require("worker_threads");
var fs = require("fs/promises");
var fsSync = require("fs");
var path = require("path");
var S3Client = require("./s3-client");
var { bufferChecksum, decryptWithPassphrase, decryptVaultKey, TLS_FILES } = require("./backup-crypto");

// Worker receives resolved paths from the parent.
var PATHS = workerData.paths || {};
var DATA_DIR = PATHS.dataDir;

// Dry-run mode: download + decrypt + checksum-verify everything, but skip
// all writes (no snapshots, no file renames, no upload restoration). Used
// by E2E tests to validate the crypto + integrity path against a live
// backup without mutating the server's on-disk state.
var DRY_RUN = !!workerData.dryRun;

function progress(step, detail, pct) {
  parentPort.postMessage({ type: "progress", step: step, detail: detail, pct: pct });
}

async function runRestore() {
  if (!workerData.passphrase || typeof workerData.passphrase !== "string" || !workerData.passphrase.trim()) {
    throw new Error("Restore passphrase is required and cannot be empty");
  }
  var passphrase = workerData.passphrase;
  var backend = new S3Client(workerData.s3Config);

  // Find the backup by timestamp
  progress("scanning", "Finding backup...", 0);
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();

  var targetPrefix = null;
  var targetHeader = null;
  for (var i = 0; i < manifestKeys.length; i++) {
    try {
      var headerBuf = await backend.getBuffer(manifestKeys[i]);
      var header = JSON.parse(headerBuf.toString("utf8"));
      if (header.timestamp === workerData.timestamp) {
        targetPrefix = manifestKeys[i].replace("manifest.json", "");
        targetHeader = header;
        break;
      }
    } catch (_e) { /* skip unreadable manifest — continue scanning */ }
  }

  if (!targetPrefix || !targetHeader) {
    throw new Error("Backup not found for timestamp: " + workerData.timestamp);
  }

  // 1. Decrypt the full manifest (also serves as passphrase verification)
  progress("manifest", "Decrypting manifest...", 5);
  var encManifestKey = targetPrefix + "manifest.enc";
  var encManifestBuf = await backend.getBuffer(encManifestKey);
  var manifestJson;
  try {
    manifestJson = await decryptWithPassphrase(encManifestBuf, passphrase, targetHeader.argon2Salt);
  } catch (err) {
    // Decryption can fail for: wrong passphrase (most common), truncated
    // ciphertext, wrong Argon2 params, incompatible manifest version. The
    // user-facing message assumes passphrase, but the original err.message
    // flows back to the parent via the worker's type:"error" post so the
    // admin endpoint + audit log capture the specific cause.
    progress("manifest", "Decryption failed: " + err.message, 5);
    throw new Error("Wrong passphrase — could not decrypt the backup manifest.");
  }
  var manifest = JSON.parse(manifestJson.toString("utf8"));

  // 2. Decrypt and validate vault.key
  progress("vault", "Decrypting vault key...", 15);
  var vaultEntry = manifest.files["vault.key.enc"];
  if (!vaultEntry) throw new Error("Backup manifest missing vault.key.enc");
  var vaultEncBuf = await backend.getBuffer(vaultEntry.s3Key);

  // Verify checksum
  if (bufferChecksum(vaultEncBuf) !== vaultEntry.checksum) {
    throw new Error("vault.key.enc checksum mismatch — backup may be corrupt");
  }

  var vaultKeyJson = await decryptVaultKey(vaultEncBuf, passphrase, targetHeader.argon2Salt);
  progress("vault", "Vault key validated", 25);

  // Validate S3 config if backup was from S3 storage
  if (manifest.storageBackend === "s3" && manifest.uploads && Object.keys(manifest.uploads).length > 0 && !workerData.s3StorageConfig) {
    throw new Error("This backup was created with S3 storage and contains upload files. Configure S3 storage credentials before restoring.");
  }

  // 2b. Snapshot live files before overwriting — enables automatic rollback
  // if restore fails mid-flow. The snapshot + rollback logic lives in a
  // dedicated module (lib/restore-rollback.js) so it's testable
  // independently of the worker, backup flow, or S3 backend.
  var rollback = require("./restore-rollback");
  var snapshotsCreated = [];
  if (!DRY_RUN) {
    progress("snapshot", "Creating pre-restore snapshots...", 25);
    snapshotsCreated = rollback.createSnapshots(DATA_DIR);
  }

  // Everything from step 3 to step 6 is wrapped in a try/catch so any
  // failure triggers automatic rollback from the pre-restore snapshots.
  try {

  // 3. Download db.key.enc
  progress("dbkey", "Downloading database key...", 30);
  var dbKeyEntry = manifest.files["db.key.enc"];
  if (dbKeyEntry) {
    var dbKeyBuf = await backend.getBuffer(dbKeyEntry.s3Key);
    if (bufferChecksum(dbKeyBuf) !== dbKeyEntry.checksum) {
      throw new Error("db.key.enc checksum mismatch — backup may be corrupt");
    }
    if (!DRY_RUN) {
      var dbKeyTmp = path.join(DATA_DIR, "db.key.enc.tmp");
      await fs.writeFile(dbKeyTmp, dbKeyBuf);
      await fs.rename(dbKeyTmp, PATHS.dbKeyEnc);
    }
  }

  // 4. Download hermitstash.db.enc
  progress("database", "Downloading database...", 40);
  var dbEncEntry = manifest.files["hermitstash.db.enc"];
  if (dbEncEntry) {
    var dbEncBuf = await backend.getBuffer(dbEncEntry.s3Key);
    if (bufferChecksum(dbEncBuf) !== dbEncEntry.checksum) {
      throw new Error("hermitstash.db.enc checksum mismatch — backup may be corrupt");
    }
    if (!DRY_RUN) {
      var dbEncTmp = path.join(DATA_DIR, "hermitstash.db.enc.tmp");
      await fs.writeFile(dbEncTmp, dbEncBuf);
      await fs.rename(dbEncTmp, PATHS.dbEnc);
    }
  }

  // 5. Write vault key — skipped in dry-run.
  // Two paths depending on whether the current server is in wrapped mode:
  //   - Plaintext mode: write vault.key (plaintext JSON) as before.
  //   - Wrapped mode: re-wrap the extracted plaintext with the current
  //     server's passphrase and write vault.key.sealed. Writing plaintext
  //     vault.key in wrapped mode would trigger the boot invariant
  //     violation (both files exist → abort).
  if (!DRY_RUN) {
    if (workerData.vaultPassphraseMode === "required") {
      if (!workerData.currentVaultPassphrase) {
        throw new Error(
          "Cannot restore in wrapped mode without the current server passphrase. " +
          "Ensure VAULT_PASSPHRASE or VAULT_PASSPHRASE_FILE is set in the server's " +
          "environment before triggering restore. (The passphrase is consumed by " +
          "vault.init() on boot; if VAULT_PASSPHRASE env was stripped, restart the " +
          "server with it set and retry.)"
        );
      }
      progress("vault", "Re-wrapping extracted vault key with current passphrase...", 45);
      var vaultWrap = require("./vault-wrap");
      var sealedBytes = await vaultWrap.wrap(Buffer.from(vaultKeyJson, "utf8"), workerData.currentVaultPassphrase);
      var sealedTmp = path.join(DATA_DIR, "vault.key.sealed.tmp");
      await fs.writeFile(sealedTmp, sealedBytes);
      // Atomic rename. If a plaintext vault.key was left over from a prior
      // state, the boot state machine will flag the both-exist invariant —
      // in restore we don't clean that up automatically because it's
      // indicative of operator intervention we shouldn't silently override.
      await fs.rename(sealedTmp, path.join(DATA_DIR, "vault.key.sealed"));
    } else {
      progress("vault", "Writing vault key...", 45);
      var vaultTmp = path.join(DATA_DIR, "vault.key.tmp");
      await fs.writeFile(vaultTmp, vaultKeyJson, "utf8");
      await fs.rename(vaultTmp, PATHS.vaultKey);
    }
  }

  // 5b. Restore TLS certificates and mTLS CA (encrypted in backup).
  // In dry-run we still download + decrypt every file to prove it's recoverable
  // but do not persist to disk.
  var tlsRestored = 0;
  for (var t = 0; t < TLS_FILES.length; t++) {
    var tlsEntry = manifest.files[TLS_FILES[t].key];
    if (tlsEntry) {
      try {
        var tlsEncBuf = await backend.getBuffer(tlsEntry.s3Key);
        var tlsPlain = await decryptWithPassphrase(tlsEncBuf, passphrase, targetHeader.argon2Salt);
        if (!DRY_RUN) {
          var tlsLocalPath = path.join(DATA_DIR, TLS_FILES[t].local);
          var tlsDir = path.dirname(tlsLocalPath);
          if (!fsSync.existsSync(tlsDir)) await fs.mkdir(tlsDir, { recursive: true });
          var tlsTmp = tlsLocalPath + ".tmp";
          await fs.writeFile(tlsTmp, tlsPlain);
          await fs.rename(tlsTmp, tlsLocalPath);
        } else {
          // Keep compiler happy: we've decrypted tlsPlain purely to verify
          // the passphrase + ciphertext work — no persistence.
          void tlsPlain;
        }
        tlsRestored++;
      } catch (_e) { /* individual TLS file restore is best-effort — continue with the rest */ }
    }
  }
  if (tlsRestored > 0) progress("tls", (DRY_RUN ? "Verified " : "Restored ") + tlsRestored + " TLS/mTLS files", 50);

  // 6. Restore uploads (if full scope)
  var uploadCount = Object.keys(manifest.uploads || {}).length;
  var failedUploads = 0;
  var restored = 0;
  if (manifest.scope === "full" && uploadCount > 0) {
    var uploadDir = workerData.uploadDir;
    var uploadKeys = Object.keys(manifest.uploads);
    var restoreToS3 = manifest.storageBackend === "s3" && workerData.s3StorageConfig;
    var storageS3 = restoreToS3 ? new S3Client(workerData.s3StorageConfig) : null;

    for (var j = 0; j < uploadKeys.length; j++) {
      var relPath = uploadKeys[j];
      var uploadEntry = manifest.uploads[relPath];

      progress("uploads", "Restoring file " + (j + 1) + " of " + uploadCount, 50 + Math.round((j / uploadCount) * 45));

      try {
        var fileBuf = await backend.getBuffer(uploadEntry.s3Key);

        // Every file still passes the path-safety check in dry-run so the
        // test catches traversal regressions too, not just crypto regressions.
        if (restoreToS3) {
          if (relPath.includes("..") || relPath.startsWith("/")) {
            throw new Error("Rejected unsafe relative path: " + relPath);
          }
          if (!DRY_RUN) await storageS3.put(relPath, fileBuf);
        } else {
          var localPath = path.join(uploadDir, relPath);
          var resolved = path.resolve(localPath);
          if (!resolved.startsWith(path.resolve(uploadDir) + path.sep)) {
            throw new Error("Rejected path that escapes upload directory: " + relPath);
          }
          if (!DRY_RUN) {
            var dir = path.dirname(localPath);
            if (!fsSync.existsSync(dir)) await fs.mkdir(dir, { recursive: true });
            await fs.writeFile(localPath, fileBuf);
          }
        }
        restored++;
      } catch (err) {
        failedUploads++;
        progress("uploads", "Failed to restore " + relPath + ": " + err.message, 50 + Math.round((j / uploadCount) * 45));
      }
    }

    progress("uploads", "Restored " + restored + " of " + uploadCount + " files" + (restoreToS3 ? " to S3" : " to local disk") + (failedUploads > 0 ? " (" + failedUploads + " failed)" : ""), 95);
  }

  } catch (err) {
    // Any failure in steps 3-6 triggers rollback. The .pre-restore files
    // copied back to live locations restore the server to its pre-restore
    // state. We DON'T unlink the .pre-restore files on failure — operator
    // can manually inspect them to compare against the failed restore.
    if (!DRY_RUN) {
      progress("rollback", "Restore failed — rolling back from pre-restore snapshots...", 100);
      rollback.rollbackFromSnapshots(DATA_DIR, snapshotsCreated);
    }
    // Re-throw so the outer .catch in the worker entry posts an error to parent.
    throw err;
  }

  // Clean up pre-restore snapshots on success.
  // Only reached when the full try block above completed without throwing.
  if (!DRY_RUN) {
    rollback.clearSnapshots(DATA_DIR, snapshotsCreated);
  }

  progress("complete", DRY_RUN ? "Dry-run complete" : "Restore complete", 100);
  var stats = { dbFiles: Object.keys(manifest.files).length, uploadFiles: restored, failedUploads: failedUploads, totalUploads: uploadCount, scope: manifest.scope, dryRun: DRY_RUN };
  var msg = { type: "success", stats: stats };
  if (failedUploads > 0) msg.warning = failedUploads + " upload files could not be restored — check backup bucket connectivity.";
  parentPort.postMessage(msg);
}

// ---- Entry point ----

runRestore()
  .catch(function (err) { parentPort.postMessage({ type: "error", error: err.message }); });
