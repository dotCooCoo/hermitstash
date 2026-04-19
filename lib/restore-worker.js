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

var DATA_DIR = workerData.dataDir;

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
    } catch (_e) {}
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

  // 2b. Snapshot live files before overwriting — enables rollback on crash
  progress("snapshot", "Creating pre-restore snapshots...", 25);
  var snapshotFiles = ["db.key.enc", "hermitstash.db.enc", "vault.key"];
  for (var s = 0; s < snapshotFiles.length; s++) {
    var srcPath = path.join(DATA_DIR, snapshotFiles[s]);
    var snapPath = srcPath + ".pre-restore";
    try {
      if (fsSync.existsSync(srcPath)) {
        fsSync.copyFileSync(srcPath, snapPath);
      }
    } catch (_e) { /* file may not exist on first-ever run */ }
  }

  // 3. Download db.key.enc
  progress("dbkey", "Downloading database key...", 30);
  var dbKeyEntry = manifest.files["db.key.enc"];
  if (dbKeyEntry) {
    var dbKeyBuf = await backend.getBuffer(dbKeyEntry.s3Key);
    if (bufferChecksum(dbKeyBuf) !== dbKeyEntry.checksum) {
      throw new Error("db.key.enc checksum mismatch — backup may be corrupt");
    }
    var dbKeyTmp = path.join(DATA_DIR, "db.key.enc.tmp");
    await fs.writeFile(dbKeyTmp, dbKeyBuf);
    await fs.rename(dbKeyTmp, path.join(DATA_DIR, "db.key.enc"));
  }

  // 4. Download hermitstash.db.enc
  progress("database", "Downloading database...", 40);
  var dbEncEntry = manifest.files["hermitstash.db.enc"];
  if (dbEncEntry) {
    var dbEncBuf = await backend.getBuffer(dbEncEntry.s3Key);
    if (bufferChecksum(dbEncBuf) !== dbEncEntry.checksum) {
      throw new Error("hermitstash.db.enc checksum mismatch — backup may be corrupt");
    }
    var dbEncTmp = path.join(DATA_DIR, "hermitstash.db.enc.tmp");
    await fs.writeFile(dbEncTmp, dbEncBuf);
    await fs.rename(dbEncTmp, path.join(DATA_DIR, "hermitstash.db.enc"));
  }

  // 5. Write vault.key (atomic: write .tmp then rename)
  progress("vault", "Writing vault key...", 45);
  var vaultTmp = path.join(DATA_DIR, "vault.key.tmp");
  await fs.writeFile(vaultTmp, vaultKeyJson, "utf8");
  await fs.rename(vaultTmp, path.join(DATA_DIR, "vault.key"));

  // 5b. Restore TLS certificates and mTLS CA (encrypted in backup)
  var tlsRestored = 0;
  for (var t = 0; t < TLS_FILES.length; t++) {
    var tlsEntry = manifest.files[TLS_FILES[t].key];
    if (tlsEntry) {
      try {
        var tlsEncBuf = await backend.getBuffer(tlsEntry.s3Key);
        var tlsPlain = await decryptWithPassphrase(tlsEncBuf, passphrase, targetHeader.argon2Salt);
        var tlsLocalPath = path.join(DATA_DIR, TLS_FILES[t].local);
        var tlsDir = path.dirname(tlsLocalPath);
        if (!fsSync.existsSync(tlsDir)) await fs.mkdir(tlsDir, { recursive: true });
        var tlsTmp = tlsLocalPath + ".tmp";
        await fs.writeFile(tlsTmp, tlsPlain);
        await fs.rename(tlsTmp, tlsLocalPath);
        tlsRestored++;
      } catch (_e) {}
    }
  }
  if (tlsRestored > 0) progress("tls", "Restored " + tlsRestored + " TLS/mTLS files", 50);

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

        if (restoreToS3) {
          // Validate S3 key — reject path traversal attempts.
          // Throw rather than continue so the per-file catch counts the rejection
          // toward failedUploads and surfaces the reason in the progress stream.
          if (relPath.includes("..") || relPath.startsWith("/")) {
            throw new Error("Rejected unsafe relative path: " + relPath);
          }
          // Restore to storage S3 bucket (matches s3:// paths in database)
          await storageS3.put(relPath, fileBuf);
        } else {
          // Restore to local disk
          var localPath = path.join(uploadDir, relPath);
          var resolved = path.resolve(localPath);
          if (!resolved.startsWith(path.resolve(uploadDir) + path.sep)) {
            throw new Error("Rejected path that escapes upload directory: " + relPath);
          }
          var dir = path.dirname(localPath);
          if (!fsSync.existsSync(dir)) await fs.mkdir(dir, { recursive: true });
          await fs.writeFile(localPath, fileBuf);
        }
        restored++;
      } catch (err) {
        failedUploads++;
        progress("uploads", "Failed to restore " + relPath + ": " + err.message, 50 + Math.round((j / uploadCount) * 45));
      }
    }

    progress("uploads", "Restored " + restored + " of " + uploadCount + " files" + (restoreToS3 ? " to S3" : " to local disk") + (failedUploads > 0 ? " (" + failedUploads + " failed)" : ""), 95);
  }

  // Clean up pre-restore snapshots on success
  for (var cs = 0; cs < snapshotFiles.length; cs++) {
    try { fsSync.unlinkSync(path.join(DATA_DIR, snapshotFiles[cs] + ".pre-restore")); } catch (_e) {}
  }

  progress("complete", "Restore complete", 100);
  var stats = { dbFiles: Object.keys(manifest.files).length, uploadFiles: restored, failedUploads: failedUploads, totalUploads: uploadCount, scope: manifest.scope };
  var msg = { type: "success", stats: stats };
  if (failedUploads > 0) msg.warning = failedUploads + " upload files could not be restored — check backup bucket connectivity.";
  parentPort.postMessage(msg);
}

// ---- Entry point ----

runRestore()
  .catch(function (err) { parentPort.postMessage({ type: "error", error: err.message }); });
