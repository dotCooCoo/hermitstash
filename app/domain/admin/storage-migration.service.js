var fs = require("fs");
var fsp = require("fs/promises");
var path = require("path");
var config = require("../../../lib/config");
var S3Client = require("../../../lib/s3-client");
var storage = require("../../../lib/storage");
var { isS3Path } = storage;
var logger = require("../../shared/logger");
var filesRepo = require("../../data/repositories/files.repo");
var { ValidationError, AppError } = require("../../shared/errors");

/**
 * Migrate all files between storage backends (local ↔ S3).
 * Files are copied as raw ciphertext — no re-encryption needed since
 * the encryption layer is independent of storage backend.
 *
 * Returns { migrated, skipped, failed, errors[] }
 */
async function migrateStorage(direction, progressCb) {
  if (direction !== "local-to-s3" && direction !== "s3-to-local") {
    throw new ValidationError("Invalid direction: " + direction + " (must be 'local-to-s3' or 's3-to-local')");
  }

  var toS3 = direction === "local-to-s3";
  var uploadDir = storage.uploadDir;

  // Validate S3 is configured
  var s3cfg = config.storage.s3;
  if (!s3cfg || !s3cfg.bucket || !s3cfg.accessKey || !s3cfg.secretKey) {
    throw new ValidationError("S3 storage is not configured. Set bucket, access key, and secret key in admin settings.");
  }

  // Prevent migration into the backup bucket
  var backupBucket = config.backup && config.backup.s3 && config.backup.s3.bucket;
  var backupEndpoint = config.backup && config.backup.s3 && (config.backup.s3.endpoint || "");
  if (backupBucket && backupBucket.trim() === s3cfg.bucket.trim() && (s3cfg.endpoint || "").trim() === backupEndpoint.trim()) {
    throw new ValidationError("Storage bucket and backup bucket are the same. Migration aborted to prevent data loss.");
  }

  var s3 = new S3Client(s3cfg);

  // Test S3 connection before starting
  try {
    await s3.testConnection();
  } catch (err) {
    throw new AppError("S3 connection failed: " + err.message, 502, "S3_UNAVAILABLE");
  }

  var allFiles = filesRepo.findAll({}).filter(function (f) {
    return f.status === "complete" && f.storagePath;
  });

  var result = { migrated: 0, skipped: 0, failed: 0, total: allFiles.length, errors: [] };

  for (var i = 0; i < allFiles.length; i++) {
    var file = allFiles[i];
    var sp = file.storagePath;

    try {
      if (toS3) {
        // Local → S3
        var isAlreadyS3 = isS3Path(sp);
        if (isAlreadyS3) { result.skipped++; continue; }

        // Read raw ciphertext from local disk
        // Failures here throw — the per-file catch below logs and counts them
        // uniformly with the rest of the failure modes.
        var localPath = path.isAbsolute(sp) ? sp : path.join(uploadDir, sp);
        var resolved = path.resolve(localPath);
        if (!resolved.startsWith(path.resolve(uploadDir) + path.sep)) {
          throw new Error("Path escapes upload directory: " + sp);
        }
        if (!fs.existsSync(localPath)) {
          throw new Error("Local file not found: " + sp);
        }
        // Async I/O so the event loop stays responsive during large migrations.
        // Previously used readFileSync which blocked per file — admin UI and
        // concurrent requests stalled on corpora with many files.
        var data = await fsp.readFile(localPath);

        // Derive the S3 key from the relative path
        var s3Key = sp;
        if (path.isAbsolute(sp)) {
          // Convert absolute local path back to relative key
          s3Key = path.relative(uploadDir, sp).replace(/\\/g, "/");
        }

        // Upload to S3
        await s3.put(s3Key, data);

        // Update DB record
        var newPath = "s3://" + s3cfg.bucket + "/" + s3Key;
        filesRepo.update(file._id, { $set: { storagePath: newPath } });

        // Delete local file after successful upload + DB update
        await fsp.unlink(localPath);

        // Clean up empty parent directories (best-effort, async)
        var parentDir = path.dirname(localPath);
        try {
          while (parentDir !== uploadDir) {
            var kids = await fsp.readdir(parentDir);
            if (kids.length !== 0) break;
            await fsp.rmdir(parentDir);
            parentDir = path.dirname(parentDir);
          }
        } catch (_e) {}

        result.migrated++;
      } else {
        // S3 → Local
        var isLocal = !isS3Path(sp);
        if (isLocal) { result.skipped++; continue; }

        // Extract the S3 key from s3://bucket/key
        var s3Key = sp.replace(/^s3:\/\/[^/]+\//, "");

        // Download raw ciphertext from S3
        var data = await s3.getBuffer(s3Key);

        // Write to local disk (async — see note above on responsiveness)
        var localPath = path.join(uploadDir, s3Key);
        var dir = path.dirname(localPath);
        if (!fs.existsSync(dir)) await fsp.mkdir(dir, { recursive: true });
        await fsp.writeFile(localPath, data);

        // Update DB record with local path
        filesRepo.update(file._id, { $set: { storagePath: s3Key } });

        // Delete from S3 after successful write + DB update
        await s3.del(s3Key);

        result.migrated++;
      }
    } catch (err) {
      result.failed++;
      result.errors.push({ file: file.shareId, error: err.message });
      logger.error("[migration] Failed to migrate file", { shareId: file.shareId, direction: direction, error: err.message });
    }

    if (progressCb) progressCb(result);
  }

  return result;
}

/**
 * Dry-run: count files that would be migrated without moving anything.
 *
 * For local->S3, also counts records whose local source file is missing
 * (would fail with "Local file not found"). These are reported as `missing`
 * so the operator can run Orphan Cleanup → "dangling records" before migrating
 * instead of watching every file fail.
 *
 * S3 source existence is not checked — listing/HEAD per object would be
 * expensive and the dangling-record scan applies the same convention.
 */
function migrationPreview(direction) {
  var toS3 = direction === "local-to-s3";
  var uploadDir = storage.uploadDir;
  var allFiles = filesRepo.findAll({}).filter(function (f) {
    return f.status === "complete" && f.storagePath;
  });

  var toMigrate = 0, alreadyDone = 0, missing = 0, totalBytes = 0;
  // Track distinct bundles touched by the migration. Operators think in terms
  // of bundles, not individual files — surfacing the bundle count gives a
  // clearer picture of scope than file count alone (e.g. "5 files in 2 bundles"
  // is more meaningful than "5 files").
  var bundlesAffected = new Set();
  var bundlesAlready = new Set();
  for (var i = 0; i < allFiles.length; i++) {
    var sp = allFiles[i].storagePath;
    var onS3 = isS3Path(sp);
    var bid = allFiles[i].bundleId;
    if (toS3 && !onS3) {
      toMigrate++;
      totalBytes += allFiles[i].size || 0;
      if (bid) bundlesAffected.add(bid);
      var localPath = path.isAbsolute(sp) ? sp : path.join(uploadDir, sp);
      if (!fs.existsSync(localPath)) missing++;
    } else if (!toS3 && onS3) {
      toMigrate++;
      totalBytes += allFiles[i].size || 0;
      if (bid) bundlesAffected.add(bid);
    } else {
      alreadyDone++;
      if (bid) bundlesAlready.add(bid);
    }
  }

  return {
    toMigrate: toMigrate,
    alreadyDone: alreadyDone,
    missing: missing,
    total: allFiles.length,
    totalBytes: totalBytes,
    bundlesAffected: bundlesAffected.size,
    bundlesAlready: bundlesAlready.size,
  };
}

module.exports = { migrateStorage: migrateStorage, migrationPreview: migrationPreview };
