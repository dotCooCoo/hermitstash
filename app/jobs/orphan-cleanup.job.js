/**
 * Orphan Cleanup Job — finds and removes storage files with no database record.
 *
 * Orphans happen when:
 *   - Upload fails after writing to disk but before DB insert
 *   - Manual file deletion from DB without removing storage
 *   - Migration leaves behind source files due to a crash
 *   - Stale bundle cleanup removes DB records but storage delete throws
 *
 * Scans local disk (uploads/bundles/) and optionally S3, builds a set of
 * all known storagePaths from the DB, then deletes anything not in the set.
 * Chunks directory is handled separately by chunk-gc.job.js.
 */
var fs = require("fs");
var path = require("path");
var { isS3Path, s3KeyFromPath } = require("../../lib/storage");
var config = require("../../lib/config");
var storage = require("../../lib/storage");
var logger = require("../shared/logger");
var { files, bundles } = require("../../lib/db");
var { TIME } = require("../../lib/constants");

/**
 * Scan local storage for orphaned files.
 * Returns { orphans: string[], totalScanned: number }
 */
function scanLocalOrphans() {
  var uploadDir = storage.uploadDir;
  var bundlesDir = path.join(uploadDir, "bundles");
  if (!fs.existsSync(bundlesDir)) return { orphans: [], totalScanned: 0 };

  // Build set of known local storagePaths from DB
  var knownPaths = new Set();
  var allFiles = files.find({});
  for (var i = 0; i < allFiles.length; i++) {
    var sp = allFiles[i].storagePath;
    if (sp && !isS3Path(sp)) {
      // Normalize: DB may store absolute or relative paths
      var rel = path.isAbsolute(sp) ? path.relative(uploadDir, sp) : sp;
      knownPaths.add(rel.replace(/\\/g, "/"));
    }
  }

  // Walk bundles/ directory
  var orphans = [];
  var totalScanned = 0;

  function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir); } catch (_e) { return; }
    for (var j = 0; j < entries.length; j++) {
      var full = path.join(dir, entries[j]);
      var stat;
      try { stat = fs.statSync(full); } catch (_e) { continue; }
      if (stat.isDirectory()) {
        walk(full);
      } else {
        totalScanned++;
        var rel = path.relative(uploadDir, full).replace(/\\/g, "/");
        // Grace period: skip files modified in the last 5 minutes to avoid
        // racing with in-flight uploads that haven't inserted a DB record yet
        if (!knownPaths.has(rel) && (Date.now() - stat.mtimeMs > TIME.FIVE_MIN)) {
          orphans.push({ path: full, relativePath: rel, size: stat.size });
        }
      }
    }
  }

  walk(bundlesDir);
  return { orphans: orphans, totalScanned: totalScanned };
}

/**
 * Scan S3 storage for orphaned objects.
 * Returns { orphans: string[], totalScanned: number }
 */
async function scanS3Orphans() {
  var s3cfg = config.storage.s3;
  if (!s3cfg || !s3cfg.bucket || !s3cfg.accessKey) return { orphans: [], totalScanned: 0 };

  var S3Client = require("../../lib/s3-client");
  var s3 = new S3Client(s3cfg);

  // Build set of known S3 keys from DB
  var knownKeys = new Set();
  var allFiles = files.find({});
  for (var i = 0; i < allFiles.length; i++) {
    var sp = allFiles[i].storagePath;
    if (sp && isS3Path(sp)) {
      knownKeys.add(s3KeyFromPath(sp));
    }
  }

  // List all objects under bundles/ prefix
  var objects;
  try {
    objects = await s3.list("bundles/");
  } catch (err) {
    logger.error("[orphan-cleanup] S3 list failed", { error: err.message });
    return { orphans: [], totalScanned: 0, error: err.message };
  }

  var orphans = [];
  for (var j = 0; j < objects.length; j++) {
    if (!knownKeys.has(objects[j])) {
      orphans.push({ key: objects[j] });
    }
  }

  return { orphans: orphans, totalScanned: objects.length };
}

/**
 * Delete local orphans. Returns count deleted.
 */
function deleteLocalOrphans(orphans) {
  var deleted = 0;
  var uploadDir = storage.uploadDir;
  for (var i = 0; i < orphans.length; i++) {
    try {
      fs.unlinkSync(orphans[i].path);
      deleted++;
      // Clean empty parent dirs up to bundles/
      var dir = path.dirname(orphans[i].path);
      var bundlesDir = path.join(uploadDir, "bundles");
      while (dir !== bundlesDir && dir.startsWith(bundlesDir)) {
        try {
          if (fs.readdirSync(dir).length === 0) { fs.rmdirSync(dir); dir = path.dirname(dir); }
          else break;
        } catch (_e) { break; }
      }
    } catch (e) {
      logger.error("[orphan-cleanup] Failed to delete local orphan", { path: orphans[i].path, error: e.message });
    }
  }
  return deleted;
}

/**
 * Delete S3 orphans. Returns count deleted.
 */
async function deleteS3Orphans(orphans) {
  var s3cfg = config.storage.s3;
  var S3Client = require("../../lib/s3-client");
  var s3 = new S3Client(s3cfg);
  var deleted = 0;
  for (var i = 0; i < orphans.length; i++) {
    try {
      await s3.del(orphans[i].key);
      deleted++;
    } catch (e) {
      logger.error("[orphan-cleanup] Failed to delete S3 orphan", { key: orphans[i].key, error: e.message });
    }
  }
  return deleted;
}

/**
 * Also find DB records pointing to files that no longer exist (dangling references).
 * These are records where storagePath points to nothing — the file was deleted
 * outside of the application.
 */
async function scanDanglingRecords() {
  var uploadDir = storage.uploadDir;
  var allFiles = files.find({}).filter(function (f) { return f.status === "complete" && f.storagePath; });
  var dangling = [];

  for (var i = 0; i < allFiles.length; i++) {
    var sp = allFiles[i].storagePath;
    if (isS3Path(sp)) {
      // S3 — skip for now (checking each key is expensive)
      continue;
    }
    var fullPath = path.isAbsolute(sp) ? sp : path.join(uploadDir, sp);
    if (!fs.existsSync(fullPath)) {
      dangling.push({ fileId: allFiles[i]._id, shareId: allFiles[i].shareId, storagePath: sp });
    }
  }
  return dangling;
}

/**
 * Find "empty" complete bundles — bundle records with zero live (non-tombstoned)
 * file records AND no orphan files on disk under their bundle directory. These
 * accumulate when sync bundles have all their files deleted (tombstones survive
 * but the bundle becomes a hollow shell), or when drop bundles expire and their
 * files are cleaned up but the bundle row sticks around. They show up in the
 * dashboard count but contribute nothing to actual storage.
 *
 * The disk check is a safety net: if there are orphan files under
 * uploads/bundles/<shareId>/ that aren't in the DB, we skip the bundle this
 * pass. Local-orphan cleanup will collect those files; a subsequent scan will
 * then find the bundle truly empty and queue it for deletion. This prevents
 * deleting a bundle row before its on-disk artifacts are accounted for.
 */
function scanEmptyBundles() {
  var uploadDir = storage.uploadDir;
  var allCompleteBundles = bundles.find({ status: "complete" });
  var allFiles = files.find({}).filter(function (f) { return !f.deletedAt; });
  var bundleFileCounts = {};
  for (var i = 0; i < allFiles.length; i++) {
    var bid = allFiles[i].bundleId;
    if (bid) bundleFileCounts[bid] = (bundleFileCounts[bid] || 0) + 1;
  }
  var empty = [];
  for (var j = 0; j < allCompleteBundles.length; j++) {
    var b = allCompleteBundles[j];
    if (bundleFileCounts[b._id]) continue; // has live files — not empty

    // Defensive disk check: skip if any file exists under the bundle's local
    // directory. Orphan cleanup runs before empty-bundle cleanup in the same
    // request, so a follow-up scan will catch this bundle once orphans are gone.
    if (b.shareId) {
      var bundleDir = path.join(uploadDir, "bundles", b.shareId);
      if (fs.existsSync(bundleDir)) {
        var hasFiles = false;
        try {
          (function walk(dir) {
            if (hasFiles) return;
            var entries = fs.readdirSync(dir, { withFileTypes: true });
            for (var k = 0; k < entries.length && !hasFiles; k++) {
              var full = path.join(dir, entries[k].name);
              if (entries[k].isDirectory()) walk(full);
              else if (entries[k].isFile()) hasFiles = true;
            }
          })(bundleDir);
        } catch (_e) { /* directory may have been removed concurrently — treat as empty */ }
        if (hasFiles) continue; // skip — orphan files present, defer to next pass
      }
    }

    empty.push({ bundleId: b._id, shareId: b.shareId, bundleType: b.bundleType, createdAt: b.createdAt });
  }
  return empty;
}

/**
 * Delete empty bundle records. Caller must have confirmed via scanEmptyBundles().
 * Returns count deleted.
 */
function deleteEmptyBundles(empties) {
  var deleted = 0;
  for (var i = 0; i < empties.length; i++) {
    try {
      bundles.remove({ _id: empties[i].bundleId });
      deleted++;
    } catch (e) {
      logger.warn("[orphan-cleanup] Failed to delete empty bundle", { bundleId: empties[i].bundleId, shareId: empties[i].shareId, error: e.message });
    }
  }
  return deleted;
}

module.exports = {
  scanLocalOrphans: scanLocalOrphans,
  scanS3Orphans: scanS3Orphans,
  deleteLocalOrphans: deleteLocalOrphans,
  deleteS3Orphans: deleteS3Orphans,
  scanDanglingRecords: scanDanglingRecords,
  scanEmptyBundles: scanEmptyBundles,
  deleteEmptyBundles: deleteEmptyBundles,
};
