/**
 * Expiry Cleanup Job — removes expired files and stale bundles.
 * Registered as a scheduled task in server.js.
 */
var { files, bundles } = require("../../lib/db");
var storage = require("../../lib/storage");
var audit = require("../../lib/audit");

/**
 * Clean up expired files (files with expiresAt in the past).
 */
async function cleanupExpiredFiles() {
  var now = new Date().toISOString();
  var expired = files.find({}).filter(function (f) { return f.expiresAt && f.expiresAt < now; });
  var removed = 0;
  for (var i = 0; i < expired.length; i++) {
    try {
      if (expired[i].storagePath) await storage.deleteFile(expired[i].storagePath);
      files.remove({ _id: expired[i]._id });
      removed++;
    } catch (e) { console.error("Expiry cleanup error:", e.message); }
  }
  if (removed > 0) {
    try { audit.log(audit.ACTIONS.FILE_EXPIRY_CLEANUP, { performedBy: "system", details: "Removed " + removed + " expired files" }); } catch (_e) {}
  }
  return removed;
}

/**
 * Clean up stale bundles (stuck in "uploading" state for >24h).
 * Removes the bundle record, any associated files from disk and DB,
 * and cleans up orphaned chunk directories.
 */
async function cleanupStaleBundles() {
  var path = require("path");
  var fs = require("fs");
  var cutoff = new Date(Date.now() - 24 * 3600000).toISOString();
  var stale = bundles.find({ status: "uploading" }).filter(function (b) { return b.createdAt && b.createdAt < cutoff; });
  var removed = 0;
  for (var i = 0; i < stale.length; i++) {
    var bundle = stale[i];
    // Delete any complete files uploaded to this bundle
    var bundleFiles = files.find({}).filter(function (f) { return f.bundleId === bundle._id; });
    for (var j = 0; j < bundleFiles.length; j++) {
      if (bundleFiles[j].storagePath) {
        try { await storage.deleteFile(bundleFiles[j].storagePath); } catch (_e) {}
      }
      files.remove({ _id: bundleFiles[j]._id });
    }
    // Clean up chunk directory if it exists
    if (bundle.shareId) {
      var chunkDir = path.join(storage.uploadDir, "chunks", bundle.shareId);
      try {
        if (fs.existsSync(chunkDir)) fs.rmSync(chunkDir, { recursive: true, force: true });
      } catch (_e) {}
    }
    bundles.remove({ _id: bundle._id });
    removed++;
  }
  return removed;
}

module.exports = { cleanupExpiredFiles, cleanupStaleBundles };
