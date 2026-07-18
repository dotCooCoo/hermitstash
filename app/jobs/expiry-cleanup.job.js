/**
 * Expiry Cleanup Job — removes expired files and stale bundles.
 * Registered as a scheduled task in server.js.
 */
var logger = require("../shared/logger");
var { files, bundles } = require("../../lib/db");
var storage = require("../../lib/storage");
var audit = require("../../lib/audit");
var { TIME } = require("../../lib/constants");

/**
 * Clean up expired files (files with expiresAt in the past).
 */
async function cleanupExpiredFiles() {
  var now = new Date().toISOString();
  var expired = files.find({}).filter(function (f) { return f.expiresAt && f.expiresAt < now; });
  var removed = 0;
  var affectedBundleShareIds = new Set();
  for (var i = 0; i < expired.length; i++) {
    try {
      if (expired[i].storagePath) await storage.deleteFile(expired[i].storagePath);
      files.remove({ _id: expired[i]._id });
      if (expired[i].bundleShareId) affectedBundleShareIds.add(expired[i].bundleShareId);
      removed++;
    } catch (e) { logger.error("Expiry cleanup error", { error: e.message }); }
  }

  // Auto-cleanup: a bundle whose last file just expired is now empty. Remove the
  // empty bundle and decrement its stash aggregate — mirroring the interactive
  // single-file delete path (routes/files.js), so a scheduled expiry doesn't
  // leave an empty bundle behind (and its customer_stash.bundleCount / totalBytes
  // permanently inflated). Uses the hash-indexed repo lookups so sealed shareId /
  // bundleShareId columns resolve correctly.
  if (affectedBundleShareIds.size > 0) {
    var filesRepo = require("../data/repositories/files.repo");
    var bundlesRepo = require("../data/repositories/bundles.repo");
    var stashRepo = require("../data/repositories/stash.repo");
    affectedBundleShareIds.forEach(function (shareId) {
      try {
        if (filesRepo.findByBundleShareId(shareId).length > 0) return; // bundle still has files
        var bundle = bundlesRepo.findByShareId(shareId);
        if (!bundle) return;
        if (bundle.stashId) {
          try { stashRepo.decrementBundleStats(bundle.stashId, bundle.totalSize); } catch (_e) { /* stash may have been deleted */ }
        }
        bundlesRepo.remove(bundle._id);
      } catch (_e) { /* best-effort empty-bundle cleanup — orphan-cleanup is the backstop */ }
    });
  }

  if (removed > 0) {
    try {
      audit.log(audit.ACTIONS.FILE_EXPIRY_CLEANUP, { performedBy: "system", details: "Removed " + removed + " expired files" });
    } catch (e) {
      logger.warn("[expiry-cleanup] Audit log write failed", { error: e.message, removed: removed });
    }
  }
  return removed;
}

/**
 * Clean up stale bundles (stuck in "uploading" state for >24h).
 * Removes the bundle record, any associated files from disk and DB,
 * and cleans up orphaned chunk directories.
 */
async function cleanupStaleBundles() {
  var cutoff = new Date(Date.now() - TIME.days(1)).toISOString();
  var stale = bundles.find({ status: "uploading" }).filter(function (b) { return b.createdAt && b.createdAt < cutoff; });
  var removed = 0;
  for (var i = 0; i < stale.length; i++) {
    var bundle = stale[i];
    // Delete any complete files uploaded to this bundle
    var bundleFiles = files.find({}).filter(function (f) { return f.bundleId === bundle._id; });
    for (var j = 0; j < bundleFiles.length; j++) {
      if (bundleFiles[j].storagePath) {
        // Best-effort delete — failures leave orphans for orphan-cleanup to find,
        // but we log so the operator knows the immediate cleanup didn't complete.
        try {
          await storage.deleteFile(bundleFiles[j].storagePath);
        } catch (e) {
          logger.warn("[expiry-cleanup] Failed to delete file for stale bundle (orphan-cleanup will retry)", { storagePath: bundleFiles[j].storagePath, bundleId: bundle._id, error: e.message });
        }
      }
      files.remove({ _id: bundleFiles[j]._id });
    }
    // Clean up chunk directory if it exists
    if (bundle.shareId) {
      try {
        storage.removeBundleChunks(bundle.shareId);
      } catch (e) {
        logger.warn("[expiry-cleanup] Failed to remove chunk directory for stale bundle (chunk-gc will retry)", { bundleShareId: bundle.shareId, bundleId: bundle._id, error: e.message });
      }
    }
    bundles.remove({ _id: bundle._id });
    removed++;
  }
  return removed;
}

/**
 * Clean up tombstoned files (soft-deleted sync bundle files older than 30 days).
 */
function cleanupTombstones() {
  var cutoff = new Date(Date.now() - TIME.days(30)).toISOString();
  var tombstones = files.find({}).filter(function (f) { return f.deletedAt && f.deletedAt < cutoff; });
  var removed = 0;
  for (var i = 0; i < tombstones.length; i++) {
    files.remove({ _id: tombstones[i]._id });
    removed++;
  }
  return removed;
}

/**
 * Clean up expired enrollment codes (older than 2 hours).
 */
function cleanupExpiredEnrollmentCodes() {
  try {
    var db = require("../../lib/db");
    var cutoff = new Date(Date.now() - TIME.hours(2)).toISOString();
    var expired = db.enrollmentCodes.find({}).filter(function (c) { return c.expiresAt < cutoff || c.status === "redeemed"; });
    for (var i = 0; i < expired.length; i++) db.enrollmentCodes.remove({ _id: expired[i]._id });
    return expired.length;
  } catch (e) {
    logger.warn("[expiry-cleanup] Enrollment code cleanup failed", { error: e.message });
    return 0;
  }
}

/**
 * Clean up expired bundle access codes (older than 1 hour).
 */
function cleanupExpiredAccessCodes() {
  try {
    var accessCodesRepo = require("../data/repositories/bundleAccessCodes.repo");
    return accessCodesRepo.cleanupExpired();
  } catch (e) {
    logger.warn("[expiry-cleanup] Access code cleanup failed", { error: e.message });
    return 0;
  }
}

/**
 * Clean up expired entries in the b.middleware.idempotencyKey.dbStore
 * table (`blamejs_idempotency_keys`). The upstream store does lazy GC
 * on read; this hourly sweep handles entries whose TTL elapsed without
 * anyone retrying. SQL is direct against the table because the upstream
 * store exposes only get/set/delete, not bulk sweep.
 */
function cleanupExpiredIdempotencyKeys() {
  try {
    var db = require("../../lib/db");
    var info = db.rawExec("DELETE FROM blamejs_idempotency_keys WHERE expires_at <= ?", Date.now());
    return info && info.changes ? info.changes : 0;
  } catch (e) {
    // Table may not exist yet (first boot before the middleware initializes it).
    if (/no such table/i.test(e.message || "")) return 0;
    logger.warn("[expiry-cleanup] Idempotency-key cleanup failed", { error: e.message });
    return 0;
  }
}

/**
 * Clean up old webhook_deliveries rows (delivery-log retention).
 * Every dispatch attempt — success, HTTP failure, and network/SSRF failure —
 * inserts a row, and the queue retries failures, so a noisy or failing endpoint
 * accumulates rows without bound. This sweep deletes anything past the retention
 * window via the idx_wd_createdAt index (createdAt is a raw ISO8601 string,
 * safe to compare in SQL). Direct SQL because the repo exposes no bulk delete.
 */
function cleanupWebhookDeliveries() {
  try {
    var db = require("../../lib/db");
    var cutoff = new Date(Date.now() - TIME.days(30)).toISOString();
    var info = db.rawExec("DELETE FROM webhook_deliveries WHERE createdAt < ?", cutoff);
    return info && info.changes ? info.changes : 0;
  } catch (e) {
    if (/no such table/i.test(e.message || "")) return 0;
    logger.warn("[expiry-cleanup] Webhook delivery cleanup failed", { error: e.message });
    return 0;
  }
}

module.exports = { cleanupExpiredFiles, cleanupStaleBundles, cleanupTombstones, cleanupExpiredAccessCodes, cleanupExpiredEnrollmentCodes, cleanupExpiredIdempotencyKeys, cleanupWebhookDeliveries };
