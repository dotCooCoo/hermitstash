/**
 * File expiry cleanup — runs periodically to delete expired files.
 * Uses indexed SQL query on expiresAt for fast ID scan, then ORM for unsealed paths.
 */
var db = require("./db");
var storage = require("./storage");
var logger = require("../app/shared/logger");

function cleanupExpired() {
  var now = new Date().toISOString();
  // Step 1: Fast indexed scan to get IDs of expired files
  var expiredIds = db.rawQuery("SELECT _id FROM files WHERE expiresAt IS NOT NULL AND expiresAt < ?", now);
  var removed = 0;
  for (var i = 0; i < expiredIds.length; i++) {
    try {
      // Step 2: Use ORM to get unsealed storagePath (field-crypto auto-unseals)
      var doc = db.files.findOne({ _id: expiredIds[i]._id });
      if (doc && doc.storagePath) storage.deleteFile(doc.storagePath);
      db.files.remove({ _id: expiredIds[i]._id });
      removed++;
    } catch (e) { logger.error("Expiry cleanup error", { error: e.message || String(e) }); }
  }
  if (removed > 0) {
    try { var audit = require("./audit"); audit.log(audit.ACTIONS.FILE_EXPIRY_CLEANUP, { performedBy: "system", details: "Expiry cleanup: removed " + removed + " files" }); } catch (_e) {}
  }
}

module.exports = { cleanupExpired: cleanupExpired };
