/**
 * Chunk Garbage Collection Job — cleans up abandoned chunk upload directories.
 * Chunks are stored in the configured scratch directory (local disk, independent
 * of STORAGE_BACKEND). If an upload is abandoned (no finalize within 24h), the
 * chunks accumulate there.
 */
var storage = require("../../lib/storage");
var logger = require("../shared/logger");
var { TIME } = require("../../lib/constants");

var CHUNK_MAX_AGE = TIME.ONE_DAY;

/**
 * Remove stale bundle-level chunk directories.
 */
function cleanupStaleChunks() {
  var stale = storage.listStaleBundleChunkDirs(CHUNK_MAX_AGE);
  var removed = 0;
  for (var i = 0; i < stale.length; i++) {
    try {
      storage.removeDirByPath(stale[i]);
      removed++;
    } catch (e) {
      logger.warn("[chunk-gc] Failed to remove chunk directory", { dir: stale[i], error: e.message });
    }
  }
  return removed;
}

module.exports = { cleanupStaleChunks };
