/**
 * Chunk Garbage Collection Job — cleans up abandoned chunk upload directories.
 * Chunks are stored in temporary folders under uploads/chunks/.
 * If an upload is abandoned (no finalize within 24h), the chunks accumulate.
 */
var fs = require("fs");
var path = require("path");
var storage = require("../../lib/storage");

var CHUNK_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Remove stale chunk directories.
 */
function cleanupStaleChunks() {
  var chunksDir = path.join(storage.uploadDir, "chunks");
  if (!fs.existsSync(chunksDir)) return 0;

  var removed = 0;
  var now = Date.now();
  try {
    var dirs = fs.readdirSync(chunksDir);
    for (var i = 0; i < dirs.length; i++) {
      var dirPath = path.join(chunksDir, dirs[i]);
      try {
        var stat = fs.statSync(dirPath);
        if (stat.isDirectory() && (now - stat.mtimeMs) > CHUNK_MAX_AGE) {
          fs.rmSync(dirPath, { recursive: true, force: true });
          removed++;
        }
      } catch (_e) {}
    }
  } catch (_e) {}
  return removed;
}

module.exports = { cleanupStaleChunks };
