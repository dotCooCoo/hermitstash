"use strict";

/**
 * The upload-tree walk used by the backup worker. Kept in its own module so it
 * loads without workerData.
 */

var fs = require("fs/promises");
var nodePath = require("node:path");

/**
 * Every file under `dir`, skipping the directories in `excludeAbs` (one
 * absolute path or a list of them).
 *
 * The backup worker excludes two directories:
 *   - the chunk scratch directory (default <uploadDir>/chunks), which holds
 *     plaintext pre-assembly chunks that must never reach the backup backend;
 *   - the limited-download store (C.PATHS.STASH_DIR), in case UPLOAD_DIR
 *     contains it. A restore must not bring back a file that has already been
 *     downloaded its allowed number of times.
 *
 * A `dir` that is one of the excluded directories, or inside one, returns no
 * files.
 */
function _within(child, parent) {
  var rel = nodePath.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !nodePath.isAbsolute(rel));
}

async function walkUploads(dir, excludeAbs) {
  var excludes = (Array.isArray(excludeAbs) ? excludeAbs : [excludeAbs])
    .filter(Boolean)
    .map(function (p) { return nodePath.resolve(p); });
  var results = [];
  var root = nodePath.resolve(dir);
  for (var x = 0; x < excludes.length; x++) {
    if (_within(root, excludes[x])) return results;
  }
  var entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (_e) { return results; }
  for (var i = 0; i < entries.length; i++) {
    var full = nodePath.join(dir, entries[i].name);
    if (entries[i].isDirectory()) {
      if (excludes.indexOf(nodePath.resolve(full)) !== -1) continue;
      var sub = await walkUploads(full, excludes);
      results.push.apply(results, sub);
    } else if (entries[i].isFile()) {
      results.push(full);
    }
  }
  return results;
}

module.exports = { walkUploads: walkUploads };
