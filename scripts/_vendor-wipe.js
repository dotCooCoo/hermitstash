"use strict";
/**
 * Empty a vendored tree in place, ready for a tarball to be extracted over it.
 *
 * The obvious `rmSync(dest, {recursive:true})` cannot be used here: a file-
 * syncing agent (Dropbox, on the machine this is developed on) holds directory
 * handles open, and the final rmdir fails with EPERM even after every child is
 * gone — leaving the tree half-gutted and the run dead, which then needs a git
 * restore before anything can load again. That happened twice while vendoring
 * 0.18.30.
 *
 * vendor-update.sh already avoided rmdir'ing the TOP directory for that reason.
 * The gap was one level down: removing a child directory recursively still ends
 * in an rmdir of that child, and a lock on lib/ kills the run just as well as a
 * lock on the root.
 *
 * So: try the clean removal for each entry, and where a directory refuses,
 * fall back to deleting its files and leaving the (empty) directory behind. The
 * extract repopulates it. An empty directory upstream no longer ships is the
 * only residue, and it carries no code.
 *
 *   node scripts/_vendor-wipe.js <dir>
 */
var fs = require("node:fs");
var path = require("node:path");

var dest = process.argv[2];
if (!dest) {
  process.stderr.write("usage: node scripts/_vendor-wipe.js <dir>\n");
  process.exit(2);
}

fs.mkdirSync(dest, { recursive: true });

var RM = { recursive: true, force: true, maxRetries: 60, retryDelay: 300 };
var filesRemoved = 0;
var dirsKept = 0;
var stubborn = [];

// Delete every file beneath dir, deepest first, without removing any directory.
function emptyFiles(dir) {
  var entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    // Unreadable, so its contents cannot be cleared — and returning quietly
    // would let whatever it holds survive into the extracted tree. Same
    // mixed-release outcome as a file that would not delete, so it is recorded
    // the same way rather than swallowed.
    stubborn.push(dir + " (unreadable: " + (err && err.code) + ")");
    return;
  }
  entries.forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) { emptyFiles(full); return; }
    try { fs.rmSync(full, { force: true, maxRetries: 60, retryDelay: 300 }); filesRemoved++; }
    catch (err) { stubborn.push(full + " (" + err.code + ")"); }
  });
  dirsKept++;
}

fs.readdirSync(dest, { withFileTypes: true }).forEach(function (entry) {
  var full = path.join(dest, entry.name);
  try {
    fs.rmSync(full, RM);
  } catch (err) {
    var code = err && err.code;
    if (code !== "EPERM" && code !== "EBUSY" && code !== "ENOTEMPTY") throw err;
    if (entry.isDirectory()) {
      // A held directory. Empty it and leave the shell; the extract writes into it.
      emptyFiles(full);
    } else {
      // A held FILE. There is no fallback for this one — the emptying pass
      // below would readdir it, fail, and return quietly, leaving a file from
      // the previous release in a tree about to receive the next one. That is
      // the mixed-release state this script exists to prevent, so it is
      // recorded and the run stops.
      stubborn.push(full + " (" + code + ")");
    }
  }
});

if (stubborn.length) {
  process.stderr.write("ERROR: " + stubborn.length + " file(s) could not be removed:\n");
  stubborn.slice(0, 10).forEach(function (f) { process.stderr.write("  " + f + "\n"); });
  process.stderr.write("Extracting over a tree that still holds old files mixes two releases.\n"
    + "Close whatever holds them (a file-syncing agent, an editor, a running server) and retry.\n");
  process.exit(1);
}

if (dirsKept) {
  process.stdout.write("  wipe: kept " + dirsKept + " locked director"
    + (dirsKept === 1 ? "y" : "ies") + ", emptied " + filesRemoved + " file(s) inside\n");
}
