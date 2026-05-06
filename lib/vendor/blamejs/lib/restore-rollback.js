"use strict";
/**
 * restore-rollback — atomic dataDir swap with a versioned rollback path.
 *
 * The primitive used by lib/restore to put a freshly-decrypted bundle
 * into place. Filesystem-level directory rename is atomic on POSIX
 * (and on Windows when nothing has the dir open) — the swap either
 * fully completes or the previous dataDir is recoverable.
 *
 *   var rb = b.restoreRollback;
 *
 *   var r = rb.swap({
 *     stagingDir:    "./data.staging",
 *     dataDir:       "./data",
 *     rollbackRoot:  "./data.rollbacks",      // optional; defaults to <dataDir>.rollbacks
 *     marker:        { bundleId: "...", reason: "scheduled-restore" },
 *   });
 *   // → { rollbackPath, markerPath, swappedAt }
 *
 *   // Reverse the most recent swap (or a specific one by path)
 *   await rb.rollback({ dataDir: "./data", rollbackPath: r.rollbackPath });
 *   // → { restoredFrom, discardedAt }
 *
 *   rb.list({ rollbackRoot: "./data.rollbacks" });
 *   // → [{ rollbackPath, swappedAt, marker }] (newest first)
 *
 *   rb.purge({ rollbackRoot: "./data.rollbacks", keep: 3 });
 *   // → { kept, deleted: [paths] }
 *
 * Layout after a successful swap:
 *
 *   ./data                         ← the freshly-restored bundle
 *   ./data.rollbacks/
 *     2026-04-27T17-46-36-075Z/    ← previous dataDir, renamed atomically
 *       (whatever was in dataDir at the time of swap)
 *     2026-04-27T17-46-36-075Z.marker.json
 *
 * The marker file carries operator-supplied metadata (which bundle
 * triggered the swap, what reason was given, when) so a list / audit
 * over rollback dirs is informative without rifling through their
 * contents.
 *
 * Concurrency: swap() refuses to operate if another rollback dir for
 * the same timestamp already exists — collisions are vanishingly rare
 * because the timestamp has millisecond precision plus the framework
 * never runs two restores in parallel on the same dataDir, but the
 * check makes a corrupted state impossible if an operator fires twice.
 *
 * Operator stop-framework-first contract: this primitive does NOT
 * close the framework's open file handles. On Linux a directory
 * rename succeeds even with handles open, but the running framework
 * process will see stale data. Operators run restore as: stop
 * framework → swap → start framework. Same as a database restore.
 */

var fs = require("fs");
var path = require("path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var nb = require("./numeric-bounds");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");

var RestoreRollbackError = defineClass("RestoreRollbackError", { alwaysPermanent: true });

function _resolveRollbackRoot(opts) {
  if (typeof opts.rollbackRoot === "string" && opts.rollbackRoot.length > 0) {
    return opts.rollbackRoot;
  }
  // Default: sibling of dataDir named <dataDir>.rollbacks
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new RestoreRollbackError("restore-rollback/no-rollback-root",
      "rollbackRoot must be supplied or derivable from opts.dataDir");
  }
  return opts.dataDir + ".rollbacks";
}


function swap(opts) {
  opts = opts || {};
  if (typeof opts.stagingDir !== "string" || !fs.existsSync(opts.stagingDir)) {
    throw new RestoreRollbackError("restore-rollback/no-staging",
      "swap: opts.stagingDir is required and must exist");
  }
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new RestoreRollbackError("restore-rollback/no-datadir",
      "swap: opts.dataDir is required");
  }
  var rollbackRoot = _resolveRollbackRoot(opts);
  atomicFile.ensureDir(rollbackRoot);

  var swappedAt = atomicFile.pathTimestamp();
  var rollbackPath = path.join(rollbackRoot, swappedAt);
  var markerPath = path.join(rollbackRoot, swappedAt + ".marker.json");

  if (fs.existsSync(rollbackPath) || fs.existsSync(markerPath)) {
    throw new RestoreRollbackError("restore-rollback/collision",
      "swap: a rollback at " + rollbackPath + " already exists — refusing to overwrite");
  }

  var hadDataDir = fs.existsSync(opts.dataDir);

  // Step 1: rename current dataDir → rollback path. Skipped on first
  // restore (no existing dataDir).
  if (hadDataDir) {
    try { fs.renameSync(opts.dataDir, rollbackPath); }
    catch (e) {
      throw new RestoreRollbackError("restore-rollback/rename-existing-failed",
        "swap: could not move existing dataDir to rollback: " + ((e && e.message) || String(e)));
    }
  }

  // Step 2: rename staging → dataDir
  try { fs.renameSync(opts.stagingDir, opts.dataDir); }
  catch (e) {
    // Step 2 failed — try to undo step 1 so the operator's dataDir is back
    if (hadDataDir) {
      try { fs.renameSync(rollbackPath, opts.dataDir); }
      catch (_e) { /* dataDir is now in rollbackPath; operator must recover manually */ }
    }
    throw new RestoreRollbackError("restore-rollback/rename-staging-failed",
      "swap: could not move staging to dataDir: " + ((e && e.message) || String(e)) +
      (hadDataDir ? " (attempted to undo previous rename — verify dataDir state)" : ""));
  }

  // Step 3: write the marker (best-effort; missing marker is recoverable
  // from the rollback dir's mtime, but operators want it for audit)
  var marker = {
    swappedAt:    new Date().toISOString(),
    rollbackPath: rollbackPath,
    dataDir:      opts.dataDir,
    operator:     opts.marker || null,
  };
  try {
    fs.writeFileSync(markerPath, JSON.stringify(marker, null, 2) + "\n", { mode: 0o600 });
  } catch (_e) { /* marker write is best-effort */ }

  return {
    rollbackPath: hadDataDir ? rollbackPath : null,
    markerPath:   markerPath,
    swappedAt:    swappedAt,
    marker:       marker,
  };
}

async function rollback(opts) {
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new RestoreRollbackError("restore-rollback/no-datadir",
      "rollback: opts.dataDir is required");
  }
  if (typeof opts.rollbackPath !== "string" || !fs.existsSync(opts.rollbackPath)) {
    throw new RestoreRollbackError("restore-rollback/no-rollback",
      "rollback: opts.rollbackPath is required and must exist");
  }

  // Move the current dataDir aside (so the rollback's rename target is empty)
  var discardedAt = null;
  if (fs.existsSync(opts.dataDir)) {
    var rollbackRoot = _resolveRollbackRoot(opts);
    atomicFile.ensureDir(rollbackRoot);
    discardedAt = atomicFile.pathTimestamp();
    var discardedPath = path.join(rollbackRoot, "discarded-" + discardedAt);
    try { fs.renameSync(opts.dataDir, discardedPath); }
    catch (e) {
      throw new RestoreRollbackError("restore-rollback/rename-existing-failed",
        "rollback: could not move current dataDir aside: " + ((e && e.message) || String(e)));
    }
    discardedAt = discardedPath;
  }

  // Rename the rollback dir back into dataDir's place
  try { fs.renameSync(opts.rollbackPath, opts.dataDir); }
  catch (e) {
    throw new RestoreRollbackError("restore-rollback/rollback-rename-failed",
      "rollback: could not move rollback into dataDir: " + ((e && e.message) || String(e)) +
      " (current dataDir, if any, was moved to " + discardedAt + ")");
  }

  // Best-effort: clean up the marker file alongside the rollback path
  var markerPath = opts.rollbackPath + ".marker.json";
  try { if (fs.existsSync(markerPath)) fs.unlinkSync(markerPath); }
  catch (_e) { /* marker cleanup is best-effort */ }

  return {
    restoredFrom: opts.rollbackPath,
    discardedAt:  discardedAt,
  };
}

function list(opts) {
  opts = opts || {};
  var rollbackRoot = _resolveRollbackRoot(opts);
  if (!fs.existsSync(rollbackRoot)) return [];
  var entries = fs.readdirSync(rollbackRoot, { withFileTypes: true });
  var out = [];
  for (var i = 0; i < entries.length; i++) {
    if (!entries[i].isDirectory()) continue;
    var name = entries[i].name;
    if (name.indexOf("discarded-") === 0) continue; // discarded dirs aren't restore points
    var p = path.join(rollbackRoot, name);
    var markerPath = p + ".marker.json";
    var marker = null;
    if (fs.existsSync(markerPath)) {
      try { marker = safeJson.parse(fs.readFileSync(markerPath, "utf8"), { maxBytes: C.BYTES.kib(64) }); }
      catch (_e) { marker = null; }
    }
    var stat;
    try { stat = fs.statSync(p); } catch (_e) { continue; }
    out.push({
      rollbackPath: p,
      swappedAt:    (marker && marker.swappedAt) || stat.mtime.toISOString(),
      marker:       marker,
    });
  }
  // Newest first
  out.sort(function (a, b) { return a.swappedAt < b.swappedAt ? 1 : -1; });
  return out;
}

function purge(opts) {
  opts = opts || {};
  nb.requireNonNegativeFiniteIntIfPresent(opts.keep,
    "restore-rollback.purge: opts.keep", RestoreRollbackError, "restore-rollback/bad-keep");
  var keep = opts.keep !== undefined ? opts.keep : 0;
  var rollbackRoot = _resolveRollbackRoot(opts);
  if (!fs.existsSync(rollbackRoot)) return { kept: keep, deleted: [] };
  // Always sweep "discarded-*" dirs — they're never restore points
  var entries = fs.readdirSync(rollbackRoot, { withFileTypes: true });
  var deleted = [];
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].isDirectory() && entries[i].name.indexOf("discarded-") === 0) {
      var p = path.join(rollbackRoot, entries[i].name);
      try { fs.rmSync(p, { recursive: true, force: true }); deleted.push(p); }
      catch (_e) { /* best-effort */ }
    }
  }

  // Keep newest `keep`, delete the rest (and their marker files)
  var rb = list(opts);
  var toDelete = rb.slice(keep);
  for (var j = 0; j < toDelete.length; j++) {
    var rbPath = toDelete[j].rollbackPath;
    var mkPath = rbPath + ".marker.json";
    try { fs.rmSync(rbPath, { recursive: true, force: true }); deleted.push(rbPath); }
    catch (_e) { /* best-effort */ }
    try { if (fs.existsSync(mkPath)) fs.unlinkSync(mkPath); }
    catch (_e) { /* best-effort */ }
  }
  return { kept: keep, deleted: deleted };
}

module.exports = {
  swap:                  swap,
  rollback:              rollback,
  list:                  list,
  purge:                  purge,
  RestoreRollbackError:  RestoreRollbackError,
};
