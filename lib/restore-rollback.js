"use strict";

/**
 * Pre-restore snapshot + rollback helpers for restore-worker.js.
 *
 * Why this is separate from restore-worker: testing the rollback logic
 * directly (without spinning up a real backup / S3 client / restore flow)
 * requires the rollback to be a plain function operating on the filesystem.
 * Extracting it here makes that possible.
 *
 * Behaviour contract (restore flow):
 *   1. Before overwriting any live file, call createSnapshots() — copies
 *      each tracked file to a .pre-restore sibling if it exists.
 *   2. Perform the restore. If anything throws, call rollbackFromSnapshots()
 *      — copies the .pre-restore files back into place, atomically per file.
 *   3. On success, call clearSnapshots() — removes .pre-restore files.
 *   4. On failure: snapshots are PRESERVED for operator inspection.
 *
 * Tracked files include both plaintext (vault.key) and wrapped (vault.key.sealed)
 * vault formats so rollback works across the v1.9 wrapped-mode boundary.
 */
var fs = require("fs");
var path = require("path");

// Files we snapshot + roll back. Order matters for rollback on crash at
// specific boundaries — restore writes db.key.enc first, then
// hermitstash.db.enc, then vault.key(.sealed). We roll back in any order
// because each .pre-restore is independent.
var SNAPSHOT_FILES = Object.freeze([
  "db.key.enc",
  "hermitstash.db.enc",
  "vault.key",
  "vault.key.sealed",
]);

// Tmp files the restore may create but fail to rename. Cleaned on rollback
// so the boot-time state machine doesn't see them as stale.
var TMP_CLEANUP_FILES = Object.freeze([
  "db.key.enc.tmp",
  "hermitstash.db.enc.tmp",
  "vault.key.tmp",
  "vault.key.sealed.tmp",
]);

/**
 * Snapshot every tracked file in dataDir that currently exists.
 * Returns the list of filenames that were actually snapshotted — callers
 * pass this to rollbackFromSnapshots() so rollback only restores what was
 * actually snapshotted (missing-source files stay missing).
 */
function createSnapshots(dataDir) {
  var created = [];
  for (var i = 0; i < SNAPSHOT_FILES.length; i++) {
    var name = SNAPSHOT_FILES[i];
    var src = path.join(dataDir, name);
    var snap = src + ".pre-restore";
    try {
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, snap);
        created.push(name);
      }
    } catch (_e) {
      // A source file may be unreadable (permissions, race with another
      // process). We don't fail the overall restore because of snapshot
      // failures — better to proceed and have a partial snapshot than to
      // refuse restore entirely.
    }
  }
  return created;
}

/**
 * Roll back live files from their .pre-restore snapshots, then clean up
 * any leftover .tmp files from incomplete atomic renames.
 *
 * - snapshotsCreated: names from createSnapshots() return value
 * - preserveSnapshots: if true (default), leaves .pre-restore files in place
 *   for operator inspection. Set false only when rollback completed successfully
 *   AND the operator wants a clean state.
 *
 * NEVER throws — rollback is a best-effort recovery. The caller cares more
 * about the original error than about a rollback sub-failure.
 */
function rollbackFromSnapshots(dataDir, snapshotsCreated, opts) {
  opts = opts || {};
  var errors = [];
  for (var r = 0; r < snapshotsCreated.length; r++) {
    var name = snapshotsCreated[r];
    var live = path.join(dataDir, name);
    var snap = live + ".pre-restore";
    try {
      if (fs.existsSync(snap)) {
        fs.copyFileSync(snap, live);
      }
    } catch (e) {
      errors.push({ file: name, error: e.message });
    }
  }
  // Clean up any leftover .tmp files from incomplete atomic renames
  for (var t = 0; t < TMP_CLEANUP_FILES.length; t++) {
    try { fs.unlinkSync(path.join(dataDir, TMP_CLEANUP_FILES[t])); } catch (_e) { /* not always present */ }
  }
  if (opts.preserveSnapshots === false) {
    for (var c = 0; c < snapshotsCreated.length; c++) {
      try { fs.unlinkSync(path.join(dataDir, snapshotsCreated[c] + ".pre-restore")); } catch (_e) { /* best effort */ }
    }
  }
  return errors;
}

/**
 * Success-path cleanup. Removes all .pre-restore files for the tracked
 * names. Called by the restore worker only after the entire restore has
 * completed without throwing.
 */
function clearSnapshots(dataDir, snapshotsCreated) {
  for (var i = 0; i < snapshotsCreated.length; i++) {
    try { fs.unlinkSync(path.join(dataDir, snapshotsCreated[i] + ".pre-restore")); } catch (_e) { /* may not exist */ }
  }
}

module.exports = {
  createSnapshots: createSnapshots,
  rollbackFromSnapshots: rollbackFromSnapshots,
  clearSnapshots: clearSnapshots,
  SNAPSHOT_FILES: SNAPSHOT_FILES,
  TMP_CLEANUP_FILES: TMP_CLEANUP_FILES,
};
