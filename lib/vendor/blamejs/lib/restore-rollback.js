// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.restoreRollback
 * @nav    Other
 * @title  Restore Rollback
 *
 * @intro
 *   Backup-restore safety net — atomic dataDir swap with a versioned
 *   rollback path. The primitive `b.restore` calls to put a
 *   freshly-decrypted bundle into place: filesystem rename is atomic
 *   on POSIX (and on Windows when nothing has the dir open), so the
 *   swap either fully completes or the previous `dataDir` is
 *   recoverable through `rollback`.
 *
 *   Three steps frame every restore: pre-restore snapshot (the
 *   existing `dataDir` is renamed into `<root>/<timestamp>/` before
 *   the new bundle moves in), post-restore verify (operator runs
 *   integrity / audit-chain checks against the live framework), and
 *   rollback on failure (a single `rollback({ rollbackPath })` call
 *   reverses the swap). A marker JSON file carries operator-supplied
 *   metadata (`bundleId`, `reason`, timestamps) so `list` and `purge`
 *   are informative without rifling through directory contents.
 *
 *   Layout after a successful swap:
 *
 *       ./data                         <- freshly-restored bundle
 *       ./data.rollbacks/
 *         2026-04-27T17-46-36-075Z/    <- previous dataDir
 *         2026-04-27T17-46-36-075Z.marker.json
 *
 *   Stop-framework-first contract: this primitive does NOT close the
 *   framework's open file handles. On Linux a directory rename
 *   succeeds with handles open, but the running process keeps reading
 *   stale data. Operators run restore as `stop framework -> swap ->
 *   start framework`, same shape as a database restore. Concurrency
 *   guard: `swap` refuses if another rollback for the same
 *   millisecond timestamp already exists — collisions are
 *   vanishingly rare but the check keeps a double-fire from
 *   corrupting state.
 *
 * @card
 *   Backup-restore safety net — atomic dataDir swap with a versioned rollback path.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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


/**
 * @primitive  b.restoreRollback.swap
 * @signature  b.restoreRollback.swap(opts)
 * @since      0.1.89
 * @status     stable
 * @related    b.restoreRollback.rollback, b.restoreRollback.list, b.restore.applyBundle
 *
 * Pre-restore snapshot + atomic swap. Renames the existing `dataDir`
 * into `<rollbackRoot>/<timestamp>/`, then renames `stagingDir` into
 * `dataDir`. If step two fails, step one is undone so the operator's
 * dataDir is intact. Writes a `<timestamp>.marker.json` carrying
 * operator metadata for later `list` / `rollback` discovery.
 *
 * @opts
 *   stagingDir:   string,                         // pre-decrypted bundle, must exist
 *   dataDir:      string,                         // live data dir to replace
 *   rollbackRoot: string,                         // optional; defaults to "<dataDir>.rollbacks"
 *   marker:       object,                         // operator metadata for the marker file
 *
 * @example
 *   var r = b.restoreRollback.swap({
 *     stagingDir: "./data.staging",
 *     dataDir:    "./data",
 *     marker:     { bundleId: "bk-2026-05-09", reason: "scheduled-restore" },
 *   });
 *   // → { rollbackPath: "./data.rollbacks/2026-05-09T...", markerPath, swappedAt, marker }
 */
function swap(opts) {
  opts = opts || {};
  if (typeof opts.stagingDir !== "string" || !nodeFs.existsSync(opts.stagingDir)) {
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
  var rollbackPath = nodePath.join(rollbackRoot, swappedAt);
  var markerPath = nodePath.join(rollbackRoot, swappedAt + ".marker.json");

  if (nodeFs.existsSync(rollbackPath) || nodeFs.existsSync(markerPath)) {
    throw new RestoreRollbackError("restore-rollback/collision",
      "swap: a rollback at " + rollbackPath + " already exists — refusing to overwrite");
  }

  var hadDataDir = nodeFs.existsSync(opts.dataDir);

  // Step 1: rename current dataDir → rollback nodePath. Skipped on first
  // restore (no existing dataDir).
  if (hadDataDir) {
    try { atomicFile.renameWithRetry(opts.dataDir, rollbackPath); }
    catch (e) {
      throw new RestoreRollbackError("restore-rollback/rename-existing-failed",
        "swap: could not move existing dataDir to rollback: " + ((e && e.message) || String(e)));
    }
  }

  // Step 2: rename staging → dataDir
  try { atomicFile.renameWithRetry(opts.stagingDir, opts.dataDir); }
  catch (e) {
    // Step 2 failed — try to undo step 1 so the operator's dataDir is back
    if (hadDataDir) {
      try { atomicFile.renameWithRetry(rollbackPath, opts.dataDir); }
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
  // CodeQL js/file-system-race: exclusive-create ("wx") refuses to
  // overwrite a pre-existing marker. The markerPath is inside the
  // operator-supplied rollbackRoot (not os.tmpdir-reachable), but the
  // exclusive flag still hardens against an attacker pre-creating the
  // path as a symlink to another file before the rename completes.
  try {
    var markerFd = nodeFs.openSync(markerPath, "wx", 0o600);
    try {
      var markerBuf = Buffer.from(JSON.stringify(marker, null, 2) + "\n");
      var written = 0;
      while (written < markerBuf.length) {
        written += nodeFs.writeSync(markerFd, markerBuf, written, markerBuf.length - written, null);
      }
      try { nodeFs.fsyncSync(markerFd); } catch (_fe) { /* fsync best-effort */ }
    } finally {
      try { nodeFs.closeSync(markerFd); } catch (_ce) { /* close best-effort */ }
    }
  } catch (_e) { /* marker write is best-effort; EEXIST tolerated */ }

  return {
    rollbackPath: hadDataDir ? rollbackPath : null,
    markerPath:   markerPath,
    swappedAt:    swappedAt,
    marker:       marker,
  };
}

/**
 * @primitive  b.restoreRollback.rollback
 * @signature  b.restoreRollback.rollback(opts)
 * @since      0.1.89
 * @status     stable
 * @related    b.restoreRollback.swap, b.restoreRollback.list
 *
 * Reverse a prior swap. Moves the current `dataDir` aside as
 * `discarded-<timestamp>/` (so the rename target is empty), then
 * renames the named `rollbackPath` back into `dataDir`. The marker
 * JSON is removed best-effort. Operator must have stopped the
 * framework first — open file handles on the live dataDir on Windows
 * cause the rename to fail.
 *
 * @opts
 *   dataDir:      string,                         // live dataDir to replace
 *   rollbackPath: string,                         // must exist; from swap() return
 *   rollbackRoot: string,                         // optional; defaults to "<dataDir>.rollbacks"
 *
 * @example
 *   var r = b.restoreRollback.swap({
 *     stagingDir: "./data.staging", dataDir: "./data",
 *     marker: { reason: "test" },
 *   });
 *   // post-restore verify failed:
 *   await b.restoreRollback.rollback({ dataDir: "./data", rollbackPath: r.rollbackPath });
 *   // → { restoredFrom: "./data.rollbacks/2026-05-09T...", discardedAt: "..." }
 */
async function rollback(opts) {
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new RestoreRollbackError("restore-rollback/no-datadir",
      "rollback: opts.dataDir is required");
  }
  if (typeof opts.rollbackPath !== "string" || !nodeFs.existsSync(opts.rollbackPath)) {
    throw new RestoreRollbackError("restore-rollback/no-rollback",
      "rollback: opts.rollbackPath is required and must exist");
  }

  // Move the current dataDir aside (so the rollback's rename target is empty)
  var discardedAt = null;
  if (nodeFs.existsSync(opts.dataDir)) {
    var rollbackRoot = _resolveRollbackRoot(opts);
    atomicFile.ensureDir(rollbackRoot);
    discardedAt = atomicFile.pathTimestamp();
    var discardedPath = nodePath.join(rollbackRoot, "discarded-" + discardedAt);
    try { atomicFile.renameWithRetry(opts.dataDir, discardedPath); }
    catch (e) {
      throw new RestoreRollbackError("restore-rollback/rename-existing-failed",
        "rollback: could not move current dataDir aside: " + ((e && e.message) || String(e)));
    }
    discardedAt = discardedPath;
  }

  // Rename the rollback dir back into dataDir's place
  try { atomicFile.renameWithRetry(opts.rollbackPath, opts.dataDir); }
  catch (e) {
    throw new RestoreRollbackError("restore-rollback/rollback-rename-failed",
      "rollback: could not move rollback into dataDir: " + ((e && e.message) || String(e)) +
      " (current dataDir, if any, was moved to " + discardedAt + ")");
  }

  // Best-effort: clean up the marker file alongside the rollback path
  var markerPath = opts.rollbackPath + ".marker.json";
  try { if (nodeFs.existsSync(markerPath)) nodeFs.unlinkSync(markerPath); }
  catch (_e) { /* marker cleanup is best-effort */ }

  return {
    restoredFrom: opts.rollbackPath,
    discardedAt:  discardedAt,
  };
}

/**
 * @primitive  b.restoreRollback.list
 * @signature  b.restoreRollback.list(opts)
 * @since      0.1.89
 * @status     stable
 * @related    b.restoreRollback.swap, b.restoreRollback.purge
 *
 * Enumerate available rollback points, newest first. Reads each
 * marker file (capped at 64 KiB via `b.safeJson` to bound a
 * tampered-marker DoS). Skips `discarded-*` directories — those are
 * sweep-only and never restore points.
 *
 * @opts
 *   dataDir:      string,                         // optional, used to derive rollbackRoot
 *   rollbackRoot: string,                         // optional; defaults to "<dataDir>.rollbacks"
 *
 * @example
 *   var points = b.restoreRollback.list({ dataDir: "./data" });
 *   points.forEach(function (p) {
 *     console.log(p.swappedAt, p.marker && p.marker.operator);
 *   });
 *   // → [{ rollbackPath, swappedAt, marker }, ...]
 */
function list(opts) {
  opts = opts || {};
  var rollbackRoot = _resolveRollbackRoot(opts);
  if (!nodeFs.existsSync(rollbackRoot)) return [];
  var entries = nodeFs.readdirSync(rollbackRoot, { withFileTypes: true });
  var out = [];
  for (var i = 0; i < entries.length; i++) {
    if (!entries[i].isDirectory()) continue;
    var name = entries[i].name;
    if (name.indexOf("discarded-") === 0) continue; // discarded dirs aren't restore points
    var p = nodePath.join(rollbackRoot, name);
    var markerPath = p + ".marker.json";
    var marker = null;
    // Capped fd-bound read (no existsSync check-then-read window): the fs read is
    // now bounded to 64 KiB too, so a tampered multi-GB marker.json is refused
    // BEFORE allocation (the parse-only cap let readFileSync slurp the whole file
    // first). refuseSymlink: the marker lives under the operator's rollbackRoot,
    // never a secret-mount. Any failure → marker:null, the best-effort behavior.
    try {
      marker = safeJson.parse(
        atomicFile.fdSafeReadSync(markerPath, { maxBytes: C.BYTES.kib(64), encoding: "utf8", refuseSymlink: true }),
        { maxBytes: C.BYTES.kib(64) });
    } catch (_e) { marker = null; }
    var stat;
    try { stat = nodeFs.statSync(p); } catch (_e) { continue; }
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

/**
 * @primitive  b.restoreRollback.purge
 * @signature  b.restoreRollback.purge(opts)
 * @since      0.1.89
 * @status     stable
 * @related    b.restoreRollback.list, b.restoreRollback.swap
 *
 * Sweep stale rollback directories. Always removes every directory
 * named `discarded-<timestamp>` (those are never restore points),
 * then keeps the newest `keep` rollback points and removes the rest
 * along with their marker files. `opts.keep` defaults to 0; pass a
 * positive integer to retain a sliding window. Best-effort: a
 * per-path unlink failure is logged via the deleted-list omission
 * rather than thrown.
 *
 * @opts
 *   dataDir:      string,
 *   rollbackRoot: string,
 *   keep:         number,                         // non-negative integer, default 0
 *
 * @example
 *   var r = b.restoreRollback.purge({ dataDir: "./data", keep: 3 });
 *   // → { kept: 3, deleted: ["./data.rollbacks/2026-04-...", ...] }
 */
function purge(opts) {
  opts = opts || {};
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.keep,
    "restore-rollback.purge: opts.keep", RestoreRollbackError, "restore-rollback/bad-keep");
  var keep = opts.keep !== undefined ? opts.keep : 0;
  var rollbackRoot = _resolveRollbackRoot(opts);
  if (!nodeFs.existsSync(rollbackRoot)) return { kept: keep, deleted: [] };
  // Always sweep "discarded-*" dirs — they're never restore points
  var entries = nodeFs.readdirSync(rollbackRoot, { withFileTypes: true });
  var deleted = [];
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].isDirectory() && entries[i].name.indexOf("discarded-") === 0) {
      var p = nodePath.join(rollbackRoot, entries[i].name);
      try { nodeFs.rmSync(p, { recursive: true, force: true }); deleted.push(p); }
      catch (_e) { /* best-effort */ }
    }
  }

  // Keep newest `keep`, delete the rest (and their marker files)
  var rb = list(opts);
  var toDelete = rb.slice(keep);
  for (var j = 0; j < toDelete.length; j++) {
    var rbPath = toDelete[j].rollbackPath;
    var mkPath = rbPath + ".marker.json";
    try { nodeFs.rmSync(rbPath, { recursive: true, force: true }); deleted.push(rbPath); }
    catch (_e) { /* best-effort */ }
    try { if (nodeFs.existsSync(mkPath)) nodeFs.unlinkSync(mkPath); }
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
