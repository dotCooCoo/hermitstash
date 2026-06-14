/**
 * Bundles Repository — persistence logic for upload bundles.
 */
var db = require("../../../lib/db");
var { bundles } = db;

function findById(id) { return bundles.findOne({ _id: id }); }
function findByShareId(shareId) { return bundles.findOne({ shareId: shareId }); }

/**
 * Lookup a bundle by shareId and return it ONLY if its status is "complete".
 *
 * Read-facing endpoints (/b/:shareId, /b/:shareId/download, /b/:shareId/*)
 * should treat in-flight ("uploading") and unfinalized bundles as 404 — the
 * caller has nothing to serve yet. Previously each route re-implemented
 * `findByShareId + status !== "complete" → 404` inline, which meant the
 * status policy drifted per endpoint. This helper encodes it once.
 *
 * Owner-operation endpoints (rename, delete, file rename inside bundle)
 * must still use findByShareId directly — they need to act on uploading
 * bundles too (e.g. delete a stuck upload).
 */
function findCompleteByShareId(shareId) {
  var b = bundles.findOne({ shareId: shareId });
  return (b && b.status === "complete") ? b : null;
}
function findAll(query) { return bundles.find(query || {}); }
function findPaginated(query, opts) { return bundles.findPaginated(query, opts); }
function count(query) { return bundles.count(query || {}); }

function create(doc) { return bundles.insert(doc); }
function update(id, ops) { return bundles.update({ _id: id }, ops); }
function remove(id) { return bundles.remove({ _id: id }); }

/**
 * Atomically increment `seq` by 1 and return the new value.
 *
 * Parallel uploads to the same sync bundle previously did
 *   var bundle = findById(id);
 *   await storage.saveFile(...);       // yields event loop
 *   update(id, { seq: (bundle.seq||0)+1 });
 * which under concurrency produced duplicate seq values on the WS stream
 * (downstream clients use `seq > lastSeq` for catch-up and silently drop
 * duplicates). This helper uses SQLite's `UPDATE ... RETURNING` so the
 * read-modify-write happens in one atomic statement.
 *
 * Returns the new seq value as an integer. `seq` is not a vault-sealed
 * column (it's a monotonic counter, not PII), so raw SQL is safe here.
 */
function incrementSeq(id) {
  var row = db.rawGet(
    "UPDATE bundles SET seq = COALESCE(seq, 0) + 1 WHERE _id = ? RETURNING seq",
    id
  );
  return row ? row.seq : null;
}

/**
 * Atomically add to receivedFiles / totalSize and return the new values.
 *
 * Mirrors incrementSeq and the decrement helpers in stash.repo: parallel
 * uploads to the same bundle previously each read receivedFiles/totalSize from
 * a pre-save snapshot and wrote `value + delta`, so concurrent writers lost
 * increments — undercounting the file count, the displayed size, and the
 * storage-quota math derived from totalSize. receivedFiles/totalSize are raw
 * INTEGER counters (not sealed), so the read-modify-write is one
 * `UPDATE ... RETURNING`. totalSize is clamped at 0 so a negative delta (a sync
 * replace shrinking a file) can't drive it below zero.
 */
function incrementCounters(id, fileDelta, sizeDelta) {
  var row = db.rawGet(
    "UPDATE bundles SET receivedFiles = MAX(0, COALESCE(receivedFiles, 0) + ?), " +
    "totalSize = MAX(0, COALESCE(totalSize, 0) + ?) WHERE _id = ? " +
    "RETURNING receivedFiles, totalSize",
    fileDelta, sizeDelta, id
  );
  return row ? { receivedFiles: row.receivedFiles, totalSize: row.totalSize } : null;
}

module.exports = { findById, findByShareId, findCompleteByShareId, findAll, findPaginated, count, create, update, remove, incrementSeq, incrementCounters };
