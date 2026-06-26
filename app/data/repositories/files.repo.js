/**
 * Files Repository — persistence logic for uploaded files.
 */
var db = require("../../../lib/db");
var { files } = db;

function findById(id) { return files.findOne({ _id: id }); }
function findByShareId(shareId) { return files.findOne({ shareId: shareId }); }
// Lookup a file by shareId ONLY when its upload finalized (status "complete")
// AND it is not a sync-bundle tombstone (deletedAt set). handleSyncFileDelete
// keeps the row with status "complete" and clears storagePath/encryptionKey, so
// a status-only check would still serve a deleted file. Content-serving routes
// must use this so neither an in-flight (chunking) upload nor a deleted file is
// ever streamed; admin/management paths may use findByShareId to act on any row.
function findCompleteByShareId(shareId) {
  var f = files.findOne({ shareId: shareId });
  return (f && f.status === "complete" && !f.deletedAt) ? f : null;
}
function findByBundle(bundleId) { return files.find({ bundleId: bundleId }); }
function findByUploader(userId) { return files.find({ uploadedBy: userId }); }
function findAll(query) { return files.find(query || {}); }
function findPaginated(query, opts) { return files.findPaginated(query, opts); }
function count(query) { return files.count(query || {}); }

function create(doc) { return files.insert(doc); }
function update(id, ops) { return files.update({ _id: id }, ops); }
function remove(id) { return files.remove({ _id: id }); }

function incrementDownloads(id) {
  // Path is ../../../lib/db (3 levels up): repositories/ → data/ → app/ → root.
  // Earlier this was ../../lib/db which resolved to app/lib/db (doesn't exist),
  // throwing on every individual-file download (bundle downloads dodged it by
  // using the route-level db import directly).
  var db = require("../../../lib/db");
  db.rawExec("UPDATE files SET downloads = downloads + 1 WHERE _id = ?", id);
}

function findByBundleShareId(shareId) { return files.find({ bundleShareId: shareId }); }
// Live (non-tombstone) files in a bundle. Sync-bundle deletes leave a
// deletedAt row with status "complete" (handleSyncFileDelete clears
// storagePath/encryptionKey only), so content-serving paths — the bundle
// browse view and the ZIP/folder download handlers — must use this variant to
// stay in sync with what the viewer is shown. find({}) callers that act on the
// whole row set (e.g. the last-file auto-cleanup check) keep findByBundleShareId.
function findLiveByBundleShareId(shareId) {
  return files.find({ bundleShareId: shareId }).filter(function (f) { return !f.deletedAt; });
}
function searchPaginated(fields, q, query, opts) { return files.searchPaginated(fields, q, query, opts); }

// Sync change-feed page: the next `limit` files in a bundle whose seq is
// strictly greater than `since`, ordered by seq ascending. bundleId + seq are
// raw (unsealed) columns, so the SELECT filters/orders/limits in SQL — it never
// materializes or field-crypto-decrypts the whole bundle to JS-filter on seq
// (the catch-up handler used to, which an attacker forces O(files) with
// since=0). Only the `_id`s of the page come back from the raw query; each is
// re-read through files.findOne so the sealed columns (relativePath, checksum)
// auto-unseal. The caller pages by advancing `since` to the last seq returned.
function findBundleChangesSince(bundleId, since, limit) {
  var sinceSeq = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0;
  var pageLimit = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 1;
  var rows = db.rawQuery(
    "SELECT _id FROM files WHERE bundleId = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
    bundleId, sinceSeq, pageLimit
  );
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var f = files.findOne({ _id: rows[i]._id });
    if (f) out.push(f);
  }
  return out;
}

module.exports = { findById, findByShareId, findCompleteByShareId, findByBundle, findByBundleShareId, findLiveByBundleShareId, findByUploader, findAll, findPaginated, searchPaginated, findBundleChangesSince, count, create, update, remove, incrementDownloads };
