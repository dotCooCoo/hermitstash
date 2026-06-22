/**
 * Files Repository — persistence logic for uploaded files.
 */
var { files } = require("../../../lib/db");

function findById(id) { return files.findOne({ _id: id }); }
function findByShareId(shareId) { return files.findOne({ shareId: shareId }); }
// Lookup a file by shareId ONLY when its upload finalized (status "complete").
// Content-serving routes must use this so an in-flight/chunking upload is never
// streamed; admin/management paths may use findByShareId to act on any status.
function findCompleteByShareId(shareId) {
  var f = files.findOne({ shareId: shareId });
  return (f && f.status === "complete") ? f : null;
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
function searchPaginated(fields, q, query, opts) { return files.searchPaginated(fields, q, query, opts); }

module.exports = { findById, findByShareId, findCompleteByShareId, findByBundle, findByBundleShareId, findByUploader, findAll, findPaginated, searchPaginated, count, create, update, remove, incrementDownloads };
