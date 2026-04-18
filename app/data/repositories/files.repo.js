/**
 * Files Repository — persistence logic for uploaded files.
 */
var { files } = require("../../../lib/db");

function findById(id) { return files.findOne({ _id: id }); }
function findByShareId(shareId) { return files.findOne({ shareId: shareId }); }
function findByBundle(bundleId) { return files.find({ bundleId: bundleId }); }
function findByUploader(userId) { return files.find({ uploadedBy: userId }); }
function findAll(query) { return files.find(query || {}); }
function findPaginated(query, opts) { return files.findPaginated(query, opts); }
function count(query) { return files.count(query || {}); }

function create(doc) { return files.insert(doc); }
function update(id, ops) { return files.update({ _id: id }, ops); }
function remove(id) { return files.remove({ _id: id }); }

function incrementDownloads(id) {
  var db = require("../../lib/db");
  db.rawExec("UPDATE files SET downloads = downloads + 1 WHERE _id = ?", id);
}

function findByBundleShareId(shareId) { return files.find({ bundleShareId: shareId }); }
function searchPaginated(fields, q, query, opts) { return files.searchPaginated(fields, q, query, opts); }

module.exports = { findById, findByShareId, findByBundle, findByBundleShareId, findByUploader, findAll, findPaginated, searchPaginated, count, create, update, remove, incrementDownloads };
