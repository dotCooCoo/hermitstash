/**
 * Customer Stash Repository — persistence logic for branded upload portals.
 */
var { customerStash } = require("../../../lib/db");

function findById(id) { return customerStash.findOne({ _id: id }); }
function findBySlug(slug) { return customerStash.findOne({ slug: slug }); }
function findAll() { return customerStash.find({}); }
function create(doc) { return customerStash.insert(doc); }
function update(id, ops) { return customerStash.update({ _id: id }, ops); }
function remove(id) { return customerStash.remove({ _id: id }); }

function decrementBundleStats(stashId, totalSize) {
  var stash = findById(stashId);
  if (!stash) return;
  update(stash._id, { $set: {
    bundleCount: Math.max(0, (parseInt(stash.bundleCount, 10) || 0) - 1),
    totalBytes: Math.max(0, (parseInt(stash.totalBytes, 10) || 0) - (totalSize || 0)),
  }});
}

function decrementBytes(stashId, bytes) {
  var stash = findById(stashId);
  if (!stash) return;
  update(stash._id, { $set: {
    totalBytes: Math.max(0, (parseInt(stash.totalBytes, 10) || 0) - (bytes || 0)),
  }});
}

module.exports = { findById, findBySlug, findAll, create, update, remove, decrementBundleStats, decrementBytes };
