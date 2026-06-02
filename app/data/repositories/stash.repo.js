/**
 * Customer Stash Repository — persistence logic for branded upload portals.
 */
var { customerStash, rawExec } = require("../../../lib/db");

function findById(id) { return customerStash.findOne({ _id: id }); }
function findBySlug(slug) { return customerStash.findOne({ slug: slug }); }
function findAll() { return customerStash.find({}); }
function create(doc) { return customerStash.insert(doc); }
function update(id, ops) { return customerStash.update({ _id: id }, ops); }
function remove(id) { return customerStash.remove({ _id: id }); }

function decrementBundleStats(stashId, totalSize) {
  // Atomic decrement (single UPDATE) so concurrent bundle deletes for the same
  // stash can't lose a decrement via read-modify-write. bundleCount/totalBytes
  // are raw INTEGER columns (not vault-sealed), so raw SQL is safe.
  rawExec("UPDATE customer_stash SET bundleCount = MAX(0, COALESCE(bundleCount, 0) - 1), totalBytes = MAX(0, COALESCE(totalBytes, 0) - ?) WHERE _id = ?", totalSize || 0, stashId);
}

function decrementBytes(stashId, bytes) {
  rawExec("UPDATE customer_stash SET totalBytes = MAX(0, COALESCE(totalBytes, 0) - ?) WHERE _id = ?", bytes || 0, stashId);
}

module.exports = { findById, findBySlug, findAll, create, update, remove, decrementBundleStats, decrementBytes };
