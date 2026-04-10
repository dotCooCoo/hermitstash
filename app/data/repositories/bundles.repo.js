/**
 * Bundles Repository — persistence logic for upload bundles.
 */
var { bundles } = require("../../../lib/db");

function findById(id) { return bundles.findOne({ _id: id }); }
function findByShareId(shareId) { return bundles.findOne({ shareId: shareId }); }
function findAll(query) { return bundles.find(query || {}); }
function findPaginated(query, opts) { return bundles.findPaginated(query, opts); }
function count(query) { return bundles.count(query || {}); }

function create(doc) { return bundles.insert(doc); }
function update(id, ops) { return bundles.update({ _id: id }, ops); }
function remove(id) { return bundles.remove({ _id: id }); }

module.exports = { findById, findByShareId, findAll, findPaginated, count, create, update, remove };
