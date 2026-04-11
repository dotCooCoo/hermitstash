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

module.exports = { findById, findBySlug, findAll, create, update, remove };
