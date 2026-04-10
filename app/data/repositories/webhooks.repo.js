/**
 * Webhooks Repository — persistence logic for webhook configuration.
 */
var { webhooks } = require("../../../lib/db");

function findById(id) { return webhooks.findOne({ _id: id }); }
function findActive() { return webhooks.find({ active: "true" }); }
function findAll() { return webhooks.find({}); }

function create(doc) { return webhooks.insert(doc); }
function update(id, ops) { return webhooks.update({ _id: id }, ops); }
function remove(id) { return webhooks.remove({ _id: id }); }

module.exports = { findById, findActive, findAll, create, update, remove };
