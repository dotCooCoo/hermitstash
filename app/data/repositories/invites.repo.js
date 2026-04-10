var { invites } = require("../../../lib/db");

function findAll(query) { return invites.find(query || {}); }
function findOne(query) { return invites.findOne(query); }
function create(doc) { return invites.insert(doc); }
function update(id, ops) { return invites.update({ _id: id }, ops); }
function remove(id) { return invites.remove({ _id: id }); }

module.exports = { findAll, findOne, create, update, remove };
