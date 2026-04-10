var { apiKeys } = require("../../../lib/db");

function findOne(query) { return apiKeys.findOne(query); }
function findAll(query) { return apiKeys.find(query || {}); }
function create(doc) { return apiKeys.insert(doc); }
function update(id, ops) { return apiKeys.update({ _id: id }, ops); }
function remove(id) { return apiKeys.remove({ _id: id }); }

module.exports = { findOne, findAll, create, update, remove };
