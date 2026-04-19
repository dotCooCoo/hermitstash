var { credentials } = require("../../../lib/db");

function findOne(query) { return credentials.findOne(query); }
function find(query) { return credentials.find(query || {}); }
function findByUser(userId) { return credentials.find({ userId: userId }); }
function create(doc) { return credentials.insert(doc); }
function update(id, ops) { return credentials.update({ _id: id }, ops); }
function remove(queryOrId) { return credentials.remove(typeof queryOrId === "string" ? { _id: queryOrId } : queryOrId); }
function removeByUser(userId) { return credentials.remove({ userId: userId }); }

module.exports = { findOne, find, findByUser, create, update, remove, removeByUser };
