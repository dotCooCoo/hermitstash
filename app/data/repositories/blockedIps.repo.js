var { blockedIps } = require("../../../lib/db");

function findOne(query) { return blockedIps.findOne(query); }
function findAll(query) { return blockedIps.find(query || {}); }
function create(doc) { return blockedIps.insert(doc); }
function remove(query) { return blockedIps.remove(query); }

module.exports = { findOne, findAll, create, remove };
