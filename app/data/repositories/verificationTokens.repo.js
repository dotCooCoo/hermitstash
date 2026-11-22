var { verificationTokens } = require("../../../lib/db");

function findOne(query) { return verificationTokens.findOne(query); }
function create(doc) { return verificationTokens.insert(doc); }
function update(query, ops) { return verificationTokens.update(query, ops); }
function remove(queryOrId) { return verificationTokens.remove(typeof queryOrId === "string" ? { _id: queryOrId } : queryOrId); }

module.exports = { findOne, create, update, remove };
