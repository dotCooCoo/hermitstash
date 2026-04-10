/**
 * Audit Repository — persistence logic for audit log entries.
 */
var { auditLog } = require("../../../lib/db");

function findPaginated(query, opts) { return auditLog.findPaginated(query, opts); }
function findAll(query) { return auditLog.find(query || {}); }
function count(query) { return auditLog.count(query || {}); }
function create(doc) { return auditLog.insert(doc); }
function remove(id) { return auditLog.remove({ _id: id }); }

module.exports = { findPaginated, findAll, count, create, remove };
