/**
 * Bundle Access Log Repository — verified email access audit trail.
 */
var { bundleAccessLog } = require("../../../lib/db");

function create(doc) { return bundleAccessLog.insert(doc); }

function findByBundle(bundleShareId) {
  return bundleAccessLog.find({ bundleShareId: bundleShareId });
}

module.exports = { create, findByBundle };
