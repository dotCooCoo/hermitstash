/**
 * Bundle Access Codes Repository — one-time email verification codes for email-gated bundles.
 */
var { bundleAccessCodes } = require("../../../lib/db");

function create(doc) { return bundleAccessCodes.insert(doc); }

function findPendingCode(bundleShareId, emailHash) {
  return bundleAccessCodes.find({ bundleShareId: bundleShareId, status: "pending" })
    .filter(function (c) { return c.emailHash === emailHash && c.expiresAt > new Date().toISOString(); })
    .sort(function (a, b) { return b.createdAt.localeCompare(a.createdAt); })[0] || null;
}

function countRecentCodes(bundleShareId, emailHash, sinceIso) {
  return bundleAccessCodes.find({ bundleShareId: bundleShareId })
    .filter(function (c) { return c.emailHash === emailHash && c.createdAt >= sinceIso; }).length;
}

function update(id, ops) { return bundleAccessCodes.update({ _id: id }, ops); }

function invalidatePending(bundleShareId, emailHash) {
  var pending = bundleAccessCodes.find({ bundleShareId: bundleShareId, status: "pending" })
    .filter(function (c) { return c.emailHash === emailHash; });
  for (var i = 0; i < pending.length; i++) {
    bundleAccessCodes.update({ _id: pending[i]._id }, { $set: { status: "expired" } });
  }
}

function cleanupExpired() {
  var cutoff = new Date(Date.now() - 3600000).toISOString();
  var old = bundleAccessCodes.find({}).filter(function (c) { return c.expiresAt < cutoff; });
  for (var i = 0; i < old.length; i++) bundleAccessCodes.remove({ _id: old[i]._id });
  return old.length;
}

module.exports = { create, findPendingCode, countRecentCodes, update, invalidatePending, cleanupExpired };
