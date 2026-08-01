/**
 * Bundle Access Codes Repository — one-time email verification codes for email-gated bundles.
 */
var db = require("../../../lib/db");
var { bundleAccessCodes } = db;
var { TIME } = require("../../../lib/constants");

function create(doc) { return bundleAccessCodes.insert(doc); }

/**
 * Atomically increment the wrong-attempt counter and return the new value.
 * Uses SQLite `UPDATE ... RETURNING` (same idiom as bundles.repo incrementSeq)
 * so concurrent wrong-code submissions can't each read the same stale `attempts`
 * and write count+1 — a lost-update that let the 5-attempt cap be brute-forced
 * past under parallelism (CWE-362). `attempts` is a raw (non-sealed) counter
 * column, so raw SQL is safe here.
 * @returns {number|null} post-increment attempts, or null if the row is gone
 */
function incrementAttempts(id) {
  var row = db.rawGet(
    "UPDATE bundle_access_codes SET attempts = COALESCE(attempts, 0) + 1 WHERE _id = ? RETURNING attempts",
    id
  );
  return row ? row.attempts : null;
}

function findPendingCode(bundleShareId, emailHash) {
  return bundleAccessCodes.find({ bundleShareId: bundleShareId, status: "pending", emailHash: emailHash })
    .filter(function (c) { return c.expiresAt > new Date().toISOString(); })
    .sort(function (a, b) { return b.createdAt.localeCompare(a.createdAt); })[0] || null;
}

function countRecentCodes(bundleShareId, emailHash, sinceIso) {
  return bundleAccessCodes.find({ bundleShareId: bundleShareId, emailHash: emailHash })
    .filter(function (c) { return c.createdAt >= sinceIso; }).length;
}

function update(id, ops) { return bundleAccessCodes.update({ _id: id }, ops); }

// Atomically consume a single-use pending code: flip status pending→used only
// while it is STILL pending, and report whether THIS call won. The status:"pending"
// in the WHERE is the compare-and-set — two concurrent redemptions of the same
// code can't both succeed (the loser changes 0 rows), closing the read-validate-
// then-write double-use race (CWE-367). Mirrors the enrollment-code claim.
function claimPending(id) {
  return !!bundleAccessCodes.update({ _id: id, status: "pending" }, { $set: { status: "used" } });
}

function invalidatePending(bundleShareId, emailHash) {
  var pending = bundleAccessCodes.find({ bundleShareId: bundleShareId, status: "pending", emailHash: emailHash });
  for (var i = 0; i < pending.length; i++) {
    bundleAccessCodes.update({ _id: pending[i]._id }, { $set: { status: "expired" } });
  }
}

function cleanupExpired() {
  var cutoff = new Date(Date.now() - TIME.hours(1)).toISOString();
  var old = bundleAccessCodes.find({}).filter(function (c) { return c.expiresAt < cutoff; });
  for (var i = 0; i < old.length; i++) bundleAccessCodes.remove({ _id: old[i]._id });
  return old.length;
}

module.exports = { create, findPendingCode, countRecentCodes, update, incrementAttempts, claimPending, invalidatePending, cleanupExpired };
