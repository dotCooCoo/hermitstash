/**
 * Users Repository — persistence logic for user accounts.
 * All database access for users goes through here.
 */
var { users, credentials } = require("../../../lib/db");
var { transaction } = require("../db/transaction");
var b = require("../../../lib/vendor/blamejs");

function findById(id) { return users.findOne({ _id: id }); }
function findByEmail(email) { return users.findOne({ email: String(email).toLowerCase() }); }
// Indexed lookup on the sealed tailscaleId via its tailscaleIdHash blind index
// (field-crypto rewrites the sealed-field predicate to the hash column).
function findByTailscaleId(tailscaleId) { return users.findOne({ tailscaleId: String(tailscaleId).toLowerCase() }); }
// Indexed lookups on the sealed oidcSubject ("<issuer>|<sub>") through its
// oidcSubjectHash blind index. The value is case-sensitive and is not folded.
function findByOidcSubject(subject) { return users.findOne({ oidcSubject: String(subject) }); }
function findAllByOidcSubject(subject) { return users.find({ oidcSubject: String(subject) }); }
function findAll(query) { return users.find(query || {}); }
function count(query) { return users.count(query || {}); }

function findPaginated(query, opts) { return users.findPaginated(query, opts); }

// insert() returns the stored row with fields still sealed; re-read by _id so
// callers receive the same unsealed shape as findById. Without this, sealed
// blobs (email, displayName) leak into anything built from the return value —
// e.g. the registration audit/SIEM event, which records targetEmail from it.
//
// A caller that holds proof of the address passes emailConfirmedVia and
// emailConfirmedAt. Without them an active account is recorded as "legacy"
// (no proof; never valid for linking) and a pending one as unconfirmed.
function create(doc) {
  var row = Object.assign({}, doc);
  if (!Object.prototype.hasOwnProperty.call(row, "emailConfirmedVia")) {
    if (row.status !== "pending") {
      row.emailConfirmedVia = "legacy";
      row.emailConfirmedAt = new Date().toISOString();
    } else {
      row.emailConfirmedVia = null;
      row.emailConfirmedAt = null;
    }
  }
  var inserted = users.insert(row);
  return (inserted && inserted._id && users.findOne({ _id: inserted._id })) || inserted;
}

// An email change that does not say how the new address was confirmed is
// recorded as "legacy", so an unproven address is never used for linking.
function update(id, ops) {
  var set = ops && ops.$set;
  if (set && typeof set === "object" &&
      Object.prototype.hasOwnProperty.call(set, "email") &&
      !Object.prototype.hasOwnProperty.call(set, "emailConfirmedVia")) {
    ops = Object.assign({}, ops, { $set: Object.assign({}, set, { emailConfirmedVia: "legacy", emailConfirmedAt: new Date().toISOString() }) });
  }
  return users.update({ _id: id }, ops);
}

// Bind an account to an OpenID Connect subject ("<issuer>|<sub>"). `label` is
// the provider email shown for the linked identity. Binding clears the block
// that an earlier unlink set.
function setOidcSubject(id, subject, label) {
  return users.update({ _id: id }, { $set: { oidcSubject: String(subject), oidcLabel: label || null, oidcAutoLinkBlockedAt: null } });
}

// Remove the OpenID Connect binding and block linking by email until the
// account is linked again from the profile page. The blind index is cleared
// explicitly, because a null source does not recompute it.
function clearOidcSubject(id) {
  return users.update({ _id: id }, { $set: { oidcSubject: null, oidcSubjectHash: null, oidcLabel: null, oidcAutoLinkBlockedAt: new Date().toISOString() } });
}

// Atomic failed-login counter bump. A read-modify-write (read count → +1 →
// $set) lets concurrent failed attempts each read the same pre-write value and
// stay under the lockout threshold (TOCTOU bypass). failedLoginAttempts is a
// raw INTEGER column, so a single SQL UPDATE increments it atomically; the
// follow-up read returns the post-increment count for the lockout decision.
function incrementFailedAttempts(id) {
  var db = require("../../../lib/db");
  db.rawExec("UPDATE users SET failedLoginAttempts = COALESCE(failedLoginAttempts, 0) + 1 WHERE _id = ?", id);
  var row = db.rawGet("SELECT failedLoginAttempts FROM users WHERE _id = ?", id);
  return row ? row.failedLoginAttempts : null;
}

// Atomically consume a single-use TOTP backup code. A snapshot read in the
// route handler followed by a splice + full-column overwrite is last-writer-
// wins across the await that completes the login: two concurrent requests
// presenting DISTINCT valid codes each write back their own snapshot-minus-
// one, so one consumed code reappears in the survivor set and stays reusable.
// totpBackupCodes is a sealed column, so a raw SQL string-replace can't touch
// the ciphertext — instead re-read the freshest sealed row, unseal, remove only
// the matching element, and write back, all inside one IMMEDIATE transaction so
// concurrent consumes serialize at the row level. Returns true if the code was
// present (and is now removed), false if it was already gone.
function consumeBackupCode(id, codeHash) {
  return transaction(function () {
    var user = users.findOne({ _id: id });
    if (!user) return false;
    var codes = Array.isArray(user.totpBackupCodes)
      ? user.totpBackupCodes
      : b.safeJson.parseOrDefault(user.totpBackupCodes || "[]", []);
    // Every stored code is compared, whatever the outcome. Each comparison is
    // constant time on its own, but stopping at the first match made the total
    // time report WHERE in the list the code sat — and the list is ordered, so
    // that narrows which of a user's backup codes was presented. The index is
    // still needed to remove the used code, so this keeps the first match
    // rather than folding to a boolean: the `idx === -1` guard runs after the
    // comparison, never in place of it.
    var idx = -1;
    for (var i = 0; i < codes.length; i++) {
      if (b.crypto.timingSafeEqual(String(codes[i]), codeHash) && idx === -1) idx = i;
    }
    if (idx === -1) return false;
    codes.splice(idx, 1);
    users.update({ _id: id }, { $set: { totpBackupCodes: JSON.stringify(codes) } });
    return true;
  });
}

/**
 * Delete a user and all associated data atomically.
 */
function deleteUser(userId, reassignTo) {
  reassignTo = reassignTo || "deleted";
  var { files } = require("../../../lib/db");

  return transaction(function () {
    var user = users.findOne({ _id: userId });
    if (!user) return null;

    // Reassign files
    var userFiles = files.find({ uploadedBy: userId });
    for (var i = 0; i < userFiles.length; i++) {
      files.update({ _id: userFiles[i]._id }, {
        $set: { uploadedBy: reassignTo, uploaderName: (user.displayName || "Unknown") + " (deleted)" },
      });
    }

    // Remove credentials
    credentials.remove({ userId: userId });

    // Remove user
    users.remove({ _id: userId });

    return { user: user, filesReassigned: userFiles.length };
  });
}

function remove(id) { return users.remove({ _id: id }); }

module.exports = { findById, findByEmail, findByTailscaleId, findByOidcSubject, findAllByOidcSubject, findAll, count, findPaginated, create, update, setOidcSubject, clearOidcSubject, remove, deleteUser, incrementFailedAttempts, consumeBackupCode };
