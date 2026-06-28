/**
 * Users Repository — persistence logic for user accounts.
 * All database access for users goes through here.
 */
var { users, credentials } = require("../../../lib/db");
var { transaction } = require("../db/transaction");
var b = require("../../../lib/vendor/blamejs");

function findById(id) { return users.findOne({ _id: id }); }
function findByEmail(email) { return users.findOne({ email: String(email).toLowerCase() }); }
function findAll(query) { return users.find(query || {}); }
function count(query) { return users.count(query || {}); }

function findPaginated(query, opts) { return users.findPaginated(query, opts); }

// insert() returns the stored row with fields still sealed; re-read by _id so
// callers receive the same unsealed shape as findById. Without this, sealed
// blobs (email, displayName) leak into anything built from the return value —
// e.g. the registration audit/SIEM event, which records targetEmail from it.
function create(doc) {
  var inserted = users.insert(doc);
  return (inserted && inserted._id && users.findOne({ _id: inserted._id })) || inserted;
}

function update(id, ops) { return users.update({ _id: id }, ops); }

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
    var idx = -1;
    for (var i = 0; i < codes.length; i++) {
      if (b.crypto.timingSafeEqual(String(codes[i]), codeHash)) { idx = i; break; }
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

module.exports = { findById, findByEmail, findAll, count, findPaginated, create, update, remove, deleteUser, incrementFailedAttempts, consumeBackupCode };
