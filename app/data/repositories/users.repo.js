/**
 * Users Repository — persistence logic for user accounts.
 * All database access for users goes through here.
 */
var { users, credentials } = require("../../../lib/db");
var { transaction } = require("../db/transaction");

function findById(id) { return users.findOne({ _id: id }); }
function findByEmail(email) { return users.findOne({ email: String(email).toLowerCase() }); }
function findAll(query) { return users.find(query || {}); }
function count(query) { return users.count(query || {}); }

function findPaginated(query, opts) { return users.findPaginated(query, opts); }

function create(doc) { return users.insert(doc); }

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

module.exports = { findById, findByEmail, findAll, count, findPaginated, create, update, remove, deleteUser, incrementFailedAttempts };
