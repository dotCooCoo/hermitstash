/**
 * Transaction helper for multi-step database operations.
 * Wraps SQLite's built-in transaction support via DatabaseSync.exec().
 *
 * Usage:
 *   var { transaction } = require("./transaction");
 *   transaction(function() {
 *     users.remove({ _id: userId });
 *     credentials.remove({ userId: userId });
 *     files.update({ uploadedBy: userId }, { $set: { uploadedBy: "deleted" } });
 *   });
 *
 * If the callback throws, the transaction is rolled back.
 * Note: _db.exec() below is SQLite DatabaseSync.exec(), NOT child_process.exec().
 */

var _db = null;

function init(db) {
  _db = db;
}

/**
 * Execute a function within a SQLite transaction.
 * Rolls back on error, commits on success.
 */
function transaction(fn) {
  if (!_db) throw new Error("Transaction helper not initialized. Call init(db) first.");
  // SQLite DatabaseSync.exec (not child_process)
  _db.exec("BEGIN IMMEDIATE"); // eslint-disable-line
  try {
    var result = fn();
    _db.exec("COMMIT"); // eslint-disable-line
    return result;
  } catch (e) {
    _db.exec("ROLLBACK"); // eslint-disable-line
    throw e;
  }
}

module.exports = { init, transaction };
