/**
 * Migration: Add lockout columns to users table.
 *
 * Adds failedLoginAttempts (INTEGER) and lockedUntil (TEXT) to track
 * brute-force login attempts and temporary account lockouts.
 *
 * These columns may already exist from inline schema code — the try/catch
 * handles the "duplicate column" error gracefully.
 *
 * Note: db.exec() below is SQLite DatabaseSync.exec(), NOT child_process.exec().
 */

module.exports = {
  up: function (db) {
    try {
      db.exec("ALTER TABLE users ADD COLUMN failedLoginAttempts INTEGER DEFAULT 0");  // eslint-disable-line
    } catch (_e) {
      // Column already exists — safe to ignore
    }
    try {
      db.exec("ALTER TABLE users ADD COLUMN lockedUntil TEXT");  // eslint-disable-line
    } catch (_e) {
      // Column already exists — safe to ignore
    }
  },
};
