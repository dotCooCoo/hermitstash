/**
 * Session Service — business logic for session lifecycle.
 * Wraps the low-level session store with higher-level operations.
 */
var { clearSessionsForUser, clearAllSessions, clearSessionById } = require("../../../lib/session");

/**
 * Login: regenerate session and set userId.
 */
function loginUser(req, userId) {
  req.regenerateSession();
  req.session.userId = userId;
}

/**
 * Start 2FA pending state: regenerate session, store pending userId with expiry.
 */
function start2faPending(req, userId) {
  req.regenerateSession();
  req.session.pendingTotpUserId = userId;
  req.session.pendingTotpExpires = Date.now() + 300000; // 5 minutes
}

/**
 * Complete 2FA: clear pending state and login.
 */
function complete2fa(req) {
  var userId = req.session.pendingTotpUserId;
  delete req.session.pendingTotpUserId;
  delete req.session.pendingTotpExpires;
  req.regenerateSession();
  req.session.userId = userId;
  return userId;
}

/**
 * Logout: clear all session data and delete from store.
 */
function logoutUser(req) {
  Object.keys(req.session).forEach(function (k) { delete req.session[k]; });
  clearSessionById(req.sessionId);
}

/**
 * Revoke all sessions globally.
 */
function revokeAll(req) {
  clearAllSessions();
  // Clear current session data so writeHead doesn't re-persist
  Object.keys(req.session).forEach(function (k) { delete req.session[k]; });
}

/**
 * Revoke all sessions for a specific user.
 */
function revokeUser(userId) {
  clearSessionsForUser(userId);
}

module.exports = { loginUser, start2faPending, complete2fa, logoutUser, revokeAll, revokeUser };
