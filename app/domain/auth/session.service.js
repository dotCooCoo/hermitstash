/**
 * Session Service — business logic for session lifecycle.
 *
 * `req.regenerateSession`, `clearSessionsForUser`, `clearSessionById`,
 * and `clearAllSessions` all became async when lib/session.js migrated
 * to `b.session` in v1.9.29. Every helper here is async; callers
 * (route handlers) await accordingly.
 */
var { clearSessionsForUser, clearAllSessions, clearSessionById, secureLogout } = require("../../../lib/session");
var { TIME } = require("../../../lib/constants");

/**
 * Login: rotate the session sid (defeats fixation) and bind the new
 * row to `userId` at the storage layer (so destroyAllForUser keys on
 * it). Caller-side req.session.userId is also set so existing HS code
 * that reads it without dereferencing the b.session row keeps working.
 */
async function loginUser(req, userId) {
  await req.regenerateSession({ userId: userId });
  req.session.userId = userId;
}

/**
 * Start 2FA pending state: rotate to a fresh anonymous sid (the user
 * is NOT logged in yet — full login happens in complete2fa). Stash the
 * pending userId + 5-minute deadline so the verify route can pick up
 * where this left off.
 */
async function start2faPending(req, userId) {
  await req.regenerateSession();
  req.session.pendingTotpUserId = userId;
  req.session.pendingTotpExpires = Date.now() + TIME.minutes(5);
}

/**
 * Complete 2FA: pull pending userId out of session.data, rotate the
 * sid to bind it to the now-confirmed user, and finalize login.
 */
async function complete2fa(req) {
  var userId = req.session.pendingTotpUserId;
  delete req.session.pendingTotpUserId;
  delete req.session.pendingTotpExpires;
  await req.regenerateSession({ userId: userId });
  req.session.userId = userId;
  return userId;
}

/**
 * Logout: clear app-side data + delete the storage row. The next
 * request gets a fresh anonymous session.
 *
 * Pass `res` (the live response) for a secure self-logout: it adds an
 * RFC 9527 Clear-Site-Data header + an expired hs_sid cookie so the
 * browser drops its client-side state, not just the server row. Callers
 * without a response (e.g. flows that revoke the row but answer on a
 * different surface) omit `res` and get the server-side-only revoke.
 */
async function logoutUser(req, res) {
  Object.keys(req.session).forEach(function (k) { delete req.session[k]; });
  if (res) {
    await secureLogout(res, req.sessionId);
  } else {
    await clearSessionById(req.sessionId);
  }
}

/**
 * Revoke every session globally. Used by admin "force-logout-all".
 */
async function revokeAll(req) {
  await clearAllSessions();
  Object.keys(req.session).forEach(function (k) { delete req.session[k]; });
}

/**
 * Revoke every session belonging to a single user.
 */
async function revokeUser(userId) {
  return clearSessionsForUser(userId);
}

module.exports = { loginUser, start2faPending, complete2fa, logoutUser, revokeAll, revokeUser };
