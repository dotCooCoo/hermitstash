/**
 * Access control middleware for bundles and stash pages.
 * Checks password/email gate session state and returns the appropriate
 * response for both browser (HTML redirect) and API (JSON 401/403) clients.
 */

/**
 * Check if a resource is locked for the current session.
 * @param {object} resource - bundle or stash record (must have accessMode, passwordHash)
 * @param {string} sessionKey - the session key to check (e.g., "bundle_abc" or "stashUnlocked_slug")
 * @param {object} session - req.session
 * @returns {false|"password"|"email"|"email-then-password"} false if unlocked
 */
function checkLock(resource, sessionKey, session) {
  var mode = resource.accessMode || (resource.passwordHash ? "password" : "open");
  if (mode === "open") return false;
  var s = session[sessionKey];
  if (mode === "password") return s ? false : "password";
  if (mode === "email") return s ? false : "email";
  if (mode === "both") {
    if (!s) return "email";
    if (typeof s === "object" && s.emailVerified && !s.passwordVerified) return "email-then-password";
    return (s === true || (typeof s === "object" && s.passwordVerified)) ? false : "email";
  }
  return false;
}

/**
 * Check if a bundle is locked.
 */
function isBundleLocked(bundle, session) {
  return checkLock(bundle, "bundle_" + bundle.shareId, session);
}

/**
 * Check if a stash page is locked.
 */
function isStashLocked(stash, session) {
  return checkLock(stash, "stashUnlocked_" + stash.slug, session);
}

/**
 * Returns true if the request prefers JSON (API client, sync client).
 */
function prefersJson(req) {
  var accept = req.headers && req.headers.accept || "";
  return accept.includes("application/json") || !!req.apiKey;
}

module.exports = { checkLock, isBundleLocked, isStashLocked, prefersJson };
