/**
 * Access control middleware for bundles and stash pages.
 * Checks password/email gate session state and returns the appropriate
 * response for both browser (HTML redirect) and API (JSON 401/403) clients.
 */

/**
 * Re-validate a session's verified email against the resource's CURRENT
 * allowed list. The gate stores the verified email at request-code time; if the
 * operator later edits allowedEmails to remove that address, a live session
 * must lose access on its next request rather than keep it until the session
 * expires. Each caller passes the matcher its route already uses
 * (bundle: exact-membership; stash: exact + @domain patterns) so the
 * enforcement test is identical to the issuance test.
 *
 * @param {string} email - the verified email carried in the session
 * @param {function|undefined} allowedMatch - predicate(email) -> boolean
 * @returns {boolean} true when still allowed (or no matcher supplied)
 */
function emailStillAllowed(email, allowedMatch) {
  if (typeof allowedMatch !== "function") return true;
  if (typeof email !== "string" || !email) return false;
  return !!allowedMatch(email);
}

/**
 * Check if a resource is locked for the current session.
 * @param {object} resource - bundle or stash record (must have accessMode, passwordHash)
 * @param {string} sessionKey - the session key to check (e.g., "bundle_abc" or "stashUnlocked_<id>")
 * @param {object} session - req.session
 * @param {function} [allowedMatch] - predicate to re-validate the session email
 *        against the resource's CURRENT allowed list (email/both modes)
 * @returns {false|"password"|"email"|"email-then-password"} false if unlocked
 */
function checkLock(resource, sessionKey, session, allowedMatch) {
  var mode = resource.accessMode || (resource.passwordHash ? "password" : "open");
  if (mode === "open") return false;
  var s = session[sessionKey];
  if (mode === "password") return s ? false : "password";
  if (mode === "email") {
    if (!s) return "email";
    // Revocation gap: re-test the stored email against the current allow-list,
    // not just session presence. A string session value carries the email; an
    // object value (from a prior "both"-mode unlock) carries it under
    // emailVerified.
    var emailVal = typeof s === "string" ? s : (s && s.emailVerified);
    return emailStillAllowed(emailVal, allowedMatch) ? false : "email";
  }
  if (mode === "both") {
    // Defense-in-depth: "both" mode requires a verified email string AND password flag.
    // The boolean true or a missing email must never satisfy the gate.
    if (!s || typeof s !== "object") return "email";
    if (typeof s.emailVerified !== "string") return "email";
    // Re-validate the carried email against the current allow-list — a removed
    // address must re-verify even if it previously cleared the password too.
    if (!emailStillAllowed(s.emailVerified, allowedMatch)) return "email";
    if (!s.passwordVerified) return "email-then-password";
    return false;
  }
  return false;
}

/**
 * Check if a bundle is locked.
 * @param {object} bundle
 * @param {object} session
 * @param {function} [allowedMatch] - re-validate the session email against
 *        bundle.allowedEmails on every request (revocation enforcement)
 */
function isBundleLocked(bundle, session, allowedMatch) {
  return checkLock(bundle, "bundle_" + bundle.shareId, session, allowedMatch);
}

/**
 * Check if a stash page is locked.
 *
 * Keyed by the stable, unguessable stash._id — NOT the human-chosen,
 * reusable slug. A slug freed by delete/rename can later bind to a brand-new
 * stash; keying the unlock state by slug would carry the prior stash's unlock
 * onto the new one (confused deputy on a reused identifier). _id is never
 * reused, mirroring the bundle gate's random shareId keying.
 *
 * @param {object} stash
 * @param {object} session
 * @param {function} [allowedMatch] - re-validate the session email against
 *        stash.allowedEmails on every request (revocation enforcement)
 */
function isStashLocked(stash, session, allowedMatch) {
  return checkLock(stash, "stashUnlocked_" + stash._id, session, allowedMatch);
}

/**
 * Returns true if the request prefers JSON (API client, sync client).
 */
function prefersJson(req) {
  var accept = req.headers && req.headers.accept || "";
  return accept.includes("application/json") || !!req.apiKey;
}

module.exports = { checkLock, isBundleLocked, isStashLocked, prefersJson };
