/**
 * Authorization helpers for browser-session routes.
 *
 * Captures the "site admin bypass" policy used across bundle, file, team,
 * vault, and profile routes. Currently a one-liner, but centralizing it
 * means future policy changes — e.g. require admin 2FA, check if admin is
 * suspended, audit admin-override usage — apply everywhere at once.
 *
 * Scope: browser-session authz only (req.user from attach-user middleware).
 * API-key authz lives in middleware/sync-guards.js (cert + bundle binding).
 */

/**
 * Does req.user have site-admin privileges?
 * Returns false if no user is attached (unauthenticated request).
 */
function isAdmin(user) {
  return !!(user && user.role === "admin");
}

/**
 * Owner-or-admin gate — the canonical ownership pattern in browser routes.
 *
 *   if (!canEditOwned(resource, req.user, "ownerId")) return 403
 *
 * The ownerField arg lets each resource name its ownership column
 * (bundles use "ownerId", files use "uploadedBy", etc).
 */
function canEditOwned(resource, user, ownerField) {
  if (!user) return false;
  if (isAdmin(user)) return true;
  if (!resource) return false;
  var owner = resource[ownerField || "ownerId"];
  return !!owner && owner === user._id;
}

module.exports = {
  isAdmin: isAdmin,
  canEditOwned: canEditOwned,
};
