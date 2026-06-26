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

var { hasScope } = require("../security/scope-policy");

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
 *   if (!canEditOwned(resource, req.user, "ownerId", req)) return 403
 *
 * The ownerField arg lets each resource name its ownership column
 * (bundles use "ownerId", files use "uploadedBy", etc).
 *
 * The optional `principal` arg (pass `req`) distinguishes an interactive
 * admin SESSION from an admin-minted API KEY. Every key is minted by an
 * admin, so api-auth attaches the admin creator as req.user — without this
 * gate a narrow "upload"/"read" key would inherit the creator's blanket
 * ownership override and edit/delete any user's resources. When req.apiKey
 * is present the admin bypass only applies if the KEY itself carries the
 * "admin" scope; otherwise the key falls through to the plain ownership
 * check. Interactive sessions (no req.apiKey) keep the unconditional bypass.
 */
function canEditOwned(resource, user, ownerField, principal) {
  if (!user) return false;
  if (isAdmin(user) && _adminBypassAllowed(principal)) return true;
  if (!resource) return false;
  var owner = resource[ownerField || "ownerId"];
  return !!owner && owner === user._id;
}

// The admin ownership override is a SESSION privilege. An API-key principal
// only inherits it when the key was explicitly minted with admin scope —
// a key labelled "upload"/"read" for least privilege must not wield it.
function _adminBypassAllowed(principal) {
  if (principal && principal.apiKey) return hasScope(principal.apiKey, "admin");
  return true;
}

module.exports = {
  isAdmin: isAdmin,
  canEditOwned: canEditOwned,
};
