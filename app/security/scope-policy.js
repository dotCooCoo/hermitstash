/**
 * Scope Policy — typed API key permissions with centralized enforcement.
 * Replaces ad-hoc permission checks scattered across routes.
 *
 * Scopes:
 *   "admin"    — full admin access (settings, user management, exports)
 *   "upload"   — create bundles, upload files
 *   "read"     — list files, download files, view bundles
 *   "sync"     — connect WebSocket, upload/replace/delete files in sync bundles
 *   "*"        — all scopes (alias for admin)
 *
 * Webhook management has no key-scoped path — every /admin/webhooks route is
 * requireAdmin-gated, so a key would need the "admin" scope to reach them. A
 * standalone "webhook" scope was never enforced anywhere; it is omitted here so
 * operators can't mint a least-privilege key labelled with a dead scope.
 */

var { ForbiddenError } = require("../shared/errors");

var VALID_SCOPES = ["admin", "upload", "read", "sync"];

/**
 * Parse a permissions string into a set of scopes.
 */
function parseScopes(permissions) {
  if (!permissions) return new Set();
  if (permissions === "*") return new Set(VALID_SCOPES);
  var scopes = new Set();
  String(permissions).split(",").forEach(function (s) {
    var trimmed = s.trim().toLowerCase();
    if (VALID_SCOPES.indexOf(trimmed) !== -1) scopes.add(trimmed);
  });
  // 'admin' implies every scope wherever it appears, not only as the exact string
  // "admin": a combined grant like "admin,upload" previously kept just
  // {admin, upload} and silently dropped read/webhook/sync access.
  if (scopes.has("admin")) return new Set(VALID_SCOPES);
  return scopes;
}

/**
 * Check if an API key has a required scope.
 */
function hasScope(apiKey, requiredScope) {
  if (!apiKey) return false;
  var scopes = parseScopes(apiKey.permissions);
  return scopes.has(requiredScope);
}

/**
 * Middleware factory: require a specific scope for API key access.
 * Session-authenticated users bypass scope checks (they use role-based auth).
 */
function requireScope(scope) {
  return async function (req, res, next) {
    // Session auth — use role-based checks (requireAuth/requireAdmin)
    if (!req.apiKey) return next();
    // API key auth — check scope
    if (hasScope(req.apiKey, scope)) return next();
    // Throw at the boundary so the centralized error handler renders the 403.
    // On api-encrypt'd routes (e.g. /drop/init, /drop/finalize) that handler
    // routes the ForbiddenError through the encrypting res.json — a direct
    // b.problemDetails.send would ship a cleartext body on a session the
    // client negotiated as encrypted.
    throw new ForbiddenError("API key lacks '" + scope + "' scope.");
  };
}

module.exports = { parseScopes, hasScope, requireScope, VALID_SCOPES };
