/**
 * Scope Policy — typed API key permissions with centralized enforcement.
 * Replaces ad-hoc permission checks scattered across routes.
 *
 * Scopes:
 *   "admin"    — full admin access (settings, user management, exports)
 *   "upload"   — create bundles, upload files
 *   "read"     — list files, download files, view bundles
 *   "webhook"  — manage webhooks
 *   "sync"     — connect WebSocket, upload/replace/delete files in sync bundles
 *   "*"        — all scopes (alias for admin)
 */

var VALID_SCOPES = ["admin", "upload", "read", "webhook", "sync"];

/**
 * Parse a permissions string into a set of scopes.
 */
function parseScopes(permissions) {
  if (!permissions) return new Set();
  if (permissions === "*" || permissions === "admin") return new Set(VALID_SCOPES);
  var scopes = new Set();
  String(permissions).split(",").forEach(function (s) {
    var trimmed = s.trim().toLowerCase();
    if (VALID_SCOPES.indexOf(trimmed) !== -1) scopes.add(trimmed);
  });
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
  return function (req, res, next) {
    // Session auth — use role-based checks (requireAuth/requireAdmin)
    if (!req.apiKey) return next();
    // API key auth — check scope
    if (hasScope(req.apiKey, scope)) return next();
    res.status(403).json({ error: "API key lacks '" + scope + "' scope." });
  };
}

module.exports = { parseScopes, hasScope, requireScope, VALID_SCOPES };
