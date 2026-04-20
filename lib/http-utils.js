/**
 * Tiny HTTP parsing helpers shared across routes + middleware.
 *
 * Keep this file small and dependency-free — it's loaded by low-level
 * middleware (api-auth, sync-guards). Don't import repositories, crypto,
 * or anything that runs I/O at require-time.
 */

/**
 * Extract a Bearer token from a request's Authorization header.
 *
 * Returns the raw token string (with surrounding whitespace trimmed) or
 * null when the header is missing, doesn't start with "Bearer ", or the
 * token after the scheme is empty. The comparison is intentionally
 * case-sensitive on the scheme — per RFC 6750 §2.1, clients MUST send
 * exactly "Bearer ".
 *
 * Previously two different sites did this inline and had drifted:
 *   server.js (WS upgrade): auth.slice(7).trim()     ← trims whitespace
 *   middleware/api-auth.js: auth.substring(7)        ← does NOT trim
 * A request with extra whitespace (e.g. "Bearer  token") would hash
 * differently in each path, breaking auth unpredictably.
 */
function extractBearerToken(req) {
  var auth = req && req.headers && req.headers.authorization;
  if (!auth || typeof auth !== "string") return null;
  if (!auth.startsWith("Bearer ")) return null;
  var token = auth.slice(7).trim();
  return token || null;
}

module.exports = {
  extractBearerToken: extractBearerToken,
};
