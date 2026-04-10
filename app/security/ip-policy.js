/**
 * IP Policy — centralized client IP resolution and blocklist checking.
 * Wraps rate-limit.getIp() and blockedIps lookups.
 */
var rateLimit = require("../../lib/rate-limit");

/**
 * Get the client's real IP address, respecting trusted proxy headers.
 */
function getClientIp(req) {
  return rateLimit.getIp(req) || "";
}

module.exports = { getClientIp };
