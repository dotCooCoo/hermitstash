/**
 * Rate-limit test-harness helpers.
 *
 * Production rate limiting runs entirely through b.middleware.rateLimit — each
 * guarded route (routes/auth.js, routes/two-factor.js, etc.) constructs its own
 * limiter and the framework owns the backing store. This module is no longer in
 * the production request path; it exposes the two things the rest of the
 * codebase still needs:
 *
 *   - getIp(req): the canonical client-IP read, delegating to lib/client-ip.js
 *     (the single trustProxy-gated wrapper). A couple of security tests assert
 *     this extraction directly.
 *   - resetAllInstances(): clears every b.middleware.rateLimit instance so the
 *     test harness can isolate cases that hammer a guarded route.
 *
 * The former hand-rolled in-memory limiter (check / middleware / sliding-window
 * stores / eviction / cleanup timer) operated on a local store nothing in
 * production read once routes moved to b.middleware.rateLimit, so it was dead
 * weight masking the real limiter's behavior — retired here.
 */
var b = require("./vendor/blamejs");
var clientIp = require("./client-ip");

/**
 * Extract client IP from request.
 * Delegates to lib/client-ip.js — the single canonical HS wrapper that applies
 * the trustProxy gate before reading X-Forwarded-For.
 */
function getIp(req) {
  return clientIp.getIp(req);
}

/**
 * Clear every b.middleware.rateLimit instance.
 *
 * The framework's resetAll() drops all keys across all limiter instances —
 * exactly what a test harness needs to isolate cases between runs. Routes
 * construct their limiters at module load, so a single call flushes login,
 * register, upload, 2FA, and every other guarded route at once.
 */
function resetAllInstances() {
  return b.middleware._modules.rateLimit.resetAll();
}

module.exports = { getIp, resetAllInstances };
