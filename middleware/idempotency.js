/**
 * Idempotency-Key middleware mount-ready instance.
 *
 * Single shared b.middleware.idempotencyKey instance pointed at the
 * DB-backed lib/idempotency-store. Mounted on mutating POST endpoints
 * where a network retry would otherwise create a duplicate resource
 * (apikeys create, webhooks create, drop init/finalize, user invite).
 *
 * Idempotency-Key is OPTIONAL. Clients that don't send the header
 * skip the cache and the middleware is a pass-through. Clients
 * sending the same key + same body within 24h get the cached
 * response replayed without re-executing the handler. Same key with
 * different body refuses with 422 problem-details
 * `idempotency/key-reuse-mismatch` (draft-ietf-httpapi-idempotency-key §4.3).
 *
 * Order matters at the route declaration: rate-limit runs FIRST
 * (block abuse from valid keys), then idempotency (replay cache
 * hits), then scope/auth (which the cached response already passed
 * on the original call).
 */
var b = require("../lib/vendor/blamejs");
var store = require("../lib/idempotency-store");

// Idempotent — error-handler.js also sets this. Whichever module loads
// first wins; subsequent calls with the same URI are no-ops. Ensures
// the middleware's problem+json error replies (missing-key / bad-key /
// key-reuse-mismatch) carry the hermitstash.com problem namespace
// instead of the framework default.
b.problemDetails.setBase("https://hermitstash.com/problems");

module.exports = b.middleware.idempotencyKey({
  store: store,
  ttlMs: b.constants.TIME.hours(24),
});
