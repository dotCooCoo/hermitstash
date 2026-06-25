/**
 * Rate-limit test-harness helpers.
 *
 * Every guarded route mounts its limiter via `guard(opts)` here, which wraps
 * b.middleware.rateLimit with HermitStash's shared problem+json denial. The
 * framework owns the limiting algorithm + the backing store; this module owns
 * the HS-specific 429 shape + the test-harness helpers:
 *
 *   - guard(opts): the production mount wrapper (b.middleware.rateLimit +
 *     problemDetails:true for RFC 9457 429s). Drop-in for b.middleware.rateLimit({...}).
 *   - getIp(req): the canonical client-IP read, delegating to lib/client-ip.js
 *     (the single trustProxy-gated wrapper). A couple of security tests assert
 *     this extraction directly.
 *   - resetAllInstances(): clears every limiter instance so the test harness
 *     can isolate cases that hammer a guarded route.
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

/**
 * Rate-limit guard — every guarded route mounts through here so all 429s are
 * RFC 9457 `application/problem+json` instead of the framework default
 * text/plain. Drop-in for `b.middleware.rateLimit({...})`: same opts (max,
 * windowMs, algorithm, ...), plus `problemDetails: true`.
 *
 * Why the framework's `problemDetails: true` and NOT a custom `onDeny`:
 * HermitStash wraps the response object (the session middleware wraps
 * res.writeHead to inject the session cookie; the legacy api-encrypt path wraps
 * res.json), so res.end does not flip res.writableEnded synchronously. The
 * framework's denyResponse falls through to a SECOND default write whenever an
 * onDeny hook leaves writableEnded false after writing — a double write that
 * throws ERR_HTTP_HEADERS_SENT and corrupts the connection. `problemDetails:
 * true` makes denyResponse emit the problem document itself and return without
 * a writableEnded check, so it is the only regression-free path here.
 *
 * Limitation: the framework's rate-limit deny passes a problemCode that its
 * denyResponse never maps to the `type` URI (it honors only problemType), so
 * the emitted 429 carries `type: "about:blank"` rather than HermitStash's
 * `https://hermitstash.com/problems/rate-limited`. about:blank is RFC 9457
 * valid — clients key off the 429 status. The specific type lands when the
 * upstream deny-response.js maps problemCode -> type (tracked upstream ask).
 */
function guard(opts) {
  opts = opts || {};
  return b.middleware.rateLimit(Object.assign({}, opts, {
    problemDetails: true,
    // Key the limiter on HermitStash's trustProxy-gated client IP — the same
    // value the blocklist and audit use — not the framework default (the raw
    // socket peer). Behind the recommended reverse proxy the socket peer is the
    // proxy, which would collapse every client into ONE bucket: a per-IP
    // throttle becomes a global lever (any client trips the login/unlock limit
    // for everyone), and loginLimiter.reset(getIp(req)) targets the wrong key.
    // A caller-supplied keyFn (e.g. a per-user limiter) still wins.
    keyFn: opts.keyFn || function (req) { return clientIp.getIp(req) || "unknown"; },
    // Resolve the framework's AUDIT-actor IP through the same trustProxy-gated
    // client IP. Without this the rate-limit / block audit event records the
    // socket peer (the reverse proxy) instead of the real client, even though the
    // limiter KEYS off the gated IP — so the audit trail named the wrong actor.
    clientIpResolver: opts.clientIpResolver || function (req) { return clientIp.getIp(req); },
  }));
}

module.exports = { getIp, resetAllInstances, guard };
