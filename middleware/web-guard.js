/**
 * Web-guard middleware — soft mTLS enforcement at the app layer.
 *
 * When config.enforceMtls is true, drops connections that are neither:
 *   - mTLS-authorized (socket.authorized === true) — a browser or proxy
 *     presenting a valid client cert signed by our CA
 *   - Bearer-authenticated with a VALID API key (Authorization: Bearer
 *     hs_xxx that resolves to a live key owned by an active user) —
 *     programmatic sync tooling, scripts, webhooks. A bearer prefix alone
 *     is NOT sufficient; the token is validated here the same way
 *     middleware/api-auth.js validates it downstream, because web-guard runs
 *     before api-auth in the pipeline (req.apiKey is not populated yet).
 *   - hitting /sync/* (sync clients, including /sync/enroll before the cert
 *     is issued)
 *   - hitting /health (container orchestration probes)
 *   - hitting /admin/api/enforce-mtls (so a Bearer-authenticated admin can
 *     flip the toggle back off via sync-client tooling even if the admin's
 *     browser cert is missing)
 *
 * Disallowed connections get req.socket.destroy() — no HTTP response is
 * rendered. An attacker scanning the port learns only that it speaks TLS.
 *
 * Default behavior (enforceMtls=false) is a no-op: next() is called
 * unconditionally. Byte-identical to pre-1.8.8 when the toggle is off.
 *
 * Hard enforcement at the TLS layer (rejectUnauthorized: true) is a
 * boot-time option via ENFORCE_MTLS_STRICT=true — see server.js. When
 * that's in effect, this middleware never sees a non-mTLS request because
 * the TLS handshake already rejected it.
 */
var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");
var certUtils = require("../lib/cert-utils");
var { apiKeys, users } = require("../lib/db");
var { validateBearerToken } = require("../app/shared/validate");

// A bearer token satisfies the soft-mTLS gate ONLY when it resolves to a live
// API key owned by an active user — mirroring middleware/api-auth.js. web-guard
// runs BEFORE api-auth in the request pipeline (pre-session, position 6), so
// req.apiKey is not populated yet; the token must be validated here. Treating
// the mere presence of an "Authorization: Bearer " prefix as authenticated let
// any caller past the gate with a bogus token and no client cert.
function isValidBearer(req) {
  var token = b.requestHelpers.extractBearer(req);
  if (!token || !validateBearerToken(token)) return false; // absent / malformed — skip the DB hit
  var key = apiKeys.findOne({ keyHash: b.crypto.sha3Hash(token) });
  if (!key || !key.userId) return false;
  var user = users.findOne({ _id: key.userId });
  return !!(user && user.status === "active");
}

function isAlwaysAllowed(pathname) {
  if (!pathname) return false;
  if (pathname === "/health") return true;
  if (pathname === "/admin/api/enforce-mtls") return true;
  if (pathname.indexOf("/sync/") === 0) return true;
  return false;
}

module.exports = function webGuard(req, res, next) {
  // A revoked client cert must NEVER be honored — in soft OR strict mode. Node's
  // TLS layer authorizes purely on chain-to-CA + not-expired (no CRL/OCSP), so a
  // revoked-but-unexpired cert still sets socket.authorized. Consult the
  // revocation list on every authorized peer cert, BEFORE the enforceMtls
  // soft-gate below (under ENFORCE_MTLS_STRICT the TLS layer admits the revoked
  // cert and config.enforceMtls may be unset, which would skip this check). The
  // sync/WS paths already do this; the web-UI mTLS path — the feature's purpose —
  // did not. isCertRevoked uses an indexed lookup, so this is cheap.
  if (req.socket && req.socket.authorized === true &&
      typeof req.socket.getPeerCertificate === "function") {
    var peerCert = req.socket.getPeerCertificate(true);
    if (peerCert && peerCert.raw && certUtils.isPeerCertRevoked(peerCert)) {
      try { req.socket.destroy(); } catch (_e) { /* socket may already be gone */ }
      return;
    }
  }

  if (!config.enforceMtls) return next();

  if (isAlwaysAllowed(req.pathname)) return next();
  if (isValidBearer(req)) return next();
  if (req.socket && req.socket.authorized === true) return next();

  // No mTLS, no Bearer, not an always-allowed path → drop the connection.
  // No response body, no template render, no information leakage.
  try { req.socket.destroy(); } catch (_e) {} // allow:silent-catch — best-effort socket teardown; peer may have already closed
};
