/**
 * Web-guard middleware — soft mTLS enforcement at the app layer.
 *
 * When config.enforceMtls is true, drops connections that are neither:
 *   - mTLS-authorized (socket.authorized === true) — a browser or proxy
 *     presenting a valid client cert signed by our CA
 *   - Bearer-authenticated (Authorization: Bearer hs_xxx) — programmatic
 *     sync tooling, scripts, webhooks
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
var config = require("../lib/config");
var certUtils = require("../lib/cert-utils");

function isBearerAuth(req) {
  var h = req.headers && req.headers.authorization;
  return !!(h && typeof h === "string" && h.startsWith("Bearer "));
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
  if (isBearerAuth(req)) return next();
  if (req.socket && req.socket.authorized === true) return next();

  // No mTLS, no Bearer, not an always-allowed path → drop the connection.
  // No response body, no template render, no information leakage.
  try { req.socket.destroy(); } catch (_e) {} // allow:silent-catch — best-effort socket teardown; peer may have already closed
};
