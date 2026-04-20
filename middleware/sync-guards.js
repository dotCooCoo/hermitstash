/**
 * Shared gate logic for /sync/* endpoints.
 *
 * Three independent sync endpoints (POST /sync/rename, POST /sync/renew-cert,
 * plus the /sync/ws upgrade handler) each need the same chain of checks:
 *
 *   1. Bearer token valid → req.apiKey attached (done by api-auth middleware)
 *   2. apiKey has "sync" or "admin" permission
 *   3. If apiKey.boundBundleId is set, the target bundleId matches it
 *   4. If apiKey.certFingerprint is set, the caller's mTLS cert matches it
 *
 * Previously these checks were inlined at each call site. Two separate
 * scope-enforcement bugs (v1.8.12 boundBundleId missing on /sync/rename;
 * v1.8.13 certFingerprint missing on /sync/rename) proved that copy-paste
 * across three endpoints is error-prone. This module is now the one place
 * new /sync/* endpoints import from — if a check exists here, every
 * consumer gets it.
 *
 * Two API shapes:
 *   - enforceXxx(...) → helper functions used by the /sync/ws upgrade
 *     handler, which writes to a raw socket (not an Express res).
 *   - requireSyncAuth({ requireBundle, requireOwner }) → 3-arg middleware
 *     for app.post() routes. Composes the helpers and handles the response.
 */
var { sha3Hash, timingSafeEqual } = require("../lib/crypto");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var { hasScope } = require("../app/security/scope-policy");

/**
 * Reconstruct PEM from a peerCert.raw buffer and hash with SHA3-512 —
 * matches how apiKey.certFingerprint is stored at enrollment time.
 */
function peerCertFingerprintSha3(peerCert) {
  if (!peerCert || !peerCert.raw) return "";
  var derB64 = peerCert.raw.toString("base64");
  var pem = "-----BEGIN CERTIFICATE-----\n" + derB64.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
  return sha3Hash(pem);
}

/**
 * Require apiKey to have "sync" or "admin" permission.
 * Returns null on pass, { status, error } on fail.
 */
function enforceSyncScope(apiKey) {
  if (!apiKey) return { status: 401, error: "Unauthorized." };
  if (!hasScope(apiKey, "sync") && !hasScope(apiKey, "admin")) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/**
 * If apiKey.boundBundleId is set, the request's target bundleId must match.
 * Pass null bundleId for endpoints not tied to a specific bundle.
 * Returns null on pass, { status, error } on fail.
 */
function enforceBundleBinding(apiKey, bundleId) {
  if (!apiKey || !apiKey.boundBundleId) return null;
  if (!bundleId || apiKey.boundBundleId !== bundleId) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/**
 * If apiKey.certFingerprint is set, the caller must present a cert whose
 * SHA3-512 PEM hash matches. The socket must also be TLS-authorized.
 *
 * Returns null on pass, { status, error } on fail.
 * socket: Node TLSSocket (from req.socket)
 */
function enforceCertBinding(apiKey, socket) {
  if (!apiKey || !apiKey.certFingerprint) return null;
  if (!socket || typeof socket.getPeerCertificate !== "function" || !socket.authorized) {
    return { status: 403, error: "Client certificate required." };
  }
  var peerCert = socket.getPeerCertificate(true);
  if (!peerCert || !peerCert.raw) {
    return { status: 403, error: "Client certificate required." };
  }
  var presentedFp = peerCertFingerprintSha3(peerCert);
  if (!presentedFp ||
      presentedFp.length !== apiKey.certFingerprint.length ||
      !timingSafeEqual(presentedFp, apiKey.certFingerprint)) {
    return { status: 403, error: "Certificate does not match API key." };
  }
  return null;
}

/**
 * Bundle-ownership check — the apiKey's user must strictly own the target
 * bundle. No admin-scope bypass: /sync/* endpoints are sync-client APIs,
 * not admin UIs, so even an admin-scoped API key can't rename/alter
 * another user's bundle through this path. (Admin routes that legitimately
 * need cross-user access live under /admin/*, not /sync/*.)
 * Returns null on pass, { status, error } on fail.
 */
function enforceBundleOwnership(apiKey, bundle) {
  if (!bundle) return { status: 404, error: "Bundle not found." };
  if (!bundle.ownerId || bundle.ownerId !== apiKey.userId) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/**
 * Express-style 3-arg middleware composing the above gates.
 *
 * Options:
 *   requireBundle: true  — read `req.body.bundleId` (must be called AFTER
 *                           parseJson has populated req.body, OR the middleware
 *                           reads the id via req.params.bundleId as a fallback).
 *                           On success, attaches req.syncBundle = <bundle>.
 *
 * Usage:
 *   app.post("/sync/rename",
 *     rateLimit.middleware(...),
 *     requireSyncAuth({ requireBundle: true }),
 *     async function (req, res) { ... }
 *   );
 *
 * Because /sync/rename reads bundleId from a JSON body, callers must parse
 * the body before the middleware runs. To keep that one-liner, the
 * middleware parses on demand if req.body is missing.
 */
function requireSyncAuth(opts) {
  opts = opts || {};
  return async function syncAuthMiddleware(req, res, next) {
    // Scope first — cheapest check, fastest reject
    var scopeErr = enforceSyncScope(req.apiKey);
    if (scopeErr) {
      res.writeHead(scopeErr.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: scopeErr.error }));
      return;
    }

    // Bundle resolution
    var bundleId = null;
    var bundle = null;
    if (opts.requireBundle) {
      // Prefer parsed body, then route params, then query string
      if (!req.body) {
        try {
          var { parseJson } = require("../lib/multipart");
          req.body = await parseJson(req);
        } catch (_e) { req.body = {}; /* malformed — treated as missing bundleId */ }
      }
      bundleId = (req.body && req.body.bundleId) || (req.params && req.params.bundleId) || null;
      if (!bundleId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "bundleId required." }));
        return;
      }
      bundle = bundlesRepo.findById(bundleId);
      var ownerErr = enforceBundleOwnership(req.apiKey, bundle);
      if (ownerErr) {
        res.writeHead(ownerErr.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: ownerErr.error }));
        return;
      }
      req.syncBundle = bundle;
    }

    // Bundle binding (runs regardless — a key without boundBundleId passes)
    var bindErr = enforceBundleBinding(req.apiKey, bundleId);
    if (bindErr) {
      res.writeHead(bindErr.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: bindErr.error }));
      return;
    }

    // Cert binding (last — involves DER parse + SHA3, most expensive)
    var certErr = enforceCertBinding(req.apiKey, req.socket);
    if (certErr) {
      res.writeHead(certErr.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: certErr.error }));
      return;
    }

    next();
  };
}

module.exports = {
  enforceSyncScope: enforceSyncScope,
  enforceBundleBinding: enforceBundleBinding,
  enforceCertBinding: enforceCertBinding,
  enforceBundleOwnership: enforceBundleOwnership,
  peerCertFingerprintSha3: peerCertFingerprintSha3,
  requireSyncAuth: requireSyncAuth,
};
