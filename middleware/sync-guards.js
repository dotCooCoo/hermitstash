/**
 * The gate chain every /sync/* endpoint shares: sync or admin scope, then the
 * key's bundle binding, then its certificate binding.
 *
 * These checks were once inlined at each call site, and each of two separate
 * regressions came from one endpoint missing a check the others had. A new
 * /sync/* endpoint imports from here so it cannot repeat that.
 *
 * The enforceXxx helpers return { status, error } for the /sync/ws upgrade
 * handler, which answers on a raw socket. requireSyncAuth composes them into
 * 3-arg middleware for the ordinary routes.
 */
var b = require("../lib/vendor/blamejs");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var { hasScope } = require("../app/security/scope-policy");
var { certFingerprintSha3 } = require("../lib/cert-utils");
var { AuthenticationError, ForbiddenError, NotFoundError, ValidationError } = require("../app/shared/errors");

/**
 * The peer certificate's SHA3-512 fingerprint. Re-wraps the DER in a PEM
 * envelope so issuance and verification hash identical bytes.
 */
function peerCertFingerprintSha3(peerCert) {
  if (!peerCert || !peerCert.raw) return "";
  var derB64 = peerCert.raw.toString("base64");
  return certFingerprintSha3("-----BEGIN CERTIFICATE-----\n" + derB64 + "\n-----END CERTIFICATE-----");
}

/** Null on pass, { status, error } on fail. */
function enforceSyncScope(apiKey) {
  if (!apiKey) return { status: 401, error: "Unauthorized." };
  if (!hasScope(apiKey, "sync") && !hasScope(apiKey, "admin")) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/** Pass a null bundleId for an endpoint not tied to one. */
function enforceBundleBinding(apiKey, bundleId) {
  if (!apiKey || !apiKey.boundBundleId) return null;
  if (!bundleId || apiKey.boundBundleId !== bundleId) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/** The socket must be TLS-authorized as well as presenting a matching cert. */
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
      !b.crypto.timingSafeEqual(presentedFp, apiKey.certFingerprint)) {
    return { status: 403, error: "Certificate does not match API key." };
  }
  return null;
}

/**
 * Strict ownership, with no admin-scope bypass: these are sync-client APIs, so
 * even an admin-scoped key cannot reach another user's bundle here. Cross-user
 * admin access lives under /admin/*.
 *
 * A stash-bound key authenticates against its stash rather than a user, and
 * stash-issued bundles often carry ownerId=null because they are created with
 * nobody signed in — without that branch every stash sync client would be
 * refused its own bundle.
 */
function enforceBundleOwnership(apiKey, bundle) {
  if (!bundle) return { status: 404, error: "Bundle not found." };
  if (apiKey.boundStashId) {
    // Confined to the stash, with no fall-through to the issuing user's own
    // bundles: a stash key carries the creating admin's userId, so falling
    // through would let a stash token rename and delete the admin's own files.
    return (bundle.stashId === apiKey.boundStashId)
      ? null
      : { status: 403, error: "Forbidden." };
  }
  if (!bundle.ownerId || bundle.ownerId !== apiKey.userId) {
    return { status: 403, error: "Forbidden." };
  }
  return null;
}

/**
 * Applies the same bindings on the cookie-UI mutation routes, which also accept
 * API-key callers but gate only on scope and ownership. Without this, a cert-
 * or stash-bound sync key presented as a bare Bearer token — with no client
 * certificate — reaches its owner's resources through the cookie path, past
 * both the certificate binding and the stash confinement.
 *
 * A session caller is a deliberate no-op: the route's own ownership check
 * governs there. `bundle` is null for a standalone file.
 */
function enforceApiKeyResourceBinding(req, bundle) {
  var apiKey = req && req.apiKey;
  if (!apiKey) return; // session caller — route ownership check governs
  var certErr = enforceCertBinding(apiKey, req.socket);
  if (certErr) throw new ForbiddenError(certErr.error);
  var bindErr = enforceBundleBinding(apiKey, bundle && bundle._id);
  if (bindErr) throw new ForbiddenError(bindErr.error);
  // Unlike enforceBundleOwnership this does not 404 an unbound key working on a
  // standalone file, which the route's own check governs.
  if (apiKey.boundStashId && (!bundle || bundle.stashId !== apiKey.boundStashId)) {
    throw new ForbiddenError("Forbidden.");
  }
}

/**
 * The gates above as 3-arg middleware. With requireBundle, the bundle id is
 * read from the body, the route params or the query string, and the resolved
 * bundle is attached as req.syncBundle. The body is parsed on demand when it
 * has not been already, so a route can mount this as a one-liner.
 */
function requireSyncAuth(opts) {
  opts = opts || {};
  return async function syncAuthMiddleware(req, res, next) {
    // Thrown rather than answered here: on an apiEncrypt session res.json is
    // the encrypting wrap, and problemDetails.send would ship cleartext.

    // Scope first — the cheapest check.
    var scopeErr = enforceSyncScope(req.apiKey);
    if (scopeErr) {
      if (scopeErr.status === 401) throw new AuthenticationError(scopeErr.error);
      throw new ForbiddenError(scopeErr.error);
    }

    var bundleId = null;
    var bundle = null;
    if (opts.requireBundle) {
      if (!req.body) {
        try {
          req.body = (await b.parsers.json(req)) || {};
        } catch (_e) { req.body = {}; /* malformed — treated as missing bundleId */ }
      }
      bundleId = (req.body && req.body.bundleId) || (req.params && req.params.bundleId) || null;
      if (!bundleId) throw new ValidationError("bundleId required.");
      bundle = bundlesRepo.findById(bundleId);
      var ownerErr = enforceBundleOwnership(req.apiKey, bundle);
      if (ownerErr) {
        if (ownerErr.status === 404) throw new NotFoundError(ownerErr.error);
        throw new ForbiddenError(ownerErr.error);
      }
      req.syncBundle = bundle;
    }

    var bindErr = enforceBundleBinding(req.apiKey, bundleId);
    if (bindErr) throw new ForbiddenError(bindErr.error);

    // Last, because a DER parse plus SHA3 is the most expensive check here.
    var certErr = enforceCertBinding(req.apiKey, req.socket);
    if (certErr) throw new ForbiddenError(certErr.error);

    next();
  };
}

module.exports = {
  enforceSyncScope: enforceSyncScope,
  enforceBundleBinding: enforceBundleBinding,
  enforceCertBinding: enforceCertBinding,
  enforceBundleOwnership: enforceBundleOwnership,
  enforceApiKeyResourceBinding: enforceApiKeyResourceBinding,
  peerCertFingerprintSha3: peerCertFingerprintSha3,
  requireSyncAuth: requireSyncAuth,
};
