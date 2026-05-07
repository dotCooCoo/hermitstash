"use strict";
/**
 * requireMtls middleware — soft-enforcement gate for routes that
 * require a client certificate.
 *
 * Operators terminate TLS at the framework's HTTPS server with
 * `requestCert: true` (the framework already wires this when
 * `b.app({ tlsOptions: { requestCert: true, ca: [...] } })` is
 * configured). For routes that MUST receive an authenticated peer
 * cert — e.g. the inbound side of an mTLS service mesh, OAuth 2.0
 * mTLS Client Authentication (RFC 8705), or operator-specific
 * service-to-service endpoints — wire this middleware in front of
 * the route to reject any request that didn't present a valid
 * client cert.
 *
 *   var requireMtls = b.middleware.requireMtls({
 *     fingerprintAllowList: [
 *       "AB:CD:EF:...",                 // colon-separated SHA3-512 hex
 *     ],
 *     denyList:             [],          // explicit revocations
 *     onAuthenticated:      function (req, res, next) {
 *       req.peerSubject = req.peerCert.subject;
 *       next();
 *     },
 *     audit:                b.audit,
 *   });
 *   router.use("/internal", requireMtls);
 *
 * Failure modes (all reject 401):
 *   - No peer cert presented (client did not negotiate mTLS)
 *   - Peer cert present but unauthorized at TLS layer
 *     (req.client.authorized === false)
 *   - Fingerprint not on the operator-supplied allow-list
 *   - Fingerprint on the operator-supplied deny-list
 *
 * Audit shape (when audit is wired): emits `mtls.required.allowed`
 * (success) or `mtls.required.refused` (denied) with the peer-cert
 * fingerprint + subject + reason in metadata. Drop-silent if no
 * audit is wired.
 *
 * The fingerprint allow / deny comparison routes through
 * b.crypto.isCertRevoked — both forms (lowercase hex / uppercase
 * colon-separated) match. Allow-list of empty / null = "any
 * peer cert authorized at the TLS layer"; specifying a non-empty
 * allow-list ALSO requires the fingerprint to match.
 */

var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");

var crypto = lazyRequire(function () { return require("../crypto"); });
var audit  = lazyRequire(function () { return require("../audit"); });

var RequireMtlsError = defineClass("RequireMtlsError", { alwaysPermanent: true });

function _normalizeFingerprintEntry(entry) {
  if (typeof entry !== "string" || entry.length === 0) {
    throw new RequireMtlsError("require-mtls/bad-fingerprint",
      "fingerprint allow/deny entries must be non-empty strings " +
      "(SHA3-512 hex or colon-separated form)");
  }
  return entry;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "fingerprintAllowList", "denyList",
    "onAuthenticated", "audit",
    "auditAction", "errorMessage",
  ], "middleware.requireMtls");

  var allowList = Array.isArray(opts.fingerprintAllowList)
    ? opts.fingerprintAllowList.map(_normalizeFingerprintEntry) : null;
  var denyList = Array.isArray(opts.denyList)
    ? opts.denyList.map(_normalizeFingerprintEntry) : [];
  var onAuthenticated = typeof opts.onAuthenticated === "function" ? opts.onAuthenticated : null;
  var auditOn  = opts.audit !== false;
  var actionBase = typeof opts.auditAction === "string" && opts.auditAction.length > 0
    ? opts.auditAction : "mtls.required";
  var errorMessage = typeof opts.errorMessage === "string" && opts.errorMessage.length > 0
    ? opts.errorMessage : "client certificate required";

  function _emit(outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   actionBase + (outcome === "success" ? ".allowed" : ".refused"),
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit is best-effort, never blocks the request */ }
  }

  function _refuse(res, reason, metadata) {
    _emit("denied", Object.assign({ reason: reason }, metadata || {}));
    if (typeof res.writeHead === "function") {
      res.writeHead(401, {
        "Content-Type":     "application/json; charset=utf-8",
        "WWW-Authenticate": "Mutual",
        "Cache-Control":    "no-store",
      });
      res.end(JSON.stringify({ error: errorMessage, reason: reason }));
    }
  }

  return function requireMtlsMiddleware(req, res, next) {
    // Node's TLSSocket exposes:
    //   req.client.authorized           — boolean, peer cert chain valid
    //   req.client.authorizationError   — string when authorized=false
    //   req.socket.getPeerCertificate() — the cert (raw + parsed fields)
    // Behind a TLS-terminating proxy (e.g. nginx, envoy) operators
    // pass the peer cert as a header (X-Client-Cert) and pre-populate
    // req.peerCert before this middleware fires. We don't inject a
    // proxy-header parser here — that's an operator-side decision tied
    // to the chosen proxy's signing model.
    var sock = req.socket || req.connection || null;
    var authorized = sock && sock.authorized === true;
    var peerCert = req.peerCert || null;
    if (!peerCert && sock && typeof sock.getPeerCertificate === "function") {
      try { peerCert = sock.getPeerCertificate(true) || null; }
      catch (_e) { peerCert = null; }
    }

    if (!authorized) {
      var authzError = (sock && sock.authorizationError) || "no-peer-cert";
      return _refuse(res, "tls-unauthorized", { authorizationError: String(authzError) });
    }
    if (!peerCert || !peerCert.raw) {
      return _refuse(res, "no-peer-cert", {});
    }

    // Compute fingerprint via the framework's SHA3-512 helper. Buffer
    // form: peerCert.raw is the DER. Hex/colon both available for
    // allow/deny matching.
    var fp;
    try {
      fp = crypto().hashCertFingerprint(peerCert.raw);
    } catch (e) {
      return _refuse(res, "fingerprint-failed", { error: (e && e.message) || String(e) });
    }

    if (denyList.length > 0 && crypto().isCertRevoked(peerCert.raw, denyList)) {
      return _refuse(res, "fingerprint-on-deny-list", {
        fingerprint: fp.colon,
        subject:     (peerCert.subject && peerCert.subject.CN) || null,
      });
    }
    if (allowList && allowList.length > 0 && !crypto().isCertRevoked(peerCert.raw, allowList)) {
      return _refuse(res, "fingerprint-not-allowed", {
        fingerprint: fp.colon,
        subject:     (peerCert.subject && peerCert.subject.CN) || null,
      });
    }

    // Authenticated — attach the parsed peer cert + fingerprint to
    // the request so downstream handlers don't have to re-parse, then
    // emit success and call next (or operator's onAuthenticated hook).
    req.peerCert        = peerCert;
    req.peerFingerprint = fp;
    _emit("success", {
      fingerprint: fp.colon,
      subject:     (peerCert.subject && peerCert.subject.CN) || null,
    });
    if (onAuthenticated) {
      try { return onAuthenticated(req, res, next); }
      catch (e) {
        return _refuse(res, "on-authenticated-threw", { error: (e && e.message) || String(e) });
      }
    }
    return next();
  };
}

module.exports = {
  create:           create,
  RequireMtlsError: RequireMtlsError,
};
