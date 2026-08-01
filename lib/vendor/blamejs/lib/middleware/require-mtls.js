// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var nodeCrypto = require("node:crypto");
var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;

var bCrypto = lazyRequire(function () { return require("../crypto"); });
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

/**
 * @primitive b.middleware.requireMtls
 * @signature b.middleware.requireMtls(opts)
 * @since     0.1.0
 * @related   b.middleware.requireBoundKey, b.middleware.bearerAuth
 *
 * Soft-enforcement gate for routes that require an authenticated
 * client certificate. Refuses with HTTP 401 when no peer cert is
 * presented, when the TLS layer marks `req.client.authorized ===
 * false`, when the SHA3-512 fingerprint isn't on the operator
 * allowlist, when it appears on the denylist, or when a
 * `revocationSource` reports it revoked. Allowlist of
 * null / empty means "any peer cert authorized at the TLS layer
 * is fine"; non-empty allowlist additionally requires fingerprint
 * match. Pair with `b.app({ tlsOptions: { requestCert: true, ca:
 * [...] } })` so the TLS layer captures the client cert.
 *
 * Pass `revocationSource: caHandle` (a `b.mtlsCa` handle, or any
 * `{ isRevoked(fingerprintHex) }` object) to enforce the CA's live
 * revocation registry at the gate — `revoke()` and `revokeGeneration()`
 * take effect without mirroring the registry into `denyList`, and the
 * check is CA-generation-independent (fingerprint-keyed). The lookup
 * fails closed: a source that throws refuses the request.
 *
 * @opts
 *   {
 *     fingerprintAllowList: string[],
 *     denyList:             string[],
 *     revocationSource:     object,           // { isRevoked(fingerprintHex): boolean } — e.g. a b.mtlsCa handle; enforces revoke()/revokeGeneration() live (fail-closed)
 *     onAuthenticated:      function(req, res, next): void,
 *     onDeny:               function(req, res, info): void,  // own the refusal (mirrors onAuthenticated); info = { status, reason, ...metadata }
 *     problemDetails:       boolean,        // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *     auditAction:          string,
 *     errorMessage:         string,
 *     audit:                object,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/internal", b.middleware.requireMtls({
 *     fingerprintAllowList: ["AB:CD:EF:01:23:45"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "fingerprintAllowList", "denyList", "revocationSource",
    "onAuthenticated", "onDeny", "problemDetails", "audit",
    "auditAction", "errorMessage",
  ], "middleware.requireMtls");

  var allowList = Array.isArray(opts.fingerprintAllowList)
    ? opts.fingerprintAllowList.map(_normalizeFingerprintEntry) : null;
  var denyList = Array.isArray(opts.denyList)
    ? opts.denyList.map(_normalizeFingerprintEntry) : [];
  // Live revocation source — any object exposing isRevoked(fingerprintHex),
  // e.g. a b.mtlsCa handle. The static denyList catches a fixed set; this makes
  // the CA's revocation registry (revoke() / revokeGeneration()) enforced at the
  // gate WITHOUT the operator mirroring it into denyList, and it is CA-generation
  // -independent (fingerprint-keyed), so revoking a superseded generation is
  // honored even though a CRL signed by the new CA could not cover the old cohort.
  // Only omission (undefined) or an explicit null means "no source". A falsy
  // non-object (false, 0, "" from a mis-derived env var) is NOT silently
  // dropped via `|| null` — it flows into validation so invalid security
  // configuration fails at construction instead of quietly disabling the check.
  var revocationSource = (opts.revocationSource === undefined || opts.revocationSource === null)
    ? null : opts.revocationSource;
  if (revocationSource !== null) {
    validateOpts.requireMethods(revocationSource, ["isRevoked"],
      "requireMtls: opts.revocationSource", RequireMtlsError, "require-mtls/bad-revocation-source");
  }
  var onAuthenticated = typeof opts.onAuthenticated === "function" ? opts.onAuthenticated : null;
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
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

  function _refuse(req, res, reason, metadata) {
    _emit("denied", Object.assign({ reason: reason }, metadata || {}));
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        401,
      info:          Object.assign({ status: 401, reason: reason }, metadata || {}),
      problemCode:   "client-certificate-required",
      problemTitle:  "Unauthorized",
      problemDetail: errorMessage,
      problemExt:    { reason: reason },
      headers:       {
        "WWW-Authenticate": "Mutual",
        "Cache-Control":    "no-store",
      },
      contentType:   "application/json; charset=utf-8",
      body:          JSON.stringify({ error: errorMessage, reason: reason }),
    });
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
      return _refuse(req, res, "tls-unauthorized", { authorizationError: String(authzError) });
    }
    if (!peerCert || !peerCert.raw) {
      return _refuse(req, res, "no-peer-cert", {});
    }

    // Compute fingerprint via the framework's SHA3-512 helper. Buffer
    // form: peerCert.raw is the DER. Hex/colon both available for
    // allow/deny matching.
    var fp;
    try {
      fp = bCrypto().hashCertFingerprint(peerCert.raw);
    } catch (e) {
      return _refuse(req, res, "fingerprint-failed", { error: (e && e.message) || String(e) });
    }

    if (denyList.length > 0 && bCrypto().isCertRevoked(peerCert.raw, denyList)) {
      return _refuse(req, res, "fingerprint-on-deny-list", {
        fingerprint: fp.colon,
        subject:     (peerCert.subject && peerCert.subject.CN) || null,
      });
    }
    // Live revocation registry (e.g. a b.mtlsCa handle). Fail CLOSED: a source
    // that throws denies rather than silently admitting a possibly-revoked cert.
    // Checked before the allow-list so a revoked-but-allowlisted cert is denied.
    if (revocationSource) {
      var revoked;
      try {
        // The revocationSource contract is a SYNCHRONOUS boolean. A non-boolean result — a Promise
        // from an async / DB-backed source, undefined, or any other garbage — is NEVER === true, so
        // silently treating it as not-revoked would ADMIT a possibly-revoked peer. This gate is
        // documented fail-CLOSED, so refuse the request on any non-boolean result (front an async
        // source with a synchronous cache).
        var byFp = revocationSource.isRevoked(fp.hex);
        if (typeof byFp !== "boolean") {
          return _refuse(req, res, "revocation-source-invalid",
            { method: "isRevoked", type: (byFp === null ? "null" : typeof byFp) });
        }
        revoked = byFp;
        // A revoke(serial) / serial-only entry carries fingerprint:null and can't
        // match by fingerprint. Check the peer certificate's serial number ONLY
        // when the source opts in with isSerialRevoked() — a documented
        // fingerprint-only isRevoked(fingerprintHex) that strictly length-validates
        // its input would throw on a shorter serial and fail-close every request.
        // A b.mtlsCa handle exposes isSerialRevoked. When serial enforcement is enabled the serial MUST
        // be checkable: a cert whose serial cannot be extracted (raw unparseable — e.g. prevalidated by
        // a TLS-terminating proxy, or an algorithm the local X.509 parser rejects) cannot be cleared
        // against the serial-only revoke(serial) path, so admitting it would break the fail-closed
        // contract. Refuse rather than silently skip the lookup.
        if (!revoked && typeof revocationSource.isSerialRevoked === "function") {
          var serial = null;
          try { serial = new nodeCrypto.X509Certificate(peerCert.raw).serialNumber; }
          catch (_se) { serial = null; }
          if (!serial) {
            return _refuse(req, res, "serial-unresolved",
              { detail: "certificate serial could not be extracted for the serial-revocation check" });
          }
          var bySerial = revocationSource.isSerialRevoked(serial);
          if (typeof bySerial !== "boolean") {
            return _refuse(req, res, "revocation-source-invalid",
              { method: "isSerialRevoked", type: (bySerial === null ? "null" : typeof bySerial) });
          }
          revoked = bySerial;
        }
      } catch (e) { return _refuse(req, res, "revocation-check-failed", { error: (e && e.message) || String(e) }); }
      if (revoked) {
        return _refuse(req, res, "fingerprint-revoked", {
          fingerprint: fp.colon,
          subject:     (peerCert.subject && peerCert.subject.CN) || null,
        });
      }
    }
    if (allowList && allowList.length > 0 && !bCrypto().isCertRevoked(peerCert.raw, allowList)) {
      return _refuse(req, res, "fingerprint-not-allowed", {
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
        return _refuse(req, res, "on-authenticated-threw", { error: (e && e.message) || String(e) });
      }
    }
    return next();
  };
}

module.exports = {
  create:           create,
  RequireMtlsError: RequireMtlsError,
};
