// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * requireBoundKey middleware — Bearer-API-key auth with scope + bound-
 * fields + cert-fingerprint binding.
 *
 * The framework's bearer-auth + dpop + requireMtls cover JWT, DPoP, and
 * mTLS. requireBoundKey covers the API-key-with-binding case that
 * shows up on internal service-to-service endpoints, partner API
 * webhook receivers, and CI runners shipping events to a hosted
 * blamejs deployment:
 *
 *   - Authorization: Bearer <api-key>
 *   - the API key is registered in an operator-supplied resolver
 *     with: { scopes: [...], boundFields: { ... }, peerCertFingerprints: [...] }
 *   - the request must present a peer cert whose fingerprint is in
 *     peerCertFingerprints (when set)
 *   - the request must include the boundFields with the registered
 *     values (e.g. { tenantId: "acme", region: "us-east-1" }) — bound
 *     fields are pulled from headers / query / body via getter
 *   - the request must hold one of the operator-required scopes
 *
 * Failure mode: 401 / 403 with a structured JSON body identifying
 * which check failed (operator audit trail). Audits emit
 * `auth.require_bound_key.allowed` / `auth.require_bound_key.refused`
 * with the api-key-id (not the secret) + reason metadata.
 *
 *   var keys = b.middleware.requireBoundKey({
 *     resolver: async function (apiKey) {
 *       // operator-supplied — usually a DB lookup with timing-safe
 *       // compare. Returns { id, scopes, boundFields, peerCertFingerprints }
 *       // or null when the key is unknown / revoked.
 *       return await keyDb.findByKey(apiKey);
 *     },
 *     requiredScopes:    ["webhook.ingest"],
 *     getBoundField:     {
 *       tenantId: function (req) { return req.headers["x-tenant-id"]; },
 *       region:   function (req) { return req.query.region; },
 *     },
 *     audit:             b.audit,
 *   });
 *   router.post("/webhook/ingest", keys, ingestHandler);
 *
 * Composition with other middleware:
 *   - b.middleware.requireMtls runs FIRST (so req.peerCert is set)
 *   - b.middleware.requireBoundKey reads req.peerCert and cross-checks
 *
 * Defaults to fail-closed on every check; resolver throws / returns
 * undefined → refused with reason "resolver-unavailable".
 */

var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;

var bCrypto = lazyRequire(function () { return require("../crypto"); });
var audit  = lazyRequire(function () { return require("../audit"); });

var RequireBoundKeyError = defineClass("RequireBoundKeyError", { alwaysPermanent: true });

function _parseBearer(req) {
  var h = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (typeof h !== "string" || h.length === 0) return null;
  var m = h.match(/^Bearer\s+([\x21-\x7e]+)$/);                                          // RFC 6750 token68
  return m ? m[1] : null;
}

function _timingSafeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  return bCrypto().timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * @primitive b.middleware.requireBoundKey
 * @signature b.middleware.requireBoundKey(opts)
 * @since     0.1.0
 * @related   b.middleware.bearerAuth, b.middleware.requireMtls
 *
 * Bearer-API-key auth with scope + bound-fields + peer-cert
 * fingerprint binding. Covers the service-to-service /
 * partner-webhook / CI-runner case where a stable API key is
 * registered with `{ scopes, boundFields, peerCertFingerprints }`.
 * The middleware verifies the inbound `Bearer` token, checks
 * scopes against `requiredScopes`, pulls each bound field via
 * the operator-supplied `getBoundField[name](req)` and compares to
 * the registered value, and (when registered) compares the
 * peer-cert fingerprint to the allowlist. Fails closed on resolver
 * error / undefined return. Refuses with HTTP 401/403 + structured
 * JSON identifying which check failed; audits the api-key id (not
 * the secret) on every decision.
 *
 * @opts
 *   {
 *     resolver:                async function(apiKey): { id, scopes, boundFields, peerCertFingerprints } | null,  // required
 *     requiredScopes:          string[],
 *     getBoundField:           Record<string, function(req): string|null>,
 *     tolerateMissingPeerCert: boolean,
 *     errorMessage:            string,
 *     auditAction:             string,
 *     audit:                   object,
 *     onDeny:                  function(req, res, info): void,  // own the refusal; info = { status, reason, ...metadata }
 *     problemDetails:          boolean,   // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/webhook", b.middleware.requireBoundKey({
 *     resolver: async function (apiKey) {
 *       if (apiKey === "valid-key") return { id: "k1", scopes: ["webhook.ingest"], boundFields: {} };
 *       return null;
 *     },
 *     requiredScopes: ["webhook.ingest"],
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "resolver", "requiredScopes", "getBoundField",
    "audit", "auditAction", "errorMessage",
    "tolerateMissingPeerCert", "onDeny", "problemDetails",
  ], "middleware.requireBoundKey");

  if (typeof opts.resolver !== "function") {
    throw new RequireBoundKeyError("require-bound-key/bad-resolver",
      "middleware.requireBoundKey: opts.resolver must be an async function (apiKey) -> {id, scopes, boundFields, peerCertFingerprints} | null");
  }
  var resolver = opts.resolver;
  var requiredScopes = Array.isArray(opts.requiredScopes) ? opts.requiredScopes.slice() : [];
  for (var rs = 0; rs < requiredScopes.length; rs++) {
    if (typeof requiredScopes[rs] !== "string" || requiredScopes[rs].length === 0) {
      throw new RequireBoundKeyError("require-bound-key/bad-scope",
        "middleware.requireBoundKey: requiredScopes[" + rs + "] must be a non-empty string");
    }
  }
  var getBoundField = (opts.getBoundField && typeof opts.getBoundField === "object")
    ? opts.getBoundField : {};
  var boundFieldNames = Object.keys(getBoundField);
  for (var bf = 0; bf < boundFieldNames.length; bf++) {
    if (typeof getBoundField[boundFieldNames[bf]] !== "function") {
      throw new RequireBoundKeyError("require-bound-key/bad-bound-field-getter",
        "middleware.requireBoundKey: getBoundField." + boundFieldNames[bf] + " must be a function (req) -> string");
    }
  }
  var auditOn = opts.audit !== false;
  var actionBase = typeof opts.auditAction === "string" && opts.auditAction.length > 0
    ? opts.auditAction : "auth.require_bound_key";
  var errorMessage = typeof opts.errorMessage === "string" && opts.errorMessage.length > 0
    ? opts.errorMessage : "api key required";
  // For operator-side fixtures and dev environments without an mTLS
  // termination layer, allow disabling the peer-cert cross-check
  // even when peerCertFingerprints is set on the registered key.
  // Production deployments leave this at default false.
  var tolerateMissingPeerCert = !!opts.tolerateMissingPeerCert;
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  function _emitAudit(outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   actionBase + (outcome === "success" ? ".allowed" : ".refused"),
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  // RFC 6750 §3 — the Bearer challenge carries an error code that
  // matches the failure: 401 with no token presented omits the code
  // entirely; an unknown / revoked token is `invalid_token`; a 403
  // missing-scope is `insufficient_scope`; a malformed bound-field
  // request is `invalid_request`. Server-side failures (500 / 503)
  // are not authentication challenges, so they advertise the scheme
  // without an (incorrect) auth-error code.
  function _bearerChallenge(status, reason) {
    if (status === 401) {
      if (reason === "no-bearer-token") return 'Bearer realm="api"';
      return 'Bearer realm="api", error="invalid_token"';
    }
    if (status === 403) return 'Bearer realm="api", error="insufficient_scope"';
    if (status === 400) return 'Bearer realm="api", error="invalid_request"';   // HTTP 400
    return 'Bearer realm="api"';
  }

  function _refuse(req, res, status, reason, metadata) {
    _emitAudit("denied", Object.assign({ reason: reason }, metadata || {}));
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        status,
      info:          Object.assign({ status: status, reason: reason }, metadata || {}),
      problemCode:   "bound-key-refused",
      problemTitle:  errorMessage,
      problemDetail: "API key authentication failed: " + reason + ".",
      problemExt:    { reason: reason },
      headers:       {
        "WWW-Authenticate": _bearerChallenge(status, reason),
        "Cache-Control":    "no-store",
      },
      contentType:   "application/json; charset=utf-8",
      body:          JSON.stringify({ error: errorMessage, reason: reason }),
    });
  }

  return async function requireBoundKeyMiddleware(req, res, next) {
    var apiKey = _parseBearer(req);
    if (!apiKey) return _refuse(req, res, 401, "no-bearer-token", {});

    var record;
    try { record = await resolver(apiKey); }
    catch (e) {
      return _refuse(req, res, 503, "resolver-unavailable", {
        error: (e && e.message) || String(e),
      });
    }
    if (!record || typeof record !== "object") {
      return _refuse(req, res, 401, "key-unknown-or-revoked", {});
    }

    // Required-scope check — operator-supplied requiredScopes must be
    // a subset of the registered key's scopes.
    var keyScopes = Array.isArray(record.scopes) ? record.scopes : [];
    for (var rsi = 0; rsi < requiredScopes.length; rsi++) {
      if (keyScopes.indexOf(requiredScopes[rsi]) === -1) {
        return _refuse(req, res, 403, "missing-scope", {
          requiredScope: requiredScopes[rsi], keyId: record.id || null,
        });
      }
    }

    // Bound-field check — every key in the registered boundFields map
    // must be present on the request and match. The operator's
    // getBoundField extracts each value from headers / query / body.
    var registered = (record.boundFields && typeof record.boundFields === "object") ? record.boundFields : {};
    var registeredKeys = Object.keys(registered);
    for (var bfi = 0; bfi < registeredKeys.length; bfi++) {
      var fieldName = registeredKeys[bfi];
      var getter = getBoundField[fieldName];
      if (!getter) {
        return _refuse(req, res, 500, "bound-field-no-getter", {
          field: fieldName, keyId: record.id || null,
        });
      }
      var presented;
      try { presented = getter(req); }
      catch (e) {
        return _refuse(req, res, 400, "bound-field-getter-threw", {                            // HTTP 400
          field: fieldName, error: (e && e.message) || String(e),
        });
      }
      if (typeof presented !== "string" || presented.length === 0) {
        return _refuse(req, res, 400, "bound-field-missing", {                                 // HTTP 400
          field: fieldName, keyId: record.id || null,
        });
      }
      var expected = String(registered[fieldName]);
      if (!_timingSafeStringEqual(presented, expected)) {
        return _refuse(req, res, 403, "bound-field-mismatch", {
          field: fieldName, keyId: record.id || null,
        });
      }
    }

    // Peer-cert fingerprint check — if the registered key pins peer
    // certs, the request must come over mTLS with a fingerprint on
    // the allowlist. b.middleware.requireMtls running upstream
    // attaches req.peerCert / req.peerFingerprint; we re-derive when
    // a downstream middleware order leaves them unset.
    var pinned = Array.isArray(record.peerCertFingerprints) ? record.peerCertFingerprints : [];
    if (pinned.length > 0) {
      var fpHex = req.peerFingerprint && req.peerFingerprint.hex;
      var fpColon = req.peerFingerprint && req.peerFingerprint.colon;
      if (!fpHex && req.peerCert && req.peerCert.raw) {
        try {
          var fp = bCrypto().hashCertFingerprint(req.peerCert.raw);
          fpHex = fp.hex; fpColon = fp.colon;
        } catch (_e) { /* fall through to refused below */ }
      }
      if (!fpHex) {
        if (tolerateMissingPeerCert) {
          // Audited bypass for dev fixtures.
          _emitAudit("denied", { reason: "peer-cert-bypass-tolerated", keyId: record.id });
        } else {
          return _refuse(req, res, 401, "peer-cert-required", {
            keyId: record.id || null,
          });
        }
      } else if (!(req.peerCert && req.peerCert.raw) || !bCrypto().isCertRevoked(req.peerCert.raw, pinned)) {
        // isCertRevoked returns true on MATCH against the deny-list
        // shape; we use it here as a fingerprint-set membership test
        // because it does the same constant-time hex/colon comparison
        // we want for an allow-list. A future refactor can rename to
        // isCertFingerprintInSet — semantically identical.
        return _refuse(req, res, 403, "peer-cert-not-pinned", {
          fingerprint: fpColon, keyId: record.id || null,
        });
      }
    }

    // All checks passed. Attach the resolved record to req.apiKey for
    // downstream handlers (without the secret — the resolver returned
    // a normalized record, the middleware never re-exposes the bearer).
    req.apiKey = {
      id:           record.id || null,
      scopes:       keyScopes.slice(),
      boundFields:  Object.assign({}, registered),
    };
    _emitAudit("success", {
      keyId:         record.id || null,
      scopesGranted: keyScopes,
    });
    return next();
  };
}

module.exports = {
  create:               create,
  RequireBoundKeyError: RequireBoundKeyError,
};
