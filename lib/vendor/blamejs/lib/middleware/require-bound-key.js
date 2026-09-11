// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
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
  var m = h.match(/^Bearer\s+([\x21-\x7e]+)$/);
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

  function _bearerChallenge(status, reason) {
    if (status === C.HTTP.STATUS.UNAUTHORIZED) {
      if (reason === "no-bearer-token") return 'Bearer realm="api"';
      return 'Bearer realm="api", error="invalid_token"';
    }
    if (status === C.HTTP.STATUS.FORBIDDEN) return 'Bearer realm="api", error="insufficient_scope"';
    if (status === C.HTTP.STATUS.BAD_REQUEST) return 'Bearer realm="api", error="invalid_request"';
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

    var keyScopes = Array.isArray(record.scopes) ? record.scopes : [];
    for (var rsi = 0; rsi < requiredScopes.length; rsi++) {
      if (keyScopes.indexOf(requiredScopes[rsi]) === -1) {
        return _refuse(req, res, 403, "missing-scope", {
          requiredScope: requiredScopes[rsi], keyId: record.id || null,
        });
      }
    }

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
        return _refuse(req, res, 400, "bound-field-getter-threw", {
          field: fieldName, error: (e && e.message) || String(e),
        });
      }
      if (typeof presented !== "string" || presented.length === 0) {
        return _refuse(req, res, 400, "bound-field-missing", {
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
          _emitAudit("denied", { reason: "peer-cert-bypass-tolerated", keyId: record.id });
        } else {
          return _refuse(req, res, 401, "peer-cert-required", {
            keyId: record.id || null,
          });
        }
      } else if (!(req.peerCert && req.peerCert.raw) || !bCrypto().isCertRevoked(req.peerCert.raw, pinned)) {
        return _refuse(req, res, 403, "peer-cert-not-pinned", {
          fingerprint: fpColon, keyId: record.id || null,
        });
      }
    }

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
