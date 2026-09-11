// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var bCrypto = require("../crypto");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { AuthError } = require("../framework-error");

var dpop = lazyRequire(function () { return require("../auth/dpop"); });
var audit = lazyRequire(function () { return require("../audit"); });

var DPOP_NONCE_BYTES = C.BYTES.bytes(24);

function _writeUnauthorized(req, res, errorCode, description, freshNonce, onDeny, problemMode) {
  var body = JSON.stringify({ error: errorCode, error_description: description });
  var challenge = 'DPoP error="' + errorCode + '", error_description="' +
                  description.replace(/"/g, "'") + '"';
  var headers = {
    "WWW-Authenticate": challenge,
  };
  if (freshNonce) headers["DPoP-Nonce"] = freshNonce;
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        C.HTTP.STATUS.UNAUTHORIZED,
    info:          { status: C.HTTP.STATUS.UNAUTHORIZED, reason: errorCode, error_description: description },
    problemCode:   "dpop-" + errorCode.replace(/_/g, "-"),
    problemTitle:  "Unauthorized",
    problemDetail: description,
    problemExt:    { error: errorCode, error_description: description },
    headers:       headers,
    contentType:   "application/json; charset=utf-8",
    body:          body,
  });
}

function _nonceManager(rotateSec) {
  var rotateMs = C.TIME.seconds(rotateSec);
  var current = null;
  var previous = null;
  var shutdown = false;
  function _fresh() {
    return {
      nonce:    bCrypto.generateBytes(DPOP_NONCE_BYTES).toString("base64url"),
      issuedAt: Date.now(),
    };
  }
  function _maybeRotate() {
    var now = Date.now();
    if (current === null) {
      current = _fresh();
      return;
    }
    if (now - current.issuedAt >= rotateMs) {
      previous = current;
      current = _fresh();
    }
  }
  return {
    issue: function () {
      if (shutdown) return null;
      _maybeRotate();
      return current.nonce;
    },
    accepts: function (n) {
      if (shutdown) return false;
      _maybeRotate();
      if (typeof n !== "string" || n.length === 0) return false;
      var accepted = [];
      if (current) accepted.push(current.nonce);
      if (previous) accepted.push(previous.nonce);
      return bCrypto.timingSafeEqualAny(n, accepted);
    },
    shutdown: function () { shutdown = true; current = null; previous = null; },
    revoke: function () {
      previous = null;
      current  = _fresh();
    },
    _state: function () {
      return {
        shutdown: shutdown,
        current:  current ? current.nonce : null,
        previous: previous ? previous.nonce : null,
      };
    },
  };
}

function _reconstructHtu(req, protoResolver, hostResolver) {
  if (!req || !req.headers) return null;
  var proto = protoResolver.resolve(req);
  var host = hostResolver.resolve(req);
  if (!host) return null;
  var path = req.url || "/";
  var qIdx = path.indexOf("?");
  if (qIdx !== -1) path = path.slice(0, qIdx);
  var hIdx = path.indexOf("#");
  if (hIdx !== -1) path = path.slice(0, hIdx);
  return proto + "://" + host + path;
}

/**
 * @primitive b.middleware.dpop
 * @signature b.middleware.dpop(opts)
 * @since     0.1.0
 * @related   b.middleware.bearerAuth
 *
 * RFC 9449 Demonstrating Proof of Possession (DPoP). Verifies the
 * `DPoP` header on inbound requests, attaches `req.dpop = { header,
 * payload, jkt }` for downstream handlers to bind to the access
 * token's `cnf.jkt` claim, and refuses with HTTP 401 +
 * `WWW-Authenticate: DPoP error="invalid_dpop_proof"` on any
 * failure. Replay store enforces single-use proofs within
 * `iatWindowSec`. Optional server-issued nonce (RFC 9449 §8) with
 * `requireNonce: true` rotates a current/previous pair lazily so
 * in-flight clients aren't kicked off at rotation. Algorithm
 * allowlist defaults to ES256 / EdDSA / ML-DSA-87 (PQC-first).
 *
 * @opts
 *   {
 *     replayStore:    object,                      // required
 *     algorithms:     string[],                    // default ES256/EdDSA/ML-DSA-87
 *     iatWindowSec:   number,                      // default 60
 *     getAccessToken: function(req): string|null,
 *     getNonce:       async function(req): string|null,
 *     getHtu:         function(req): string,
 *     trustedProxies: string|string[],             // CIDRs of your reverse proxies — peer-gates X-Forwarded-Proto + X-Forwarded-Host for htu reconstruction
 *     protocolResolver: function(req): "http"|"https",  // own the scheme decision
 *     hostResolver:   function(req): string|null,  // own the authority decision
 *     nonceStore:     object,
 *     nonceWindowSec: number,
 *     nonceRotateSec: number,
 *     requireNonce:   boolean,
 *     audit:          boolean,                      // default true
 *     onDeny:         function(req, res, info): void,  // own the 401; info = { status, reason, error_description }
 *     problemDetails: boolean,                      // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/api", b.middleware.dpop({
 *     replayStore:  b.nonceStore.create({ backend: "memory" }),
 *     iatWindowSec: 60,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "replayStore", "algorithms", "iatWindowSec",
    "getAccessToken", "getNonce", "getHtu", "audit",
    "nonceStore", "nonceWindowSec", "nonceRotateSec", "requireNonce",
    "trustedProxies", "protocolResolver", "hostResolver",
    "trustForwardedHeaders", "onDeny", "problemDetails",
  ], "middleware.dpop");

  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var auditOn = opts.audit !== false;
  var algorithms = opts.algorithms;
  var iatWindowSec = opts.iatWindowSec;
  validateOpts.requireMethods(opts.replayStore, ["checkAndInsert"],
    "middleware.dpop: opts.replayStore", AuthError, "auth-dpop/replay-store-required");
  var replayStore = opts.replayStore;
  var requireNonce = opts.requireNonce === true;

  var nonceMgr = null;
  if (requireNonce) {
    validateOpts.optionalPositiveFinite(opts.nonceRotateSec,
      "middleware.dpop: nonceRotateSec", AuthError, "auth-dpop/bad-opt");
    var rotateSec = opts.nonceRotateSec || (C.TIME.minutes(5) / C.TIME.seconds(1));
    nonceMgr = _nonceManager(rotateSec);
  }
  if (opts.nonceStore !== undefined) {
    throw new AuthError("auth-dpop/bad-opt",
      "middleware.dpop: opts.nonceStore is not supported — use { requireNonce: true, nonceRotateSec? }; the rolling-pair manager is internal");
  }
  if (opts.nonceWindowSec !== undefined) {
    throw new AuthError("auth-dpop/bad-opt",
      "middleware.dpop: opts.nonceWindowSec is not supported — use nonceRotateSec");
  }

  validateOpts.optionalFunction(opts.getAccessToken,
    "middleware.dpop: getAccessToken", AuthError, "auth-dpop/bad-opt");
  validateOpts.optionalFunction(opts.getNonce,
    "middleware.dpop: getNonce", AuthError, "auth-dpop/bad-opt");
  validateOpts.optionalFunction(opts.getHtu,
    "middleware.dpop: getHtu", AuthError, "auth-dpop/bad-opt");

  var _proto = requestHelpers.trustedProtocol({
    trustedProxies:   opts.trustedProxies,
    protocolResolver: opts.protocolResolver,
  });
  var _host = requestHelpers.trustedHost({
    trustedProxies: opts.trustedProxies,
    hostResolver:   opts.hostResolver,
  });
  if (typeof opts.getHtu !== "function" && opts.trustForwardedHeaders === true && !_proto.peerGated) {
    throw new AuthError("auth-dpop/bad-opt",
      "middleware.dpop: trustForwardedHeaders is spoofable for the htu reconstruction " +
      "(a direct caller can forge X-Forwarded-Proto / X-Forwarded-Host) and is no longer " +
      "honored on its own. Declare your reverse proxies via trustedProxies: [\"10.0.0.0/8\", …] " +
      "(peer-gates X-Forwarded-Proto + X-Forwarded-Host), or own the decision via " +
      "protocolResolver(req) / hostResolver(req) / getHtu(req).");
  }

  function _freshNonce() { return nonceMgr ? nonceMgr.issue() : null; }

  var middleware = async function dpopMiddleware(req, res, next) {
    var proofHeader = req.headers && req.headers.dpop;
    if (Array.isArray(proofHeader)) {
      return _writeUnauthorized(req, res, "invalid_dpop_proof",
        "multiple DPoP headers are not allowed", null, onDeny, problemMode);
    }
    if (typeof proofHeader !== "string" || proofHeader.length === 0) {
      return _writeUnauthorized(req, res,
        nonceMgr ? "use_dpop_nonce" : "invalid_dpop_proof",
        "DPoP header required", _freshNonce(), onDeny, problemMode);
    }
    if (proofHeader.indexOf(",") !== -1) {
      return _writeUnauthorized(req, res, "invalid_dpop_proof",
        "multiple DPoP proofs in one header value are not allowed", null, onDeny, problemMode);
    }

    var htu = (typeof opts.getHtu === "function" ? opts.getHtu(req) : _reconstructHtu(req, _proto, _host));
    if (!htu) {
      return _writeUnauthorized(req, res, "invalid_dpop_proof", "could not reconstruct htu", null, onDeny, problemMode);
    }
    var htm = (req.method || "").toUpperCase();

    var accessToken = null;
    if (typeof opts.getAccessToken === "function") {
      try { accessToken = await opts.getAccessToken(req); }
      catch (_e) { accessToken = null; }
    }
    var nonce = null;
    if (typeof opts.getNonce === "function") {
      try { nonce = await opts.getNonce(req); }
      catch (_e) { nonce = null; }
    } else if (nonceMgr) {
      nonce = null;
    }

    var verifyOpts = { htm: htm, htu: htu };
    if (algorithms) verifyOpts.algorithms = algorithms;
    if (iatWindowSec !== undefined) verifyOpts.iatWindowSec = iatWindowSec;
    if (accessToken) verifyOpts.accessToken = accessToken;
    if (nonce) verifyOpts.nonce = nonce;
    verifyOpts.replayStore = replayStore;

    var result;
    try { result = await dpop().verify(proofHeader, verifyOpts); }
    catch (e) {
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "auth.bearer.failure",
            actor:   { clientIp: requestHelpers.clientIp(req) },
            outcome: "failure",
            metadata: {
              method: "dpop",
              reason: (e && e.code) || "verify-failed",
              route:  req.url,
            },
          });
        } catch (_ignored) { /* drop-silent — observability sink failure */ }
      }
      var errorCode = "invalid_dpop_proof";
      if (e && (e.code === "auth-dpop/missing-nonce" || e.code === "auth-dpop/nonce-mismatch")) {
        errorCode = "use_dpop_nonce";
      }
      return _writeUnauthorized(req, res, errorCode,
        (e && e.message) || "DPoP proof verification failed",
        _freshNonce(), onDeny, problemMode);
    }

    if (nonceMgr) {
      var presented = result.payload && result.payload.nonce;
      if (typeof presented !== "string" || !nonceMgr.accepts(presented)) {
        if (auditOn) {
          try {
            audit().safeEmit({
              action:  "auth.bearer.failure",
              actor:   { clientIp: requestHelpers.clientIp(req) },
              outcome: "failure",
              metadata: { method: "dpop", reason: "stale-nonce", route: req.url },
            });
          } catch (_ignored) { /* drop-silent */ }
        }
        return _writeUnauthorized(req, res, "use_dpop_nonce",
          "DPoP-Nonce required (server-managed challenge)", _freshNonce(), onDeny, problemMode);
      }
    }

    if (nonceMgr && !res.headersSent) {
      try { res.setHeader("DPoP-Nonce", _freshNonce()); }
      catch (_e) { /* drop-silent — header set best-effort */ }
    }

    req.dpop = result;
    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "auth.bearer.success",
          actor:   { clientIp: requestHelpers.clientIp(req) },
          outcome: "success",
          metadata: { method: "dpop", jkt: result.jkt, route: req.url },
        });
      } catch (_ignored) { /* drop-silent */ }
    }
    return next();
  };

  middleware.shutdown = function () { if (nonceMgr) nonceMgr.shutdown(); };
  middleware.revoke   = function () { if (nonceMgr) nonceMgr.revoke();   };
  return middleware;
}

module.exports = {
  create: create,
};
