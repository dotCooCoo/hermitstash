"use strict";
/**
 * dpop middleware — RFC 9449 Demonstrating Proof of Possession.
 *
 * Verifies the `DPoP` header on inbound requests, attaches the result
 * to `req.dpop = { header, payload, jkt }` for downstream handlers, and
 * rejects with 401 + `WWW-Authenticate: DPoP` on any failure.
 *
 *   var dpop = b.middleware.dpop({
 *     replayStore:    b.nonceStore.create({ backend: "memory" }),
 *     algorithms:     ["ES256", "EdDSA", "ML-DSA-87"],
 *     iatWindowSec:   60,
 *     getAccessToken: function (req) {
 *       // optional — extract Bearer token to bind ath
 *       var h = req.headers.authorization || "";
 *       return h.toLowerCase().startsWith("bearer ") ? h.slice(7) : null;
 *     },
 *     getNonce: async function (req) {
 *       // optional — server-issued challenge (RFC 9449 §8); return null
 *       // to skip nonce enforcement
 *       return null;
 *     },
 *     audit: true,
 *   });
 *   router.use("/api", dpop);
 *
 * On success:
 *   - req.dpop = { header, payload, jkt }
 *   - downstream handlers can compare req.dpop.jkt to the cnf claim
 *     of the access token to enforce key-bound bearer semantics
 *
 * On failure:
 *   - 401 with WWW-Authenticate: DPoP error="invalid_dpop_proof",
 *     error_description="<reason>"
 *   - audit.bearer.failure event when audit: true (default)
 */

var C = require("../constants");
var bCrypto = require("../crypto");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { AuthError } = require("../framework-error");

var dpop = lazyRequire(function () { return require("../auth/dpop"); });
var audit = lazyRequire(function () { return require("../audit"); });

// RFC 9449 §8 — server-issued nonce length (24 random bytes ≈ 192 bits
// of entropy after base64url, far above the spec's "unpredictable" bar).
var DPOP_NONCE_BYTES = C.BYTES.bytes(24);

function _writeUnauthorized(req, res, errorCode, description, freshNonce, onDeny, problemMode) {
  var body = JSON.stringify({ error: errorCode, error_description: description });
  // RFC 9449 §7 — error code is invalid_dpop_proof OR use_dpop_nonce.
  var challenge = 'DPoP error="' + errorCode + '", error_description="' +
                  description.replace(/"/g, "'") + '"';
  var headers = {
    "WWW-Authenticate": challenge,
  };
  if (freshNonce) headers["DPoP-Nonce"] = freshNonce;
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        401,                                                            // HTTP 401 status
    info:          { status: 401, reason: errorCode, error_description: description },
    problemCode:   "dpop-" + errorCode.replace(/_/g, "-"),
    problemTitle:  "Unauthorized",
    problemDetail: description,
    problemExt:    { error: errorCode, error_description: description },
    headers:       headers,
    contentType:   "application/json; charset=utf-8",
    body:          body,
  });
}

// RFC 9449 §8 — server-issued DPoP-Nonce challenge. The framework
// holds a rolling pair (current, previous) and rotates after
// rotateSec elapses. Both the current and previous values are
// accepted from clients; previous is needed to cover the brief
// race window after rotation when in-flight requests still carry
// the prior nonce. Rotation happens lazily on access; no timer.
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
      // Constant-time compare so server-issued nonce probing can't
      // narrow the rolling-pair bytes via response-timing — matches
      // the timingSafeEqual discipline on the DPoP-proof nonce.
      if (current && bCrypto.timingSafeEqual(n, current.nonce)) return true;
      if (previous && bCrypto.timingSafeEqual(n, previous.nonce)) return true;
      return false;
    },
    // Hot-reload coexistence. Operators redeploying without
    // a clean process restart need a way to drain in-flight clients
    // before swapping the middleware instance. shutdown() returns no
    // fresh nonces and refuses every presented nonce, so the
    // surrounding middleware emits 401 + use_dpop_nonce on the old
    // instance and the new instance owns the trust anchor cleanly.
    shutdown: function () { shutdown = true; current = null; previous = null; },
    // revoke() — rotate both rolling-pair slots, invalidating every
    // outstanding nonce immediately. Useful after a suspected nonce
    // leak. Distinct from shutdown(): the manager keeps serving fresh
    // nonces afterwards.
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
  // The proof's htu is the request URI WITHOUT query/fragment. Behind a
  // reverse proxy the operator may override via opts.getHtu. RFC 9449 §4.3
  // says htu MUST be the absolute URL the request was sent to — and it is
  // cryptographically bound in the proof, so a forged scheme/authority lets a
  // proof signed for one origin validate against another. proto + host are
  // resolved through the peer-gated requestHelpers resolvers built in create():
  // X-Forwarded-Proto / -Host are honored only from a declared trusted-proxy
  // peer; otherwise the real TLS socket scheme + the request's own Host are
  // used and forged forwarded headers are ignored.
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
    // htu reconstruction trust. trustedProxies (CIDRs) peer-gates
    // X-Forwarded-Proto + X-Forwarded-Host; protocolResolver/hostResolver let
    // the operator own each. trustForwardedHeaders (legacy boolean) is refused
    // on its own — see the peer-gating block below.
    "trustedProxies", "protocolResolver", "hostResolver",
    "trustForwardedHeaders", "onDeny", "problemDetails",
  ], "middleware.dpop");

  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var auditOn = opts.audit !== false;
  var algorithms = opts.algorithms;
  var iatWindowSec = opts.iatWindowSec;
  // replayStore is the jti-replay defense (RFC 9449 §11.1) — REQUIRED. Reading
  // it optionally and gating the check behind `if (replayStore)` would silently
  // mount a proof-of-possession gate that performs no replay check, letting a
  // captured proof replay indefinitely. Fail closed at config time: a missing
  // store and a store lacking checkAndInsert both throw here, not at the first
  // request. (The low-level b.auth.dpop.verify primitive keeps replayStore
  // optional for advanced callers that track jti themselves.)
  validateOpts.requireMethods(opts.replayStore, ["checkAndInsert"],
    "middleware.dpop: opts.replayStore", AuthError, "auth-dpop/replay-store-required");
  var replayStore = opts.replayStore;
  var requireNonce = opts.requireNonce === true;

  // Server-issued DPoP-Nonce challenge flow (RFC 9449 §8). When
  // requireNonce is true, the middleware refuses any proof that does
  // not carry a recognised nonce, and emits a fresh DPoP-Nonce
  // header on every 401 + as a refresh on every successful response.
  // The rolling-pair manager rotates without timers; no operator
  // store is needed.
  var nonceMgr = null;
  if (requireNonce) {
    validateOpts.optionalPositiveFinite(opts.nonceRotateSec,
      "middleware.dpop: nonceRotateSec", AuthError, "auth-dpop/bad-opt");
    var rotateSec = opts.nonceRotateSec || (C.TIME.minutes(5) / C.TIME.seconds(1));
    nonceMgr = _nonceManager(rotateSec);
  }
  // Reject the obsolete nonceStore opt with a clear migration message —
  // pre-v0.7.89 docs may surface it; the rolling-pair shape supersedes.
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

  // htu reconstruction (RFC 9449 §4.3) builds the absolute request URL —
  // proto + host — that the proof's cryptographically-bound `htu` claim is
  // verified against. Behind a proxy both come from forgeable X-Forwarded-*
  // headers, so resolve them through the peer-gated requestHelpers primitives
  // (the same fail-closed model csrf-protect / security-headers / cors use):
  // X-Forwarded-Proto / -Host are honored ONLY when the immediate peer is a
  // declared trusted proxy. The legacy trustForwardedHeaders:true trusted the
  // headers from ANY caller — a direct attacker could forge XFP:https / a
  // victim XFH to make a proof signed for one origin validate against another
  // (htu confusion). It is refused on its own; migrate to trustedProxies.
  var _proto = requestHelpers.trustedProtocol({
    trustedProxies:   opts.trustedProxies,
    protocolResolver: opts.protocolResolver,
  });
  var _host = requestHelpers.trustedHost({
    trustedProxies: opts.trustedProxies,
    hostResolver:   opts.hostResolver,
  });
  // Only refuse the spoofable legacy flag when the htu is actually
  // reconstructed from the request. When the operator supplies getHtu they own
  // the entire URI, _reconstructHtu (and the forwarded headers) is never
  // consulted, so a leftover trustForwardedHeaders is moot — don't fail
  // construction on it (the error text even offers getHtu as a migration path).
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
    if (typeof proofHeader !== "string" || proofHeader.length === 0) {
      return _writeUnauthorized(req, res,
        nonceMgr ? "use_dpop_nonce" : "invalid_dpop_proof",
        "DPoP header required", _freshNonce(), onDeny, problemMode);
    }
    // RFC 9449 §4.1 — only ONE DPoP header value per request.
    if (Array.isArray(proofHeader)) {
      return _writeUnauthorized(req, res, "invalid_dpop_proof",
        "multiple DPoP headers are not allowed", null, onDeny, problemMode);
    }
    // RFC 9449 §4.1 single-value invariant. node:http
    // collapses repeated headers into a comma-joined string when the
    // client ships `DPoP: proof1, DPoP: proof2`; the Array.isArray
    // check above catches the multi-value array shape but a
    // comma-joined string slips past. Refuse explicitly so a buggy /
    // hostile client can't smuggle two proofs past the verifier (the
    // verify() call below would only see the first one, leaving the
    // second unprocessed).
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
      // For server-managed nonces, verify() runs WITHOUT a strict
      // expected-nonce; we then check the payload's nonce against
      // our rolling-pair below. This lets us issue + rotate without
      // requiring a request-by-request operator callback.
      nonce = null;
    }

    var verifyOpts = { htm: htm, htu: htu };
    if (algorithms) verifyOpts.algorithms = algorithms;
    if (iatWindowSec !== undefined) verifyOpts.iatWindowSec = iatWindowSec;
    if (accessToken) verifyOpts.accessToken = accessToken;
    if (nonce) verifyOpts.nonce = nonce;
    verifyOpts.replayStore = replayStore;   // required at create() — always present

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
      // RFC 9449 §8 — when nonce is missing/invalid the server SHOULD use
      // use_dpop_nonce to signal the client to retry with a new nonce.
      if (e && (e.code === "auth-dpop/missing-nonce" || e.code === "auth-dpop/nonce-mismatch")) {
        errorCode = "use_dpop_nonce";
      }
      return _writeUnauthorized(req, res, errorCode,
        (e && e.message) || "DPoP proof verification failed",
        _freshNonce(), onDeny, problemMode);
    }

    // Server-managed nonce check — payload MUST carry a recognized
    // rolling-pair nonce. Missing or stale → 401 + DPoP-Nonce.
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

    // Refresh the nonce on every successful response so the client
    // always carries the latest one (RFC 9449 §8.1 recommendation).
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

  // Surface the nonce manager's lifecycle hooks on the
  // returned middleware so hot-reload deploys can drain in-flight
  // clients before swapping instances. shutdown() refuses every
  // subsequent proof + issues no fresh nonces; revoke() rotates the
  // rolling pair without disabling the manager (useful after a
  // suspected nonce leak). Both are no-ops when requireNonce is off.
  middleware.shutdown = function () { if (nonceMgr) nonceMgr.shutdown(); };
  middleware.revoke   = function () { if (nonceMgr) nonceMgr.revoke();   };
  return middleware;
}

module.exports = {
  create: create,
};
