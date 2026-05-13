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
var { AuthError } = require("../framework-error");

var dpop = lazyRequire(function () { return require("../auth/dpop"); });
var audit = lazyRequire(function () { return require("../audit"); });

// RFC 9449 §8 — server-issued nonce length (24 random bytes ≈ 192 bits
// of entropy after base64url, far above the spec's "unpredictable" bar).
var DPOP_NONCE_BYTES = C.BYTES.bytes(24);

function _writeUnauthorized(res, errorCode, description, freshNonce) {
  if (res.headersSent) return;
  var body = JSON.stringify({ error: errorCode, error_description: description });
  // RFC 9449 §7 — error code is invalid_dpop_proof OR use_dpop_nonce.
  var challenge = 'DPoP error="' + errorCode + '", error_description="' +
                  description.replace(/"/g, "'") + '"';
  var headers = {                                                                  // allow:raw-byte-literal — HTTP 401 status
    "Content-Type":     "application/json; charset=utf-8",
    "Content-Length":   Buffer.byteLength(body),
    "WWW-Authenticate": challenge,
  };
  if (freshNonce) headers["DPoP-Nonce"] = freshNonce;
  res.writeHead(401, headers);
  res.end(body);
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
    issue: function () { _maybeRotate(); return current.nonce; },
    accepts: function (n) {
      _maybeRotate();
      if (typeof n !== "string" || n.length === 0) return false;
      return (current && n === current.nonce) || (previous && n === previous.nonce);
    },
  };
}

function _reconstructHtu(req, mopts) {
  // The proof's htu is the request URI WITHOUT query/fragment. Behind
  // a reverse proxy the operator may need to override via opts.htu /
  // opts.getHtu. X-Forwarded-* headers are ATTACKER-CONTROLLED when
  // the origin is reachable directly; an attacker who can hit the
  // origin while spoofing X-Forwarded-Proto: https can trick this
  // function into building an `https` htu that the DPoP proof was
  // signed for — when the origin is actually serving HTTP. RFC 9449
  // §4.3 says htu MUST be the absolute URL the request was sent to.
  //
  // Default: ignore X-Forwarded-* and derive proto/host from the
  // socket. Operators with a confirmed-trusted front proxy opt in
  // via opts.trustForwardedHeaders: true. (Audit 2026-05-11.)
  mopts = mopts || {};
  var trustForwarded = mopts.trustForwardedHeaders === true;
  var proto;
  if (trustForwarded && req.headers["x-forwarded-proto"]) {
    proto = String(req.headers["x-forwarded-proto"]).split(",")[0].trim();
  } else {
    proto = req.socket && req.socket.encrypted ? "https" : "http";
  }
  var host;
  if (trustForwarded && req.headers["x-forwarded-host"]) {
    host = String(req.headers["x-forwarded-host"]).split(",")[0].trim();
  } else {
    host = req.headers.host;
  }
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
 *     nonceStore:     object,
 *     nonceWindowSec: number,
 *     nonceRotateSec: number,
 *     requireNonce:   boolean,
 *     audit:          boolean,                      // default true
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
    // v0.9.4 — opt-in trust gate for X-Forwarded-Proto/Host when
    // reconstructing htu. Default off (audit 2026-05-11); operators
    // with a confirmed-trusted front proxy set this to `true`.
    "trustForwardedHeaders",
  ], "middleware.dpop");

  var auditOn = opts.audit !== false;
  var algorithms = opts.algorithms;
  var iatWindowSec = opts.iatWindowSec;
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

  function _freshNonce() { return nonceMgr ? nonceMgr.issue() : null; }

  return async function dpopMiddleware(req, res, next) {
    var proofHeader = req.headers && req.headers.dpop;
    if (typeof proofHeader !== "string" || proofHeader.length === 0) {
      return _writeUnauthorized(res,
        nonceMgr ? "use_dpop_nonce" : "invalid_dpop_proof",
        "DPoP header required", _freshNonce());
    }
    // RFC 9449 §4.1 — only ONE DPoP header value per request.
    if (Array.isArray(proofHeader)) {
      return _writeUnauthorized(res, "invalid_dpop_proof",
        "multiple DPoP headers are not allowed");
    }

    var htu = (typeof opts.getHtu === "function" ? opts.getHtu(req) : _reconstructHtu(req, opts));
    if (!htu) {
      return _writeUnauthorized(res, "invalid_dpop_proof", "could not reconstruct htu");
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
    if (replayStore) verifyOpts.replayStore = replayStore;

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
      return _writeUnauthorized(res, errorCode,
        (e && e.message) || "DPoP proof verification failed",
        _freshNonce());
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
        return _writeUnauthorized(res, "use_dpop_nonce",
          "DPoP-Nonce required (server-managed challenge)", _freshNonce());
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
}

module.exports = {
  create: create,
};
