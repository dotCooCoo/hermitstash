"use strict";
/**
 * JWT (RFC 7519) — PQC-signed JSON Web Tokens.
 *
 * Default signing algorithm: SLH-DSA-SHAKE-256f (FIPS 205, hash-only,
 * Cat-5 PQC). Matches the framework's SHAKE-family hash posture and
 * the audit-sign default — long-lived signed claims should sit on the
 * worst-case-PQC side of the choice. ML-DSA-87 (FIPS 204, lattice-
 * based, Cat-5 PQC) is the opt-in for high-throughput JWT issuance
 * paths where the ~80× sign-time penalty of SLH-DSA matters more than
 * the conservative-PQC argument.
 *
 * Caveats on emitting PQC-signed JWTs to the wild:
 *
 *   - Signature size: SLH-DSA-SHAKE-256f signatures are ~50 KB. A
 *     base64url-encoded JWT containing one is ~67 KB on the wire.
 *     Acceptable for stored long-lived tokens (license attestations,
 *     refresh tokens with multi-day validity, signed compliance
 *     receipts) — not for high-frequency request-bearer tokens.
 *     ML-DSA-87 brings this down to ~6 KB encoded.
 *
 *   - Algorithm naming is NOT in the IANA JOSE registry yet. The
 *     framework uses the IETF working-draft names ("SLH-DSA-SHAKE-256f",
 *     "ML-DSA-87") — when those become registered, the header `alg`
 *     value may shift; verify accepts whatever the supported-list
 *     declares. Expect to re-issue tokens at registry-stabilization
 *     time the same way you'd re-issue at any algorithm rotation.
 *
 *   - JWS-RFC-7515-required `crit` header parameter handling is NOT
 *     implemented (no critical extensions defined here). A token
 *     bearing an unknown `crit` is rejected as malformed.
 *
 * Public API (b.auth.jwt.*):
 *
 *   jwt.sign(claims, opts)        → string    (compact JWS, async)
 *   jwt.verify(token, opts)       → claims    (async; throws AuthError)
 *   jwt.decode(token)             → { header, payload, signature }
 *                                   (NO verification — inspection only)
 *
 * Sign opts:
 *   algorithm:    "SLH-DSA-SHAKE-256f" (default) | "ML-DSA-87"
 *   privateKey:   PEM string OR KeyObject from node:crypto.createPrivateKey
 *   kid:          optional key ID embedded in header (rotation hint)
 *   typ:          "JWT" (default) — operators emitting access-tokens may
 *                  want "at+jwt" per RFC 9068
 *   issuer:       claims.iss override (also accepts claims.iss directly)
 *   audience:     claims.aud override (string or string[])
 *   subject:      claims.sub override
 *   expiresInSec: relative exp (claims.exp = now + expiresInSec)
 *   notBeforeSec: relative nbf (claims.nbf = now + notBeforeSec)
 *   jti:          claims.jti override (string; if missing, no jti is added —
 *                  the framework doesn't auto-mint without an operator request
 *                  since jti has uniqueness/replay-tracking semantics that
 *                  belong at the application layer)
 *   now:          test-time clock injection (epoch milliseconds)
 *
 * Verify opts:
 *   publicKey:           PEM string OR KeyObject (required)
 *   algorithms:          [string]   allowed alg list. Default: [DEFAULT_ALGORITHM]
 *                        Pass an explicit list when accepting tokens
 *                        signed with multiple algos (e.g. mid-rotation).
 *   issuer:              expected iss (string OR string[]; matched any-of)
 *   audience:            expected aud (same shape; matches any-of, since
 *                        aud itself can be array per RFC 7519 §4.1.3)
 *   subject:             expected sub (string)
 *   clockToleranceSec:   leeway on exp/nbf comparisons. Default 0.
 *   now:                 test-time clock injection
 *
 * Errors are AuthError(code, message) with permanent=true. Distinct
 * codes per failure class so callers can branch (display "expired"
 * vs "not yet valid" UX, audit "bad-signature" attempts separately).
 */
var nodeCrypto = require("crypto");
var C = require("../constants");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

// Algorithm registry. The string keys are the JWT header `alg` values
// the framework emits + accepts. The values map to Node's
// generateKeyPairSync / sign / verify identifiers.
var ALGORITHM_TO_NODE = {
  "SLH-DSA-SHAKE-256f": "slh-dsa-shake-256f",
  "ML-DSA-87":          "ml-dsa-87",
};
var DEFAULT_ALGORITHM    = "SLH-DSA-SHAKE-256f";
var SUPPORTED_ALGORITHMS = Object.freeze(Object.keys(ALGORITHM_TO_NODE));

function _b64urlEncode(buf) {
  if (typeof buf === "string") buf = Buffer.from(buf, "utf8");
  return buf.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _b64urlDecode(s) {
  if (typeof s !== "string") throw new AuthError("auth-jwt/malformed", "expected base64url string");
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";
  return Buffer.from(padded, "base64");
}

function _toKeyObject(pemOrKey, kind) {
  // kind is 'private' or 'public' — passes through if already a KeyObject;
  // converts PEM string via createPrivateKey/createPublicKey.
  if (pemOrKey == null) {
    throw new AuthError("auth-jwt/missing-key", kind + "Key is required");
  }
  if (typeof pemOrKey === "object" && typeof pemOrKey.asymmetricKeyType === "string") {
    return pemOrKey;
  }
  if (typeof pemOrKey === "string") {
    if (kind === "private") return nodeCrypto.createPrivateKey({ key: pemOrKey, format: "pem" });
    return nodeCrypto.createPublicKey({ key: pemOrKey, format: "pem" });
  }
  throw new AuthError("auth-jwt/bad-key", kind + "Key must be PEM string or KeyObject");
}

function _resolveAlgorithm(alg) {
  if (typeof alg !== "string" || !ALGORITHM_TO_NODE[alg]) {
    throw new AuthError("auth-jwt/unsupported-algorithm",
      "algorithm must be one of " + SUPPORTED_ALGORITHMS.join(", ") + " (got: " + alg + ")");
  }
  return ALGORITHM_TO_NODE[alg];
}

// ---- sign ----

async function sign(claims, opts) {
  if (typeof claims !== "object" || claims === null) {
    throw new AuthError("auth-jwt/bad-claims", "claims must be an object");
  }
  opts = opts || {};
  var alg = opts.algorithm || DEFAULT_ALGORITHM;
  _resolveAlgorithm(alg);
  var key = _toKeyObject(opts.privateKey, "private");

  var nowMs = opts.now || Date.now();
  var nowSec = Math.floor(nowMs / C.TIME.seconds(1));

  // Build the claims object. Operator-provided claim values take
  // precedence over opts shorthand to avoid surprising overrides.
  var payload = Object.assign({}, claims);
  if (payload.iat === undefined) payload.iat = nowSec;
  if (opts.issuer !== undefined && payload.iss === undefined)   payload.iss = opts.issuer;
  if (opts.audience !== undefined && payload.aud === undefined) payload.aud = opts.audience;
  if (opts.subject !== undefined && payload.sub === undefined)  payload.sub = opts.subject;
  if (opts.jti !== undefined && payload.jti === undefined)      payload.jti = opts.jti;
  if (typeof opts.expiresInSec === "number" && payload.exp === undefined) {
    payload.exp = nowSec + opts.expiresInSec;
  }
  // Auto-mint jti when the token has an expiry but no operator-set
  // jti. The replay-defense path on verify() requires every replay-
  // protected token to carry a jti; without auto-mint, an operator
  // who configured replayStore on verify but forgot to set jti on
  // sign produces tokens that never replay-protect — and the
  // failure surfaces only at first replay attempt (via the
  // verifier's "missing-jti" throw). Auto-mint closes the silent
  // hole; operators who explicitly want a deterministic jti pass
  // opts.jti themselves.
  if (payload.exp !== undefined && payload.jti === undefined) {
    var fwCryptoJti = require("../crypto");                                // allow:inline-require — circular-load defense (crypto imports jwt? no — but use lazy form to keep parity)
    payload.jti = fwCryptoJti.generateBytes(C.BYTES.bytes(16)).toString("base64url");
  }
  if (typeof opts.notBeforeSec === "number" && payload.nbf === undefined) {
    payload.nbf = nowSec + opts.notBeforeSec;
  }

  var header = { alg: alg, typ: opts.typ || "JWT" };
  if (opts.kid) header.kid = String(opts.kid);

  var headerB64  = _b64urlEncode(JSON.stringify(header));
  var payloadB64 = _b64urlEncode(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;

  // node:crypto.sign with null algorithm — KeyObject knows its own alg.
  var sig = nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key);
  return signingInput + "." + _b64urlEncode(sig);
}

// ---- decode (no verify — for inspection) ----

function decode(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new AuthError("auth-jwt/malformed", "token must be a non-empty string");
  }
  var parts = token.split(".");
  if (parts.length !== 3) {
    throw new AuthError("auth-jwt/malformed", "token must have three dot-separated parts");
  }
  var header, payload;
  try { header  = safeJson.parse(_b64urlDecode(parts[0])); }
  catch (_e) { throw new AuthError("auth-jwt/malformed", "header is not valid base64url-JSON"); }
  try { payload = safeJson.parse(_b64urlDecode(parts[1])); }
  catch (_e) { throw new AuthError("auth-jwt/malformed", "payload is not valid base64url-JSON"); }
  var signature;
  try { signature = _b64urlDecode(parts[2]); }
  catch (_e) { throw new AuthError("auth-jwt/malformed", "signature is not valid base64url"); }
  return { header: header, payload: payload, signature: signature, signingInput: parts[0] + "." + parts[1] };
}

// ---- verify ----

function _matchClaim(actual, expected, claimName) {
  // expected is string OR string[]. actual is string OR string[].
  // Match is "any-of": at least one expected value must appear in
  // actual (or equal it when actual is scalar). Mirrors RFC 7519
  // §4.1.3's tolerance for `aud` being an array.
  var expectedList = Array.isArray(expected) ? expected : [expected];
  var actualList   = Array.isArray(actual)   ? actual   : [actual];
  for (var i = 0; i < expectedList.length; i++) {
    if (actualList.indexOf(expectedList[i]) !== -1) return true;
  }
  return false;
}

async function verify(token, opts) {
  opts = opts || {};
  var allowed = Array.isArray(opts.algorithms) && opts.algorithms.length > 0
    ? opts.algorithms
    : [DEFAULT_ALGORITHM];
  // Validate the allowlist itself — typoed entries should surface here,
  // not as silent "every token rejected."
  for (var i = 0; i < allowed.length; i++) {
    if (!ALGORITHM_TO_NODE[allowed[i]]) {
      throw new AuthError("auth-jwt/unsupported-algorithm",
        "opts.algorithms[" + i + "] = '" + allowed[i] + "' is not in the supported list (" +
        SUPPORTED_ALGORITHMS.join(", ") + ")");
    }
  }
  var decoded = decode(token);

  // keyResolver — operator-supplied per-token key lookup (typically by
  // header.kid against a rotation table or remote JWKS). Mutually
  // exclusive with opts.publicKey: pass one or the other, not both.
  // The resolver receives the FULL decoded header and returns either
  // the key (sync) or a Promise<key> (async).
  //
  // SECURITY: when the resolver uses header.kid as a filename / map
  // key / cache index, it MUST sanitize the kid first. Path-traversal
  // (`../etc/passwd`), null-byte (`key\0..`), control chars, and
  // similar shapes turn a kid lookup into an arbitrary-file-read
  // primitive (CVE-2018-0114 java-jwt class). Use
  // `b.guardJwt.kidSafe(header.kid)` — throws on traversal indicators
  // and control bytes, returns the validated kid on success.
  var key;
  if (typeof opts.keyResolver === "function") {
    if (opts.publicKey !== undefined) {
      throw new AuthError("auth-jwt/conflicting-key-source",
        "verify: pass keyResolver OR publicKey, not both");
    }
    var resolved;
    try { resolved = await opts.keyResolver(decoded.header); }
    catch (e) {
      throw new AuthError("auth-jwt/key-resolver-failed",
        "keyResolver threw: " + ((e && e.message) || String(e)));
    }
    if (!resolved) {
      throw new AuthError("auth-jwt/key-not-found",
        "keyResolver returned no key for kid='" +
        (decoded.header.kid || "<absent>") + "'");
    }
    key = _toKeyObject(resolved, "public");
  } else {
    key = _toKeyObject(opts.publicKey, "public");
  }

  // Reject unknown critical-header extensions outright (RFC 7515 §4.1.11)
  if (decoded.header.crit !== undefined) {
    throw new AuthError("auth-jwt/unknown-crit",
      "token declares critical extensions which this verifier does not support");
  }

  // RFC 8725 §3.11 — typ-confusion class. When opts.expectedTyp is
  // supplied (e.g. "JWT", "at+jwt", "logout+jwt"), refuse tokens
  // whose header.typ doesn't match. Caller-side check; the framework
  // doesn't impose a default typ to remain compatible with legacy
  // tokens that omit it. Match is case-insensitive per RFC 8725.
  if (opts.expectedTyp !== undefined) {
    validateOpts.requireNonEmptyString(opts.expectedTyp,
      "verify: opts.expectedTyp", AuthError, "auth-jwt/bad-expected-typ");
    var got = decoded.header.typ;
    if (typeof got !== "string" || got.toLowerCase() !== opts.expectedTyp.toLowerCase()) {
      throw new AuthError("auth-jwt/typ-mismatch",
        "token header.typ='" + got + "' does not match expectedTyp='" +
        opts.expectedTyp + "' (RFC 8725 §3.11 typ-confusion class)");
    }
  }

  // Algorithm must be in the allowed list AND match what we know how
  // to verify (i.e. one of SUPPORTED_ALGORITHMS).
  if (allowed.indexOf(decoded.header.alg) === -1) {
    throw new AuthError("auth-jwt/algorithm-not-allowed",
      "token alg='" + decoded.header.alg + "' is not in the allowed list [" + allowed.join(", ") + "]");
  }

  var verified = false;
  try {
    verified = nodeCrypto.verify(null, Buffer.from(decoded.signingInput, "ascii"), key, decoded.signature);
  } catch (e) {
    // node:crypto throws on key/signature shape mismatches (e.g. ML-DSA
    // signature against an SLH-DSA key). Treat as bad-signature so
    // operators can audit a single class of "this token isn't ours."
    throw new AuthError("auth-jwt/invalid-signature",
      "signature verification failed: " + (e.message || String(e)));
  }
  if (!verified) {
    throw new AuthError("auth-jwt/invalid-signature", "signature verification failed");
  }

  // Time-based claim validation
  var nowSec = Math.floor((opts.now || Date.now()) / C.TIME.seconds(1));
  if (opts.clockToleranceSec !== undefined && opts.clockToleranceSec !== null) {
    if (typeof opts.clockToleranceSec !== "number" ||
        !isFinite(opts.clockToleranceSec) ||
        opts.clockToleranceSec < 0) {
      // Throw at config time: a negative tolerance over-tightens the
      // window (legit tokens get rejected as expired or not-yet-valid)
      // and a non-finite value would NaN-poison the comparison. Catch
      // both here rather than producing surprise rejections in production.
      throw new AuthError("auth-jwt/bad-clock-tolerance",
        "verify: clockToleranceSec must be a non-negative finite number, got " +
        JSON.stringify(opts.clockToleranceSec));
    }
  }
  var tol = typeof opts.clockToleranceSec === "number" ? opts.clockToleranceSec : 0;
  var p = decoded.payload;

  // Strict registered-claim typing per RFC 7519 §4.1. exp / nbf / iat MUST
  // be NumericDate values (JSON numeric, seconds since epoch). A claim
  // present-but-not-a-number is a malformed token — silently skipping the
  // check would let a token with `exp: "0"` or `exp: "9999999999"` (string)
  // bypass expiration enforcement entirely.
  function _requireNumericDate(name, value) {
    if (typeof value !== "number" || !isFinite(value)) {
      throw new AuthError("auth-jwt/malformed",
        "claim '" + name + "' must be a finite number (RFC 7519 NumericDate), got " +
        (value === null ? "null" : typeof value));
    }
  }
  if (p.exp !== undefined) _requireNumericDate("exp", p.exp);
  if (p.nbf !== undefined) _requireNumericDate("nbf", p.nbf);
  if (p.iat !== undefined) _requireNumericDate("iat", p.iat);

  if (p.exp !== undefined && p.exp + tol < nowSec) {
    throw new AuthError("auth-jwt/expired",
      "token expired at exp=" + p.exp + " (now=" + nowSec + ", tolerance=" + tol + "s)");
  }
  if (p.nbf !== undefined && p.nbf - tol > nowSec) {
    throw new AuthError("auth-jwt/not-yet-valid",
      "token not yet valid: nbf=" + p.nbf + " (now=" + nowSec + ", tolerance=" + tol + "s)");
  }

  // String-claim assertions
  if (opts.issuer !== undefined && !_matchClaim(p.iss, opts.issuer, "iss")) {
    throw new AuthError("auth-jwt/iss-mismatch",
      "iss='" + p.iss + "' does not match expected " + JSON.stringify(opts.issuer));
  }
  if (opts.audience !== undefined && !_matchClaim(p.aud, opts.audience, "aud")) {
    throw new AuthError("auth-jwt/aud-mismatch",
      "aud=" + JSON.stringify(p.aud) + " does not match expected " + JSON.stringify(opts.audience));
  }
  if (opts.subject !== undefined && p.sub !== opts.subject) {
    throw new AuthError("auth-jwt/sub-mismatch",
      "sub='" + p.sub + "' does not match expected '" + opts.subject + "'");
  }

  // Replay defense — when operator wires `replayStore`, the verifier
  // refuses tokens whose jti has been seen within the replay window.
  // Defends against captured-bearer-token replay (RFC 7519 §4.1.7
  // recommends jti for exactly this purpose; CVE-class — token-reuse
  // under TLS-terminated proxies, log scraping, browser-history
  // exposure, leaked Authorization headers in shared dev tools).
  //
  // The store contract is the same atomic check-and-insert shape that
  // `b.nonceStore` exposes:
  //
  //   await replayStore.checkAndInsert(jti, expireAtMs)
  //     → true  if this jti was NOT previously seen (now recorded)
  //     → false if this jti was already seen (replay)
  //
  // `expireAtMs` is the absolute unix-ms timestamp at which the entry
  // should expire — matching `b.nonceStore`'s memory + cluster backends.
  // `b.nonceStore.create({ backend: "memory" | "cluster" | custom })`
  // returns a value satisfying this contract directly.
  //
  // Atomicity matters: a check-then-insert split would be a race window
  // where two concurrent verifies on the same jti both succeed.
  //
  // The token MUST carry a jti claim — without one the verifier can't
  // bind to anything, and the operator's intent to enforce replay
  // defense was a config mistake. Throw at verify time so the
  // misconfiguration surfaces, rather than silently letting every
  // jti-less token through.
  if (opts.replayStore !== undefined && opts.replayStore !== null) {
    validateOpts.optionalObjectWithMethod(
      opts.replayStore, "checkAndInsert",
      "verify: replayStore", AuthError, "auth-jwt/bad-replay-store",
      "must expose checkAndInsert(jti, expireAtMs) — use b.nonceStore.create() " +
      "or supply a compatible backend");
    if (typeof p.jti !== "string" || p.jti.length === 0) {
      throw new AuthError("auth-jwt/replay-no-jti",
        "verify: replayStore opt requires the token to carry a jti " +
        "claim (RFC 7519 §4.1.7); got " +
        (p.jti === undefined ? "<absent>" : typeof p.jti));
    }
    // expireAt = exp claim if present, else nowMs + 24h. The 24h cap
    // bounds in-memory growth when an operator forgets to set exp.
    var nowMs = (typeof opts.now === "number" ? opts.now : Date.now());
    var expireAtMs = nowMs + C.TIME.hours(24);
    if (typeof p.exp === "number") {
      expireAtMs = p.exp * C.TIME.seconds(1);
    }
    var inserted;
    try { inserted = await opts.replayStore.checkAndInsert(p.jti, expireAtMs); }
    catch (e) {
      throw new AuthError("auth-jwt/replay-store-failed",
        "replayStore.checkAndInsert threw: " + ((e && e.message) || String(e)));
    }
    if (inserted === false) {
      throw new AuthError("auth-jwt/replay",
        "token jti='" + p.jti + "' has been seen before — replay refused");
    }
  }

  return p;
}

module.exports = {
  sign:                  sign,
  verify:                verify,
  decode:                decode,
  DEFAULT_ALGORITHM:     DEFAULT_ALGORITHM,
  SUPPORTED_ALGORITHMS:  SUPPORTED_ALGORITHMS,
};
