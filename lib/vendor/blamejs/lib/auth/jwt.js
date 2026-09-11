// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var C = require("../constants");
var bCrypto = require("../crypto");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var nonceStore = require("../nonce-store");
var { AuthError } = require("../framework-error");

var ALGORITHM_TO_NODE = {
  "SLH-DSA-SHAKE-256f": "slh-dsa-shake-256f",
  "ML-DSA-87":          "ml-dsa-87",
};
var DEFAULT_ALGORITHM    = "SLH-DSA-SHAKE-256f";
var SUPPORTED_ALGORITHMS = Object.freeze(Object.keys(ALGORITHM_TO_NODE));

function _b64urlEncode(buf) { return bCrypto.toBase64Url(buf); }

var _b64urlDecode = bCrypto.makeBase64UrlDecoder({
  errorClass:  AuthError,
  code:        "auth-jwt/malformed",
  typeMessage: "expected base64url string",
  badMessage:  "JWT segment is not valid base64url",
});

function _toKeyObject(pemOrKey, kind) {
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
  if (typeof alg !== "string" || !Object.prototype.hasOwnProperty.call(ALGORITHM_TO_NODE, alg)) {
    throw new AuthError("auth-jwt/unsupported-algorithm",
      "algorithm must be one of " + SUPPORTED_ALGORITHMS.join(", ") + " (got: " + alg + ")");
  }
  return ALGORITHM_TO_NODE[alg];
}

function _assertAlgMatchesKey(alg, key, kind) {
  var expectedNodeType = ALGORITHM_TO_NODE[alg];
  var actual = key && typeof key.asymmetricKeyType === "string" ? key.asymmetricKeyType : null;
  if (actual !== expectedNodeType) {
    throw new AuthError("auth-jwt/alg-key-mismatch",
      "declared alg '" + alg + "' requires a '" + expectedNodeType + "' key but the " +
      kind + " key is '" + (actual || "unknown") + "' — the JWS alg header must be bound to " +
      "the key's actual algorithm (CWE-347 algorithm confusion)");
  }
}

async function sign(claims, opts) {
  if (typeof claims !== "object" || claims === null) {
    throw new AuthError("auth-jwt/bad-claims", "claims must be an object");
  }
  opts = opts || {};
  var alg = opts.algorithm || DEFAULT_ALGORITHM;
  _resolveAlgorithm(alg);
  var key = _toKeyObject(opts.privateKey, "private");
  _assertAlgMatchesKey(alg, key, "private");

  var nowMs = opts.now || Date.now();
  var nowSec = Math.floor(nowMs / C.TIME.seconds(1));

  var payload = Object.assign({}, claims);
  if (payload.iat === undefined) payload.iat = nowSec;
  if (opts.issuer !== undefined && payload.iss === undefined)   payload.iss = opts.issuer;
  if (opts.audience !== undefined && payload.aud === undefined) payload.aud = opts.audience;
  if (opts.subject !== undefined && payload.sub === undefined)  payload.sub = opts.subject;
  if (opts.jti !== undefined && payload.jti === undefined)      payload.jti = opts.jti;
  if (typeof opts.expiresInSec === "number" && payload.exp === undefined) {
    payload.exp = nowSec + opts.expiresInSec;
  }
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

  var sig = nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key);
  return signingInput + "." + _b64urlEncode(sig);
}

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
  if (!safeJson.isJsonObject(header)) {
    throw new AuthError("auth-jwt/malformed", "header is not a JSON object");
  }
  if (!safeJson.isJsonObject(payload)) {
    throw new AuthError("auth-jwt/malformed", "payload is not a JSON object");
  }
  var signature;
  try { signature = _b64urlDecode(parts[2]); }
  catch (_e) { throw new AuthError("auth-jwt/malformed", "signature is not valid base64url"); }
  return { header: header, payload: payload, signature: signature, signingInput: parts[0] + "." + parts[1] };
}

function _matchClaim(actual, expected, claimName) {
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
  for (var i = 0; i < allowed.length; i++) {
    if (!Object.prototype.hasOwnProperty.call(ALGORITHM_TO_NODE, allowed[i])) {
      throw new AuthError("auth-jwt/unsupported-algorithm",
        "opts.algorithms[" + i + "] = '" + allowed[i] + "' is not in the supported list (" +
        SUPPORTED_ALGORITHMS.join(", ") + ")");
    }
  }
  var decoded = decode(token);

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

  if (decoded.header.crit !== undefined) {
    throw new AuthError("auth-jwt/unknown-crit",
      "token declares critical extensions which this verifier does not support");
  }

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

  if (allowed.indexOf(decoded.header.alg) === -1) {
    throw new AuthError("auth-jwt/algorithm-not-allowed",
      "token alg='" + decoded.header.alg + "' is not in the allowed list [" + allowed.join(", ") + "]");
  }

  _assertAlgMatchesKey(decoded.header.alg, key, "public");

  var verified = false;
  try {
    verified = nodeCrypto.verify(null, Buffer.from(decoded.signingInput, "ascii"), key, decoded.signature);
  } catch (e) {
    throw new AuthError("auth-jwt/invalid-signature",
      "signature verification failed: " + (e.message || String(e)));
  }
  if (!verified) {
    throw new AuthError("auth-jwt/invalid-signature", "signature verification failed");
  }

  var nowSec = Math.floor((opts.now || Date.now()) / C.TIME.seconds(1));
  if (opts.clockToleranceSec !== undefined && opts.clockToleranceSec !== null) {
    if (typeof opts.clockToleranceSec !== "number" ||
        !isFinite(opts.clockToleranceSec) ||
        opts.clockToleranceSec < 0) {
      throw new AuthError("auth-jwt/bad-clock-tolerance",
        "verify: clockToleranceSec must be a non-negative finite number, got " +
        JSON.stringify(opts.clockToleranceSec));
    }
  }
  var tol = typeof opts.clockToleranceSec === "number" ? opts.clockToleranceSec : 0;
  var p = decoded.payload;

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

  if (opts.issuer !== undefined &&
      (typeof p.iss !== "string" || !_matchClaim(p.iss, opts.issuer, "iss"))) {
    throw new AuthError("auth-jwt/iss-mismatch",
      "iss=" + JSON.stringify(p.iss) + " does not match expected " + JSON.stringify(opts.issuer));
  }
  if (opts.audience !== undefined && !_matchClaim(p.aud, opts.audience, "aud")) {
    throw new AuthError("auth-jwt/aud-mismatch",
      "aud=" + JSON.stringify(p.aud) + " does not match expected " + JSON.stringify(opts.audience));
  }
  if (opts.subject !== undefined && p.sub !== opts.subject) {
    throw new AuthError("auth-jwt/sub-mismatch",
      "sub='" + p.sub + "' does not match expected '" + opts.subject + "'");
  }

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
    var nowMs = (typeof opts.now === "number" ? opts.now : Date.now());
    var expireAtMs = nowMs + C.TIME.hours(24);
    if (typeof p.exp === "number") {
      expireAtMs = p.exp * C.TIME.seconds(1);
    }
    await nonceStore.enforceReplay(opts.replayStore, p.jti, expireAtMs, {
      errorClass:      AuthError,
      storeFailedCode: "auth-jwt/replay-store-failed",
      replayCode:      "auth-jwt/replay",
      tokenLabel:      "token",
    });
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
