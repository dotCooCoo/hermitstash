// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var bCrypto = require("../crypto");
var jwk = require("../jwk");
var jwtExternal = require("./jwt-external");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var validateOpts = require("../validate-opts");
var nonceStore = require("../nonce-store");
var C = require("../constants");
var { AuthError } = require("../framework-error");

var DEFAULT_IAT_WINDOW_SEC = C.TIME.minutes(1) / C.TIME.seconds(1);
var MAX_PROOF_BYTES        = C.BYTES.kib(96);

var SUPPORTED_CLASSICAL_ALGS = [
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "RS256", "RS384", "RS512",
  "EdDSA",
];

var SUPPORTED_PQC_ALGS = [
  "ML-DSA-87",
];

var SUPPORTED_ALGS = SUPPORTED_CLASSICAL_ALGS.concat(SUPPORTED_PQC_ALGS);

var REFUSED_ALGS = ["HS256", "HS384", "HS512", "none"];

function _b64urlEncode(buf) { return bCrypto.toBase64Url(buf); }

var _b64urlDecode = bCrypto.makeBase64UrlDecoder({
  errorClass:  AuthError,
  code:        "auth-dpop/bad-base64",
  typeMessage: "expected base64url string",
  badMessage:  "DPoP segment is not valid base64url",
});

var DPOP_KTY = { EC: 1, OKP: 1, RSA: 1, AKP: 1 };

function thumbprint(key) {
  if (!key || typeof key !== "object" || typeof key.kty !== "string" || key.kty.length === 0) {
    throw new AuthError("auth-dpop/bad-jwk", "jwk must be an object with a kty");
  }
  if (!Object.prototype.hasOwnProperty.call(DPOP_KTY, key.kty)) {
    throw new AuthError("auth-dpop/refused-kty", "jwk.kty='" + key.kty + "' is not allowed (DPoP requires asymmetric kty)");
  }
  try { return jwk.thumbprint(key); }
  catch (e) { throw new AuthError("auth-dpop/bad-jwk", (e && e.message) || "invalid jwk"); }
}

function _sha256B64Url(input) {
  var hash = nodeCrypto.createHash("sha256").update(input, "utf8").digest();
  return _b64urlEncode(hash);
}

function _normalizeHtu(htu) {
  if (typeof htu !== "string" || htu.length === 0) {
    throw new AuthError("auth-dpop/bad-htu", "htu must be a non-empty string");
  }
  var parsed;
  try { parsed = safeUrl.parse(htu, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }); }
  catch (e) {
    throw new AuthError("auth-dpop/bad-htu",
      "htu parse failed: " + ((e && e.message) || String(e)));
  }
  var port = (parsed.port && parsed.port.length > 0) ? (":" + parsed.port) : "";
  return parsed.protocol + "//" + parsed.hostname + port + (parsed.pathname || "/");
}

function _signParamsForAlg(alg) {
  var params = jwtExternal.algParams(alg);
  if (params) return params;
  if (alg === "ML-DSA-87") return { hash: null, pqc: true };
  throw new AuthError("auth-dpop/unsupported-alg",
    "alg '" + alg + "' is not supported by DPoP");
}

function _toPrivateKey(value) {
  if (!value) {
    throw new AuthError("auth-dpop/missing-private-key",
      "buildProof: privateKey is required");
  }
  if (value instanceof nodeCrypto.KeyObject) return value;
  if (typeof value === "string" || Buffer.isBuffer(value)) {
    try { return nodeCrypto.createPrivateKey({ key: value, format: "pem" }); }
    catch (e) {
      throw new AuthError("auth-dpop/bad-private-key",
        "PEM parse failed: " + ((e && e.message) || String(e)));
    }
  }
  if (typeof value === "object" && value.kty) {
    try { return nodeCrypto.createPrivateKey({ key: value, format: "jwk" }); }
    catch (e) {
      throw new AuthError("auth-dpop/bad-private-key",
        "JWK parse failed: " + ((e && e.message) || String(e)));
    }
  }
  throw new AuthError("auth-dpop/bad-private-key",
    "privateKey must be PEM string/Buffer, JWK object, or KeyObject");
}

function _publicJwkFromPrivate(privateKey) {
  var pub = nodeCrypto.createPublicKey(privateKey);
  try { return pub.export({ format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-dpop/bad-private-key",
      "could not derive public JWK: " + ((e && e.message) || String(e)));
  }
}

function _detectAlgFromKey(key) {
  var t = key.asymmetricKeyType;
  var details = key.asymmetricKeyDetails || {};
  if (t === "ec" && details.namedCurve === "prime256v1") return "ES256";
  if (t === "ec" && details.namedCurve === "secp384r1")  return "ES384";
  if (t === "ec" && details.namedCurve === "secp521r1")  return "ES512";
  if (t === "ed25519" || t === "ed448")                  return "EdDSA";
  if (t === "rsa" || t === "rsa-pss")                    return "RS256";
  if (t === "ml-dsa-87")                                 return "ML-DSA-87";
  throw new AuthError("auth-dpop/unsupported-key",
    "could not infer DPoP alg from key type='" + t + "' " +
    "(SLH-DSA is not currently supported in DPoP — Node lacks SLH-DSA " +
    "JWK round-trip; use ML-DSA-87 for PQC-DPoP)");
}

function _jwkToKeyObject(jwk) {
  return bCrypto.importPublicJwk(jwk, {
    errorClass:    AuthError,
    code:          "auth-dpop/bad-jwk",
    messagePrefix: "could not import jwk: ",
  });
}

async function buildProof(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "htm", "htu", "privateKey", "algorithm", "accessToken", "nonce", "jti", "iat", "jwk",
  ], "auth.dpop.buildProof");

  validateOpts.requireNonEmptyString(opts.htm,
    "buildProof: htm (HTTP method)", AuthError, "auth-dpop/bad-htm");
  validateOpts.requireNonEmptyString(opts.htu,
    "buildProof: htu (request URI)", AuthError, "auth-dpop/bad-htu");
  var key = _toPrivateKey(opts.privateKey);
  var alg = opts.algorithm || _detectAlgFromKey(key);
  if (REFUSED_ALGS.indexOf(alg) !== -1) {
    throw new AuthError("auth-dpop/refused-alg",
      "alg '" + alg + "' is refused by DPoP (HMAC/none)");
  }
  if (SUPPORTED_ALGS.indexOf(alg) === -1) {
    throw new AuthError("auth-dpop/unsupported-alg",
      "alg '" + alg + "' is not supported by DPoP");
  }

  var proofKey = opts.jwk || _publicJwkFromPrivate(key);
  var pubJwk;
  if (proofKey.kty === "EC") pubJwk = { kty: "EC", crv: proofKey.crv, x: proofKey.x, y: proofKey.y };
  else if (proofKey.kty === "OKP") pubJwk = { kty: "OKP", crv: proofKey.crv, x: proofKey.x };
  else if (proofKey.kty === "RSA") pubJwk = { kty: "RSA", e: proofKey.e, n: proofKey.n };
  else if (proofKey.kty === "AKP") pubJwk = { kty: "AKP", alg: proofKey.alg, pub: proofKey.pub };
  else throw new AuthError("auth-dpop/refused-kty",
    "jwk.kty='" + proofKey.kty + "' is not allowed");

  var jti = opts.jti || _b64urlEncode(nodeCrypto.randomBytes(C.BYTES.bytes(16)));
  var nowMs = (typeof opts.iat === "number" ? opts.iat * C.TIME.seconds(1) : Date.now());
  var iatSec = Math.floor(nowMs / C.TIME.seconds(1));

  var header = { typ: "dpop+jwt", alg: alg, jwk: pubJwk };
  var payload = {
    jti: jti,
    htm: opts.htm.toUpperCase(),
    htu: _normalizeHtu(opts.htu),
    iat: iatSec,
  };
  if (typeof opts.accessToken === "string" && opts.accessToken.length > 0) {
    payload.ath = _sha256B64Url(opts.accessToken);
  }
  if (typeof opts.nonce === "string" && opts.nonce.length > 0) {
    payload.nonce = opts.nonce;
  }

  var headerB64  = _b64urlEncode(JSON.stringify(header));
  var payloadB64 = _b64urlEncode(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;

  var params = _signParamsForAlg(alg);
  var sig;
  if (params.pqc) {
    sig = nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key);
  } else if (params.hash === null) {
    sig = nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"), key);
  } else {
    var keyParam = { key: key };
    if (params.padding !== undefined) keyParam.padding = params.padding;
    if (params.saltLength !== undefined) keyParam.saltLength = params.saltLength;
    if (params.dsaEncoding !== undefined) keyParam.dsaEncoding = params.dsaEncoding;
    sig = nodeCrypto.sign(params.hash, Buffer.from(signingInput, "ascii"), keyParam);
  }

  return signingInput + "." + _b64urlEncode(sig);
}

async function verify(proof, opts) {
  if (typeof proof !== "string" || proof.length === 0) {
    throw new AuthError("auth-dpop/no-proof", "DPoP proof must be a non-empty string");
  }
  if (proof.length > MAX_PROOF_BYTES) {
    throw new AuthError("auth-dpop/proof-too-large",
      "DPoP proof exceeds " + MAX_PROOF_BYTES + " bytes");
  }
  opts = opts || {};
  validateOpts(opts, [
    "htm", "htu", "algorithms", "iatWindowSec", "accessToken",
    "expectedThumbprint", "nonce", "replayStore", "now",
  ], "auth.dpop.verify");

  validateOpts.requireNonEmptyString(opts.htm,
    "verify: opts.htm (expected HTTP method)", AuthError, "auth-dpop/bad-htm");
  validateOpts.requireNonEmptyString(opts.htu,
    "verify: opts.htu (expected request URI)", AuthError, "auth-dpop/bad-htu");

  var allowed = (Array.isArray(opts.algorithms) && opts.algorithms.length > 0)
    ? opts.algorithms : SUPPORTED_ALGS;
  for (var ai = 0; ai < allowed.length; ai += 1) {
    if (REFUSED_ALGS.indexOf(allowed[ai]) !== -1) {
      throw new AuthError("auth-dpop/refused-alg",
        "alg '" + allowed[ai] + "' is refused by DPoP");
    }
    if (SUPPORTED_ALGS.indexOf(allowed[ai]) === -1) {
      throw new AuthError("auth-dpop/unsupported-alg",
        "alg '" + allowed[ai] + "' is not supported (supported: " +
        SUPPORTED_ALGS.join(", ") + ")");
    }
  }

  var iatWindowSec = (typeof opts.iatWindowSec === "number" ? opts.iatWindowSec : DEFAULT_IAT_WINDOW_SEC);
  if (!isFinite(iatWindowSec) || iatWindowSec <= 0) {
    throw new AuthError("auth-dpop/bad-iat-window",
      "iatWindowSec must be a positive finite number");
  }

  var parts = proof.split(".");
  if (parts.length !== 3) {
    throw new AuthError("auth-dpop/malformed", "proof must have 3 dot-separated parts");
  }
  var header, payload;
  try { header  = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8")); }
  catch (_e) { throw new AuthError("auth-dpop/malformed", "header is not valid base64url-JSON"); }
  try { payload = safeJson.parse(_b64urlDecode(parts[1]).toString("utf8")); }
  catch (_e) { throw new AuthError("auth-dpop/malformed", "payload is not valid base64url-JSON"); }
  if (!safeJson.isJsonObject(header)) {
    throw new AuthError("auth-dpop/malformed", "header is not a JSON object");
  }
  if (!safeJson.isJsonObject(payload)) {
    throw new AuthError("auth-dpop/malformed", "payload is not a JSON object");
  }

  if (header.typ !== "dpop+jwt") {
    throw new AuthError("auth-dpop/bad-typ",
      "header.typ must be 'dpop+jwt' (got " + JSON.stringify(header.typ) + ")");
  }
  if (typeof header.alg !== "string") {
    throw new AuthError("auth-dpop/malformed", "header.alg is required");
  }
  if (allowed.indexOf(header.alg) === -1) {
    throw new AuthError("auth-dpop/alg-not-allowed",
      "alg '" + header.alg + "' not in allowed list [" + allowed.join(", ") + "]");
  }
  if (!header.jwk || typeof header.jwk !== "object") {
    throw new AuthError("auth-dpop/missing-jwk",
      "header.jwk is required (DPoP proof embeds the public key)");
  }
  if (header.jwk.d !== undefined || header.jwk.p !== undefined ||
      header.jwk.q !== undefined || header.jwk.dp !== undefined ||
      header.jwk.dq !== undefined || header.jwk.qi !== undefined ||
      header.jwk.k !== undefined || header.jwk.priv !== undefined) {
    throw new AuthError("auth-dpop/jwk-has-private",
      "header.jwk contains private-key components — refused");
  }
  if (header.crit !== undefined) {
    throw new AuthError("auth-dpop/unknown-crit",
      "DPoP proof declares 'crit' header — refused");
  }

  jwtExternal._assertAlgKtyMatch(header.alg, header.jwk);

  var key = _jwkToKeyObject(header.jwk);
  var params = _signParamsForAlg(header.alg);
  var signingInput = parts[0] + "." + parts[1];
  var sigBuf;
  try { sigBuf = _b64urlDecode(parts[2]); }
  catch (_e) { throw new AuthError("auth-dpop/malformed", "signature is not valid base64url"); }

  var verified = false;
  try {
    if (params.pqc || params.hash === null) {
      verified = nodeCrypto.verify(null, Buffer.from(signingInput, "ascii"), key, sigBuf);
    } else {
      var keyParam = { key: key };
      if (params.padding !== undefined) keyParam.padding = params.padding;
      if (params.saltLength !== undefined) keyParam.saltLength = params.saltLength;
      if (params.dsaEncoding !== undefined) keyParam.dsaEncoding = params.dsaEncoding;
      verified = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), keyParam, sigBuf);
    }
  } catch (e) {
    throw new AuthError("auth-dpop/invalid-signature",
      "signature verification failed: " + ((e && e.message) || String(e)));
  }
  if (!verified) {
    throw new AuthError("auth-dpop/invalid-signature", "signature verification failed");
  }

  var jkt = thumbprint(header.jwk);
  if (typeof opts.expectedThumbprint === "string" && opts.expectedThumbprint.length > 0) {
    if (!bCrypto.timingSafeEqual(jkt, opts.expectedThumbprint)) {
      throw new AuthError("auth-dpop/thumbprint-mismatch",
        "proof key thumbprint does not match expected");
    }
  }

  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new AuthError("auth-dpop/missing-jti", "payload.jti is required");
  }
  if (typeof payload.htm !== "string" || payload.htm.length === 0) {
    throw new AuthError("auth-dpop/bad-htm", "payload.htm is required");
  }
  if (payload.htm.toUpperCase() !== opts.htm.toUpperCase()) {
    throw new AuthError("auth-dpop/htm-mismatch",
      "payload.htm='" + payload.htm + "' does not match expected '" + opts.htm + "'");
  }
  if (typeof payload.htu !== "string" || payload.htu.length === 0) {
    throw new AuthError("auth-dpop/bad-htu", "payload.htu is required");
  }
  var expectedHtu = _normalizeHtu(opts.htu);
  var actualHtu = _normalizeHtu(payload.htu);
  if (actualHtu !== expectedHtu) {
    throw new AuthError("auth-dpop/htu-mismatch",
      "payload.htu='" + actualHtu + "' does not match expected '" + expectedHtu + "'");
  }
  if (typeof payload.iat !== "number" || !isFinite(payload.iat)) {
    throw new AuthError("auth-dpop/bad-iat",
      "payload.iat must be a finite number (RFC 7519 NumericDate)");
  }
  var nowMs = (typeof opts.now === "number" ? opts.now : Date.now());
  var nowSec = Math.floor(nowMs / C.TIME.seconds(1));
  if (Math.abs(nowSec - payload.iat) > iatWindowSec) {
    throw new AuthError("auth-dpop/iat-out-of-window",
      "payload.iat=" + payload.iat + " outside ±" + iatWindowSec + "s of now=" + nowSec);
  }

  if (typeof opts.accessToken === "string" && opts.accessToken.length > 0) {
    var expectedAth = _sha256B64Url(opts.accessToken);
    if (typeof payload.ath !== "string" || payload.ath.length === 0) {
      throw new AuthError("auth-dpop/missing-ath",
        "accessToken supplied but proof has no ath claim");
    }
    if (!bCrypto.timingSafeEqual(payload.ath, expectedAth)) {
      throw new AuthError("auth-dpop/ath-mismatch",
        "payload.ath does not match SHA-256 of access token");
    }
  }

  if (typeof opts.nonce === "string" && opts.nonce.length > 0) {
    if (typeof payload.nonce !== "string" || payload.nonce.length === 0) {
      throw new AuthError("auth-dpop/missing-nonce",
        "nonce expected but proof has no nonce claim");
    }
    if (!bCrypto.timingSafeEqual(payload.nonce, opts.nonce)) {
      throw new AuthError("auth-dpop/nonce-mismatch",
        "payload.nonce does not match expected");
    }
  }

  if (opts.replayStore !== undefined && opts.replayStore !== null) {
    validateOpts.optionalObjectWithMethod(
      opts.replayStore, "checkAndInsert",
      "verify: replayStore", AuthError, "auth-dpop/bad-replay-store",
      "must expose checkAndInsert(jti, expireAtMs) — use b.nonceStore.create()");
    var expireAtMs = nowMs + iatWindowSec * C.TIME.seconds(1) * 2;
    await nonceStore.enforceReplay(opts.replayStore, payload.jti, expireAtMs, {
      errorClass:      AuthError,
      storeFailedCode: "auth-dpop/replay-store-failed",
      replayCode:      "auth-dpop/replay",
      tokenLabel:      "DPoP proof",
    });
  }

  return { header: header, payload: payload, jkt: jkt };
}

module.exports = {
  buildProof:  buildProof,
  verify:      verify,
  thumbprint:  thumbprint,
  SUPPORTED_ALGS:           SUPPORTED_ALGS,
  SUPPORTED_CLASSICAL_ALGS: SUPPORTED_CLASSICAL_ALGS,
  SUPPORTED_PQC_ALGS:       SUPPORTED_PQC_ALGS,
  REFUSED_ALGS:             REFUSED_ALGS,
};
