"use strict";
/**
 * DPoP — Demonstrating Proof of Possession (RFC 9449).
 *
 * A DPoP proof is a short-lived JWT signed by an ephemeral keypair the
 * client holds. The client embeds the public half (`jwk` header) in the
 * proof and signs over the request method + URI + a per-request `jti`,
 * optionally binding the proof to the access token (`ath` claim) and a
 * server-issued nonce.
 *
 * The server verifies the proof against the embedded public key and
 * checks: typ / alg / iat freshness / htm / htu / jti uniqueness within
 * the freshness window / optional ath against the presented access
 * token / optional nonce / optional thumbprint match.
 *
 * Defends against captured-bearer-token theft: an attacker who exfils
 * the access token still can't replay it without also stealing the
 * client's private key (which never leaves the client).
 *
 * Surface:
 *
 *   await b.auth.dpop.buildProof(opts)        // → string  (compact JWS)
 *   await b.auth.dpop.verify(proof, opts)     // → { header, payload, jkt }
 *   b.auth.dpop.thumbprint(jwk)               // → base64url-sha256(canonical-jwk)
 *
 * Middleware: see `lib/middleware/dpop.js` (`b.middleware.dpop`).
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("../crypto");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var { AuthError } = require("../framework-error");

// ---- constants ----

var DEFAULT_IAT_WINDOW_SEC = C.TIME.minutes(1) / C.TIME.seconds(1);   // 60 seconds
// SLH-DSA-SHAKE-256f signatures alone are ~50 KB before base64url +
// the embedded JWK; the cap accommodates the worst-case PQC alg, with
// margin. Operators emitting only classical-alg proofs see proofs in
// the ~500-byte range.
var MAX_PROOF_BYTES        = C.BYTES.kib(96);

// Classical asymmetric algs for DPoP (RFC 9449 §4.2).
var SUPPORTED_CLASSICAL_ALGS = [
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "RS256", "RS384", "RS512",
  "EdDSA",
];

// PQC algs the framework accepts in DPoP proofs. ML-DSA-87 is the
// throughput-friendly option; SLH-DSA-SHAKE-256f is intentionally
// omitted because Node does not currently support JWK
// import/export for SLH-DSA (and DPoP requires the public key embedded
// as a JWK in the proof header). Re-add to this list when Node exposes
// SLH-DSA JWK round-trip; SLH-DSA's ~50 KB signatures + ~80x sign-time
// penalty also make it a poor fit for per-request DPoP proofs.
var SUPPORTED_PQC_ALGS = [
  "ML-DSA-87",
];

var SUPPORTED_ALGS = SUPPORTED_CLASSICAL_ALGS.concat(SUPPORTED_PQC_ALGS);

// HMAC + "none" are NEVER accepted in DPoP. HMAC requires a shared
// secret which DPoP's embedded-jwk model can't supply; "none" defeats
// the entire proof.
var REFUSED_ALGS = ["HS256", "HS384", "HS512", "none"];

// ---- helpers ----

function _b64urlEncode(buf) { return bCrypto.toBase64Url(buf); }

function _b64urlDecode(s) {
  if (typeof s !== "string") {
    throw new AuthError("auth-dpop/bad-base64", "expected base64url string");
  }
  try { return bCrypto.fromBase64Url(s); }
  catch (_e) {
    throw new AuthError("auth-dpop/bad-base64",
      "DPoP segment is not valid base64url");
  }
}

// Canonical JWK per RFC 7638 — keys present in lexicographic order,
// only the kty-defined "required" members. Used for thumbprint.
function _canonicalJwk(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new AuthError("auth-dpop/bad-jwk", "jwk must be an object");
  }
  if (typeof jwk.kty !== "string" || jwk.kty.length === 0) {
    throw new AuthError("auth-dpop/bad-jwk", "jwk.kty is required");
  }
  if (jwk.kty === "EC") {
    if (typeof jwk.crv !== "string" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      throw new AuthError("auth-dpop/bad-jwk", "EC jwk requires crv, x, y");
    }
    return JSON.stringify({ crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y });
  }
  if (jwk.kty === "OKP") {
    if (typeof jwk.crv !== "string" || typeof jwk.x !== "string") {
      throw new AuthError("auth-dpop/bad-jwk", "OKP jwk requires crv, x");
    }
    return JSON.stringify({ crv: jwk.crv, kty: "OKP", x: jwk.x });
  }
  if (jwk.kty === "RSA") {
    if (typeof jwk.e !== "string" || typeof jwk.n !== "string") {
      throw new AuthError("auth-dpop/bad-jwk", "RSA jwk requires e, n");
    }
    return JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n });
  }
  if (jwk.kty === "AKP") {
    // PQC asymmetric key package (draft-ietf-cose-cnsa-pqc / IANA AKP
    // registry). Node:crypto exports ML-DSA / SLH-DSA public keys with
    // kty=AKP, alg=<algId>, pub=<base64url public bytes>.
    if (typeof jwk.alg !== "string" || typeof jwk.pub !== "string") {
      throw new AuthError("auth-dpop/bad-jwk", "AKP jwk requires alg, pub");
    }
    return JSON.stringify({ alg: jwk.alg, kty: "AKP", pub: jwk.pub });
  }
  // Symmetric keys (oct) and any other kty are refused outright — DPoP's
  // proof model requires asymmetric.
  throw new AuthError("auth-dpop/refused-kty",
    "jwk.kty='" + jwk.kty + "' is not allowed (DPoP requires asymmetric kty)");
}

function thumbprint(jwk) {
  var canonical = _canonicalJwk(jwk);
  var hash = nodeCrypto.createHash("sha256").update(canonical, "utf8").digest();
  return _b64urlEncode(hash);
}

function _sha256B64Url(input) {
  var hash = nodeCrypto.createHash("sha256").update(input, "utf8").digest();
  return _b64urlEncode(hash);
}

// Strip query + fragment from htu per RFC 9449 §4.3 step 5.
function _normalizeHtu(htu) {
  if (typeof htu !== "string" || htu.length === 0) {
    throw new AuthError("auth-dpop/bad-htu", "htu must be a non-empty string");
  }
  // Use safeUrl to validate the URL itself (refuses control bytes,
  // unsupported schemes, etc.). Then strip query + fragment.
  var parsed;
  try { parsed = safeUrl.parse(htu, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }); }
  catch (e) {
    throw new AuthError("auth-dpop/bad-htu",
      "htu parse failed: " + ((e && e.message) || String(e)));
  }
  // Reconstruct origin + path; safeUrl exposes the parsed pieces.
  var port = (parsed.port && parsed.port.length > 0) ? (":" + parsed.port) : "";
  return parsed.protocol + "//" + parsed.hostname + port + (parsed.pathname || "/");
}

// Pick alg-specific node:crypto verify params. PQC algs use
// signWithoutAlgorithm shape (`null` algorithm).
function _signParamsForAlg(alg) {
  if (alg === "RS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "PS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };  // allow:raw-byte-literal — RFC 7518 PS256 salt length
  if (alg === "PS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 };  // allow:raw-byte-literal — RFC 7518 PS384 salt length
  if (alg === "PS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 };  // allow:raw-byte-literal — RFC 7518 PS512 salt length
  if (alg === "ES256") return { hash: "sha256", dsaEncoding: "ieee-p1363" };
  if (alg === "ES384") return { hash: "sha384", dsaEncoding: "ieee-p1363" };
  if (alg === "ES512") return { hash: "sha512", dsaEncoding: "ieee-p1363" };
  if (alg === "EdDSA") return { hash: null };
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
  // Export the public half as a JWK so we can embed it in the header.
  var pub = nodeCrypto.createPublicKey(privateKey);
  try { return pub.export({ format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-dpop/bad-private-key",
      "could not derive public JWK: " + ((e && e.message) || String(e)));
  }
}

function _detectAlgFromKey(key) {
  // Best-effort algorithm detection from the key type. Operators can
  // override via opts.algorithm.
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
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-dpop/bad-jwk",
      "could not import jwk: " + ((e && e.message) || String(e)));
  }
}

// ---- buildProof ----

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

  var jwk = opts.jwk || _publicJwkFromPrivate(key);
  // Strip private parts from the embedded jwk if the operator passed a
  // private JWK by accident — ONLY public components belong in the proof.
  var pubJwk;
  if (jwk.kty === "EC") pubJwk = { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
  else if (jwk.kty === "OKP") pubJwk = { kty: "OKP", crv: jwk.crv, x: jwk.x };
  else if (jwk.kty === "RSA") pubJwk = { kty: "RSA", e: jwk.e, n: jwk.n };
  else if (jwk.kty === "AKP") pubJwk = { kty: "AKP", alg: jwk.alg, pub: jwk.pub };
  else throw new AuthError("auth-dpop/refused-kty",
    "jwk.kty='" + jwk.kty + "' is not allowed");

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

// ---- verify ----

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

  // Header checks
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
  // Refuse private-half-leak in the header (the proof must not embed
  // the private key — RFC 9449 §4.2 only public parameters).
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

  // Verify signature against the embedded jwk
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

  // Compute thumbprint for downstream binding (jkt → access-token cnf claim)
  var jkt = thumbprint(header.jwk);
  if (typeof opts.expectedThumbprint === "string" && opts.expectedThumbprint.length > 0) {
    if (!bCrypto.timingSafeEqual(jkt, opts.expectedThumbprint)) {
      throw new AuthError("auth-dpop/thumbprint-mismatch",
        "proof key thumbprint does not match expected");
    }
  }

  // Payload checks
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

  // ath — when caller supplies accessToken, payload MUST carry matching ath
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

  // nonce — when caller supplies expected nonce, payload MUST match.
  // Constant-time compare (audit 2026-05-15): the nonce is a server-
  // issued secret-shaped value matched against attacker-controlled
  // payload bytes. RFC 9449 §8 mandates the value be unpredictable;
  // a leaking compare reveals prefix bytes over many attempts. ath
  // already used timingSafeEqual; nonce now matches.
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

  // jti replay defense via b.nonceStore-shaped backend
  if (opts.replayStore !== undefined && opts.replayStore !== null) {
    validateOpts.optionalObjectWithMethod(
      opts.replayStore, "checkAndInsert",
      "verify: replayStore", AuthError, "auth-dpop/bad-replay-store",
      "must expose checkAndInsert(jti, expireAtMs) — use b.nonceStore.create()");
    var expireAtMs = nowMs + iatWindowSec * C.TIME.seconds(1) * 2;
    var inserted;
    try { inserted = await opts.replayStore.checkAndInsert(payload.jti, expireAtMs); }
    catch (e) {
      throw new AuthError("auth-dpop/replay-store-failed",
        "replayStore.checkAndInsert threw: " + ((e && e.message) || String(e)));
    }
    if (inserted === false) {
      throw new AuthError("auth-dpop/replay",
        "DPoP proof jti='" + payload.jti + "' has been seen before — replay refused");
    }
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
