// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.dbsc
 * @nav    Identity
 * @title  Device Bound Session Credentials
 * @order  378
 *
 * @intro
 *   IETF draft-ietf-oauth-attestation-based-client-auth + Chrome's
 *   DBSC proposal — binds an HTTP session to a browser-generated key
 *   pair so a stolen session cookie alone can't impersonate the user
 *   from a different device. The browser holds the private key in
 *   secure hardware; every refresh proves possession via a signed
 *   challenge.
 *
 *   Server flow:
 *     1. `b.dbsc.challenge()` — mint a random challenge, sign it
 *        with the operator's HMAC key for replay defense, return
 *        the challenge string + the `Sec-Session-Challenge` header
 *        value. The browser auto-resolves the challenge via the
 *        DBSC refresh endpoint.
 *     2. `b.dbsc.verifyBindingAssertion(jwt, { challenge, expectedAud })`
 *        — verify the browser-supplied JWT signed by the binding
 *        public key. Returns `{ valid, sub, jkt }` where `jkt` is
 *        the JWK thumbprint of the binding key.
 *
 *   Composes existing b.crypto + b.auth.jwt; DBSC mandates ES256 /
 *   RS256 (browser TPM hardware). The framework refuses HS256 /
 *   none on parsed JWTs.
 *
 * @card
 *   IETF DBSC challenge minter + binding-assertion verifier. Stops device-portable session theft by binding cookies to hardware keys.
 */

var nodeCrypto    = require("node:crypto");
var validateOpts  = require("./validate-opts");
var safeJson      = require("./safe-json");
var bCrypto       = require("./crypto");
var jwk           = require("./jwk");
var jwtExternal   = require("./auth/jwt-external");
var C             = require("./constants");
var { defineClass } = require("./framework-error");

var DbscError = defineClass("DbscError", { alwaysPermanent: true });

var DEFAULT_CHALLENGE_TTL_MS = C.TIME.minutes(5);

// Clock-skew allowance for a forward-dated `iat`. An assertion whose iat
// sits further ahead than this is refused: without an upper bound a future
// iat makes the stale check (Date.now() - iat*1000 > maxAge) permanently
// false, so the assertion never expires and the maxAge replay window is
// defeated. Mirrors the future-iat bound in b.auth.jwt.verifyExternal
// (iat-future) and dpop's ±window; sized to tolerate ordinary client clock
// drift without admitting a far-future token.
var IAT_FUTURE_SKEW_MS = C.TIME.minutes(1);

/**
 * @primitive b.dbsc.challenge
 * @signature b.dbsc.challenge(opts)
 * @since     0.10.16
 * @status    stable
 *
 * Mint a fresh DBSC challenge. Returns `{ challenge, expiresAt,
 * headerValue }` where `headerValue` is the `Sec-Session-Challenge`
 * value to set on the response. The challenge is HMAC-SHA3-512
 * signed so the server can verify the same challenge it issued
 * on the assertion-verify path without persisting it.
 *
 * @opts
 *   secretKey:    Buffer,     // operator HMAC secret (>=32 bytes)
 *   ttlMs:        number,     // default 5 minutes
 *   nonce:        string,     // optional caller-supplied nonce (default: 32-byte random)
 *
 * @example
 *   var c = b.dbsc.challenge({ secretKey: opSecret });
 *   res.setHeader("Sec-Session-Challenge", c.headerValue);
 */
function challenge(opts) {
  opts = validateOpts.requireObject(opts, "dbsc.challenge", DbscError, "dbsc/bad-opts");
  validateOpts(opts, ["secretKey", "ttlMs", "nonce"], "dbsc.challenge");
  if (!Buffer.isBuffer(opts.secretKey) || opts.secretKey.length < 32) {                               // 32-byte HMAC secret floor
    throw new DbscError("dbsc/bad-secret",
      "challenge: opts.secretKey must be a Buffer (>= 32 bytes)");
  }
  validateOpts.optionalPositiveFinite(opts.ttlMs, "dbsc.challenge: ttlMs",
    DbscError, "dbsc/bad-ttl");
  var ttlMs     = opts.ttlMs || DEFAULT_CHALLENGE_TTL_MS;
  var nonceBuf  = opts.nonce ? Buffer.from(String(opts.nonce), "utf8") : bCrypto.generateBytes(32);   // 32-byte nonce
  var expiresAt = Date.now() + ttlMs;
  var msg = nonceBuf.toString("base64") + "." + expiresAt;
  var mac = nodeCrypto.createHmac("sha3-512", opts.secretKey).update(msg).digest("base64");
  var challengeStr = msg + "." + mac;
  return {
    challenge:   challengeStr,
    expiresAt:   expiresAt,
    headerValue: challengeStr,
  };
}

/**
 * @primitive b.dbsc.verifyChallenge
 * @signature b.dbsc.verifyChallenge(challengeStr, { secretKey })
 * @since     0.10.16
 * @status    stable
 *
 * Verify a challenge string previously issued by `challenge()`.
 * Returns truthy when the HMAC matches and the challenge hasn't
 * expired. Refuses with typed errors on shape / expiry / MAC
 * mismatch.
 *
 * @example
 *   var ok = b.dbsc.verifyChallenge(req.headers["sec-session-challenge"],
 *     { secretKey: process.env.DBSC_HMAC_KEY });
 */
function verifyChallenge(challengeStr, opts) {
  opts = validateOpts.requireObject(opts, "dbsc.verifyChallenge",
    DbscError, "dbsc/bad-opts");
  if (typeof challengeStr !== "string") {
    throw new DbscError("dbsc/bad-challenge",
      "verifyChallenge: challenge must be a string");
  }
  if (!Buffer.isBuffer(opts.secretKey) || opts.secretKey.length < 32) {                               // 32-byte HMAC secret floor
    throw new DbscError("dbsc/bad-secret",
      "verifyChallenge: opts.secretKey must be a Buffer (>= 32 bytes)");
  }
  var parts = challengeStr.split(".");
  if (parts.length !== 3) {
    throw new DbscError("dbsc/bad-challenge-shape",
      "verifyChallenge: challenge must have 3 dot-separated parts");
  }
  var expiresAt = parseInt(parts[1], 10);
  if (!isFinite(expiresAt) || expiresAt <= 0) {
    throw new DbscError("dbsc/bad-expires",
      "verifyChallenge: expiresAt is not a positive integer");
  }
  if (Date.now() > expiresAt) {
    throw new DbscError("dbsc/expired",
      "verifyChallenge: challenge expired");
  }
  var msg = parts[0] + "." + parts[1];
  var expected = nodeCrypto.createHmac("sha3-512", opts.secretKey).update(msg).digest("base64");
  if (!bCrypto.timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(parts[2], "utf8"))) {
    throw new DbscError("dbsc/bad-mac",
      "verifyChallenge: HMAC mismatch (forged or wrong secret)");
  }
  return { valid: true, expiresAt: expiresAt };
}

/**
 * @primitive b.dbsc.verifyBindingAssertion
 * @signature b.dbsc.verifyBindingAssertion(assertion, opts)
 * @since     0.10.16
 * @status    stable
 *
 * Verify a DBSC binding-assertion JWT. The browser signs a JWT with
 * the device-bound private key whose header includes the JWK
 * thumbprint of the binding key. Returns `{ valid, jkt, claims }`.
 * Refuses HS256 / none (algorithm-confusion class) and any
 * mismatched audience / challenge.
 *
 * @opts
 *   secretKey:     Buffer,     // HMAC secret used by challenge() (for re-verify)
 *   expectedAud:   string,     // expected RP origin
 *   maxAgeSec:     number,     // default 300s
 *
 * @example
 *   var v = b.dbsc.verifyBindingAssertion(req.body, {
 *     secretKey:   opSecret,
 *     expectedAud: "https://rp.example",
 *   });
 *   if (!v.valid) throw 401;
 *   v.jkt;   // → JWK thumbprint of the binding key (use as a session pin)
 */
function verifyBindingAssertion(assertion, opts) {
  opts = validateOpts.requireObject(opts, "dbsc.verifyBindingAssertion",
    DbscError, "dbsc/bad-opts");
  validateOpts(opts, ["secretKey", "expectedAud", "maxAgeSec"],
    "dbsc.verifyBindingAssertion");
  if (typeof assertion !== "string") {
    throw new DbscError("dbsc/bad-assertion",
      "verifyBindingAssertion: assertion must be a string JWT");
  }
  validateOpts.requireNonEmptyString(opts.expectedAud, "expectedAud",
    DbscError, "dbsc/missing-aud");
  var parts = assertion.split(".");
  if (parts.length !== 3) {
    throw new DbscError("dbsc/bad-jwt-shape",
      "verifyBindingAssertion: JWT must have 3 parts");
  }
  var headerJson, payloadJson;
  try { headerJson  = safeJson.parse(Buffer.from(parts[0], "base64url").toString("utf8")); }
  catch (_e) { throw new DbscError("dbsc/bad-jwt-header", "JWT header is not parseable JSON"); }
  try { payloadJson = safeJson.parse(Buffer.from(parts[1], "base64url").toString("utf8")); }
  catch (_e) { throw new DbscError("dbsc/bad-jwt-payload", "JWT payload is not parseable JSON"); }
  // Algorithm-confusion defense — DBSC mandates ES256 / RS256 from
  // hardware-backed keys; refuse symmetric or none algs.
  if (headerJson.alg !== "ES256" && headerJson.alg !== "RS256") {
    throw new DbscError("dbsc/bad-alg",
      "verifyBindingAssertion: alg " + headerJson.alg + " refused (DBSC mandates ES256 / RS256)");
  }
  if (!headerJson.jwk || typeof headerJson.jwk !== "object") {
    throw new DbscError("dbsc/no-jwk",
      "verifyBindingAssertion: JWT header missing jwk (binding-key proof)");
  }
  // Verify the JWT signature against the embedded jwk (proof-of-
  // possession of the binding-key). Refuse alg/kty mismatches at the
  // import boundary (alg-confusion defense — JWT_KEY_CONFUSION-class
  // attacks pass an HS256 jwk for an ES256-claimed token).
  jwtExternal._assertAlgKtyMatch(headerJson.alg, headerJson.jwk);
  var pubKey = bCrypto.importPublicJwk(headerJson.jwk, {
    errorClass:    DbscError,
    code:          "dbsc/bad-jwk",
    messagePrefix: "verifyBindingAssertion: jwk could not be imported: ",
  });
  var signingInput = parts[0] + "." + parts[1];
  var sigBytes = Buffer.from(parts[2], "base64url");
  var ok;
  if (headerJson.alg === "ES256") {
    // JWT raw r||s → DER for nodeCrypto.verify.
    if (sigBytes.length !== 64) {                                                                     // P-256 r||s shape
      throw new DbscError("dbsc/bad-sig", "ES256 signature must be 64 bytes raw");
    }
    var derSig = _ecdsaRawToDer(sigBytes);
    ok = nodeCrypto.verify("sha256", Buffer.from(signingInput, "utf8"), pubKey, derSig);
  } else {
    ok = nodeCrypto.verify("sha256", Buffer.from(signingInput, "utf8"), pubKey, sigBytes);
  }
  if (!ok) {
    throw new DbscError("dbsc/bad-signature",
      "verifyBindingAssertion: JWT signature does not verify against embedded jwk");
  }
  // Validate audience + freshness.
  if (payloadJson.aud !== opts.expectedAud) {
    throw new DbscError("dbsc/bad-aud",
      "verifyBindingAssertion: aud '" + payloadJson.aud + "' != expected '" + opts.expectedAud + "'");
  }
  // Freshness — every assertion MUST carry either an `iat` (so the
  // age check below can reject stale tokens) or a `challenge` (so the
  // re-verify below pins the assertion to a server-issued nonce with
  // its own expiry). An assertion lacking both replays indefinitely
  // until the signing key rotates — refuse at the verifier boundary.
  if (typeof payloadJson.iat !== "number" && !payloadJson.challenge) {
    throw new DbscError("dbsc/no-freshness",
      "verifyBindingAssertion: assertion must carry either 'iat' (age-checked) " +
      "or 'challenge' (server-nonce-bound); without freshness material the " +
      "assertion replays indefinitely");
  }
  var maxAge = (opts.maxAgeSec || 300) * 1000;                                                        // allow:raw-time-literal — 5min default
  if (typeof payloadJson.iat === "number" && Date.now() - payloadJson.iat * 1000 > maxAge) {          // allow:raw-time-literal — sec→ms
    throw new DbscError("dbsc/stale",
      "verifyBindingAssertion: iat is more than " + opts.maxAgeSec + "s old");
  }
  // Upper-bound iat: a forward-dated assertion (beyond IAT_FUTURE_SKEW_MS)
  // is refused. A future iat makes the stale check above never fire, so the
  // assertion would stay "fresh" indefinitely — a freshness fail-open on an
  // attacker-chosen iat that defeats the maxAge replay bound.
  if (typeof payloadJson.iat === "number" && payloadJson.iat * 1000 - Date.now() > IAT_FUTURE_SKEW_MS) {   // allow:raw-time-literal — sec→ms
    throw new DbscError("dbsc/iat-future",
      "verifyBindingAssertion: iat is more than " + (IAT_FUTURE_SKEW_MS / C.TIME.seconds(1)) + "s in the future");
  }
  // Re-verify any embedded challenge if the assertion claims one.
  if (payloadJson.challenge) {
    verifyChallenge(payloadJson.challenge, { secretKey: opts.secretKey });
  }
  // Compute JWK thumbprint (RFC 7638) for operator-side session-pin.
  var jkt = _jwkThumbprint(headerJson.jwk);
  return { valid: true, jkt: jkt, claims: payloadJson };
}

function _ecdsaRawToDer(raw) {
  if (raw.length !== 64) throw new DbscError("dbsc/bad-sig", "raw r||s must be 64 bytes");            // P-256 r||s shape
  var r = _trimLeadingZeros(raw.slice(0, 32));                                                        // 32-byte r
  var s = _trimLeadingZeros(raw.slice(32));                                                           // 32-byte s offset
  function _intDer(buf) {
    // Prepend 0x00 if high bit set (positive INTEGER per DER).
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);                               // DER sign-bit pad
    return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);                                      // ASN.1 INTEGER tag
  }
  var rDer = _intDer(r);
  var sDer = _intDer(s);
  var seqBody = Buffer.concat([rDer, sDer]);
  return Buffer.concat([Buffer.from([0x30, seqBody.length]), seqBody]);                               // ASN.1 SEQUENCE tag
}

function _trimLeadingZeros(buf) {
  var i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i += 1;                                                // leading zero byte
  return buf.slice(i);
}

function _jwkThumbprint(key) {
  // RFC 7638 thumbprint (base64url(SHA-256(canonical JWK))) via b.jwk.
  try { return jwk.thumbprint(key); }
  catch (e) { throw new DbscError("dbsc/bad-jwk-kty", "jwkThumbprint: " + ((e && e.message) || "invalid jwk")); }
}

module.exports = {
  challenge:                challenge,
  verifyChallenge:          verifyChallenge,
  verifyBindingAssertion:   verifyBindingAssertion,
  DbscError:                DbscError,
};
