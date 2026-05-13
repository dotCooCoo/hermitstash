"use strict";
/**
 * jwt-external — verify JWTs signed by an external IdP using classical
 * algorithms (RS256 / RS384 / RS512 / PS256 / PS384 / PS512 / ES256 /
 * ES384 / ES512 / EdDSA).
 *
 * Distinct from `b.auth.jwt.verify` which is PQC-only (ML-DSA-65 etc.).
 * Operators integrating with Auth0 / Okta / Keycloak / AWS Cognito /
 * Azure AD / Google IdP / Apple-sign-in use this primitive — those IdPs
 * sign with classical algorithms and the framework's PQC verifier
 * cannot accept their tokens.
 *
 *   var rv = await b.auth.jwt.verifyExternal(token, {
 *     algorithms: ["RS256", "ES256"],          // REQUIRED — no defaults
 *     jwks:       jwksKeysArray,                // pre-fetched RFC 7517 keys
 *     // OR
 *     jwksUri:    "https://example.auth0.com/.well-known/jwks.json",
 *     jwksCacheMs: C.TIME.minutes(10),         // default 10m
 *     // OR
 *     keyResolver: async function (header) { return jwkOrKeyObject; },
 *
 *     audience:    "api://my-api",             // optional but recommended
 *     issuer:      "https://example.auth0.com/", // optional but recommended
 *     subject:     "user@example.com",         // optional sub-equality check
 *     clockSkewMs: 30 * 1000,                  // default 30s tolerance
 *   });
 *   // → { header, claims }   (throws AuthError on any failure)
 *
 * Defenses against the well-known JWT pitfalls:
 *
 *   - alg confusion (CVE-2024-54150 / CVE-2025-30144 / CVE-2026-22817
 *     Hono class) — `algorithms` is REQUIRED with no default; `none`,
 *     `HS256` cannot be accepted unless the operator explicitly listed
 *     them, and even then the verifier refuses HS* algs in
 *     verifyExternal because HMAC + a public-key JWKS is the canonical
 *     alg-confusion shape. Operators with HMAC need a different path.
 *   - kid spoofing — the resolved key MUST come from the operator's
 *     trust source (the JWKS array or operator's keyResolver). The
 *     header's `kid` only selects WHICH key from that source.
 *   - exp/nbf/iat — checked against now (with clockSkewMs tolerance).
 *   - aud / iss / sub — checked when the operator passes the expected
 *     value. iss MUST match exactly (not substring).
 *   - JWKS endpoint trust — `jwksUri` resolves through the framework's
 *     `b.httpClient` (SSRF gate, TLS-required by default, response-size
 *     cap). The jwksCache is per-process and TTL-bounded.
 *
 * Returns { header, claims } on success. Every failure surfaces as
 * AuthError with a code in `auth-jwt-external/<reason>` so operators
 * can route alerts on a single class.
 */

var nodeCrypto = require("crypto");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var { AuthError } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var cache      = lazyRequire(function () { return require("../cache"); });
var auditFwk   = lazyRequire(function () { return require("../audit"); });

// ---- constants ----

var DEFAULT_CLOCK_SKEW_MS = C.TIME.seconds(30);
var DEFAULT_JWKS_CACHE_MS = C.TIME.minutes(10);
var MAX_JWKS_BYTES        = C.BYTES.kib(64);
var MAX_TOKEN_BYTES       = C.BYTES.kib(16);

// HMAC-shaped algs (HS256/384/512) and "none" are NEVER accepted by
// this primitive. HMAC + a JWKS-shaped public-key trust source is the
// canonical alg-confusion vector; "none" is the canonical alg-bypass.
var REFUSED_ALGS = ["HS256", "HS384", "HS512", "none"];

// PSS salt lengths per RFC 7518 §3.5.
var PSS_SALT_SHA256 = 32;                                                        // allow:raw-byte-literal — RFC 7518 SHA-256 salt length
var PSS_SALT_SHA384 = 48;                                                        // allow:raw-byte-literal — RFC 7518 SHA-384 salt length
var PSS_SALT_SHA512 = 64;                                                        // allow:raw-byte-literal — RFC 7518 SHA-512 salt length

var SUPPORTED_CLASSICAL_ALGS = [
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA",
];

// ---- per-instance JWKS cache shared across calls ----

var _sharedJwksCache = null;
function _getJwksCache() {
  if (_sharedJwksCache) return _sharedJwksCache;
  _sharedJwksCache = cache().create({
    namespace: "auth-jwt-external.jwks",
    ttlMs:     DEFAULT_JWKS_CACHE_MS,
  });
  return _sharedJwksCache;
}

// ---- helpers ----

function _b64urlDecode(s) {
  if (typeof s !== "string") {
    throw new AuthError("auth-jwt-external/bad-base64", "expected base64url string");
  }
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";                                       // allow:raw-byte-literal — base64 quartet padding
  return Buffer.from(padded, "base64");
}

function _verifyParamsForAlg(alg) {
  if (alg === "RS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "PS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_SHA256 };
  if (alg === "PS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_SHA384 };
  if (alg === "PS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_SHA512 };
  if (alg === "ES256") return { hash: "sha256", dsaEncoding: "ieee-p1363" };
  if (alg === "ES384") return { hash: "sha384", dsaEncoding: "ieee-p1363" };
  if (alg === "ES512") return { hash: "sha512", dsaEncoding: "ieee-p1363" };
  if (alg === "EdDSA") return { hash: null };
  throw new AuthError("auth-jwt-external/unsupported-alg",
    "alg '" + alg + "' is not supported by verifyExternal");
}

function _jwkToKey(jwk) {
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-jwt-external/bad-jwk",
      "could not import JWK (kid=" + (jwk && jwk.kid) + "): " + ((e && e.message) || String(e)));
  }
}

function _toKey(value) {
  if (!value) {
    throw new AuthError("auth-jwt-external/no-key",
      "key resolution returned no value");
  }
  if (value instanceof nodeCrypto.KeyObject) return value;
  if (typeof value === "object" && value.kty) return _jwkToKey(value);
  if (typeof value === "string") {
    try { return nodeCrypto.createPublicKey({ key: value, format: "pem" }); }
    catch (e) {
      throw new AuthError("auth-jwt-external/bad-pem",
        "PEM parse failed: " + ((e && e.message) || String(e)));
    }
  }
  if (Buffer.isBuffer(value)) {
    try { return nodeCrypto.createPublicKey({ key: value, format: "pem" }); }
    catch (e) {
      throw new AuthError("auth-jwt-external/bad-pem",
        "PEM parse failed: " + ((e && e.message) || String(e)));
    }
  }
  throw new AuthError("auth-jwt-external/bad-key-shape",
    "key must be a JWK object, PEM string/Buffer, or KeyObject");
}

async function _fetchJwks(uri, cacheMs) {
  // Validate the URI and fetch via http-client (SSRF gate, response-
  // size cap, TLS-required by default).
  safeUrl.parse(uri, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  var jc = _getJwksCache();
  var key = "jwks:" + uri;
  return await jc.wrap(key, async function () {
    var res = await httpClient().request({
      method:        "GET",
      url:           uri,
      maxBytes:      MAX_JWKS_BYTES,
      timeoutMs:     C.TIME.seconds(10),
    });
    if (res.statusCode < 200 || res.statusCode >= 300) {                         // allow:raw-byte-literal — HTTP 2xx range
      throw new AuthError("auth-jwt-external/jwks-fetch-failed",
        "JWKS endpoint " + uri + " returned " + res.statusCode);
    }
    var jwks;
    try { jwks = safeJson.parse(res.body.toString("utf8"), { maxBytes: MAX_JWKS_BYTES }); }
    catch (e) {
      throw new AuthError("auth-jwt-external/jwks-parse-failed",
        "JWKS parse failed: " + ((e && e.message) || String(e)));
    }
    if (!jwks || !Array.isArray(jwks.keys)) {
      throw new AuthError("auth-jwt-external/bad-jwks",
        "JWKS response missing 'keys' array");
    }
    return jwks.keys;
  }, cacheMs || DEFAULT_JWKS_CACHE_MS);
}

function _selectKey(keys, header, vopts) {
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new AuthError("auth-jwt-external/no-jwks-keys",
      "JWKS source has no keys");
  }
  if (header.kid) {
    for (var i = 0; i < keys.length; i += 1) {
      if (keys[i].kid === header.kid) return keys[i];
    }
    throw new AuthError("auth-jwt-external/no-matching-kid",
      "no JWKS key matches header.kid='" + header.kid + "'");
  }
  // Refuse kid-less tokens by default (audit 2026-05-11). JWKS
  // rotation creates a window where the rotated-out key is still
  // cached but the rotated-in key is already published; an
  // attacker shipping a kid-less token gets the lone-key path
  // during that window. Modern IdPs always emit kid. Operators
  // with non-conforming issuers opt in via vopts.allowKidlessJwks
  // = true (logged via the caller's audit hook).
  if (keys.length === 1 && vopts && vopts.allowKidlessJwks === true) return keys[0];
  throw new AuthError("auth-jwt-external/kid-required",
    "JWKS has " + keys.length + " key(s) but token header has no kid — " +
    "framework refuses kid-less tokens to defend against JWKS-rotation " +
    "key-pick attacks (pass vopts.allowKidlessJwks: true to opt out)");
}

// ---- public surface ----

async function verifyExternal(token, opts) {
  if (typeof token !== "string" || token.length === 0) {
    throw new AuthError("auth-jwt-external/no-token", "token must be a non-empty string");
  }
  if (token.length > MAX_TOKEN_BYTES) {
    throw new AuthError("auth-jwt-external/token-too-large",
      "token exceeds " + MAX_TOKEN_BYTES + " bytes");
  }
  opts = opts || {};
  validateOpts(opts, [
    "algorithms", "jwks", "jwksUri", "jwksCacheMs", "keyResolver",
    "audience", "issuer", "subject", "clockSkewMs",
    // v0.9.4 — opt-out for the kid-less-token JWKS-of-one refusal
    // (default refuses; non-conforming IdPs that emit kid-less tokens
    // set this true). Audit 2026-05-11.
    "allowKidlessJwks",
  ], "auth.jwt.verifyExternal");

  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new AuthError("auth-jwt-external/algorithms-required",
      "verifyExternal: opts.algorithms is required (no defaults — operator MUST " +
      "name accepted algorithms to defend against alg-confusion)");
  }
  for (var ai = 0; ai < opts.algorithms.length; ai += 1) {
    var listed = opts.algorithms[ai];
    if (REFUSED_ALGS.indexOf(listed) !== -1) {
      throw new AuthError("auth-jwt-external/refused-alg",
        "verifyExternal refuses '" + listed + "' (HMAC/none is the alg-confusion vector " +
        "against JWKS-shaped public-key trust sources)");
    }
    if (SUPPORTED_CLASSICAL_ALGS.indexOf(listed) === -1) {
      throw new AuthError("auth-jwt-external/unsupported-alg",
        "alg '" + listed + "' is not supported (supported: " +
        SUPPORTED_CLASSICAL_ALGS.join(", ") + ")");
    }
  }
  var sourcesGiven = (opts.jwks ? 1 : 0) + (opts.jwksUri ? 1 : 0) +
                     (typeof opts.keyResolver === "function" ? 1 : 0);
  if (sourcesGiven === 0) {
    throw new AuthError("auth-jwt-external/no-key-source",
      "verifyExternal: pass exactly one of jwks, jwksUri, keyResolver");
  }
  if (sourcesGiven > 1) {
    throw new AuthError("auth-jwt-external/conflicting-key-source",
      "verifyExternal: pass exactly one of jwks, jwksUri, keyResolver");
  }

  // Decode header + payload.
  var parts = token.split(".");
  // CVE-2026-29000 / CVE-2026-23993 / CVE-2026-22817 / CVE-2026-34950 —
  // JWE-bypass + alg-confusion. A 5-segment compact serialization is a
  // JWE (RFC 7516); accepting it on a JWS verifier is the canonical
  // confused-deputy shape. verifyExternal is JWS-only; refuse JWE
  // outright. Operators with JWE need a separate handler wired to
  // their KMS — never a defaulted JWE path on the JWS verifier.
  if (parts.length === 5) {
    try { auditFwk().safeEmit({
      action:   "jwt.jwe.refused",
      outcome:  "denied",
      metadata: { reason: "jwe-on-jws-verifier" },
    }); } catch (_e) { /* audit best-effort */ }
    throw new AuthError("auth-jwt-external/jwe-refused",
      "5-segment JWE token refused — verifyExternal only handles JWS " +
      "(JWE bypass class — CVE-2026-29000 / CVE-2026-23993 / CVE-2026-22817 / CVE-2026-34950)");
  }
  if (parts.length !== 3) {
    throw new AuthError("auth-jwt-external/malformed-jwt",
      "token does not have 3 parts");
  }
  var header, payload;
  try {
    header  = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8"), { maxBytes: MAX_JWKS_BYTES });
    payload = safeJson.parse(_b64urlDecode(parts[1]).toString("utf8"), { maxBytes: MAX_JWKS_BYTES });
  } catch (e) {
    throw new AuthError("auth-jwt-external/malformed-jwt",
      "header/payload decode failed: " + ((e && e.message) || String(e)));
  }
  if (!header || typeof header.alg !== "string") {
    throw new AuthError("auth-jwt-external/malformed-jwt", "header missing 'alg'");
  }
  if (header.crit !== undefined) {
    throw new AuthError("auth-jwt-external/unknown-crit",
      "token declares 'crit' header — verifyExternal does not support critical extensions");
  }
  if (opts.algorithms.indexOf(header.alg) === -1) {
    throw new AuthError("auth-jwt-external/alg-not-allowed",
      "token alg='" + header.alg + "' not in allowed list [" + opts.algorithms.join(", ") + "]");
  }

  // Resolve key.
  var key;
  if (typeof opts.keyResolver === "function") {
    var resolved;
    try { resolved = await opts.keyResolver(header); }
    catch (e) {
      throw new AuthError("auth-jwt-external/key-resolver-failed",
        "keyResolver threw: " + ((e && e.message) || String(e)));
    }
    key = _toKey(resolved);
  } else {
    var keys = opts.jwks ? opts.jwks
                         : await _fetchJwks(opts.jwksUri, opts.jwksCacheMs);
    var jwk = _selectKey(keys, header, opts);
    key = _jwkToKey(jwk);
  }

  // Verify signature.
  var params = _verifyParamsForAlg(header.alg);
  var signingInput = parts[0] + "." + parts[1];
  var sig = _b64urlDecode(parts[2]);
  var verifyOpts = { key: key };
  if (params.padding !== undefined)     verifyOpts.padding     = params.padding;
  if (params.saltLength !== undefined)  verifyOpts.saltLength  = params.saltLength;
  if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
  var verified;
  try {
    verified = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
  } catch (e) {
    throw new AuthError("auth-jwt-external/invalid-signature",
      "signature verification failed: " + ((e && e.message) || String(e)));
  }
  if (!verified) {
    throw new AuthError("auth-jwt-external/invalid-signature",
      "signature verification failed");
  }

  // Claim validation.
  var clockSkewMs = typeof opts.clockSkewMs === "number" ? opts.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  var nowSec   = Math.floor(Date.now() / C.TIME.seconds(1));
  var skewSec  = Math.floor(clockSkewMs / C.TIME.seconds(1));

  if (typeof payload.exp !== "number") {
    throw new AuthError("auth-jwt-external/missing-exp", "claim 'exp' missing");
  }
  if (payload.exp + skewSec < nowSec) {
    throw new AuthError("auth-jwt-external/expired",
      "token expired (exp=" + payload.exp + ", now=" + nowSec + ")");
  }
  if (typeof payload.nbf === "number" && payload.nbf - skewSec > nowSec) {
    throw new AuthError("auth-jwt-external/nbf-future",
      "token not-yet-valid (nbf=" + payload.nbf + ", now=" + nowSec + ")");
  }
  if (typeof payload.iat === "number" && payload.iat - skewSec > nowSec) {
    throw new AuthError("auth-jwt-external/iat-future",
      "token iat is in the future");
  }

  if (opts.audience) {
    var aud = payload.aud;
    var expectedAud = Array.isArray(opts.audience) ? opts.audience : [opts.audience];
    var actualAud = Array.isArray(aud) ? aud : (typeof aud === "string" ? [aud] : []);
    var audMatch = false;
    for (var ej = 0; ej < expectedAud.length; ej += 1) {
      if (actualAud.indexOf(expectedAud[ej]) !== -1) { audMatch = true; break; }
    }
    if (!audMatch) {
      throw new AuthError("auth-jwt-external/aud-mismatch",
        "token aud '" + JSON.stringify(aud) + "' does not match expected '" +
        JSON.stringify(opts.audience) + "'");
    }
  }
  if (opts.issuer && payload.iss !== opts.issuer) {
    throw new AuthError("auth-jwt-external/iss-mismatch",
      "token iss '" + payload.iss + "' does not match expected '" + opts.issuer + "'");
  }
  if (opts.subject && payload.sub !== opts.subject) {
    throw new AuthError("auth-jwt-external/sub-mismatch",
      "token sub '" + payload.sub + "' does not match expected '" + opts.subject + "'");
  }

  return { header: header, claims: payload };
}

module.exports = {
  verifyExternal:           verifyExternal,
  SUPPORTED_CLASSICAL_ALGS: SUPPORTED_CLASSICAL_ALGS,
  REFUSED_ALGS:             REFUSED_ALGS,
};
