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
 *   - alg confusion (CVE-2024-54150 / CVE-2026-22817 Hono class) —
 *     `algorithms` is REQUIRED with no default; `none`,
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

var nodeCrypto = require("node:crypto");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var bCrypto = require("../crypto");
var { AuthError } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var cache      = lazyRequire(function () { return require("../cache"); });
var audit      = lazyRequire(function () { return require("../audit"); });

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
var PSS_SALT_SHA256 = 32;                                                        // RFC 7518 SHA-256 salt length
var PSS_SALT_SHA384 = 48;                                                        // RFC 7518 SHA-384 salt length
var PSS_SALT_SHA512 = 64;                                                        // RFC 7518 SHA-512 salt length

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
  while (padded.length % 4) padded += "=";                                       // base64 quartet padding
  return Buffer.from(padded, "base64");
}

// EC named-curve → the one ES* alg whose hash matches it (RFC 7518 §3.4).
// A P-256 key signs ES256 and only ES256; the curve fixes the hash, so a
// header alg of ES384 over a P-256 signature is self-inconsistent and a
// conforming verifier rejects it. Naming the binding here lets the signer
// derive the right header alg from the key instead of trusting a caller-
// supplied alg the key can't actually produce.
var _EC_CURVE_ALG = { prime256v1: "ES256", secp384r1: "ES384", secp521r1: "ES512" };

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

// _toPrivateKey — import the operator's classical signing key from any of
// the three shapes node:crypto understands (KeyObject / PEM string|Buffer /
// private JWK). The PQC framework signer (lib/auth/jwt.js) never travels
// this path; this is the classical-interop importer only.
function _toPrivateKey(value, label) {
  if (!value) {
    throw new AuthError("auth-jwt-external/sign-no-key", label + ": privateKey is required");
  }
  if (value instanceof nodeCrypto.KeyObject) return value;
  try {
    if (typeof value === "string" || Buffer.isBuffer(value)) {
      return nodeCrypto.createPrivateKey({ key: value, format: "pem" });
    }
    if (typeof value === "object" && value.kty) {
      return nodeCrypto.createPrivateKey({ key: value, format: "jwk" });
    }
  } catch (e) {
    throw new AuthError("auth-jwt-external/sign-bad-key",
      label + ": private key parse failed: " + ((e && e.message) || String(e)));
  }
  throw new AuthError("auth-jwt-external/sign-bad-key",
    label + ": privateKey must be a PEM string/Buffer, private JWK object, or KeyObject");
}

// _resolveSignAlg — derive the JWS `alg` for a private key, validating any
// explicit override against what the key can actually produce. A signer
// that emitted a fixed `alg` header while signing with an incompatible key
// (e.g. an `ES256` header over an Ed25519 signature) would mint a token no
// conforming verifier accepts; deriving the alg from the key — or refusing
// an incompatible explicit alg BEFORE signing — closes that self-invalid
// shape. RFC 7518 §3.1 maps each `alg` to the key type it requires.
function _resolveSignAlg(explicitAlg, privateKey, label) {
  var kty = privateKey.asymmetricKeyType;
  var defaultAlg, compatible;
  if (kty === "ec") {
    var curve = (privateKey.asymmetricKeyDetails && privateKey.asymmetricKeyDetails.namedCurve) || "";
    defaultAlg = _EC_CURVE_ALG[curve];
    if (!defaultAlg) {
      throw new AuthError("auth-jwt-external/sign-key-unsupported",
        label + ": EC curve '" + curve + "' has no JWS alg (use P-256 / P-384 / P-521)");
    }
    compatible = [defaultAlg];                       // an EC curve pins exactly one ES alg
  } else if (kty === "rsa") {
    defaultAlg = "RS256";
    compatible = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
  } else if (kty === "rsa-pss") {
    defaultAlg = "PS256";
    compatible = ["PS256", "PS384", "PS512"];        // an RSA-PSS key cannot produce an RS* signature
  } else if (kty === "ed25519" || kty === "ed448") {
    defaultAlg = "EdDSA";
    compatible = ["EdDSA"];
  } else {
    throw new AuthError("auth-jwt-external/sign-key-unsupported",
      label + ": key type '" + String(kty) + "' is not a supported JWS signing key (EC / RSA / Ed25519 / Ed448)");
  }
  if (explicitAlg === undefined || explicitAlg === null) return defaultAlg;
  if (explicitAlg === "none" || REFUSED_ALGS.indexOf(explicitAlg) !== -1) {
    throw new AuthError("auth-jwt-external/sign-alg-refused",
      label + ": alg '" + explicitAlg + "' is refused (HMAC / none are never valid for an asymmetric signer)");
  }
  if (SUPPORTED_CLASSICAL_ALGS.indexOf(explicitAlg) === -1) {
    throw new AuthError("auth-jwt-external/sign-alg-unsupported",
      label + ": alg '" + explicitAlg + "' is not a supported classical JWS algorithm (" +
      SUPPORTED_CLASSICAL_ALGS.join(", ") + ")");
  }
  if (compatible.indexOf(explicitAlg) === -1) {
    throw new AuthError("auth-jwt-external/sign-alg-key-mismatch",
      label + ": alg '" + explicitAlg + "' is incompatible with the " + kty +
      " key (compatible: " + compatible.join(", ") + ")");
  }
  return explicitAlg;
}

// _signCompactJws — produce the compact JWS serialization (protected
// header . payload . signature) for an already-resolved alg + imported
// private key. Header and payload are JCS-independent here: they are
// serialized exactly once by the signer, base64url-encoded, and that byte
// string IS the signing input, so there is no canonicalization gap a
// verifier could diverge on.
function _signCompactJws(header, payload, privateKey, alg) {
  var params = _verifyParamsForAlg(alg);
  var headerB64  = bCrypto.toBase64Url(Buffer.from(JSON.stringify(header), "utf8"));
  var payloadB64 = bCrypto.toBase64Url(Buffer.from(JSON.stringify(payload), "utf8"));
  var signingInput = headerB64 + "." + payloadB64;
  var input = Buffer.from(signingInput, "ascii");
  var sig;
  if (params.hash === null) {
    sig = nodeCrypto.sign(null, input, privateKey);     // EdDSA — no prehash
  } else {
    var keyParam = { key: privateKey };
    if (params.padding !== undefined)     keyParam.padding     = params.padding;
    if (params.saltLength !== undefined)  keyParam.saltLength  = params.saltLength;
    if (params.dsaEncoding !== undefined) keyParam.dsaEncoding = params.dsaEncoding;
    sig = nodeCrypto.sign(params.hash, input, keyParam);
  }
  return signingInput + "." + bCrypto.toBase64Url(sig);
}

function _jwkToKey(jwk) {
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) {
    throw new AuthError("auth-jwt-external/bad-jwk",
      "could not import JWK (kid=" + (jwk && jwk.kid) + "): " + ((e && e.message) || String(e)));
  }
}

// CVE-2026-22817 — RS256→HS256 alg-confusion + the broader alg/kty
// confused-deputy class. The header `alg` is attacker-controlled; the
// JWK's `kty` (and `crv` for EC / OKP) describes what the resolved key
// actually IS. Without a cross-check, a server that resolved an RSA
// public key (RS256/PS256 family) can be tricked into accepting a token
// declaring `alg: "HS256"` — Node's verify() treats the RSA public key
// bytes as an HMAC secret and the signature verifies. Equivalent
// confusion lives between EC (ES*) and RSA (RS*/PS*) when the issuer
// publishes both key types under one kid scheme. Crossing alg → expected
// kty/crv BEFORE handing the JWK to node:crypto closes the class.
//
// Routed through from oauth.verifyIdToken / jwt-external.verifyExternal /
// oid4vci proof verify / sd-jwt-vc.verify / openid-federation.verifyEntityStatement
// per the v0.9.x audit (CVE-2026-22817 column).
//
// RFC 7518 §3 maps the JWS `alg` to the key shape it requires:
//   RS*/PS*  → kty=RSA
//   ES256    → kty=EC, crv=P-256
//   ES384    → kty=EC, crv=P-384
//   ES512    → kty=EC, crv=P-521
//   EdDSA    → kty=OKP (crv=Ed25519 or Ed448)
//   ML-DSA-* → kty=AKP, alg=<algId>      (draft-ietf-cose-cnsa-pqc)
function _assertAlgKtyMatch(alg, jwk) {
  if (typeof alg !== "string" || alg.length === 0) {
    throw new AuthError("auth-jwt-external/bad-alg",
      "_assertAlgKtyMatch: alg must be a non-empty string");
  }
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") {
    throw new AuthError("auth-jwt-external/bad-jwk",
      "_assertAlgKtyMatch: JWK must declare kty");
  }
  var expectedKty = null;
  var expectedCrv = null;
  if (alg === "RS256" || alg === "RS384" || alg === "RS512" ||
      alg === "PS256" || alg === "PS384" || alg === "PS512") {
    expectedKty = "RSA";
  } else if (alg === "ES256") { expectedKty = "EC"; expectedCrv = "P-256"; }
  else if   (alg === "ES384") { expectedKty = "EC"; expectedCrv = "P-384"; }
  else if   (alg === "ES512") { expectedKty = "EC"; expectedCrv = "P-521"; }
  else if   (alg === "EdDSA") { expectedKty = "OKP"; }
  else if   (alg === "ML-DSA-65" || alg === "ML-DSA-87") { expectedKty = "AKP"; }
  else {
    // Unknown alg — caller's alg allowlist should have rejected first;
    // refuse here defensively (CWE-347 alg-confusion class — unknown-alg
    // paths that skip downstream verification; cf. CVE-2026-22817).
    throw new AuthError("auth-jwt-external/unsupported-alg",
      "_assertAlgKtyMatch: alg '" + alg + "' has no defined key-type binding");
  }
  if (jwk.kty !== expectedKty) {
    throw new AuthError("auth-jwt-external/alg-kty-mismatch",
      "JWS alg '" + alg + "' requires JWK kty='" + expectedKty +
      "' but resolved JWK has kty='" + jwk.kty + "' (CVE-2026-22817 — alg confusion)");
  }
  if (expectedCrv && jwk.crv !== expectedCrv) {
    throw new AuthError("auth-jwt-external/alg-crv-mismatch",
      "JWS alg '" + alg + "' requires JWK crv='" + expectedCrv +
      "' but resolved JWK has crv='" + (jwk.crv || "<absent>") + "' (CVE-2026-22817 — curve confusion)");
  }
}

// Constant-time issuer comparison (CVE-2026-23552 — cross-realm/issuer
// JWT acceptance via weak iss validation). Both sides are
// operator-supplied strings; a non-CT compare leaks length / prefix
// timing that lets an attacker narrow which realm prefix the verifier
// accepts. cryptoTimingSafeEqual handles unequal-length safely and
// returns false rather than throwing.
function _issuerMatches(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  return bCrypto.timingSafeEqual(actual, expected);
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
    if (res.statusCode < 200 || res.statusCode >= 300) {                         // HTTP 2xx range
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
  // Refuse kid-less tokens by default. JWKS
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
    // set this true).
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
  // CVE-2026-29000 / CVE-2026-22817 / CVE-2026-34950 —
  // JWE-bypass + alg-confusion. A 5-segment compact serialization is a
  // JWE (RFC 7516); accepting it on a JWS verifier is the canonical
  // confused-deputy shape. verifyExternal is JWS-only; refuse JWE
  // outright. Operators with JWE need a separate handler wired to
  // their KMS — never a defaulted JWE path on the JWS verifier.
  if (parts.length === 5) {
    try { audit().safeEmit({
      action:   "jwt.jwe.refused",
      outcome:  "denied",
      metadata: { reason: "jwe-on-jws-verifier" },
    }); } catch (_e) { /* audit best-effort */ }
    throw new AuthError("auth-jwt-external/jwe-refused",
      "5-segment JWE token refused — verifyExternal only handles JWS " +
      "(JWE bypass class — CVE-2026-29000 / CVE-2026-22817 / CVE-2026-34950)");
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
  // Alg-allowlist gate (CWE-347 improper-sig-verification / CWE-757
  // algorithm-downgrade) — refuse alg values outside the accepted list
  // BEFORE any key lookup. The early refusal closes the class where an
  // unknown / unsupported alg slips through to a downstream code path
  // that interprets it permissively. The per-listed algorithm check
  // above in the opts-validation loop refuses the OPERATOR'S allowlist
  // shape; this check refuses the TOKEN'S declared alg before any
  // key-resolver / JWKS-fetch side effect.
  if (opts.algorithms.indexOf(header.alg) === -1) {
    throw new AuthError("auth-jwt-external/alg-not-allowed",
      "token alg='" + header.alg + "' not in allowed list [" + opts.algorithms.join(", ") +
      "] (alg-allowlist gate — refused before key lookup)");
  }
  if (SUPPORTED_CLASSICAL_ALGS.indexOf(header.alg) === -1) {
    throw new AuthError("auth-jwt-external/unsupported-alg",
      "token alg='" + header.alg + "' is not in the verifier's supported set (alg-allowlist gate)");
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
    // When keyResolver returns a JWK object, cross-check alg/kty BEFORE
    // _toKey hands it to node:crypto (CVE-2026-22817). PEM / KeyObject
    // shapes can't carry a kty surface so the check happens at JWKS
    // resolution only.
    if (resolved && typeof resolved === "object" &&
        !(resolved instanceof nodeCrypto.KeyObject) &&
        !Buffer.isBuffer(resolved) &&
        typeof resolved.kty === "string") {
      _assertAlgKtyMatch(header.alg, resolved);
    }
    key = _toKey(resolved);
  } else {
    var keys = opts.jwks ? opts.jwks
                         : await _fetchJwks(opts.jwksUri, opts.jwksCacheMs);
    var jwk = _selectKey(keys, header, opts);
    // CVE-2026-22817 — cross-check alg/kty BEFORE importing the JWK as
    // a key object. Without this an attacker-controlled `alg: "HS256"`
    // against an RSA-kty JWK would have node:crypto.verify treat the
    // RSA public key as an HMAC secret.
    _assertAlgKtyMatch(header.alg, jwk);
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
  if (opts.issuer) {
    // CVE-2026-23552 — cross-realm / cross-issuer JWT acceptance via
    // weak iss validation. Constant-time compare defeats prefix-timing
    // narrowing; emit a DISTINCT audit event (separate from sig-verify-
    // fail) so detection signals lights up on the cross-realm shape
    // independently of generic verification failures. The `typeof ... !==
    // "string"` guard also rejects an array-valued iss (CVE-2025-30144,
    // fast-jwt — an iss array `["attacker", "valid"]` passed an any-match
    // check); only a single string iss is accepted.
    if (typeof payload.iss !== "string" ||
        !_issuerMatches(payload.iss, opts.issuer)) {
      try { audit().safeEmit({
        action:   "jwt.iss.mismatch",
        outcome:  "denied",
        metadata: {
          expectedIssuer: opts.issuer,
          // payload.iss is attacker-controlled, but logging it for
          // detection is the point — operators correlate against
          // their tenant table to identify cross-realm probes.
          presentedIssuer: typeof payload.iss === "string" ? payload.iss : null,
          reason: "cross-realm-jwt-refused",
        },
      }); } catch (_e) { /* drop-silent — observability sink */ }
      throw new AuthError("auth-jwt-external/iss-mismatch",
        "token iss '" + payload.iss + "' does not match expected '" + opts.issuer +
        "' (CVE-2026-23552 — cross-realm refused)");
    }
  }
  if (opts.subject && payload.sub !== opts.subject) {
    throw new AuthError("auth-jwt-external/sub-mismatch",
      "token sub '" + payload.sub + "' does not match expected '" + opts.subject + "'");
  }

  return { header: header, claims: payload };
}

/**
 * @primitive b.auth.jws.sign
 * @signature b.auth.jws.sign(claims, opts)
 * @since     0.14.22
 * @status    stable
 * @compliance soc2
 * @related   b.auth.jar.build, b.auth.jar.parse
 *
 * Mint a compact JWS (RFC 7515) over <code>claims</code> using a classical
 * asymmetric algorithm — RS/PS256/384/512, ES256/384/512, or EdDSA. This
 * primitive exists strictly for <strong>interop with external ecosystems</strong>:
 * OAuth/OIDC OPs and RPs (and the wallet / FAPI profiles built on them)
 * require a request object / assertion signed with a classical JWS alg, and
 * the framework's own token signer (<code>b.auth.jwt.sign</code>) is
 * PQC-only (ML-DSA / SLH-DSA). It is <strong>never the framework-internal
 * token default</strong>; <code>lib/jwt.js</code> remains the signer for
 * tokens blamejs itself issues. The verify counterpart is
 * <code>b.auth.jwt.verifyExternal</code>; this is its inverse for the cases
 * where blamejs is the client emitting a signed object to a third party.
 *
 * The signing <code>alg</code> is derived from the key type (RFC 7518 §3.1)
 * so the header alg always matches the signature the key can actually
 * produce; an explicit <code>opts.alg</code> is validated against the key
 * and refused if incompatible. <code>alg: "none"</code> and HMAC algs are
 * refused outright — an asymmetric signer never emits them. The protected
 * header always carries <code>alg</code>; <code>typ</code> and <code>kid</code>
 * are set from <code>opts</code> when supplied (callers minting a typed
 * object such as a JAR request object pass <code>typ</code>). Extra
 * <code>opts.header</code> members pass through with two refusals:
 * <code>b64</code> (RFC 7797 unencoded payload — it changes the signing
 * input, which this signer always base64url-encodes) and <code>crit</code>
 * (RFC 7515 §4.1.11 — it promises extension semantics the signer does not
 * implement). Emitting either would produce a JWS whose header claims
 * semantics its signature was not computed under.
 *
 * @opts
 *   {
 *     privateKey:  KeyObject|PEM|JWK,  // required — classical signing key
 *     alg?:        string,             // override; default inferred from the key (RS256 / ES256/384/512 / PS256 / EdDSA)
 *     typ?:        string,             // protected-header typ (e.g. "oauth-authz-req+jwt")
 *     kid?:        string,             // protected-header kid (JWKS key selection)
 *     header?:     object,             // extra protected-header members (alg/typ/kid reserved; b64/crit refused)
 *   }
 *
 * @example
 *   var jws = b.auth.jws.sign(
 *     { iss: "client", aud: "https://as.example.com", response_type: "code" },
 *     { privateKey: clientKey, typ: "oauth-authz-req+jwt", kid: "c1" });
 *   // → "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ..."
 */
function signExternal(claims, opts) {
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new AuthError("auth-jwt-external/sign-bad-claims",
      "jws.sign: claims must be a plain object");
  }
  validateOpts.requireObject(opts, "jws.sign", AuthError, "auth-jwt-external/sign-bad-opts");
  validateOpts(opts, ["privateKey", "alg", "typ", "kid", "header"], "auth.jws.sign");
  if (opts.alg !== undefined && opts.alg !== null) {
    validateOpts.requireNonEmptyString(opts.alg, "jws.sign: alg", AuthError, "auth-jwt-external/sign-bad-alg");
  }
  if (opts.typ !== undefined && opts.typ !== null) {
    validateOpts.requireNonEmptyString(opts.typ, "jws.sign: typ", AuthError, "auth-jwt-external/sign-bad-typ");
  }
  if (opts.kid !== undefined && opts.kid !== null) {
    validateOpts.requireNonEmptyString(opts.kid, "jws.sign: kid", AuthError, "auth-jwt-external/sign-bad-kid");
  }
  validateOpts.optionalPlainObject(opts.header, "jws.sign: header", AuthError, "auth-jwt-external/sign-bad-header",
    "must be a plain object of extra protected-header members");
  // RFC 7797 `b64: false` changes the JWS signing input (the payload is
  // signed raw, not base64url-encoded) and RFC 7515 §4.1.11 `crit`
  // promises the producer implements every extension it names.
  // _signCompactJws always base64url-encodes the payload and implements
  // no header extensions, so passing either member through would mint a
  // JWS whose header advertises semantics its signature was not computed
  // under — a compliant verifier derives a different signing input (or
  // refuses the critical header). Refused until those semantics are
  // actually implemented.
  if (opts.header !== undefined && opts.header !== null &&
      (Object.prototype.hasOwnProperty.call(opts.header, "b64") ||
       Object.prototype.hasOwnProperty.call(opts.header, "crit"))) {
    throw new AuthError("auth-jwt-external/sign-unsupported-header",
      "jws.sign: header members 'b64' (RFC 7797 unencoded payload) and 'crit' " +
      "(RFC 7515 §4.1.11 critical extensions) are not supported — the signer " +
      "always base64url-encodes the payload and implements no critical extensions");
  }

  var key = _toPrivateKey(opts.privateKey, "jws.sign");
  var alg = _resolveSignAlg(opts.alg, key, "jws.sign");

  // Extra protected-header members first (alg/typ/kid reserved so a
  // caller-supplied header object can never override the signer-set alg —
  // the canonical alg-substitution shape), then the reserved members.
  var header = validateOpts.assignOwnEnumerable({}, opts.header, ["alg", "typ", "kid"]);
  header.alg = alg;
  if (opts.typ !== undefined && opts.typ !== null) header.typ = opts.typ;
  if (opts.kid !== undefined && opts.kid !== null) header.kid = opts.kid;

  return _signCompactJws(header, claims, key, alg);
}

module.exports = {
  verifyExternal:           verifyExternal,
  signExternal:             signExternal,
  SUPPORTED_CLASSICAL_ALGS: SUPPORTED_CLASSICAL_ALGS,
  REFUSED_ALGS:             REFUSED_ALGS,
  // Shared JOSE defenses — routed from oauth.verifyIdToken /
  // oid4vci proof verify / sd-jwt-vc.verify / openid-federation.
  _assertAlgKtyMatch:       _assertAlgKtyMatch,
  _issuerMatches:           _issuerMatches,
  // Classical-JWS signer internals — composed by oauth.js's attestation
  // builders so the alg-from-key + compact-JWS bodies live in exactly one
  // place (the classical-JOSE domain owner).
  _toPrivateKey:            _toPrivateKey,
  _resolveSignAlg:          _resolveSignAlg,
  _signCompactJws:          _signCompactJws,
};
