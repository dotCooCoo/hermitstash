// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var cache = require("../cache");
var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var safeAsync = require("../safe-async");
var bCrypto = require("../crypto");
var { generateBytes, timingSafeEqual: cryptoTimingSafeEqual } = bCrypto;
var httpClient = require("../http-client");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var { URL } = require("node:url");
var { defineClass } = require("../framework-error");
var validateOpts = require("../validate-opts");
var lazyRequire = require("../lazy-require");
var jwtExternal = require("./jwt-external");
// RFC 9101 request-object builder — composed by pushAuthorizationRequest
// when the operator opts into sending a signed request object. Top-of-file
// per convention §3; no circular load — jar requires jwt-external +
// validate-opts only, nothing from oauth.
var jar         = require("./jar");
var audit       = lazyRequire(function () { return require("../audit"); });

var OAUTH_MAX_RESPONSE_BYTES = C.BYTES.kib(256);

var OAuthError = defineClass("OAuthError", { alwaysPermanent: true });

var PRESETS = Object.freeze({
  google: {
    issuer:        "https://accounts.google.com",
    defaultScope:  ["openid", "email", "profile"],
    isOidc:        true,
  },
  microsoft: {
    issuer:        "https://login.microsoftonline.com/common/v2.0",
    defaultScope:  ["openid", "email", "profile"],
    isOidc:        true,
  },
  apple: {
    issuer:        "https://appleid.apple.com",
    defaultScope:  ["openid", "email", "name"],
    isOidc:        true,
    responseMode:  "form_post",
  },
  auth0: {
    issuerTemplate: function (opts) {
      if (!opts.auth0Domain) {
        throw new OAuthError("auth-oauth/auth0-domain",
          "auth0 preset requires opts.auth0Domain ('your-tenant.auth0.com')");
      }
      return "https://" + opts.auth0Domain;
    },
    defaultScope:   ["openid", "email", "profile"],
    isOidc:         true,
  },
  keycloak: {
    issuerTemplate: function (opts) {
      if (!opts.keycloakUrl || !opts.keycloakRealm) {
        throw new OAuthError("auth-oauth/keycloak-config",
          "keycloak preset requires opts.keycloakUrl and opts.keycloakRealm");
      }
      return opts.keycloakUrl.replace(/\/$/, "") + "/realms/" + opts.keycloakRealm;
    },
    defaultScope:   ["openid", "email", "profile"],
    isOidc:         true,
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint:         "https://github.com/login/oauth/access_token",
    userinfoEndpoint:      "https://api.github.com/user",
    defaultScope:          ["read:user", "user:email"],
    isOidc:                false,
  },
  generic: {
    // Operator-defined endpoints (or issuer-driven discovery). The
    // preset itself adds nothing — its presence makes provider:'generic'
    // a valid explicit selector instead of falling through to "unknown
    // provider preset". Operators pass authorizationEndpoint /
    // tokenEndpoint / userinfoEndpoint (or issuer + isOidc:true to
    // discover) on opts.
  },
});

var DEFAULT_ACCEPTED_ALGS = Object.freeze([
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
]);

var DEFAULT_DISCOVERY_CACHE_MS = C.TIME.hours(1);
var DEFAULT_CLOCK_SKEW_MS      = C.TIME.minutes(1);

var PKCE_VERIFIER_BYTES        = C.BYTES.bytes(32);
var STATE_NONCE_BYTES          = C.BYTES.bytes(16);

var MAX_DEVICE_CODE_BYTES      = C.BYTES.kib(8);
var MIN_DEVICE_POLL_INTERVAL_SEC = 5;
var DEFAULT_LOGOUT_TOKEN_MAX_AGE_SEC = C.TIME.minutes(5) / C.TIME.seconds(1);

var RFC_8693_TOKEN_TYPES = Object.freeze([
  "urn:ietf:params:oauth:token-type:access_token",
  "urn:ietf:params:oauth:token-type:refresh_token",
  "urn:ietf:params:oauth:token-type:id_token",
  "urn:ietf:params:oauth:token-type:saml1",
  "urn:ietf:params:oauth:token-type:saml2",
  "urn:ietf:params:oauth:token-type:jwt",
  "urn:openid:params:token-type:device-secret",
]);

function _b64urlEncode(buf) { return bCrypto.toBase64Url(buf); }

var _b64urlDecode = bCrypto.makeBase64UrlDecoder({
  errorClass:  OAuthError,
  code:        "auth-oauth/bad-base64",
  typeMessage: "expected base64url string",
  badMessage:  "segment is not valid base64url",
});

function _generateRandomToken(bytes) {
  return _b64urlEncode(generateBytes(bytes));
}

function _generatePkce() {
  var verifier = _b64urlEncode(generateBytes(PKCE_VERIFIER_BYTES));
  var challenge = _b64urlEncode(nodeCrypto.createHash("sha256").update(verifier).digest());
  return { verifier: verifier, challenge: challenge };
}

/**
 * @primitive  b.auth.oauth.generatePkce
 * @signature  b.auth.oauth.generatePkce()
 * @since      0.18.0
 * @status     stable
 * @related    b.auth.oauth.parseCallback
 *
 * Generate a PKCE (RFC 7636) verifier/challenge pair for a hand-rolled
 * authorization-code flow that does not go through `create()`. The
 * `code_challenge_method` is always `S256`: the challenge is the base64url
 * of SHA-256 over the verifier, and the verifier is 43 base64url characters
 * (32 CSPRNG bytes).
 *
 * @example
 *   var pkce = b.auth.oauth.generatePkce();
 *   // → { verifier: "…43 chars…", challenge: "…base64url(SHA-256(verifier))…" }
 */
function generatePkce() {
  return _generatePkce();
}

function _validateUrl(url, allowHttp, label) {
  if (typeof url !== "string" || url.length === 0) {
    throw new OAuthError("auth-oauth/bad-url", label + ": URL is required");
  }
  var isLocalhostHttp = false;
  try {
    var parsed = new URL(url);                                                                  // allow:raw-new-url-parse-only — RFC 9700 §4.1.1 localhost-exception lookup; safeUrl re-validates below for non-localhost paths
    var rawHost = parsed.hostname || "";
    while (rawHost.length > 0 && rawHost.charAt(rawHost.length - 1) === ".") {
      rawHost = rawHost.slice(0, -1);
    }
    if (parsed.protocol === "http:" &&
        (rawHost === "localhost" ||
         rawHost === "127.0.0.1" ||
         rawHost === "[::1]" ||
         rawHost === "::1")) {
      isLocalhostHttp = true;
    }
  } catch (_e) { /* malformed; let safeUrl surface the canonical error below */ }
  if (isLocalhostHttp) return url;

  try {
    safeUrl.parse(url, {
      allowedProtocols: allowHttp ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS,
    });
  } catch (e) {
    if (e && e.code === "safe-url/protocol-disallowed") {
      throw new OAuthError("auth-oauth/insecure-url",
        label + ": must be https" + (allowHttp ? " or http" : " (or http://localhost for dev)") +
        " (got '" + url + "')");
    }
    throw new OAuthError("auth-oauth/bad-url",
      label + ": invalid URL '" + url + "'");
  }
  return url;
}

function _verifyParamsForAlg(alg) {
  var params = jwtExternal.algParams(alg);
  if (!params || alg === "EdDSA") {
    throw new OAuthError("auth-oauth/unsupported-alg",
      "alg '" + alg + "' is not supported for ID-token verification");
  }
  return params;
}

function _jwkToKey(jwk) {
  return bCrypto.importPublicJwk(jwk, {
    errorClass:    OAuthError,
    code:          "auth-oauth/bad-jwk",
    messagePrefix: "could not import JWK (kid=" + (jwk && jwk.kid) + "): ",
  });
}

var RAR_SUBSET_FIELDS = Object.freeze(["locations", "actions", "datatypes", "privileges"]);

var RAR_MAX_BYTES = C.BYTES.kib(64);

function _validateAuthorizationDetailsArray(value, label) {
  if (!Array.isArray(value)) {
    throw new OAuthError("auth-oauth/bad-authorization-details",
      label + ": authorizationDetails must be an array of typed objects (RFC 9396 §2)");
  }
  for (var i = 0; i < value.length; i += 1) {
    var entry = value[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new OAuthError("auth-oauth/bad-authorization-details",
        label + ": authorizationDetails[" + i + "] must be an object");
    }
    if (typeof entry.type !== "string" || entry.type.length === 0) {
      throw new OAuthError("auth-oauth/bad-authorization-details",
        label + ": authorizationDetails[" + i + "] missing required 'type' field (RFC 9396 §2)");
    }
  }
  return value;
}

function _arraySubfieldExceeds(grantedVal, requestedVal) {
  if (grantedVal === undefined) return false;
  if (!Array.isArray(grantedVal)) {
    return !(requestedVal !== undefined &&
             !Array.isArray(requestedVal) &&
             grantedVal === requestedVal);
  }
  if (!Array.isArray(requestedVal)) return grantedVal.length > 0;
  for (var i = 0; i < grantedVal.length; i += 1) {
    if (requestedVal.indexOf(grantedVal[i]) === -1) return true;
  }
  return false;
}

function _grantedDetailExceeds(granted, requestedForType) {
  if (!requestedForType) return true;
  for (var i = 0; i < RAR_SUBSET_FIELDS.length; i += 1) {
    var f = RAR_SUBSET_FIELDS[i];
    if (_arraySubfieldExceeds(granted[f], requestedForType[f])) return true;
  }
  return false;
}

function _crossCheckGrantedAuthorizationDetails(grantedRaw, requested, strict) {
  if (grantedRaw === undefined || grantedRaw === null) return null;
  if (!Array.isArray(grantedRaw)) {
    throw new OAuthError("auth-oauth/bad-granted-authorization-details",
      "token response authorization_details must be a JSON array (RFC 9396 §7)");
  }
  if (Buffer.byteLength(JSON.stringify(grantedRaw), "utf8") > RAR_MAX_BYTES) {
    throw new OAuthError("auth-oauth/granted-authorization-details-too-large",
      "token response authorization_details exceeds " + RAR_MAX_BYTES + " bytes");
  }
  if (requested === undefined || requested === null) return grantedRaw;
  for (var i = 0; i < grantedRaw.length; i += 1) {
    var granted = grantedRaw[i];
    if (!granted || typeof granted !== "object" || Array.isArray(granted) ||
        typeof granted.type !== "string") {
      throw new OAuthError("auth-oauth/bad-granted-authorization-details",
        "token response authorization_details[" + i + "] is not a typed object (RFC 9396 §2)");
    }
    var match = null;
    for (var j = 0; j < requested.length; j += 1) {
      if (requested[j].type === granted.type) { match = requested[j]; break; }
    }
    if (_grantedDetailExceeds(granted, match)) {
      if (strict) {
        throw new OAuthError("auth-oauth/authorization-details-over-grant",
          "token response granted an authorization_detail (type='" + granted.type +
          "') that exceeds the request — refusing per RFC 9396 §7 (broadened grant). " +
          "Operators that intentionally accept asymmetric grants pass " +
          "verifyAuthorizationDetails: false.");
      }
    }
  }
  return grantedRaw;
}

var ATTESTATION_ALGS = Object.freeze([
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA",
]);

var ATTESTATION_JWT_TYP     = "oauth-client-attestation+jwt";
var ATTESTATION_POP_JWT_TYP = "oauth-client-attestation-pop+jwt";

var MAX_ATTESTATION_JWT_BYTES = C.BYTES.kib(16);

var DEFAULT_POP_MAX_AGE_SEC = C.TIME.minutes(5) / C.TIME.seconds(1);

function _attestationCryptoParams(alg) {
  if (alg === "EdDSA") return { hash: null };
  return _verifyParamsForAlg(alg);
}

function _toAttestationPrivateKey(value, label) {
  try { return jwtExternal._toPrivateKey(value, label); }
  catch (e) {
    var code = (e && e.code) === "auth-jwt-external/sign-no-key"
      ? "auth-oauth/attestation-no-key" : "auth-oauth/attestation-bad-key";
    /* c8 ignore next -- String(e) fallback: the jwt-external error always carries a message */
    throw new OAuthError(code, (e && e.message) || String(e));
  }
}

function _resolveAttestationAlg(explicitAlg, privateKey, label) {
  try {
    return jwtExternal._resolveSignAlg(explicitAlg, privateKey, label);
  } catch (e) {
    /* c8 ignore next -- || "" is unreachable: _resolveSignAlg always throws a coded AuthError */
    var ec = (e && e.code) || "";
    if (ec === "auth-jwt-external/sign-alg-key-mismatch") {
      /* c8 ignore next -- String(e) fallback: the mapped error always carries a message */
      throw new OAuthError("auth-oauth/attestation-alg-key-mismatch", (e && e.message) || String(e));
    }
    if (ec === "auth-jwt-external/sign-alg-refused" || ec === "auth-jwt-external/sign-alg-unsupported") {
      throw new OAuthError("auth-oauth/attestation-alg-not-accepted",
        label + ": alg '" + explicitAlg + "' is not an accepted attestation algorithm");
    }
    if (ec === "auth-jwt-external/sign-key-unsupported") {
      /* c8 ignore next -- String(e) fallback: the mapped error always carries a message */
      throw new OAuthError("auth-oauth/attestation-key-unsupported", (e && e.message) || String(e));
    }
    /* c8 ignore next -- unreachable: _resolveSignAlg only emits the four codes handled above */
    throw new OAuthError("auth-oauth/attestation-bad-key", (e && e.message) || String(e));
  }
}

function _signAttestationJws(header, payload, privateKey, alg) {
  return jwtExternal._signCompactJws(header, payload, privateKey, alg);
}

function _verifyAttestationJws(jws, publicKeyJwk, label, expectedTyp) {
  if (typeof jws !== "string" || jws.length === 0) {
    throw new OAuthError("auth-oauth/attestation-malformed", label + ": JWT must be a non-empty string");
  }
  if (jws.length > MAX_ATTESTATION_JWT_BYTES) {
    throw new OAuthError("auth-oauth/attestation-too-large",
      label + ": JWT exceeds " + MAX_ATTESTATION_JWT_BYTES + " bytes");
  }
  var parts = jws.split(".");
  if (parts.length === 5) {
    throw new OAuthError("auth-oauth/attestation-jwe-refused",
      label + ": 5-segment JWE refused — attestation JWTs are JWS only");
  }
  if (parts.length !== 3) {
    throw new OAuthError("auth-oauth/attestation-malformed", label + ": JWT is not 3 segments");
  }
  var header, payload;
  try {
    header  = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8"), { maxBytes: MAX_ATTESTATION_JWT_BYTES });
    payload = safeJson.parse(_b64urlDecode(parts[1]).toString("utf8"), { maxBytes: MAX_ATTESTATION_JWT_BYTES });
  } catch (e) {
    /* c8 ignore next 2 -- String(e) fallback: the decode error always carries a message */
    throw new OAuthError("auth-oauth/attestation-malformed",
      label + ": header/payload decode failed: " + ((e && e.message) || String(e)));
  }
  if (!header || typeof header.alg !== "string") {
    throw new OAuthError("auth-oauth/attestation-malformed", label + ": header missing 'alg'");
  }
  if (ATTESTATION_ALGS.indexOf(header.alg) === -1) {
    throw new OAuthError("auth-oauth/attestation-alg-not-accepted",
      label + ": alg '" + header.alg + "' is not an accepted attestation algorithm " +
      "(HMAC / none refused — alg-allowlist gate)");
  }
  if (header.crit !== undefined && header.crit !== null) {
    throw new OAuthError("auth-oauth/attestation-crit-not-supported",
      label + ": JWS 'crit' header is not supported (RFC 7515 §4.1.11)");
  }
  if (typeof expectedTyp === "string" && header.typ !== expectedTyp) {
    throw new OAuthError("auth-oauth/attestation-wrong-typ",
      label + ": header.typ must be '" + expectedTyp + "' (RFC 8725 §3.11 " +
      "explicit typing); got " + JSON.stringify(header.typ));
  }
  jwtExternal._assertAlgKtyMatch(header.alg, publicKeyJwk);
  var keyObject = _jwkToKey(publicKeyJwk);
  var params = _attestationCryptoParams(header.alg);
  var signingInput = parts[0] + "." + parts[1];
  var sig = _b64urlDecode(parts[2]);
  var verifyOpts = { key: keyObject };
  if (params.padding !== undefined)     verifyOpts.padding     = params.padding;
  if (params.saltLength !== undefined)  verifyOpts.saltLength  = params.saltLength;
  if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
  var ok;
  try {
    ok = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
    /* c8 ignore next 4 -- verify cannot raise: the alg/kty/crv cross-check above guarantees a compatible key/params pairing, so a bad signature returns false rather than throwing */
  } catch (verifyErr) {
    throw new OAuthError("auth-oauth/attestation-bad-signature",
      label + ": signature verification raised: " + ((verifyErr && verifyErr.message) || String(verifyErr)));
  }
  if (!ok) {
    throw new OAuthError("auth-oauth/attestation-bad-signature", label + ": signature verification failed");
  }
  return { header: header, payload: payload };
}

function _publicCnfJwk(jwk, label) {
  /* c8 ignore next 4 -- unreachable: the sole caller validates instanceKeyJwk as a required object before this call */
  if (!jwk || typeof jwk !== "object") {
    throw new OAuthError("auth-oauth/attestation-bad-cnf",
      label + ": instanceKeyJwk (public JWK for the cnf claim) is required");
  }
  if (jwk.kty === "EC")  return { kty: "EC",  crv: jwk.crv, x: jwk.x, y: jwk.y };
  if (jwk.kty === "OKP") return { kty: "OKP", crv: jwk.crv, x: jwk.x };
  if (jwk.kty === "RSA") return { kty: "RSA", e: jwk.e, n: jwk.n };
  throw new OAuthError("auth-oauth/attestation-bad-cnf",
    label + ": instanceKeyJwk.kty='" + jwk.kty + "' is not an asymmetric public JWK");
}

function _optionalFiniteNumber(value, label, code) {
  if (value === undefined || value === null) return;
  if (typeof value !== "number" || !isFinite(value)) {
    throw new OAuthError(code, label + " must be a finite number (epoch seconds)");
  }
}

/**
 * @primitive b.auth.oauth.buildClientAttestation
 * @signature b.auth.oauth.buildClientAttestation(opts)
 * @since     0.14.20
 * @status    experimental
 * @related   b.auth.oauth.buildClientAttestationPop, b.auth.oauth.verifyClientAttestation
 *
 * Builds the `OAuth-Client-Attestation` JWT defined by
 * draft-ietf-oauth-attestation-based-client-auth-08 §4. The client's
 * backend ("Attester") signs a JWT binding the `client_id` (in `sub`)
 * to a per-instance public key carried in the RFC 7800 `cnf` claim.
 * The companion PoP (`buildClientAttestationPop`) then proves the
 * instance holds the matching private key — together they replace a
 * shared `client_secret` for FAPI / wallet clients.
 *
 * The JWT is a classical JWS (RS/PS/ES/EdDSA) signed via `node:crypto`;
 * HMAC and `none` are refused. This is the interop case distinct from
 * `b.auth.jwt`, which signs framework tokens PQC-only.
 *
 * Opt-in / additive: a client that never calls this behaves as before.
 *
 * @opts
 *   {
 *     clientId:            string,         // → sub claim (required)
 *     attesterPrivateKey:  KeyObject|PEM|JWK, // Attester signing key (required)
 *     instanceKeyJwk:      object,         // instance PUBLIC JWK → cnf.jwk (required)
 *     algorithm?:          string,         // JWS alg (default: inferred from the key type — ES256/384/512, RS256, or EdDSA)
 *     expiresInSec?:       number,         // exp = iat + this (default: 300)
 *     nbf?:                number,         // optional not-before (epoch seconds)
 *     iat?:                number,         // override issued-at (epoch seconds)
 *     extraClaims?:        object,         // merged without overriding spec fields
 *   }
 *
 * @example
 *   var att = b.auth.oauth.buildClientAttestation({
 *     clientId:           "wallet-app",
 *     attesterPrivateKey: attesterKey,
 *     instanceKeyJwk:     instancePublicJwk,
 *   });
 *   // → "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0Ii..."
 */
function buildClientAttestation(aopts) {
  aopts = aopts || {};
  validateOpts.shape(aopts, {
    clientId:     { rule: "required-string",       code: "auth-oauth/attestation-no-client-id" },
    attesterPrivateKey: function (v, l) {
      if (v === undefined || v === null) {
        throw new OAuthError("auth-oauth/attestation-no-attester-key",
          l + " (Attester signing key) is required");
      }
    },
    instanceKeyJwk: { rule: "required-object",   code: "auth-oauth/attestation-bad-cnf" },
    algorithm:      { rule: "optional-string",   code: "auth-oauth/attestation-bad-alg" },
    nbf:            function (v, l) { _optionalFiniteNumber(v, l, "auth-oauth/attestation-bad-nbf"); },
    iat:            function (v, l) { _optionalFiniteNumber(v, l, "auth-oauth/attestation-bad-iat"); },
    extraClaims:    { rule: "optional-plain-object", code: "auth-oauth/attestation-bad-extra-claims" },
    expiresInSec: { rule: "optional-positive-int", code: "auth-oauth/attestation-bad-expiry" },
  }, "buildClientAttestation", OAuthError, "auth-oauth/attestation-no-client-id");
  var key = _toAttestationPrivateKey(aopts.attesterPrivateKey, "buildClientAttestation");
  var alg = _resolveAttestationAlg(aopts.algorithm, key, "buildClientAttestation");
  var cnfJwk = _publicCnfJwk(aopts.instanceKeyJwk, "buildClientAttestation");
  var iatSec = typeof aopts.iat === "number" ? aopts.iat : Math.floor(Date.now() / C.TIME.seconds(1));
  var ttl = typeof aopts.expiresInSec === "number" ? aopts.expiresInSec : DEFAULT_POP_MAX_AGE_SEC;
  var payload = {
    sub: aopts.clientId,
    iat: iatSec,
    exp: iatSec + ttl,
    cnf: { jwk: cnfJwk },
  };
  if (typeof aopts.nbf === "number") payload.nbf = aopts.nbf;
  if (aopts.extraClaims && typeof aopts.extraClaims === "object" && !Array.isArray(aopts.extraClaims)) {
    validateOpts.assignOwnEnumerable(payload, aopts.extraClaims, Object.keys(payload));
  }
  return _signAttestationJws(
    { typ: ATTESTATION_JWT_TYP, alg: alg }, payload, key, alg);
}

/**
 * @primitive b.auth.oauth.buildClientAttestationPop
 * @signature b.auth.oauth.buildClientAttestationPop(opts)
 * @since     0.14.20
 * @status    experimental
 * @related   b.auth.oauth.buildClientAttestation, b.auth.oauth.verifyClientAttestation
 *
 * Builds the `OAuth-Client-Attestation-PoP` JWT defined by
 * draft-ietf-oauth-attestation-based-client-auth-08 §5. Signed by the
 * per-instance PRIVATE key whose public half lives in the attestation's
 * `cnf` claim, it proves the instance possesses that key for this
 * request. `aud` MUST be the authorization server's issuer; `jti` is a
 * fresh per-request identifier the AS tracks for replay defense.
 *
 * Asymmetric JWS only (RS/PS/ES/EdDSA) — MAC / `none` are refused.
 *
 * Opt-in / additive.
 *
 * @opts
 *   {
 *     instancePrivateKey:  KeyObject|PEM|JWK, // matches cnf.jwk (required)
 *     audience:            string,         // AS issuer URL → aud (required)
 *     algorithm?:          string,         // JWS alg (default: inferred from the key type — ES256/384/512, RS256, or EdDSA)
 *     challenge?:          string,         // server-issued nonce → challenge claim
 *     jti?:                string,         // override jti (default: fresh CSPRNG)
 *     iat?:                number,         // override issued-at (epoch seconds)
 *     expiresInSec?:       number,         // optional exp = iat + this
 *   }
 *
 * @example
 *   var pop = b.auth.oauth.buildClientAttestationPop({
 *     instancePrivateKey: instanceKey,
 *     audience:           "https://as.example.com",
 *   });
 *   // send both headers on the token request:
 *   //   OAuth-Client-Attestation: <att>
 *   //   OAuth-Client-Attestation-PoP: <pop>
 */
function buildClientAttestationPop(popts) {
  popts = popts || {};
  validateOpts.shape(popts, {
    audience:     { rule: "required-string",       code: "auth-oauth/attestation-pop-no-aud",
                    label: "buildClientAttestationPop: audience (AS issuer)" },
    instancePrivateKey: function (v, l) {
      if (v === undefined || v === null) {
        throw new OAuthError("auth-oauth/attestation-pop-no-instance-key",
          l + " (instance signing key matching cnf.jwk) is required");
      }
    },
    algorithm:    { rule: "optional-string",       code: "auth-oauth/attestation-pop-bad-alg" },
    jti:          { rule: "optional-string",       code: "auth-oauth/attestation-pop-bad-jti" },
    iat:          function (v, l) { _optionalFiniteNumber(v, l, "auth-oauth/attestation-pop-bad-iat"); },
    challenge:    { rule: "optional-string",       code: "auth-oauth/attestation-pop-bad-challenge" },
    expiresInSec: { rule: "optional-positive-int", code: "auth-oauth/attestation-pop-bad-expiry" },
  }, "buildClientAttestationPop", OAuthError, "auth-oauth/attestation-pop-no-aud");
  var key = _toAttestationPrivateKey(popts.instancePrivateKey, "buildClientAttestationPop");
  var alg = _resolveAttestationAlg(popts.algorithm, key, "buildClientAttestationPop");
  var iatSec = typeof popts.iat === "number" ? popts.iat : Math.floor(Date.now() / C.TIME.seconds(1));
  var jti = typeof popts.jti === "string" && popts.jti.length > 0
              ? popts.jti : _generateRandomToken(STATE_NONCE_BYTES);
  var payload = {
    aud: popts.audience,
    jti: jti,
    iat: iatSec,
  };
  if (typeof popts.expiresInSec === "number") payload.exp = iatSec + popts.expiresInSec;
  if (typeof popts.challenge === "string" && popts.challenge.length > 0) {
    payload.challenge = popts.challenge;
  }
  return _signAttestationJws(
    { typ: ATTESTATION_POP_JWT_TYP, alg: alg }, payload, key, alg);
}

/**
 * @primitive b.auth.oauth.verifyClientAttestation
 * @signature b.auth.oauth.verifyClientAttestation(attestationJwt, popJwt, opts)
 * @since     0.14.20
 * @status    experimental
 * @related   b.auth.oauth.buildClientAttestation, b.auth.oauth.buildClientAttestationPop
 *
 * Verifies a `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`
 * header pair, performing the authorization-server checks of
 * draft-ietf-oauth-attestation-based-client-auth-08 §8: the attestation
 * signature against a TRUSTED Attester key; the PoP signature against
 * the attestation's `cnf` key (never the Attester's); attestation `exp`
 * freshness; PoP `aud` == this AS issuer (constant-time); PoP `iat`
 * within `maxPopAgeSec`; optional server-challenge binding; and `jti`
 * replay defense via an operator-supplied atomic check-and-insert.
 *
 * Async (returns a Promise) so the `jti` replay store can be an async
 * Redis / DB check-and-insert. Resolves to `{ clientId, cnfJwk,
 * attestation, pop }` on success; rejects with a typed `OAuthError` on
 * any failure. Opt-in / additive — an AS that doesn't accept
 * attestation-based auth never calls it.
 *
 * @opts
 *   {
 *     attesterJwk:        object,    // trusted Attester PUBLIC JWK (required)
 *     expectedAudience:   string,    // this AS issuer URL (required)
 *     expectedClientId?:  string,    // request client_id; must equal attestation sub
 *     challenge?:         string,    // server-issued nonce the PoP must echo
 *     maxPopAgeSec?:      number,    // PoP iat freshness window (default: 300)
 *     clockSkewSec?:      number,    // allowed skew (default: 60)
 *     seenJti?:           function,  // (jti, iat) → truthy when UNSEEN (atomic); may return a Promise (async store)
 *   }
 *
 * @example
 *   var v = await b.auth.oauth.verifyClientAttestation(
 *     req.headers["oauth-client-attestation"],
 *     req.headers["oauth-client-attestation-pop"],
 *     { attesterJwk: trustedAttesterJwk, expectedAudience: "https://as.example.com",
 *       seenJti: function (jti) { return jtiStore.checkAndInsert(jti); } });
 *   // → { clientId: "wallet-app", cnfJwk: {...}, attestation: {...}, pop: {...} }
 */
async function verifyClientAttestation(attestationJwt, popJwt, vopts) {
  vopts = vopts || {};
  validateOpts(vopts, [
    "attesterJwk", "expectedAudience", "expectedClientId", "challenge",
    "maxPopAgeSec", "clockSkewSec", "seenJti",
  ], "auth.oauth.verifyClientAttestation");
  if (!vopts.attesterJwk || typeof vopts.attesterJwk !== "object") {
    throw new OAuthError("auth-oauth/attestation-no-attester-jwk",
      "verifyClientAttestation: opts.attesterJwk (trusted Attester public JWK) is required");
  }
  validateOpts.requireNonEmptyString(vopts.expectedAudience,
    "verifyClientAttestation: expectedAudience (this AS issuer)", OAuthError,
    "auth-oauth/attestation-no-expected-aud");

  var att = _verifyAttestationJws(attestationJwt, vopts.attesterJwk, "client-attestation",
    ATTESTATION_JWT_TYP);
  var ap = att.payload || {};
  if (typeof ap.sub !== "string" || ap.sub.length === 0) {
    throw new OAuthError("auth-oauth/attestation-no-sub",
      "client-attestation: missing 'sub' (client_id) claim");
  }
  if (!ap.cnf || typeof ap.cnf !== "object" || !ap.cnf.jwk || typeof ap.cnf.jwk !== "object") {
    throw new OAuthError("auth-oauth/attestation-no-cnf",
      "client-attestation: missing 'cnf.jwk' confirmation key (RFC 7800)");
  }
  var nowSec  = Math.floor(Date.now() / C.TIME.seconds(1));
  numericBounds.requireNonNegativeFiniteIntIfPresent(vopts.clockSkewSec,
    "verifyClientAttestation: opts.clockSkewSec", OAuthError, "auth-oauth/bad-clock-skew");
  var skewSec = typeof vopts.clockSkewSec === "number" ? vopts.clockSkewSec : (C.TIME.minutes(1) / C.TIME.seconds(1));
  if (typeof ap.exp !== "number" || ap.exp + skewSec < nowSec) {
    throw new OAuthError("auth-oauth/attestation-expired",
      "client-attestation: expired (exp=" + ap.exp + ", now=" + nowSec + ")");
  }
  if (typeof ap.nbf === "number" && ap.nbf - skewSec > nowSec) {
    throw new OAuthError("auth-oauth/attestation-not-yet-valid", "client-attestation: nbf in the future");
  }
  if (vopts.expectedClientId !== undefined && vopts.expectedClientId !== null) {
    if (!_constantTimeStrEq(String(vopts.expectedClientId), ap.sub)) {
      throw new OAuthError("auth-oauth/attestation-client-id-mismatch",
        "client-attestation: sub does not match the request's client_id");
    }
  }

  var pop = _verifyAttestationJws(popJwt, ap.cnf.jwk, "client-attestation-pop",
    ATTESTATION_POP_JWT_TYP);
  var pp = pop.payload || {};
  if (typeof pp.aud !== "string" || !_constantTimeStrEq(vopts.expectedAudience, pp.aud)) {
    throw new OAuthError("auth-oauth/attestation-pop-aud-mismatch",
      "client-attestation-pop: aud does not match this authorization server's issuer");
  }
  if (typeof pp.jti !== "string" || pp.jti.length === 0) {
    throw new OAuthError("auth-oauth/attestation-pop-no-jti", "client-attestation-pop: missing 'jti'");
  }
  if (typeof pp.iat !== "number") {
    throw new OAuthError("auth-oauth/attestation-pop-no-iat", "client-attestation-pop: missing 'iat'");
  }
  numericBounds.requireNonNegativeFiniteIntIfPresent(vopts.maxPopAgeSec,
    "verifyClientAttestation: opts.maxPopAgeSec", OAuthError, "auth-oauth/bad-pop-max-age");
  var maxAge = typeof vopts.maxPopAgeSec === "number" ? vopts.maxPopAgeSec : DEFAULT_POP_MAX_AGE_SEC;
  if (pp.iat - skewSec > nowSec) {
    throw new OAuthError("auth-oauth/attestation-pop-iat-future", "client-attestation-pop: iat in the future");
  }
  if (pp.iat + maxAge + skewSec < nowSec) {
    throw new OAuthError("auth-oauth/attestation-pop-stale",
      "client-attestation-pop: iat older than maxPopAgeSec (" + maxAge + "s)");
  }
  if (typeof pp.exp === "number" && pp.exp + skewSec < nowSec) {
    throw new OAuthError("auth-oauth/attestation-pop-expired", "client-attestation-pop: expired");
  }
  if (vopts.challenge !== undefined && vopts.challenge !== null) {
    if (typeof pp.challenge !== "string" || !_constantTimeStrEq(String(vopts.challenge), pp.challenge)) {
      throw new OAuthError("auth-oauth/attestation-pop-challenge-mismatch",
        "client-attestation-pop: challenge does not match the server-issued value");
    }
  }
  if (typeof vopts.seenJti === "function") {
    var unseen;
    try {
      unseen = vopts.seenJti(pp.jti, pp.iat);
      if (unseen && typeof unseen.then === "function") unseen = await unseen;
    } catch (e) {
      throw new OAuthError("auth-oauth/attestation-pop-seen-callback-failed",
        "client-attestation-pop: seenJti() callback threw: " + ((e && e.message) || String(e)));
    }
    if (!unseen) {
      throw new OAuthError("auth-oauth/attestation-pop-replay",
        "client-attestation-pop: jti already seen (replay refused, draft §12.1)");
    }
  }
  return {
    clientId:    ap.sub,
    cnfJwk:      ap.cnf.jwk,
    attestation: ap,
    pop:         pp,
  };
}

function _constantTimeStrEq(a, b) {
  /* c8 ignore next -- every caller passes a String()-wrapped first argument, so the typeof-a arm never short-circuits */
  if (typeof a !== "string" || typeof b !== "string") return false;
  return cryptoTimingSafeEqual(a, b);
}

var RESERVED_AUTHZ_PARAMS = {
  "response_type":         1,
  "client_id":             1,
  "redirect_uri":          1,
  "scope":                 1,
  "state":                 1,
  "nonce":                 1,
  "code_challenge":        1,
  "code_challenge_method": 1,
  "response_mode":         1,
  "authorization_details": 1,
  "request":               1,
  "request_uri":           1,
};

function _assertNoReservedExtraParams(extraParams, reserved, errCode, ctx) {
  /* c8 ignore next -- every caller guards `extraParams && typeof === "object"` first, so the !extraParams arm never short-circuits */
  if (!extraParams || typeof extraParams !== "object") return;
  var ek = Object.keys(extraParams);
  for (var i = 0; i < ek.length; i++) {
    if (Object.prototype.hasOwnProperty.call(reserved, ek[i])) {
      throw new OAuthError(errCode,
        ctx + ": extraParams key '" + ek[i] + "' collides with a " +
        "framework-managed parameter — pass it through the named option instead");
    }
  }
}

function create(opts) {
  opts = opts || {};
  var clientId     = opts.clientId;
  var clientSecret = opts.clientSecret || null;
  var redirectUri  = opts.redirectUri;
  if (opts.pkce === false) {
    throw new OAuthError("auth-oauth/pkce-required",
      "create: pkce: false is refused. OAuth 2.1 (draft-ietf-oauth-v2-1) " +
      "requires PKCE for all clients. Remove the opt or upgrade the IdP.");
  }
  var pkce = true;
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.clockSkewMs,
    "oauth.create: opts.clockSkewMs", OAuthError, "auth-oauth/bad-clock-skew");
  var clockSkewMs  = typeof opts.clockSkewMs === "number" ? opts.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  var discoveryCacheMs = typeof opts.discoveryCacheMs === "number"
                           ? opts.discoveryCacheMs : DEFAULT_DISCOVERY_CACHE_MS;
  var acceptedAlgorithms = Array.isArray(opts.acceptedAlgorithms) && opts.acceptedAlgorithms.length > 0
                             ? opts.acceptedAlgorithms.slice() : DEFAULT_ACCEPTED_ALGS.slice();
  var allowHttp        = !!opts.allowHttp;
  var allowInternal    = opts.allowInternal != null ? opts.allowInternal : null;
  var httpClientOpts   = opts.httpClient || {};
  var httpOpts   = validateOpts.outboundHttpOpts(opts.http, "oauth.create", OAuthError, "auth-oauth");
  var httpDialer = httpOpts.client
    ? httpClient.pinnedClient(httpOpts.client, httpOpts.allowedHosts)
    : httpClient;
  var responseMode     = opts.responseMode || null;
  var allowKidlessJwks = opts.allowKidlessJwks === true;

  if (!clientId) {
    throw new OAuthError("auth-oauth/no-client-id", "create: opts.clientId is required");
  }
  if (redirectUri) _validateUrl(redirectUri, allowHttp, "redirectUri");

  var preset = null;
  if (opts.provider) {
    if (!Object.prototype.hasOwnProperty.call(PRESETS, opts.provider)) {
      throw new OAuthError("auth-oauth/unknown-provider",
        "unknown provider preset '" + opts.provider + "' (known: " +
        Object.keys(PRESETS).join(", ") + ")");
    }
    preset = PRESETS[opts.provider];
  }
  var isOidc = (preset && typeof preset.isOidc === "boolean") ? preset.isOidc
             : (opts.isOidc !== undefined ? !!opts.isOidc : true);
  var issuer = opts.issuer
             || (preset && typeof preset.issuerTemplate === "function" && preset.issuerTemplate(opts))
             || (preset && preset.issuer)
             || null;
  if (issuer) _validateUrl(issuer, allowHttp, "issuer");
  var scope = Array.isArray(opts.scope) && opts.scope.length > 0
                ? opts.scope.slice()
                : (preset && preset.defaultScope ? preset.defaultScope.slice() : ["openid"]);
  if (!responseMode && preset && preset.responseMode) responseMode = preset.responseMode;

  var tokenEndpointAuthMethod = opts.tokenEndpointAuthMethod || "client_secret_post";
  if (tokenEndpointAuthMethod !== "client_secret_post" && tokenEndpointAuthMethod !== "client_secret_basic") {
    throw new OAuthError("auth-oauth/bad-auth-method",
      "create: tokenEndpointAuthMethod must be 'client_secret_post' or 'client_secret_basic'");
  }

  var staticEndpoints = {
    authorizationEndpoint: opts.authorizationEndpoint || (preset && preset.authorizationEndpoint) || null,
    tokenEndpoint:         opts.tokenEndpoint         || (preset && preset.tokenEndpoint)         || null,
    userinfoEndpoint:      opts.userinfoEndpoint      || (preset && preset.userinfoEndpoint)      || null,
    revocationEndpoint:    opts.revocationEndpoint    || (preset && preset.revocationEndpoint)    || null,
    jwksUri:               opts.jwksUri               || (preset && preset.jwksUri)               || null,
    endSessionEndpoint:    opts.endSessionEndpoint    || (preset && preset.endSessionEndpoint)    || null,
    checkSessionIframe:    opts.checkSessionIframe    || (preset && preset.checkSessionIframe)    || null,
    pushedAuthorizationRequestEndpoint:
                           opts.pushedAuthorizationRequestEndpoint ||
                           (preset && preset.pushedAuthorizationRequestEndpoint) || null,
    backchannelAuthenticationEndpoint:
                           opts.backchannelAuthenticationEndpoint ||
                           (preset && preset.backchannelAuthenticationEndpoint) || null,
    introspectionEndpoint: opts.introspectionEndpoint || (preset && preset.introspectionEndpoint) || null,
    registrationEndpoint:  opts.registrationEndpoint  || (preset && preset.registrationEndpoint)  || null,
    deviceAuthorizationEndpoint:
                           opts.deviceAuthorizationEndpoint ||
                           (preset && preset.deviceAuthorizationEndpoint) || null,
  };

  var jwksCacheMs = typeof opts.jwksCacheMs === "number" ? opts.jwksCacheMs : DEFAULT_DISCOVERY_CACHE_MS;
  var _discoveryCache = cache.create({
    namespace: "oauth.discovery." + clientId,
    ttlMs:     discoveryCacheMs,
  });
  var _jwksCache = cache.create({
    namespace: "oauth.jwks." + clientId,
    ttlMs:     jwksCacheMs,
  });

  async function _fetchJson(url, fetchOpts) {
    fetchOpts = fetchOpts || {};
    var hc = httpDialer;
    var req = Object.assign({
      url:    url,
      method: "GET",
    }, fetchOpts);
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    _mergeHttpClientOpts(req);
    var res = await hc.request(req);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
      var bodyText = res.body ? res.body.toString("utf8") : "";
      throw new OAuthError("auth-oauth/http-" + res.statusCode,
        url + " returned " + res.statusCode + ": " + bodyText.slice(0, 500));
    }
    /* c8 ignore next -- httpClient always yields a Buffer body (empty Buffer for no content), so this never returns null */
    if (!res.body) return null;
    try { return safeJson.parse(res.body.toString("utf8"), { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
      /* c8 ignore next 2 -- String(e) fallback: the parse error always carries a message */
      throw new OAuthError("auth-oauth/bad-json",
        url + " response not JSON: " + ((e && e.message) || String(e)));
    }
  }

  async function _discover() {
    if (!isOidc || !issuer) return null;
    return _discoveryCache.wrap("config", async function () {
      var url = issuer.replace(/\/$/, "") + "/.well-known/openid-configuration";
      _validateUrl(url, allowHttp, "discovery url");
      var config = await _fetchJson(url);
      if (!config || typeof config !== "object") {
        throw new OAuthError("auth-oauth/bad-discovery", "discovery document missing");
      }
      if (config.issuer && config.issuer !== issuer) {
        throw new OAuthError("auth-oauth/issuer-mismatch",
          "discovery issuer '" + config.issuer + "' does not match configured issuer '" + issuer + "'");
      }
      return config;
    });
  }

  function _assertS256Supported(config) {
    if (!config || typeof config !== "object") return;
    var methods = config.code_challenge_methods_supported;
    if (!Array.isArray(methods)) return;
    var hasS256 = false;
    for (var i = 0; i < methods.length; i++) {
      if (methods[i] === "S256") { hasS256 = true; break; }
    }
    if (!hasS256) {
      throw new OAuthError("auth-oauth/pkce-downgrade",
        "OP discovery advertises code_challenge_methods_supported " +
        JSON.stringify(methods) + " without 'S256'. The framework sends " +
        "S256 (RFC 7636) and refuses to emit an authorization request the " +
        "OP claims it cannot verify — a stripped-S256 / plain-only " +
        "discovery is the signature of a PKCE downgrade (RFC 9700 §4.13). " +
        "Fix the OP metadata or, on a genuinely S256-incapable IdP, " +
        "front it with a conforming gateway.");
    }
  }

  async function _peekDiscovery() {
    if (!isOidc || !issuer) return null;
    try { return (await _discoveryCache.get("config")) || null; }
    /* c8 ignore next -- defensive: the in-memory discovery cache get() does not throw */
    catch (_e) { return null; }
  }

  async function _resolveEndpoint(name) {
    if (staticEndpoints[name]) return staticEndpoints[name];
    var config = await _discover();
    if (!config) {
      throw new OAuthError("auth-oauth/no-endpoint",
        name + " endpoint not configured and no OIDC discovery available");
    }
    var snake = ({
      authorizationEndpoint: "authorization_endpoint",
      tokenEndpoint:         "token_endpoint",
      userinfoEndpoint:      "userinfo_endpoint",
      revocationEndpoint:    "revocation_endpoint",
      jwksUri:               "jwks_uri",
      endSessionEndpoint:    "end_session_endpoint",
      checkSessionIframe:    "check_session_iframe",
      pushedAuthorizationRequestEndpoint: "pushed_authorization_request_endpoint",
      backchannelAuthenticationEndpoint:  "backchannel_authentication_endpoint",
      introspectionEndpoint:              "introspection_endpoint",
      registrationEndpoint:               "registration_endpoint",
      deviceAuthorizationEndpoint:        "device_authorization_endpoint",
    })[name];
    var endpoint = config[snake];
    if (!endpoint) {
      throw new OAuthError("auth-oauth/no-endpoint",
        name + " not present in discovery document");
    }
    return endpoint;
  }

  async function authorizationUrl(uopts) {
    uopts = uopts || {};
    if (!redirectUri) {
      throw new OAuthError("auth-oauth/no-redirect-uri",
        "authorizationUrl: a redirectUri must be configured at create() for the authorization-code flow");
    }
    var endpoint = await _resolveEndpoint("authorizationEndpoint");
    _assertS256Supported(await _peekDiscovery());
    var state = uopts.state || _generateRandomToken(STATE_NONCE_BYTES);
    var nonce = uopts.nonce || (isOidc ? _generateRandomToken(STATE_NONCE_BYTES) : null);
    /* c8 ignore next -- pkce is always true (create() refuses pkce:false), so the : null alternate is dead */
    var pkceVals = pkce ? _generatePkce() : null;
    var params = new URLSearchParams();
    params.set("response_type", "code");
    params.set("client_id",     clientId);
    params.set("redirect_uri",  redirectUri);
    params.set("scope",         scope.join(" "));
    params.set("state",         state);
    if (nonce)         params.set("nonce", nonce);
    if (pkceVals) {
      params.set("code_challenge", pkceVals.challenge);
      params.set("code_challenge_method", "S256");
    }
    if (responseMode)  params.set("response_mode", responseMode);
    if (uopts.prompt)  params.set("prompt", uopts.prompt);
    if (uopts.loginHint) params.set("login_hint", uopts.loginHint);
    if (uopts.maxAge != null) params.set("max_age", String(uopts.maxAge));
    var requestedAuthzDetails = null;
    if (uopts.authorizationDetails !== undefined) {
      requestedAuthzDetails = _validateAuthorizationDetailsArray(
        uopts.authorizationDetails, "authorizationUrl");
      params.set("authorization_details", JSON.stringify(requestedAuthzDetails));
    }
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      _assertNoReservedExtraParams(uopts.extraParams, RESERVED_AUTHZ_PARAMS,
        "auth-oauth/reserved-extra-param", "authorizationUrl");
      var ek = Object.keys(uopts.extraParams);
      for (var i = 0; i < ek.length; i++) params.set(ek[i], String(uopts.extraParams[ek[i]]));
    }
    var sep = endpoint.indexOf("?") === -1 ? "?" : "&";
    return {
      url:       endpoint + sep + params.toString(),
      state:     state,
      nonce:     nonce,
      /* c8 ignore next 2 -- pkceVals is always truthy (pkce is always on), so the : null alternates are dead */
      verifier:  pkceVals ? pkceVals.verifier  : null,
      challenge: pkceVals ? pkceVals.challenge : null,
      authorizationDetails: requestedAuthzDetails,
    };
  }

  async function exchangeCode(eopts) {
    eopts = eopts || {};
    if (!redirectUri) {
      throw new OAuthError("auth-oauth/no-redirect-uri",
        "exchangeCode: a redirectUri must be configured at create() for the authorization-code flow");
    }
    if (!eopts.code) {
      throw new OAuthError("auth-oauth/no-code", "exchangeCode: opts.code is required");
    }
    if (pkce && !eopts.verifier) {
      throw new OAuthError("auth-oauth/no-verifier",
        "exchangeCode: opts.verifier is required when PKCE is on (default)");
    }
    if (isOidc && eopts.skipNonceCheck !== true &&
        (typeof eopts.nonce !== "string" || eopts.nonce.length === 0)) {
      throw new OAuthError("auth-oauth/no-nonce",
        "exchangeCode: a non-empty nonce is required on OIDC flows. Pass the " +
        "value returned from authorizationUrl() through to exchangeCode " +
        "({ code, state, verifier, nonce }). Operators with a deliberate " +
        "no-nonce flow must pass `skipNonceCheck: true` (audited reason).");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var body = new URLSearchParams();
    body.set("grant_type",   "authorization_code");
    body.set("code",         eopts.code);
    body.set("redirect_uri", redirectUri);
    body.set("client_id",    clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    if (eopts.verifier) body.set("code_verifier", eopts.verifier);
    var requestedAuthzDetails = null;
    if (eopts.authorizationDetails !== undefined && eopts.authorizationDetails !== null) {
      requestedAuthzDetails = _validateAuthorizationDetailsArray(
        eopts.authorizationDetails, "exchangeCode");
      body.set("authorization_details", JSON.stringify(requestedAuthzDetails));
    }

    var tokens = await _postForm(endpoint, body);
    return await _normalizeTokens(tokens, {
      nonce:          eopts.nonce,
      skipNonceCheck: eopts.skipNonceCheck,
      requestedAuthorizationDetails: requestedAuthzDetails,
      verifyAuthorizationDetails:    eopts.verifyAuthorizationDetails,
    });
  }

  async function refreshAccessToken(refreshToken, ropts) {
    ropts = ropts || {};
    if (!refreshToken) {
      throw new OAuthError("auth-oauth/no-refresh-token",
        "refreshAccessToken: refresh token is required");
    }
    var alreadySeen = false;
    if (typeof ropts.checkAndInsert === "function") {
      var nowMs = Date.now();
      var expireAtMs = nowMs + C.TIME.hours(24);
      var inserted;
      try { inserted = await ropts.checkAndInsert(refreshToken, expireAtMs); }
      catch (e) {
        throw new OAuthError("auth-oauth/seen-callback-failed",
          "refreshAccessToken: checkAndInsert() callback threw: " + ((e && e.message) || String(e)));
      }
      alreadySeen = !inserted;
    } else if (typeof ropts.seen === "function") {
      try { alreadySeen = await ropts.seen(refreshToken); }
      catch (e) {
        throw new OAuthError("auth-oauth/seen-callback-failed",
          "refreshAccessToken: seen() callback threw: " + ((e && e.message) || String(e)));
      }
    }
    if (alreadySeen) {
      throw new OAuthError("auth-oauth/refresh-token-replay",
        "refreshAccessToken: refresh token has been presented before — refused " +
        "(OAuth 2.1 §6.1 / RFC 9700 §4.13 one-time-use defense). The operator MUST " +
        "treat this as a token-theft signal: revoke the refresh-token family + force " +
        "the user to re-authenticate.");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var body = new URLSearchParams();
    body.set("grant_type",    "refresh_token");
    body.set("refresh_token", refreshToken);
    body.set("client_id",     clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    var tokens = await _postForm(endpoint, body);
    var normalized = await _normalizeTokens(tokens, { skipNonceCheck: true });
    if (normalized.refreshToken && normalized.refreshToken !== refreshToken) {
      normalized.refreshTokenRotated = true;
      normalized.previousRefreshToken = refreshToken;
    } else {
      normalized.refreshTokenRotated = false;
    }
    return normalized;
  }

  /**
   * @primitive b.auth.oauth.parseCallback
   * @signature b.auth.oauth.parseCallback(query, opts?)
   * @since     0.8.70
   * @related   b.auth.oauth.parseJarmResponse, b.fapi2.assertCallback
   *
   * Parses the OP's redirect-back query/form parameters and applies
   * RFC 9207 OAuth 2.0 Authorization Server Issuer Identification
   * cross-checks. The `iss` parameter the OP echoes on the callback
   * MUST match the configured issuer; mismatches surface as a
   * deterministic refusal (mix-up / IdP-substitution defense per
   * RFC 9207 §2.3).
   *
   * The framework refuses the callback when:
   *   - an `error` param is present (OP-side authorization failure)
   *   - `iss` is present but does NOT match the configured issuer
   *   - `state` is supplied to opts.expectedState and doesn't match
   *
   * Returns `{ code, state, iss }` for the happy path. Operators feed
   * `code` + their stored `verifier` + `nonce` to `exchangeCode`.
   *
   * The OP advertises support via `authorization_response_iss_parameter_supported`
   * in discovery; the framework reads it once at the first parseCallback
   * call and refuses missing-`iss` callbacks under FAPI 2.0 posture
   * regardless (per FAPI 2.0 §5.4.2).
   *
   * @opts
   *   {
   *     expectedState?:    string,    // value returned by authorizationUrl()
   *     requireIssParam?:  boolean,   // refuse callbacks lacking iss (default: read OP discovery; FAPI 2.0 forces true)
   *   }
   *
   * @example
   *   app.get("/oauth/callback", async function (req, res) {
   *     var url = new URL(req.url, "http://placeholder.invalid");
   *     var params = Object.fromEntries(url.searchParams);
   *     var parsed = await oauth.parseCallback(params, { expectedState: req.session.oauthState });
   *     var tokens = await oauth.exchangeCode({ code: parsed.code,
   *       verifier: req.session.pkceVerifier, nonce: req.session.oidcNonce });
   *   });
   */
  async function parseCallback(query, popts) {
    popts = popts || {};
    if (!query || typeof query !== "object") {
      throw new OAuthError("auth-oauth/bad-callback",
        "parseCallback: query must be an object of param key→value");
    }
    if (typeof query.error === "string" && query.error.length > 0) {
      var aerr = new OAuthError("auth-oauth/op-error",
        "parseCallback: OP returned error '" + query.error + "'" +
        (query.error_description ? ": " + query.error_description : ""));
      aerr.opError = query.error;
      aerr.opErrorDescription = query.error_description || null;
      throw aerr;
    }
    var requireIss = popts.requireIssParam === true;
    if (!requireIss) {
      var disc = null;
      try { disc = await _discover(); } catch (_e) { /* discovery already failed elsewhere; let exchangeCode surface it */ }
      if (disc && disc.authorization_response_iss_parameter_supported === true) {
        requireIss = true;
      }
    }
    if (typeof query.iss === "string" && query.iss.length > 0) {
      if (query.iss !== issuer) {
        throw new OAuthError("auth-oauth/iss-mismatch-callback",
          "parseCallback: callback iss '" + query.iss + "' does not match " +
          "configured issuer '" + issuer + "' (RFC 9207 §2.3 mix-up defense)");
      }
    } else if (requireIss) {
      throw new OAuthError("auth-oauth/missing-iss-callback",
        "parseCallback: OP advertises authorization_response_iss_parameter_supported " +
        "but the callback omitted `iss` — refused (RFC 9207 / FAPI 2.0 §5.4.2)");
    }
    if (popts.expectedState !== undefined && popts.expectedState !== null) {
      if (typeof query.state !== "string" ||
          !cryptoTimingSafeEqual(query.state, popts.expectedState)) {
        throw new OAuthError("auth-oauth/state-mismatch",
          "parseCallback: state mismatch (CSRF defense) — expected and " +
          "supplied state values do not match");
      }
    }
    if (typeof query.code !== "string" || query.code.length === 0) {
      throw new OAuthError("auth-oauth/no-code-in-callback",
        "parseCallback: callback missing `code` parameter");
    }
    return { code: query.code, state: query.state || null, iss: query.iss || issuer };
  }

  /**
   * @primitive b.auth.oauth.parseJarmResponse
   * @signature b.auth.oauth.parseJarmResponse(responseJwt, opts?)
   * @since     0.8.70
   * @related   b.auth.oauth.parseCallback, b.fapi2.assertCallback
   *
   * JWT Authorization Response Mode (JARM, OAuth 2.0 JARM spec).
   * When `response_mode` is `query.jwt` / `fragment.jwt` /
   * `form_post.jwt`, the OP delivers the authorization response as a
   * signed JWT in a single `response` parameter instead of as bare
   * query/form params. This primitive verifies the JWS against the
   * OP's JWKS, validates `iss` / `aud` / `exp` / `nbf`, and returns
   * the inner params (`code` / `state` / `iss` / `error`) as if they
   * had been the raw query.
   *
   * The verified params then flow through `parseCallback` for the
   * normal RFC 9207 + state-CSRF + error-refusal pipeline.
   *
   * @opts
   *   {
   *     expectedState?:    string,
   *     requireIssParam?:  boolean,   // refuse a response lacking iss (default: read OP discovery)
   *   }
   *
   * @example
   *   app.get("/oauth/callback", async function (req, res) {
   *     var jwt = new URL(req.url, "x:/").searchParams.get("response");
   *     var params = await oauth.parseJarmResponse(jwt, { expectedState: req.session.oauthState });
   *     var tokens = await oauth.exchangeCode({ code: params.code,
   *       verifier: req.session.pkceVerifier, nonce: req.session.oidcNonce });
   *   });
   */
  async function parseJarmResponse(responseJwt, jopts) {
    jopts = jopts || {};
    if (typeof responseJwt !== "string" || responseJwt.length === 0) {
      throw new OAuthError("auth-oauth/no-jarm-response",
        "parseJarmResponse: response JWT required");
    }
    if (responseJwt.split(".").length !== 3) {
      throw new OAuthError("auth-oauth/malformed-jarm-response",
        "parseJarmResponse: response is not a 3-segment JWS");
    }
    var verified = await verifyIdToken(responseJwt, {
      skipNonceCheck: true,
    });
    var c = verified.claims;
    if (Object.prototype.hasOwnProperty.call(c, "nonce")) {
      throw new OAuthError("auth-oauth/jarm-forbidden-nonce",
        "parseJarmResponse: JARM responses MUST NOT carry `nonce` (JARM §4)");
    }
    return await parseCallback({
      code:                c.code,
      state:               c.state,
      iss:                 c.iss,
      error:               c.error,
      error_description:   c.error_description,
    }, { expectedState: jopts.expectedState, requireIssParam: jopts.requireIssParam });
  }

  async function fetchUserInfo(accessToken, ufiOpts) {
    ufiOpts = ufiOpts || {};
    if (!accessToken) {
      throw new OAuthError("auth-oauth/no-access-token",
        "fetchUserInfo: access token is required");
    }
    if (isOidc && ufiOpts.idTokenSub === undefined && ufiOpts.skipSubCheck !== true) {
      throw new OAuthError("auth-oauth/userinfo-no-id-token-sub",
        "fetchUserInfo: OIDC providers require ufiOpts.idTokenSub " +
        "(the verified sub claim from the id_token returned by " +
        "exchangeCode) so the userinfo response can be cross-checked. " +
        "Pass { idTokenSub: tokens.idToken.payload.sub } or, for non-" +
        "OIDC OAuth 2.0 deployments mis-flagged as isOidc, opt out " +
        "explicitly with { skipSubCheck: true } and an audited reason.");
    }
    var endpoint = await _resolveEndpoint("userinfoEndpoint");
    var profile = await _fetchJson(endpoint, {
      headers: {
        "Authorization": "Bearer " + accessToken,
        "Accept":        "application/json",
        "User-Agent":    "blamejs",
      },
    });
    if (isOidc && ufiOpts.idTokenSub !== undefined && profile && profile.sub !== ufiOpts.idTokenSub) {
      throw new OAuthError("auth-oauth/userinfo-sub-mismatch",
        "fetchUserInfo: userinfo.sub (" + profile.sub + ") does not match " +
        "the id_token sub (" + ufiOpts.idTokenSub + ") — possible token " +
        "substitution attack");
    }
    return profile;
  }

  async function revokeToken(token, ropts) {
    if (!token) {
      throw new OAuthError("auth-oauth/no-token", "revokeToken: token is required");
    }
    ropts = ropts || {};
    var endpoint = await _resolveEndpoint("revocationEndpoint");
    var body = new URLSearchParams();
    body.set("token", token);
    if (ropts.type) body.set("token_type_hint", ropts.type);
    body.set("client_id", clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    var hc = httpDialer;
    var req = {
      url:     endpoint,
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    Buffer.from(body.toString(), "utf8"),
    };
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    _mergeHttpClientOpts(req);
    var res = await hc.request(req);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new OAuthError("auth-oauth/revoke-failed",
        "revocation returned " + res.statusCode);
    }
  }

  function _mergeHttpClientOpts(req) {
    var ownHeaders = req.headers || {};
    Object.assign(req, httpClientOpts);
    req.headers = Object.assign({}, req.headers, ownHeaders);
    if (httpOpts.allowedHosts) req.allowedHosts = httpOpts.allowedHosts.slice();
    _validateUrl(req.url, allowHttp, "outbound endpoint");
  }

  function _parseRetryAfterMs(ra) {
    var s = String(ra).trim();
    if (/^\d+$/.test(s)) return Math.min(parseInt(s, 10), 3600) * C.TIME.seconds(1);
    var when = Date.parse(s);
    if (!isNaN(when)) { var d = when - Date.now(); return d > 0 ? Math.min(d, C.TIME.hours(1)) : 0; }
    return 0;
  }

  function _clientBasicAuthHeaders(body) {
    if (clientSecret && tokenEndpointAuthMethod === "client_secret_basic") {
      body.delete("client_secret");
      return { Authorization: "Basic " + Buffer.from(
        encodeURIComponent(clientId) + ":" + encodeURIComponent(clientSecret), "utf8").toString("base64") };
    }
    return null;
  }

  async function _postForm(endpoint, body, extraHeaders, applyTokenClientAuth) {
    var hc = httpDialer;
    var authHeaders = applyTokenClientAuth === false ? null : _clientBasicAuthHeaders(body);
    var req = {
      url:     endpoint,
      method:  "POST",
      headers: Object.assign({
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "application/json",
      }, authHeaders || {}, extraHeaders || {}),
      body:    Buffer.from(body.toString(), "utf8"),
    };
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    _mergeHttpClientOpts(req);
    req.responseMode = "always-resolve";
    var res = await hc.request(req);
    /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
    var text = res.body ? res.body.toString("utf8") : "";
    if (res.statusCode < 200 || res.statusCode >= 300) {
      var tokenErr = new OAuthError("auth-oauth/token-error-" + res.statusCode,
        endpoint + " returned " + res.statusCode + ": " + text.slice(0, 500));
      var ra = res.headers && (res.headers["retry-after"] !== undefined ? res.headers["retry-after"] : res.headers["Retry-After"]);
      if (ra !== undefined && ra !== null) tokenErr.retryAfterMs = _parseRetryAfterMs(ra);
      throw tokenErr;
    }
    var parsed;
    try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
      /* c8 ignore next 2 -- String(e) fallback: the parse error always carries a message */
      throw new OAuthError("auth-oauth/bad-token-json",
        "token endpoint response not JSON: " + ((e && e.message) || String(e)));
    }
    return parsed;
  }

  async function _normalizeTokens(raw, vopts) {
    /* c8 ignore next -- every caller passes a vopts object, so the || {} default is unreachable */
    vopts = vopts || {};
    var grantedScope;
    if (typeof raw.scope === "string") {
      grantedScope = raw.scope.split(" ").filter(function (s) { return s.length > 0; });
    } else if (raw.scope === undefined) {
      grantedScope = scope.slice();
    } else {
      grantedScope = [];
    }
    var tokens = {
      accessToken:  raw.access_token,
      tokenType:    raw.token_type || "Bearer",
      expiresIn:    raw.expires_in || null,
      refreshToken: raw.refresh_token || null,
      idToken:      raw.id_token || null,
      scope:        grantedScope,
      raw:          raw,
    };
    if (tokens.idToken && isOidc) {
      var v = await verifyIdToken(tokens.idToken, {
        nonce:          vopts.nonce,
        skipNonceCheck: vopts.skipNonceCheck,
      });
      tokens.claims  = v.claims;
      tokens.profile = {
        sub:     v.claims.sub,
        email:   v.claims.email,
        name:    v.claims.name,
        picture: v.claims.picture,
      };
    }
    if (raw.authorization_details !== undefined) {
      var strict = vopts.requestedAuthorizationDetails != null &&
                   vopts.verifyAuthorizationDetails !== false;
      tokens.authorizationDetails = _crossCheckGrantedAuthorizationDetails(
        raw.authorization_details,
        vopts.requestedAuthorizationDetails != null ? vopts.requestedAuthorizationDetails : null,
        strict);
    } else {
      tokens.authorizationDetails = null;
    }
    return tokens;
  }

  async function _getJwks() {
    return _jwksCache.wrap("keys", async function () {
      var jwksUri = await _resolveEndpoint("jwksUri");
      var jwks = await _fetchJson(jwksUri);
      if (!jwks || !Array.isArray(jwks.keys)) {
        throw new OAuthError("auth-oauth/bad-jwks", "JWKS response missing 'keys' array");
      }
      return jwks.keys;
    });
  }

  async function verifyIdToken(idToken, vopts) {
    vopts = vopts || {};
    if (typeof idToken !== "string") {
      throw new OAuthError("auth-oauth/no-id-token", "verifyIdToken: idToken must be a string");
    }
    var parts = idToken.split(".");
    if (parts.length === 5) {
      try { audit().safeEmit({
        action:   "jwt.jwe.refused",
        outcome:  "denied",
        metadata: { reason: "jwe-on-jws-verifier", primitive: "oauth.verifyIdToken" },
        /* c8 ignore next -- drop-silent observability sink: safeEmit does not throw */
      }); } catch (_e) { /* drop-silent — observability sink */ }
      throw new OAuthError("auth-oauth/jwe-refused",
        "5-segment JWE id_token refused — verifyIdToken only handles JWS " +
        "(CVE-2026-29000 / CVE-2026-22817 / CVE-2026-34950 JWE-bypass class)");
    }
    if (parts.length !== 3) {
      throw new OAuthError("auth-oauth/malformed-jwt", "ID token does not have 3 parts");
    }
    var header, payload;
    try {
      header  = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8"), { maxBytes: OAUTH_MAX_RESPONSE_BYTES });
      payload = safeJson.parse(_b64urlDecode(parts[1]).toString("utf8"), { maxBytes: OAUTH_MAX_RESPONSE_BYTES });
    } catch (e) {
      /* c8 ignore next 2 -- String(e) fallback: the decode error always carries a message */
      throw new OAuthError("auth-oauth/malformed-jwt",
        "ID token header/payload base64 decode failed: " + ((e && e.message) || String(e)));
    }
    if (!header || typeof header.alg !== "string") {
      throw new OAuthError("auth-oauth/malformed-jwt", "ID token header missing 'alg'");
    }
    if (acceptedAlgorithms.indexOf(header.alg) === -1) {
      throw new OAuthError("auth-oauth/alg-not-accepted",
        "ID token signed with '" + header.alg + "' which is not in the accepted-algorithm list " +
        "(alg-allowlist gate — refused before key lookup)");
    }
    if (header.crit !== undefined && header.crit !== null) {
      throw new OAuthError("auth-oauth/crit-not-supported",
        "ID token JWS header carries 'crit' extension list; this verifier does not " +
        "support any critical extensions and refuses per RFC 7515 §4.1.11");
    }
    var keys = await _getJwks();
    var match = null;
    if (header.kid) {
      for (var i = 0; i < keys.length; i++) {
        if (keys[i].kid === header.kid) { match = keys[i]; break; }
      }
    }
    if (!match) {
      var allowKidless = vopts.allowKidlessJwks === true || allowKidlessJwks;
      if (!header.kid && keys.length === 1 && allowKidless) {
        match = keys[0];
      } else {
        throw new OAuthError("auth-oauth/no-matching-key",
          header.kid
            ? "no JWKS key matches header.kid='" + header.kid + "'"
            : "ID token has no kid header; framework refuses kid-less " +
              "tokens to defend against JWKS-rotation key-pick attacks " +
              "(pass `allowKidlessJwks: true` to b.auth.oauth.create() — " +
              "client-level — if your IdP genuinely emits kid-less tokens; " +
              "or vopts.allowKidlessJwks: true on a single verifyIdToken " +
              "call)");
      }
    }
    jwtExternal._assertAlgKtyMatch(header.alg, match);
    var keyObject = _jwkToKey(match);
    var params = _verifyParamsForAlg(header.alg);
    var signingInput = parts[0] + "." + parts[1];
    var sig = _b64urlDecode(parts[2]);
    var verifyOpts = { key: keyObject };
    if (params.padding !== undefined) verifyOpts.padding = params.padding;
    if (params.saltLength !== undefined) verifyOpts.saltLength = params.saltLength;
    if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
    var verified;
    try {
      verified = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
      /* c8 ignore next 5 -- verify cannot raise: the alg/kty/crv cross-check above guarantees a compatible key/params pairing, so a bad signature returns false rather than throwing */
    } catch (verifyErr) {
      throw new OAuthError("auth-oauth/bad-signature",
        "ID token signature verification raised: " +
        ((verifyErr && verifyErr.message) || String(verifyErr)));
    }
    if (!verified) {
      throw new OAuthError("auth-oauth/bad-signature", "ID token signature verification failed");
    }

    var now = Math.floor(Date.now() / C.TIME.seconds(1));
    var skewSec = Math.floor(clockSkewMs / C.TIME.seconds(1));
    if (vopts.skipExpCheck) {
      if (!payload.events || typeof payload.events !== "object" ||
          !payload.events["http://schemas.openid.net/event/backchannel-logout"]) {
        throw new OAuthError("auth-oauth/skip-exp-check-not-allowed",
          "skipExpCheck is only valid for back-channel-logout tokens " +
          "(OIDC Back-Channel Logout 1.0 §2.4); this token carries no logout event claim");
      }
      var logoutMaxAgeSec = (typeof vopts.maxAgeSec === "number" && isFinite(vopts.maxAgeSec) &&
        vopts.maxAgeSec > 0) ? vopts.maxAgeSec : DEFAULT_LOGOUT_TOKEN_MAX_AGE_SEC;
      if (typeof payload.iat !== "number" || payload.iat + logoutMaxAgeSec + skewSec < now) {
        throw new OAuthError("auth-oauth/logout-token-stale",
          "logout token iat is older than " + logoutMaxAgeSec + "s (no exp; iat is the freshness bound)");
      }
    } else {
      if (typeof payload.exp !== "number" || payload.exp + skewSec < now) {
        throw new OAuthError("auth-oauth/expired", "ID token expired (exp=" + payload.exp + ", now=" + now + ")");
      }
    }
    if (typeof payload.iat === "number" && payload.iat - skewSec > now) {
      throw new OAuthError("auth-oauth/iat-future", "ID token iat is in the future");
    }
    if (typeof payload.nbf === "number" && payload.nbf - skewSec > now) {
      throw new OAuthError("auth-oauth/nbf-future", "ID token nbf is in the future");
    }
    if (isOidc && !issuer) {
      throw new OAuthError("auth-oauth/issuer-required",
        "verifyIdToken: an OIDC client must be configured with `issuer` to validate the " +
        "id_token's iss (OIDC Core 3.1.3.7 / cross-realm-JWT defense); pass issuer to b.auth.oauth.create()");
    }
    if (issuer) {
      if (typeof payload.iss !== "string" ||
          !jwtExternal._issuerMatches(payload.iss, issuer)) {
        try { audit().safeEmit({
          action:   "jwt.iss.mismatch",
          outcome:  "denied",
          metadata: {
            expectedIssuer:  issuer,
            presentedIssuer: typeof payload.iss === "string" ? payload.iss : null,
            reason:          "cross-realm-jwt-refused",
            primitive:       "oauth.verifyIdToken",
          },
          /* c8 ignore next -- drop-silent observability sink: safeEmit does not throw */
        }); } catch (_e) { /* drop-silent — observability sink */ }
        throw new OAuthError("auth-oauth/iss-mismatch",
          "ID token iss '" + payload.iss + "' does not match expected '" + issuer +
          "' (CVE-2026-23552 — cross-realm refused)");
      }
    }
    var aud = Array.isArray(payload.aud) ? payload.aud : (payload.aud ? [payload.aud] : []);
    if (aud.indexOf(clientId) === -1) {
      throw new OAuthError("auth-oauth/aud-mismatch",
        "ID token aud does not contain clientId '" + clientId + "'");
    }
    if (aud.length > 1 && typeof payload.azp !== "string") {
      throw new OAuthError("auth-oauth/azp-required",
        "ID token has multiple audiences but no azp (authorized party) claim");
    }
    if (payload.azp !== undefined && payload.azp !== clientId) {
      throw new OAuthError("auth-oauth/azp-mismatch",
        "ID token azp '" + payload.azp + "' is not clientId '" + clientId + "'");
    }
    if (vopts.nonce && !vopts.skipNonceCheck) {
      if (typeof payload.nonce !== "string" ||
          !cryptoTimingSafeEqual(payload.nonce, vopts.nonce)) {
        throw new OAuthError("auth-oauth/nonce-mismatch",
          "ID token nonce mismatch (replay protection)");
      }
    }
    return { header: header, claims: payload };
  }

  async function endSessionUrl(uopts) {
    uopts = uopts || {};
    var endpoint;
    try { endpoint = await _resolveEndpoint("endSessionEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-end-session-endpoint",
        "endSessionUrl: IdP discovery doc has no end_session_endpoint " +
        "(set opts.endSessionEndpoint on create() if the IdP doesn't publish it)");
    }
    var params = new URLSearchParams();
    if (uopts.idTokenHint) params.set("id_token_hint", uopts.idTokenHint);
    if (uopts.postLogoutRedirectUri) {
      _validateUrl(uopts.postLogoutRedirectUri, allowHttp, "postLogoutRedirectUri");
      params.set("post_logout_redirect_uri", uopts.postLogoutRedirectUri);
    }
    if (uopts.state)        params.set("state", uopts.state);
    if (uopts.logoutHint)   params.set("logout_hint", uopts.logoutHint);
    if (uopts.uiLocales)    params.set("ui_locales", uopts.uiLocales);
    if (uopts.clientId !== false) params.set("client_id", clientId);
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      var RESERVED_END_SESSION_PARAMS = {
        "id_token_hint":              1,
        "post_logout_redirect_uri":   1,
        "state":                      1,
        "logout_hint":                1,
        "ui_locales":                 1,
        "client_id":                  1,
      };
      _assertNoReservedExtraParams(uopts.extraParams, RESERVED_END_SESSION_PARAMS,
        "auth-oauth/end-session-reserved-extra-param", "endSessionUrl");
      var ek = Object.keys(uopts.extraParams);
      for (var i = 0; i < ek.length; i++) params.set(ek[i], String(uopts.extraParams[ek[i]]));
    }
    var qs = params.toString();
    if (qs.length === 0) return endpoint;
    var sep = endpoint.indexOf("?") === -1 ? "?" : "&";
    return endpoint + sep + qs;
  }

  async function pushAuthorizationRequest(uopts) {
    uopts = uopts || {};
    if (!redirectUri) {
      throw new OAuthError("auth-oauth/no-redirect-uri",
        "pushAuthorizationRequest: a redirectUri must be configured at create() for the authorization-code flow");
    }
    var endpoint;
    try { endpoint = await _resolveEndpoint("pushedAuthorizationRequestEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-par-endpoint",
        "pushAuthorizationRequest: IdP discovery doc has no " +
        "pushed_authorization_request_endpoint (set opts.pushedAuthorizationRequestEndpoint " +
        "on create() if the IdP doesn't publish it)");
    }
    var sro = uopts.signedRequestObject || null;
    if (sro) {
      validateOpts.optionalPlainObject(sro, "pushAuthorizationRequest: signedRequestObject",
        OAuthError, "auth-oauth/par-bad-request-object-opt",
        "must be an object { key, alg?, kid?, audience?, expiresInMs? }");
      validateOpts(sro, ["key", "alg", "kid", "audience", "expiresInMs"],
        "pushAuthorizationRequest.signedRequestObject");
    }
    _assertS256Supported(await _peekDiscovery());
    var state = uopts.state || _generateRandomToken(STATE_NONCE_BYTES);
    var nonce = uopts.nonce || (isOidc ? _generateRandomToken(STATE_NONCE_BYTES) : null);
    var pkceVals = _generatePkce();
    var authzParams = {
      response_type:        "code",
      client_id:            clientId,
      redirect_uri:         redirectUri,
      scope:                scope.join(" "),
      state:                state,
      code_challenge:        pkceVals.challenge,
      code_challenge_method: "S256",
    };
    if (nonce)        authzParams.nonce         = nonce;
    if (responseMode) authzParams.response_mode = responseMode;
    if (uopts.prompt)    authzParams.prompt     = uopts.prompt;
    if (uopts.loginHint) authzParams.login_hint = uopts.loginHint;
    if (uopts.maxAge != null) authzParams.max_age = String(uopts.maxAge);
    var requestedAuthzDetails = null;
    if (uopts.authorizationDetails !== undefined) {
      requestedAuthzDetails = _validateAuthorizationDetailsArray(
        uopts.authorizationDetails, "pushAuthorizationRequest");
      authzParams.authorization_details = sro
        ? requestedAuthzDetails
        : JSON.stringify(requestedAuthzDetails);
    }
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      _assertNoReservedExtraParams(uopts.extraParams, RESERVED_AUTHZ_PARAMS,
        "auth-oauth/reserved-extra-param", "pushAuthorizationRequest");
      var ek = Object.keys(uopts.extraParams);
      for (var i = 0; i < ek.length; i++) authzParams[ek[i]] = String(uopts.extraParams[ek[i]]);
    }

    var body = new URLSearchParams();
    if (sro) {
      var requestJwt = jar.build(authzParams, {
        clientId:    clientId,
        audience:    sro.audience || issuer,
        key:         sro.key,
        alg:         sro.alg,
        kid:         sro.kid,
        expiresInMs: sro.expiresInMs,
      });
      body.set("request",   requestJwt);
      body.set("client_id", clientId);
      if (clientSecret) body.set("client_secret", clientSecret);
    } else {
      var ak = Object.keys(authzParams);
      for (var ap = 0; ap < ak.length; ap++) body.set(ak[ap], authzParams[ak[ap]]);
      if (clientSecret) body.set("client_secret", clientSecret);
    }
    var rv = await _postForm(endpoint, body, null, false);
    if (!rv || typeof rv.request_uri !== "string" || rv.request_uri.length === 0) {
      throw new OAuthError("auth-oauth/par-bad-response",
        "pushAuthorizationRequest: IdP did not return a request_uri (got " +
        JSON.stringify(rv).slice(0, 200) + ")");
    }
    var authzEndpoint = await _resolveEndpoint("authorizationEndpoint");
    var qs = new URLSearchParams();
    qs.set("client_id",   clientId);
    qs.set("request_uri", rv.request_uri);
    var sep = authzEndpoint.indexOf("?") === -1 ? "?" : "&";
    return {
      url:         authzEndpoint + sep + qs.toString(),
      state:       state,
      nonce:       nonce,
      verifier:    pkceVals.verifier,
      challenge:   pkceVals.challenge,
      requestUri:  rv.request_uri,
      expiresIn:   typeof rv.expires_in === "number" ? rv.expires_in : null,
      authorizationDetails: requestedAuthzDetails,
      requestObjectSent:    !!sro,
    };
  }

  function parseFrontchannelLogoutRequest(req) {
    if (!req || !req.url) {
      throw new OAuthError("auth-oauth/bad-frontchannel-logout-req",
        "parseFrontchannelLogoutRequest: req with url required");
    }
    var u;
    try { u = new URL(req.url, "http://placeholder.invalid"); }                                  // allow:raw-new-url-parse-only — req.url is the framework-normalized path; placeholder base provides a synthetic origin for relative-path parse
    catch (_e) {
      throw new OAuthError("auth-oauth/bad-frontchannel-logout-url",
        "parseFrontchannelLogoutRequest: malformed request URL");
    }
    var iss = u.searchParams.get("iss");
    var sid = u.searchParams.get("sid");
    if (iss && (typeof issuer !== "string" || !jwtExternal._issuerMatches(iss, issuer))) {
      try { audit().safeEmit({
        action:   "jwt.iss.mismatch",
        outcome:  "denied",
        metadata: {
          expectedIssuer:  issuer,
          presentedIssuer: iss,
          reason:          "frontchannel-logout-cross-realm",
          primitive:       "oauth.parseFrontchannelLogoutRequest",
        },
        /* c8 ignore next -- drop-silent observability sink: safeEmit does not throw */
      }); } catch (_e) { /* drop-silent — observability sink */ }
      throw new OAuthError("auth-oauth/frontchannel-logout-iss-mismatch",
        "parseFrontchannelLogoutRequest: iss \"" + iss +
        "\" does not match configured issuer \"" + issuer +
        "\" (CVE-2026-23552 — cross-realm refused)");
    }
    return { iss: iss || issuer, sid: sid || null };
  }

  async function verifyBackchannelLogoutToken(logoutToken, vopts) {
    vopts = vopts || {};
    var logoutTokenIsString = typeof logoutToken === "string";
    if (!logoutTokenIsString || logoutToken.length === 0) {
      throw new OAuthError("auth-oauth/bad-logout-token",
        "verifyBackchannelLogoutToken: logoutToken must be a non-empty string");
    } else if (logoutToken.length > OAUTH_MAX_RESPONSE_BYTES) {
      throw new OAuthError("auth-oauth/logout-token-too-large",
        "verifyBackchannelLogoutToken: logout_token exceeds " +
        OAUTH_MAX_RESPONSE_BYTES + " bytes");
    }
    var parts = logoutToken.split(".");
    if (parts.length !== 3) {
      throw new OAuthError("auth-oauth/malformed-logout-token",
        "verifyBackchannelLogoutToken: logout_token must be a 3-segment JWS");
    }
    var headerObj;
    try { headerObj = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8"), { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (_e) {
      throw new OAuthError("auth-oauth/bad-logout-header",
        "verifyBackchannelLogoutToken: malformed header");
    }
    if (headerObj.typ !== "logout+jwt") {
      throw new OAuthError("auth-oauth/wrong-typ",
        "verifyBackchannelLogoutToken: header.typ must be \"logout+jwt\" (got \"" +
        headerObj.typ + "\")");
    }
    var verified = await verifyIdToken(logoutToken, {
      skipNonceCheck: true,
      skipExpCheck:   true,
      maxAgeSec:      vopts.maxAgeSec,
    });
    var claims = verified.claims;

    /* c8 ignore next 5 -- defense-in-depth: verifyIdToken's skipExpCheck self-guard already enforced the backchannel-logout event before returning, so this re-check never fires */
    if (!claims.events || typeof claims.events !== "object" ||
        !claims.events["http://schemas.openid.net/event/backchannel-logout"]) {
      throw new OAuthError("auth-oauth/missing-logout-event",
        "verifyBackchannelLogoutToken: payload.events missing http://schemas.openid.net/event/backchannel-logout");
    }
    if (Object.prototype.hasOwnProperty.call(claims, "nonce")) {
      throw new OAuthError("auth-oauth/forbidden-nonce",
        "verifyBackchannelLogoutToken: payload.nonce is forbidden in logout tokens (§2.6)");
    }
    if (!claims.sub && !claims.sid) {
      throw new OAuthError("auth-oauth/no-sub-or-sid",
        "verifyBackchannelLogoutToken: payload must include sub or sid");
    }
    var logoutMaxAgeSec = typeof vopts.maxAgeSec === "number"
      ? vopts.maxAgeSec
      : DEFAULT_LOGOUT_TOKEN_MAX_AGE_SEC;
    var nowSecLogout = Math.floor(Date.now() / C.TIME.seconds(1));
    /* c8 ignore next 4 -- defense-in-depth: verifyIdToken's skipExpCheck freshness gate already required a numeric iat before returning, so this re-check never fires */
    if (typeof claims.iat !== "number") {
      throw new OAuthError("auth-oauth/logout-token-no-iat",
        "verifyBackchannelLogoutToken: payload.iat required (OIDC BCL §2.4)");
    }
    if (claims.iat + logoutMaxAgeSec < nowSecLogout) {
      throw new OAuthError("auth-oauth/logout-token-too-old",
        "verifyBackchannelLogoutToken: payload.iat=" + claims.iat +
        " is older than maxAgeSec=" + logoutMaxAgeSec +
        " (OIDC BCL §2.6 — old logout-token refused)");
    }
    if (vopts.atomicReplayStore && typeof vopts.atomicReplayStore.checkAndInsert === "function") {
      if (typeof claims.jti !== "string" || claims.jti.length === 0) {
        throw new OAuthError("auth-oauth/no-jti",
          "verifyBackchannelLogoutToken: jti required when atomicReplayStore is configured");
      }
      var expireAtMs = (nowSecLogout + logoutMaxAgeSec * 2) * C.TIME.seconds(1);
      var inserted;
      try { inserted = await vopts.atomicReplayStore.checkAndInsert(claims.jti, expireAtMs); }
      catch (e) {
        throw new OAuthError("auth-oauth/replay-store-failed",
          "verifyBackchannelLogoutToken: atomicReplayStore.checkAndInsert threw: " +
          ((e && e.message) || String(e)));
      }
      if (!inserted) {
        throw new OAuthError("auth-oauth/logout-token-replay",
          "verifyBackchannelLogoutToken: jti '" + claims.jti +
          "' already seen — replay refused (atomic)");
      }
    } else if (typeof vopts.seen === "function") {
      if (typeof claims.jti !== "string" || claims.jti.length === 0) {
        throw new OAuthError("auth-oauth/no-jti",
          "verifyBackchannelLogoutToken: jti required when a seen() callback is configured");
      }
      var first;
      try { first = await vopts.seen({ jti: claims.jti, iss: claims.iss, iat: claims.iat }); }
      catch (e) {
        throw new OAuthError("auth-oauth/seen-callback-failed",
          "verifyBackchannelLogoutToken: seen() callback threw: " + ((e && e.message) || String(e)));
      }
      if (!first) {
        throw new OAuthError("auth-oauth/logout-token-replay",
          "verifyBackchannelLogoutToken: jti already seen — replay refused");
      }
    }
    return {
      iss:    claims.iss,
      aud:    claims.aud,
      sub:    claims.sub || null,
      sid:    claims.sid || null,
      jti:    claims.jti || null,
      /* c8 ignore next -- iat is always a positive number here (enforced above), so the || null arm is unreachable */
      iat:    claims.iat || null,
      events: claims.events,
      claims: claims,
    };
  }

  async function checkSessionIframeUrl() {
    var url;
    try { url = await _resolveEndpoint("checkSessionIframe"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-check-session-iframe",
        "checkSessionIframeUrl: IdP discovery doc has no check_session_iframe " +
        "(set opts.checkSessionIframe on create() if the IdP doesn't publish it)");
    }
    return url;
  }

  /**
   * @primitive b.auth.oauth.introspectToken
   * @signature b.auth.oauth.introspectToken(token, opts?)
   * @since     0.8.77
   * @related   b.middleware.bearerAuth
   *
   * RFC 7662 OAuth 2.0 Token Introspection. Resource-server side
   * primitive: POSTs to the AS's introspection endpoint with the
   * presented token and returns the active/inactive verdict + claims.
   * `active: false` SHOULD be treated as token-invalid regardless of
   * other fields (RFC 7662 §2.2). When the AS supports `token_type_hint`,
   * pass `opts.tokenTypeHint` ("access_token" or "refresh_token") to
   * speed up the lookup; the AS may ignore the hint.
   *
   * @opts
   *   {
   *     tokenTypeHint?: "access_token" | "refresh_token",
   *   }
   *
   * @example
   *   var verdict = await oauth.introspectToken(bearer);
   *   if (!verdict.active) throw new Error("invalid_token");
   */
  async function introspectToken(token, iopts) {
    iopts = iopts || {};
    if (typeof token !== "string" || token.length === 0) {
      throw new OAuthError("auth-oauth/bad-introspect",
        "introspectToken: token must be a non-empty string");
    }
    var endpoint;
    try { endpoint = await _resolveEndpoint("introspectionEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-introspection-endpoint",
        "introspectToken: AS does not advertise introspection_endpoint " +
        "(set opts.introspectionEndpoint on create() if it's static)");
    }
    var body = new URLSearchParams();
    body.set("token", token);
    if (iopts.tokenTypeHint) body.set("token_type_hint", iopts.tokenTypeHint);
    body.set("client_id", clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    var parsed = await _postForm(endpoint, body, null, false);
    if (typeof parsed.active !== "boolean") {
      throw new OAuthError("auth-oauth/bad-introspect-response",
        "introspectToken: response missing required `active` boolean");
    }
    return parsed;
  }

  /**
   * @primitive b.auth.oauth.registerClient
   * @signature b.auth.oauth.registerClient(metadata, opts?)
   * @since     0.8.77
   * @related   b.auth.oauth.introspectToken
   *
   * RFC 7591 OAuth 2.0 Dynamic Client Registration. POSTs the
   * client metadata to the AS's `registration_endpoint` and returns
   * the issued `client_id` + (for confidential clients) `client_secret`
   * + `registration_access_token` + `registration_client_uri`.
   *
   * The framework refuses to register a client without an explicit
   * `redirect_uris` array — RFC 7591 §2 makes it OPTIONAL but every
   * security-sensitive deployment needs it; mis-registering with an
   * empty list lets any redirect_uri be assigned later by the AS.
   *
   * @opts
   *   {
   *     initialAccessToken?: string,   // RFC 7591 §3 — bearer for the registration endpoint
   *   }
   *
   * @example
   *   var rv = await oauth.registerClient({
   *     redirect_uris:            ["https://rp.example/cb"],
   *     token_endpoint_auth_method: "client_secret_basic",
   *     grant_types:              ["authorization_code", "refresh_token"],
   *     response_types:           ["code"],
   *     client_name:              "Example RP",
   *   });
   *   // rv.client_id / rv.client_secret / rv.registration_access_token
   */
  async function registerClient(metadata, ropts) {
    ropts = ropts || {};
    if (!metadata || typeof metadata !== "object") {
      throw new OAuthError("auth-oauth/bad-register",
        "registerClient: metadata must be an object");
    }
    if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
      throw new OAuthError("auth-oauth/register-no-redirect-uris",
        "registerClient: metadata.redirect_uris must be a non-empty array " +
        "(RFC 7591 §2 makes it optional, but registering without explicit URIs " +
        "creates an open-redirect surface)");
    }
    for (var ri = 0; ri < metadata.redirect_uris.length; ri++) {
      _validateUrl(metadata.redirect_uris[ri], allowHttp,
        "metadata.redirect_uris[" + ri + "]");
    }
    var endpoint;
    try { endpoint = await _resolveEndpoint("registrationEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-registration-endpoint",
        "registerClient: AS does not advertise registration_endpoint");
    }
    var hc      = httpDialer;
    var headers = {
      "Content-Type": "application/json",
      "Accept":       "application/json",
    };
    if (ropts.initialAccessToken) {
      headers["Authorization"] = "Bearer " + ropts.initialAccessToken;
    }
    var req = {
      url:     endpoint,
      method:  "POST",
      headers: headers,
      body:    Buffer.from(safeJson.stringify(metadata), "utf8"),
    };
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    _mergeHttpClientOpts(req);
    var res  = await hc.request(req);
    /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
    var text = res.body ? res.body.toString("utf8") : "";
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new OAuthError("auth-oauth/register-failed-" + res.statusCode,
        "registerClient: " + res.statusCode + ": " + text.slice(0, 500));
    }
    var parsed;
    try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
      /* c8 ignore next 2 -- String(e) fallback: the parse error always carries a message */
      throw new OAuthError("auth-oauth/bad-register-response",
        "registerClient: response not JSON: " + ((e && e.message) || String(e)));
    }
    if (typeof parsed.client_id !== "string" || parsed.client_id.length === 0) {
      throw new OAuthError("auth-oauth/register-no-client-id",
        "registerClient: response missing client_id");
    }
    return parsed;
  }

  /**
   * @primitive b.auth.oauth.readClient
   * @signature b.auth.oauth.readClient(registrationClientUri, registrationAccessToken)
   * @since     0.10.16
   * @status    stable
   * @related   b.auth.oauth.registerClient, b.auth.oauth.updateClient, b.auth.oauth.deleteClient
   *
   * RFC 7592 §2.1 OAuth 2.0 Dynamic Client Registration Management
   * Protocol — read the current client configuration via GET against
   * the operator-supplied `registration_client_uri` carrying the
   * `registration_access_token`. Returns the AS's full client metadata.
   *
   * @example
   *   var meta = await oauth.readClient(rv.registration_client_uri,
   *     rv.registration_access_token);
   */
  async function readClient(registrationClientUri, registrationAccessToken) {
    return _dcrManagementCall("GET", registrationClientUri, registrationAccessToken, null);
  }

  /**
   * @primitive b.auth.oauth.updateClient
   * @signature b.auth.oauth.updateClient(registrationClientUri, registrationAccessToken, metadata)
   * @since     0.10.16
   * @status    stable
   *
   * RFC 7592 §2.2 update the dynamically-registered client's metadata
   * via PUT. The AS may rotate `registration_access_token` / regenerate
   * `client_secret` in the response — operators MUST persist the new
   * values atomically with the update.
   *
   * @example
   *   var updated = await oauth.updateClient(
   *     rv.registration_client_uri,
   *     rv.registration_access_token,
   *     { redirect_uris: ["https://rp.example/cb-new"],
   *       grant_types:   ["authorization_code", "refresh_token"] });
   */
  async function updateClient(registrationClientUri, registrationAccessToken, metadata) {
    if (!metadata || typeof metadata !== "object") {
      throw new OAuthError("auth-oauth/bad-update",
        "updateClient: metadata must be an object");
    }
    if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
      throw new OAuthError("auth-oauth/update-no-redirect-uris",
        "updateClient: metadata.redirect_uris must be a non-empty array " +
        "(same posture as registerClient — RFC 7591/7592 makes it optional, " +
        "operating without explicit URIs creates an open-redirect surface)");
    }
    for (var ri = 0; ri < metadata.redirect_uris.length; ri++) {
      _validateUrl(metadata.redirect_uris[ri], allowHttp,
        "metadata.redirect_uris[" + ri + "]");
    }
    return _dcrManagementCall("PUT", registrationClientUri, registrationAccessToken, metadata);
  }

  /**
   * @primitive b.auth.oauth.deleteClient
   * @signature b.auth.oauth.deleteClient(registrationClientUri, registrationAccessToken)
   * @since     0.10.16
   * @status    stable
   *
   * RFC 7592 §2.3 deregister the dynamically-registered client via
   * DELETE. The AS responds 204 No Content on success; this primitive
   * returns true / throws on failure (404 = client already gone is
   * surfaced as a specific error so the caller can swallow it).
   *
   * @example
   *   await oauth.deleteClient(rv.registration_client_uri,
   *     rv.registration_access_token);
   */
  async function deleteClient(registrationClientUri, registrationAccessToken) {
    await _dcrManagementCall("DELETE", registrationClientUri, registrationAccessToken, null);
    return true;
  }

  async function _dcrManagementCall(method, registrationClientUri, registrationAccessToken, body) {
    if (typeof registrationClientUri !== "string" || registrationClientUri.length === 0) {
      throw new OAuthError("auth-oauth/bad-registration-client-uri",
        method.toLowerCase() + "Client: registrationClientUri must be a non-empty string");
    }
    if (typeof registrationAccessToken !== "string" || registrationAccessToken.length === 0) {
      throw new OAuthError("auth-oauth/bad-registration-access-token",
        method.toLowerCase() + "Client: registrationAccessToken must be a non-empty string");
    }
    _validateUrl(registrationClientUri, allowHttp, "registrationClientUri");
    var headers = {
      "Authorization": "Bearer " + registrationAccessToken,
      "Accept":        "application/json",
    };
    var req = {
      url:     registrationClientUri,
      method:  method,
      headers: headers,
    };
    if (body !== null) {
      headers["Content-Type"] = "application/json";
      req.body = Buffer.from(safeJson.stringify(body), "utf8");
    }
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    _mergeHttpClientOpts(req);
    var res = await httpDialer.request(req);
    if (method === "DELETE") {
      if (res.statusCode === C.HTTP.STATUS.NO_CONTENT || res.statusCode === C.HTTP.STATUS.OK) return null;
      if (res.statusCode === C.HTTP.STATUS.NOT_FOUND) {
        throw new OAuthError("auth-oauth/dcr-not-found",
          "deleteClient: 404 — registrationClientUri does not resolve to a client");
      }
      throw new OAuthError("auth-oauth/dcr-delete-failed-" + res.statusCode,
        "deleteClient: " + res.statusCode);
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
      var errText = res.body ? res.body.toString("utf8").slice(0, 500) : "";
      throw new OAuthError("auth-oauth/dcr-" + method.toLowerCase() + "-failed-" + res.statusCode,
        method.toLowerCase() + "Client: " + res.statusCode + ": " + errText);
    }
    /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
    var text = res.body ? res.body.toString("utf8") : "";
    try { return safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
      /* c8 ignore next 2 -- String(e) fallback: the parse error always carries a message */
      throw new OAuthError("auth-oauth/dcr-bad-response",
        method.toLowerCase() + "Client: response not JSON: " + ((e && e.message) || String(e)));
    }
  }

  /**
   * @primitive b.auth.oauth.deviceAuthorization
   * @signature b.auth.oauth.deviceAuthorization(opts?)
   * @since     0.8.77
   * @related   b.auth.oauth.pollDeviceCode
   *
   * RFC 8628 OAuth 2.0 Device Authorization Grant. Initiates the
   * device-code flow by POSTing to the AS's device_authorization
   * endpoint. Returns `{ device_code, user_code, verification_uri,
   * verification_uri_complete?, expires_in, interval }`. The caller
   * displays `user_code` + `verification_uri` to the user, then polls
   * via `pollDeviceCode(device_code, { interval })`.
   *
   * @opts
   *   {
   *     scope?: string[],    // override the client's default scope set
   *   }
   *
   * @example
   *   var auth = await oauth.deviceAuthorization();
   *   console.log("Visit " + auth.verification_uri + " and enter " + auth.user_code);
   *   var tokens = await oauth.pollDeviceCode(auth.device_code, { interval: auth.interval });
   */
  async function deviceAuthorization(dopts) {
    dopts = dopts || {};
    var endpoint;
    try { endpoint = await _resolveEndpoint("deviceAuthorizationEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-device-endpoint",
        "deviceAuthorization: AS does not advertise device_authorization_endpoint");
    }
    var body = new URLSearchParams();
    body.set("client_id", clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    var scopes = Array.isArray(dopts.scope) ? dopts.scope : scope;
    if (scopes && scopes.length > 0) body.set("scope", scopes.join(" "));
    var parsed = await _postForm(endpoint, body, null, false);
    if (typeof parsed.device_code !== "string" ||
        typeof parsed.user_code   !== "string" ||
        typeof parsed.verification_uri !== "string") {
      throw new OAuthError("auth-oauth/bad-device-response",
        "deviceAuthorization: response missing device_code / user_code / verification_uri");
    }
    return parsed;
  }

  /**
   * @primitive b.auth.oauth.pollDeviceCode
   * @signature b.auth.oauth.pollDeviceCode(deviceCode, opts?)
   * @since     0.8.77
   * @related   b.auth.oauth.deviceAuthorization
   *
   * Polls the token endpoint with grant_type=urn:ietf:params:oauth:
   * grant-type:device_code per RFC 8628 §3.4-§3.5. Honors the slow_down
   * error by extending the interval; returns the token response on
   * success; throws on expired_token / access_denied.
   *
   * @opts
   *   {
   *     interval?:  number,        // seconds — default from deviceAuthorization()
   *     maxWaitMs?: number,        // total budget (default 600s)
   *   }
   *
   * @example
   *   var auth = await oauth.deviceAuthorization();
   *   var tokens = await oauth.pollDeviceCode(auth.device_code, { interval: auth.interval });
   */
  async function pollDeviceCode(deviceCode, popts) {
    popts = popts || {};
    if (typeof deviceCode !== "string" || deviceCode.length === 0) {
      throw new OAuthError("auth-oauth/bad-device-code",
        "pollDeviceCode: deviceCode must be a non-empty string");
    }
    if (deviceCode.length > MAX_DEVICE_CODE_BYTES) {
      throw new OAuthError("auth-oauth/device-code-too-large",
        "pollDeviceCode: deviceCode exceeds " + MAX_DEVICE_CODE_BYTES + " bytes " +
        "(RFC 8628 §3.4 — opaque server-generated code, no legitimate need for length above the cap)");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var interval = Math.max(MIN_DEVICE_POLL_INTERVAL_SEC, popts.interval || MIN_DEVICE_POLL_INTERVAL_SEC);
    var deadline = Date.now() + (popts.maxWaitMs || C.TIME.minutes(10));
    while (Date.now() < deadline) {
      var body = new URLSearchParams();
      body.set("grant_type",  "urn:ietf:params:oauth:grant-type:device_code");
      body.set("device_code", deviceCode);
      body.set("client_id",   clientId);
      if (clientSecret) body.set("client_secret", clientSecret);
      var authHeaders = _clientBasicAuthHeaders(body);
      var hc  = httpDialer;
      var req = {
        url:     endpoint,
        method:  "POST",
        headers: Object.assign({
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept":       "application/json",
        }, authHeaders || {}),
        body:    Buffer.from(body.toString(), "utf8"),
      };
      if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
      if (allowInternal !== null) req.allowInternal = allowInternal;
      _mergeHttpClientOpts(req);
      req.responseMode = "always-resolve";
      var res    = await hc.request(req);
      /* c8 ignore next -- httpClient always yields a Buffer body, so the empty-string arm is unreachable */
      var text   = res.body ? res.body.toString("utf8") : "";
      var parsed;
      try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
      catch (_e) { parsed = null; }
      if (res.statusCode >= 200 && res.statusCode < 300 && parsed && parsed.access_token) {
        return await _normalizeTokens(parsed, popts);
      }
      var err = parsed && parsed.error;
      if (err === "authorization_pending") {
        await safeAsync.sleep(C.TIME.seconds(interval));
        continue;
      }
      if (err === "slow_down") {
        interval += 5;
        await safeAsync.sleep(C.TIME.seconds(interval));
        continue;
      }
      throw new OAuthError("auth-oauth/device-" + (err || "unknown"),
        "pollDeviceCode: " + (parsed && parsed.error_description ? parsed.error_description : text.slice(0, 200)));
    }
    /* c8 ignore next 2 -- the || fallback is unreachable: reaching this timeout requires a truthy (small) maxWaitMs; a falsy one yields the 10-minute deadline that never expires within a test window */
    throw new OAuthError("auth-oauth/device-poll-timeout",
      "pollDeviceCode: exceeded maxWaitMs " + (popts.maxWaitMs || C.TIME.minutes(10)));
  }

  /**
   * @primitive b.auth.oauth.exchangeToken
   * @signature b.auth.oauth.exchangeToken(opts)
   * @since     0.8.77
   * @related   b.auth.oauth.introspectToken
   *
   * RFC 8693 OAuth 2.0 Token Exchange. Trades a subject token (and
   * optionally an actor token for delegation chains) for a new
   * access token with different audience / scopes / authorization
   * context. Used by middleware tier services that need to call
   * downstream APIs on behalf of an upstream caller.
   *
   * @opts
   *   {
   *     subjectToken:     string,     // required
   *     subjectTokenType: string,     // required — RFC 8693 §3 URN
   *     actorToken?:      string,     // delegation actor
   *     actorTokenType?:  string,     // RFC 8693 §3 URN
   *     audience?:        string,
   *     resource?:        string,
   *     scope?:           string[],
   *     requestedTokenType?: string,  // default: access_token URN
   *   }
   *
   * @example
   *   var newTokens = await oauth.exchangeToken({
   *     subjectToken:     upstreamAccessToken,
   *     subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
   *     audience:         "https://downstream.example.com",
   *   });
   */
  async function exchangeToken(xopts) {
    xopts = xopts || {};
    if (typeof xopts.subjectToken !== "string" || xopts.subjectToken.length === 0) {
      throw new OAuthError("auth-oauth/bad-exchange",
        "exchangeToken: opts.subjectToken required");
    }
    if (typeof xopts.subjectTokenType !== "string") {
      throw new OAuthError("auth-oauth/bad-exchange",
        "exchangeToken: opts.subjectTokenType required (RFC 8693 §3 URN)");
    }
    if (RFC_8693_TOKEN_TYPES.indexOf(xopts.subjectTokenType) === -1 &&
        xopts.allowCustomTokenType !== true) {
      throw new OAuthError("auth-oauth/bad-subject-token-type",
        "exchangeToken: subjectTokenType '" + xopts.subjectTokenType + "' not in RFC 8693 §3 " +
        "(allowed: " + RFC_8693_TOKEN_TYPES.join(", ") + "); pass `allowCustomTokenType: true` " +
        "to accept operator-defined URNs");
    }
    if (xopts.actorTokenType &&
        RFC_8693_TOKEN_TYPES.indexOf(xopts.actorTokenType) === -1 &&
        xopts.allowCustomTokenType !== true) {
      throw new OAuthError("auth-oauth/bad-actor-token-type",
        "exchangeToken: actorTokenType '" + xopts.actorTokenType + "' not in RFC 8693 §3");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var body = new URLSearchParams();
    body.set("grant_type",           "urn:ietf:params:oauth:grant-type:token-exchange");
    body.set("subject_token",        xopts.subjectToken);
    body.set("subject_token_type",   xopts.subjectTokenType);
    body.set("client_id",            clientId);
    if (clientSecret)         body.set("client_secret", clientSecret);
    if (xopts.actorToken)     body.set("actor_token", xopts.actorToken);
    if (xopts.actorTokenType) body.set("actor_token_type", xopts.actorTokenType);
    if (xopts.audience)       body.set("audience", xopts.audience);
    if (xopts.resource)       body.set("resource", xopts.resource);
    if (xopts.scope && xopts.scope.length > 0) {
      body.set("scope", xopts.scope.join(" "));
    }
    if (xopts.requestedTokenType) {
      body.set("requested_token_type", xopts.requestedTokenType);
    }
    var parsed = await _postForm(endpoint, body);
    return await _normalizeTokens(parsed, xopts);
  }

  /**
   * @primitive b.auth.oauth.nativeSsoExchange
   * @signature b.auth.oauth.nativeSsoExchange(opts)
   * @since     0.10.16
   * @status    stable
   * @related   b.auth.oauth.exchangeToken
   *
   * OpenID Connect Native SSO 1.0 §6 — exchange a `device_secret` +
   * `id_token` pair for a fresh access token for a different client
   * on the same device (the "second app SSO" pattern). Composes
   * exchangeToken with the Native-SSO requested-token-type +
   * device-secret URNs.
   *
   * The device_secret comes from the AS in the same response body as
   * id_token on the initial authentication when the AS supports Native
   * SSO; sibling apps on the same device get it via a platform IPC
   * channel.
   *
   * @opts
   *   {
   *     deviceSecret:   string,    // required — opaque device_secret from initial auth
   *     idToken:        string,    // required — last-seen id_token bound to the device_secret
   *     audience?:      string,    // optional — second app's client_id / resource indicator
   *     scope?:         string[],
   *   }
   *
   * @example
   *   var tokens = await oauth.nativeSsoExchange({
   *     deviceSecret: secondAppRequest.deviceSecret,
   *     idToken:      secondAppRequest.idToken,
   *     audience:     "second-app-client-id",
   *   });
   */
  async function nativeSsoExchange(nopts) {
    nopts = nopts || {};
    if (typeof nopts.deviceSecret !== "string" || nopts.deviceSecret.length === 0) {
      throw new OAuthError("auth-oauth/bad-native-sso",
        "nativeSsoExchange: opts.deviceSecret required");
    }
    if (typeof nopts.idToken !== "string" || nopts.idToken.length === 0) {
      throw new OAuthError("auth-oauth/bad-native-sso",
        "nativeSsoExchange: opts.idToken required");
    }
    return await exchangeToken({
      subjectToken:        nopts.idToken,
      subjectTokenType:    "urn:ietf:params:oauth:token-type:id_token",
      actorToken:          nopts.deviceSecret,
      actorTokenType:      "urn:openid:params:token-type:device-secret",
      audience:            nopts.audience,
      scope:               nopts.scope,
      requestedTokenType:  "urn:ietf:params:oauth:token-type:access_token",
    });
  }

  function clientAttestationHeaders(copts) {
    copts = copts || {};
    var audience = copts.audience || issuer;
    if (!audience) {
      throw new OAuthError("auth-oauth/attestation-no-aud",
        "clientAttestationHeaders: opts.audience (AS issuer) is required when the client " +
        "was created without an issuer");
    }
    var attestation = buildClientAttestation({
      clientId:           clientId,
      attesterPrivateKey: copts.attesterPrivateKey,
      instanceKeyJwk:     copts.instanceKeyJwk,
      algorithm:          copts.algorithm,
      expiresInSec:       copts.expiresInSec,
    });
    var pop = buildClientAttestationPop({
      instancePrivateKey: copts.instancePrivateKey,
      audience:           audience,
      algorithm:          copts.popAlgorithm || copts.algorithm,
      challenge:          copts.challenge,
      expiresInSec:       copts.popExpiresInSec,
    });
    return {
      attestation: attestation,
      pop:         pop,
      headers: {
        "OAuth-Client-Attestation":     attestation,
        "OAuth-Client-Attestation-PoP": pop,
      },
    };
  }

  function _validateScopeOpt(scopeOpt, label) {
    if (scopeOpt === undefined || scopeOpt === null || typeof scopeOpt === "string") return;
    if (Array.isArray(scopeOpt) && scopeOpt.every(function (x) { return typeof x === "string"; })) return;
    throw new OAuthError("auth-oauth/bad-scope",
      label + ": scope must be a string or an array of strings");
  }

  function _scopeParam(override) {
    var s = override;
    if (Array.isArray(s)) return s.length > 0 ? s.join(" ") : null;
    if (typeof s === "string" && s.length > 0) return s;
    return null;
  }

  /**
   * @primitive b.auth.oauth.clientCredentials
   * @signature b.auth.oauth.clientCredentials(opts?)
   * @since     0.18.8
   * @status    stable
   * @related   b.auth.oauth.clientCredentialsManager
   *
   * RFC 6749 §4.4 <code>client_credentials</code> grant — machine-to-machine
   * authentication with no user present. POSTs
   * <code>grant_type=client_credentials</code> to the token endpoint,
   * authenticating with the client id/secret via <code>client_secret_post</code>
   * (default) or <code>client_secret_basic</code>, and returns the access token.
   * A machine-to-machine request sends NO scope unless you supply one — the
   * client's authorization-code scope default is not applied. Per the RFC a
   * refresh_token is NEVER issued for this grant — present the credentials again
   * to renew (see <code>clientCredentialsManager</code> for a cached,
   * auto-renewing wrapper). A client_credentials-only client needs no
   * <code>redirectUri</code> at <code>create</code>.
   *
   * Resolves <code>{ accessToken, tokenType, expiresIn, expiresAt, scope }</code>
   * where <code>expiresAt</code> is an epoch-ms deadline (or null when the AS
   * omits <code>expires_in</code>).
   *
   * @opts
   *   scope: string[] | string,   // scope for this token (default: none — a machine-to-machine request sends no scope)
   *
   * @example
   *   var t = await oauth.clientCredentials();
   *   await fetch(api, { headers: { Authorization: "Bearer " + t.accessToken } });
   */
  async function clientCredentials(ccopts) {
    ccopts = validateOpts.requireObject(ccopts === undefined ? {} : ccopts,
      "clientCredentials", OAuthError, "auth-oauth/bad-opts");
    validateOpts(ccopts, ["scope"], "clientCredentials");
    _validateScopeOpt(ccopts.scope, "clientCredentials");
    if (!clientSecret) {
      throw new OAuthError("auth-oauth/no-client-secret",
        "clientCredentials: a clientSecret is required for the client_credentials grant");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var body = new URLSearchParams();
    body.set("grant_type", "client_credentials");
    body.set("client_id", clientId);
    body.set("client_secret", clientSecret);
    var reqScope = _scopeParam(ccopts.scope === undefined ? null : ccopts.scope);
    if (reqScope) body.set("scope", reqScope);
    var raw = await _postForm(endpoint, body);
    if (!raw || typeof raw.access_token !== "string" || raw.access_token.length === 0) {
      throw new OAuthError("auth-oauth/no-access-token",
        "clientCredentials: token endpoint response has no access_token");
    }
    var expiresIn = (typeof raw.expires_in === "number" && isFinite(raw.expires_in) && raw.expires_in > 0)
                      ? Math.floor(raw.expires_in) : null;
    return {
      accessToken: raw.access_token,
      tokenType:   typeof raw.token_type === "string" ? raw.token_type : "Bearer",
      expiresIn:   expiresIn,
      expiresAt:   expiresIn !== null ? Date.now() + C.TIME.seconds(expiresIn) : null,
      scope:       typeof raw.scope === "string" ? raw.scope : reqScope,
    };
  }

  /**
   * @primitive b.auth.oauth.clientCredentialsManager
   * @signature b.auth.oauth.clientCredentialsManager(opts?)
   * @since     0.18.8
   * @status    stable
   * @related   b.auth.oauth.clientCredentials
   *
   * A memory-cached <code>client_credentials</code> token manager.
   * <code>getToken()</code> returns a valid bearer access token — fetching one
   * on first use and re-fetching <code>refreshSkewSec</code> before expiry (60s
   * by default). Concurrent <code>getToken()</code> calls during a fetch share
   * ONE in-flight request (no thundering herd). A 429 from the token endpoint
   * opens a short backoff window during which the still-cached token is served
   * rather than hammering the AS. State is per-manager and in-memory only —
   * seal the long-lived <code>clientSecret</code> at rest yourself.
   *
   * @opts
   *   scope:          string[] | string,  // override the client's scope
   *   refreshSkewSec: number,             // re-fetch this many seconds before expiry (default: 60)
   *   backoffSec:     number,             // 429 backoff window (default: 30)
   *
   * @example
   *   var mgr = oauth.clientCredentialsManager();
   *   var token = await mgr.getToken();   // cached + auto-renewed
   */
  function clientCredentialsManager(mopts) {
    mopts = validateOpts.requireObject(mopts === undefined ? {} : mopts,
      "clientCredentialsManager", OAuthError, "auth-oauth/bad-opts");
    validateOpts(mopts, ["scope", "refreshSkewSec", "backoffSec"], "clientCredentialsManager");
    _validateScopeOpt(mopts.scope, "clientCredentialsManager");
    numericBounds.requirePositiveFiniteIntIfPresent(mopts.refreshSkewSec, "refreshSkewSec",
      OAuthError, "auth-oauth/bad-refresh-skew");
    numericBounds.requirePositiveFiniteIntIfPresent(mopts.backoffSec, "backoffSec",
      OAuthError, "auth-oauth/bad-backoff");
    var skewMs    = typeof mopts.refreshSkewSec === "number" ? C.TIME.seconds(mopts.refreshSkewSec) : C.TIME.minutes(1);
    var backoffMs = typeof mopts.backoffSec === "number" ? C.TIME.seconds(mopts.backoffSec) : C.TIME.seconds(30);
    var cached = null;
    var inflight = null;
    var backoffUntil = 0;

    function _isTransientRefreshError(e) {
      /* c8 ignore next -- e is always a coded error from the refresh; the null guard is defensive */
      if (!e) return false;
      var m = /^auth-oauth\/token-error-(\d+)$/.exec(e.code);
      if (m) { var s = parseInt(m[1], 10); return s === 429 || s >= 500; }
      return e.permanent === false;
    }

    function _usable(now) {
      if (!cached || cached.expiresAt === null || cached.expiresAt <= now) return false;
      var effectiveSkew = (cached.lifetimeMs !== null && cached.lifetimeMs <= skewMs)
        ? cached.lifetimeMs / 2
        : skewMs;
      return cached.expiresAt - now > effectiveSkew;
    }
    function _servableDuringBackoff(now) {
      return cached && cached.expiresAt !== null && cached.expiresAt > now;
    }
    async function getToken() {
      var now = Date.now();
      if (_usable(now)) return cached.accessToken;
      if (now < backoffUntil) {
        if (_servableDuringBackoff(now)) return cached.accessToken;
        throw new OAuthError("auth-oauth/backoff-active",
          "clientCredentialsManager: token endpoint is in 429 backoff and no still-valid cached token is available");
      }
      if (inflight) return inflight;
      inflight = clientCredentials({ scope: mopts.scope }).then(function (t) {
        cached = { accessToken: t.accessToken, expiresAt: t.expiresAt,
          lifetimeMs: t.expiresIn !== null ? C.TIME.seconds(t.expiresIn) : null };
        backoffUntil = 0;
        inflight = null;
        return t.accessToken;
      }, function (e) {
        inflight = null;
        if (_isTransientRefreshError(e)) {
          var waitMs = (e.code === "auth-oauth/token-error-429" && typeof e.retryAfterMs === "number" && e.retryAfterMs > 0)
            ? e.retryAfterMs : backoffMs;
          backoffUntil = Date.now() + waitMs;
          if (_servableDuringBackoff(Date.now())) return cached.accessToken;
        }
        throw e;
      });
      return inflight;
    }
    return { getToken: getToken };
  }

  return {
    authorizationUrl:                authorizationUrl,
    exchangeCode:                    exchangeCode,
    clientCredentials:               clientCredentials,
    clientCredentialsManager:        clientCredentialsManager,
    refreshAccessToken:              refreshAccessToken,
    fetchUserInfo:                   fetchUserInfo,
    revokeToken:                     revokeToken,
    verifyIdToken:                   verifyIdToken,
    discover:                        _discover,
    endSessionUrl:                   endSessionUrl,
    pushAuthorizationRequest:        pushAuthorizationRequest,
    parseFrontchannelLogoutRequest:  parseFrontchannelLogoutRequest,
    verifyBackchannelLogoutToken:    verifyBackchannelLogoutToken,
    checkSessionIframeUrl:           checkSessionIframeUrl,
    parseCallback:                   parseCallback,
    parseJarmResponse:               parseJarmResponse,
    introspectToken:                 introspectToken,
    registerClient:                  registerClient,
    readClient:                      readClient,
    updateClient:                    updateClient,
    deleteClient:                    deleteClient,
    deviceAuthorization:             deviceAuthorization,
    pollDeviceCode:                  pollDeviceCode,
    exchangeToken:                   exchangeToken,
    nativeSsoExchange:               nativeSsoExchange,
    clientAttestationHeaders:        clientAttestationHeaders,
    issuer:              issuer,
    clientId:            clientId,
    redirectUri:         redirectUri,
    scope:               scope,
    isOidc:              isOidc,
  };
}

module.exports = {
  create:                create,
  PRESETS:               PRESETS,
  OAuthError:            OAuthError,
  DEFAULT_ACCEPTED_ALGS: DEFAULT_ACCEPTED_ALGS,
  ATTESTATION_ALGS:      ATTESTATION_ALGS,
  buildClientAttestation:    buildClientAttestation,
  buildClientAttestationPop: buildClientAttestationPop,
  verifyClientAttestation:   verifyClientAttestation,
  generatePkce:              generatePkce,
  _generatePkce:         _generatePkce,
  _generateRandomToken:  _generateRandomToken,
  _b64urlEncode:         _b64urlEncode,
  _b64urlDecode:         _b64urlDecode,
  _verifyParamsForAlg:   _verifyParamsForAlg,
  _crossCheckGrantedAuthorizationDetails: _crossCheckGrantedAuthorizationDetails,
};
