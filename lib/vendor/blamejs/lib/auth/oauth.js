// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * oauth — OAuth 2 / OIDC client.
 *
 * "Login with Google / GitHub / Microsoft / Apple / etc." — table
 * stakes for B2C and SSO B2B. Without this, operators reach for
 * `passport-*` packages and we lose control of the request flow.
 *
 * The framework's PQC-first stance applies to outbound crypto we
 * emit. OIDC IdPs sign ID tokens with classical-algo JWS (RS256,
 * ES256, etc.) — third-party crypto we MUST verify. This module
 * carries an OIDC-specific verifier for that interop case;
 * `lib/auth/jwt.js` remains PQC-only for tokens the FRAMEWORK signs.
 *
 * Public API:
 *
 *   var oauth = b.auth.oauth.create({
 *     provider:    "google",                              // preset
 *     clientId:    "...", clientSecret: "...",
 *     redirectUri: "https://app/auth/callback",
 *     scope:       ["openid", "email", "profile"],
 *   });
 *
 *   // Or generic:
 *   var oauth = b.auth.oauth.create({
 *     issuer:      "https://auth.example.com",            // OIDC discovery
 *     clientId, clientSecret, redirectUri, scope: [...],
 *   });
 *
 *   // Step 1 — Build the authorize URL. Operator persists the
 *   // returned `verifier` and `state` in their session.
 *   var auth = await oauth.authorizationUrl();
 *   //  → { url, state, nonce, verifier, challenge }
 *   res.redirect(302, auth.url);
 *
 *   // Step 2 — In the callback handler, verify state + exchange code.
 *   var stored = req.session.get("oauth-state");
 *   if (req.query.state !== stored.state) throw new ForbiddenError();
 *   var tokens = await oauth.exchangeCode({
 *     code:     req.query.code,
 *     state:    req.query.state,
 *     verifier: stored.verifier,
 *   });
 *   //  → { accessToken, idToken, refreshToken, tokenType, expiresIn,
 *   //      scope, claims, profile }
 *
 *   // Step 3 — operator decides: create user, link to existing, etc.
 *
 *   // Refresh:
 *   var fresh = await oauth.refreshAccessToken(tokens.refreshToken);
 *
 *   // Revoke (RFC 7009; not all providers support it — checked at
 *   // discovery, throws if unavailable):
 *   await oauth.revokeToken(tokens.refreshToken, { type: "refresh_token" });
 *
 *   // Userinfo (OIDC standard endpoint):
 *   var profile = await oauth.fetchUserInfo(tokens.accessToken);
 *
 * Vendor presets (b.auth.oauth.PRESETS):
 *   google     OIDC discovery via accounts.google.com
 *   microsoft  OIDC via login.microsoftonline.com (common tenant)
 *   apple      "Sign in with Apple" — RSA-PSS signed ID tokens
 *   auth0      OIDC via {tenant}.auth0.com (operator passes tenant)
 *   keycloak   OIDC via {host}/realms/{realm}/.well-known/...
 *   github     OAuth 2 only (NOT OIDC — no ID token; GitHub uses
 *              a userinfo-equivalent endpoint /user)
 *   generic    operator passes endpoints manually
 *
 * Discovery:
 *   When `issuer` (or a preset's discovery URL) is set, the client
 *   fetches `/.well-known/openid-configuration` on first use and
 *   caches authorization_endpoint, token_endpoint, jwks_uri,
 *   userinfo_endpoint, revocation_endpoint, supported algos. Cache
 *   default 1 hour; operators tune via `discoveryCacheMs`.
 *
 * PKCE:
 *   ON BY DEFAULT. RFC 7636. The framework refuses to build an
 *   authorization URL without PKCE unless the operator explicitly
 *   passes `pkce: false` (and even then it logs a warning). Operators
 *   on legacy IdPs that don't support PKCE — vanishingly rare in 2026
 *   — must opt out explicitly.
 *
 * State + nonce:
 *   Generated fresh per-call. The framework returns them but doesn't
 *   store them — that's the operator's session's job. The state
 *   verifies the OAuth callback came from the same browser session
 *   (CSRF defense); the nonce verifies the ID token wasn't replayed
 *   from a different login flow.
 *
 * ID token verification (when an ID token is present):
 *   - Header alg must be on `acceptedAlgorithms` (default RS256, RS384,
 *     RS512, ES256, ES384, ES512, PS256, PS384, PS512). HS256 is
 *     refused — symmetric-keyed ID tokens are an anti-pattern.
 *   - kid lookup against the discovered JWKS.
 *   - Signature verification via node:crypto for the matching algo.
 *   - Claim validation: iss matches issuer, aud contains clientId,
 *     exp not past, iat not future, nonce matches the call's nonce.
 *
 * HTTPS:
 *   All endpoints must be https except localhost during dev. The
 *   discovery / token / userinfo / revocation / jwks fetches go
 *   through `b.httpClient` which enforces the framework's PQC-locked
 *   posture by default (operators with mixed-protocol setups pass
 *   `allowedProtocols`).
 */

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
// Shared JOSE defenses (CVE-2026-22817 alg/kty cross-check +
// CVE-2026-23552 constant-time iss compare). Top-of-file per project
// convention §3; no circular load — jwt-external requires nothing from
// oauth.
var jwtExternal = require("./jwt-external");
// RFC 9101 request-object builder — composed by pushAuthorizationRequest
// when the operator opts into sending a signed request object. Top-of-file
// per convention §3; no circular load — jar requires jwt-external +
// validate-opts only, nothing from oauth.
var jar         = require("./jar");
var audit       = lazyRequire(function () { return require("../audit"); });

// Cap on responses parsed from upstream OAuth providers. Token /
// userinfo / discovery responses are tiny in spec; 256 KiB leaves
// huge headroom and prevents a hostile (or compromised) upstream
// from staging a parse-bomb against the framework.
var OAUTH_MAX_RESPONSE_BYTES = C.BYTES.kib(256);

var OAuthError = defineClass("OAuthError", { alwaysPermanent: true });

// Vendor presets. Each entry has either { issuer } (OIDC) or explicit
// endpoints { authorizationEndpoint, tokenEndpoint, userinfoEndpoint }.
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
    // Apple wants form_post response_mode (browser POSTs back to redirect).
    responseMode:  "form_post",
  },
  auth0: {
    // Operator passes auth0Domain: "tenant.auth0.com" via opts; we
    // expand it into the issuer URL.
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
    // Keycloak realms: opts.keycloakUrl + opts.keycloakRealm
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
    // GitHub is OAuth 2 only — no OIDC, no ID tokens, no JWKS.
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

// Random material lengths. PKCE verifier per RFC 7636 §4.1 needs >= 256
// bits of entropy; 32 bytes hits that exactly. State + nonce are 16
// bytes (128-bit unguessability) which is the minimum recommended by
// OAuth 2.0 Threat Model §4.4.1.8 / §4.4.1.13.
var PKCE_VERIFIER_BYTES        = C.BYTES.bytes(32);
var STATE_NONCE_BYTES          = C.BYTES.bytes(16);
// JOSE PSS salt lengths (RFC 7518 §3.5) now live with the shared alg table
// in jwtExternal.algParams; _verifyParamsForAlg here is a thin wrapper.

// RFC 8628 §3.4 — device_code length cap. The spec doesn't fix a max
// length but 8 KiB comfortably accommodates any legitimate base64url
// CSPRNG output and refuses pathological payloads.
var MAX_DEVICE_CODE_BYTES      = C.BYTES.kib(8);
// RFC 8628 §3.4 — 5s is the spec-documented MINIMUM polling interval.
var MIN_DEVICE_POLL_INTERVAL_SEC = 5;
// OIDC Back-Channel Logout §2.6 — replay defense via jti store catches
// duplicate-jti reuse, but pre-v0.9.x an old captured logout-token
// with a fresh jti could still pass. Enforce iat freshness against
// this floor (operator-tunable).
var DEFAULT_LOGOUT_TOKEN_MAX_AGE_SEC = C.TIME.minutes(5) / C.TIME.seconds(1);

// RFC 8693 §3 — registered token-type URNs for token exchange.
// Operators with custom URNs pass allowCustomTokenType:true with a
// documented downstream contract.
var RFC_8693_TOKEN_TYPES = Object.freeze([
  "urn:ietf:params:oauth:token-type:access_token",
  "urn:ietf:params:oauth:token-type:refresh_token",
  "urn:ietf:params:oauth:token-type:id_token",
  "urn:ietf:params:oauth:token-type:saml1",
  "urn:ietf:params:oauth:token-type:saml2",
  "urn:ietf:params:oauth:token-type:jwt",
  // openid-native-sso-1_0 §6 — device_secret is the token type
  // carrying the per-device long-lived secret returned alongside
  // id_token during native-sso-aware authentication.
  "urn:openid:params:token-type:device-secret",
]);

// ---- helpers ----

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
  // RFC 7636: code_verifier is 43–128 chars [A-Za-z0-9-._~].
  // base64url of 32 random bytes = 43 chars, all valid.
  var verifier = _b64urlEncode(generateBytes(PKCE_VERIFIER_BYTES));
  var challenge = _b64urlEncode(nodeCrypto.createHash("sha256").update(verifier).digest());
  return { verifier: verifier, challenge: challenge };
}

function _validateUrl(url, allowHttp, label) {
  if (typeof url !== "string" || url.length === 0) {
    throw new OAuthError("auth-oauth/bad-url", label + ": URL is required");
  }
  // RFC 9700 §4.1.1 — redirect URIs MUST be HTTPS, with an exception
  // for `http://localhost` and `http://127.0.0.1[:port]` to enable
  // local development. Pre-v0.8.33 operators developing on localhost
  // had to set `allowHttp: true` globally, which loosens the gate
  // for ALL operator-supplied URLs (issuer, discovery, token, etc.).
  // Now: when the URL is loopback, accept HTTP without flipping the
  // global flag.
  var isLocalhostHttp = false;
  try {
    var parsed = new URL(url);                                                                  // allow:raw-new-url-parse-only — RFC 9700 §4.1.1 localhost-exception lookup; safeUrl re-validates below for non-localhost paths
    // Strip trailing root-zone dot before the localhost compare.
    // RFC 1034 §3.1 — `localhost.` resolves identically to `localhost`;
    // without the strip, an attacker who registers `evil.com` as a
    // public OAuth issuer and supplies `http://localhost./...` (with
    // a trailing dot) slips past the equality check on a name that
    // some DNS configurations resolve to a different target than the
    // operator expects.
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

  // Operator-supplied OAuth issuer / endpoint URL — route through
  // safeUrl so the scheme allowlist is consistent with the rest of the
  // framework's outbound gates. Map safe-url's error codes to the
  // domain-specific oauth codes operators already key alerts on.
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

// ---- JOSE alg → node:crypto verify parameters ----

function _verifyParamsForAlg(alg) {
  // Returns { hash, padding, dsaEncoding } for node:crypto.verify, from the
  // shared classical-JOSE table (jwtExternal.algParams). ID-token verification
  // deliberately does NOT accept EdDSA — most OIDC OPs sign with RS256/ES256
  // and the framework keeps the ID-token verify surface to the RSA/ECDSA set.
  var params = jwtExternal.algParams(alg);
  if (!params || alg === "EdDSA") {
    throw new OAuthError("auth-oauth/unsupported-alg",
      "alg '" + alg + "' is not supported for ID-token verification");
  }
  return params;
}

// ---- JWKS → KeyObject ----

function _jwkToKey(jwk) {
  // node's createPublicKey accepts JWK directly since Node 16.
  return bCrypto.importPublicJwk(jwk, {
    errorClass:    OAuthError,
    code:          "auth-oauth/bad-jwk",
    messagePrefix: "could not import JWK (kid=" + (jwk && jwk.kid) + "): ",
  });
}

// ---- RFC 9396 Rich Authorization Requests (RAR) ----
//
// The client requests fine-grained, typed authorization via the
// `authorization_details` parameter (a JSON array of objects each
// carrying a required `type`). The authorization server returns the
// GRANTED `authorization_details` in the token response (RFC 9396 §7);
// the client cross-checks granted against requested so an AS (hostile
// or buggy) cannot silently broaden the grant — a granted detail whose
// `type` was never requested, or whose array-valued sub-fields
// (`locations` / `actions` / `datatypes` / `privileges`) exceed the
// requested set, is refused. This is the client-side mirror of the
// AS-side subset rule (RFC 9396 §6.3) and defends against an upstream
// privilege-escalation.

// Sub-fields whose values are bounded arrays of strings; a granted
// value here MUST be a subset of the requested value for the same type
// (RFC 9396 §2.1 — locations / actions / datatypes / privileges are the
// registered array-valued common data fields; `privileges` is the most
// authority-bearing of them, so an unchecked over-grant here is the
// sharpest escalation).
var RAR_SUBSET_FIELDS = Object.freeze(["locations", "actions", "datatypes", "privileges"]);

// Cap on a serialized authorization_details payload. RFC 9396 puts no
// fixed limit; 64 KiB matches the step-up RAR parser and refuses a
// pathological array without touching legitimate transaction payloads.
var RAR_MAX_BYTES = C.BYTES.kib(64);

// Validate the request-side authorization_details array. Config-time
// entry-point → THROW on bad shape (operator typo at boot). Mirrors
// step-up.parseAuthorizationDetails but operates on an already-parsed
// array (the operator passes opts.authorizationDetails as JS objects).
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

// True when `grantedVal` (an array of strings) contains an element not
// present in `requestedVal`. Anything the AS grants outside the request
// is an over-grant. A non-array granted value where the request was an
// array, or a granted array where no request entry constrained it, is
// also treated as exceeding.
function _arraySubfieldExceeds(grantedVal, requestedVal) {
  if (grantedVal === undefined) return false;          // not granted → can't exceed
  if (!Array.isArray(grantedVal)) {
    // AS returned a non-array where RAR defines an array field. If the
    // request didn't carry this field at all, an unconstrained scalar
    // is an over-grant; if it matches the requested scalar exactly it
    // is fine (lenient toward non-conforming-but-equal AS output).
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

// Decide whether a single granted authorization_detail exceeds what was
// requested. `requestedForType` is the matching request entry (same
// type) or null when the type was never requested.
function _grantedDetailExceeds(granted, requestedForType) {
  if (!requestedForType) return true;                  // type never requested
  for (var i = 0; i < RAR_SUBSET_FIELDS.length; i += 1) {
    var f = RAR_SUBSET_FIELDS[i];
    if (_arraySubfieldExceeds(granted[f], requestedForType[f])) return true;
  }
  return false;
}

// Cross-check the granted authorization_details from a token response
// against what the client requested. Returns the normalized granted
// array (or null when the AS returned none). `requested` is the
// validated request array (or null/undefined when RAR was not used).
//
// strict=true (default when requested details were sent): refuse on any
// over-grant. strict=false: surface but don't throw (operator audits).
function _crossCheckGrantedAuthorizationDetails(grantedRaw, requested, strict) {
  if (grantedRaw === undefined || grantedRaw === null) return null;
  if (!Array.isArray(grantedRaw)) {
    throw new OAuthError("auth-oauth/bad-granted-authorization-details",
      "token response authorization_details must be a JSON array (RFC 9396 §7)");
  }
  // Bound the parse cost of an attacker-influenced upstream payload.
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
    // Find a requested entry of the SAME type. Exact string equality on
    // the type field — never a substring scan.
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

// ---- OAuth 2.0 Attestation-Based Client Authentication ----
// (draft-ietf-oauth-attestation-based-client-auth-08)
//
// A FAPI / wallet client authenticates with two HTTP headers instead of
// a client_secret:
//   OAuth-Client-Attestation       — a JWT signed by the client's
//                                     BACKEND ("Attester"), binding the
//                                     client_id to a per-instance public
//                                     key via a `cnf` claim (§4).
//   OAuth-Client-Attestation-PoP    — a JWT signed by the per-instance
//                                     PRIVATE key (the one named in the
//                                     attestation's `cnf`), proving the
//                                     instance possesses that key (§5).
//
// The framework signs these with node:crypto directly — this is the
// classical-JWS interop case (the Attester / instance keys are RS/PS/ES/
// EdDSA), distinct from lib/auth/jwt.js which signs framework tokens
// PQC-only. HMAC ("none" included) is refused on both JWTs.

// Asymmetric JWS algorithms accepted for attestation + PoP. HMAC and
// "none" are intentionally absent (draft §5.2 requires an asymmetric
// signature for the PoP; we apply the same floor to the attestation).
var ATTESTATION_ALGS = Object.freeze([
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA",
]);

// draft-ietf-oauth-attestation-based-client-auth §4.1 / §5.1 — the REQUIRED,
// distinct `typ` header of each JWT. One literal per role, used by BOTH the
// builders (the value we emit) and the verifier (the value we pin) so the
// produced typ and the checked typ can never drift apart.
var ATTESTATION_JWT_TYP     = "oauth-client-attestation+jwt";
var ATTESTATION_POP_JWT_TYP = "oauth-client-attestation-pop+jwt";

// Cap on an attestation / PoP JWT. HTTP-header-borne JWTs are small;
// 16 KiB refuses a pathological header without touching real tokens.
var MAX_ATTESTATION_JWT_BYTES = C.BYTES.kib(16);

// Default acceptable PoP age (draft §8 step "iat within an acceptable
// time window"). Operator-tunable via opts.maxPopAgeSec.
var DEFAULT_POP_MAX_AGE_SEC = C.TIME.minutes(5) / C.TIME.seconds(1);

// Sign/verify params keyed by alg — superset of _verifyParamsForAlg that
// also covers EdDSA (used only on the attestation verify path; the
// ID-token verifier keeps its own narrower table untouched).
function _attestationCryptoParams(alg) {
  if (alg === "EdDSA") return { hash: null };
  return _verifyParamsForAlg(alg);
}

// _toAttestationPrivateKey / _resolveAttestationAlg / _signAttestationJws —
// thin wrappers over the classical-JWS signer that the jwt-external module
// owns (b.auth.jws.sign internals). The attestation path keeps its own
// `auth-oauth/attestation-*` error codes so operators routing alerts on
// that class see no change; the signer BODIES (alg-from-key derivation,
// compact-JWS assembly) live in exactly one place — the classical-JOSE
// domain owner — rather than duplicated here. RFC 7518 §3.1 alg↔key
// binding and the self-invalid-alg defenses are enforced by the composed
// primitive.

function _toAttestationPrivateKey(value, label) {
  try { return jwtExternal._toPrivateKey(value, label); }
  catch (e) {
    var code = (e && e.code) === "auth-jwt-external/sign-no-key"
      ? "auth-oauth/attestation-no-key" : "auth-oauth/attestation-bad-key";
    throw new OAuthError(code, (e && e.message) || String(e));
  }
}

// Resolve the JWS alg for an attestation / PoP signature. When the caller
// gives no `algorithm`, the composed signer infers the default that matches
// the key type so a non-EC attester key (RSA, Ed25519) yields a
// self-consistent JWS — header alg ⇄ signature key — instead of a fixed
// `ES256` header signed with the real key, which `verifyClientAttestation`'s
// alg/kty cross-check would then reject. An explicit alg incompatible with
// the key is refused BEFORE signing. The draft additionally floors the
// accepted set to ATTESTATION_ALGS (no HMAC / none); the composed resolver
// already refuses those, surfaced here as the attestation-specific code.
function _resolveAttestationAlg(explicitAlg, privateKey, label) {
  try {
    return jwtExternal._resolveSignAlg(explicitAlg, privateKey, label);
  } catch (e) {
    var ec = (e && e.code) || "";
    if (ec === "auth-jwt-external/sign-alg-key-mismatch") {
      throw new OAuthError("auth-oauth/attestation-alg-key-mismatch", (e && e.message) || String(e));
    }
    if (ec === "auth-jwt-external/sign-alg-refused" || ec === "auth-jwt-external/sign-alg-unsupported") {
      throw new OAuthError("auth-oauth/attestation-alg-not-accepted",
        label + ": alg '" + explicitAlg + "' is not an accepted attestation algorithm");
    }
    if (ec === "auth-jwt-external/sign-key-unsupported") {
      throw new OAuthError("auth-oauth/attestation-key-unsupported", (e && e.message) || String(e));
    }
    throw new OAuthError("auth-oauth/attestation-bad-key", (e && e.message) || String(e));
  }
}

function _signAttestationJws(header, payload, privateKey, alg) {
  return jwtExternal._signCompactJws(header, payload, privateKey, alg);
}

// Verify a compact JWS against an already-imported public KeyObject. The
// alg is read from the header but MUST equal expectedAlg AND match the
// key's kty (via the shared cross-check) — no alg-confusion window.
// `expectedTyp` (when supplied) pins the JOSE `typ` header so a JWT minted
// for another purpose but signed by the same key can't be replayed into the
// attestation / PoP slot.
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
  // Explicit typing (RFC 8725 §3.11 / draft-ietf-oauth-attestation-based-
  // client-auth §6): the attestation and PoP JWTs each carry a REQUIRED,
  // distinct `typ`. Pinning it stops a JWT minted for a different purpose
  // but signed by the same key (a private_key_jwt client assertion, another
  // proof-of-possession JWT) from being replayed into the attestation / PoP
  // slot — the cross-JWT confused-deputy class. The framework's other JWS
  // verifiers already pin typ (dpop+jwt, logout+jwt); this one now matches.
  if (typeof expectedTyp === "string" && header.typ !== expectedTyp) {
    throw new OAuthError("auth-oauth/attestation-wrong-typ",
      label + ": header.typ must be '" + expectedTyp + "' (RFC 8725 §3.11 " +
      "explicit typing); got " + JSON.stringify(header.typ));
  }
  // CVE-2026-22817 — cross-check alg against the key's kty before verify.
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
  } catch (verifyErr) {
    throw new OAuthError("auth-oauth/attestation-bad-signature",
      label + ": signature verification raised: " + ((verifyErr && verifyErr.message) || String(verifyErr)));
  }
  if (!ok) {
    throw new OAuthError("auth-oauth/attestation-bad-signature", label + ": signature verification failed");
  }
  return { header: header, payload: payload };
}

// Strip a JWK down to its public components only — a private half MUST
// never reach the attestation's cnf claim. Mirrors the dpop.buildProof
// public-only embed.
function _publicCnfJwk(jwk, label) {
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

// Config-time check for an OPTIONAL epoch-seconds override (iat / nbf): if
// present it must be a finite number, so a typo is caught at build time
// rather than silently ignored by the `typeof === "number"` body guard.
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
    // KeyObject | PEM string | JWK object — typed downstream by
    // _toAttestationPrivateKey; the shape only enforces presence.
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
    sub: aopts.clientId,                 // draft §4.1 — sub = client_id
    iat: iatSec,
    exp: iatSec + ttl,
    cnf: { jwk: cnfJwk },                // draft §4.1 — RFC 7800 cnf
  };
  if (typeof aopts.nbf === "number") payload.nbf = aopts.nbf;
  // Operator extra claims merged WITHOUT overriding the spec-required
  // fields (proto-pollution sentinels skipped, the spec keys reserved).
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
    // KeyObject | PEM string | JWK object — typed downstream by
    // _toAttestationPrivateKey; the shape only enforces presence.
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
    aud: popts.audience,                 // draft §5.2 — AS issuer
    jti: jti,                            // draft §5.2 — replay detection
    iat: iatSec,                         // draft §5.2
  };
  if (typeof popts.expiresInSec === "number") payload.exp = iatSec + popts.expiresInSec;
  if (typeof popts.challenge === "string" && popts.challenge.length > 0) {
    payload.challenge = popts.challenge; // draft §5.2 — server nonce
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

  // 1. Attestation signature against the TRUSTED attester key.
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
  // A present skew/maxAge must be a non-negative finite integer; a bare typeof
  // check lets Infinity/NaN through, and `exp + Infinity < now` (or NaN) is
  // always false — disabling the attestation/PoP expiry gates.
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
    // Exact equality (constant-time) — defends against a client_id the
    // request claims that the attestation never bound (draft §8 step 10).
    if (!_constantTimeStrEq(String(vopts.expectedClientId), ap.sub)) {
      throw new OAuthError("auth-oauth/attestation-client-id-mismatch",
        "client-attestation: sub does not match the request's client_id");
    }
  }

  // 2. PoP signature against the attestation's cnf key (NOT the attester).
  var pop = _verifyAttestationJws(popJwt, ap.cnf.jwk, "client-attestation-pop",
    ATTESTATION_POP_JWT_TYP);
  var pp = pop.payload || {};
  // aud MUST be THIS AS issuer (constant-time, exact). Attacker-replayed
  // PoP minted for a different AS is refused (draft §8 step 7).
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
  // challenge binding when the AS issued one (draft §8 step 5/6).
  if (vopts.challenge !== undefined && vopts.challenge !== null) {
    if (typeof pp.challenge !== "string" || !_constantTimeStrEq(String(vopts.challenge), pp.challenge)) {
      throw new OAuthError("auth-oauth/attestation-pop-challenge-mismatch",
        "client-attestation-pop: challenge does not match the server-issued value");
    }
  }
  // Replay defense (draft §12.1). Atomic check-and-insert contract:
  // returns truthy when the jti was UNSEEN (first sighting). The result
  // MAY be a Promise (Redis/DB store) — it is awaited so an async store's
  // resolved `false` (a replayed jti) refuses, instead of comparing a
  // never-`false` Promise object. Hot dep — a thrown / rejected callback
  // is surfaced as a typed error, not swallowed.
  if (typeof vopts.seenJti === "function") {
    var unseen;
    try {
      unseen = vopts.seenJti(pp.jti, pp.iat);
      if (unseen && typeof unseen.then === "function") unseen = await unseen;
    } catch (e) {
      throw new OAuthError("auth-oauth/attestation-pop-seen-callback-failed",
        "client-attestation-pop: seenJti() callback threw: " + ((e && e.message) || String(e)));
    }
    // Fail closed on ANY non-truthy result. The contract is "returns truthy
    // when UNSEEN"; an operator store fronting Redis EXISTS / SISMEMBER or a
    // SQL COUNT returns 0 (falsy, not `false`) on a replay, so an
    // `=== false` comparison would miss it and accept the replayed PoP.
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

// Constant-time string equality. b.crypto.timingSafeEqual accepts
// strings, returns false (never throws) on length mismatch, and refuses
// non-string/Buffer input — so it carries the timing + type discipline.
function _constantTimeStrEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return cryptoTimingSafeEqual(a, b);
}

// Framework-managed authorization-request parameters. Operator-supplied
// extraParams may not carry any of these — the builder generates them and
// RETURNS the security-critical ones (state, PKCE verifier/challenge) to the
// caller, so an extraParams override would silently diverge the returned
// values from what the URL/PAR body actually carries (a broken CSRF / PKCE
// binding). Covers redirect target, client identity, requested response,
// scope, state, nonce, PKCE challenge, response mode, RAR details, and the
// JAR request container.
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

// Refuse operator-supplied extraParams keys that collide with a framework-
// managed parameter. extraParams is operator-controlled, so a collision is a
// config-time bug (a library merge / copy-paste) — refuse it loudly rather
// than let it shadow a value the framework generated and returned. Fail
// closed; shared by authorizationUrl, pushAuthorizationRequest, and
// endSessionUrl so every URL/PAR builder guards the same way.
function _assertNoReservedExtraParams(extraParams, reserved, errCode, ctx) {
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

// ---- core ----

function create(opts) {
  opts = opts || {};
  var clientId     = opts.clientId;
  var clientSecret = opts.clientSecret || null;     // public clients can omit
  var redirectUri  = opts.redirectUri;
  // OAuth 2.1 baseline (draft-ietf-oauth-v2-1) makes PKCE mandatory for
  // ALL clients (not just public clients). The framework refuses
  // pkce: false outright — the prior "warn and continue" path was a
  // pre-1.0 leniency that's now closed. Operators integrating with
  // genuinely-broken legacy IdPs that don't accept code_challenge can
  // strip the parameters at their own ingress; the framework primitive
  // does not ship that escape hatch.
  if (opts.pkce === false) {
    throw new OAuthError("auth-oauth/pkce-required",
      "create: pkce: false is refused. OAuth 2.1 (draft-ietf-oauth-v2-1) " +
      "requires PKCE for all clients. Remove the opt or upgrade the IdP.");
  }
  var pkce = true;
  // A present clockSkewMs must be a non-negative finite integer; Infinity/NaN
  // would disable verifyIdToken's exp gate (`exp + Infinity < now` is always
  // false → an expired ID token verifies). Reject a malformed skew at config
  // time so the operator catches it.
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.clockSkewMs,
    "oauth.create: opts.clockSkewMs", OAuthError, "auth-oauth/bad-clock-skew");
  var clockSkewMs  = typeof opts.clockSkewMs === "number" ? opts.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  var discoveryCacheMs = typeof opts.discoveryCacheMs === "number"
                           ? opts.discoveryCacheMs : DEFAULT_DISCOVERY_CACHE_MS;
  var acceptedAlgorithms = Array.isArray(opts.acceptedAlgorithms) && opts.acceptedAlgorithms.length > 0
                             ? opts.acceptedAlgorithms.slice() : DEFAULT_ACCEPTED_ALGS.slice();
  var allowHttp        = !!opts.allowHttp;          // localhost dev opt-in (scheme)
  var allowInternal    = opts.allowInternal != null ? opts.allowInternal : null; // localhost dev opt-in (SSRF gate)
  var httpClientOpts   = opts.httpClient || {};
  var responseMode     = opts.responseMode || null;
  // v0.9.5 — client-level opt-out for the kid-less JWKS-of-one
  // refusal added in v0.9.4. Surfaced at the create() level (not
  // per-verifyIdToken-call) so it threads through every code path
  // that lands on verifyIdToken — _normalizeTokens for exchangeCode
  // / pollDeviceCode / exchangeToken / refreshAccessToken, JARM
  // wrapper, and the public verifyIdToken entry point. Operators
  // with non-conforming IdPs set this once at client construction.
  var allowKidlessJwks = opts.allowKidlessJwks === true;

  if (!clientId) {
    throw new OAuthError("auth-oauth/no-client-id", "create: opts.clientId is required");
  }
  if (!redirectUri) {
    throw new OAuthError("auth-oauth/no-redirect-uri", "create: opts.redirectUri is required");
  }
  _validateUrl(redirectUri, allowHttp, "redirectUri");

  // Resolve preset → effective config.
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
  // OIDC Core §15.5 — issuer is a URL the framework subsequently uses
  // as the OP identity in discovery + JWT iss comparisons. An operator
  // typo in opts.auth0Domain / opts.keycloakUrl flows into the preset's
  // issuerTemplate output verbatim; without validation that mistake
  // reaches discovery + the iss compare. Re-route through _validateUrl
  // so the issuer the framework will trust later is well-formed before
  // any network round-trip.
  if (issuer) _validateUrl(issuer, allowHttp, "issuer");
  var scope = Array.isArray(opts.scope) && opts.scope.length > 0
                ? opts.scope.slice()
                : (preset && preset.defaultScope ? preset.defaultScope.slice() : ["openid"]);
  if (!responseMode && preset && preset.responseMode) responseMode = preset.responseMode;

  // Endpoints — either from preset (explicit), discovery, or operator opts.
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
    // _resolveEndpoint maps these three snake-case discovery keys, and the
    // introspect / register / device-grant primitives resolve through it. A
    // static (non-discovery) client must be able to supply them as opts —
    // introspectToken's own no-endpoint refusal tells operators to set
    // opts.introspectionEndpoint, so create() has to actually read it.
    introspectionEndpoint: opts.introspectionEndpoint || (preset && preset.introspectionEndpoint) || null,
    registrationEndpoint:  opts.registrationEndpoint  || (preset && preset.registrationEndpoint)  || null,
    deviceAuthorizationEndpoint:
                           opts.deviceAuthorizationEndpoint ||
                           (preset && preset.deviceAuthorizationEndpoint) || null,
  };

  // Discovery + JWKS caches use b.cache.create + .wrap so concurrent
  // boot races for the same IdP collapse to one fetch (single-flight)
  // and operators can wire b.audit / observability without us
  // re-implementing those hooks here. Per-cache namespaces are unique
  // per oauth-client instance (clientId-scoped) so two clients pointed
  // at different IdPs don't collide in a future cluster-cache backend.
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
    var hc = httpClient;
    var req = Object.assign({
      url:    url,
      method: "GET",
    }, fetchOpts);
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    Object.assign(req, httpClientOpts);
    var res = await hc.request(req);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      var bodyText = res.body ? res.body.toString("utf8") : "";
      throw new OAuthError("auth-oauth/http-" + res.statusCode,
        url + " returned " + res.statusCode + ": " + bodyText.slice(0, 500));
    }
    if (!res.body) return null;
    try { return safeJson.parse(res.body.toString("utf8"), { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
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

  // PKCE downgrade defense (RFC 9700 §4.13 / OAuth 2.1 §6.2.4 +
  // RFC 7636). The client always sends code_challenge_method=S256 (the
  // plain method and pkce:false are refused). A network attacker who
  // can tamper with discovery metadata can advertise an OP that only
  // supports the `plain` method (or omits S256), nudging a permissive
  // client into a weaker exchange. We don't downgrade — but if the OP's
  // published `code_challenge_methods_supported` is PRESENT and does not
  // list "S256", the redirect we'd build sends an S256 challenge the OP
  // claims it cannot verify, which is the signature of a stripped-S256
  // MITM. Refuse rather than emit an authorization request the metadata
  // says will fail.
  //
  // Back-compat: an OP that does not publish the field at all keeps
  // today's behavior (S256 is still sent — RFC 7636 §4.2 lets the OP
  // accept S256 without advertising it). The check is a non-fetching
  // peek at the already-resolved discovery document: it never forces a
  // network round-trip, so static-endpoint clients (no discovery) are
  // unaffected. Config-time refusal — throw so the operator sees the
  // mismatch instead of a silently-doomed redirect.
  function _assertS256Supported(config) {
    if (!config || typeof config !== "object") return;
    var methods = config.code_challenge_methods_supported;
    if (!Array.isArray(methods)) return;       // field absent → keep behavior
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

  // Peek the cached discovery document WITHOUT triggering a fetch, so
  // the PKCE-downgrade gate only inspects metadata the client already
  // resolved on the discovery path. Returns null when no discovery has
  // occurred (static endpoints / non-OIDC) — back-compat preserved.
  async function _peekDiscovery() {
    if (!isOidc || !issuer) return null;
    try { return (await _discoveryCache.get("config")) || null; }
    catch (_e) { return null; }
  }

  async function _resolveEndpoint(name) {
    if (staticEndpoints[name]) return staticEndpoints[name];
    var config = await _discover();
    if (!config) {
      throw new OAuthError("auth-oauth/no-endpoint",
        name + " endpoint not configured and no OIDC discovery available");
    }
    // OIDC discovery uses snake_case key names.
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
    var endpoint = await _resolveEndpoint("authorizationEndpoint");
    // RFC 9700 §4.13 — refuse an OP whose discovery metadata advertises
    // code_challenge_methods_supported without S256 (PKCE downgrade /
    // stripped-S256 MITM). _resolveEndpoint already populated the
    // discovery cache on the OIDC path; this peek never fetches.
    _assertS256Supported(await _peekDiscovery());
    // CVE-2026-34511 — PKCE verifier leak via state. The state token is
    // an opaque CSPRNG output; the PKCE verifier is generated separately
    // and returned in its own field for the caller to store. The
    // `code_verifier` is NEVER concatenated into `state` and `state`
    // never carries operator-supplied PII. PKCE-S256 is the default
    // (pkce: false throws above); _generatePkce() emits
    // base64url(SHA-256(verifier)) per RFC 7636.
    var state = uopts.state || _generateRandomToken(STATE_NONCE_BYTES);
    var nonce = uopts.nonce || (isOidc ? _generateRandomToken(STATE_NONCE_BYTES) : null);
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
    // RFC 9396 — fine-grained authorization request. Validated at this
    // entry-point (THROW on bad shape) then serialized as the JSON-array
    // `authorization_details` parameter. The validated array is returned
    // so the caller can thread it into exchangeCode for the granted-vs-
    // requested cross-check.
    var requestedAuthzDetails = null;
    if (uopts.authorizationDetails !== undefined) {
      requestedAuthzDetails = _validateAuthorizationDetailsArray(
        uopts.authorizationDetails, "authorizationUrl");
      params.set("authorization_details", JSON.stringify(requestedAuthzDetails));
    }
    // Operator-supplied additional params (audience, resource, etc.).
    // Refuse keys that collide with a framework-managed parameter so an
    // operator typo / library-merge can't shadow the redirect_uri / state /
    // code_challenge the builder generated and returned — which would
    // silently diverge the returned {state, verifier} from the URL and
    // break the CSRF / PKCE binding.
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
      verifier:  pkceVals ? pkceVals.verifier  : null,
      challenge: pkceVals ? pkceVals.challenge : null,
      authorizationDetails: requestedAuthzDetails,
    };
  }

  async function exchangeCode(eopts) {
    eopts = eopts || {};
    if (!eopts.code) {
      throw new OAuthError("auth-oauth/no-code", "exchangeCode: opts.code is required");
    }
    if (pkce && !eopts.verifier) {
      throw new OAuthError("auth-oauth/no-verifier",
        "exchangeCode: opts.verifier is required when PKCE is on (default)");
    }
    // Nonce enforcement on OIDC paths. authorizationUrl() always
    // emits a nonce when isOidc; if the operator forgot to thread it
    // through to exchangeCode, _normalizeTokens silently skipped the
    // nonce check on the ID token and a captured token from another
    // browser session could be replayed without detection. Throw
    // loudly so the operator sees the bug at config time, not at
    // first-replay-attempt time.
    // Require a NON-EMPTY STRING nonce, not merely a defined one: a falsy
    // nonce (null / "" — e.g. a session field that was never set) would slip a
    // strict `=== undefined` guard, and the downstream verifier only checks the
    // nonce when vopts.nonce is truthy, so the ID-token nonce check would be
    // silently skipped and a token captured from another session replayed.
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
    // RFC 9396 — the operator threads the requested authorization_details
    // (the validated array returned from authorizationUrl /
    // pushAuthorizationRequest) so the granted set in the token response
    // can be cross-checked. The array is also re-sent on the token
    // request, which RFC 9396 §6.3 allows for narrowing the grant.
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
    // OAuth 2.1 §6.1 / RFC 9700 §4.13 — refresh-token replay defense.
    // Operator passes a `seen(refreshToken)` callback that returns
    // truthy when the SAME refresh_token has been presented before.
    // The framework refuses the request loudly because OAuth 2.1
    // mandates one-time-use refresh tokens for public + non-sender-
    // constrained confidential clients. Operators with sender-
    // constrained tokens (DPoP / mTLS) can opt out by NOT supplying
    // a seen callback.
    //
    // Atomic check-and-insert — pre-v0.9.3 the
    // check ran via `ropts.seen(token)` which was a check-then-act
    // race: two concurrent refresh requests landed on the same
    // event-loop tick could both see `seen === false` and both POST
    // to the token endpoint, neither flagging the replay. The
    // framework-wide checkAndInsert contract (lib/nonce-store.js,
    // lib/auth/jwt.js) is: returns `true` when the value was UNSEEN
    // and is now recorded (first sighting); returns `false` when
    // already present (replay). The legacy `seen` callback returned
    // the opposite (true means seen-already); both surfaces are
    // supported but normalize to a single `alreadySeen` boolean
    // below.
    var alreadySeen = false;
    if (typeof ropts.checkAndInsert === "function") {
      var nowMs = Date.now();
      // 24h max refresh-token TTL — operators with shorter TTLs
      // should configure their store's own expiry policy.
      var expireAtMs = nowMs + C.TIME.hours(24);
      var inserted;
      try { inserted = await ropts.checkAndInsert(refreshToken, expireAtMs); }
      catch (e) {
        throw new OAuthError("auth-oauth/seen-callback-failed",
          "refreshAccessToken: checkAndInsert() callback threw: " + ((e && e.message) || String(e)));
      }
      // Spec contract: a TRUTHY result → first sighting (the value was
      // inserted, OK); a FALSY result → replay. v0.9.3 had this inverted,
      // which broke every first refresh attempt for operators reusing an
      // existing b.nonceStore-style backend. Test truthiness, not an
      // `=== false` literal: a store fronting Redis SETNX / SQL INSERT
      // returns 0 (falsy, not `false`) when the row already existed, so
      // an exact-literal compare would miss the replay and fail OPEN.
      alreadySeen = !inserted;
    } else if (typeof ropts.seen === "function") {
      // Legacy non-atomic path. Documented as a check-then-act race;
      // operators sharing a single-writer store (Redis SETNX, DB
      // INSERT ON CONFLICT) MUST migrate to checkAndInsert. Stays
      // here for backwards-compat with existing operator code.
      // Legacy contract: truthy → the token was presented before (replay).
      // The value is used by truthiness at the gate below, so a store
      // returning 1 from Redis EXISTS / a SQL COUNT is honored as "seen"
      // instead of being missed by an `=== true` literal compare.
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
    // Refreshed tokens may not include a new id_token; verification
    // is conditional. We surface rotation explicitly so the operator's
    // store can swap the old refresh_token for the new one and feed
    // the new one to the next seen() check.
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
    // RFC 9207 — when the OP echoes `iss`, cross-check it against the
    // configured issuer. Defends against the mix-up attack where an
    // honest-but-curious OP receives a code intended for a different
    // OP. The cross-check is critical for OPs with multi-tenant
    // shared clients.
    var requireIss = popts.requireIssParam === true;
    if (!requireIss) {
      // OP discovery may advertise support; check once.
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
      // Constant-time compare on the CSRF state token. Project
      // discipline (auth/dpop.js, mail-srs.js, webhook.js) is
      // timingSafeEqual for any secret-shaped value compared
      // against attacker-controlled input.
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
   *     acceptedAlgs?:     string[],   // default: framework's accepted set
   *     maxClockSkewMs?:   number,
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
    // Reuse verifyIdToken's JWKS-lookup + signature path. JARM
    // responses share the OP's signing keypair; the checks differ
    // only in claim validation (no nonce, audience = clientId, no
    // ID-token-specific claims). We wrap verifyIdToken with the
    // skip-nonce flag and apply JARM-specific claim checks below.
    // verifyIdToken applies the create()-level accepted algorithms / JWKS /
    // clock-skew; only the JARM-specific skip-nonce flag is passed here.
    var verified = await verifyIdToken(responseJwt, {
      skipNonceCheck: true,
    });
    var c = verified.claims;
    // Per JARM §4: `iss` MUST match the OP issuer; `aud` MUST contain
    // the client_id; `exp` enforced (verifyIdToken already does);
    // `nonce` MUST NOT be present (JARM responses are not ID tokens).
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

  // OIDC requires fetchUserInfo to be called AFTER the id_token has
  // been verified and its sub claim is known — otherwise the
  // userinfo response can't be cross-checked against the id_token's
  // sub, and a hostile IdP could swap the userinfo for a different
  // user. RFC 7662 §3 doesn't mandate the cross-check but every OIDC
  // conformance suite requires it. We refuse to call userinfo when
  // isOidc=true unless the caller threaded the verified idTokenSub
  // (or explicitly opted out via skipSubCheck for a non-OIDC OAuth
  // 2.0 server presented as isOidc=false).
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
    var hc = httpClient;
    var req = {
      url:     endpoint,
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    Buffer.from(body.toString(), "utf8"),
    };
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    Object.assign(req, httpClientOpts);
    var res = await hc.request(req);
    // RFC 7009: 200 even if the token was already revoked / unknown.
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new OAuthError("auth-oauth/revoke-failed",
        "revocation returned " + res.statusCode);
    }
  }

  async function _postForm(endpoint, body) {
    var hc = httpClient;
    var req = {
      url:     endpoint,
      method:  "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "application/json",
      },
      body:    Buffer.from(body.toString(), "utf8"),
    };
    if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (allowInternal !== null) req.allowInternal = allowInternal;
    Object.assign(req, httpClientOpts);
    var res = await hc.request(req);
    var text = res.body ? res.body.toString("utf8") : "";
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new OAuthError("auth-oauth/token-error-" + res.statusCode,
        endpoint + " returned " + res.statusCode + ": " + text.slice(0, 500));
    }
    var parsed;
    try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
      throw new OAuthError("auth-oauth/bad-token-json",
        "token endpoint response not JSON: " + ((e && e.message) || String(e)));
    }
    return parsed;
  }

  async function _normalizeTokens(raw, vopts) {
    vopts = vopts || {};
    // RFC 6749 §3.3 — scope is space-separated, ONLY U+0020. `\s+` previously
    // matched U+0085 NEL, U+00A0 NBSP, etc., so a hostile AS returning
    // `scope: "admin<NEL>read"` would surface as `["admin", "read"]` and the
    // operator's scope allowlist saw two distinct scopes. Spec-strict split on
    // single-space keeps a non-token separator inside one token.
    //
    // §5.1 also fixes the PRESENT-vs-ABSENT distinction that a bare truthiness
    // test lost: an ABSENT scope ("OPTIONAL, if identical to the requested
    // scope") means the client got what it asked for → mirror the request; a
    // PRESENT scope is authoritative, INCLUDING the empty string, which grants
    // ZERO scopes. Coercing "" to the requested set (its falsy value slipped
    // the old `raw.scope ? …` test into the absent branch) would report a
    // downscoped-to-nothing grant as the full requested set — a scope-based
    // authorization guard downstream then treats denied scopes as granted. A
    // malformed non-string scope is treated as zero (fail closed), never as
    // the requested set.
    var grantedScope;
    if (typeof raw.scope === "string") {
      grantedScope = raw.scope.split(" ").filter(function (s) { return s.length > 0; });
    } else if (raw.scope === undefined) {
      // ONLY a truly ABSENT property (undefined) mirrors the request (RFC 6749
      // §3.3 "OPTIONAL, if identical to the requested scope"). A PRESENT but
      // malformed value — `null`, a number, an object — is NOT an omitted
      // scope; treating `{ "scope": null }` as absent would copy the full
      // requested set and report a grant the AS never made. Fall through to
      // zero (fail closed).
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
    // RFC 9396 §7 — surface the GRANTED authorization_details and, when
    // the operator threaded the requested array through, cross-check it.
    // strict by default whenever a request was sent (refuse an over-
    // grant); operators that intentionally accept asymmetric grants pass
    // verifyAuthorizationDetails: false.
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
    // CVE-2026-29000 / CVE-2026-22817 — mirror
    // jwt-external's 5-segment JWE refusal. A 5-segment compact
    // serialization is a JWE (RFC 7516); verifyIdToken is a JWS verifier
    // and a JWE shape reaching here is the confused-deputy class an OP
    // shipping JWE id_tokens would exercise. Operators with JWE
    // id_tokens wire a separate JWE handler at their KMS — never on
    // this verifier path.
    if (parts.length === 5) {
      try { audit().safeEmit({
        action:   "jwt.jwe.refused",
        outcome:  "denied",
        metadata: { reason: "jwe-on-jws-verifier", primitive: "oauth.verifyIdToken" },
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
      throw new OAuthError("auth-oauth/malformed-jwt",
        "ID token header/payload base64 decode failed: " + ((e && e.message) || String(e)));
    }
    if (!header || typeof header.alg !== "string") {
      throw new OAuthError("auth-oauth/malformed-jwt", "ID token header missing 'alg'");
    }
    // Alg-allowlist gate (CWE-347 / CWE-757) — refuse unknown alg BEFORE
    // any key resolution.
    // The acceptedAlgorithms list is the operator's posture; an alg
    // outside it never reaches the JWKS lookup or node:crypto.verify.
    if (acceptedAlgorithms.indexOf(header.alg) === -1) {
      throw new OAuthError("auth-oauth/alg-not-accepted",
        "ID token signed with '" + header.alg + "' which is not in the accepted-algorithm list " +
        "(alg-allowlist gate — refused before key lookup)");
    }
    // RFC 7515 §4.1.11 — refuse JWS with `crit` header. Every other
    // verifier in the framework (jwt.js, jwt-external.js, dpop.js)
    // refuses; verifyIdToken previously silently ignored, letting an
    // attacker-controlled OP ship critical extensions the verifier
    // doesn't understand.
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
    // Pre-v0.9.4 fell back to keys[0] when the token carried NO kid
    // and the JWKS had exactly one key. This is a latent vector
    // during JWKS rotation: an attacker who can ship a kid-less
    // token gets the lone key during the window the rotated-out
    // key was still cached at the IdP but the rotated-in key is
    // already published. Refuse kid-less tokens unconditionally —
    // every modern IdP includes kid; absent kid is a spec smell.
    // Operators with non-conforming IdPs that
    // genuinely emit kid-less tokens can opt out via
    // vopts.allowKidlessJwks = true with a logged warning.
    if (!match) {
      // Operator opt-out reads from EITHER the per-call vopts OR the
      // client-level config — `_normalizeTokens` calls verifyIdToken
      // with a reduced vopts ({ nonce, skipNonceCheck }), so a
      // per-call opt would not reach the standard exchangeCode /
      // pollDeviceCode / exchangeToken / refreshAccessToken flows.
      // The client-level `create({ allowKidlessJwks: true })` fills
      // that gap. (v0.9.5 follow-up to the v0.9.4 audit fix.)
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
    // CVE-2026-22817 — cross-check JWS alg against the resolved JWK's
    // kty (and crv for EC). Without this an attacker-controlled
    // `alg: "HS256"` against an RSA-kty JWK would hand the public-key
    // bytes to node:crypto.verify as an HMAC secret. Routed through the
    // shared helper so every JWT verifier (oauth / jwt-external /
    // oid4vci / sd-jwt-vc / openid-federation) enforces the same check.
    jwtExternal._assertAlgKtyMatch(header.alg, match);
    var keyObject = _jwkToKey(match);
    var params = _verifyParamsForAlg(header.alg);
    var signingInput = parts[0] + "." + parts[1];
    var sig = _b64urlDecode(parts[2]);
    var verifyOpts = { key: keyObject };
    if (params.padding !== undefined) verifyOpts.padding = params.padding;
    if (params.saltLength !== undefined) verifyOpts.saltLength = params.saltLength;
    if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
    // nodeCrypto.verify panics on key/sig shape mismatch (e.g. an
    // ES256 signature attempted against an RS256 key returned by a
    // hostile or buggy IdP with duplicate kids). Wrap so the panic
    // becomes a typed AuthError, matching the discipline in
    // jwt-external.js + dpop.js.
    var verified;
    try {
      verified = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
    } catch (verifyErr) {
      throw new OAuthError("auth-oauth/bad-signature",
        "ID token signature verification raised: " +
        ((verifyErr && verifyErr.message) || String(verifyErr)));
    }
    if (!verified) {
      throw new OAuthError("auth-oauth/bad-signature", "ID token signature verification failed");
    }

    // Claim validation.
    var now = Math.floor(Date.now() / C.TIME.seconds(1));
    var skewSec = Math.floor(clockSkewMs / C.TIME.seconds(1));
    // OIDC Back-Channel Logout 1.0 §2.4 — logout tokens have no `exp`
    // claim; freshness comes from `iat` + jti-replay window. `skipExpCheck`
    // bypasses the exp gate for that path ONLY. It is a public-API option,
    // so it must be self-guarding: refuse it on any token that is not a
    // logout token (no back-channel-logout event), or a caller could verify
    // an expired/replayed id_token clean. Logout tokens then carry no exp,
    // so `iat` is the only freshness bound — enforce a max-age floor.
    if (vopts.skipExpCheck) {
      if (!payload.events || typeof payload.events !== "object" ||
          !payload.events["http://schemas.openid.net/event/backchannel-logout"]) {
        throw new OAuthError("auth-oauth/skip-exp-check-not-allowed",
          "skipExpCheck is only valid for back-channel-logout tokens " +
          "(OIDC Back-Channel Logout 1.0 §2.4); this token carries no logout event claim");
      }
      // Honor the operator's configured replay window. verifyBackchannelLogoutToken
      // exposes vopts.maxAgeSec (default 5 min) and passes it through here; a
      // deployment that widened the window must not have this freshness floor
      // reject a token between the default and its configured max age.
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
    if (issuer) {
      // CVE-2026-23552 — cross-realm / cross-issuer JWT acceptance. The
      // expected issuer is operator-supplied; payload.iss is attacker-
      // controlled bytes. Constant-time compare defeats prefix-timing
      // narrowing. Emit a DISTINCT audit event (separate from the
      // bad-signature failure) so detection signals on cross-realm
      // probes independently of generic verification failures.
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
    // OIDC Core §3.1.3.7: a multi-audience ID token MUST carry an azp
    // (authorized party), and a present azp MUST equal our client_id.
    // Without this, a token whose authorized party is a DIFFERENT client but
    // whose aud array also lists this RP would verify clean — a confused-deputy
    // / token-substitution hole.
    if (aud.length > 1 && typeof payload.azp !== "string") {
      throw new OAuthError("auth-oauth/azp-required",
        "ID token has multiple audiences but no azp (authorized party) claim");
    }
    if (payload.azp !== undefined && payload.azp !== clientId) {
      throw new OAuthError("auth-oauth/azp-mismatch",
        "ID token azp '" + payload.azp + "' is not clientId '" + clientId + "'");
    }
    if (vopts.nonce && !vopts.skipNonceCheck) {
      // Constant-time nonce compare — secret-shaped value matched
      // against attacker-controlled payload.
      if (typeof payload.nonce !== "string" ||
          !cryptoTimingSafeEqual(payload.nonce, vopts.nonce)) {
        throw new OAuthError("auth-oauth/nonce-mismatch",
          "ID token nonce mismatch (replay protection)");
      }
    }
    return { header: header, claims: payload };
  }

  // ---- OIDC RP-Initiated Logout (OpenID Connect Session Mgmt 1.0) ----
  //
  // The IdP exposes an `end_session_endpoint` in its discovery doc;
  // the RP-initiated logout flow redirects the user to that endpoint
  // with the id_token_hint + post_logout_redirect_uri so the IdP
  // terminates the IdP session and bounces the user back to the
  // operator's app. Operators wire this on their /logout route.
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
      // OIDC RP-Init Logout §3.1 — postLogoutRedirectUri is operator-
      // supplied; an operator typo could ship `http://` or
      // `javascript:`. Route through the framework's URL gate before
      // emitting so the URL is validated the same way as every other
      // operator-supplied OAuth URL.
      _validateUrl(uopts.postLogoutRedirectUri, allowHttp, "postLogoutRedirectUri");
      params.set("post_logout_redirect_uri", uopts.postLogoutRedirectUri);
    }
    if (uopts.state)        params.set("state", uopts.state);
    if (uopts.logoutHint)   params.set("logout_hint", uopts.logoutHint);
    if (uopts.uiLocales)    params.set("ui_locales", uopts.uiLocales);
    if (uopts.clientId !== false) params.set("client_id", clientId);
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      // OIDC RP-Init Logout §3.1 — extraParams carries operator-
      // controlled key/value pairs. Refuse keys that collide with
      // first-class params so an operator typo / library-merge can't
      // smuggle a second `post_logout_redirect_uri` past the
      // _validateUrl gate above. Defense-in-depth — the operator
      // controls extraParams, so this is a config-time invariant, not
      // an attacker-input filter.
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

  // ---- OAuth 2.0 Pushed Authorization Requests (RFC 9126) ----
  //
  // PAR: the client POSTs the authorization-request parameters
  // directly to the IdP's PAR endpoint (mTLS or client-secret
  // authenticated) and gets back a `request_uri` it then puts in the
  // browser-side redirect to /authorize. Defends against parameter
  // tampering by an MITM at the user-agent + against URL-length
  // overflow on long authorization requests.
  //
  // RFC 9101 signed request object: pass `signedRequestObject: { key,
  // alg?, kid?, audience?, expiresInMs? }` to push a JAR request object
  // instead of plain form params. The authorization parameters then
  // travel as signed claims (RFC 9126 §3 — form body carries only
  // `request` + client auth), so the PAR endpoint can verify they
  // arrived exactly as the client signed them. Absent → plain-form PAR.
  async function pushAuthorizationRequest(uopts) {
    uopts = uopts || {};
    var endpoint;
    try { endpoint = await _resolveEndpoint("pushedAuthorizationRequestEndpoint"); }
    catch (_e) {
      throw new OAuthError("auth-oauth/no-par-endpoint",
        "pushAuthorizationRequest: IdP discovery doc has no " +
        "pushed_authorization_request_endpoint (set opts.pushedAuthorizationRequestEndpoint " +
        "on create() if the IdP doesn't publish it)");
    }
    // RFC 9101 signed-request-object opt: when the operator supplies
    // `signedRequestObject` (a config object carrying the client's signing
    // key), the authorization parameters travel as claims of a JAR request
    // object rather than as bare form params. Validated config-time; absent
    // → the existing plain-form path sends the same key/value set
    // (form-encoded params are unordered per the media type).
    var sro = uopts.signedRequestObject || null;
    if (sro) {
      validateOpts.optionalPlainObject(sro, "pushAuthorizationRequest: signedRequestObject",
        OAuthError, "auth-oauth/par-bad-request-object-opt",
        "must be an object { key, alg?, kid?, audience?, expiresInMs? }");
      validateOpts(sro, ["key", "alg", "kid", "audience", "expiresInMs"],
        "pushAuthorizationRequest.signedRequestObject");
    }
    // Same PKCE-downgrade gate as authorizationUrl (RFC 9700 §4.13):
    // PAR pushes the identical S256 challenge, so an OP advertising
    // code_challenge_methods_supported without S256 is refused here too.
    _assertS256Supported(await _peekDiscovery());
    // Build the same param set authorizationUrl would emit, then POST
    // it to PAR instead of putting it in the redirect URL.
    var state = uopts.state || _generateRandomToken(STATE_NONCE_BYTES);
    var nonce = uopts.nonce || (isOidc ? _generateRandomToken(STATE_NONCE_BYTES) : null);
    var pkceVals = _generatePkce();
    // The authorization-request parameters. On the plain path these are set
    // on the form body directly; on the JAR path they become request-object
    // claims and the form body carries only `request` + client auth.
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
    // RFC 9396 — push the fine-grained authorization request through PAR.
    // On the plain-form branch the value is a form parameter (JSON STRING);
    // on the signed-request-object branch it becomes a JAR claim and MUST
    // be the native JSON ARRAY (RFC 9101/9396) — a conforming AS rejects a
    // string-valued authorization_details claim. Carry the validated array
    // and serialize ONLY when it travels as a form param.
    var requestedAuthzDetails = null;
    if (uopts.authorizationDetails !== undefined) {
      requestedAuthzDetails = _validateAuthorizationDetailsArray(
        uopts.authorizationDetails, "pushAuthorizationRequest");
      authzParams.authorization_details = sro
        ? requestedAuthzDetails                    // JAR claim — native array
        : JSON.stringify(requestedAuthzDetails);   // form param — JSON string
    }
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      // Same reserved-key guard as authorizationUrl — a PAR request pushes
      // the identical security-critical parameter set, so extraParams may
      // not shadow redirect_uri / state / code_challenge here either.
      _assertNoReservedExtraParams(uopts.extraParams, RESERVED_AUTHZ_PARAMS,
        "auth-oauth/reserved-extra-param", "pushAuthorizationRequest");
      var ek = Object.keys(uopts.extraParams);
      for (var i = 0; i < ek.length; i++) authzParams[ek[i]] = String(uopts.extraParams[ek[i]]);
    }

    var body = new URLSearchParams();
    if (sro) {
      // RFC 9126 §3 — when a signed request object is pushed, the
      // authorization parameters MUST appear ONLY as claims of the JWT;
      // the form body carries `request` plus the parameters a client
      // authentication method requires (client_id, and client_secret for
      // the secret-based methods) and nothing else. The JAR `aud` is the
      // AS issuer identifier (RFC 9101 §5) — the operator may override but
      // it defaults to the configured `issuer`.
      var requestJwt = jar.build(authzParams, {
        clientId:    clientId,
        audience:    sro.audience || issuer,
        key:         sro.key,
        alg:         sro.alg,
        kid:         sro.kid,
        expiresInMs: sro.expiresInMs,
      });
      body.set("request",   requestJwt);
      body.set("client_id", clientId);                 // RFC 9126 §3 — client identification
      if (clientSecret) body.set("client_secret", clientSecret);
    } else {
      var ak = Object.keys(authzParams);
      for (var ap = 0; ap < ak.length; ap++) body.set(ak[ap], authzParams[ak[ap]]);
      if (clientSecret) body.set("client_secret", clientSecret);
    }
    var rv = await _postForm(endpoint, body);
    if (!rv || typeof rv.request_uri !== "string" || rv.request_uri.length === 0) {
      throw new OAuthError("auth-oauth/par-bad-response",
        "pushAuthorizationRequest: IdP did not return a request_uri (got " +
        JSON.stringify(rv).slice(0, 200) + ")");                                 // error-message snippet length
    }
    // Build the browser-side redirect URL: /authorize?client_id=...&request_uri=...
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

  // ---- OIDC Front-Channel Logout 1.0 ----
  //
  // The IdP renders an iframe pointing at the RP's
  // frontchannel_logout_uri with `iss` + `sid` query params; the RP's
  // iframe-served endpoint clears the local session for that sid and
  // returns a no-content / blank page. Operators stand up a single
  // /oidc/frontchannel-logout route, parse the request, and call
  // `parseFrontchannelLogoutRequest(req)` to extract the validated
  // (iss, sid) tuple to feed their session-store deletion.
  //
  // The IdP advertises support via `frontchannel_logout_supported`
  // and `frontchannel_logout_session_required` in discovery; the RP
  // registers `frontchannel_logout_uri` + `frontchannel_logout_session_required`
  // at client-registration time. We don't auto-register here — the
  // RP's registration step is operator-side; this surface only
  // handles the runtime parse.
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
    // OpenID Connect Front-Channel Logout 1.0 §3: `iss` MUST match the
    // configured issuer when present (defends against an attacker-controlled IdP forging a
    // logout for a session at a different IdP). `sid` is required
    // when the RP registered with frontchannel_logout_session_required=true;
    // we surface it either way and let the operator decide.
    // CVE-2026-23552 — constant-time issuer compare. Defeats prefix-
    // timing narrowing against the configured issuer string; iss is
    // attacker-controlled query-param input.
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
      }); } catch (_e) { /* drop-silent — observability sink */ }
      throw new OAuthError("auth-oauth/frontchannel-logout-iss-mismatch",
        "parseFrontchannelLogoutRequest: iss \"" + iss +
        "\" does not match configured issuer \"" + issuer +
        "\" (CVE-2026-23552 — cross-realm refused)");
    }
    return { iss: iss || issuer, sid: sid || null };
  }

  // ---- OIDC Back-Channel Logout 1.0 ----
  //
  // The IdP POSTs an `application/x-www-form-urlencoded` body with
  // `logout_token=<jwt>` to the RP's backchannel_logout_uri. The
  // logout token is a JWT with:
  //   header.typ = "logout+jwt"
  //   payload.iss = the IdP issuer
  //   payload.aud = the RP's client_id
  //   payload.iat = recent timestamp
  //   payload.jti = unique id (replay-cache key)
  //   payload.events = { "http://schemas.openid.net/event/backchannel-logout": {} }
  //   payload.sub OR payload.sid (one of)
  //   MUST NOT contain `nonce`
  //
  // The RP verifies the JWS using the IdP's JWKS, validates each
  // claim, and destroys every session for the matching sub or sid.
  //
  // Replay defense: operators provide a `seen({jti, iat}) -> Promise<bool>`
  // callback that returns true the FIRST time it sees a (jti, iss)
  // pair within the operator's chosen window (typical: 5 minutes).
  // Subsequent calls with the same (jti, iss) return false and the
  // RP rejects the duplicate. The framework does not maintain the
  // store — operators wire b.cache or b.db.
  async function verifyBackchannelLogoutToken(logoutToken, vopts) {
    vopts = vopts || {};
    // Type / non-empty / length-cap gate, folded into one bounds check.
    // The cap runs BEFORE the split + base64url decode — an attacker-
    // reachable endpoint can POST an arbitrarily large logout_token, and
    // bounding it first stops the decode from allocating unbounded memory.
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
    // Route the pre-verify header parse through safeJson (size-bounded) like
    // the in-module id_token / JWS-header siblings — the bare JSON.parse on
    // an attacker-reachable, not-yet-signature-checked header was the one
    // unbounded parse on this surface. The JWS signature is verified by
    // verifyIdToken below.
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
    // Reuse verifyIdToken's signature-verification path. It looks up
    // the IdP JWKS and checks the JWS — same trust anchor.
    // verifyIdToken applies the create()-level issuer / clientId / accepted
    // algorithms / JWKS / clock-skew — the same trust anchor as id_tokens.
    // Only the per-call logout-token semantics are passed here.
    var verified = await verifyIdToken(logoutToken, {
      // Logout tokens have no nonce — disable the nonce check that
      // verifyIdToken would otherwise enforce on id_tokens.
      skipNonceCheck: true,
      // Logout tokens have no exp claim per OIDC Back-Channel Logout
      // §2.4 — the freshness gate is iat + jti-replay window.
      skipExpCheck:   true,
      // Pass the operator's configured replay window through so verifyIdToken's
      // iat freshness floor uses it, not the 5-min default (the wrapper's own
      // maxAgeSec check below stays as a belt-and-suspenders bound).
      maxAgeSec:      vopts.maxAgeSec,
    });
    var claims = verified.claims;

    // §2.6 — events claim presence + correct shape
    if (!claims.events || typeof claims.events !== "object" ||
        !claims.events["http://schemas.openid.net/event/backchannel-logout"]) {
      throw new OAuthError("auth-oauth/missing-logout-event",
        "verifyBackchannelLogoutToken: payload.events missing http://schemas.openid.net/event/backchannel-logout");
    }
    // §2.6 — nonce MUST NOT be present (nonce is for ID tokens only)
    if (Object.prototype.hasOwnProperty.call(claims, "nonce")) {
      throw new OAuthError("auth-oauth/forbidden-nonce",
        "verifyBackchannelLogoutToken: payload.nonce is forbidden in logout tokens (§2.6)");
    }
    // §2.4 — sub OR sid REQUIRED (at least one)
    if (!claims.sub && !claims.sid) {
      throw new OAuthError("auth-oauth/no-sub-or-sid",
        "verifyBackchannelLogoutToken: payload must include sub or sid");
    }
    // OIDC Back-Channel Logout §2.6 — iat freshness gate. Logout tokens
    // have no exp claim; freshness rests entirely on iat plus a
    // replay-cache window. A captured old logout-token with a fresh jti
    // (never seen by THIS RP's replay store, e.g. cleared across a
    // restart) would otherwise pass. Refuse iat older than
    // opts.maxAgeSec (default 5 minutes) — matches the standard 5-min
    // jti-replay-cache window operators ship.
    var logoutMaxAgeSec = typeof vopts.maxAgeSec === "number"
      ? vopts.maxAgeSec
      : DEFAULT_LOGOUT_TOKEN_MAX_AGE_SEC;
    var nowSecLogout = Math.floor(Date.now() / C.TIME.seconds(1));
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
    // Replay defense — atomic checkAndInsert when the operator supplies
    // a b.nonceStore-shaped backend, fallback to the legacy
    // seen()-callback when supplied. The atomic shape closes the
    // race-class first surfaced for refresh-token rotation in v0.9.3:
    // two simultaneous deliveries of the same logout_token both pass
    // the seen() check and both run the operator's session-destroy
    // handler. atomicReplayStore.checkAndInsert(jti, expireAtMs)
    // returns true if it WAS the first insert, false on duplicate.
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
      // Fail closed on ANY non-truthy result. A store fronting SETNX / an
      // ON-CONFLICT INSERT returns 0 (falsy, not `false`) on a duplicate,
      // so an `=== false` compare would miss the replay.
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
      // Fail closed on ANY non-truthy result — `seen()` returns truthy the
      // first time it sees the (jti, iss) pair; a store returning 0 for a
      // duplicate must still refuse, which an `=== false` compare would miss.
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
      iat:    claims.iat || null,
      events: claims.events,
      claims: claims,
    };
  }

  // ---- OIDC Session Management 1.0 — check_session_iframe ----
  //
  // The IdP advertises a `check_session_iframe` URL in discovery.
  // The RP loads it inside an iframe and posts `<client_id>
  // <session_state>` messages to it; the iframe responds with
  // "changed" / "unchanged" / "error" so the RP can periodically
  // poll without a full network round-trip.
  //
  // This builder returns the iframe URL plus a small client-side
  // helper string operators embed in their HTML to drive the
  // postMessage handshake. The framework does not host the iframe —
  // the IdP does. Operators that want CSP-compliant inline scripts
  // emit the helper through the framework's nonce middleware.
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
    var parsed = await _postForm(endpoint, body);
    // RFC 7662 §2.2 — `active` is the only required field; coerce
    // every other interpretation through it.
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
    // RFC 7591 §2 / RFC 9700 §4.1.1 — every redirect_uri MUST be a
    // valid https:// URL (or http://localhost for dev). Pre-v0.9.x the
    // gate only enforced presence; an operator copying a config with
    // `http://app.example` or `javascript:` would ship that string to
    // the AS, which then permanently associates the open-redirect
    // surface with the registered client_id. Validate at registration
    // time so the bad URL never reaches the AS.
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
    var hc      = httpClient;
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
    Object.assign(req, httpClientOpts);
    var res  = await hc.request(req);
    var text = res.body ? res.body.toString("utf8") : "";
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw new OAuthError("auth-oauth/register-failed-" + res.statusCode,
        "registerClient: " + res.statusCode + ": " + text.slice(0, 500));
    }
    var parsed;
    try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
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
    Object.assign(req, httpClientOpts);
    var res = await httpClient.request(req);
    if (method === "DELETE") {
      if (res.statusCode === 204 || res.statusCode === 200) return null;
      if (res.statusCode === 404) {
        throw new OAuthError("auth-oauth/dcr-not-found",
          "deleteClient: 404 — registrationClientUri does not resolve to a client");
      }
      throw new OAuthError("auth-oauth/dcr-delete-failed-" + res.statusCode,
        "deleteClient: " + res.statusCode);
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      var errText = res.body ? res.body.toString("utf8").slice(0, 500) : "";
      throw new OAuthError("auth-oauth/dcr-" + method.toLowerCase() + "-failed-" + res.statusCode,
        method.toLowerCase() + "Client: " + res.statusCode + ": " + errText);
    }
    var text = res.body ? res.body.toString("utf8") : "";
    try { return safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
    catch (e) {
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
    var parsed = await _postForm(endpoint, body);
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
    // RFC 8628 §3.4 — device_code is server-generated and opaque to the
    // client, but the polling loop POSTs it on every iteration. Without
    // a length cap an attacker who controls the device_code source
    // (e.g. a hostile AS in a CIBA-style misconfig) can amplify the
    // outbound HTTP body across N polls. The 8 KiB cap matches RFC 8628
    // §6.1's "alphanumeric with sufficient entropy" — even base64url
    // 512-bit codes fit comfortably.
    if (deviceCode.length > MAX_DEVICE_CODE_BYTES) {
      throw new OAuthError("auth-oauth/device-code-too-large",
        "pollDeviceCode: deviceCode exceeds " + MAX_DEVICE_CODE_BYTES + " bytes " +
        "(RFC 8628 §3.4 — opaque server-generated code, no legitimate need for length above the cap)");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    // RFC 8628 §3.4 — "If no value is provided, clients MUST use 5 as
    // the default" and §3.5 directs clients to use slow_down responses
    // to extend the interval. A 1s floor violates the spec's "5
    // RECOMMENDED" and amplifies AS load. Enforce 5s minimum.
    var interval = Math.max(MIN_DEVICE_POLL_INTERVAL_SEC, popts.interval || MIN_DEVICE_POLL_INTERVAL_SEC);
    var deadline = Date.now() + (popts.maxWaitMs || C.TIME.minutes(10));
    while (Date.now() < deadline) {
      var body = new URLSearchParams();
      body.set("grant_type",  "urn:ietf:params:oauth:grant-type:device_code");
      body.set("device_code", deviceCode);
      body.set("client_id",   clientId);
      if (clientSecret) body.set("client_secret", clientSecret);
      var hc  = httpClient;
      var req = {
        url:     endpoint,
        method:  "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept":       "application/json",
        },
        body:    Buffer.from(body.toString(), "utf8"),
      };
      if (allowHttp) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
      if (allowInternal !== null) req.allowInternal = allowInternal;
      Object.assign(req, httpClientOpts);
      // RFC 8628 §3.5 / RFC 6749 §5.2 return the device-grant errors
      // (authorization_pending / slow_down and the terminal codes) as an
      // HTTP 400 whose body carries `error`. The loop below reads that body,
      // so the token request MUST NOT let b.httpClient reject the 4xx first —
      // the default buffer mode would throw before the pending/slow_down/
      // terminal handling runs, aborting the grant on the first poll (which
      // is almost always authorization_pending). Force always-resolve AFTER
      // merging httpClientOpts so an operator override cannot silently
      // reinstate buffer mode.
      req.responseMode = "always-resolve";
      var res    = await hc.request(req);
      var text   = res.body ? res.body.toString("utf8") : "";
      var parsed;
      try { parsed = safeJson.parse(text, { maxBytes: OAUTH_MAX_RESPONSE_BYTES }); }
      catch (_e) { parsed = null; }
      if (res.statusCode >= 200 && res.statusCode < 300 && parsed && parsed.access_token) {
        return await _normalizeTokens(parsed, popts);
      }
      // RFC 8628 §3.5 — error codes that should keep polling.
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
      // Terminal errors.
      throw new OAuthError("auth-oauth/device-" + (err || "unknown"),
        "pollDeviceCode: " + (parsed && parsed.error_description ? parsed.error_description : text.slice(0, 200)));   // 200-char error-snippet cap, not bytes
    }
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
    // RFC 8693 §3 — the token-type URN identifies the requested format
    // (access_token / refresh_token / id_token / saml2 / saml1 / jwt).
    // Pre-v0.9.x accepted any string, which let an attacker-controlled
    // service or operator-mistyped value reach the AS verbatim. Refuse
    // anything outside the RFC 8693 §3 list unless the operator
    // explicitly opts in via { allowCustomTokenType: true } with a
    // documented downstream contract.
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

  // draft-ietf-oauth-attestation-based-client-auth — convenience that
  // builds BOTH headers for THIS client. clientId is taken from create();
  // audience defaults to the configured issuer (the AS the client talks
  // to). The instance attestation/PoP keys are passed per call.
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

  return {
    authorizationUrl:                authorizationUrl,
    exchangeCode:                    exchangeCode,
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
    // Diagnostic / power-user surface
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
  // draft-ietf-oauth-attestation-based-client-auth — issuer-agnostic
  // builders + validator (usable without a create()'d client).
  buildClientAttestation:    buildClientAttestation,
  buildClientAttestationPop: buildClientAttestationPop,
  verifyClientAttestation:   verifyClientAttestation,
  // Internal helpers exposed for tests
  _generatePkce:         _generatePkce,
  _generateRandomToken:  _generateRandomToken,
  _b64urlEncode:         _b64urlEncode,
  _b64urlDecode:         _b64urlDecode,
  _verifyParamsForAlg:   _verifyParamsForAlg,
  _crossCheckGrantedAuthorizationDetails: _crossCheckGrantedAuthorizationDetails,
};
