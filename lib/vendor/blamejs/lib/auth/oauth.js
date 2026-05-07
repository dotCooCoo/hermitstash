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
var { generateBytes } = require("../crypto");
var httpClient = require("../http-client");
var safeJson = require("../safe-json");
var safeUrl = require("../safe-url");
var { URL } = require("url");
var { defineClass } = require("../framework-error");

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
// JOSE PSS salt lengths (RFC 7518 §3.5) match the hash-output size:
// PS256/SHA-256 → 32, PS384/SHA-384 → 48, PS512/SHA-512 → 64.
var PSS_SALT_BYTES_SHA256      = C.BYTES.bytes(32);
var PSS_SALT_BYTES_SHA384      = C.BYTES.bytes(48);
var PSS_SALT_BYTES_SHA512      = C.BYTES.bytes(64);

// ---- helpers ----

function _b64urlEncode(buf) {
  if (typeof buf === "string") buf = Buffer.from(buf, "utf8");
  return buf.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _b64urlDecode(s) {
  if (typeof s !== "string") throw new OAuthError("auth-oauth/bad-base64", "expected base64url string");
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";
  return Buffer.from(padded, "base64");
}

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
    var parsed = new URL(url);                                                                  // allow:raw-new-url — RFC 9700 §4.1.1 localhost-exception lookup; safeUrl re-validates below for non-localhost paths
    if (parsed.protocol === "http:" &&
        (parsed.hostname === "localhost" ||
         parsed.hostname === "127.0.0.1" ||
         parsed.hostname === "[::1]" ||
         parsed.hostname === "::1")) {
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
  // Returns { hash, padding, dsaEncoding } for node:crypto.verify.
  if (alg === "RS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "RS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
  if (alg === "PS256") return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_BYTES_SHA256 };
  if (alg === "PS384") return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_BYTES_SHA384 };
  if (alg === "PS512") return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_BYTES_SHA512 };
  if (alg === "ES256") return { hash: "sha256", dsaEncoding: "ieee-p1363" };
  if (alg === "ES384") return { hash: "sha384", dsaEncoding: "ieee-p1363" };
  if (alg === "ES512") return { hash: "sha512", dsaEncoding: "ieee-p1363" };
  throw new OAuthError("auth-oauth/unsupported-alg",
    "alg '" + alg + "' is not supported for ID-token verification");
}

// ---- JWKS → KeyObject ----

function _jwkToKey(jwk) {
  // node's createPublicKey accepts JWK directly since Node 16.
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) {
    throw new OAuthError("auth-oauth/bad-jwk",
      "could not import JWK (kid=" + (jwk && jwk.kid) + "): " + ((e && e.message) || String(e)));
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
  var clockSkewMs  = typeof opts.clockSkewMs === "number" ? opts.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  var discoveryCacheMs = typeof opts.discoveryCacheMs === "number"
                           ? opts.discoveryCacheMs : DEFAULT_DISCOVERY_CACHE_MS;
  var acceptedAlgorithms = Array.isArray(opts.acceptedAlgorithms) && opts.acceptedAlgorithms.length > 0
                             ? opts.acceptedAlgorithms.slice() : DEFAULT_ACCEPTED_ALGS.slice();
  var allowHttp        = !!opts.allowHttp;          // localhost dev opt-in (scheme)
  var allowInternal    = opts.allowInternal != null ? opts.allowInternal : null; // localhost dev opt-in (SSRF gate)
  var httpClientOpts   = opts.httpClient || {};
  var responseMode     = opts.responseMode || null;

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
    pushedAuthorizationRequestEndpoint:
                           opts.pushedAuthorizationRequestEndpoint ||
                           (preset && preset.pushedAuthorizationRequestEndpoint) || null,
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
      pushedAuthorizationRequestEndpoint: "pushed_authorization_request_endpoint",
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
    // Operator-supplied additional params (audience, resource, etc.).
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
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
    if (isOidc && eopts.nonce === undefined && eopts.skipNonceCheck !== true) {
      throw new OAuthError("auth-oauth/no-nonce",
        "exchangeCode: nonce is required on OIDC flows. Pass the " +
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

    var tokens = await _postForm(endpoint, body);
    return await _normalizeTokens(tokens, { nonce: eopts.nonce, skipNonceCheck: eopts.skipNonceCheck });
  }

  async function refreshAccessToken(refreshToken) {
    if (!refreshToken) {
      throw new OAuthError("auth-oauth/no-refresh-token",
        "refreshAccessToken: refresh token is required");
    }
    var endpoint = await _resolveEndpoint("tokenEndpoint");
    var body = new URLSearchParams();
    body.set("grant_type",    "refresh_token");
    body.set("refresh_token", refreshToken);
    body.set("client_id",     clientId);
    if (clientSecret) body.set("client_secret", clientSecret);
    var tokens = await _postForm(endpoint, body);
    // Refreshed tokens may not include a new id_token; verification
    // is conditional.
    return await _normalizeTokens(tokens, { skipNonceCheck: true });
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
    var tokens = {
      accessToken:  raw.access_token,
      tokenType:    raw.token_type || "Bearer",
      expiresIn:    raw.expires_in || null,
      refreshToken: raw.refresh_token || null,
      idToken:      raw.id_token || null,
      scope:        raw.scope ? raw.scope.split(/\s+/) : scope.slice(),
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
    if (acceptedAlgorithms.indexOf(header.alg) === -1) {
      throw new OAuthError("auth-oauth/alg-not-accepted",
        "ID token signed with '" + header.alg + "' which is not in the accepted-algorithm list");
    }
    var keys = await _getJwks();
    var match = null;
    if (header.kid) {
      for (var i = 0; i < keys.length; i++) {
        if (keys[i].kid === header.kid) { match = keys[i]; break; }
      }
    } else if (keys.length === 1) {
      match = keys[0];
    }
    if (!match) {
      throw new OAuthError("auth-oauth/no-matching-key",
        "no JWKS key matches header.kid='" + header.kid + "'");
    }
    var keyObject = _jwkToKey(match);
    var params = _verifyParamsForAlg(header.alg);
    var signingInput = parts[0] + "." + parts[1];
    var sig = _b64urlDecode(parts[2]);
    var verifyOpts = { key: keyObject };
    if (params.padding !== undefined) verifyOpts.padding = params.padding;
    if (params.saltLength !== undefined) verifyOpts.saltLength = params.saltLength;
    if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
    var verified = nodeCrypto.verify(params.hash, Buffer.from(signingInput, "ascii"), verifyOpts, sig);
    if (!verified) {
      throw new OAuthError("auth-oauth/bad-signature", "ID token signature verification failed");
    }

    // Claim validation.
    var now = Math.floor(Date.now() / C.TIME.seconds(1));
    var skewSec = Math.floor(clockSkewMs / C.TIME.seconds(1));
    if (typeof payload.exp !== "number" || payload.exp + skewSec < now) {
      throw new OAuthError("auth-oauth/expired", "ID token expired (exp=" + payload.exp + ", now=" + now + ")");
    }
    if (typeof payload.iat === "number" && payload.iat - skewSec > now) {
      throw new OAuthError("auth-oauth/iat-future", "ID token iat is in the future");
    }
    if (typeof payload.nbf === "number" && payload.nbf - skewSec > now) {
      throw new OAuthError("auth-oauth/nbf-future", "ID token nbf is in the future");
    }
    if (issuer && payload.iss !== issuer) {
      throw new OAuthError("auth-oauth/iss-mismatch",
        "ID token iss '" + payload.iss + "' does not match expected '" + issuer + "'");
    }
    var aud = Array.isArray(payload.aud) ? payload.aud : (payload.aud ? [payload.aud] : []);
    if (aud.indexOf(clientId) === -1) {
      throw new OAuthError("auth-oauth/aud-mismatch",
        "ID token aud does not contain clientId '" + clientId + "'");
    }
    if (vopts.nonce && !vopts.skipNonceCheck) {
      if (payload.nonce !== vopts.nonce) {
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
      params.set("post_logout_redirect_uri", uopts.postLogoutRedirectUri);
    }
    if (uopts.state)        params.set("state", uopts.state);
    if (uopts.logoutHint)   params.set("logout_hint", uopts.logoutHint);
    if (uopts.uiLocales)    params.set("ui_locales", uopts.uiLocales);
    if (uopts.clientId !== false) params.set("client_id", clientId);
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
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
    // Build the same param set authorizationUrl would emit, then POST
    // it to PAR instead of putting it in the redirect URL.
    var state = uopts.state || _generateRandomToken(STATE_NONCE_BYTES);
    var nonce = uopts.nonce || (isOidc ? _generateRandomToken(STATE_NONCE_BYTES) : null);
    var pkceVals = _generatePkce();
    var body = new URLSearchParams();
    body.set("response_type", "code");
    body.set("client_id",     clientId);
    body.set("redirect_uri",  redirectUri);
    body.set("scope",         scope.join(" "));
    body.set("state",         state);
    if (nonce) body.set("nonce", nonce);
    body.set("code_challenge",        pkceVals.challenge);
    body.set("code_challenge_method", "S256");
    if (responseMode) body.set("response_mode", responseMode);
    if (uopts.prompt)    body.set("prompt", uopts.prompt);
    if (uopts.loginHint) body.set("login_hint", uopts.loginHint);
    if (uopts.maxAge != null) body.set("max_age", String(uopts.maxAge));
    if (clientSecret) body.set("client_secret", clientSecret);
    if (uopts.extraParams && typeof uopts.extraParams === "object") {
      var ek = Object.keys(uopts.extraParams);
      for (var i = 0; i < ek.length; i++) body.set(ek[i], String(uopts.extraParams[ek[i]]));
    }
    var rv = await _postForm(endpoint, body);
    if (!rv || typeof rv.request_uri !== "string" || rv.request_uri.length === 0) {
      throw new OAuthError("auth-oauth/par-bad-response",
        "pushAuthorizationRequest: IdP did not return a request_uri (got " +
        JSON.stringify(rv).slice(0, 200) + ")");                                 // allow:raw-byte-literal — error-message snippet length
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
    };
  }

  return {
    authorizationUrl:    authorizationUrl,
    exchangeCode:        exchangeCode,
    refreshAccessToken:  refreshAccessToken,
    fetchUserInfo:       fetchUserInfo,
    revokeToken:         revokeToken,
    verifyIdToken:       verifyIdToken,
    discover:            _discover,
    endSessionUrl:           endSessionUrl,
    pushAuthorizationRequest: pushAuthorizationRequest,
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
  // Internal helpers exposed for tests
  _generatePkce:         _generatePkce,
  _generateRandomToken:  _generateRandomToken,
  _b64urlEncode:         _b64urlEncode,
  _b64urlDecode:         _b64urlDecode,
  _verifyParamsForAlg:   _verifyParamsForAlg,
};
