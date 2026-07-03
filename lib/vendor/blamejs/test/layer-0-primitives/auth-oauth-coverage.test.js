// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.oauth — config-time + offline-validation coverage.
 *
 * Complements oauth-callback.test.js (which exercises the network-driven
 * discovery / PAR / attestation happy paths) by pinning the input-
 * validation, option-default, and adversarial-shape branches that resolve
 * WITHOUT a live IdP: create() gating, _validateUrl scheme/localhost
 * rules, the pre-JWKS verifyIdToken refusals (JWE / crit / alg-allowlist /
 * malformed), the per-method required-argument guards, the offline URL
 * builders (authorizationUrl / endSessionUrl), parseFrontchannelLogoutRequest,
 * the RFC 9396 granted-details cross-check edge cases, and the
 * attestation builder/verifier validation surface.
 *
 * Every assertion drives the public b.auth.oauth surface; no branch here
 * reaches the network (each throws before endpoint resolution, or builds a
 * URL from a static endpoint, or is a pure helper).
 */

var crypto  = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var X = b.auth.oauth;

// Reject a SYNCHRONOUS call with a specific OAuthError code.
function rejects(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw !== null && threw.code === code);
}

// Reject an ASYNC call (Promise) with a specific OAuthError code.
async function arejects(label, fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label, threw !== null && threw.code === code);
}

// A static-endpoint OIDC client: every endpoint is configured, so no code
// path here forces a discovery fetch.
function _staticOidcClient(extra) {
  var opts = {
    issuer:                "https://idp.example",
    clientId:              "rp-cov",
    clientSecret:          "cov-secret",
    redirectUri:           "https://rp.example/cb",
    isOidc:                true,
    authorizationEndpoint: "https://idp.example/auth",
    tokenEndpoint:         "https://idp.example/token",
    userinfoEndpoint:      "https://idp.example/userinfo",
    revocationEndpoint:    "https://idp.example/revoke",
    endSessionEndpoint:    "https://idp.example/logout",
    jwksUri:               "https://idp.example/jwks",
  };
  if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
  return X.create(opts);
}

function _b64url(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

async function run() {
  // ---- module surface ----
  check("oauth.create is fn",                    typeof X.create === "function");
  check("oauth.OAuthError is fn",                typeof X.OAuthError === "function");
  check("oauth.PRESETS frozen",                  Object.isFrozen(X.PRESETS));
  check("oauth.PRESETS has the 7 vendors",
        ["google", "microsoft", "apple", "auth0", "keycloak", "github", "generic"]
          .every(function (p) { return Object.prototype.hasOwnProperty.call(X.PRESETS, p); }));
  check("oauth.DEFAULT_ACCEPTED_ALGS excludes HS256",
        X.DEFAULT_ACCEPTED_ALGS.indexOf("HS256") === -1 && X.DEFAULT_ACCEPTED_ALGS.indexOf("RS256") !== -1);
  check("oauth.ATTESTATION_ALGS includes EdDSA, excludes HS256",
        X.ATTESTATION_ALGS.indexOf("EdDSA") !== -1 && X.ATTESTATION_ALGS.indexOf("HS256") === -1);

  // ---- create(): required-arg + posture gating ----
  rejects("create: pkce:false refused (OAuth 2.1)",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", pkce: false }); },
          "auth-oauth/pkce-required");
  rejects("create: missing clientId refused",
          function () { X.create({ redirectUri: "https://x/cb" }); }, "auth-oauth/no-client-id");
  rejects("create: missing redirectUri refused",
          function () { X.create({ clientId: "a" }); }, "auth-oauth/no-redirect-uri");
  rejects("create: unknown provider preset refused",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", provider: "nope" }); },
          "auth-oauth/unknown-provider");
  rejects("create: non-finite clockSkewMs refused (Infinity would disable exp gate)",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", clockSkewMs: Infinity }); },
          "auth-oauth/bad-clock-skew");
  rejects("create: NaN clockSkewMs refused",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", clockSkewMs: NaN }); },
          "auth-oauth/bad-clock-skew");

  // ---- _validateUrl via redirectUri (scheme allowlist + localhost rule) ----
  rejects("create: http:// non-localhost redirect refused",
          function () { X.create({ clientId: "a", redirectUri: "http://evil.example/cb" }); },
          "auth-oauth/insecure-url");
  rejects("create: javascript: redirect refused",
          function () { X.create({ clientId: "a", redirectUri: "javascript:alert(1)" }); },
          "auth-oauth/insecure-url");
  check("create: http://localhost redirect accepted (dev exception)",
        !!X.create({ clientId: "a", redirectUri: "http://localhost:3000/cb" }));
  check("create: http://127.0.0.1 redirect accepted (dev exception)",
        !!X.create({ clientId: "a", redirectUri: "http://127.0.0.1/cb" }));
  check("create: http://[::1] redirect accepted (dev exception)",
        !!X.create({ clientId: "a", redirectUri: "http://[::1]:8080/cb" }));
  // RFC 1034 trailing-root-dot must still map to the loopback exception,
  // NOT slip an attacker-registered public 'localhost.' issuer past the gate.
  check("create: http://localhost./ trailing-dot accepted as loopback",
        !!X.create({ clientId: "a", redirectUri: "http://localhost./cb" }));

  // ---- create(): preset issuer templating ----
  rejects("create: auth0 preset without auth0Domain refused",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", provider: "auth0" }); },
          "auth-oauth/auth0-domain");
  rejects("create: keycloak preset without url/realm refused",
          function () { X.create({ clientId: "a", redirectUri: "https://x/cb", provider: "keycloak" }); },
          "auth-oauth/keycloak-config");
  var a0 = X.create({ clientId: "a", redirectUri: "https://x/cb", provider: "auth0", auth0Domain: "t.auth0.com" });
  check("create: auth0 preset expands issuer", a0.issuer === "https://t.auth0.com");
  var kc = X.create({ clientId: "a", redirectUri: "https://x/cb",
    provider: "keycloak", keycloakUrl: "https://kc.example/", keycloakRealm: "r" });
  check("create: keycloak preset expands issuer + strips trailing slash",
        kc.issuer === "https://kc.example/realms/r");
  var gh = X.create({ provider: "github", clientId: "gh", redirectUri: "https://rp.example/cb" });
  check("create: github preset is non-OIDC", gh.isOidc === false && gh.issuer === null);

  // ---- helper: _verifyParamsForAlg ----
  check("_verifyParamsForAlg RS256 → RSA PKCS1 sha256",
        X._verifyParamsForAlg("RS256").hash === "sha256" && X._verifyParamsForAlg("RS256").padding !== undefined);
  check("_verifyParamsForAlg PS256 → PSS saltLength set",
        X._verifyParamsForAlg("PS256").saltLength === 32);
  check("_verifyParamsForAlg ES256 → ieee-p1363 dsaEncoding",
        X._verifyParamsForAlg("ES256").dsaEncoding === "ieee-p1363");
  rejects("_verifyParamsForAlg EdDSA refused for ID-token verify",
          function () { X._verifyParamsForAlg("EdDSA"); }, "auth-oauth/unsupported-alg");
  rejects("_verifyParamsForAlg HS256 refused (no symmetric ID tokens)",
          function () { X._verifyParamsForAlg("HS256"); }, "auth-oauth/unsupported-alg");

  // ---- helper: base64url + PKCE ----
  check("_b64urlEncode/_b64urlDecode round-trips",
        X._b64urlDecode(X._b64urlEncode(Buffer.from("hello-oauth"))).toString("utf8") === "hello-oauth");
  rejects("_b64urlDecode refuses non-base64url input",
          function () { X._b64urlDecode("@@@@"); }, "auth-oauth/bad-base64");
  var pkce = X._generatePkce();
  check("_generatePkce: verifier is 43 base64url chars (RFC 7636 32-byte)", pkce.verifier.length === 43);
  check("_generatePkce: challenge is base64url(SHA-256(verifier))",
        pkce.challenge === crypto.createHash("sha256").update(pkce.verifier).digest("base64url"));
  check("_generateRandomToken(16) → 22 base64url chars (128-bit)",
        X._generateRandomToken(16).length === 22);

  // ---- verifyIdToken: pre-JWKS refusals (no network reached) ----
  var oa = _staticOidcClient();
  await arejects("verifyIdToken: non-string refused",
                 function () { return oa.verifyIdToken(123); }, "auth-oauth/no-id-token");
  await arejects("verifyIdToken: 5-segment JWE refused (CVE-2026-29000 class)",
                 function () { return oa.verifyIdToken("a.b.c.d.e"); }, "auth-oauth/jwe-refused");
  await arejects("verifyIdToken: 2-segment token refused",
                 function () { return oa.verifyIdToken("a.b"); }, "auth-oauth/malformed-jwt");
  await arejects("verifyIdToken: undecodable header refused",
                 function () { return oa.verifyIdToken("!!!." + _b64url({}) + ".sig"); }, "auth-oauth/malformed-jwt");
  await arejects("verifyIdToken: header missing alg refused",
                 function () { return oa.verifyIdToken(_b64url({ typ: "JWT" }) + "." + _b64url({}) + ".sig"); },
                 "auth-oauth/malformed-jwt");
  await arejects("verifyIdToken: alg not in accepted list refused before key lookup",
                 function () { return oa.verifyIdToken(_b64url({ alg: "HS256" }) + "." + _b64url({}) + ".sig"); },
                 "auth-oauth/alg-not-accepted");
  await arejects("verifyIdToken: crit header refused (RFC 7515 §4.1.11)",
                 function () { return oa.verifyIdToken(_b64url({ alg: "RS256", crit: ["x"] }) + "." + _b64url({}) + ".sig"); },
                 "auth-oauth/crit-not-supported");

  // ---- authorizationUrl: offline (static endpoints / non-OIDC) ----
  var ghAuth = await gh.authorizationUrl();
  var ghUrl  = new URL(ghAuth.url);
  check("authorizationUrl: non-OIDC emits no nonce", ghAuth.nonce === null);
  check("authorizationUrl: always S256 PKCE",
        ghUrl.searchParams.get("code_challenge_method") === "S256" &&
        ghUrl.searchParams.get("code_challenge") === ghAuth.challenge);
  check("authorizationUrl: verifier is the 43-char PKCE verifier", ghAuth.verifier.length === 43);
  check("authorizationUrl: carries response_type/client_id/redirect_uri/state",
        ghUrl.searchParams.get("response_type") === "code" &&
        ghUrl.searchParams.get("client_id") === "gh" &&
        ghUrl.searchParams.get("redirect_uri") === "https://rp.example/cb" &&
        ghUrl.searchParams.get("state") === ghAuth.state);

  var ghAuth2 = await gh.authorizationUrl({ prompt: "consent", loginHint: "a@b.co", maxAge: 60 });
  var ghUrl2  = new URL(ghAuth2.url);
  check("authorizationUrl: prompt/login_hint/max_age threaded through",
        ghUrl2.searchParams.get("prompt") === "consent" &&
        ghUrl2.searchParams.get("login_hint") === "a@b.co" &&
        ghUrl2.searchParams.get("max_age") === "60");

  var ghState = await gh.authorizationUrl({ state: "given-state", nonce: "given-nonce" });
  check("authorizationUrl: caller-supplied state is used verbatim",
        ghState.state === "given-state" && new URL(ghState.url).searchParams.get("state") === "given-state");

  // static OIDC client: nonce present, discovery NOT fetched (static endpoint)
  var oidcAuth = await oa.authorizationUrl();
  check("authorizationUrl: OIDC client emits a fresh nonce",
        typeof oidcAuth.nonce === "string" && oidcAuth.nonce.length > 0 &&
        new URL(oidcAuth.url).searchParams.get("nonce") === oidcAuth.nonce);

  // separator selection when the endpoint already carries a query string
  var oaQ = _staticOidcClient({ authorizationEndpoint: "https://idp.example/auth?foo=1" });
  var qAuth = await oaQ.authorizationUrl();
  check("authorizationUrl: appends with & when endpoint has an existing query",
        qAuth.url.indexOf("/auth?foo=1&") !== -1);

  // responseMode threaded (github + explicit opt, offline)
  var ghRm = X.create({ provider: "github", clientId: "gh", redirectUri: "https://rp.example/cb", responseMode: "form_post" });
  check("authorizationUrl: response_mode from opts emitted",
        new URL((await ghRm.authorizationUrl()).url).searchParams.get("response_mode") === "form_post");

  // RFC 9396 authorization_details validation on authorizationUrl
  var rar = await gh.authorizationUrl({ authorizationDetails: [{ type: "payment_initiation", actions: ["initiate"] }] });
  check("authorizationUrl: serializes valid authorization_details",
        /[?&]authorization_details=/.test(rar.url) && Array.isArray(rar.authorizationDetails));
  await arejects("authorizationUrl: non-array authorization_details refused",
                 function () { return gh.authorizationUrl({ authorizationDetails: "nope" }); },
                 "auth-oauth/bad-authorization-details");
  await arejects("authorizationUrl: entry missing type refused",
                 function () { return gh.authorizationUrl({ authorizationDetails: [{ noType: 1 }] }); },
                 "auth-oauth/bad-authorization-details");
  await arejects("authorizationUrl: non-object entry refused",
                 function () { return gh.authorizationUrl({ authorizationDetails: [42] }); },
                 "auth-oauth/bad-authorization-details");

  // ---- exchangeCode: required-arg + OIDC nonce gate ----
  await arejects("exchangeCode: missing code refused",
                 function () { return oa.exchangeCode({}); }, "auth-oauth/no-code");
  await arejects("exchangeCode: missing verifier refused when PKCE on",
                 function () { return oa.exchangeCode({ code: "c" }); }, "auth-oauth/no-verifier");
  await arejects("exchangeCode: OIDC flow without nonce refused",
                 function () { return oa.exchangeCode({ code: "c", verifier: "v" }); }, "auth-oauth/no-nonce");
  await arejects("exchangeCode: empty-string nonce refused (falsy slips === undefined guard)",
                 function () { return oa.exchangeCode({ code: "c", verifier: "v", nonce: "" }); }, "auth-oauth/no-nonce");

  // ---- refreshAccessToken: replay defense (correct-shape callbacks) ----
  await arejects("refreshAccessToken: missing token refused",
                 function () { return oa.refreshAccessToken(""); }, "auth-oauth/no-refresh-token");
  await arejects("refreshAccessToken: seen()===true refuses replay",
                 function () { return oa.refreshAccessToken("rt", { seen: function () { return true; } }); },
                 "auth-oauth/refresh-token-replay");
  await arejects("refreshAccessToken: checkAndInsert()===false refuses replay",
                 function () { return oa.refreshAccessToken("rt", { checkAndInsert: function () { return false; } }); },
                 "auth-oauth/refresh-token-replay");
  await arejects("refreshAccessToken: checkAndInsert throwing surfaces typed error",
                 function () { return oa.refreshAccessToken("rt", { checkAndInsert: function () { throw new Error("store down"); } }); },
                 "auth-oauth/seen-callback-failed");
  await arejects("refreshAccessToken: seen throwing surfaces typed error",
                 function () { return oa.refreshAccessToken("rt", { seen: function () { throw new Error("store down"); } }); },
                 "auth-oauth/seen-callback-failed");

  // ---- exchangeToken / nativeSsoExchange: RFC 8693 token-type gate ----
  await arejects("exchangeToken: missing subjectToken refused",
                 function () { return oa.exchangeToken({}); }, "auth-oauth/bad-exchange");
  await arejects("exchangeToken: missing subjectTokenType refused",
                 function () { return oa.exchangeToken({ subjectToken: "s" }); }, "auth-oauth/bad-exchange");
  await arejects("exchangeToken: subjectTokenType outside RFC 8693 §3 refused",
                 function () { return oa.exchangeToken({ subjectToken: "s", subjectTokenType: "urn:custom" }); },
                 "auth-oauth/bad-subject-token-type");
  await arejects("exchangeToken: actorTokenType outside RFC 8693 §3 refused",
                 function () { return oa.exchangeToken({ subjectToken: "s",
                   subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
                   actorToken: "a", actorTokenType: "urn:bad" }); },
                 "auth-oauth/bad-actor-token-type");
  await arejects("nativeSsoExchange: missing deviceSecret refused",
                 function () { return oa.nativeSsoExchange({ idToken: "x" }); }, "auth-oauth/bad-native-sso");
  await arejects("nativeSsoExchange: missing idToken refused",
                 function () { return oa.nativeSsoExchange({ deviceSecret: "x" }); }, "auth-oauth/bad-native-sso");

  // ---- device grant / introspection / revoke / userinfo required-arg ----
  await arejects("pollDeviceCode: empty deviceCode refused",
                 function () { return oa.pollDeviceCode(""); }, "auth-oauth/bad-device-code");
  await arejects("pollDeviceCode: over-long deviceCode refused (amplification cap)",
                 function () { return oa.pollDeviceCode("a".repeat(9000)); }, "auth-oauth/device-code-too-large");
  await arejects("introspectToken: empty token refused",
                 function () { return oa.introspectToken(""); }, "auth-oauth/bad-introspect");
  await arejects("revokeToken: missing token refused",
                 function () { return oa.revokeToken(""); }, "auth-oauth/no-token");
  await arejects("fetchUserInfo: missing access token refused",
                 function () { return oa.fetchUserInfo(""); }, "auth-oauth/no-access-token");
  await arejects("fetchUserInfo: OIDC requires verified idTokenSub cross-check",
                 function () { return oa.fetchUserInfo("at"); }, "auth-oauth/userinfo-no-id-token-sub");

  // ---- dynamic client registration (RFC 7591/7592) required-arg ----
  await arejects("registerClient: non-object metadata refused",
                 function () { return oa.registerClient(null); }, "auth-oauth/bad-register");
  await arejects("registerClient: empty redirect_uris refused (open-redirect surface)",
                 function () { return oa.registerClient({}); }, "auth-oauth/register-no-redirect-uris");
  await arejects("registerClient: http redirect_uri refused",
                 function () { return oa.registerClient({ redirect_uris: ["http://evil.example"] }); },
                 "auth-oauth/insecure-url");
  await arejects("updateClient: non-object metadata refused",
                 function () { return oa.updateClient("https://as/reg", "tok", null); }, "auth-oauth/bad-update");
  await arejects("updateClient: empty redirect_uris refused",
                 function () { return oa.updateClient("https://as/reg", "tok", {}); }, "auth-oauth/update-no-redirect-uris");
  await arejects("readClient: empty registrationClientUri refused",
                 function () { return oa.readClient("", "tok"); }, "auth-oauth/bad-registration-client-uri");
  await arejects("readClient: empty registrationAccessToken refused",
                 function () { return oa.readClient("https://as/reg", ""); }, "auth-oauth/bad-registration-access-token");
  await arejects("deleteClient: http registrationClientUri refused",
                 function () { return oa.deleteClient("http://evil/reg", "tok"); }, "auth-oauth/insecure-url");

  // ---- endSessionUrl: offline builder (static end_session_endpoint) ----
  var esUrl = await oa.endSessionUrl({ idTokenHint: "idt", state: "s1",
    postLogoutRedirectUri: "https://rp.example/done", logoutHint: "u@x", uiLocales: "en" });
  var esU = new URL(esUrl);
  check("endSessionUrl: threads id_token_hint/state/logout_hint/ui_locales + client_id",
        esU.searchParams.get("id_token_hint") === "idt" &&
        esU.searchParams.get("state") === "s1" &&
        esU.searchParams.get("post_logout_redirect_uri") === "https://rp.example/done" &&
        esU.searchParams.get("logout_hint") === "u@x" &&
        esU.searchParams.get("ui_locales") === "en" &&
        esU.searchParams.get("client_id") === "rp-cov");
  var esNoCid = await oa.endSessionUrl({ clientId: false });
  check("endSessionUrl: clientId:false omits client_id (bare endpoint)",
        new URL(esNoCid).searchParams.get("client_id") === null);
  await arejects("endSessionUrl: javascript: post_logout_redirect_uri refused",
                 function () { return oa.endSessionUrl({ postLogoutRedirectUri: "javascript:alert(1)" }); },
                 "auth-oauth/insecure-url");
  await arejects("endSessionUrl: extraParams colliding with a first-class key refused",
                 function () { return oa.endSessionUrl({ extraParams: { state: "smuggled" } }); },
                 "auth-oauth/end-session-reserved-extra-param");

  // ---- parseFrontchannelLogoutRequest: synchronous, no network ----
  rejects("parseFrontchannelLogoutRequest: missing req refused",
          function () { oa.parseFrontchannelLogoutRequest(null); }, "auth-oauth/bad-frontchannel-logout-req");
  var fcl = oa.parseFrontchannelLogoutRequest({ url: "/fc?iss=https%3A%2F%2Fidp.example&sid=sess-1" });
  check("parseFrontchannelLogoutRequest: matching iss returns (iss, sid)",
        fcl.iss === "https://idp.example" && fcl.sid === "sess-1");
  var fclNoIss = oa.parseFrontchannelLogoutRequest({ url: "/fc?sid=sess-2" });
  check("parseFrontchannelLogoutRequest: absent iss defaults to configured issuer, sid surfaced",
        fclNoIss.iss === "https://idp.example" && fclNoIss.sid === "sess-2");
  rejects("parseFrontchannelLogoutRequest: cross-realm iss refused (CVE-2026-23552)",
          function () { oa.parseFrontchannelLogoutRequest({ url: "/fc?iss=https%3A%2F%2Fevil.example" }); },
          "auth-oauth/frontchannel-logout-iss-mismatch");

  // ---- parseCallback: shape guards (network-free forms) ----
  await arejects("parseCallback: non-object query refused",
                 function () { return oa.parseCallback(null); }, "auth-oauth/bad-callback");
  await arejects("parseCallback: missing code refused (iss supplied + requireIssParam skips discovery)",
                 function () { return oa.parseCallback({ iss: "https://idp.example" }, { requireIssParam: true }); },
                 "auth-oauth/no-code-in-callback");
  await arejects("parseCallback: OP error param refused",
                 function () { return oa.parseCallback({ error: "access_denied" }, { requireIssParam: true }); },
                 "auth-oauth/op-error");

  // ---- parseJarmResponse: shape guards ----
  await arejects("parseJarmResponse: empty response refused",
                 function () { return oa.parseJarmResponse(""); }, "auth-oauth/no-jarm-response");
  await arejects("parseJarmResponse: non-3-segment response refused",
                 function () { return oa.parseJarmResponse("not.a.jws.token.here"); }, "auth-oauth/malformed-jarm-response");

  // ---- RFC 9396 granted-details cross-check: edge cases ----
  check("crossCheck: null granted → null",
        X._crossCheckGrantedAuthorizationDetails(null, null, true) === null);
  check("crossCheck: undefined granted → null",
        X._crossCheckGrantedAuthorizationDetails(undefined, [{ type: "x" }], true) === null);
  check("crossCheck: no requested → granted passed through verbatim",
        JSON.stringify(X._crossCheckGrantedAuthorizationDetails([{ type: "x" }], null, true)) === JSON.stringify([{ type: "x" }]));
  rejects("crossCheck: non-array granted refused",
          function () { X._crossCheckGrantedAuthorizationDetails({ type: "x" }, null, true); },
          "auth-oauth/bad-granted-authorization-details");
  rejects("crossCheck: granted entry not a typed object refused",
          function () { X._crossCheckGrantedAuthorizationDetails([{ noType: 1 }], [{ type: "x" }], true); },
          "auth-oauth/bad-granted-authorization-details");
  var reqDetails = [{ type: "payment_initiation", actions: ["initiate", "status"], locations: ["https://rs/pay"] }];
  var subset = X._crossCheckGrantedAuthorizationDetails(
    [{ type: "payment_initiation", actions: ["status"] }], reqDetails, true);
  check("crossCheck: granted subset accepted", Array.isArray(subset) && subset.length === 1);
  rejects("crossCheck: over-granted datatypes field refused",
          function () { X._crossCheckGrantedAuthorizationDetails(
            [{ type: "payment_initiation", datatypes: ["ssn"] }], reqDetails, true); },
          "auth-oauth/authorization-details-over-grant");
  var big = [];
  for (var bi = 0; bi < 20000; bi++) big.push({ type: "payment_initiation", locations: ["https://rs.example/very/long/path/segment/" + bi] });
  rejects("crossCheck: oversized granted payload refused (parse-bomb cap)",
          function () { X._crossCheckGrantedAuthorizationDetails(big, [{ type: "payment_initiation" }], false); },
          "auth-oauth/granted-authorization-details-too-large");

  // ---- attestation builders: validation + claim shaping ----
  var attKp  = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instPub = instKp.publicKey.export({ format: "jwk" });
  var attPub  = attKp.publicKey.export({ format: "jwk" });

  rejects("buildClientAttestation: missing clientId refused",
          function () { X.buildClientAttestation({ attesterPrivateKey: attKp.privateKey, instanceKeyJwk: instPub }); },
          "auth-oauth/attestation-no-client-id");
  rejects("buildClientAttestation: missing attesterPrivateKey refused",
          function () { X.buildClientAttestation({ clientId: "w", instanceKeyJwk: instPub }); },
          "auth-oauth/attestation-no-attester-key");
  rejects("buildClientAttestation: missing instanceKeyJwk refused",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey }); },
          "auth-oauth/attestation-bad-cnf");
  rejects("buildClientAttestation: symmetric cnf kty refused (no private half in cnf)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: { kty: "oct", k: "AAAA" } }); },
          "auth-oauth/attestation-bad-cnf");
  rejects("buildClientAttestation: non-finite nbf refused",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: instPub, nbf: Infinity }); }, "auth-oauth/attestation-bad-nbf");
  rejects("buildClientAttestation: non-finite iat refused",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: instPub, iat: NaN }); }, "auth-oauth/attestation-bad-iat");
  rejects("buildClientAttestation: zero expiresInSec refused (positive-int)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: instPub, expiresInSec: 0 }); }, "auth-oauth/attestation-bad-expiry");

  // extraClaims cannot overwrite spec-reserved fields (sub/iat/exp/cnf/nbf)
  var attExtra = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
    instanceKeyJwk: instPub, iat: 1000, expiresInSec: 60, nbf: 100,
    extraClaims: { sub: "HIJACK", exp: 9, role: "admin" } });
  var attPayload = JSON.parse(Buffer.from(attExtra.split(".")[1], "base64url").toString("utf8"));
  check("buildClientAttestation: extraClaims cannot override sub/exp; passes non-reserved keys",
        attPayload.sub === "w" && attPayload.exp === 1060 && attPayload.role === "admin" &&
        attPayload.iat === 1000 && attPayload.nbf === 100);

  rejects("buildClientAttestationPop: missing audience refused",
          function () { X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey }); },
          "auth-oauth/attestation-pop-no-aud");
  rejects("buildClientAttestationPop: missing instancePrivateKey refused",
          function () { X.buildClientAttestationPop({ audience: "https://as" }); },
          "auth-oauth/attestation-pop-no-instance-key");
  var popShaped = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as",
    expiresInSec: 120, challenge: "srv-ch", jti: "fixed-jti" });
  var popPayload = JSON.parse(Buffer.from(popShaped.split(".")[1], "base64url").toString("utf8"));
  check("buildClientAttestationPop: exp/challenge/jti overrides shaped into payload",
        typeof popPayload.exp === "number" && popPayload.challenge === "srv-ch" && popPayload.jti === "fixed-jti");

  // ---- verifyClientAttestation: validation + freshness gates ----
  var att = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey, instanceKeyJwk: instPub });
  var pop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as" });
  await arejects("verifyClientAttestation: missing attesterJwk refused",
                 function () { return X.verifyClientAttestation(att, pop, { expectedAudience: "https://as" }); },
                 "auth-oauth/attestation-no-attester-jwk");
  await arejects("verifyClientAttestation: missing expectedAudience refused",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub }); },
                 "auth-oauth/attestation-no-expected-aud");
  await arejects("verifyClientAttestation: non-finite clockSkewSec refused (would disable exp gate)",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub,
                   expectedAudience: "https://as", clockSkewSec: Infinity }); }, "auth-oauth/bad-clock-skew");
  await arejects("verifyClientAttestation: non-finite maxPopAgeSec refused",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub,
                   expectedAudience: "https://as", maxPopAgeSec: Infinity }); }, "auth-oauth/bad-pop-max-age");
  var expiredAtt = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
    instanceKeyJwk: instPub, iat: 1000, expiresInSec: 60 });
  await arejects("verifyClientAttestation: expired attestation refused",
                 function () { return X.verifyClientAttestation(expiredAtt, pop, { attesterJwk: attPub, expectedAudience: "https://as" }); },
                 "auth-oauth/attestation-expired");
  var stalePop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as", iat: 1000 });
  await arejects("verifyClientAttestation: stale PoP iat refused",
                 function () { return X.verifyClientAttestation(att, stalePop, { attesterJwk: attPub, expectedAudience: "https://as" }); },
                 "auth-oauth/attestation-pop-stale");
  var futurePop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as",
    iat: Math.floor(Date.now() / 1000) + 100000 });
  await arejects("verifyClientAttestation: future PoP iat refused",
                 function () { return X.verifyClientAttestation(att, futurePop, { attesterJwk: attPub, expectedAudience: "https://as" }); },
                 "auth-oauth/attestation-pop-iat-future");
  await arejects("verifyClientAttestation: seenJti callback throwing surfaces typed error",
                 function () {
                   var freshPop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://as" });
                   return X.verifyClientAttestation(att, freshPop, { attesterJwk: attPub, expectedAudience: "https://as",
                     seenJti: function () { throw new Error("store down"); } });
                 }, "auth-oauth/attestation-pop-seen-callback-failed");

  console.log("auth-oauth-coverage checks passed");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
