// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.oauth — config-time validation, offline builders, and loopback
 * IdP round-trips.
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
 * Every assertion drives the public b.auth.oauth surface. The offline
 * sections never reach the network (each throws before endpoint
 * resolution, builds a URL from a static endpoint, or is a pure helper);
 * the loopback sections drive the error, wrong-state, backend-failure and
 * adversarial branches that only resolve with a live IdP round-trip,
 * against a 127.0.0.1 stand-in AS/JWKS server (allowHttp + allowInternal,
 * never a real endpoint, never rejectUnauthorized:false) serving
 * locally-signed ES256 id_tokens.
 */

var crypto  = require("node:crypto");
var http    = require("node:http");
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

// ================= loopback IdP round-trip scenarios =====================

function throws(label, fn, code) {
  var e = null;
  try { fn(); } catch (x) { e = x; }
  check(label, e !== null && e.code === code);
}

async function athrows(label, fn, code) {
  var e = null;
  try { await fn(); } catch (x) { e = x; }
  check(label, e !== null && e.code === code);
}

async function aresolves(label, fn) {
  var ok = false;
  var val = null;
  try { val = await fn(); ok = true; } catch (_e) { ok = false; }
  check(label, ok);
  return val;
}

// ---- local signing key + JWKS material ----

var KID    = "kid-cov2";
var KP     = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var PRIV   = KP.privateKey;
var PUBJWK = Object.assign(KP.publicKey.export({ format: "jwk" }), { kid: KID, use: "sig", alg: "ES256" });

function _b64urlJson(o) { return Buffer.from(JSON.stringify(o), "utf8").toString("base64url"); }

function signToken(header, payload) {
  var params = X._verifyParamsForAlg(header.alg);
  var input  = _b64urlJson(header) + "." + _b64urlJson(payload);
  var o = { key: PRIV };
  if (params.padding     !== undefined) o.padding     = params.padding;
  if (params.saltLength  !== undefined) o.saltLength  = params.saltLength;
  if (params.dsaEncoding !== undefined) o.dsaEncoding = params.dsaEncoding;
  var sig = crypto.sign(params.hash, Buffer.from(input, "ascii"), o);
  return input + "." + sig.toString("base64url");
}

// Build an ES256 id_token for `clientId`. `claims`/`hdr` override the
// defaults; a claim/header set to undefined is dropped from the JSON.
function mkToken(clientId, claims, hdr) {
  var now = Math.floor(Date.now() / 1000);
  var payload = { iss: "https://idp.example", aud: clientId, iat: now, exp: now + 3600 };
  if (claims) { var ck = Object.keys(claims); for (var i = 0; i < ck.length; i++) payload[ck[i]] = claims[ck[i]]; }
  var header = { alg: "ES256", typ: "JWT", kid: KID };
  if (hdr) { var hk = Object.keys(hdr); for (var j = 0; j < hk.length; j++) header[hk[j]] = hdr[hk[j]]; }
  if (header._noKid) { delete header.kid; delete header._noKid; }
  return signToken(header, payload);
}

// Flip one decoded signature byte — keeps the 64-byte P1363 length so
// nodeCrypto.verify RETURNS false rather than throwing.
function tamperSig(tok) {
  var p = tok.split(".");
  var sig = Buffer.from(p[2], "base64url");
  sig[0] = sig[0] ^ 0xff;
  return p[0] + "." + p[1] + "." + sig.toString("base64url");
}

// ---- loopback stand-in AS ----

function makeServer() {
  var routes = {};
  function respond(res, r) {
    var status = r.status || 200;
    var body = r.text !== undefined ? r.text : JSON.stringify(r.json !== undefined ? r.json : {});
    res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
  }
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var r = routes[req.method + " " + u.pathname];
      if (r === undefined) r = routes[u.pathname];
      if (typeof r === "function") { r(req, res, Buffer.concat(chunks).toString("utf8"), u); return; }
      if (r) { respond(res, r); return; }
      res.writeHead(404, { "Content-Type": "application/json" }); res.end("{}");
    });
  });
  return { server: server, routes: routes };
}

// Full-endpoint discovery-free OIDC client aimed at the loopback stand-in.
// The stand-in returns OAuth error responses with their spec HTTP status
// (4xx/5xx); b.httpClient rejects those by default, so surface them to the
// oauth layer with the documented `responseMode: "always-resolve"` opt so the
// module's own typed-error branches run (the default-path device-grant
// consequence of NOT setting this is reported separately as a defect).
function mk(base, clientId, extra) {
  var opts = {
    issuer:                      "https://idp.example",
    clientId:                    clientId,
    clientSecret:                "sec",
    redirectUri:                 "https://rp.example/cb",
    isOidc:                      true,
    allowHttp:                   true,
    allowInternal:               true,
    httpClient:                  { responseMode: "always-resolve" },
    jwksUri:                     base + "/jwks",
    authorizationEndpoint:       base + "/auth",
    tokenEndpoint:               base + "/token",
    userinfoEndpoint:            base + "/userinfo",
    revocationEndpoint:          base + "/revoke",
    introspectionEndpoint:       base + "/introspect",
    registrationEndpoint:        base + "/register",
    deviceAuthorizationEndpoint: base + "/device",
    endSessionEndpoint:          base + "/logout",
    checkSessionIframe:          base + "/checksession",
  };
  if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
  return X.create(opts);
}

// Minimal client with NO static endpoints + no discovery — every endpoint
// resolution lands on the "no-endpoint" refusal.
function mkBare(clientId, extra) {
  var opts = { clientId: clientId, redirectUri: "https://rp.example/cb", isOidc: false };
  if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
  return X.create(opts);
}

// Discovery-backed client (issuer = the loopback /dfull tenant). Used for the
// introspection / registration / device endpoints, which resolve ONLY through
// OIDC discovery — create()'s staticEndpoints does not carry those three (see
// the reported defect); a discovery doc is the working configuration.
function mkDisc(base, clientId, extra) {
  var opts = { issuer: base + "/dfull", clientId: clientId, clientSecret: "sec",
    redirectUri: "https://rp.example/cb", isOidc: true, allowHttp: true, allowInternal: true,
    httpClient: { responseMode: "always-resolve" } };
  if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
  return X.create(opts);
}

// Discovery document the mkDisc tenant serves.
function installDiscoveryDoc(base, routes) {
  routes["/dfull/.well-known/openid-configuration"] = { json: {
    issuer:                         base + "/dfull",
    authorization_endpoint:         base + "/auth",
    token_endpoint:                 base + "/token",
    jwks_uri:                       base + "/jwks",
    userinfo_endpoint:              base + "/userinfo",
    revocation_endpoint:            base + "/revoke",
    introspection_endpoint:         base + "/introspect",
    registration_endpoint:          base + "/register",
    device_authorization_endpoint:  base + "/device",
    end_session_endpoint:           base + "/logout",
    check_session_iframe:           base + "/checksession",
    code_challenge_methods_supported: ["S256"],
  } };
}

// =========================================================================

async function scenarioVerifyIdToken(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var CID = "cov2-verify";
  var oa  = mk(base, CID, { issuer: "https://idp.example" });

  // Happy path — valid signature, all claims well-formed.
  var ok = await aresolves("verifyIdToken: valid ES256 token resolves",
    function () { return oa.verifyIdToken(mkToken(CID, { sub: "u1" })); });
  check("verifyIdToken: returns header + claims", ok && ok.claims && ok.claims.sub === "u1" && ok.header.alg === "ES256");

  var nowS = Math.floor(Date.now() / 1000);

  await athrows("verifyIdToken: expired token refused",
    function () { return oa.verifyIdToken(mkToken(CID, { exp: nowS - 100, iat: nowS - 200 })); },
    "auth-oauth/expired");
  await athrows("verifyIdToken: iat-in-future refused",
    function () { return oa.verifyIdToken(mkToken(CID, { iat: nowS + 100000, exp: nowS + 200000 })); },
    "auth-oauth/iat-future");
  await athrows("verifyIdToken: nbf-in-future refused",
    function () { return oa.verifyIdToken(mkToken(CID, { nbf: nowS + 100000 })); },
    "auth-oauth/nbf-future");
  await athrows("verifyIdToken: iss mismatch refused (CVE-2026-23552)",
    function () { return oa.verifyIdToken(mkToken(CID, { iss: "https://evil.example" })); },
    "auth-oauth/iss-mismatch");
  await athrows("verifyIdToken: aud not containing clientId refused",
    function () { return oa.verifyIdToken(mkToken(CID, { aud: "someone-else" })); },
    "auth-oauth/aud-mismatch");
  await athrows("verifyIdToken: missing aud refused",
    function () { return oa.verifyIdToken(mkToken(CID, { aud: undefined })); },
    "auth-oauth/aud-mismatch");
  await athrows("verifyIdToken: multi-aud without azp refused (OIDC §3.1.3.7)",
    function () { return oa.verifyIdToken(mkToken(CID, { aud: [CID, "other-rp"] })); },
    "auth-oauth/azp-required");
  await athrows("verifyIdToken: azp not clientId refused",
    function () { return oa.verifyIdToken(mkToken(CID, { azp: "other-rp" })); },
    "auth-oauth/azp-mismatch");
  await aresolves("verifyIdToken: multi-aud with matching azp accepted",
    function () { return oa.verifyIdToken(mkToken(CID, { aud: [CID, "other-rp"], azp: CID })); });
  // Single-aud token whose azp equals clientId is accepted (the azp-present-
  // and-equal branch of OIDC Core §3.1.3.7 — distinct from the multi-aud path).
  await aresolves("verifyIdToken: single-aud token with azp === clientId accepted",
    function () { return oa.verifyIdToken(mkToken(CID, { azp: CID })); });
  // A multi-aud token whose azp is a NON-string (type confusion) fails the
  // `typeof azp !== "string"` guard and is refused as azp-required — the AS
  // cannot dodge the authorized-party requirement by emitting a numeric azp.
  await athrows("verifyIdToken: multi-aud with non-string azp refused (azp-required)",
    function () { return oa.verifyIdToken(mkToken(CID, { aud: [CID, "other-rp"], azp: 123 })); },
    "auth-oauth/azp-required");

  // nonce branches
  await aresolves("verifyIdToken: matching nonce accepted",
    function () { return oa.verifyIdToken(mkToken(CID, { nonce: "n1" }), { nonce: "n1" }); });
  await athrows("verifyIdToken: nonce mismatch refused",
    function () { return oa.verifyIdToken(mkToken(CID, { nonce: "n1" }), { nonce: "n2" }); },
    "auth-oauth/nonce-mismatch");
  await athrows("verifyIdToken: expected nonce but token carries none refused",
    function () { return oa.verifyIdToken(mkToken(CID, {}), { nonce: "n2" }); },
    "auth-oauth/nonce-mismatch");

  // signature branches
  await athrows("verifyIdToken: tampered signature refused (verify → false)",
    function () { return oa.verifyIdToken(tamperSig(mkToken(CID, {}))); },
    "auth-oauth/bad-signature");
  var malformedSig = (function () {
    var p = mkToken(CID, {}).split(".");
    return p[0] + "." + p[1] + "." + crypto.randomBytes(10).toString("base64url");
  })();
  await athrows("verifyIdToken: malformed-length signature refused",
    function () { return oa.verifyIdToken(malformedSig); }, "auth-oauth/bad-signature");

  // kid resolution branches
  await athrows("verifyIdToken: unknown kid refused",
    function () { return oa.verifyIdToken(mkToken(CID, {}, { kid: "nope" })); },
    "auth-oauth/no-matching-key");
  await athrows("verifyIdToken: kid-less token refused by default (JWKS-rotation defense)",
    function () { return oa.verifyIdToken(mkToken(CID, {}, { _noKid: true })); },
    "auth-oauth/no-matching-key");
  await aresolves("verifyIdToken: kid-less token accepted with vopts.allowKidlessJwks",
    function () { return oa.verifyIdToken(mkToken(CID, {}, { _noKid: true }), { allowKidlessJwks: true }); });

  // alg/kty cross-check (CVE-2026-22817) — RS256 header against the EC JWK.
  await athrows("verifyIdToken: alg/kty mismatch refused (RS256 header, EC JWK)",
    function () {
      var tok = _b64urlJson({ alg: "RS256", typ: "JWT", kid: KID }) + "." +
                _b64urlJson({ iss: "https://idp.example", aud: CID, iat: nowS, exp: nowS + 3600 }) + ".AAAA";
      return oa.verifyIdToken(tok);
    }, "auth-jwt-external/alg-kty-mismatch");

  // skipExpCheck is self-guarding — refused on a non-logout token.
  await athrows("verifyIdToken: skipExpCheck on a non-logout token refused",
    function () { return oa.verifyIdToken(mkToken(CID, {}), { skipExpCheck: true, skipNonceCheck: true }); },
    "auth-oauth/skip-exp-check-not-allowed");

  // client-level allowKidlessJwks threads through create()
  var oaKidless = mk(base, "cov2-verify-kidless", { allowKidlessJwks: true });
  await aresolves("verifyIdToken: client-level allowKidlessJwks accepts kid-less token",
    function () { return oaKidless.verifyIdToken(mkToken("cov2-verify-kidless", {}, { _noKid: true })); });

  // custom acceptedAlgorithms rejects an off-list alg before key lookup
  var oaEcOnly = mk(base, "cov2-verify-ec", { acceptedAlgorithms: ["ES256"] });
  await athrows("verifyIdToken: alg outside custom acceptedAlgorithms refused",
    function () {
      var tok = _b64urlJson({ alg: "RS512", typ: "JWT", kid: KID }) + "." +
                _b64urlJson({ iss: "https://idp.example", aud: "cov2-verify-ec", iat: nowS, exp: nowS + 3600 }) + ".AAAA";
      return oaEcOnly.verifyIdToken(tok);
    }, "auth-oauth/alg-not-accepted");

  // JWKS backend failures — fresh clients so the JWKS cache is unfilled.
  routes["/jwks-500"]    = { status: 500, text: "boom" };
  routes["/jwks-nokeys"] = { json: { not_keys: [] } };
  var oa500 = mk(base, "cov2-verify-j500", { jwksUri: base + "/jwks-500" });
  await athrows("verifyIdToken: JWKS endpoint 500 surfaces http-500",
    function () { return oa500.verifyIdToken(mkToken("cov2-verify-j500", {})); }, "auth-oauth/http-500");
  var oaNoKeys = mk(base, "cov2-verify-jnk", { jwksUri: base + "/jwks-nokeys" });
  await athrows("verifyIdToken: JWKS without keys[] refused",
    function () { return oaNoKeys.verifyIdToken(mkToken("cov2-verify-jnk", {})); }, "auth-oauth/bad-jwks");
}

async function scenarioTokenFlows(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var CID = "cov2-token";
  var oa  = mk(base, CID);

  // exchangeCode with a verifiable id_token (nonce enforced).
  routes["/token"] = { json: {
    access_token: "at-1", token_type: "Bearer", expires_in: 3600, refresh_token: "rt-1",
    scope: "openid email",
    id_token: mkToken(CID, { sub: "user-42", email: "u@x", nonce: "nz1" }),
  } };
  var tok = await aresolves("exchangeCode: full flow returns tokens + verified claims",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", nonce: "nz1" }); });
  check("exchangeCode: accessToken + profile.sub + scope split",
    tok && tok.accessToken === "at-1" && tok.profile.sub === "user-42" &&
    tok.scope.length === 2 && tok.scope[0] === "openid");

  // exchangeCode RFC 9396 granted-details subset accepted (strict).
  routes["/token"] = { json: {
    access_token: "at-2",
    authorization_details: [{ type: "payment_initiation", actions: ["status"] }],
  } };
  var tokRar = await aresolves("exchangeCode: granted authorization_details subset accepted",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true,
      authorizationDetails: [{ type: "payment_initiation", actions: ["initiate", "status"] }] }); });
  check("exchangeCode: authorizationDetails surfaced", tokRar && Array.isArray(tokRar.authorizationDetails) &&
    tokRar.authorizationDetails.length === 1);

  // exchangeCode over-grant refused (strict).
  routes["/token"] = { json: {
    access_token: "at-3",
    authorization_details: [{ type: "payment_initiation", actions: ["transfer"] }],
  } };
  await athrows("exchangeCode: granted over-grant refused (strict)",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true,
      authorizationDetails: [{ type: "payment_initiation", actions: ["initiate", "status"] }] }); },
    "auth-oauth/authorization-details-over-grant");

  // exchangeCode over-grant SURFACED (verifyAuthorizationDetails:false).
  var tokLax = await aresolves("exchangeCode: over-grant surfaced without refusal when verify disabled",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true,
      verifyAuthorizationDetails: false,
      authorizationDetails: [{ type: "payment_initiation", actions: ["initiate"] }] }); });
  check("exchangeCode: non-strict surfaces granted details", tokLax && Array.isArray(tokLax.authorizationDetails));

  // RFC 6749 §3.3 — the granted `scope` is delimited by U+0020 ONLY. A hostile
  // AS that separates two scope tokens with a NON-space whitespace (here U+0085
  // NEL) must NOT surface as two allowlist-matchable scopes; the pair stays a
  // single opaque token so an operator scope allowlist can't be tricked into
  // seeing a scope that was never granted. Drives the real exchangeCode path.
  routes["/token"] = { json: { access_token: "at-scope", scope: "admin\u0085read" } };
  var scTok = await aresolves("exchangeCode: hostile non-space scope separator stays one token (RFC 6749 §3.3)",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true }); });
  check("exchangeCode: NEL-separated scope is not split into an allowlist bypass",
    scTok && scTok.scope.length === 1 && scTok.scope[0] === "admin\u0085read" &&
    scTok.scope.indexOf("admin") === -1 && scTok.scope.indexOf("read") === -1);

  // RFC 6749 \u00a73.3 \u2014 a PRESENT but malformed `scope` ({ "scope": null }) is NOT
  // an omitted scope. Only a truly ABSENT property mirrors the requested set;
  // treating null as absent would copy the full requested scope (openid email)
  // and report a grant the AS never made. A malformed scope falls through to
  // zero (fail closed).
  routes["/token"] = { json: { access_token: "at-null-scope", scope: null } };
  var nullScTok = await aresolves("exchangeCode: null scope is malformed, not absent",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true }); });
  check("exchangeCode: null scope grants ZERO scopes, not the requested set",
    nullScTok && Array.isArray(nullScTok.scope) && nullScTok.scope.length === 0);

  // _postForm backend-failure branches.
  routes["/token"] = { status: 400, json: { error: "invalid_grant" } };
  await athrows("exchangeCode: token endpoint non-2xx surfaces token-error-400",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true }); }, "auth-oauth/token-error-400");
  routes["/token"] = { status: 200, text: "not-json-at-all" };
  await athrows("exchangeCode: token endpoint non-JSON surfaces bad-token-json",
    function () { return oa.exchangeCode({ code: "c", verifier: "v", skipNonceCheck: true }); }, "auth-oauth/bad-token-json");

  // refreshAccessToken rotation branches (no callbacks → replay gate skipped).
  routes["/token"] = { json: { access_token: "at-r", refresh_token: "rt-new" } };
  var fr = await aresolves("refreshAccessToken: full flow with rotation",
    function () { return oa.refreshAccessToken("rt-old"); });
  check("refreshAccessToken: rotation flagged + previous captured",
    fr && fr.refreshTokenRotated === true && fr.previousRefreshToken === "rt-old");
  routes["/token"] = { json: { access_token: "at-r2" } };
  var fr2 = await aresolves("refreshAccessToken: no new refresh_token → not rotated",
    function () { return oa.refreshAccessToken("rt-old"); });
  check("refreshAccessToken: rotation false when unchanged", fr2 && fr2.refreshTokenRotated === false);

  // refresh with a fresh id_token verifies (skipNonceCheck path).
  routes["/token"] = { json: { access_token: "at-r3", id_token: mkToken(CID, { sub: "user-42" }) } };
  var fr3 = await aresolves("refreshAccessToken: refreshed id_token verified (skip-nonce)",
    function () { return oa.refreshAccessToken("rt-old"); });
  check("refreshAccessToken: refreshed profile surfaced", fr3 && fr3.profile && fr3.profile.sub === "user-42");

  // exchangeToken (RFC 8693) full flow.
  routes["/token"] = { json: { access_token: "at-x", token_type: "Bearer" } };
  var xt = await aresolves("exchangeToken: full flow returns tokens",
    function () { return oa.exchangeToken({ subjectToken: "s",
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      audience: "https://down.example", resource: "https://rs.example", scope: ["a", "b"],
      requestedTokenType: "urn:ietf:params:oauth:token-type:access_token" }); });
  check("exchangeToken: returns accessToken", xt && xt.accessToken === "at-x");

  // exchangeToken with a custom subjectTokenType permitted by opt-in.
  await aresolves("exchangeToken: custom token type allowed with allowCustomTokenType",
    function () { return oa.exchangeToken({ subjectToken: "s", subjectTokenType: "urn:acme:custom",
      allowCustomTokenType: true }); });

  // nativeSsoExchange composes exchangeToken.
  routes["/token"] = { json: { access_token: "at-n" } };
  var ns = await aresolves("nativeSsoExchange: full flow returns tokens",
    function () { return oa.nativeSsoExchange({ deviceSecret: "ds", idToken: "idt", audience: "app2" }); });
  check("nativeSsoExchange: returns accessToken", ns && ns.accessToken === "at-n");
}

async function scenarioUserinfoRevokeIntrospect(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var CID = "cov2-uri";
  var oa  = mk(base, CID);

  routes["/userinfo"] = { json: { sub: "u1", email: "a@b" } };
  var prof = await aresolves("fetchUserInfo: OIDC with matching idTokenSub returns profile",
    function () { return oa.fetchUserInfo("at", { idTokenSub: "u1" }); });
  check("fetchUserInfo: profile carries sub", prof && prof.sub === "u1");
  await athrows("fetchUserInfo: userinfo.sub mismatch refused (substitution defense)",
    function () { return oa.fetchUserInfo("at", { idTokenSub: "someone-else" }); },
    "auth-oauth/userinfo-sub-mismatch");
  await aresolves("fetchUserInfo: skipSubCheck bypasses the cross-check",
    function () { return oa.fetchUserInfo("at", { skipSubCheck: true }); });

  // non-OIDC client needs no idTokenSub.
  var oaNonOidc = mk(base, "cov2-uri-nonoidc", { isOidc: false });
  await aresolves("fetchUserInfo: non-OIDC client returns profile without cross-check",
    function () { return oaNonOidc.fetchUserInfo("at"); });

  // _fetchJson backend-failure branches.
  routes["/userinfo"] = { status: 500, text: "boom" };
  await athrows("fetchUserInfo: userinfo 500 surfaces http-500",
    function () { return oa.fetchUserInfo("at", { skipSubCheck: true }); }, "auth-oauth/http-500");
  routes["/userinfo"] = { status: 200, text: "<<not json>>" };
  await athrows("fetchUserInfo: userinfo non-JSON surfaces bad-json",
    function () { return oa.fetchUserInfo("at", { skipSubCheck: true }); }, "auth-oauth/bad-json");

  // revokeToken success + failure.
  routes["/revoke"] = { status: 200, json: {} };
  await aresolves("revokeToken: 2xx resolves (RFC 7009)",
    function () { return oa.revokeToken("tok", { type: "refresh_token" }); });
  routes["/revoke"] = { status: 400, json: {} };
  await athrows("revokeToken: non-2xx surfaces revoke-failed",
    function () { return oa.revokeToken("tok"); }, "auth-oauth/revoke-failed");

  // introspectToken success + bad-response + no-endpoint (discovery-backed —
  // the introspection endpoint resolves only via OIDC discovery).
  var oaI = mkDisc(base, "cov2-uri-introspect");
  routes["/introspect"] = { json: { active: true, scope: "read" } };
  var intr = await aresolves("introspectToken: active verdict returned",
    function () { return oaI.introspectToken("tok", { tokenTypeHint: "access_token" }); });
  check("introspectToken: active boolean surfaced", intr && intr.active === true);
  routes["/introspect"] = { json: { scope: "read" } };
  await athrows("introspectToken: response missing active boolean refused",
    function () { return oaI.introspectToken("tok"); }, "auth-oauth/bad-introspect-response");

  var oaBare = mkBare("cov2-uri-bare");
  await athrows("introspectToken: no introspection endpoint refused",
    function () { return oaBare.introspectToken("tok"); }, "auth-oauth/no-introspection-endpoint");
}

async function scenarioRegisterDcr(base, routes) {
  var CID = "cov2-reg";
  var oa  = mk(base, CID);
  // registration_endpoint resolves only via OIDC discovery.
  var oaReg = mkDisc(base, "cov2-reg-disc");

  routes["/register"] = { status: 201, json: { client_id: "new-client", client_secret: "cs" } };
  var reg = await aresolves("registerClient: full flow returns client_id",
    function () { return oaReg.registerClient({ redirect_uris: ["https://rp.example/cb"] },
      { initialAccessToken: "iat-token" }); });
  check("registerClient: client_id surfaced", reg && reg.client_id === "new-client");

  routes["/register"] = { status: 400, text: "bad" };
  await athrows("registerClient: non-2xx surfaces register-failed",
    function () { return oaReg.registerClient({ redirect_uris: ["https://rp.example/cb"] }); },
    "auth-oauth/register-failed-400");
  routes["/register"] = { status: 201, text: "notjson" };
  await athrows("registerClient: non-JSON response refused",
    function () { return oaReg.registerClient({ redirect_uris: ["https://rp.example/cb"] }); },
    "auth-oauth/bad-register-response");
  routes["/register"] = { status: 201, json: { note: "no id here" } };
  await athrows("registerClient: response missing client_id refused",
    function () { return oaReg.registerClient({ redirect_uris: ["https://rp.example/cb"] }); },
    "auth-oauth/register-no-client-id");

  // _validateUrl empty-string redirect_uri → bad-url (before endpoint resolve).
  await athrows("registerClient: empty-string redirect_uri refused (URL required)",
    function () { return oaReg.registerClient({ redirect_uris: [""] }); }, "auth-oauth/bad-url");

  var oaBare = mkBare("cov2-reg-bare");
  await athrows("registerClient: no registration endpoint refused",
    function () { return oaBare.registerClient({ redirect_uris: ["https://rp.example/cb"] }); },
    "auth-oauth/no-registration-endpoint");

  // DCR management (RFC 7592).
  routes["GET /dcr"]    = { json: { client_id: "c", redirect_uris: ["https://rp.example/cb"] } };
  routes["PUT /dcr"]    = { json: { client_id: "c", registration_access_token: "rotated" } };
  routes["DELETE /dcr"] = { status: 204 };
  var uri = base + "/dcr";
  var rc = await aresolves("readClient: GET returns metadata",
    function () { return oa.readClient(uri, "rat"); });
  check("readClient: metadata surfaced", rc && rc.client_id === "c");
  var uc = await aresolves("updateClient: PUT returns rotated metadata",
    function () { return oa.updateClient(uri, "rat", { redirect_uris: ["https://rp.example/cb2"] }); });
  check("updateClient: rotated token surfaced", uc && uc.registration_access_token === "rotated");
  var del = await aresolves("deleteClient: 204 resolves true",
    function () { return oa.deleteClient(uri, "rat"); });
  check("deleteClient: returns true", del === true);

  routes["DELETE /dcr"] = { status: 404 };
  await athrows("deleteClient: 404 surfaces dcr-not-found",
    function () { return oa.deleteClient(uri, "rat"); }, "auth-oauth/dcr-not-found");
  routes["DELETE /dcr"] = { status: 500 };
  await athrows("deleteClient: other status surfaces dcr-delete-failed",
    function () { return oa.deleteClient(uri, "rat"); }, "auth-oauth/dcr-delete-failed-500");

  routes["GET /dcr-500"] = { status: 500, text: "err" };
  await athrows("readClient: non-2xx GET surfaces dcr-get-failed",
    function () { return oa.readClient(base + "/dcr-500", "rat"); }, "auth-oauth/dcr-get-failed-500");
  routes["GET /dcr-badjson"] = { status: 200, text: "notjson" };
  await athrows("readClient: non-JSON GET surfaces dcr-bad-response",
    function () { return oa.readClient(base + "/dcr-badjson", "rat"); }, "auth-oauth/dcr-bad-response");
}

async function scenarioDeviceAndPoll(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  // device_authorization_endpoint resolves only via OIDC discovery.
  var oa = mkDisc(base, "cov2-dev");

  routes["/device"] = { json: { device_code: "dc-1", user_code: "UC-1", verification_uri: "https://verify.example" } };
  var dev = await aresolves("deviceAuthorization: returns device_code + user_code",
    function () { return oa.deviceAuthorization({ scope: ["openid"] }); });
  check("deviceAuthorization: device_code surfaced", dev && dev.device_code === "dc-1");
  routes["/device"] = { json: { note: "missing fields" } };
  await athrows("deviceAuthorization: response missing fields refused",
    function () { return oa.deviceAuthorization(); }, "auth-oauth/bad-device-response");
  var oaBare = mkBare("cov2-dev-bare");
  await athrows("deviceAuthorization: no device endpoint refused",
    function () { return oaBare.deviceAuthorization(); }, "auth-oauth/no-device-endpoint");

  // pollDeviceCode success on first poll (no sleep).
  routes["/token"] = { json: { access_token: "at-poll" } };
  var polled = await aresolves("pollDeviceCode: success on first poll",
    function () { return oa.pollDeviceCode("dc-1"); });
  check("pollDeviceCode: returns tokens", polled && polled.accessToken === "at-poll");

  // pollDeviceCode terminal error.
  routes["/token"] = { status: 400, json: { error: "access_denied", error_description: "user declined" } };
  await athrows("pollDeviceCode: terminal error surfaced",
    function () { return oa.pollDeviceCode("dc-1"); }, "auth-oauth/device-access_denied");

  // pollDeviceCode authorization_pending → one 5s poll interval → timeout.
  routes["/token"] = { json: { error: "authorization_pending" } };
  await athrows("pollDeviceCode: authorization_pending then budget exhausted → timeout",
    function () { return oa.pollDeviceCode("dc-1", { maxWaitMs: 1 }); }, "auth-oauth/device-poll-timeout");

  // pollDeviceCode slow_down (RFC 8628 §3.5) → interval bumped, keeps polling
  // → budget exhausted → timeout (proves the slow_down branch is taken, not
  // surfaced as a terminal error).
  routes["/token"] = { json: { error: "slow_down" } };
  await athrows("pollDeviceCode: slow_down bumps the interval then times out",
    function () { return oa.pollDeviceCode("dc-1", { maxWaitMs: 1 }); }, "auth-oauth/device-poll-timeout");
}

// pollDeviceCode over the DEFAULT b.httpClient (no `responseMode:
// "always-resolve"` workaround). RFC 8628 §3.5 / RFC 6749 §5.2 deliver
// authorization_pending / slow_down / terminal OAuth errors as HTTP 400.
// The poll loop must read `parsed.error` from that 400 body; if the token
// request runs in the default buffer mode, b.httpClient rejects the 4xx
// BEFORE the loop reads the error, so the grant aborts on the first poll
// (which is almost always authorization_pending). This scenario uses NO
// httpClient override, so it fails RED until pollDeviceCode itself requests
// always-resolve.
async function scenarioDeviceGrantDefaultHttp(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var oa = X.create({
    clientId:      "cov2-devgrant",
    clientSecret:  "sec",
    redirectUri:   "https://rp.example/cb",
    isOidc:        false,
    allowHttp:     true,
    allowInternal: true,
    tokenEndpoint: base + "/token",
  });

  // Terminal OAuth error delivered as HTTP 400 (RFC 6749 §5.2): the typed
  // device-<error> branch must run, proving the 400 body was parsed rather
  // than surfaced as a raw HTTP reject.
  routes["/token"] = { status: 400, json: { error: "access_denied", error_description: "user declined" } };
  await athrows("pollDeviceCode(default httpClient): HTTP 400 terminal error is parsed, not HTTP-thrown",
    function () { return oa.pollDeviceCode("dc-1"); }, "auth-oauth/device-access_denied");

  // authorization_pending delivered as HTTP 400: the loop must KEEP polling
  // (not abort on the first poll), so a tight budget resolves to the device
  // poll-timeout, never a raw HTTP reject.
  routes["/token"] = { status: 400, json: { error: "authorization_pending" } };
  await athrows("pollDeviceCode(default httpClient): HTTP 400 authorization_pending keeps polling → timeout",
    function () { return oa.pollDeviceCode("dc-1", { maxWaitMs: 1 }); }, "auth-oauth/device-poll-timeout");
}

// A static (non-discovery) client that supplies introspection / registration
// / device_authorization endpoints as create() opts. create() must read
// those three snake-case-mapped endpoints into staticEndpoints so
// _resolveEndpoint finds them WITHOUT any OIDC discovery round-trip. Before
// the fix, staticEndpoints omitted them, so introspectToken / registerClient
// / deviceAuthorization all landed on their no-endpoint refusals — an
// operator setting opts.introspectionEndpoint (exactly what introspectToken's
// own refusal message tells them to do) still could not use the endpoint.
async function scenarioStaticExtraEndpoints(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var oa = X.create({
    clientId:                    "cov2-static-extra",
    clientSecret:                "sec",
    redirectUri:                 "https://rp.example/cb",
    isOidc:                      false,
    allowHttp:                   true,
    allowInternal:               true,
    introspectionEndpoint:       base + "/introspect",
    registrationEndpoint:        base + "/register",
    deviceAuthorizationEndpoint: base + "/device",
  });

  routes["/introspect"] = { json: { active: true, scope: "openid" } };
  var verdict = await aresolves("introspectToken: resolves via static opts.introspectionEndpoint (no discovery)",
    function () { return oa.introspectToken("tok"); });
  check("introspectToken(static): active surfaced", verdict && verdict.active === true);

  routes["/register"] = { json: { client_id: "reg-static", client_secret: "s" } };
  var reg = await aresolves("registerClient: resolves via static opts.registrationEndpoint (no discovery)",
    function () { return oa.registerClient({ redirect_uris: ["https://rp.example/cb"] }); });
  check("registerClient(static): client_id surfaced", reg && reg.client_id === "reg-static");

  routes["/device"] = { json: { device_code: "dc-s", user_code: "UC-s", verification_uri: "https://verify.example" } };
  var dev = await aresolves("deviceAuthorization: resolves via static opts.deviceAuthorizationEndpoint (no discovery)",
    function () { return oa.deviceAuthorization({ scope: ["openid"] }); });
  check("deviceAuthorization(static): device_code surfaced", dev && dev.device_code === "dc-s");
}

async function scenarioBackchannelLogout(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var CID   = "cov2-bcl";
  var oa    = mk(base, CID);
  var EVENT = "http://schemas.openid.net/event/backchannel-logout";

  function logoutTok(claims, hdr) {
    var now = Math.floor(Date.now() / 1000);
    var payload = { iss: "https://idp.example", aud: CID, iat: now, jti: "jti-" + crypto.randomBytes(4).toString("hex"),
                    events: {}, sub: "u1" };
    payload.events[EVENT] = {};
    if (claims) { var ck = Object.keys(claims); for (var i = 0; i < ck.length; i++) payload[ck[i]] = claims[ck[i]]; }
    var header = { alg: "ES256", typ: "logout+jwt", kid: KID };
    if (hdr) { var hk = Object.keys(hdr); for (var j = 0; j < hk.length; j++) header[hk[j]] = hdr[hk[j]]; }
    return signToken(header, payload);
  }

  // Valid logout token, no replay store.
  var res = await aresolves("verifyBackchannelLogoutToken: valid token resolves",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok()); });
  check("verifyBackchannelLogoutToken: surfaces sub + events", res && res.sub === "u1" && res.events);

  await athrows("verifyBackchannelLogoutToken: non-string refused",
    function () { return oa.verifyBackchannelLogoutToken(123); }, "auth-oauth/bad-logout-token");
  await athrows("verifyBackchannelLogoutToken: non-3-segment refused",
    function () { return oa.verifyBackchannelLogoutToken("a.b"); }, "auth-oauth/malformed-logout-token");
  await athrows("verifyBackchannelLogoutToken: wrong typ refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({}, { typ: "JWT" })); }, "auth-oauth/wrong-typ");
  await athrows("verifyBackchannelLogoutToken: forbidden nonce refused (§2.6)",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ nonce: "x" })); }, "auth-oauth/forbidden-nonce");
  await athrows("verifyBackchannelLogoutToken: missing sub AND sid refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ sub: undefined, sid: undefined })); },
    "auth-oauth/no-sub-or-sid");
  // Token-type confusion: a JWS that carries typ="logout+jwt" but NO
  // back-channel-logout event is not a logout token. It must fail closed —
  // verifyIdToken's skipExpCheck self-guard (which the wrapper relies on to
  // waive the exp claim) refuses any token lacking the logout event, so a
  // non-logout token cannot borrow the exp-waiver to slip an id_token in
  // through the logout endpoint.
  await athrows("verifyBackchannelLogoutToken: logout+jwt typ without the logout event refused (fail-closed)",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ events: undefined })); },
    "auth-oauth/skip-exp-check-not-allowed");

  // stale logout iat (verifyIdToken freshness floor) — no exp on logout tokens.
  var nowS = Math.floor(Date.now() / 1000);
  await athrows("verifyBackchannelLogoutToken: stale iat refused (freshness floor)",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ iat: nowS - 100000 })); },
    "auth-oauth/logout-token-stale");
  // widened maxAgeSec accepts an older-but-in-window token.
  await aresolves("verifyBackchannelLogoutToken: widened maxAgeSec accepts older token",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ iat: nowS - 400 }), { maxAgeSec: 100000 }); });

  // atomic replay store branches.
  await aresolves("verifyBackchannelLogoutToken: atomic first-sighting accepted",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(),
      { atomicReplayStore: { checkAndInsert: function () { return true; } } }); });
  await athrows("verifyBackchannelLogoutToken: atomic replay (falsy) refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(),
      { atomicReplayStore: { checkAndInsert: function () { return 0; } } }); },
    "auth-oauth/logout-token-replay");
  await athrows("verifyBackchannelLogoutToken: atomic store throwing surfaces typed error",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(),
      { atomicReplayStore: { checkAndInsert: function () { throw new Error("down"); } } }); },
    "auth-oauth/replay-store-failed");
  await athrows("verifyBackchannelLogoutToken: atomic store but missing jti refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ jti: undefined }),
      { atomicReplayStore: { checkAndInsert: function () { return true; } } }); },
    "auth-oauth/no-jti");

  // legacy seen() branches.
  await aresolves("verifyBackchannelLogoutToken: seen() first-sighting accepted",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(), { seen: function () { return true; } }); });
  await athrows("verifyBackchannelLogoutToken: seen() replay (falsy) refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(), { seen: function () { return 0; } }); },
    "auth-oauth/logout-token-replay");
  await athrows("verifyBackchannelLogoutToken: seen() throwing surfaces typed error",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok(), { seen: function () { throw new Error("down"); } }); },
    "auth-oauth/seen-callback-failed");
  await athrows("verifyBackchannelLogoutToken: seen() but missing jti refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ jti: undefined }), { seen: function () { return true; } }); },
    "auth-oauth/no-jti");

  // ---- pre-verify shape gates (fire before the JWS signature check) ----
  await athrows("verifyBackchannelLogoutToken: oversized token refused (length cap before decode)",
    function () { return oa.verifyBackchannelLogoutToken("a".repeat(300000)); },
    "auth-oauth/logout-token-too-large");
  var badHeaderTok = Buffer.from("not-json", "utf8").toString("base64url") + "." + _b64urlJson({}) + ".sig";
  await athrows("verifyBackchannelLogoutToken: undecodable header refused",
    function () { return oa.verifyBackchannelLogoutToken(badHeaderTok); }, "auth-oauth/bad-logout-header");

  // ---- wrapper freshness floor STRICTER than verifyIdToken's (skew grace) ----
  // iat that clears verifyIdToken's iat + maxAge + skew floor but fails the
  // wrapper's own iat + maxAge (no skew) bound — the belt-and-suspenders check.
  var nowBcl = Math.floor(Date.now() / 1000);
  await athrows("verifyBackchannelLogoutToken: iat past the wrapper's own maxAge floor refused",
    function () { return oa.verifyBackchannelLogoutToken(logoutTok({ iat: nowBcl - 130 }), { maxAgeSec: 100 }); },
    "auth-oauth/logout-token-too-old");
}

async function scenarioJarm(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var CID = "cov2-jarm";
  var oa  = mk(base, CID);

  function jarmTok(claims) {
    var now = Math.floor(Date.now() / 1000);
    var payload = { iss: "https://idp.example", aud: CID, iat: now, exp: now + 300 };
    if (claims) { var ck = Object.keys(claims); for (var i = 0; i < ck.length; i++) payload[ck[i]] = claims[ck[i]]; }
    return signToken({ alg: "ES256", typ: "JWT", kid: KID }, payload);
  }

  var res = await aresolves("parseJarmResponse: valid signed response returns params",
    function () { return oa.parseJarmResponse(jarmTok({ code: "cc", state: "ss", iss: "https://idp.example" }),
      { expectedState: "ss" }); });
  check("parseJarmResponse: code/state surfaced", res && res.code === "cc" && res.state === "ss");

  await athrows("parseJarmResponse: forbidden nonce claim refused (JARM §4)",
    function () { return oa.parseJarmResponse(jarmTok({ code: "cc", nonce: "n" })); },
    "auth-oauth/jarm-forbidden-nonce");
}

async function scenarioDiscovery(base, routes) {
  // Each discovery client uses its own issuer path → isolated .well-known route.
  function wk(seg, doc) { routes["/" + seg + "/.well-known/openid-configuration"] = doc; }
  function disClient(seg, clientId, extra) {
    var opts = { issuer: base + "/" + seg, clientId: clientId, clientSecret: "sec",
      redirectUri: "https://rp.example/cb", isOidc: true, allowHttp: true, allowInternal: true };
    if (extra) { var k = Object.keys(extra); for (var i = 0; i < k.length; i++) opts[k[i]] = extra[k[i]]; }
    return X.create(opts);
  }

  // issuer mismatch between config + discovery doc.
  wk("dmis", { json: { issuer: "https://evil.example", authorization_endpoint: base + "/auth",
    token_endpoint: base + "/token", jwks_uri: base + "/jwks" } });
  var oaMis = disClient("dmis", "cov2-dmis");
  await athrows("discovery: doc issuer != configured issuer refused",
    function () { return oaMis.authorizationUrl(); }, "auth-oauth/issuer-mismatch");

  // discovery doc is not an object.
  wk("dbad", { text: "123" });
  var oaBadDisc = disClient("dbad", "cov2-dbad");
  await athrows("discovery: non-object document refused",
    function () { return oaBadDisc.authorizationUrl(); }, "auth-oauth/bad-discovery");

  // discovery doc valid but missing the requested endpoint.
  wk("dnoep", { json: { issuer: base + "/dnoep", authorization_endpoint: base + "/auth",
    token_endpoint: base + "/token", jwks_uri: base + "/jwks" } });
  var oaNoEp = disClient("dnoep", "cov2-dnoep");
  await athrows("discovery: endpoint absent from document refused",
    function () { return oaNoEp.revokeToken("t"); }, "auth-oauth/no-endpoint");
  var cfg = await aresolves("discover(): returns the resolved configuration",
    function () { return oaNoEp.discover(); });
  check("discover(): config issuer surfaced", cfg && cfg.issuer === base + "/dnoep");

  // parseCallback requireIss driven by discovery metadata.
  wk("dmeta", { json: { issuer: base + "/dmeta", authorization_endpoint: base + "/auth",
    token_endpoint: base + "/token", jwks_uri: base + "/jwks",
    authorization_response_iss_parameter_supported: true } });
  var oaMeta = disClient("dmeta", "cov2-dmeta");
  await athrows("parseCallback: OP advertises iss-param support, missing iss refused",
    function () { return oaMeta.parseCallback({ code: "c" }); }, "auth-oauth/missing-iss-callback");

  // parseCallback tolerates discovery failure (catch branch) — code still parses.
  wk("dcatch", { status: 500, text: "err" });
  var oaCatch = disClient("dcatch", "cov2-dcatch");
  var rv = await aresolves("parseCallback: discovery failure is swallowed, code returned",
    function () { return oaCatch.parseCallback({ code: "ccc" }); });
  check("parseCallback: code surfaced despite discovery failure", rv && rv.code === "ccc");

  // No discovery available + no static endpoint → not-configured refusal.
  var oaNone = X.create({ clientId: "cov2-none", redirectUri: "https://rp.example/cb", isOidc: false });
  await athrows("resolveEndpoint: no static endpoint + no discovery refused",
    function () { return oaNone.exchangeCode({ code: "c", verifier: "v" }); }, "auth-oauth/no-endpoint");

  // OP discovery advertises code_challenge_methods_supported WITHOUT S256 →
  // refuse the authorization request (RFC 9700 §4.13 — stripped-S256 / PKCE
  // downgrade signature).
  wk("ddown", { json: { issuer: base + "/ddown", authorization_endpoint: base + "/auth",
    token_endpoint: base + "/token", jwks_uri: base + "/jwks",
    code_challenge_methods_supported: ["plain"] } });
  var oaDown = disClient("ddown", "cov2-ddown");
  await athrows("authorizationUrl: OP advertising plain-only PKCE methods refused (downgrade defense)",
    function () { return oaDown.authorizationUrl(); }, "auth-oauth/pkce-downgrade");
}

async function scenarioBuildersAndUrls(base, routes) {
  // checkSessionIframeUrl full + refusal.
  var oa = mk(base, "cov2-misc");
  var csi = await aresolves("checkSessionIframeUrl: returns configured iframe URL",
    function () { return oa.checkSessionIframeUrl(); });
  check("checkSessionIframeUrl: URL surfaced", csi === base + "/checksession");

  var oaBare = mkBare("cov2-misc-bare");
  await athrows("checkSessionIframeUrl: no iframe endpoint refused",
    function () { return oaBare.checkSessionIframeUrl(); }, "auth-oauth/no-check-session-iframe");
  await athrows("endSessionUrl: no end_session endpoint refused",
    function () { return oaBare.endSessionUrl({}); }, "auth-oauth/no-end-session-endpoint");
  await athrows("pushAuthorizationRequest: no PAR endpoint refused",
    function () { return oaBare.pushAuthorizationRequest({}); }, "auth-oauth/no-par-endpoint");

  // PAR bad response (no request_uri).
  routes["/par"] = { status: 201, json: { note: "no request_uri" } };
  var oaPar = mk(base, "cov2-par", { pushedAuthorizationRequestEndpoint: base + "/par" });
  await athrows("pushAuthorizationRequest: response without request_uri refused",
    function () { return oaPar.pushAuthorizationRequest({}); }, "auth-oauth/par-bad-response");

  // clientAttestationHeaders without an issuer + no audience → refusal.
  var attKp  = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var oaNoIss = mkBare("cov2-att-noaud");
  throws("clientAttestationHeaders: missing audience + no issuer refused",
    function () { return oaNoIss.clientAttestationHeaders({ attesterPrivateKey: attKp.privateKey,
      instanceKeyJwk: instKp.publicKey.export({ format: "jwk" }), instancePrivateKey: instKp.privateKey }); },
    "auth-oauth/attestation-no-aud");

  // create(): a couple of remaining construction branches.
  var apple = X.create({ provider: "apple", clientId: "a", redirectUri: "https://x/cb" });
  check("create: apple preset threads responseMode + OIDC", apple.isOidc === true);
  var ms = X.create({ provider: "microsoft", clientId: "a", redirectUri: "https://x/cb" });
  check("create: microsoft preset is OIDC", ms.isOidc === true);
  var tuned = X.create({ clientId: "a", redirectUri: "https://x/cb", isOidc: true,
    acceptedAlgorithms: ["ES256"], discoveryCacheMs: 1000, jwksCacheMs: 1000, allowInternal: false });
  check("create: custom accepted-algorithms + cache TTLs accepted", !!tuned);

  // _validateUrl: a syntactically-invalid (non-protocol) URL → bad-url.
  throws("create: syntactically invalid redirectUri refused",
    function () { return X.create({ clientId: "a", redirectUri: "https://" }); }, "auth-oauth/bad-url");
}

// Sign an ES256 compact JWS with an arbitrary EC P-256 private key — used to
// craft adversarial attestation / PoP tokens the public builders refuse to
// emit (missing sub / cnf, forbidden claim shapes, expired PoP). ieee-p1363
// matches the attestation verifier's ES256 params so the crafted signature
// VERIFIES and the code reaches the semantic claim checks under test.
function _signEs256(privateKey, header, payload) {
  var input = _b64urlJson(header) + "." + _b64urlJson(payload);
  var sig = crypto.sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + sig.toString("base64url");
}

// Flip one signature byte on a compact JWS (keeps length so verify RETURNS
// false rather than throwing).
function _tamperJws(jws) {
  var p = jws.split(".");
  var s = Buffer.from(p[2], "base64url");
  s[0] = s[0] ^ 0xff;
  return p[0] + "." + p[1] + "." + s.toString("base64url");
}

// b.auth.oauth.buildClientAttestation / buildClientAttestationPop /
// verifyClientAttestation / clientAttestationHeaders — the attestation-based
// client-authentication surface (draft-ietf-oauth-attestation-based-client-
// auth-08). Pure crypto, no network: covers the key/alg resolution error
// wrappers, the _verifyAttestationJws adversarial-shape refusals, every
// verifier semantic gate (sub / cnf / nbf / client_id / PoP aud+jti+iat+exp /
// challenge / jti-replay), the async seenJti store, and the full valid
// round-trip return.
async function scenarioAttestationVerify() {
  var attKp  = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var attPub  = attKp.publicKey.export({ format: "jwk" });
  var instPub = instKp.publicKey.export({ format: "jwk" });
  var AUD = "https://as.example";
  var now = Math.floor(Date.now() / 1000);

  // ---- buildClientAttestation: key + alg resolution error wrappers ----
  rejects("buildClientAttestation: unusable attester key string refused (bad-key wrapper)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: "not-a-pem-key",
            instanceKeyJwk: instPub }); }, "auth-oauth/attestation-bad-key");
  rejects("buildClientAttestation: empty attester key string refused (no-key wrapper)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: "",
            instanceKeyJwk: instPub }); }, "auth-oauth/attestation-no-key");
  rejects("buildClientAttestation: symmetric algorithm refused (attestation alg allowlist)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: instPub, algorithm: "HS256" }); }, "auth-oauth/attestation-alg-not-accepted");
  rejects("buildClientAttestation: RS256 alg on an EC attester key refused (alg/key mismatch)",
          function () { X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey,
            instanceKeyJwk: instPub, algorithm: "RS256" }); }, "auth-oauth/attestation-alg-key-mismatch");
  rejects("buildClientAttestation: key-agreement (X25519) attester key refused (cannot sign)",
          function () { X.buildClientAttestation({ clientId: "w",
            attesterPrivateKey: crypto.generateKeyPairSync("x25519").privateKey,
            instanceKeyJwk: instPub }); }, "auth-oauth/attestation-key-unsupported");

  // ---- _verifyAttestationJws: adversarial attestation shapes ----
  // (verifyClientAttestation runs the attestation JWS through it first; the
  // pop arg is irrelevant because each refusal fires before the pop verify.)
  var vopts = { attesterJwk: attPub, expectedAudience: AUD };
  var dummyPop = "x.y.z";
  await arejects("verifyClientAttestation: non-string attestation refused",
                 function () { return X.verifyClientAttestation(123, dummyPop, vopts); }, "auth-oauth/attestation-malformed");
  await arejects("verifyClientAttestation: empty attestation refused",
                 function () { return X.verifyClientAttestation("", dummyPop, vopts); }, "auth-oauth/attestation-malformed");
  await arejects("verifyClientAttestation: oversized attestation refused (header cap)",
                 function () { return X.verifyClientAttestation("a".repeat(17000), dummyPop, vopts); }, "auth-oauth/attestation-too-large");
  await arejects("verifyClientAttestation: 5-segment JWE attestation refused",
                 function () { return X.verifyClientAttestation("a.b.c.d.e", dummyPop, vopts); }, "auth-oauth/attestation-jwe-refused");
  await arejects("verifyClientAttestation: non-3-segment attestation refused",
                 function () { return X.verifyClientAttestation("a.b", dummyPop, vopts); }, "auth-oauth/attestation-malformed");
  await arejects("verifyClientAttestation: undecodable attestation header refused",
                 function () { return X.verifyClientAttestation("!!!." + _b64urlJson({}) + ".sig", dummyPop, vopts); }, "auth-oauth/attestation-malformed");
  await arejects("verifyClientAttestation: attestation header missing alg refused",
                 function () { return X.verifyClientAttestation(_b64urlJson({ typ: "x" }) + "." + _b64urlJson({}) + ".sig", dummyPop, vopts); },
                 "auth-oauth/attestation-malformed");
  await arejects("verifyClientAttestation: attestation alg not in allowlist refused",
                 function () { return X.verifyClientAttestation(_b64urlJson({ alg: "HS256" }) + "." + _b64urlJson({}) + ".sig", dummyPop, vopts); },
                 "auth-oauth/attestation-alg-not-accepted");
  await arejects("verifyClientAttestation: attestation crit header refused (RFC 7515 §4.1.11)",
                 function () { return X.verifyClientAttestation(_b64urlJson({ alg: "ES256", crit: ["x"] }) + "." + _b64urlJson({}) + ".sig", dummyPop, vopts); },
                 "auth-oauth/attestation-crit-not-supported");
  var goodShapeAtt = _signEs256(attKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation+jwt" },
    { sub: "w", cnf: { jwk: instPub }, iat: now, exp: now + 300 });
  await arejects("verifyClientAttestation: tampered attestation signature refused (verify → false)",
                 function () { return X.verifyClientAttestation(_tamperJws(goodShapeAtt), dummyPop, vopts); },
                 "auth-oauth/attestation-bad-signature");

  // ---- verifyClientAttestation: semantic claim gates ----
  var att = X.buildClientAttestation({ clientId: "wallet", attesterPrivateKey: attKp.privateKey, instanceKeyJwk: instPub });
  var pop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: AUD });

  // Explicit typing (RFC 8725 §3.11 / draft §6): a JWT with the right claims +
  // a valid signature by the right key but the WRONG `typ` (a bare "JWT" that a
  // co-signing key — e.g. a private_key_jwt client assertion — could also mint)
  // MUST be refused, not repurposed into the attestation / PoP slot. Both roles
  // are checked; the attestation carries its full valid claim set so only the
  // typ mismatch can fire, and the PoP is verified after a well-typed
  // attestation so the PoP typ gate is what refuses.
  var wrongTypAtt = _signEs256(attKp.privateKey, { alg: "ES256", typ: "JWT" },
    { sub: "wallet", cnf: { jwk: instPub }, iat: now, exp: now + 300 });
  await arejects("verifyClientAttestation: attestation with wrong typ refused (RFC 8725 §3.11 explicit typing)",
                 function () { return X.verifyClientAttestation(wrongTypAtt, pop, vopts); },
                 "auth-oauth/attestation-wrong-typ");
  var wrongTypPop = _signEs256(instKp.privateKey, { alg: "ES256", typ: "JWT" },
    { aud: AUD, jti: "typ-pop-1", iat: now });
  await arejects("verifyClientAttestation: PoP with wrong typ refused (RFC 8725 §3.11 explicit typing)",
                 function () { return X.verifyClientAttestation(att, wrongTypPop, vopts); },
                 "auth-oauth/attestation-wrong-typ");

  // These hand-crafted attestations carry the correct `typ` so each reaches the
  // SEMANTIC gate under test — the explicit-typing gate (exercised separately
  // below) would otherwise fire first.
  var noSubAtt = _signEs256(attKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation+jwt" }, { cnf: { jwk: instPub }, iat: now, exp: now + 300 });
  await arejects("verifyClientAttestation: attestation missing sub refused",
                 function () { return X.verifyClientAttestation(noSubAtt, pop, vopts); }, "auth-oauth/attestation-no-sub");
  var noCnfAtt = _signEs256(attKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation+jwt" }, { sub: "w", iat: now, exp: now + 300 });
  await arejects("verifyClientAttestation: attestation missing cnf.jwk refused (RFC 7800)",
                 function () { return X.verifyClientAttestation(noCnfAtt, pop, vopts); }, "auth-oauth/attestation-no-cnf");
  var nbfAtt = _signEs256(attKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation+jwt" }, { sub: "w", cnf: { jwk: instPub }, iat: now, exp: now + 300, nbf: now + 100000 });
  await arejects("verifyClientAttestation: attestation nbf in the future refused",
                 function () { return X.verifyClientAttestation(nbfAtt, pop, vopts); }, "auth-oauth/attestation-not-yet-valid");
  await arejects("verifyClientAttestation: expectedClientId != attestation sub refused (draft §8 step 10)",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub, expectedAudience: AUD, expectedClientId: "someone-else" }); },
                 "auth-oauth/attestation-client-id-mismatch");

  var popWrongAud = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: "https://other.example" });
  await arejects("verifyClientAttestation: PoP aud != expectedAudience refused (draft §8 step 7)",
                 function () { return X.verifyClientAttestation(att, popWrongAud, vopts); }, "auth-oauth/attestation-pop-aud-mismatch");
  var popNoJti = _signEs256(instKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" }, { aud: AUD, iat: now });
  await arejects("verifyClientAttestation: PoP missing jti refused",
                 function () { return X.verifyClientAttestation(att, popNoJti, vopts); }, "auth-oauth/attestation-pop-no-jti");
  var popNoIat = _signEs256(instKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" }, { aud: AUD, jti: "j1" });
  await arejects("verifyClientAttestation: PoP missing iat refused",
                 function () { return X.verifyClientAttestation(att, popNoIat, vopts); }, "auth-oauth/attestation-pop-no-iat");
  var popExpired = _signEs256(instKp.privateKey, { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" }, { aud: AUD, jti: "j2", iat: now, exp: now - 1000 });
  await arejects("verifyClientAttestation: PoP with exp in the past refused",
                 function () { return X.verifyClientAttestation(att, popExpired, vopts); }, "auth-oauth/attestation-pop-expired");
  await arejects("verifyClientAttestation: server challenge unmatched by PoP refused (draft §8 step 5/6)",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub, expectedAudience: AUD, challenge: "srv-nonce" }); },
                 "auth-oauth/attestation-pop-challenge-mismatch");
  await arejects("verifyClientAttestation: seenJti reporting replay (falsy) refused (draft §12.1)",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub, expectedAudience: AUD, seenJti: function () { return 0; } }); },
                 "auth-oauth/attestation-pop-replay");
  await arejects("verifyClientAttestation: async seenJti resolving replay refused",
                 function () { return X.verifyClientAttestation(att, pop, { attesterJwk: attPub, expectedAudience: AUD, seenJti: function () { return Promise.resolve(0); } }); },
                 "auth-oauth/attestation-pop-replay");

  // ---- full valid round-trip (the success return) ----
  var challPop = X.buildClientAttestationPop({ instancePrivateKey: instKp.privateKey, audience: AUD, challenge: "srv-nonce" });
  var okv = await aresolves("verifyClientAttestation: valid attestation + PoP verifies (numeric skew/maxAge, async seenJti)",
    function () { return X.verifyClientAttestation(att, challPop, { attesterJwk: attPub, expectedAudience: AUD,
      expectedClientId: "wallet", challenge: "srv-nonce", maxPopAgeSec: 600, clockSkewSec: 30,
      seenJti: function () { return Promise.resolve(true); } }); });
  check("verifyClientAttestation: surfaces clientId + cnfJwk + attestation + pop",
        okv && okv.clientId === "wallet" && okv.cnfJwk && okv.cnfJwk.kty === "EC" && okv.attestation && okv.pop);

  // ---- clientAttestationHeaders: builds BOTH headers, verifies end-to-end ----
  var hdrClient = X.create({ clientId: "wallet", redirectUri: "https://rp.example/cb", isOidc: false });
  var pair = hdrClient.clientAttestationHeaders({ attesterPrivateKey: attKp.privateKey,
    instanceKeyJwk: instPub, instancePrivateKey: instKp.privateKey, audience: AUD,
    challenge: "hdr-challenge", expiresInSec: 120, popExpiresInSec: 90 });
  check("clientAttestationHeaders: emits both attestation + PoP header JWTs",
        pair && pair.headers["OAuth-Client-Attestation"] === pair.attestation &&
        pair.headers["OAuth-Client-Attestation-PoP"] === pair.pop);
  var hv = await aresolves("clientAttestationHeaders: emitted pair verifies against attester + cnf keys",
    function () { return X.verifyClientAttestation(pair.attestation, pair.pop, { attesterJwk: attPub,
      expectedAudience: AUD, expectedClientId: "wallet", challenge: "hdr-challenge" }); });
  check("clientAttestationHeaders: round-trip surfaces verified clientId", hv && hv.clientId === "wallet");

  // ---- _publicCnfJwk: every asymmetric instance-key type (EC above; RSA/OKP) ----
  // The cnf claim MUST carry public halves only — a private component never
  // reaches it.
  var rsaPub = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
  var attRsa = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey, instanceKeyJwk: rsaPub });
  var cnfRsa = JSON.parse(Buffer.from(attRsa.split(".")[1], "base64url").toString("utf8")).cnf.jwk;
  check("buildClientAttestation: RSA instance key shaped into cnf (n/e only, no private half)",
        cnfRsa.kty === "RSA" && cnfRsa.n && cnfRsa.e && cnfRsa.d === undefined);
  var okpPub = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  var attOkp = X.buildClientAttestation({ clientId: "w", attesterPrivateKey: attKp.privateKey, instanceKeyJwk: okpPub });
  var cnfOkp = JSON.parse(Buffer.from(attOkp.split(".")[1], "base64url").toString("utf8")).cnf.jwk;
  check("buildClientAttestation: OKP instance key shaped into cnf (x only, no private half)",
        cnfOkp.kty === "OKP" && cnfOkp.x && cnfOkp.d === undefined);

  // ---- EdDSA end-to-end (ATTESTATION_ALGS advertises EdDSA; the EC/RSA
  // paths above never exercise the alg=EdDSA verify branch: hash:null crypto
  // params + the OKP arm of the alg/kty cross-check + node's Ed25519 verify).
  // Both the Attester and the instance key are Ed25519, so the attestation
  // JWS AND the PoP JWS travel the EdDSA verify path.
  var edAttKp  = crypto.generateKeyPairSync("ed25519");
  var edInstKp = crypto.generateKeyPairSync("ed25519");
  var edAttPub  = edAttKp.publicKey.export({ format: "jwk" });
  var edInstPub = edInstKp.publicKey.export({ format: "jwk" });
  var edAtt = X.buildClientAttestation({ clientId: "ed-wallet",
    attesterPrivateKey: edAttKp.privateKey, instanceKeyJwk: edInstPub });
  check("buildClientAttestation: Ed25519 attester key infers an EdDSA-header JWS",
        JSON.parse(Buffer.from(edAtt.split(".")[0], "base64url").toString("utf8")).alg === "EdDSA");
  var edPop = X.buildClientAttestationPop({ instancePrivateKey: edInstKp.privateKey, audience: AUD });
  var edV = await aresolves("verifyClientAttestation: EdDSA attestation + PoP round-trip verifies",
    function () { return X.verifyClientAttestation(edAtt, edPop, { attesterJwk: edAttPub,
      expectedAudience: AUD, expectedClientId: "ed-wallet" }); });
  check("verifyClientAttestation: EdDSA round-trip surfaces clientId + OKP cnf",
        edV && edV.clientId === "ed-wallet" && edV.cnfJwk && edV.cnfJwk.kty === "OKP");
  // A tampered EdDSA PoP signature (one flipped byte, length preserved) must
  // RETURN false from node's verify → typed bad-signature, never a silent pass.
  await arejects("verifyClientAttestation: tampered EdDSA PoP signature refused (verify -> false)",
                 function () { return X.verifyClientAttestation(edAtt, _tamperJws(edPop),
                   { attesterJwk: edAttPub, expectedAudience: AUD }); },
                 "auth-oauth/attestation-bad-signature");
  // alg/kty cross-check on the EdDSA arm: an EdDSA header verified against a
  // NON-OKP (EC) attester JWK is refused before any signature math.
  await arejects("verifyClientAttestation: EdDSA header against an EC attester JWK refused (alg/kty)",
                 function () { return X.verifyClientAttestation(edAtt, edPop,
                   { attesterJwk: instPub, expectedAudience: AUD }); },
                 "auth-jwt-external/alg-kty-mismatch");
}

// Network-free branches on clients that reach neither discovery nor a token
// endpoint: authorizationUrl extraParams (reserved-key guard + pass-through),
// parseCallback iss/state mismatch (requireIssParam skips discovery), and
// parseFrontchannelLogoutRequest's malformed-URL refusal.
async function scenarioOfflineExtras() {
  var ghx = X.create({ provider: "github", clientId: "gh-x", redirectUri: "https://rp.example/cb" });
  var extra = await ghx.authorizationUrl({ extraParams: { audience: "https://api.example", resource: "https://rs.example" } });
  var eu = new URL(extra.url);
  check("authorizationUrl: non-reserved extraParams appended verbatim",
        eu.searchParams.get("audience") === "https://api.example" && eu.searchParams.get("resource") === "https://rs.example");
  await arejects("authorizationUrl: extraParams colliding with a reserved key refused",
                 function () { return ghx.authorizationUrl({ extraParams: { state: "smuggled" } }); },
                 "auth-oauth/reserved-extra-param");

  var sc = _staticOidcClient();  // issuer https://idp.example
  await arejects("parseCallback: callback iss != configured issuer refused (RFC 9207 mix-up)",
                 function () { return sc.parseCallback({ code: "c", iss: "https://evil.example" }, { requireIssParam: true }); },
                 "auth-oauth/iss-mismatch-callback");
  await arejects("parseCallback: state mismatch refused (CSRF defense)",
                 function () { return sc.parseCallback({ code: "c", state: "wrong", iss: "https://idp.example" },
                   { requireIssParam: true, expectedState: "right" }); }, "auth-oauth/state-mismatch");

  rejects("parseFrontchannelLogoutRequest: malformed request URL refused",
          function () { sc.parseFrontchannelLogoutRequest({ url: "http://a b" }); },
          "auth-oauth/bad-frontchannel-logout-url");
}

// PAR (RFC 9126). Plain form path (authorization_details as a JSON-string
// form param + extraParams) and the RFC 9101 signed-request-object (JAR) path
// where the same parameters travel as request-object claims and the form body
// carries only `request` + client auth.
async function scenarioParFlows(base, routes) {
  routes["/jwks"] = { json: { keys: [PUBJWK] } };
  var jarKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var oa = mk(base, "cov2-par-flow", { pushedAuthorizationRequestEndpoint: base + "/par" });
  routes["/par"] = { status: 201, json: { request_uri: "urn:ietf:params:oauth:request_uri:abc", expires_in: 90 } };

  var par = await aresolves("pushAuthorizationRequest: plain flow returns request_uri + redirect URL",
    function () { return oa.pushAuthorizationRequest({
      authorizationDetails: [{ type: "payment_initiation", actions: ["initiate"] }],
      extraParams: { audience: "https://api.example" },
      prompt: "consent", loginHint: "u@x", maxAge: 120 }); });
  check("pushAuthorizationRequest: request_uri + expiresIn surfaced, plain path",
        par && par.requestUri === "urn:ietf:params:oauth:request_uri:abc" && par.expiresIn === 90 &&
        par.url.indexOf("request_uri=") !== -1 && par.requestObjectSent === false);

  await athrows("pushAuthorizationRequest: extraParams colliding with a reserved key refused",
                function () { return oa.pushAuthorizationRequest({ extraParams: { redirect_uri: "https://evil.example" } }); },
                "auth-oauth/reserved-extra-param");

  var sro = await aresolves("pushAuthorizationRequest: signed-request-object (JAR) flow returns request_uri",
    function () { return oa.pushAuthorizationRequest({
      signedRequestObject: { key: jarKp.privateKey },
      authorizationDetails: [{ type: "payment_initiation", actions: ["initiate"] }] }); });
  check("pushAuthorizationRequest: requestObjectSent flag set on the JAR path",
        sro && sro.requestObjectSent === true && sro.requestUri === "urn:ietf:params:oauth:request_uri:abc");
}

// b.auth.oauth fetches go through the shared b.httpClient keep-alive agent;
// its cached sockets (and the mock server) would otherwise keep the forked
// worker's event loop open. Drain them inside run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "auth-oauth: TCP handle drain after _resetForTest" });
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

  // An explicit create() scope array overrides the preset default and is
  // reflected verbatim (space-joined) in the authorization request.
  var ghScoped = X.create({ provider: "github", clientId: "gh-scope",
    redirectUri: "https://rp.example/cb", scope: ["read:user", "repo", "gist"] });
  check("authorizationUrl: explicit create() scope array reflected space-joined",
        new URL((await ghScoped.authorizationUrl()).url).searchParams.get("scope") === "read:user repo gist" &&
        ghScoped.scope.length === 3);

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
  // The refusal surfaces the OP-supplied error + error_description on the
  // thrown error so operators can branch on `opError` (documented fields).
  var opErr = null;
  try { await oa.parseCallback({ error: "access_denied", error_description: "user declined consent" },
    { requireIssParam: true }); } catch (e) { opErr = e; }
  check("parseCallback: op-error carries opError + opErrorDescription fields",
        opErr && opErr.code === "auth-oauth/op-error" && opErr.opError === "access_denied" &&
        opErr.opErrorDescription === "user declined consent");

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
  // Granted a type that was never requested → over-grant (non-strict surfaces).
  var unreqType = X._crossCheckGrantedAuthorizationDetails(
    [{ type: "never-requested" }], [{ type: "asked" }], false);
  check("crossCheck: unrequested granted type surfaced under non-strict",
        Array.isArray(unreqType) && unreqType.length === 1);
  // A granted subfield delivered as a NON-array scalar the request never
  // constrained is an over-grant (RFC 9396 §7 — AS returned a scalar where a
  // RAR array field is defined and the request omitted it).
  var scalarSub = X._crossCheckGrantedAuthorizationDetails(
    [{ type: "t", locations: "https://rs.example/one" }], [{ type: "t" }], false);
  check("crossCheck: unconstrained non-array granted subfield surfaced under non-strict",
        Array.isArray(scalarSub) && scalarSub.length === 1);
  // A granted scalar EQUAL to the requested scalar is lenient-accepted (a
  // non-conforming-but-equal AS output is not treated as broadening).
  var scalarEq = X._crossCheckGrantedAuthorizationDetails(
    [{ type: "t", actions: "read" }], [{ type: "t", actions: "read" }], true);
  check("crossCheck: matching non-array granted scalar accepted under strict",
        Array.isArray(scalarEq) && scalarEq.length === 1);

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

  // Attestation verifier semantics + full round-trip, and the remaining
  // network-free builder/parser branches.
  await scenarioAttestationVerify();
  await scenarioOfflineExtras();

  console.log("auth-oauth offline checks passed");

  // ---- loopback IdP round-trips (stand-in AS on 127.0.0.1) ----
  var made   = makeServer();
  var server = made.server;
  var routes = made.routes;
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var base = "http://127.0.0.1:" + server.address().port;
  installDiscoveryDoc(base, routes);
  try {
    await scenarioVerifyIdToken(base, routes);
    await scenarioTokenFlows(base, routes);
    await scenarioUserinfoRevokeIntrospect(base, routes);
    await scenarioRegisterDcr(base, routes);
    await scenarioDeviceAndPoll(base, routes);
    await scenarioDeviceGrantDefaultHttp(base, routes);
    await scenarioStaticExtraEndpoints(base, routes);
    await scenarioParFlows(base, routes);
    await scenarioBackchannelLogout(base, routes);
    await scenarioJarm(base, routes);
    await scenarioDiscovery(base, routes);
    await scenarioBuildersAndUrls(base, routes);
  } finally {
    server.close();
    await _drainTcpHandles();
  }
  console.log("auth-oauth loopback checks passed");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
