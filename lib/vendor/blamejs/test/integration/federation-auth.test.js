// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live federated-authentication round-trip against the docker-compose
 * Keycloak fixture. Exercises:
 *
 *   - b.auth.oauth.create + .discover (OIDC well-known fetch from a
 *     real OP)
 *   - b.auth.oauth.authorizationUrl (state + nonce + PKCE)
 *   - b.auth.oauth.exchangeCode flow simulated end-to-end via
 *     resource-owner-password grant (Keycloak's
 *     directAccessGrantsEnabled=true) — gives us an issuer-signed
 *     id_token + access_token without driving a browser
 *   - b.auth.oauth.verifyIdToken against the realm's JWKS
 *   - b.auth.oauth.fetchUserInfo against /userinfo with the access
 *     token
 *   - b.auth.oauth.endSessionUrl build (RP-Initiated Logout)
 *   - b.auth.oauth.parseFrontchannelLogoutRequest with synthetic
 *     iss + sid (Front-Channel Logout 1.0)
 *   - b.auth.oauth.verifyBackchannelLogoutToken using a logout-token
 *     minted from the realm's signing key (Back-Channel Logout 1.0)
 *   - b.auth.saml.sp.create + buildAuthnRequest (HTTP-Redirect form
 *     against the IdP's SAML endpoint)
 *   - b.auth.saml.sp.metadata XML emit
 *   - b.auth.oauth.deviceAuthorization + pollDeviceCode (RFC 8628
 *     device grant — the poll survives the authorization_pending HTTP
 *     400 rather than aborting on the first poll; provisions a
 *     device-grant client via the admin API)
 *   - b.auth.saml.sp.verifyResponse over a Keycloak-ENCRYPTED
 *     assertion (SAML 2.0 §2.5). Keycloak 26.0.8 emits aes128-cbc +
 *     rsa-oaep-mgf1p(SHA-1), which the framework refuses by design, so
 *     the assertion is the fail-closed refusal; the AES-GCM +
 *     RSA-OAEP-SHA256 positive-decrypt branch takes effect on Keycloak
 *     >= 26.2 (see the stage comment).
 *
 * Deferred (open-conditions noted):
 *   - CIBA (Keycloak 26 supports it but requires extra realm-import
 *     keys; re-open when the realm-import learns
 *     `attributes.cibaBackchannelTokenDeliveryMode`).
 *   - OID4VCI / OID4VP (preview-only in Keycloak; re-open when the
 *     `oid4vc-issuer` SPI ships in the base image).
 *   - OpenID Federation 1.0 has no native Keycloak provider; the
 *     trust-chain / metadata-policy path is covered in-process by
 *     test/integration/openid-federation-chain.test.js (three loopback
 *     entity-statement servers) rather than against Keycloak.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b        = require("../../");
var nodeCrypto       = require("node:crypto");
var nodeChildProcess = require("node:child_process");
var nodeFs           = require("node:fs");
var nodeOs           = require("node:os");
var nodePath         = require("node:path");

var KEYCLOAK_BASE  = "http://127.0.0.1:18080";
var REALM          = "blamejs-test";
var ISSUER         = KEYCLOAK_BASE + "/realms/" + REALM;
var CLIENT_ID      = "blamejs-rp-oidc";
var CLIENT_SECRET  = "blamejs-test-rp-secret";
var REDIRECT_URI   = "http://127.0.0.1:18099/callback";
var TEST_USERNAME  = "alice";
var TEST_PASSWORD  = "blamejs-test-password";
var SP_ENTITY_ID   = "https://sp.blamejs-test.example";
var SP_ACS_URL     = "http://127.0.0.1:18099/saml/acs";
var IDP_SSO_URL    = ISSUER + "/protocol/saml";
var IDP_LOGOUT_URL = ISSUER + "/protocol/openid-connect/logout";

function _b64uEncode(buf) {
  if (typeof buf === "string") buf = Buffer.from(buf, "utf8");
  return buf.toString("base64url");
}

// Tiny cookie jar — tracks Set-Cookie headers across redirects so the
// SAML round-trip can carry Keycloak's KC_RESTART / AUTH_SESSION_ID
// cookies through the login form POST.
function _newCookieJar() {
  var byName = Object.create(null);
  return {
    absorb: function (setCookieHeader) {
      if (!setCookieHeader) return;
      var arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
      arr.forEach(function (sc) {
        var firstSemi = String(sc).indexOf(";");
        var pair = firstSemi === -1 ? String(sc) : String(sc).slice(0, firstSemi);
        var eq = pair.indexOf("=");
        if (eq === -1) return;
        var name = pair.slice(0, eq).trim();
        var value = pair.slice(eq + 1).trim();
        if (value === "" || /max-age=0/i.test(sc)) { delete byName[name]; return; }
        byName[name] = value;
      });
    },
    header: function () {
      var keys = Object.keys(byName);
      if (keys.length === 0) return null;
      return keys.map(function (k) { return k + "=" + byName[k]; }).join("; ");
    },
  };
}

async function _httpReq(method, url, jar, opts) {
  opts = opts || {};
  var headers = Object.assign({}, opts.headers || {});
  var cookieHeader = jar && jar.header();
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  var req = {
    method:           method,
    url:              url,
    headers:          headers,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    responseMode:     "always-resolve",
  };
  if (opts.body !== undefined) {
    req.body = opts.body;
    if (typeof opts.body === "string" && !headers["Content-Type"]) {
      req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    }
  }
  if (opts.redirect === false) req.redirect = { manual: true };
  var res = await b.httpClient.request(req);
  if (jar) jar.absorb(res.headers && (res.headers["set-cookie"] || res.headers["Set-Cookie"]));
  return res;
}

// Extract the IdP signing certificate PEM from Keycloak's SAML
// descriptor XML. Keycloak emits a single <ds:X509Certificate> under
// IDPSSODescriptor/KeyDescriptor[use=signing]; we grab it via regex
// (the XML is stable Keycloak output, not operator-supplied).
function _extractIdpSigningCertPem(descriptorXml) {
  var m = /<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/.exec(descriptorXml);
  if (!m) throw new Error("descriptor XML missing X509Certificate");
  var b64 = m[1].replace(/\s+/g, "");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") + "\n-----END CERTIFICATE-----\n";
}

async function _fetchJson(url) {
  var res = await b.httpClient.request({
    method:           "GET",
    url:              url,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new Error("fetch " + url + " → " + res.statusCode + " " + (res.body && res.body.toString().slice(0, 200)));
  }
  return JSON.parse(res.body.toString("utf8"));
}

async function _passwordGrant() {
  // Keycloak Direct Access Grant — bypasses the browser-driven authorization_code
  // flow so the integration test can drive the full token-side pipeline (id_token
  // verify, userinfo fetch, RP-initiated logout) without a headless browser.
  var body = new URLSearchParams();
  body.set("grant_type",    "password");
  body.set("client_id",     CLIENT_ID);
  body.set("client_secret", CLIENT_SECRET);
  body.set("username",      TEST_USERNAME);
  body.set("password",      TEST_PASSWORD);
  body.set("scope",         "openid profile email");
  var res = await b.httpClient.request({
    method:           "POST",
    url:              ISSUER + "/protocol/openid-connect/token",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    headers:          { "Content-Type": "application/x-www-form-urlencoded" },
    body:             body.toString(),
  });
  if (res.statusCode !== 200) {
    throw new Error("password grant failed: " + res.statusCode + " " + (res.body && res.body.toString().slice(0, 300)));
  }
  return JSON.parse(res.body.toString("utf8"));
}

async function _signLogoutToken(signingKid, sub, sid, jti) {
  // Mint a logout_token JWT using the realm's RSA signing key. The realm
  // exposes the private key only via the admin REST API (which requires
  // a master-realm token); we instead build a JWS with a fresh ephemeral
  // key + a kid that intentionally won't match the realm JWKS, then
  // assert that verifyBackchannelLogoutToken refuses with the expected
  // "no matching key" / signature failure code path.
  //
  // For the positive path we exchange a real ID token (from the password
  // grant) and reuse its `sid` claim if present — Keycloak emits a `sid`
  // when "Backchannel Logout Session Required" is true on the client.
  var key = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var header  = { alg: "RS256", typ: "logout+jwt", kid: signingKid };
  var payload = {
    iss:    ISSUER,
    aud:    CLIENT_ID,
    iat:    Math.floor(Date.now() / 1000),
    jti:    jti,
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    sub:    sub || undefined,
    sid:    sid || undefined,
  };
  var signingInput = _b64uEncode(JSON.stringify(header)) + "." + _b64uEncode(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), key.privateKey);
  return signingInput + "." + sig.toString("base64url");
}

// ---- Keycloak Admin REST helpers ----
// The realm is imported once at container start; the device-grant and
// encrypted-SAML stages need two client shapes the base import doesn't carry
// (a device-grant client without a forced PKCE challenge, and a SAML SP with
// assertion encryption on). They're applied idempotently via the admin API so
// the test is robust against both the already-running container and a fresh
// `compose up`; the realm JSON carries the same shapes for a cold start.
var KC_ADMIN_USER    = "admin";
var KC_ADMIN_PASS    = "blamejs-test-admin";
var DEVICE_CLIENT_ID = "blamejs-device-oidc";
var DEVICE_SECRET    = "blamejs-test-device-secret";
var SP_ENC_ENTITY_ID = "https://sp-enc.blamejs-test.example";

async function _adminToken() {
  var body = new URLSearchParams();
  body.set("grant_type", "password");
  body.set("client_id",  "admin-cli");
  body.set("username",   KC_ADMIN_USER);
  body.set("password",   KC_ADMIN_PASS);
  var res = await b.httpClient.request({
    method:           "POST",
    url:              KEYCLOAK_BASE + "/realms/master/protocol/openid-connect/token",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    headers:          { "Content-Type": "application/x-www-form-urlencoded" },
    body:             body.toString(),
  });
  if (res.statusCode !== 200) {
    throw new Error("admin token grant failed: " + res.statusCode + " " + (res.body && res.body.toString().slice(0, 200)));
  }
  return JSON.parse(res.body.toString("utf8")).access_token;
}

async function _kcAdmin(method, subPath, tok, jsonBody) {
  var req = {
    method:           method,
    url:              KEYCLOAK_BASE + "/admin/realms/" + REALM + subPath,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    responseMode:     "always-resolve",
    headers:          { Authorization: "Bearer " + tok },
  };
  if (jsonBody !== undefined) {
    req.headers["Content-Type"] = "application/json";
    req.body = JSON.stringify(jsonBody);
  }
  var res = await b.httpClient.request(req);
  var json = null;
  if (res.body && res.body.length) {
    try { json = JSON.parse(res.body.toString("utf8")); } catch (_e) { json = null; }
  }
  return { statusCode: res.statusCode, json: json };
}

// Create-or-update a confidential OIDC client with the device grant enabled and
// no forced PKCE challenge (b.auth.oauth.deviceAuthorization sends no
// code_challenge, and the base blamejs-rp-oidc client forces S256).
async function _ensureDeviceClient(tok) {
  var rep = {
    clientId:                  DEVICE_CLIENT_ID,
    name:                      "blamejs OIDC device-grant (integration test)",
    enabled:                   true,
    protocol:                  "openid-connect",
    publicClient:              false,
    secret:                    DEVICE_SECRET,
    standardFlowEnabled:       false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled:    false,
    attributes: {
      "oauth2.device.authorization.grant.enabled": "true",
      "pkce.code.challenge.method":                "",
    },
  };
  var listed = await _kcAdmin("GET", "/clients?clientId=" + encodeURIComponent(DEVICE_CLIENT_ID), tok);
  if (Array.isArray(listed.json) && listed.json.length > 0) {
    var existing = listed.json[0];
    var merged = Object.assign({}, existing, rep, {
      id:         existing.id,
      attributes: Object.assign({}, existing.attributes, rep.attributes),
    });
    await _kcAdmin("PUT", "/clients/" + existing.id, tok, merged);
  } else {
    await _kcAdmin("POST", "/clients", tok, rep);
  }
}

// Generate an ephemeral SP RSA keypair + self-signed cert at runtime so no
// private key is committed. Keycloak encrypts the assertion CEK to the cert's
// RSA public key; the SP decrypts with the private key. Uses openssl (dev
// tooling — the integration runner already shells to docker); returns null when
// openssl is unavailable so the stage skips cleanly.
function _generateSpEncryptionKeypair() {
  var dir      = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-saml-sp-enc-"));
  var keyPath  = nodePath.join(dir, "sp-key.pem");
  var certPath = nodePath.join(dir, "sp-cert.pem");
  try {
    var r = nodeChildProcess.spawnSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
      "-days", "3650", "-nodes", "-subj", "/CN=sp-enc.blamejs-test.example", "-sha256",
    ], { stdio: "ignore" });
    if (!r || r.status !== 0 || !nodeFs.existsSync(certPath) || !nodeFs.existsSync(keyPath)) return null;
    var keyPem     = nodeFs.readFileSync(keyPath, "utf8");
    var certPem    = nodeFs.readFileSync(certPath, "utf8");
    var certDerB64 = new nodeCrypto.X509Certificate(certPem).raw.toString("base64");
    return { keyPem: keyPem, certDerB64: certDerB64 };
  } catch (_e) {
    return null;
  } finally {
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e2) {}
  }
}

// Create-or-update a SAML SP client with assertion encryption enabled, keyed to
// the supplied SP certificate. The algorithm attributes request AES-GCM +
// RSA-OAEP-SHA256 (what the framework decrypts); Keycloak < 26.2 ignores them
// and emits its aes128-cbc + rsa-oaep-mgf1p(SHA-1) defaults, which the framework
// refuses by design.
async function _ensureSamlEncClient(tok, certDerB64) {
  var attrs = {
    "saml.assertion.signature":               "true",
    "saml.server.signature":                  "false",
    "saml.signature.algorithm":               "RSA_SHA256",
    "saml.client.signature":                  "false",
    "saml.encrypt":                           "true",
    "saml.encryption.certificate":            certDerB64,
    "saml.encryption.algorithm":              "AES_256_GCM",
    "saml.encryption.keyAlgorithm":           "RSA-OAEP",
    "saml.encryption.digestMethod":           "SHA-256",
    "saml.encryption.maskGenerationFunction": "MGF1-SHA256",
    "saml.force.post.binding":                "true",
    "saml_assertion_consumer_url_post":       SP_ACS_URL,
    "saml_name_id_format":                    "username",
    "saml.authnstatement":                    "true",
  };
  var rep = {
    clientId:            SP_ENC_ENTITY_ID,
    name:                "blamejs SAML SP encrypted (integration test)",
    enabled:             true,
    protocol:            "saml",
    publicClient:        true,
    redirectUris:        [SP_ACS_URL],
    frontchannelLogout:  false,
    attributes:          attrs,
    defaultClientScopes: ["role_list"],
  };
  var listed = await _kcAdmin("GET", "/clients?clientId=" + encodeURIComponent(SP_ENC_ENTITY_ID), tok);
  if (Array.isArray(listed.json) && listed.json.length > 0) {
    var existing = listed.json[0];
    var merged = Object.assign({}, existing, rep, {
      id:         existing.id,
      attributes: Object.assign({}, existing.attributes, attrs),
    });
    await _kcAdmin("PUT", "/clients/" + existing.id, tok, merged);
  } else {
    await _kcAdmin("POST", "/clients", tok, rep);
  }
}

// Drive Keycloak's login form for a SAML AuthnRequest redirect URL and return
// the base64 SAMLResponse from the auto-submit form (or null). Mirrors the
// cookie-jar + form-post steps of the plaintext SAML round-trip so the
// encrypted stage reuses the same login mechanics.
async function _driveSamlLoginCapture(authnRedirectUrl) {
  var jar = _newCookieJar();
  var loginPage = await _httpReq("GET", authnRedirectUrl, jar);
  if (loginPage.statusCode !== 200) return null;
  var actionMatch = /action="(http:\/\/[^"]+\/login-actions\/authenticate[^"]+)"/.exec(loginPage.body.toString("utf8"));
  if (!actionMatch) return null;
  var loginBody = new URLSearchParams();
  loginBody.set("username",     TEST_USERNAME);
  loginBody.set("password",     TEST_PASSWORD);
  loginBody.set("credentialId", "");
  var loginPost = await _httpReq("POST", actionMatch[1].replace(/&amp;/g, "&"), jar, {
    headers:  { "Content-Type": "application/x-www-form-urlencoded" },
    body:     loginBody.toString(),
    redirect: false,
  });
  var responseHtml;
  if (loginPost.statusCode === 200) {
    responseHtml = loginPost.body.toString("utf8");
  } else if (loginPost.statusCode === 302 || loginPost.statusCode === 303) {
    var follow = await _httpReq("GET", loginPost.headers.location || loginPost.headers.Location, jar);
    responseHtml = follow.body.toString("utf8");
  } else {
    return null;
  }
  var m = /name="SAMLResponse"\s+value="([^"]+)"/.exec(responseHtml);
  return m ? m[1] : null;
}

async function run() {
  // ---- service readiness ----
  var keycloak = await services.requireService("keycloak");
  if (!keycloak.ok) throw new Error("keycloak unreachable: " + keycloak.reason);

  // ---- OIDC discovery ----
  var disc = await _fetchJson(ISSUER + "/.well-known/openid-configuration");
  check("discovery: issuer matches",                   disc.issuer === ISSUER);
  check("discovery: authorization_endpoint present",   typeof disc.authorization_endpoint === "string");
  check("discovery: token_endpoint present",           typeof disc.token_endpoint === "string");
  check("discovery: jwks_uri present",                 typeof disc.jwks_uri === "string");
  check("discovery: end_session_endpoint present",     typeof disc.end_session_endpoint === "string");
  check("discovery: frontchannel_logout_supported",    disc.frontchannel_logout_supported === true);
  check("discovery: backchannel_logout_supported",     disc.backchannel_logout_supported === true);

  // ---- b.auth.oauth.create + discover round-trip ----
  var oauth = b.auth.oauth.create({
    issuer:        ISSUER,
    clientId:      CLIENT_ID,
    clientSecret:  CLIENT_SECRET,
    redirectUri:   REDIRECT_URI,
    scope:         ["openid", "profile", "email"],
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });
  var discViaOauth = await oauth.discover();
  check("oauth.discover: issuer matches realm",        discViaOauth.issuer === ISSUER);

  // ---- authorization URL build ----
  var authz = await oauth.authorizationUrl();
  check("oauth.authorizationUrl: returns url + state + nonce + verifier",
    typeof authz.url === "string" && typeof authz.state === "string" &&
    typeof authz.nonce === "string" && typeof authz.verifier === "string");
  check("oauth.authorizationUrl: state non-empty",     authz.state.length >= 16);
  check("oauth.authorizationUrl: includes PKCE",        authz.url.indexOf("code_challenge=") !== -1);
  check("oauth.authorizationUrl: includes scope=openid", /scope=[^&]*openid/.test(authz.url));

  // ---- token retrieval via password grant (skips the browser leg) ----
  var tokens = await _passwordGrant();
  check("password grant: id_token returned",            typeof tokens.id_token === "string" && tokens.id_token.split(".").length === 3);
  check("password grant: access_token returned",        typeof tokens.access_token === "string");

  // ---- ID-token verify against the realm JWKS ----
  var idTokenInfo = await oauth.verifyIdToken(tokens.id_token, {
    skipNonceCheck: true,                                                                     // password grant doesn't carry a nonce
  });
  check("verifyIdToken: claims surfaced",               idTokenInfo && idTokenInfo.claims);
  check("verifyIdToken: iss matches issuer",            idTokenInfo.claims.iss === ISSUER);
  check("verifyIdToken: aud contains clientId",         (Array.isArray(idTokenInfo.claims.aud) ? idTokenInfo.claims.aud : [idTokenInfo.claims.aud]).indexOf(CLIENT_ID) !== -1);
  check("verifyIdToken: preferred_username = alice",    idTokenInfo.claims.preferred_username === TEST_USERNAME);

  // ---- UserInfo ----
  var userinfo = await oauth.fetchUserInfo(tokens.access_token, {
    idTokenSub: idTokenInfo.claims.sub,
  });
  check("fetchUserInfo: email matches alice",           userinfo && userinfo.email === "alice@example.com");

  // ---- RP-Initiated Logout URL ----
  var logoutUrl = await oauth.endSessionUrl({
    idTokenHint:           tokens.id_token,
    postLogoutRedirectUri: "http://127.0.0.1:18099/post-logout",
    state:                 "logout-state-1",
  });
  check("endSessionUrl: routes through end_session_endpoint", logoutUrl.indexOf(IDP_LOGOUT_URL) === 0);
  check("endSessionUrl: includes id_token_hint",         logoutUrl.indexOf("id_token_hint=") !== -1);
  check("endSessionUrl: includes state",                 logoutUrl.indexOf("state=logout-state-1") !== -1);

  // ---- Front-Channel Logout 1.0 — req-parse ----
  var fclReq = { url: "/oidc/frontchannel-logout?iss=" + encodeURIComponent(ISSUER) + "&sid=session-1" };
  var fcl = oauth.parseFrontchannelLogoutRequest(fclReq);
  check("parseFrontchannelLogoutRequest: iss matches",   fcl.iss === ISSUER);
  check("parseFrontchannelLogoutRequest: sid extracted", fcl.sid === "session-1");

  var threw = false;
  try { oauth.parseFrontchannelLogoutRequest({ url: "/x?iss=https://attacker.example" }); }
  catch (e) { threw = /iss.*does not match/.test(e.message); }
  check("parseFrontchannelLogoutRequest: refuses iss mismatch", threw);

  // ---- Back-Channel Logout 1.0 — verifyBackchannelLogoutToken ----
  // Synthetic logout token signed with an ephemeral key whose kid does
  // NOT exist in the realm JWKS. Should fail at the JWKS-lookup stage,
  // proving the verifier doesn't accept a self-signed logout token.
  var tamperedJwt = await _signLogoutToken("attacker-key", "alice-sub", "session-1", "jti-1");
  threw = false;
  try { await oauth.verifyBackchannelLogoutToken(tamperedJwt); }
  catch (e) { threw = /no JWKS key matches|bad-signature|key/i.test(e.message); }
  check("verifyBackchannelLogoutToken: refuses unknown kid", threw);

  // jti-replay defense: even if the operator's seen() callback says
  // "already seen", we should refuse loudly. Use a second ephemeral
  // signature so we drive past the kid check by reusing the realm's
  // first JWKS kid (which still won't match the sig but exercises the
  // events-claim + nonce-forbidden + sub/sid validation path before
  // the jti-replay check fires).
  var jwksOpts = await _fetchJson(disc.jwks_uri);
  var realmKid = jwksOpts.keys && jwksOpts.keys[0] && jwksOpts.keys[0].kid;
  var spoofed = await _signLogoutToken(realmKid || "rk", "alice-sub", "session-2", "jti-2");
  threw = false;
  try {
    await oauth.verifyBackchannelLogoutToken(spoofed, {
      seen: async function () { return true; },
    });
  } catch (e) {
    // Fails on signature (we signed with our own key, not the realm's
    // private key) — that's the expected outcome.
    threw = /bad-signature|signature/i.test(e.message);
  }
  check("verifyBackchannelLogoutToken: refuses spoofed signature even with realm kid", threw);

  // Logout token shape validation: typ must be logout+jwt
  var wrongTypHeader = { alg: "RS256", typ: "JWT", kid: realmKid || "rk" };
  var wrongTypPayload = {
    iss: ISSUER, aud: CLIENT_ID, iat: Math.floor(Date.now() / 1000),
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    sub: "alice-sub",
  };
  var wrongTypInput = _b64uEncode(JSON.stringify(wrongTypHeader)) + "." + _b64uEncode(JSON.stringify(wrongTypPayload));
  // Sign with whatever we have (signature won't verify but typ-check fires first)
  var wrongTypJwt = wrongTypInput + ".X";
  threw = false;
  try { await oauth.verifyBackchannelLogoutToken(wrongTypJwt); }
  catch (e) { threw = /wrong-typ|logout\+jwt/.test(e.message); }
  check("verifyBackchannelLogoutToken: refuses typ != logout+jwt", threw);

  // ---- SAML SP — AuthnRequest build + metadata ----
  // Use the realm's signing cert (looked up via the JWKS — Keycloak's
  // OIDC + SAML share the same signing-key pool by default).
  var spCertPem = "-----BEGIN CERTIFICATE-----\n" +
    "MIIDazCCAlOgAwIBAgIUGY6zT0ZGVTd0BLAMEjsTtRgYBVowDQYJKoZIhvcNAQEL\n" +
    "BQAwRTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5BMQswCQYDVQQHDAJOQTELMAkG\n" +
    "A1UECgwCTkExDzANBgNVBAMMBnRlc3RpbmcwIBcNMjQwMTAxMDAwMDAwWhgPMjEy\n" +
    "NDAxMDEwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOQTELMAkGA1UE\n" +
    "BwwCTkExCzAJBgNVBAoMAk5BMQ8wDQYDVQQDDAZ0ZXN0aW5nMIIBIjANBgkqhkiG\n" +
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vF8VYJ9d6/EXUxQ6TYAQ9kFNqg3sWbT5Qc+\n" +
    "5p3aJtGZhPeZEdxg7nwBxNW4SGtTtfHSlBzCYqQCCPBJYHWA8tJ7MHGvJzKQF5Yh\n" +
    "5lJyG2LyB5dNFaZ7aN5J5xH7Q5yz7QqrYHWKZD8SvrXKqL6r5W5T3FHqJyqL3Q5l\n" +
    "Q5aR5J5qK3Y5vQ5lJ3R5gT5w5P5n5C5y5Q5y3Q5gJ5Q5lQ5Q5R5J5qK3Y5vQ5lJ3\n" +
    "R5gT5w5P5n5C5y5Q5y3Q5gJ5Q5lQ5Q5R5J5qK3Y5vQ5lJ3R5gT5w5P5n5C5y5Q5y\n" +
    "3Q5gJ5Q5lQ5Q5R5J5qK3Y5vQ5lJ3R5gT5w5P5n5C5y5wIDAQABo1MwUTAdBgNVHQ4E\n" +
    "FgQUR2hYzZ8z9QzZ9zZ9zZ9zZ9zZ9zUwHwYDVR0jBBgwFoAUR2hYzZ8z9QzZ9zZ9\n" +
    "zZ9zZ9zZ9zUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAg5Z5\n" +
    "fake-cert-truncated-for-shape-only-not-used-for-actual-verification\n" +
    "-----END CERTIFICATE-----\n";
  var sp = b.auth.saml.sp.create({
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: SP_ACS_URL,
    idpEntityId:                 ISSUER,
    idpSsoUrl:                   IDP_SSO_URL,
    idpCertPem:                  spCertPem,
  });
  var ar = sp.buildAuthnRequest({ relayState: "/dashboard" });
  check("saml.buildAuthnRequest: redirectUrl includes IdP",     ar.redirectUrl.indexOf(IDP_SSO_URL) === 0);
  check("saml.buildAuthnRequest: SAMLRequest param present",    ar.redirectUrl.indexOf("SAMLRequest=") !== -1);
  check("saml.buildAuthnRequest: RelayState param present",     ar.redirectUrl.indexOf("RelayState=") !== -1);
  check("saml.buildAuthnRequest: id starts with underscore",    typeof ar.id === "string" && ar.id.charAt(0) === "_");

  // SP metadata XML — operators serve this verbatim
  var meta = sp.metadata();
  check("saml.metadata: includes EntityDescriptor",             meta.indexOf("md:EntityDescriptor") !== -1);
  check("saml.metadata: includes SP entityID",                  meta.indexOf(SP_ENTITY_ID) !== -1);
  check("saml.metadata: includes ACS Location",                 meta.indexOf(SP_ACS_URL) !== -1);

  // ---- Full SAML round-trip: drive the IdP login form, capture the
  //      signed SAMLResponse, hand it to sp.verifyResponse() ----
  //
  // We don't have a headless browser in the test stack, but Keycloak's
  // login form is plain HTML with a stable action-URL pattern that
  // we can drive with cookies + URL-encoded form POSTs. This closes
  // the IdP→SP signature-verify path that the unit test
  // (federation-vc-suite.test.js) exercises with synthetic XML.

  // Fetch the IdP signing cert from Keycloak's SAML descriptor — this
  // is the trust anchor sp.create needs.
  var descResp = await _httpReq("GET",
    ISSUER + "/protocol/saml/descriptor", null);
  check("SAML descriptor: 200",                                  descResp.statusCode === 200);
  var idpSigningCertPem = _extractIdpSigningCertPem(descResp.body.toString("utf8"));
  check("SAML descriptor: signing cert extracted",               /-----BEGIN CERTIFICATE-----/.test(idpSigningCertPem));

  // Re-create the SP with the real IdP cert so verifyResponse can
  // validate the assertion's XMLDSig signature.
  var spReal = b.auth.saml.sp.create({
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: SP_ACS_URL,
    idpEntityId:                 ISSUER,
    idpSsoUrl:                   IDP_SSO_URL,
    idpCertPem:                  idpSigningCertPem,
  });
  var arReal = spReal.buildAuthnRequest();

  var jar = _newCookieJar();

  // Step 1 — GET the AuthnRequest redirect; Keycloak responds with
  // the login HTML form. Parse out the form's action URL.
  var loginPage = await _httpReq("GET", arReal.redirectUrl, jar);
  check("SAML login: 200 from IdP",                              loginPage.statusCode === 200);
  var loginHtml = loginPage.body.toString("utf8");
  var actionMatch = /action="(http:\/\/[^"]+\/login-actions\/authenticate[^"]+)"/.exec(loginHtml);
  check("SAML login: action URL extracted",                      !!actionMatch);
  var actionUrl = actionMatch[1].replace(/&amp;/g, "&");

  // Step 2 — POST credentials to the action URL with the cookie jar.
  // Keycloak responds with an auto-submit HTML form whose
  // `name="SAMLResponse" value="..."` carries the signed response.
  var loginBody = new URLSearchParams();
  loginBody.set("username",     TEST_USERNAME);
  loginBody.set("password",     TEST_PASSWORD);
  loginBody.set("credentialId", "");
  var loginPost = await _httpReq("POST", actionUrl, jar, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    loginBody.toString(),
    redirect: false,
  });
  // Keycloak may 302 to a follow-up, then the auto-submit page; or it
  // may 200 the auto-submit page directly. Handle both.
  var responseHtml = null;
  if (loginPost.statusCode === 200) {
    responseHtml = loginPost.body.toString("utf8");
  } else if (loginPost.statusCode === 302 || loginPost.statusCode === 303) {
    var follow = await _httpReq("GET", loginPost.headers.location || loginPost.headers.Location, jar);
    check("SAML login: follow-up GET 200",                       follow.statusCode === 200);
    responseHtml = follow.body.toString("utf8");
  } else {
    check("SAML login POST: 200 or 30x (got " + loginPost.statusCode + ")", false);
    responseHtml = "";
  }

  // Step 3 — extract the SAMLResponse base64 from the auto-submit form.
  var samlResponseMatch = /name="SAMLResponse"\s+value="([^"]+)"/.exec(responseHtml);
  check("SAML login: SAMLResponse value extracted",              !!samlResponseMatch);
  var samlResponseB64 = samlResponseMatch && samlResponseMatch[1];

  // Step 4 — hand the response to sp.verifyResponse(). This is the
  // path the test set out to cover: real Keycloak-signed assertion,
  // real XMLDSig signature, real SubjectConfirmation Bearer constraint
  // checks, real AudienceRestriction check.
  if (samlResponseB64) {
    var info = spReal.verifyResponse(samlResponseB64, {
      expectedInResponseTo: arReal.id,
    });
    check("SAML verifyResponse: returns parsed info",            info && typeof info === "object");
    check("SAML verifyResponse: nameId matches alice",            info && (info.nameId === TEST_USERNAME || info.nameId === "alice@example.com"));
    check("SAML verifyResponse: issuer matches IdP entityID",     info && info.issuer === ISSUER);
    check("SAML verifyResponse: inResponseTo matches AuthnRequest", info && info.inResponseTo === arReal.id);
    check("SAML verifyResponse: audience matches SP entityID",    info && info.audience === SP_ENTITY_ID);
  }

  // ---- CIBA — Keycloak's CIBA endpoint is exposed at
  //      /protocol/openid-connect/ext/ciba/auth (verified above in the
  //      discovery response). Build a CIBA client + invoke
  //      startAuthentication; we don't drive the user-side approval
  //      step, so the call should reach the IdP and return an
  //      authReqId OR a deterministic error indicating the realm
  //      hasn't enabled CIBA for this client (which is the operator-
  //      facing "configure your client" path). Either outcome
  //      validates the wire format.
  var ciba = b.auth.ciba.client.create({
    issuer:                            ISSUER,
    clientId:                          CLIENT_ID,
    clientAuth:                        "secret",
    clientSecret:                      CLIENT_SECRET,
    deliveryMode:                      "poll",
    backchannelAuthenticationEndpoint: ISSUER + "/protocol/openid-connect/ext/ciba/auth",
    tokenEndpoint:                     ISSUER + "/protocol/openid-connect/token",
    allowHttp:                         true,
    httpClientOpts:                    { allowInternal: true },
  });
  try {
    var ticket = await ciba.startAuthentication({ loginHint: TEST_USERNAME });
    check("CIBA: startAuthentication returned authReqId",
      ticket && typeof ticket.authReqId === "string" && ticket.authReqId.length > 0);
  } catch (e) {
    // Keycloak refuses CIBA when the client doesn't have it enabled —
    // surfaces as a deterministic auth-ciba/<error-code> we can assert
    // on. That confirms the wire format hit the IdP.
    check("CIBA: IdP returned a deterministic error (client not enabled for CIBA)",
      /auth-ciba\//.test(e.code || e.message || ""));
  }

  // ---- SAML SLO HTTP-Redirect — drive a LogoutRequest through the
  //      IdP's SLO endpoint, parse the LogoutResponse. v0.11.0 added
  //      SLO support; this round-trip exercises buildLogoutRequest +
  //      parseLogoutResponse against Keycloak's real SAML endpoint.
  var IDP_SLO_URL = ISSUER + "/protocol/saml";
  var spSlo = b.auth.saml.sp.create({
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: SP_ACS_URL,
    idpEntityId:                 ISSUER,
    idpSsoUrl:                   IDP_SSO_URL,
    idpSloUrl:                   IDP_SLO_URL,
    idpCertPem:                  idpSigningCertPem,
  });
  var lr = spSlo.buildLogoutRequest({
    nameId:       TEST_USERNAME,
    sessionIndex: "_session-from-real-saml-roundtrip",
  });
  check("SAML buildLogoutRequest: redirectUrl includes IdP SLO endpoint",
    lr.redirectUrl.indexOf(IDP_SLO_URL) === 0);
  check("SAML buildLogoutRequest: SAMLRequest param present",
    lr.redirectUrl.indexOf("SAMLRequest=") !== -1);
  check("SAML buildLogoutRequest: id starts with underscore",
    typeof lr.id === "string" && lr.id.charAt(0) === "_");

  // Keycloak's SLO endpoint returns either 200 (with an auto-POST form
  // carrying a SAMLResponse), a 302 redirect to a no-cookie SLO page,
  // or a 500 when the LogoutRequest references no active IdP session
  // (which is the realistic outcome for our cookie-less request — the
  // user we built the LogoutRequest for has no live session at the IdP
  // because we never drove the full browser login). The 4xx range is
  // what would indicate a structural fault in our SAML wire format —
  // Keycloak refuses malformed SLO requests with 400. Accept any
  // non-4xx status as proof the wire format parsed cleanly.
  var sloResp = await _httpReq("GET", lr.redirectUrl, _newCookieJar());
  check("SAML SLO request: IdP parsed LogoutRequest (got " + sloResp.statusCode +
        ", not in the 400-499 'malformed' range)",
    !(sloResp.statusCode >= 400 && sloResp.statusCode < 500));

  // ---- RFC 7592 Dynamic Client Registration Management — register
  //      a fresh client against Keycloak's anonymous DCR endpoint,
  //      read it back, update it, then delete it. Keycloak supports
  //      RFC 7592 out of the box for realms with `clients-trusted-host`
  //      policy disabled (the blamejs-test realm import sets this).
  if (typeof disc.registration_endpoint === "string") {
    var oauthForDcr = b.auth.oauth.create({
      issuer:           ISSUER,
      clientId:         CLIENT_ID,
      clientSecret:     CLIENT_SECRET,
      redirectUri:      REDIRECT_URI,
      isOidc:           true,
      allowHttp:        true,
      allowInternal:    true,
    });
    var registered = null;
    try {
      registered = await oauthForDcr.registerClient({
        redirect_uris:              ["https://rp.dcr-test.example/cb"],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types:                ["authorization_code", "refresh_token"],
        response_types:             ["code"],
        client_name:                "blamejs-v0.11.1 DCR roundtrip",
      });
    } catch (eR) {
      // Keycloak realm policy may refuse anonymous registration (the
      // default "Trusted Hosts" policy is the most common reason —
      // operators with locked-down realms expect this refusal until
      // they whitelist the registering host). Either a framework-coded
      // `auth-oauth/*` error or an upstream HTTP_ERROR (4xx from the
      // AS surfaced by b.httpClient) proves the wire format reached
      // the AS and got a deterministic response — that's what this
      // test set out to validate.
      var dccode = (eR && eR.code) || "";
      check("DCR registerClient: AS responded with deterministic outcome (" + dccode + ")",
        dccode.indexOf("auth-oauth/") === 0 ||
        dccode === "HTTP_ERROR");
    }
    if (registered) {
      check("DCR registerClient: AS issued client_id",
        typeof registered.client_id === "string" && registered.client_id.length > 0);
      check("DCR registerClient: AS returned registration_client_uri",
        typeof registered.registration_client_uri === "string");
      check("DCR registerClient: AS returned registration_access_token",
        typeof registered.registration_access_token === "string");

      // readClient — GET against the management endpoint
      try {
        var readBack = await oauthForDcr.readClient(
          registered.registration_client_uri,
          registered.registration_access_token);
        check("DCR readClient: returns same client_id",
          readBack.client_id === registered.client_id);
      } catch (eRd) {
        check("DCR readClient: deterministic outcome (AS or rule denied)",
          eRd && eRd.code && eRd.code.indexOf("auth-oauth/") === 0);
      }

      // updateClient — change redirect_uris
      try {
        var updated = await oauthForDcr.updateClient(
          registered.registration_client_uri,
          registered.registration_access_token,
          {
            redirect_uris:              ["https://rp.dcr-test.example/cb-new"],
            token_endpoint_auth_method: "client_secret_basic",
            grant_types:                ["authorization_code", "refresh_token"],
            response_types:             ["code"],
            client_name:                "blamejs-v0.11.1 DCR roundtrip (updated)",
          });
        check("DCR updateClient: AS accepted update",
          updated && updated.client_id === registered.client_id);
      } catch (eUp) {
        check("DCR updateClient: deterministic outcome (AS or rule denied)",
          eUp && eUp.code && eUp.code.indexOf("auth-oauth/") === 0);
      }

      // deleteClient — DELETE against the management endpoint
      try {
        await oauthForDcr.deleteClient(
          registered.registration_client_uri,
          registered.registration_access_token);
        check("DCR deleteClient: deregistered without error", true);
      } catch (eDe) {
        check("DCR deleteClient: deterministic outcome (AS or rule denied)",
          eDe && eDe.code && eDe.code.indexOf("auth-oauth/") === 0);
      }
    }
  } else {
    check("DCR: deferred (AS doesn't advertise registration_endpoint)", true);
  }

  // ---- OAuth Device Authorization Grant (RFC 8628) — the poll survives an
  //      authorization_pending HTTP 400 ----
  // RFC 8628 §3.5 / RFC 6749 §5.2 deliver `authorization_pending` as an HTTP
  // 400 whose body carries the OAuth `error`. Before v0.16.5 the token poll ran
  // in the http client's buffering mode, which rejected the 400 before the
  // pending handler read the body, so the grant aborted on the FIRST poll
  // (almost always authorization_pending, since the user hasn't approved yet).
  // Drive the grant against Keycloak's real device endpoint and assert the poll
  // keeps going across the pending 400s to a deterministic device-poll-timeout —
  // not the HTTP_ERROR abort the buffered path threw.
  var adminTok = await _adminToken();
  await _ensureDeviceClient(adminTok);
  var deviceOauth = b.auth.oauth.create({
    issuer:        ISSUER,
    clientId:      DEVICE_CLIENT_ID,
    clientSecret:  DEVICE_SECRET,
    redirectUri:   REDIRECT_URI,
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });
  var devAuth = await deviceOauth.deviceAuthorization();
  check("deviceAuthorization: device_code + user_code + verification_uri returned",
    typeof devAuth.device_code === "string" && typeof devAuth.user_code === "string" &&
    typeof devAuth.verification_uri === "string");
  // The user never approves, so every poll returns authorization_pending (400).
  // maxWaitMs spans at least two 5s poll intervals — reaching device-poll-timeout
  // proves the loop survived the pending 400s rather than aborting on the first
  // (which is what a reverted buffer-mode poll would do, throwing HTTP_ERROR).
  var devThrew = null;
  try {
    await deviceOauth.pollDeviceCode(devAuth.device_code, { interval: devAuth.interval, maxWaitMs: 6000 });
  } catch (e) { devThrew = e; }
  check("pollDeviceCode: survives authorization_pending 400 and reaches device-poll-timeout",
    !!devThrew && devThrew.code === "auth-oauth/device-poll-timeout");

  // ---- SAML EncryptedAssertion decrypt interop (SAML 2.0 §2.5) ----
  // Enable assertion encryption on a dedicated SP client, drive the login, and
  // hand the Keycloak-encrypted SAMLResponse to verifyResponse with the SP
  // private key. Keycloak 26.0.8 emits aes128-cbc content + rsa-oaep-mgf1p
  // (SHA-1) key transport — both refused by the framework by design (XMLEnc CBC
  // padding-oracle; SHA-1 OAEP), so against that output the assertion is that
  // the framework fails CLOSED (no auth bypass). On a Keycloak that emits
  // AES-GCM + RSA-OAEP-SHA256 (26.2+, where the encryption algorithm attributes
  // take effect), the GCM branch asserts nameId/issuer/audience decrypt. The SP
  // keypair is generated at runtime so no private key is committed.
  var spEnc = _generateSpEncryptionKeypair();
  if (!spEnc) {
    check("SAML EncryptedAssertion: skipped — openssl unavailable for runtime SP cert (see file header)", true);
  } else {
    await _ensureSamlEncClient(adminTok, spEnc.certDerB64);
    var spEncHandle = b.auth.saml.sp.create({
      entityId:                    SP_ENC_ENTITY_ID,
      assertionConsumerServiceUrl: SP_ACS_URL,
      idpEntityId:                 ISSUER,
      idpSsoUrl:                   IDP_SSO_URL,
      idpCertPem:                  idpSigningCertPem,
    });
    var arEnc = spEncHandle.buildAuthnRequest();
    var encRespB64 = await _driveSamlLoginCapture(arEnc.redirectUrl);
    check("SAML EncryptedAssertion: login round-trip captured a SAMLResponse",
      typeof encRespB64 === "string" && encRespB64.length > 0);
    if (encRespB64) {
      var encXml = Buffer.from(encRespB64, "base64").toString("utf8");
      check("SAML EncryptedAssertion: Keycloak returned an <EncryptedAssertion>",
        encXml.indexOf("EncryptedAssertion") !== -1);
      var contentAlgMatch = /EncryptedData\b[\s\S]*?EncryptionMethod Algorithm="([^"]+)"/.exec(encXml);
      var keyAlgMatch     = /EncryptedKey\b[\s\S]*?EncryptionMethod Algorithm="([^"]+)"/.exec(encXml);
      var contentAlg = contentAlgMatch ? contentAlgMatch[1] : "";
      var keyAlg     = keyAlgMatch ? keyAlgMatch[1] : "";
      var gcmContent = /aes(?:128|192|256)-gcm/.test(contentAlg);
      var sha256Oaep = /xmlenc(?:11)?#sha(?:256|384|512)/.test(encXml);
      if (gcmContent && sha256Oaep) {
        // Keycloak >= 26.2 path: the framework decrypts the assertion.
        var encInfo = spEncHandle.verifyResponse(encRespB64, {
          spPrivateKeyPem:      spEnc.keyPem,
          expectedInResponseTo: arEnc.id,
        });
        check("SAML EncryptedAssertion: decrypted nameId is alice",
          encInfo && (encInfo.nameId === TEST_USERNAME || encInfo.nameId === "alice@example.com"));
        check("SAML EncryptedAssertion: decrypted issuer matches IdP entityID",
          encInfo && encInfo.issuer === ISSUER);
        check("SAML EncryptedAssertion: decrypted audience matches SP entityID",
          encInfo && encInfo.audience === SP_ENC_ENTITY_ID);
      } else {
        // Keycloak 26.0.8 path: aes128-cbc + rsa-oaep-mgf1p(SHA-1). The framework
        // refuses both by design; assert the fail-closed refusal against the real
        // IdP output. Positive decrypt is pending a Keycloak >= 26.2 image.
        var encThrew = null;
        try {
          spEncHandle.verifyResponse(encRespB64, {
            spPrivateKeyPem:      spEnc.keyPem,
            expectedInResponseTo: arEnc.id,
          });
        } catch (e) { encThrew = e; }
        check("SAML EncryptedAssertion: framework fails closed on Keycloak 26.0.8 weak-crypto envelope (" +
              contentAlg + " / " + keyAlg + ")",
          !!encThrew &&
          /^auth-saml\/encrypted-(weak-oaep-digest|unsupported-content-alg|unsupported-key-alg)$/.test(encThrew.code || ""));
      }
    }
  }

  // ---- Federation primitives — deferred, document the open conditions ----
  check("OID4VCI: deferred (Keycloak oid4vc-issuer SPI is preview-only)",                 true);
  check("OID4VP: deferred (no wallet harness in the test stack)",                         true);
  check("OpenID Federation: covered by openid-federation-chain.test.js (loopback trust-chain, no Keycloak provider)", true);
  check("OIDC Native SSO: deferred (Keycloak's device_secret support is preview-only)",   true);
}

module.exports = { run: run };
if (require.main === module) {
  run().then(
    function () { console.log("[federation-auth] OK"); },
    function (e) { console.error("[federation-auth] FAIL:", e.stack || e); process.exit(1); }
  );
}
