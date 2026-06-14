"use strict";
/**
 * b.auth.oauth callback / JARM / refresh-rotation primitives (v0.8.70):
 *   - parseCallback   (RFC 9207 AS Issuer Identifier validation)
 *   - parseJarmResponse (OAuth 2.0 JARM signed authorization response)
 *   - refreshAccessToken seen() callback (RFC 9700 §4.13 / OAuth 2.1 §6.1)
 *   - authorizationUrl PKCE-downgrade refusal (RFC 9700 §4.13 / RFC 7636)
 *   - authorizationUrl / exchangeCode authorization_details (RFC 9396 RAR)
 *   - buildClientAttestation / buildClientAttestationPop /
 *     verifyClientAttestation (draft-ietf-oauth-attestation-based-client-auth)
 *   - pushAuthorizationRequest signed-request-object opt (RFC 9101 +
 *     RFC 9126 §3 — request= in the PAR body, params as JAR claims)
 */

var http    = require("node:http");
var crypto  = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Minimal OIDC discovery server: serves /.well-known/openid-configuration
// with operator-chosen code_challenge_methods_supported so the PKCE
// downgrade gate runs against a real discovery round-trip.
function _spawnDiscoveryServer(methods) {
  var issuerHolder = { value: null };
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname !== "/.well-known/openid-configuration") { res.writeHead(404); res.end(); return; }
    var doc = {
      issuer:                 issuerHolder.value,
      authorization_endpoint: issuerHolder.value + "/auth",
      token_endpoint:         issuerHolder.value + "/token",
      jwks_uri:               issuerHolder.value + "/jwks",
    };
    if (methods !== undefined) doc.code_challenge_methods_supported = methods;
    var body = JSON.stringify(doc);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
  });
  server._issuerHolder = issuerHolder;
  return server;
}

// Mock authorization server with discovery + a PAR endpoint that records
// the posted form body. Discovery advertises S256 so the PKCE-downgrade
// gate passes; the PAR endpoint returns a fixed request_uri.
function _spawnParServer() {
  var captured = { body: null };
  var holder = { value: null };
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname === "/.well-known/openid-configuration") {
      var doc = {
        issuer:                              holder.value,
        authorization_endpoint:              holder.value + "/auth",
        token_endpoint:                      holder.value + "/token",
        jwks_uri:                            holder.value + "/jwks",
        pushed_authorization_request_endpoint: holder.value + "/par",
        code_challenge_methods_supported:    ["S256"],
      };
      var body = JSON.stringify(doc);
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
      return;
    }
    if (u.pathname === "/par" && req.method === "POST") {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        captured.body = Buffer.concat(chunks).toString("utf8");
        var out = JSON.stringify({ request_uri: "urn:ietf:params:oauth:request_uri:abc123", expires_in: 90 });
        res.writeHead(201, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(out) });
        res.end(out);
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  server._holder = holder;
  server._captured = captured;
  return server;
}

async function _pkceDowngradeCase(methods, expectRefusal, label) {
  var server = _spawnDiscoveryServer(methods);
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var issuer = "http://127.0.0.1:" + server.address().port;
  server._issuerHolder.value = issuer;
  try {
    var oa = b.auth.oauth.create({
      issuer:        issuer,
      clientId:      "rp-dl",
      redirectUri:   "https://rp.example/cb",
      isOidc:        true,
      allowHttp:     true,
      allowInternal: true,
    });
    var err = null;
    try { await oa.authorizationUrl(); } catch (e) { err = e; }
    if (expectRefusal) {
      check(label, err !== null && err.code === "auth-oauth/pkce-downgrade");
    } else {
      check(label, err === null);
    }
  } finally { server.close(); }
}

async function run() {
  var oauth = b.auth.oauth.create({
    issuer:        "https://idp.example",
    clientId:      "rp-1",
    clientSecret:  "test-secret",
    redirectUri:   "https://rp.example/cb",
    scope:         ["openid"],
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });

  var rv = await oauth.parseCallback({ code: "abc123", state: "s1", iss: "https://idp.example" }, { expectedState: "s1" });
  check("oauth.parseCallback: happy path returns code+state",     rv.code === "abc123" && rv.state === "s1");

  var threw = false;
  try { await oauth.parseCallback({ code: "abc", iss: "https://attacker.example" }); }
  catch (e) { threw = /iss-mismatch-callback/.test(e.code) && /RFC 9207/.test(e.message); }
  check("oauth.parseCallback: iss mismatch refused (RFC 9207)",   threw);

  threw = false;
  try { await oauth.parseCallback({ error: "access_denied", error_description: "user said no" }); }
  catch (e) { threw = /op-error/.test(e.code); }
  check("oauth.parseCallback: OP error param refused",            threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc", state: "wrong" }, { expectedState: "expected" }); }
  catch (e) { threw = /state-mismatch/.test(e.code); }
  check("oauth.parseCallback: state mismatch refused (CSRF)",     threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc" }, { requireIssParam: true }); }
  catch (e) { threw = /missing-iss-callback/.test(e.code); }
  check("oauth.parseCallback: requireIssParam refuses missing iss", threw);

  threw = false;
  try { await oauth.parseJarmResponse(""); }
  catch (e) { threw = /no-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: empty refused",                 threw);

  threw = false;
  try { await oauth.parseJarmResponse("not-a-jws"); }
  catch (e) { threw = /malformed-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: non-3-segment refused",         threw);

  threw = false;
  try {
    await oauth.refreshAccessToken("rt-1", { seen: async function () { return true; } });
  } catch (e) { threw = /refresh-token-replay/.test(e.code); }
  check("oauth.refreshAccessToken: seen()=true refuses replay",   threw);

  // PKCE downgrade defense (RFC 9700 §4.13 / RFC 7636). An OP whose
  // discovery metadata advertises code_challenge_methods_supported
  // without "S256" is refused at authorizationUrl; S256-capable or
  // field-absent OPs keep working (back-compat).
  await _pkceDowngradeCase(["plain"], true,
    "oauth.authorizationUrl: plain-only OP refused (PKCE downgrade)");
  await _pkceDowngradeCase([], true,
    "oauth.authorizationUrl: empty methods list refused (no S256)");
  await _pkceDowngradeCase(["S256"], false,
    "oauth.authorizationUrl: S256-only OP accepted");
  await _pkceDowngradeCase(["S256", "plain"], false,
    "oauth.authorizationUrl: S256+plain OP accepted");
  await _pkceDowngradeCase(undefined, false,
    "oauth.authorizationUrl: field-absent OP accepted (back-compat)");

  // Static-endpoint client with no discovery must never gain a network
  // fetch or a downgrade refusal — the gate only inspects already-
  // resolved discovery metadata.
  var oaStatic = b.auth.oauth.create({
    issuer:                "https://static.example",
    clientId:              "rp-static",
    redirectUri:           "https://rp.example/cb",
    isOidc:                true,
    authorizationEndpoint: "https://static.example/auth",
    tokenEndpoint:         "https://static.example/token",
  });
  var staticErr = null;
  try { await oaStatic.authorizationUrl(); } catch (e) { staticErr = e; }
  check("oauth.authorizationUrl: static endpoints skip discovery (no fetch, no refusal)",
        staticErr === null);

  // ---- RFC 9396 Rich Authorization Requests (RAR) ----
  var oaRar = b.auth.oauth.create({
    issuer:                "https://static.example",
    clientId:              "rp-rar",
    redirectUri:           "https://rp.example/cb",
    isOidc:                true,
    authorizationEndpoint: "https://static.example/auth",
    tokenEndpoint:         "https://static.example/token",
  });
  var requested = [
    { type: "payment_initiation", actions: ["initiate", "status"],
      locations: ["https://rs.example/pay"] },
  ];
  var rar = await oaRar.authorizationUrl({ authorizationDetails: requested });
  check("oauth.authorizationUrl: serializes authorization_details (RFC 9396)",
        /[?&]authorization_details=/.test(rar.url));
  check("oauth.authorizationUrl: returns validated authorizationDetails",
        Array.isArray(rar.authorizationDetails) && rar.authorizationDetails.length === 1);
  // back-compat — a client that omits the opt emits no authorization_details
  var noRar = await oaRar.authorizationUrl();
  check("oauth.authorizationUrl: omitted authorizationDetails → no param (back-compat)",
        !/authorization_details=/.test(noRar.url) && noRar.authorizationDetails === null);
  // config-time refusal on malformed shape
  var rarThrew = null;
  try { await oaRar.authorizationUrl({ authorizationDetails: [{ noType: 1 }] }); }
  catch (e) { rarThrew = e; }
  check("oauth.authorizationUrl: authorization_details missing type refused",
        rarThrew && rarThrew.code === "auth-oauth/bad-authorization-details");
  rarThrew = null;
  try { await oaRar.authorizationUrl({ authorizationDetails: "not-an-array" }); }
  catch (e) { rarThrew = e; }
  check("oauth.authorizationUrl: non-array authorization_details refused",
        rarThrew && rarThrew.code === "auth-oauth/bad-authorization-details");

  // granted-vs-requested cross-check (the security-relevant subset rule)
  var X = b.auth.oauth;
  var subset = X._crossCheckGrantedAuthorizationDetails(
    [{ type: "payment_initiation", actions: ["status"], locations: ["https://rs.example/pay"] }],
    requested, true);
  check("oauth: granted authorization_details subset accepted",
        Array.isArray(subset) && subset.length === 1);
  var overThrew = null;
  try {
    X._crossCheckGrantedAuthorizationDetails(
      [{ type: "payment_initiation", actions: ["initiate", "transfer"] }], requested, true);
  } catch (e) { overThrew = e; }
  check("oauth: granted action beyond request refused (RFC 9396 over-grant)",
        overThrew && overThrew.code === "auth-oauth/authorization-details-over-grant");
  overThrew = null;
  try {
    X._crossCheckGrantedAuthorizationDetails([{ type: "account_access" }], requested, true);
  } catch (e) { overThrew = e; }
  check("oauth: granted unrequested type refused (RFC 9396 over-grant)",
        overThrew && overThrew.code === "auth-oauth/authorization-details-over-grant");
  // non-strict mode surfaces over-grant without throwing
  var surfaced = X._crossCheckGrantedAuthorizationDetails([{ type: "account_access" }], requested, false);
  check("oauth: non-strict cross-check surfaces granted without refusal",
        Array.isArray(surfaced) && surfaced.length === 1);
  // location over-grant
  overThrew = null;
  try {
    X._crossCheckGrantedAuthorizationDetails(
      [{ type: "payment_initiation", locations: ["https://rs.example/pay", "https://evil.example"] }],
      requested, true);
  } catch (e) { overThrew = e; }
  check("oauth: granted location beyond request refused (RFC 9396 over-grant)",
        overThrew && overThrew.code === "auth-oauth/authorization-details-over-grant");
  // privileges over-grant — `privileges` is a registered array-valued common
  // data field (RFC 9396 §2.1); a granted privileges array the request never
  // constrained is the sharpest escalation and must be refused.
  overThrew = null;
  try {
    X._crossCheckGrantedAuthorizationDetails(
      [{ type: "payment_initiation", privileges: ["admin"] }], requested, true);
  } catch (e) { overThrew = e; }
  check("oauth: granted privilege beyond request refused (RFC 9396 over-grant)",
        overThrew && overThrew.code === "auth-oauth/authorization-details-over-grant");

  // ---- draft-ietf-oauth-attestation-based-client-auth ----
  var attesterKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instanceKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instancePubJwk = instanceKp.publicKey.export({ format: "jwk" });
  var attesterPubJwk = attesterKp.publicKey.export({ format: "jwk" });

  var attestation = b.auth.oauth.buildClientAttestation({
    clientId:           "wallet-app",
    attesterPrivateKey: attesterKp.privateKey,
    instanceKeyJwk:     instancePubJwk,
  });
  var pop = b.auth.oauth.buildClientAttestationPop({
    instancePrivateKey: instanceKp.privateKey,
    audience:           "https://as.example.com",
  });
  // header typ values per draft §4 / §5
  var attHeader = JSON.parse(Buffer.from(attestation.split(".")[0], "base64url").toString("utf8"));
  var popHeader = JSON.parse(Buffer.from(pop.split(".")[0], "base64url").toString("utf8"));
  check("oauth.attestation: attestation typ is oauth-client-attestation+jwt",
        attHeader.typ === "oauth-client-attestation+jwt");
  check("oauth.attestation: pop typ is oauth-client-attestation-pop+jwt",
        popHeader.typ === "oauth-client-attestation-pop+jwt");

  var jtiSeen = {};
  var seenJti = function (jti) { if (jtiSeen[jti]) { return false; } jtiSeen[jti] = 1; return true; };
  var verified = await b.auth.oauth.verifyClientAttestation(attestation, pop, {
    attesterJwk:      attesterPubJwk,
    expectedAudience: "https://as.example.com",
    expectedClientId: "wallet-app",
    seenJti:          seenJti,
  });
  check("oauth.verifyClientAttestation: valid pair → clientId from sub",
        verified.clientId === "wallet-app");
  check("oauth.verifyClientAttestation: returns the cnf key",
        verified.cnfJwk && verified.cnfJwk.kty === "EC");

  // replay (jti already seen) refused — draft §12.1
  var attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, pop, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com", seenJti: seenJti });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: jti replay refused (draft §12.1)",
        attThrew && attThrew.code === "auth-oauth/attestation-pop-replay");

  // wrong audience refused — draft §8 step 7
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, pop, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://other.example.com" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: PoP aud mismatch refused",
        attThrew && attThrew.code === "auth-oauth/attestation-pop-aud-mismatch");

  // PoP forged with a key not in the cnf claim refused — possession proof
  var attackerKp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var forgedPop = b.auth.oauth.buildClientAttestationPop({
    instancePrivateKey: attackerKp.privateKey, audience: "https://as.example.com" });
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, forgedPop, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: PoP not signed by cnf key refused",
        attThrew && attThrew.code === "auth-oauth/attestation-bad-signature");

  // attestation forged by an untrusted attester refused
  attThrew = null;
  var rogueAtt = b.auth.oauth.buildClientAttestation({
    clientId: "wallet-app", attesterPrivateKey: attackerKp.privateKey, instanceKeyJwk: instancePubJwk });
  try {
    await b.auth.oauth.verifyClientAttestation(rogueAtt, b.auth.oauth.buildClientAttestationPop({
      instancePrivateKey: instanceKp.privateKey, audience: "https://as.example.com" }), {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: untrusted attester signature refused",
        attThrew && attThrew.code === "auth-oauth/attestation-bad-signature");

  // client_id mismatch refused — draft §8 step 10
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, b.auth.oauth.buildClientAttestationPop({
      instancePrivateKey: instanceKp.privateKey, audience: "https://as.example.com" }), {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com",
      expectedClientId: "different-client" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: client_id != attestation sub refused",
        attThrew && attThrew.code === "auth-oauth/attestation-client-id-mismatch");

  // challenge binding — draft §8 step 5/6
  var popChal = b.auth.oauth.buildClientAttestationPop({
    instancePrivateKey: instanceKp.privateKey, audience: "https://as.example.com", challenge: "srv-nonce-1" });
  var vChal = await b.auth.oauth.verifyClientAttestation(attestation, popChal, {
    attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com", challenge: "srv-nonce-1" });
  check("oauth.verifyClientAttestation: matching challenge accepted", vChal.clientId === "wallet-app");
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, popChal, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com", challenge: "WRONG" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: challenge mismatch refused",
        attThrew && attThrew.code === "auth-oauth/attestation-pop-challenge-mismatch");

  // HMAC alg refused at build (no symmetric attestation)
  attThrew = null;
  try {
    b.auth.oauth.buildClientAttestation({ clientId: "w", attesterPrivateKey: attesterKp.privateKey,
      instanceKeyJwk: instancePubJwk, algorithm: "HS256" });
  } catch (e) { attThrew = e; }
  check("oauth.buildClientAttestation: HMAC alg refused",
        attThrew && attThrew.code === "auth-oauth/attestation-alg-not-accepted");

  // 5-segment JWE refused on the verifier path
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation("a.b.c.d.e", pop, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com" });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: 5-segment JWE attestation refused",
        attThrew && attThrew.code === "auth-oauth/attestation-jwe-refused");

  // builder infers the JWS alg from the key type — a non-EC attester key
  // with no explicit `algorithm` must produce a self-consistent JWS (header
  // alg matches the signing key), not a fixed ES256 header the verifier's
  // alg/kty cross-check would reject.
  var edAttKp = crypto.generateKeyPairSync("ed25519");
  var edAtt = b.auth.oauth.buildClientAttestation({
    clientId: "wallet-app", attesterPrivateKey: edAttKp.privateKey, instanceKeyJwk: instancePubJwk });
  var edAttHdr = JSON.parse(Buffer.from(edAtt.split(".")[0], "base64url").toString("utf8"));
  check("oauth.buildClientAttestation: Ed25519 key infers EdDSA alg", edAttHdr.alg === "EdDSA");
  var edVerified = await b.auth.oauth.verifyClientAttestation(edAtt, b.auth.oauth.buildClientAttestationPop({
    instancePrivateKey: instanceKp.privateKey, audience: "https://as.example.com" }), {
    attesterJwk: edAttKp.publicKey.export({ format: "jwk" }), expectedAudience: "https://as.example.com" });
  check("oauth.verifyClientAttestation: Ed25519-signed attestation verifies", edVerified.clientId === "wallet-app");

  var rsaAttKp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaAttHdr = JSON.parse(Buffer.from(b.auth.oauth.buildClientAttestation({
    clientId: "wallet-app", attesterPrivateKey: rsaAttKp.privateKey, instanceKeyJwk: instancePubJwk
  }).split(".")[0], "base64url").toString("utf8"));
  check("oauth.buildClientAttestation: RSA key infers RS256 alg", rsaAttHdr.alg === "RS256");

  // an explicit alg incompatible with the key is refused BEFORE signing
  // (a P-256 key cannot produce an RS256 signature).
  attThrew = null;
  try {
    b.auth.oauth.buildClientAttestation({ clientId: "w", attesterPrivateKey: attesterKp.privateKey,
      instanceKeyJwk: instancePubJwk, algorithm: "RS256" });
  } catch (e) { attThrew = e; }
  check("oauth.buildClientAttestation: explicit alg incompatible with key refused",
        attThrew && attThrew.code === "auth-oauth/attestation-alg-key-mismatch");

  // async (Promise) replay store is awaited — a Redis/DB seenJti returns a
  // Promise; the verifier must await it so a resolved `false` (replayed
  // jti) refuses instead of comparing a never-`false` Promise object.
  var asyncSeen = {};
  var asyncSeenJti = function (jti) {
    return Promise.resolve().then(function () {
      if (asyncSeen[jti]) { return false; }
      asyncSeen[jti] = 1;
      return true;
    });
  };
  var popAsync = b.auth.oauth.buildClientAttestationPop({
    instancePrivateKey: instanceKp.privateKey, audience: "https://as.example.com" });
  var asyncOk = await b.auth.oauth.verifyClientAttestation(attestation, popAsync, {
    attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com", seenJti: asyncSeenJti });
  check("oauth.verifyClientAttestation: async seenJti first sighting accepted",
        asyncOk.clientId === "wallet-app");
  attThrew = null;
  try {
    await b.auth.oauth.verifyClientAttestation(attestation, popAsync, {
      attesterJwk: attesterPubJwk, expectedAudience: "https://as.example.com", seenJti: asyncSeenJti });
  } catch (e) { attThrew = e; }
  check("oauth.verifyClientAttestation: async seenJti replay refused (Promise awaited)",
        attThrew && attThrew.code === "auth-oauth/attestation-pop-replay");

  // instance-bound convenience builder produces both headers
  var hdrs = oaRar.clientAttestationHeaders({
    attesterPrivateKey: attesterKp.privateKey,
    instanceKeyJwk:     instancePubJwk,
    instancePrivateKey: instanceKp.privateKey,
    audience:           "https://as.example.com",
  });
  check("oauth.clientAttestationHeaders: emits both header fields",
        typeof hdrs.headers["OAuth-Client-Attestation"] === "string" &&
        typeof hdrs.headers["OAuth-Client-Attestation-PoP"] === "string");

  // ---- RFC 9101 + RFC 9126 §3 — PAR with a signed request object ----
  await _testParRequestObject();
  await _testParPlainUnchanged();

  // ---- OIDC Back-Channel Logout — bounded token + header parse ----
  await _testBackchannelLogoutOversized();
}

// PAR carrying a signed request object: the form body MUST hold `request=`
// + client auth ONLY, and the authorization parameters travel as request-
// object claims, NOT as bare form params. The pushed JWT is verified
// in-test against the client's public JWK via b.auth.jar.parse.
async function _testParRequestObject() {
  var server = _spawnParServer();
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var issuer = "http://127.0.0.1:" + server.address().port;
  server._holder.value = issuer;
  try {
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var pubJwk = Object.assign(kp.publicKey.export({ format: "jwk" }), { kid: "c1", use: "sig", alg: "ES256" });
    var oa = b.auth.oauth.create({
      issuer:        issuer,
      clientId:      "par-client",
      clientSecret:  "par-secret",
      redirectUri:   "https://rp.example/cb",
      scope:         ["openid", "profile"],
      isOidc:        true,
      allowHttp:     true,
      allowInternal: true,
    });
    var rv = await oa.pushAuthorizationRequest({
      signedRequestObject: { key: kp.privateKey, kid: "c1" },
      authorizationDetails: [
        { type: "payment_initiation", actions: ["initiate"], locations: ["https://rs.example/pay"] },
      ],
    });
    check("oauth.PAR+RO: returns a request_uri", rv.requestUri === "urn:ietf:params:oauth:request_uri:abc123");
    check("oauth.PAR+RO: flags requestObjectSent", rv.requestObjectSent === true);

    var posted = new URLSearchParams(server._captured.body);
    check("oauth.PAR+RO: form body carries request=", typeof posted.get("request") === "string" && posted.get("request").length > 0);
    check("oauth.PAR+RO: form body carries client_id (client auth)", posted.get("client_id") === "par-client");
    check("oauth.PAR+RO: form body carries client_secret (client auth)", posted.get("client_secret") === "par-secret");
    // RFC 9126 §3 — the authorization parameters MUST NOT appear as bare
    // form params alongside the request object.
    check("oauth.PAR+RO: response_type NOT a bare form param", posted.get("response_type") === null);
    check("oauth.PAR+RO: redirect_uri NOT a bare form param", posted.get("redirect_uri") === null);
    check("oauth.PAR+RO: scope NOT a bare form param", posted.get("scope") === null);
    check("oauth.PAR+RO: code_challenge NOT a bare form param", posted.get("code_challenge") === null);

    // The pushed request object verifies against the client's public key and
    // carries the authorization parameters as claims (round-trip via jar.parse).
    var parsed = await b.auth.jar.parse(posted.get("request"), {
      clientId: "par-client", audience: issuer, algorithms: ["ES256"], jwks: [pubJwk],
    });
    check("oauth.PAR+RO: request object verifies + carries response_type claim", parsed.params.response_type === "code");
    check("oauth.PAR+RO: request object carries redirect_uri + scope + S256 claims",
      parsed.params.redirect_uri === "https://rp.example/cb" && parsed.params.scope === "openid profile" &&
      parsed.params.code_challenge_method === "S256" && typeof parsed.params.code_challenge === "string");
    check("oauth.PAR+RO: request object aud is the AS issuer", parsed.claims.aud === issuer);
    // RFC 9101/9396 — authorization_details travels as a JSON ARRAY claim,
    // not a JSON string (a conforming AS rejects the string-valued claim).
    check("oauth.PAR+RO: authorization_details is a native array claim",
      Array.isArray(parsed.params.authorization_details) &&
      parsed.params.authorization_details.length === 1 &&
      parsed.params.authorization_details[0].type === "payment_initiation");
  } finally { server.close(); }
}

// RFC OIDC Back-Channel Logout — the pre-verify header parse + the token
// split run on an attacker-reachable, not-yet-signature-checked token, so
// the token must be length-bounded before either.
async function _testBackchannelLogoutOversized() {
  var oa = b.auth.oauth.create({
    issuer:        "https://idp.example",
    clientId:      "rp-bcl",
    redirectUri:   "https://rp.example/cb",
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });
  // A logout_token far larger than the response-bytes cap must be refused
  // BEFORE the split / base64url header decode.
  var huge = "a".repeat(300000) + ".b.c";
  var threw = null;
  try { await oa.verifyBackchannelLogoutToken(huge); }
  catch (e) { threw = e; }
  check("oauth.backchannelLogout: oversized token refused before parse",
    threw && threw.code === "auth-oauth/logout-token-too-large");

  // A well-formed-shape but bogus header still parses through safeJson
  // (size-bounded) and fails downstream, not with an unbounded-parse crash.
  var bogusHeader = Buffer.from("{not json", "utf8").toString("base64url");
  var threw2 = null;
  try { await oa.verifyBackchannelLogoutToken(bogusHeader + ".payload.sig"); }
  catch (e) { threw2 = e; }
  check("oauth.backchannelLogout: malformed header refused (bounded parse)",
    threw2 && threw2.code === "auth-oauth/bad-logout-header");
}

// PAR WITHOUT a signed request object: byte-for-byte the prior plain-form
// behavior — authorization parameters are bare form params, no `request=`.
async function _testParPlainUnchanged() {
  var server = _spawnParServer();
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var issuer = "http://127.0.0.1:" + server.address().port;
  server._holder.value = issuer;
  try {
    var oa = b.auth.oauth.create({
      issuer:        issuer,
      clientId:      "par-client",
      clientSecret:  "par-secret",
      redirectUri:   "https://rp.example/cb",
      scope:         ["openid"],
      isOidc:        true,
      allowHttp:     true,
      allowInternal: true,
    });
    var rv = await oa.pushAuthorizationRequest();
    check("oauth.PAR plain: requestObjectSent is false", rv.requestObjectSent === false);
    var posted = new URLSearchParams(server._captured.body);
    check("oauth.PAR plain: NO request= param", posted.get("request") === null);
    check("oauth.PAR plain: response_type bare form param present", posted.get("response_type") === "code");
    check("oauth.PAR plain: redirect_uri bare form param present", posted.get("redirect_uri") === "https://rp.example/cb");
    check("oauth.PAR plain: code_challenge_method S256 present", posted.get("code_challenge_method") === "S256");
    check("oauth.PAR plain: client_secret present", posted.get("client_secret") === "par-secret");
  } finally { server.close(); }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
