// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.fedcm + b.dbsc — federated credentials + device-bound session
 * credentials. Browser-side identity primitives.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

// ---- FedCM ----

function testFedcmWellKnown() {
  var wk = b.fedcm.wellKnown({ provider_urls: ["https://idp.example/c.json"] });
  check("wellKnown returns provider_urls",
    Array.isArray(wk.provider_urls) && wk.provider_urls[0] === "https://idp.example/c.json");
  var threw = null;
  try { b.fedcm.wellKnown({ provider_urls: ["http://insecure"] }); }
  catch (e) { threw = e.code; }
  check("non-https provider_url refused", threw === "fedcm/bad-provider-url");
}

function testFedcmConfig() {
  var cfg = b.fedcm.config({
    accounts_endpoint:        "/fedcm/accounts",
    client_metadata_endpoint: "/fedcm/cm",
    id_assertion_endpoint:    "/fedcm/idassert",
    login_url:                "https://idp.example/login",
    branding: { name: "IdP", background_color: "#000", color: "#fff" },
  });
  check("config has required endpoints",
    cfg.accounts_endpoint === "/fedcm/accounts" &&
    cfg.id_assertion_endpoint === "/fedcm/idassert");
  check("config preserves branding", cfg.branding.name === "IdP");
}

function testFedcmAccounts() {
  var resp = b.fedcm.accountsResponse({
    accounts: [
      { id: "1", name: "Alice", email: "alice@example.com" },
      { id: "2", name: "Bob",   email: "bob@example.com", approved_clients: ["rp.example"] },
    ],
  });
  check("accounts response shape", resp.accounts.length === 2);
  check("approved_clients preserved",
    Array.isArray(resp.accounts[1].approved_clients));
  var threw = null;
  try { b.fedcm.accountsResponse({ accounts: [{ name: "no id" }] }); }
  catch (e) { threw = e.code; }
  check("missing account id refused", threw === "fedcm/bad-account");
}

function testFedcmIdAssertion() {
  var resp = b.fedcm.idAssertionResponse({ token: "eyJhbGc..." });
  check("idAssertionResponse echoes token", resp.token === "eyJhbGc...");
  var threw = null;
  try { b.fedcm.idAssertionResponse({}); }
  catch (e) { threw = e.code; }
  check("missing token refused", threw === "fedcm/missing-token");
}

function testFedcmClientMetadata() {
  var resp = b.fedcm.clientMetadataResponse({
    privacy_policy_url:   "https://rp.example/privacy",
    terms_of_service_url: "https://rp.example/tos",
  });
  check("clientMetadataResponse echoes URLs",
    resp.privacy_policy_url === "https://rp.example/privacy" &&
    resp.terms_of_service_url === "https://rp.example/tos");
  var threw = null;
  try {
    b.fedcm.clientMetadataResponse({
      privacy_policy_url:   "http://insecure",
      terms_of_service_url: "https://rp.example/tos",
    });
  } catch (e) { threw = e.code; }
  check("non-https privacy_policy_url refused", threw === "fedcm/bad-privacy-url");
}

function testFedcmDisconnect() {
  var resp = b.fedcm.disconnectResponse({ account_id: "1234" });
  check("disconnectResponse echoes account_id", resp.account_id === "1234");
  var threw = null;
  try { b.fedcm.disconnectResponse({}); }
  catch (e) { threw = e.code; }
  check("missing account_id refused", threw === "fedcm/missing-account-id");
}

function testFedcmErrorClass() {
  // Surface the error class for catch-binding patterns.
  check("FedcmError is a class", typeof b.fedcm.FedcmError === "function");
  var e = new b.fedcm.FedcmError("fedcm/test", "synthetic");
  check("FedcmError instances carry code", e.code === "fedcm/test");
}

function testDbscErrorClass() {
  check("DbscError is a class", typeof b.dbsc.DbscError === "function");
  var e = new b.dbsc.DbscError("dbsc/test", "synthetic");
  check("DbscError instances carry code", e.code === "dbsc/test");
}

// ---- DBSC ----

function _newSecret() { return nodeCrypto.randomBytes(32); }

// Sign a real ES256 DBSC binding-assertion (header carries the embedded
// binding-key jwk; signature is the JWT raw r||s form the verifier expects).
// Shared by the round-trip + freshness tests so the DER→raw conversion lives
// in one place.
function _signEs256Assertion(kp, payload) {
  var jwk = kp.publicKey.export({ format: "jwk" });
  var header  = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT", jwk: jwk }), "utf8").toString("base64url");
  var payloadB = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  var signingInput = header + "." + payloadB;
  var derSig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "utf8"), kp.privateKey);
  // DER SEQUENCE(INTEGER r, INTEGER s) → fixed-width raw r||s.
  var off = 2;
  if (derSig[1] & 0x80) off = 2 + (derSig[1] & 0x7f);
  var rLen = derSig[off + 1];
  var r = derSig.slice(off + 2, off + 2 + rLen);
  off = off + 2 + rLen;
  var sLen = derSig[off + 1];
  var s = derSig.slice(off + 2, off + 2 + sLen);
  if (r.length > 32 && r[0] === 0) r = r.slice(1);
  if (s.length > 32 && s[0] === 0) s = s.slice(1);
  var raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length);
  s.copy(raw, 64 - s.length);
  return signingInput + "." + raw.toString("base64url");
}

function testDbscChallengeRoundtrip() {
  var secret = _newSecret();
  var c = b.dbsc.challenge({ secretKey: secret });
  check("challenge string is non-empty",  typeof c.challenge === "string" && c.challenge.length > 0);
  check("challenge has expiresAt",        typeof c.expiresAt === "number" && c.expiresAt > Date.now());
  var v = b.dbsc.verifyChallenge(c.challenge, { secretKey: secret });
  check("verifyChallenge accepts same secret", v.valid === true);
}

function testDbscChallengeWrongSecret() {
  var s1 = _newSecret();
  var s2 = _newSecret();
  var c = b.dbsc.challenge({ secretKey: s1 });
  var threw = null;
  try { b.dbsc.verifyChallenge(c.challenge, { secretKey: s2 }); }
  catch (e) { threw = e.code; }
  check("wrong-secret challenge refused", threw === "dbsc/bad-mac");
}

function testDbscChallengeExpired() {
  var secret = _newSecret();
  var c = b.dbsc.challenge({ secretKey: secret, ttlMs: 1 });
  // Manually wait > 1ms by re-using the issuesAt vs expiresAt math.
  // Synthesize an already-expired challenge instead of sleeping.
  var msg  = Buffer.from("nonce", "utf8").toString("base64") + "." + (Date.now() - 1000);
  var mac  = nodeCrypto.createHmac("sha3-512", secret).update(msg).digest("base64");
  var stale = msg + "." + mac;
  var threw = null;
  try { b.dbsc.verifyChallenge(stale, { secretKey: secret }); }
  catch (e) { threw = e.code; }
  check("expired challenge refused", threw === "dbsc/expired");
  void c;
}

function testDbscBindingAssertionAlgConfusion() {
  var secret = _newSecret();
  // Forge a JWT with alg=HS256 — DBSC must refuse.
  var header  = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" }), "utf8").toString("base64url");
  var payload = Buffer.from(JSON.stringify({ aud: "https://rp.example", iat: Math.floor(Date.now() / 1000) }), "utf8").toString("base64url");
  var fakeJwt = header + "." + payload + ".signature";
  var threw = null;
  try { b.dbsc.verifyBindingAssertion(fakeJwt, { secretKey: secret, expectedAud: "https://rp.example" }); }
  catch (e) { threw = e.code; }
  check("HS256 binding-assertion refused (alg-confusion)", threw === "dbsc/bad-alg");
}

function testDbscBindingAssertionMissingJwk() {
  var secret = _newSecret();
  var header  = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" }), "utf8").toString("base64url");
  var payload = Buffer.from(JSON.stringify({ aud: "https://rp.example" }), "utf8").toString("base64url");
  var fakeJwt = header + "." + payload + ".sig";
  var threw = null;
  try { b.dbsc.verifyBindingAssertion(fakeJwt, { secretKey: secret, expectedAud: "https://rp.example" }); }
  catch (e) { threw = e.code; }
  check("ES256 without embedded jwk refused", threw === "dbsc/no-jwk");
}

function testDbscBindingAssertionRoundtrip() {
  // Generate a real ECDSA-P256 key, sign a JWT properly, verify.
  var secret = _newSecret();
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var jwt = _signEs256Assertion(kp, { aud: "https://rp.example", iat: Math.floor(Date.now() / 1000) });
  var v = b.dbsc.verifyBindingAssertion(jwt, {
    secretKey: secret, expectedAud: "https://rp.example",
  });
  check("ES256 binding-assertion verifies", v.valid === true);
  check("verify returns JWK thumbprint",    typeof v.jkt === "string" && v.jkt.length > 0);
}

function testDbscBindingAssertionFutureIat() {
  // Freshness fail-open: an assertion whose `iat` is far in the FUTURE must
  // be refused. The stale check only rejects a too-OLD iat
  // (Date.now() - iat*1000 > maxAge); a forward-dated iat makes that
  // difference negative, so it never trips and the assertion stays "fresh"
  // indefinitely — defeating the maxAge replay bound. Siblings bound the
  // future too (b.auth.jwt.verifyExternal → iat-future; dpop → ±window).
  var secret = _newSecret();
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var future = Math.floor(Date.now() / 1000) + 100000000;   // ~3 years ahead
  var jwt = _signEs256Assertion(kp, { aud: "https://rp.example", iat: future });
  var threw = null;
  try {
    b.dbsc.verifyBindingAssertion(jwt, { secretKey: secret, expectedAud: "https://rp.example" });
  } catch (e) { threw = e.code; }
  check("far-future iat binding-assertion refused", threw === "dbsc/iat-future");
}

function run() {
  testFedcmWellKnown();
  testFedcmConfig();
  testFedcmAccounts();
  testFedcmIdAssertion();
  testFedcmClientMetadata();
  testFedcmDisconnect();
  testFedcmErrorClass();
  testDbscErrorClass();
  testDbscChallengeRoundtrip();
  testDbscChallengeWrongSecret();
  testDbscChallengeExpired();
  testDbscBindingAssertionAlgConfusion();
  testDbscBindingAssertionMissingJwk();
  testDbscBindingAssertionRoundtrip();
  testDbscBindingAssertionFutureIat();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
