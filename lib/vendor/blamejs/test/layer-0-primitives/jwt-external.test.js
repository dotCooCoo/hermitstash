// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.jwt.verifyExternal — classical-alg JWT verifier — and
 * b.auth.jws.sign, its signer counterpart.
 *
 * Covers verify: surface; algorithms required (no defaults — alg-confusion
 * defense); HMAC/none refused; alg-not-allowed rejected; missing
 * key-source rejected; conflicting key-source rejected; valid RS256
 * round-trip with kid match; aud/iss/exp claim validation.
 *
 * Covers sign: ES256 / EdDSA / RS256 round-trip back through verifyExternal;
 * alg derived from the key; none/HMAC/alg-key-mismatch refused; a
 * caller-supplied header.alg cannot override the signer-derived alg;
 * header.b64 / header.crit refused (RFC 7797 / RFC 7515 §4.1.11 —
 * semantics-changing members the signer does not implement).
 */

var helpers = require("../helpers");
var b           = helpers.b;
var check       = helpers.check;
var nodeCrypto  = require("crypto");

function _b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _signJwt(privateKey, header, payload) {
  var h = _b64url(JSON.stringify(header));
  var p = _b64url(JSON.stringify(payload));
  var input = h + "." + p;
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), {
    key:     privateKey,
    padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
  });
  return input + "." + _b64url(sig);
}

function _rsaPair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,                                                         // allow:raw-byte-literal — RSA modulus bits
    publicKeyEncoding:  { type: "spki",  format: "jwk" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function testSurface() {
  check("auth.jwt.verifyExternal exposed",
        typeof b.auth.jwt.verifyExternal === "function");
}

async function testAlgorithmsRequired() {
  var threw = null;
  try { await b.auth.jwt.verifyExternal("a.b.c", { jwks: [] }); }
  catch (e) { threw = e; }
  check("algorithms required (no defaults — alg-confusion defense)",
        threw && /algorithms-required/.test(threw.code || ""));
}

async function testHmacRefused() {
  var threw = null;
  try { await b.auth.jwt.verifyExternal("a.b.c", { algorithms: ["HS256"], jwks: [] }); }
  catch (e) { threw = e; }
  check("HS256 refused (alg-confusion vector vs JWKS public-key trust)",
        threw && /refused-alg/.test(threw.code || ""));

  var threwNone = null;
  try { await b.auth.jwt.verifyExternal("a.b.c", { algorithms: ["none"], jwks: [] }); }
  catch (e) { threwNone = e; }
  check("'none' refused",
        threwNone && /refused-alg/.test(threwNone.code || ""));
}

async function testNoKeySource() {
  var threw = null;
  try { await b.auth.jwt.verifyExternal("a.b.c", { algorithms: ["RS256"] }); }
  catch (e) { threw = e; }
  check("no key source → no-key-source",
        threw && /no-key-source/.test(threw.code || ""));
}

async function testConflictingKeySource() {
  var threw = null;
  try {
    await b.auth.jwt.verifyExternal("a.b.c", {
      algorithms:  ["RS256"],
      jwks:        [],
      keyResolver: function () { return null; },
    });
  } catch (e) { threw = e; }
  check("two key sources → conflicting-key-source",
        threw && /conflicting-key-source/.test(threw.code || ""));
}

async function testRoundTripRs256() {
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1", use: "sig", alg: "RS256" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  var token = _signJwt(keys.privateKey,
    { alg: "RS256", typ: "JWT", kid: "k1" },
    { sub: "u1", aud: "api://my-api", iss: "https://idp.example.com",
      exp: nowSec + 300, iat: nowSec });                                         // allow:raw-byte-literal — 5min token lifetime in seconds

  var rv = await b.auth.jwt.verifyExternal(token, {
    algorithms: ["RS256"],
    jwks:       [jwk],
    audience:   "api://my-api",
    issuer:     "https://idp.example.com",
  });
  check("valid RS256 token round-trips with kid match",
        rv && rv.claims && rv.claims.sub === "u1");
}

async function testAudMismatch() {
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  var token = _signJwt(keys.privateKey,
    { alg: "RS256", kid: "k1" },
    { sub: "u1", aud: "api://other", exp: nowSec + 300 });                       // allow:raw-byte-literal — 5min

  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["RS256"], jwks: [jwk], audience: "api://my-api",
    });
  } catch (e) { threw = e; }
  check("audience mismatch → aud-mismatch",
        threw && /aud-mismatch/.test(threw.code || ""));
}

async function testExpired() {
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  var token = _signJwt(keys.privateKey,
    { alg: "RS256", kid: "k1" },
    { sub: "u1", exp: nowSec - 600 });                                           // allow:raw-byte-literal — 10min in past

  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["RS256"], jwks: [jwk],
    });
  } catch (e) { threw = e; }
  check("expired token → expired",
        threw && /expired/.test(threw.code || ""));
}

// b.auth.jws.sign — the classical-JWS signer (inverse of verifyExternal).
// A token it mints must round-trip back through verifyExternal across the
// alg families, the alg must be derived from the key, and `none`/HMAC/
// alg-key-mismatch are refused.
async function testJwsSignSurface() {
  check("auth.jws.sign exposed", typeof b.auth.jws.sign === "function");
}

async function testJwsSignRoundTrip() {
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  // (key generator, public JWK with kid, expected alg)
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  var rsa = _rsaPair();
  var cases = [
    { name: "ES256", priv: ec.privateKey,  jwk: ec.publicKey.export({ format: "jwk" }),  alg: "ES256" },
    { name: "EdDSA", priv: ed.privateKey,  jwk: ed.publicKey.export({ format: "jwk" }),  alg: "EdDSA" },
    { name: "RS256", priv: rsa.privateKey, jwk: rsa.publicKey,                            alg: "RS256" },
  ];
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var jwk = Object.assign({}, c.jwk, { kid: "k1", use: "sig", alg: c.alg });
    var token = b.auth.jws.sign(
      { sub: "u1", iss: "client", aud: "https://as.example.com", exp: nowSec + 300, iat: nowSec },  // allow:raw-byte-literal — 5min
      { privateKey: c.priv, kid: "k1", typ: "JWT" });
    var hdr = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    check("jws.sign[" + c.name + "]: alg inferred from key", hdr.alg === c.alg);
    check("jws.sign[" + c.name + "]: typ + kid set", hdr.typ === "JWT" && hdr.kid === "k1");
    var rv = await b.auth.jwt.verifyExternal(token, {
      algorithms: [c.alg], jwks: [jwk], audience: "https://as.example.com", issuer: "client" });
    check("jws.sign[" + c.name + "]: round-trips through verifyExternal", rv.claims.sub === "u1");
  }
}

async function testJwsSignRefusals() {
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var e1 = null;
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, alg: "none" }); } catch (e) { e1 = e; }
  check("jws.sign: alg 'none' refused", e1 && /sign-alg-refused/.test(e1.code || ""));
  var e2 = null;
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, alg: "HS256" }); } catch (e) { e2 = e; }
  check("jws.sign: HMAC alg refused", e2 && /sign-alg-refused/.test(e2.code || ""));
  var e3 = null;
  // a P-256 key cannot produce RS256.
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, alg: "RS256" }); } catch (e) { e3 = e; }
  check("jws.sign: alg incompatible with key refused", e3 && /sign-alg-key-mismatch/.test(e3.code || ""));
  var e4 = null;
  try { b.auth.jws.sign("not-an-object", { privateKey: ec.privateKey }); } catch (e) { e4 = e; }
  check("jws.sign: non-object claims refused", e4 && /sign-bad-claims/.test(e4.code || ""));
  var e5 = null;
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, bogus: 1 }); } catch (e) { e5 = e; }
  check("jws.sign: unknown opt refused (config-time)", e5 !== null);
}

// A caller-supplied header.alg can never override the signer-derived alg —
// the canonical alg-substitution shape is closed.
async function testJwsSignHeaderCannotOverrideAlg() {
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var token = b.auth.jws.sign({ sub: "u" }, {
    privateKey: ec.privateKey, header: { alg: "HS256", foo: "bar" } });
  var hdr = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
  check("jws.sign: header.alg override ignored (signer sets ES256)", hdr.alg === "ES256");
  check("jws.sign: extra header members pass through", hdr.foo === "bar");
}

// `b64` (RFC 7797 unencoded payload) changes the signing input and `crit`
// (RFC 7515 §4.1.11) promises extension semantics the signer does not
// implement — passing either through would mint a JWS whose header claims
// semantics its signature was not computed under. Both refused.
async function testJwsSignB64CritRefused() {
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var e1 = null;
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, header: { b64: false } }); }
  catch (e) { e1 = e; }
  check("jws.sign: header.b64 refused (RFC 7797 not implemented)",
        e1 && /sign-unsupported-header/.test(e1.code || ""));
  var e2 = null;
  try { b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey, header: { crit: ["exp"] } }); }
  catch (e) { e2 = e; }
  check("jws.sign: header.crit refused (no critical extensions implemented)",
        e2 && /sign-unsupported-header/.test(e2.code || ""));
  var e3 = null;
  try {
    b.auth.jws.sign({ sub: "u" }, {
      privateKey: ec.privateKey, header: { b64: true, crit: ["b64"] } });
  } catch (e) { e3 = e; }
  check("jws.sign: b64:true + crit:['b64'] refused too (no silent pass on the 'harmless' spelling)",
        e3 && /sign-unsupported-header/.test(e3.code || ""));
}

async function run() {
  testSurface();
  await testAlgorithmsRequired();
  await testHmacRefused();
  await testNoKeySource();
  await testConflictingKeySource();
  await testRoundTripRs256();
  await testAudMismatch();
  await testExpired();
  await testJwsSignSurface();
  await testJwsSignRoundTrip();
  await testJwsSignRefusals();
  await testJwsSignHeaderCannotOverrideAlg();
  await testJwsSignB64CritRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
