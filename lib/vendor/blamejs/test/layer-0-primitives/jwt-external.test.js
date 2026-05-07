"use strict";
/**
 * b.auth.jwt.verifyExternal — classical-alg JWT verifier.
 *
 * Covers: surface; algorithms required (no defaults — alg-confusion
 * defense); HMAC/none refused; alg-not-allowed rejected; missing
 * key-source rejected; conflicting key-source rejected; valid RS256
 * round-trip with kid match; aud/iss/exp claim validation.
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

async function run() {
  testSurface();
  await testAlgorithmsRequired();
  await testHmacRefused();
  await testNoKeySource();
  await testConflictingKeySource();
  await testRoundTripRs256();
  await testAudMismatch();
  await testExpired();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
