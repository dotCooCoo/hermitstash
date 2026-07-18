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

// ---- shared fixtures for the branch/error coverage below ----

// One RSA keypair reused across the RS256 mint/verify branch tests — RSA
// generation is the slow step and none of the branches under test depend
// on key uniqueness.
var _sharedRsaKp = null;
function _rsaKp() {
  if (!_sharedRsaKp) {
    _sharedRsaKp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });  // allow:raw-byte-literal — RSA modulus bits
  }
  return _sharedRsaKp;
}

// Public JWK for the shared RSA key, optionally tagged with a kid.
function _rsaPubJwk(kid) {
  var jwk = _rsaKp().publicKey.export({ format: "jwk" });
  if (kid) jwk.kid = kid;
  return jwk;
}

// Public EC JWK on a named curve, optionally tagged with a kid.
function _ecJwk(curve, kid) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: curve });
  var jwk = kp.publicKey.export({ format: "jwk" });
  if (kid) jwk.kid = kid;
  return jwk;
}

// Mint a valid RS256 JWS over `claims` with the shared RSA key via the real
// signer (b.auth.jws.sign derives RS256 from the RSA key type).
function _mintRs256(claims, kid) {
  var opts = { privateKey: _rsaKp().privateKey };
  if (kid) opts.kid = kid;
  return b.auth.jws.sign(claims, opts);
}

// An unsigned 3-part token — the signature segment is a placeholder for
// branches that fail BEFORE signature verification (alg / kid / kty / decode
// gates), so the signature bytes are never inspected.
function _unsigned(header, payload) {
  return _b64url(JSON.stringify(header)) + "." +
         _b64url(JSON.stringify(payload)) + "." + _b64url("sig");
}

// Wrap a fixed value in a keyResolver (keeps the closure out of a loop body).
function _constResolver(v) { return function () { return v; }; }

// Seconds-since-epoch anchor for building exp / nbf / iat claims.
var _nowSec = Math.floor(Date.now() / 1000);                                     // allow:raw-byte-literal — seconds-per-ms

// Assert verifyExternal rejects `token` under `opts` with a code matching `re`.
async function _expectCode(label, token, opts, re) {
  var threw = null;
  try { await b.auth.jwt.verifyExternal(token, opts); }
  catch (e) { threw = e; }
  check(label, threw && re.test(threw.code || ""));
}

// Assert jws.sign rejects `claims`/`opts` with a code matching `re`.
function _expectSignCode(label, claims, opts, re) {
  var threw = null;
  try { b.auth.jws.sign(claims, opts); }
  catch (e) { threw = e; }
  check(label, threw && re.test(threw.code || ""));
}

// Read the protected-header `alg` from a compact JWS.
function _hdrAlg(jws) {
  return JSON.parse(Buffer.from(jws.split(".")[0], "base64url").toString("utf8")).alg;
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

// ---- verifyExternal: token pre-flight rejections ----
// Everything refused before key resolution: bad token type/size, an
// operator alg outside the supported set, a JWE on the JWS verifier, a
// non-3-segment token, an undecodable header, a header missing alg, a crit
// header, and a token alg absent from the operator's allowed list.
async function testTokenPreflight() {
  var jwk = _rsaPubJwk("k1");
  await _expectCode("empty token → no-token",
    "", { algorithms: ["RS256"], jwks: [jwk] }, /no-token/);
  var threw = null;
  try { await b.auth.jwt.verifyExternal(12345, { algorithms: ["RS256"], jwks: [jwk] }); }
  catch (e) { threw = e; }
  check("non-string token → no-token", threw && /no-token/.test(threw.code || ""));
  await _expectCode("oversized token → token-too-large",
    "a".repeat(17000), { algorithms: ["RS256"], jwks: [jwk] }, /token-too-large/);          // allow:raw-byte-literal — exceeds 16 KiB token cap
  await _expectCode("operator lists an unsupported alg → unsupported-alg",
    "a.b.c", { algorithms: ["RS999"], jwks: [jwk] }, /unsupported-alg/);
  await _expectCode("5-segment JWE token → jwe-refused",
    "a.b.c.d.e", { algorithms: ["RS256"], jwks: [jwk] }, /jwe-refused/);
  await _expectCode("2-segment token → malformed-jwt",
    "a.b", { algorithms: ["RS256"], jwks: [jwk] }, /malformed-jwt/);
  await _expectCode("header decodes to non-JSON → malformed-jwt",
    _b64url("not json") + "." + _b64url("{}") + "." + _b64url("sig"),
    { algorithms: ["RS256"], jwks: [jwk] }, /malformed-jwt/);
  await _expectCode("header missing alg → malformed-jwt",
    _unsigned({ typ: "JWT" }, { exp: _nowSec + 300 }),                                       // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [jwk] }, /malformed-jwt/);
  await _expectCode("crit header → unknown-crit",
    _unsigned({ alg: "RS256", kid: "k1", crit: ["exp"] }, { exp: _nowSec + 300 }),           // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [jwk] }, /unknown-crit/);
  await _expectCode("token alg supported but not in allowed list → alg-not-allowed",
    _unsigned({ alg: "RS384", kid: "k1" }, { exp: _nowSec + 300 }),                          // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [jwk] }, /alg-not-allowed/);
}

// ---- verifyExternal: JWKS kid resolution ----
// Empty JWKS, no-matching-kid, and the kid-less refusal (default) vs the
// allowKidlessJwks opt-in that accepts a lone-key JWKS.
async function testKidResolution() {
  var jwkK1 = _rsaPubJwk("k1");
  await _expectCode("empty JWKS array → no-jwks-keys",
    _unsigned({ alg: "RS256", kid: "k1" }, { exp: _nowSec + 300 }),                          // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [] }, /no-jwks-keys/);
  await _expectCode("kid with no matching JWKS key → no-matching-kid",
    _unsigned({ alg: "RS256", kid: "absent" }, { exp: _nowSec + 300 }),                      // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [jwkK1] }, /no-matching-kid/);
  await _expectCode("kid-less token, multi-key JWKS → kid-required",
    _unsigned({ alg: "RS256" }, { exp: _nowSec + 300 }),                                     // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [jwkK1, _rsaPubJwk("k2")] }, /kid-required/);
  await _expectCode("kid-less token, single-key JWKS, no opt-in → kid-required",
    _unsigned({ alg: "RS256" }, { exp: _nowSec + 300 }),                                     // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [_rsaPubJwk()] }, /kid-required/);
  var rv = await b.auth.jwt.verifyExternal(
    _mintRs256({ sub: "u1", exp: _nowSec + 300 }),                                           // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [_rsaPubJwk()], allowKidlessJwks: true });
  check("kid-less single-key JWKS + allowKidlessJwks → verifies", rv.claims.sub === "u1");
}

// ---- verifyExternal: CVE-2026-22817 alg↔kty/crv cross-check ----
// The resolved JWK's key type must match the header alg BEFORE it is handed
// to node:crypto: a missing kty, an RSA alg over an EC key, and an ES256 alg
// over a P-384 key are each refused.
async function testAlgKtyCrossCheck() {
  await _expectCode("resolved JWK without kty → bad-jwk",
    _unsigned({ alg: "RS256", kid: "k1" }, { exp: _nowSec + 300 }),                          // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [{ kid: "k1" }] }, /bad-jwk/);
  await _expectCode("alg RS256 over an EC JWK → alg-kty-mismatch",
    _unsigned({ alg: "RS256", kid: "k1" }, { exp: _nowSec + 300 }),                          // allow:raw-byte-literal — 5min
    { algorithms: ["RS256"], jwks: [_ecJwk("P-256", "k1")] }, /alg-kty-mismatch/);
  await _expectCode("alg ES256 over a P-384 JWK → alg-crv-mismatch",
    _unsigned({ alg: "ES256", kid: "k1" }, { exp: _nowSec + 300 }),                          // allow:raw-byte-literal — 5min
    { algorithms: ["ES256"], jwks: [_ecJwk("P-384", "k1")] }, /alg-crv-mismatch/);
}

// ---- verifyExternal: signature rejection ----
// A byte-flipped signature over an otherwise-valid RS256 token fails
// verification.
async function testSignatureVerification() {
  var token = _mintRs256({ sub: "u1", exp: _nowSec + 300 }, "k1");                           // allow:raw-byte-literal — 5min
  var parts = token.split(".");
  // Invert the first signature byte — a leading byte carries meaningful
  // bits (unlike a trailing base64url char, whose low bits are padding and
  // can round-trip unchanged), so the tamper is deterministic.
  var sigBuf = Buffer.from(parts[2], "base64url");
  sigBuf[0] = sigBuf[0] ^ 0xff;
  var tampered = parts[0] + "." + parts[1] + "." + _b64url(sigBuf);
  await _expectCode("tampered signature → invalid-signature",
    tampered, { algorithms: ["RS256"], jwks: [_rsaPubJwk("k1")] }, /invalid-signature/);
}

// ---- verifyExternal: claim validation ----
// exp/nbf/iat time gates, the iss cross-realm refusal (including the
// array-iss CVE-2025-30144 shape and a missing iss), the sub-equality check,
// and the clockSkewMs handling — a finite skew tolerates a just-expired
// token while Infinity is refused rather than silently disabling expiry.
async function testClaimValidation() {
  var jwk = _rsaPubJwk("k1");
  await _expectCode("missing exp claim → missing-exp",
    _mintRs256({ sub: "u1" }, "k1"),
    { algorithms: ["RS256"], jwks: [jwk] }, /missing-exp/);
  await _expectCode("nbf in the future → nbf-future",
    _mintRs256({ sub: "u1", exp: _nowSec + 7200, nbf: _nowSec + 3600 }, "k1"),               // allow:raw-byte-literal — 2h/1h in seconds
    { algorithms: ["RS256"], jwks: [jwk], now: Date.now() }, /nbf-future/);
  await _expectCode("iat in the future → iat-future",
    _mintRs256({ sub: "u1", exp: _nowSec + 7200, iat: _nowSec + 3600 }, "k1"),               // allow:raw-byte-literal — 2h/1h in seconds
    { algorithms: ["RS256"], jwks: [jwk] }, /iat-future/);
  await _expectCode("issuer mismatch → iss-mismatch",
    _mintRs256({ sub: "u1", exp: _nowSec + 3600, iss: "https://evil.example" }, "k1"),       // allow:raw-byte-literal — 1h
    { algorithms: ["RS256"], jwks: [jwk], issuer: "https://idp.example.com" }, /iss-mismatch/);
  await _expectCode("array-valued iss refused → iss-mismatch",
    _mintRs256({ sub: "u1", exp: _nowSec + 3600, iss: ["https://idp.example.com", "x"] }, "k1"),  // allow:raw-byte-literal — 1h
    { algorithms: ["RS256"], jwks: [jwk], issuer: "https://idp.example.com" }, /iss-mismatch/);
  await _expectCode("missing iss when issuer expected → iss-mismatch",
    _mintRs256({ sub: "u1", exp: _nowSec + 3600 }, "k1"),                                    // allow:raw-byte-literal — 1h
    { algorithms: ["RS256"], jwks: [jwk], issuer: "https://idp.example.com" }, /iss-mismatch/);
  await _expectCode("subject mismatch → sub-mismatch",
    _mintRs256({ sub: "u1", exp: _nowSec + 3600 }, "k1"),                                    // allow:raw-byte-literal — 1h
    { algorithms: ["RS256"], jwks: [jwk], subject: "someone-else" }, /sub-mismatch/);
  var tolerated = await b.auth.jwt.verifyExternal(
    _mintRs256({ sub: "u1", exp: _nowSec - 10 }, "k1"),                                      // allow:raw-byte-literal — 10s past
    { algorithms: ["RS256"], jwks: [jwk], clockSkewMs: 60000 });                             // allow:raw-byte-literal — 60s skew in ms
  check("finite clockSkewMs tolerates a just-expired token", tolerated.claims.sub === "u1");
  await _expectCode("Infinity clockSkewMs refused (cannot disable expiry) → bad-clock-skew",
    _mintRs256({ sub: "u1", exp: _nowSec - 3600 }, "k1"),                                    // allow:raw-byte-literal — 1h past
    { algorithms: ["RS256"], jwks: [jwk], clockSkewMs: Infinity }, /bad-clock-skew/);
}

// ---- verifyExternal: keyResolver value shapes ----
// A keyResolver may return a KeyObject, a public JWK, a PEM string, or a PEM
// Buffer — each imports and verifies. (PEM / KeyObject / Buffer carry no kty
// surface so the alg↔kty cross-check applies to the JWK shape only.)
async function testKeyResolverShapes() {
  var kp = _rsaKp();
  var pubPem = kp.publicKey.export({ type: "spki", format: "pem" });
  var token = _mintRs256({ sub: "u1", exp: _nowSec + 300 }, "k1");                           // allow:raw-byte-literal — 5min
  var shapes = [
    { name: "KeyObject",  val: kp.publicKey },
    { name: "public JWK", val: kp.publicKey.export({ format: "jwk" }) },
    { name: "PEM string", val: pubPem },
    { name: "PEM Buffer", val: Buffer.from(pubPem) },
  ];
  for (var i = 0; i < shapes.length; i++) {
    var rv = await b.auth.jwt.verifyExternal(token, {
      algorithms:  ["RS256"],
      keyResolver: _constResolver(shapes[i].val),
    });
    check("keyResolver returns " + shapes[i].name + " → verifies", rv.claims.sub === "u1");
  }
}

// ---- verifyExternal: keyResolver rejections ----
async function testKeyResolverRejections() {
  var token = _unsigned({ alg: "RS256" }, { exp: _nowSec + 300 });                           // allow:raw-byte-literal — 5min
  await _expectCode("keyResolver returns null → no-key",
    token, { algorithms: ["RS256"], keyResolver: _constResolver(null) }, /no-key/);
  await _expectCode("keyResolver returns a non-key value → bad-key-shape",
    token, { algorithms: ["RS256"], keyResolver: _constResolver(42) }, /bad-key-shape/);
  await _expectCode("keyResolver throws → key-resolver-failed",
    token, { algorithms: ["RS256"], keyResolver: function () { throw new Error("boom"); } },
    /key-resolver-failed/);
  await _expectCode("keyResolver returns unparseable PEM string → bad-pem",
    token, { algorithms: ["RS256"], keyResolver: _constResolver("not-a-pem") }, /bad-pem/);
  await _expectCode("keyResolver returns unparseable PEM Buffer → bad-pem",
    token, { algorithms: ["RS256"], keyResolver: _constResolver(Buffer.from("not-a-pem")) },
    /bad-pem/);
}

// ---- jws.sign: key import + alg-derivation branches ----
// The private-key importer (missing / unparseable / non-key / JWK) and the
// alg resolver (default-from-key for rsa-pss, unsupported EC curve, non-JWS
// key type, an explicit non-classical alg, and an explicit compatible alg).
async function testJwsSignKeyImport() {
  _expectSignCode("jws.sign: missing privateKey → sign-no-key",
    { sub: "u" }, {}, /sign-no-key/);
  _expectSignCode("jws.sign: unparseable PEM key → sign-bad-key",
    { sub: "u" }, { privateKey: "not-a-pem" }, /sign-bad-key/);
  _expectSignCode("jws.sign: non-key value → sign-bad-key",
    { sub: "u" }, { privateKey: 12345 }, /sign-bad-key/);
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  check("jws.sign: private JWK accepted, derives ES256",
    _hdrAlg(b.auth.jws.sign({ sub: "u" }, { privateKey: ec.privateKey.export({ format: "jwk" }) })) === "ES256");
  _expectSignCode("jws.sign: EC secp256k1 has no JWS alg → sign-key-unsupported",
    { sub: "u" },
    { privateKey: nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" }).privateKey },
    /sign-key-unsupported/);
  var pss = nodeCrypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 });              // allow:raw-byte-literal — RSA modulus bits
  check("jws.sign: rsa-pss key defaults to PS256",
    _hdrAlg(b.auth.jws.sign({ sub: "u" }, { privateKey: pss.privateKey })) === "PS256");
  _expectSignCode("jws.sign: x25519 (non-signing) key → sign-key-unsupported",
    { sub: "u" }, { privateKey: nodeCrypto.generateKeyPairSync("x25519").privateKey },
    /sign-key-unsupported/);
  _expectSignCode("jws.sign: explicit non-classical alg → sign-alg-unsupported",
    { sub: "u" }, { privateKey: _rsaKp().privateKey, alg: "ML-DSA-65" }, /sign-alg-unsupported/);
  check("jws.sign: explicit compatible alg RS512 honored",
    _hdrAlg(b.auth.jws.sign({ sub: "u" }, { privateKey: _rsaKp().privateKey, alg: "RS512" })) === "RS512");
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
  await testTokenPreflight();
  await testKidResolution();
  await testAlgKtyCrossCheck();
  await testSignatureVerification();
  await testClaimValidation();
  await testKeyResolverShapes();
  await testKeyResolverRejections();
  await testJwsSignKeyImport();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
