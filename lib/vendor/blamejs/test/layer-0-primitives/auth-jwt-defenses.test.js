// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Cross-cutting JWT defenses landed in 0.9.57:
 *
 *   CVE-2026-22817 — alg/kty confusion (RS256→HS256, ES256↔RSA, etc.)
 *   CVE-2026-23552 — cross-realm JWT acceptance (constant-time iss)
 *   Alg-allowlist gate (CWE-347 / CWE-757) — unknown-alg paths skipping verify
 *
 * Plus the larger AUTH-2…AUTH-36 findings closed in the same batch:
 *
 *   AUTH-2  — verifyIdToken JWE refusal
 *   AUTH-3  — verifyIdToken alg/kty cross-check
 *   AUTH-4  — jwt-external alg/kty cross-check
 *   AUTH-5  — oid4vci proof JWT crit refusal + alg/kty
 *   AUTH-6  — oid4vci access-token single-use
 *   AUTH-7  — exchangeToken subject/actor URN allowlist
 *   AUTH-8  — verifyBackchannelLogoutToken atomicReplayStore
 *   AUTH-9  — federation buildTrustChain cycle guard
 *   AUTH-10 — federation kid-less JWKS refusal
 *   AUTH-13 — pollDeviceCode device_code length cap
 *   AUTH-14 — DPoP nonce timingSafeEqual compare
 *   AUTH-15 — DPoP middleware comma-joined refusal
 *   AUTH-16 — AAL.AMR.WEBAUTHN → "hwk"
 *   AUTH-17 — PRM HTTPS enforcement on authorizationServers
 *   AUTH-18 — PRM signed_metadata emission
 *   AUTH-19 — FAL2 requires injection-protection
 *   AUTH-20 — SD-JWT VC typ refusal
 *   AUTH-21 — SD-JWT VC crit refusal
 *   AUTH-22 — CIBA parseNotification lowercase-only auth header
 *   AUTH-23 — frontchannel logout iss compare timing-safe
 *   AUTH-27 — passkey.compareBackupState helper
 *   AUTH-28 — passkey extensions allowlist
 *   AUTH-29 — passkey PRF salt length cap
 *   AUTH-31 — pollDeviceCode minimum interval 5s (RFC 8628 §3.4)
 *   AUTH-35 — verifyBackchannelLogoutToken iat freshness
 *   AUTH-36 — DPoP middleware shutdown / revoke hooks
 */

var helpers = require("../helpers");
var b           = helpers.b;
var check       = helpers.check;
var nodeCrypto  = require("crypto");

function _b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _signJwt(privateKey, header, payload, padding) {
  var h = _b64url(JSON.stringify(header));
  var p = _b64url(JSON.stringify(payload));
  var input = h + "." + p;
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), {
    key:     privateKey,
    padding: padding || nodeCrypto.constants.RSA_PKCS1_PADDING,
  });
  return input + "." + _b64url(sig);
}

function _rsaPair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,                                                         // allow:raw-byte-literal — RSA modulus
    publicKeyEncoding:  { type: "spki",  format: "jwk" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _ecPair(curve) {
  return nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: curve,
    publicKeyEncoding:  { type: "spki",  format: "jwk" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

// -------- Core b.auth.jwt (PQC framework signer) helpers --------
// ML-DSA-87 keygen is available on the Node 24 CI floor; SLH-DSA keygen is
// Node-26+ (see auth-status-list.test.js), so the core round-trips below sign
// with ML-DSA-87 and only NAME SLH-DSA-SHAKE-256f in headers/allowlists.
function _mlPair() { return nodeCrypto.generateKeyPairSync("ml-dsa-87"); }

function _b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// _rawJws — build a compact JWS with a caller-chosen header, so a test can
// forge the header.alg/key divergence that the shipped sign() now refuses to
// emit. Signs with null digest (KeyObject drives the real algorithm), exactly
// as lib/auth/jwt.js does.
function _rawJws(privateKey, header, payload) {
  var input = _b64urlJson(header) + "." + _b64urlJson(payload);
  var sig = nodeCrypto.sign(null, Buffer.from(input, "ascii"), privateKey);
  return input + "." + Buffer.from(sig).toString("base64url");
}

var _NOW_MS  = 1700000000000;                                                    // allow:raw-byte-literal — fixed test clock (epoch ms)
var _NOW_SEC = 1700000000;                                                       // allow:raw-byte-literal — same instant, seconds

// -------- CVE-2026-22817 — alg/kty cross-check (jwt-external) --------

async function testAlgKtyMismatchRsaWithEs256() {
  // Attacker-controlled token declares alg=ES256 but JWKS publishes an
  // RSA-kty JWK under the same kid. Without _assertAlgKtyMatch, the
  // verifier would attempt EC verify against an RSA public key and
  // either always-fail or panic — both lousy outcomes. With the helper,
  // the alg-kty-mismatch fires BEFORE node:crypto.verify.
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  // Sign the token with RS256 but declare alg ES256 in header. The
  // verifier rejects on the cross-check before signature even runs.
  var token = _signJwt(keys.privateKey, { alg: "ES256", kid: "k1" }, { sub: "u1", exp: nowSec + 300 });   // allow:raw-byte-literal — 5min lifetime
  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["ES256"], jwks: [jwk],
    });
  } catch (e) { threw = e; }
  check("CVE-2026-22817 — RSA JWK + ES256 alg refused (alg-kty-mismatch)",
        threw && /alg-kty-mismatch|alg-crv-mismatch/.test(threw.code || ""));
}

async function testAlgKtyMismatchEcCurveConfusion() {
  // ES384 declared in header but JWKS has a P-256 EC JWK — curve
  // confusion fires alg-crv-mismatch.
  var keys = _ecPair("P-256");
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  var token = _signJwt(keys.privateKey, { alg: "ES384", kid: "k1" }, { sub: "u1", exp: nowSec + 300 });   // allow:raw-byte-literal — 5min
  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["ES384"], jwks: [jwk],
    });
  } catch (e) { threw = e; }
  check("CVE-2026-22817 — EC curve confusion refused (alg-crv-mismatch)",
        threw && /alg-(kty|crv)-mismatch/.test(threw.code || ""));
}

// -------- CVE-2026-23552 — constant-time iss compare --------

async function testCrossRealmIssRefused() {
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal — seconds-per-ms
  // Token issued by realm-A; verifier configured for realm-B. Must
  // surface as iss-mismatch (CVE-2026-23552) — distinct from
  // bad-signature.
  var token = _signJwt(keys.privateKey,
    { alg: "RS256", kid: "k1" },
    { sub: "u1", aud: "api", iss: "https://idp-a.example.com", exp: nowSec + 300 });   // allow:raw-byte-literal
  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["RS256"], jwks: [jwk],
      issuer:     "https://idp-b.example.com",
    });
  } catch (e) { threw = e; }
  check("CVE-2026-23552 — cross-realm iss refused as iss-mismatch (distinct from sig)",
        threw && /iss-mismatch/.test(threw.code || ""));
}

// -------- Alg-allowlist gate — unknown alg refused before key lookup --------

async function testUnknownAlgRefusedBeforeLookup() {
  // Caller's allowlist is ES256 only; token declares HS256. Verifier
  // must refuse on the allowlist gate WITHOUT touching the JWKS source.
  var keys = _rsaPair();
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);                                    // allow:raw-byte-literal
  var token = _signJwt(keys.privateKey,
    { alg: "HS256", kid: "k1" },
    { sub: "u1", exp: nowSec + 300 });                                           // allow:raw-byte-literal
  var threw = null;
  try {
    await b.auth.jwt.verifyExternal(token, {
      algorithms: ["ES256"], jwks: [jwk],
    });
  } catch (e) { threw = e; }
  // HS256 is in REFUSED_ALGS so the operator-allowlist refusal fires
  // FIRST; but the underlying mechanic — token alg refused before key
  // resolution — is what the alg-allowlist gate (CWE-347 / CWE-757) closes.
  check("alg-allowlist gate — token alg refused before key lookup",
        threw && /alg-not-allowed|refused-alg/.test(threw.code || ""));
}

// -------- AUTH-16 — AAL.AMR.WEBAUTHN → "hwk" --------

function testAalAmrWebauthnIsHwk() {
  check("AUTH-16 — AAL.AMR.WEBAUTHN now maps to 'hwk' (was 'fido-u2f')",
        b.auth.aal.AMR.WEBAUTHN === "hwk");
  check("AUTH-16 — AAL.AMR.PASSKEY remains 'passkey'",
        b.auth.aal.AMR.PASSKEY === "passkey");
}

// -------- AUTH-19 — FAL2 requires injection-protection --------

function testFal2RequiresInjectionProtection() {
  // Back-channel + replayProtected alone (no encryption, no
  // backChannelAuthenticated) is NOT FAL2 — downgrades to FAL1 per
  // NIST 800-63C-4 §5.2.
  var f = b.auth.fal.fromAssertion({
    channel: "back", replayProtected: true, hokBinding: null,
  });
  check("AUTH-19 — back-channel + replay alone is FAL1 (no injection-protection)",
        f === "FAL1");
  // backChannelAuthenticated upgrades to FAL2.
  var f2 = b.auth.fal.fromAssertion({
    channel: "back", replayProtected: true, backChannelAuthenticated: true, hokBinding: null,
  });
  check("AUTH-19 — back-channel + replay + backChannelAuthenticated is FAL2",
        f2 === "FAL2");
  // encrypted alone (front-channel) also satisfies FAL2.
  var f3 = b.auth.fal.fromAssertion({
    channel: "front", encrypted: true, replayProtected: true, hokBinding: null,
  });
  check("AUTH-19 — encrypted front-channel + replay is FAL2",
        f3 === "FAL2");
}

// -------- AUTH-27 — passkey.compareBackupState --------

function testPasskeyCompareBackupState() {
  check("AUTH-27 — compareBackupState exposed",
        typeof b.auth.passkey.compareBackupState === "function");

  // Same state → ok
  var same = b.auth.passkey.compareBackupState(
    { backupEligible: true,  backupState: true  },
    { backupEligible: true,  backupState: true  }
  );
  check("AUTH-27 — same backup-state is 'ok'", same.verdict === "ok");

  // BE off → on (suspicious)
  var beOn = b.auth.passkey.compareBackupState(
    { backupEligible: false, backupState: false },
    { backupEligible: true,  backupState: false }
  );
  check("AUTH-27 — BE-flipped-on detected",
        beOn.verdict === "be-flipped-on");

  // BS off → on (legitimate but audit-worthy)
  var bsOn = b.auth.passkey.compareBackupState(
    { backupEligible: true,  backupState: false },
    { backupEligible: true,  backupState: true  }
  );
  check("AUTH-27 — BS-flipped-on detected",
        bsOn.verdict === "bs-flipped-on");
}

// -------- AUTH-29 — PRF salt length cap (32 bytes) --------

function testPrfSaltLengthCap() {
  var fortyTwoByteSalt = Buffer.alloc(42).fill(1);
  var threw = null;
  try {
    b.auth.passkey.extensions.prf({ eval: { first: fortyTwoByteSalt } });
  } catch (e) { threw = e; }
  check("AUTH-29 — PRF eval.first > 32 bytes refused",
        threw && /extension-input-too-large/.test(threw.code || ""));

  // 32-byte salt passes.
  var ok = b.auth.passkey.extensions.prf({ eval: { first: Buffer.alloc(32).fill(2) } });
  check("AUTH-29 — PRF eval.first at 32-byte cap accepted",
        ok && ok.prf && typeof ok.prf.eval.first === "string");
}

// -------- AUTH-28 — passkey extensions allowlist --------

async function testPasskeyExtensionsAllowlist() {
  // The startRegistration / startAuthentication / conditionalAuthOptions
  // surfaces all funnel `opts.extensions` through _validateExtensions.
  // Reach the allowlist via the conditionalAuthOptions path (cheapest
  // — no vendor I/O beyond synchronous shape parsing). Unknown
  // extension key must refuse with a specific error code.
  var threw = null;
  try {
    await b.auth.passkey.conditionalAuthOptions({
      rpId: "example.com",
      extensions: { "evil": { foo: "bar" } },
    });
  } catch (e) { threw = e; }
  check("AUTH-28 — unknown passkey extension key refused",
        threw && /unknown-extension|bad-extensions/.test(threw.code || ""));
}

// -------- AUTH-17 — PRM HTTPS enforcement --------

function testPrmHttpsEnforced() {
  var threw = null;
  try {
    b.middleware.protectedResourceMetadata({
      resource:             "https://api.example.com",
      authorizationServers: ["http://insecure.test"],   // not https
    });
  } catch (e) { threw = e; }
  check("AUTH-17 — authorizationServers[*] must be https",
        threw && /bad-as-url|bad-as/.test(threw.code || ""));
}

// -------- AUTH-18 — PRM signed_metadata --------

function testPrmSignedMetadataEmits() {
  var keys = _ecPair("P-256");
  var mw = b.middleware.protectedResourceMetadata({
    resource:             "https://api.example.com",
    authorizationServers: ["https://idp.example.com"],
    signMetadata: { key: keys.privateKey, alg: "ES256", kid: "sig-1" },
  });
  check("AUTH-18 — signedMetadata exposed when signMetadata is wired",
        typeof mw.signedMetadata === "string" &&
        mw.signedMetadata.split(".").length === 3);
}

// -------- AUTH-22 — CIBA parseNotification lowercase only --------

async function testCibaParseNotificationLowercaseOnly() {
  // Lowercase-Authorization is what node:http delivers. Capital-A
  // fallback is now structurally removed. We exercise the rejection
  // path with no header at all — the lowercase-only path is still
  // reachable (verified by code-grep + the no-header branch).
  var ciba = b.auth.ciba.client.create({
    issuer:                  "https://idp.example.com",
    clientId:                "rp",
    clientSecret:            "s3cr3t-very-long-and-opaque-enough-for-ciba-minimum-entropy-guard-padding-here",
    tokenEndpoint:           "https://idp.example.com/token",
    backchannelAuthenticationEndpoint: "https://idp.example.com/bc-auth",
    deliveryMode:            "ping",
    clientNotificationToken: "abc-token-very-long-and-opaque-enough-for-ciba-minimum-entropy-guard-padding",
  });
  var threw = null;
  // parseNotification is async (it verifies a pushed id_token) — the
  // missing-bearer refusal surfaces as a rejection.
  try { await ciba.parseNotification({ headers: {} }, { body: {} }); }
  catch (e) { threw = e; }
  check("AUTH-22 — parseNotification requires lowercase 'authorization' header",
        threw && /missing-bearer/.test(threw.code || ""));
}

// -------- AUTH-36 — DPoP middleware shutdown / revoke --------

function testDpopMiddlewareShutdownExposed() {
  var mw = b.middleware.dpop({
    replayStore:    b.nonceStore.create({ backend: "memory" }),
    requireNonce:   true,
    nonceRotateSec: 60,                                                          // allow:raw-time-literal — rotation interval
  });
  check("AUTH-36 — dpop middleware exposes shutdown()", typeof mw.shutdown === "function");
  check("AUTH-36 — dpop middleware exposes revoke()",   typeof mw.revoke   === "function");
  // Calling them must not throw.
  mw.shutdown();
  mw.revoke();
  check("AUTH-36 — shutdown/revoke run without throwing", true);
}

// A JOSE header segment of base64url("null") parses to JSON null; the verifier
// must reject it with a typed malformed error, not dereference null and throw a
// raw TypeError (broken error contract — a consumer branching on .code or
// expecting AuthError gets an unhandled TypeError instead).
async function testNullJoseHeaderTypedError() {
  var _b = function (o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); };
  var nullHeaderTok = _b("null") + "." + _b({ sub: "x" }) + "." + _b("sig");

  var jwtThrew = null;
  try { b.auth.jwt.decode(nullHeaderTok); } catch (e) { jwtThrew = e; }
  check("jwt.decode null header → typed auth-jwt/malformed (not TypeError)",
        jwtThrew && jwtThrew.code === "auth-jwt/malformed");

  var dpopThrew = null;
  try {
    await b.auth.dpop.verify(nullHeaderTok, { htm: "POST", htu: "https://api.example.com/token" });
  } catch (e) { dpopThrew = e; }
  check("dpop.verify null header → typed auth-dpop/malformed (not TypeError)",
        dpopThrew && dpopThrew.code === "auth-dpop/malformed");
}

async function testJwtExternalNonFiniteSkewRejected() {
  // A present clockSkewMs of Infinity / NaN would make `exp + skewSec < now`
  // (and the nbf/iat-future gates) always false — silently accepting an expired
  // or not-yet-valid token. verifyExternal must reject a non-finite skew as a
  // bad value, never use it to disable the expiry gate. RED before the guard:
  // the expired token verifies. (jar.js threads this same opt to verifyExternal,
  // so fixing it here closes the signed-request-object path too.)
  var keys = _ecPair("P-256");
  var jwk = Object.assign({}, keys.publicKey, { kid: "k1" });
  var nowSec = Math.floor(Date.now() / 1000);
  var hp = _b64url(JSON.stringify({ alg: "ES256", kid: "k1" })) + "." +
           _b64url(JSON.stringify({ sub: "u1", exp: nowSec - 100000 }));   // expired
  var sig = nodeCrypto.sign("sha256", Buffer.from(hp, "ascii"),
    { key: keys.privateKey, dsaEncoding: "ieee-p1363" });
  var token = hp + "." + _b64url(sig);
  var bad = [Infinity, NaN, -1];
  for (var i = 0; i < bad.length; i++) {
    var threw = null;
    try {
      await b.auth.jwt.verifyExternal(token, { algorithms: ["ES256"], jwks: [jwk], clockSkewMs: bad[i] });
    } catch (e) { threw = e; }
    check("jwt-external: non-finite/negative clockSkewMs (" + String(bad[i]) + ") rejected, expiry gate not disabled",
          threw && /bad-clock-skew/.test(threw.code || ""));
  }
  // A sane finite skew still works: the same expired token is rejected as
  // expired (not bad-skew), proving the guard didn't break the happy path.
  var expiredThrew = null;
  try {
    await b.auth.jwt.verifyExternal(token, { algorithms: ["ES256"], jwks: [jwk], clockSkewMs: 30000 });
  } catch (e) { expiredThrew = e; }
  check("jwt-external: finite skew still rejects an expired token (as expired)",
        expiredThrew && /expired/.test(expiredThrew.code || ""));
}

async function testOauthCreateNonFiniteSkewRejected() {
  // oauth.create runs no finiteness check on clockSkewMs, which flows into
  // verifyIdToken's exp gate; Infinity/NaN would disable ID-token expiry.
  // Config-time rejection (operator catches the typo at boot).
  var bad = [Infinity, NaN, -5];
  for (var i = 0; i < bad.length; i++) {
    var threw = null;
    try {
      b.auth.oauth.create({
        issuer: "https://idp.example", clientId: "c1", clientSecret: "s1",
        redirectUri: "https://app.example/cb", clockSkewMs: bad[i],
      });
    } catch (e) { threw = e; }
    check("oauth.create: non-finite/negative clockSkewMs (" + String(bad[i]) + ") refused at config time",
          threw && /bad-clock-skew/.test(threw.code || ""));
  }
}

// ========================================================================
// Core b.auth.jwt (PQC framework signer) — verify/sign/decode defenses
// ========================================================================

// PRIMARY RED — algorithm-confusion / allowlist bypass (CWE-347).
//
// node:crypto.verify(null, ...) drives the algorithm from the KeyObject, NOT
// the JWS header.alg. verify() gates its algorithm allowlist on that header
// label. So a token signed by an ML-DSA-87 key but declaring
// alg="SLH-DSA-SHAKE-256f" passes an SLH-ONLY allowlist and is verified with
// the ML-DSA key — a full algorithm-allowlist bypass. Exactly the shape an
// operator uses the allowlist to prevent (pin the high-assurance algorithm).
//
// RED on the buggy tree: verify RESOLVES with the attacker's claims.
// GREEN after binding header.alg to the key: auth-jwt/alg-key-mismatch.
async function testAlgConfusionAllowlistBypass() {
  var ml = _mlPair();
  // Forge: header says SLH-DSA-SHAKE-256f, signature is a real ML-DSA-87 sig.
  var confused = _rawJws(ml.privateKey,
    { alg: "SLH-DSA-SHAKE-256f", typ: "JWT" },
    { sub: "attacker", role: "admin", iat: _NOW_SEC });

  var claims = null, threw = null;
  try {
    claims = await b.auth.jwt.verify(confused, {
      publicKey:  ml.publicKey,
      algorithms: ["SLH-DSA-SHAKE-256f"],   // SLH-only allowlist
      now:        _NOW_MS,
    });
  } catch (e) { threw = e; }
  check("core jwt: SLH-declared/ML-signed token refused (alg-key binding, CWE-347)",
        threw && threw.code === "auth-jwt/alg-key-mismatch");
  check("core jwt: alg-confused token yields NO claims (fail closed, no bypass)",
        claims === null);

  // Ordering control: when the forged label is NOT in the allowlist, the
  // allowlist gate fires first (algorithm-not-allowed), still fail-closed.
  var threw2 = null;
  try {
    await b.auth.jwt.verify(confused, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS,
    });
  } catch (e) { threw2 = e; }
  check("core jwt: forged label outside allowlist refused (algorithm-not-allowed)",
        threw2 && threw2.code === "auth-jwt/algorithm-not-allowed");

  // Positive control: a correctly-labeled ML-DSA token still verifies, proving
  // the binding didn't break the happy path.
  var honest = _rawJws(ml.privateKey,
    { alg: "ML-DSA-87", typ: "JWT" }, { sub: "u1", iat: _NOW_SEC });
  var ok = await b.auth.jwt.verify(honest, {
    publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS,
  });
  check("core jwt: correctly-labeled ML-DSA token still verifies", ok && ok.sub === "u1");
}

// RED (sign side of the same root) — sign() must not EMIT a token whose header
// alg misstates the signing key's real algorithm (the artifact the verify
// bypass consumes). Config-time throw.
async function testSignRefusesMismatchedAlgKey() {
  var ml = _mlPair();
  var threw = null;
  try {
    await b.auth.jwt.sign({ sub: "u1" },
      { privateKey: ml.privateKey, algorithm: "SLH-DSA-SHAKE-256f" });
  } catch (e) { threw = e; }
  check("core jwt: sign refuses SLH alg with an ML-DSA key (no mislabeled token emitted)",
        threw && threw.code === "auth-jwt/alg-key-mismatch");

  // Matched alg/key still signs (happy path intact).
  var tok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87" });
  check("core jwt: sign with matched ML-DSA alg/key emits a 3-part token",
        typeof tok === "string" && tok.split(".").length === 3);
}

// decode() — malformed-segment / non-object / part-count branches all return
// typed auth-jwt/malformed, never a raw throw.
function testCoreJwtDecodeMalformed() {
  var cases = [
    ["", "empty string"],
    ["only-two.parts", "two parts"],
    ["a.b.c.d", "four parts"],
    ["!!!.b.c", "non-base64url header"],
    [_b64urlJson([1, 2, 3]) + "." + _b64urlJson({ sub: "x" }) + ".c", "array header (not object)"],
    [_b64urlJson({ alg: "ML-DSA-87" }) + "." + _b64urlJson("string-payload") + ".c", "scalar payload (not object)"],
  ];
  for (var i = 0; i < cases.length; i++) {
    var threw = null;
    try { b.auth.jwt.decode(cases[i][0]); } catch (e) { threw = e; }
    check("core jwt: decode(" + cases[i][1] + ") throws typed auth-jwt/malformed",
          threw && threw.code === "auth-jwt/malformed");
  }
  // Non-string token.
  var t2 = null;
  try { b.auth.jwt.decode(12345); } catch (e) { t2 = e; }
  check("core jwt: decode(non-string) throws auth-jwt/malformed",
        t2 && t2.code === "auth-jwt/malformed");
}

// Key resolution branches: missing key, keyResolver/publicKey conflict,
// resolver-throws, resolver-returns-nothing, resolver-success.
async function testCoreJwtKeyResolution() {
  var ml = _mlPair();
  var token = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });

  var t1 = null;
  try { await b.auth.jwt.verify(token, { algorithms: ["ML-DSA-87"], now: _NOW_MS }); }
  catch (e) { t1 = e; }
  check("core jwt: verify with neither publicKey nor keyResolver → missing-key",
        t1 && t1.code === "auth-jwt/missing-key");

  var t2 = null;
  try {
    await b.auth.jwt.verify(token, {
      publicKey: ml.publicKey, keyResolver: function () { return ml.publicKey; },
      algorithms: ["ML-DSA-87"], now: _NOW_MS,
    });
  } catch (e) { t2 = e; }
  check("core jwt: keyResolver AND publicKey together → conflicting-key-source",
        t2 && t2.code === "auth-jwt/conflicting-key-source");

  var t3 = null;
  try {
    await b.auth.jwt.verify(token, {
      keyResolver: function () { throw new Error("jwks down"); },
      algorithms: ["ML-DSA-87"], now: _NOW_MS,
    });
  } catch (e) { t3 = e; }
  check("core jwt: keyResolver that throws → key-resolver-failed",
        t3 && t3.code === "auth-jwt/key-resolver-failed");

  var t4 = null;
  try {
    await b.auth.jwt.verify(token, {
      keyResolver: function () { return null; },
      algorithms: ["ML-DSA-87"], now: _NOW_MS,
    });
  } catch (e) { t4 = e; }
  check("core jwt: keyResolver returning no key → key-not-found",
        t4 && t4.code === "auth-jwt/key-not-found");

  // Async resolver returning the right key succeeds, and receives the full
  // decoded header (kid is delegated to the operator to sanitize).
  var sawKid = null;
  var ok = await b.auth.jwt.verify(token, {
    keyResolver: function (hdr) { sawKid = hdr.alg; return Promise.resolve(ml.publicKey); },
    algorithms: ["ML-DSA-87"], now: _NOW_MS,
  });
  check("core jwt: async keyResolver returning the right key verifies",
        ok && ok.sub === "u1" && sawKid === "ML-DSA-87");
}

// crit + expectedTyp defenses.
async function testCoreJwtCritAndTyp() {
  var ml = _mlPair();
  // Unknown crit extension → refused (RFC 7515 §4.1.11).
  var critTok = _rawJws(ml.privateKey,
    { alg: "ML-DSA-87", typ: "JWT", crit: ["exp"] }, { sub: "u1", iat: _NOW_SEC });
  var t1 = null;
  try {
    await b.auth.jwt.verify(critTok, { publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS });
  } catch (e) { t1 = e; }
  check("core jwt: unknown crit header refused (auth-jwt/unknown-crit)",
        t1 && t1.code === "auth-jwt/unknown-crit");

  // expectedTyp mismatch (case-insensitive per RFC 8725 §3.11).
  var jwtTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", typ: "JWT", now: _NOW_MS });
  var t2 = null;
  try {
    await b.auth.jwt.verify(jwtTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], expectedTyp: "at+jwt", now: _NOW_MS,
    });
  } catch (e) { t2 = e; }
  check("core jwt: expectedTyp mismatch refused (auth-jwt/typ-mismatch)",
        t2 && t2.code === "auth-jwt/typ-mismatch");

  // Matching typ (different case) accepted.
  var ok = await b.auth.jwt.verify(jwtTok, {
    publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], expectedTyp: "jwt", now: _NOW_MS,
  });
  check("core jwt: expectedTyp matches case-insensitively", ok && ok.sub === "u1");

  // Empty/blank expectedTyp is a config error.
  var t3 = null;
  try {
    await b.auth.jwt.verify(jwtTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], expectedTyp: "", now: _NOW_MS,
    });
  } catch (e) { t3 = e; }
  check("core jwt: empty expectedTyp refused (auth-jwt/bad-expected-typ)",
        t3 && t3.code === "auth-jwt/bad-expected-typ");
}

// Algorithm allowlist gate branches: an unsupported entry in the caller's list,
// and a token alg outside the list.
async function testCoreJwtAlgAllowlist() {
  var ml = _mlPair();
  var token = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });

  // Caller lists a bogus algorithm → surfaced at config time.
  var t1 = null;
  try {
    await b.auth.jwt.verify(token, { publicKey: ml.publicKey, algorithms: ["HS256"], now: _NOW_MS });
  } catch (e) { t1 = e; }
  check("core jwt: unsupported alg in allowlist refused (auth-jwt/unsupported-algorithm)",
        t1 && t1.code === "auth-jwt/unsupported-algorithm");

  // "none" can never be configured into the allowlist.
  var t2 = null;
  try {
    await b.auth.jwt.verify(token, { publicKey: ml.publicKey, algorithms: ["none"], now: _NOW_MS });
  } catch (e) { t2 = e; }
  check("core jwt: alg 'none' cannot enter the allowlist (auth-jwt/unsupported-algorithm)",
        t2 && t2.code === "auth-jwt/unsupported-algorithm");

  // Token alg legitimately outside the (valid) allowlist.
  var t3 = null;
  try {
    await b.auth.jwt.verify(token, {
      publicKey: ml.publicKey, algorithms: ["SLH-DSA-SHAKE-256f"], now: _NOW_MS,
    });
  } catch (e) { t3 = e; }
  check("core jwt: token alg outside allowlist refused (auth-jwt/algorithm-not-allowed)",
        t3 && t3.code === "auth-jwt/algorithm-not-allowed");
}

// Signature integrity: tampering the payload after signing invalidates it.
async function testCoreJwtTamperedSignature() {
  var ml = _mlPair();
  var token = await b.auth.jwt.sign({ sub: "u1", role: "user" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });
  var parts = token.split(".");
  var forgedPayload = _b64urlJson({ sub: "u1", role: "admin", iat: _NOW_SEC });
  var tampered = parts[0] + "." + forgedPayload + "." + parts[2];
  var threw = null;
  try {
    await b.auth.jwt.verify(tampered, { publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS });
  } catch (e) { threw = e; }
  check("core jwt: tampered payload refused (auth-jwt/invalid-signature)",
        threw && threw.code === "auth-jwt/invalid-signature");
}

// Time-based claims: exp / nbf enforcement, clock tolerance leeway, bad
// tolerance config, and NumericDate typing (a string exp must not bypass).
async function testCoreJwtTimeClaims() {
  var ml = _mlPair();

  // Expired token (exp = now + 100s; verify 200s later).
  var expiredTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", expiresInSec: 100, now: _NOW_MS });
  var laterMs = (_NOW_SEC + 200) * 1000;                                          // allow:raw-byte-literal — seconds→ms
  var t1 = null;
  try {
    await b.auth.jwt.verify(expiredTok, { publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: laterMs });
  } catch (e) { t1 = e; }
  check("core jwt: expired token refused (auth-jwt/expired)",
        t1 && t1.code === "auth-jwt/expired");

  // Clock tolerance widens the window enough to accept it.
  var okTol = await b.auth.jwt.verify(expiredTok, {
    publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: laterMs, clockToleranceSec: 300,
  });
  check("core jwt: clockToleranceSec leeway accepts a barely-expired token", okTol && okTol.sub === "u1");

  // not-yet-valid (nbf in the future).
  var futureTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", notBeforeSec: 100, now: _NOW_MS });
  var t2 = null;
  try {
    await b.auth.jwt.verify(futureTok, { publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS });
  } catch (e) { t2 = e; }
  check("core jwt: nbf-in-future refused (auth-jwt/not-yet-valid)",
        t2 && t2.code === "auth-jwt/not-yet-valid");

  // Negative / non-finite clock tolerance is a config error.
  var bad = [-1, Infinity, NaN];
  for (var i = 0; i < bad.length; i++) {
    var tb = null;
    try {
      await b.auth.jwt.verify(expiredTok, {
        publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: laterMs, clockToleranceSec: bad[i],
      });
    } catch (e) { tb = e; }
    check("core jwt: clockToleranceSec=" + String(bad[i]) + " refused (auth-jwt/bad-clock-tolerance)",
          tb && tb.code === "auth-jwt/bad-clock-tolerance");
  }

  // NumericDate typing: a STRING exp must not silently bypass expiry.
  var strExpTok = _rawJws(ml.privateKey,
    { alg: "ML-DSA-87", typ: "JWT" }, { sub: "u1", exp: "9999999999", iat: _NOW_SEC });
  var t3 = null;
  try {
    await b.auth.jwt.verify(strExpTok, { publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], now: _NOW_MS });
  } catch (e) { t3 = e; }
  check("core jwt: string exp refused as malformed (no expiry bypass, RFC 7519 NumericDate)",
        t3 && t3.code === "auth-jwt/malformed");
}

// Registered-claim assertions: iss (StringOrURI, not an array), aud (any-of),
// sub (exact).
async function testCoreJwtClaimAssertions() {
  var ml = _mlPair();

  // iss-array injection: iss:["evil","trusted"] must NOT satisfy a single
  // trusted-issuer expectation (CVE-2025-30144 class).
  var arrIssTok = await b.auth.jwt.sign(
    { sub: "u1", iss: ["evil.example", "trusted.example"] },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });
  var t1 = null;
  try {
    await b.auth.jwt.verify(arrIssTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], issuer: "trusted.example", now: _NOW_MS,
    });
  } catch (e) { t1 = e; }
  check("core jwt: array iss does not satisfy single-issuer expectation (auth-jwt/iss-mismatch)",
        t1 && t1.code === "auth-jwt/iss-mismatch");

  // aud any-of: token aud is an array, expectation matches one entry.
  var audTok = await b.auth.jwt.sign(
    { sub: "u1", aud: ["svc-a", "svc-b"] },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });
  var okAud = await b.auth.jwt.verify(audTok, {
    publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], audience: "svc-b", now: _NOW_MS,
  });
  check("core jwt: aud array matches expected any-of", okAud && okAud.sub === "u1");
  var t2 = null;
  try {
    await b.auth.jwt.verify(audTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], audience: "svc-c", now: _NOW_MS,
    });
  } catch (e) { t2 = e; }
  check("core jwt: aud mismatch refused (auth-jwt/aud-mismatch)",
        t2 && t2.code === "auth-jwt/aud-mismatch");

  // sub exact match.
  var subTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: _NOW_MS });
  var t3 = null;
  try {
    await b.auth.jwt.verify(subTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], subject: "u2", now: _NOW_MS,
    });
  } catch (e) { t3 = e; }
  check("core jwt: sub mismatch refused (auth-jwt/sub-mismatch)",
        t3 && t3.code === "auth-jwt/sub-mismatch");
}

// Replay defense: jti-less token refused when replayStore is wired; a valid
// token verifies once and is refused on second use; a store missing
// checkAndInsert is a config error.
async function testCoreJwtReplay() {
  var ml = _mlPair();
  var store = b.nonceStore.create({ backend: "memory" });
  // The memory replay store evicts against real wall-clock, and expireAt is
  // derived from the token's exp claim — so drive this case on the real clock
  // (a fixed past exp would evict the entry before the replay check).
  var realNowMs = Date.now();

  // No exp → no auto-jti → replayStore has nothing to bind → refuse.
  var noJtiTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", now: realNowMs });
  var t1 = null;
  try {
    await b.auth.jwt.verify(noJtiTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], replayStore: store, now: realNowMs,
    });
  } catch (e) { t1 = e; }
  check("core jwt: replayStore with a jti-less token refused (auth-jwt/replay-no-jti)",
        t1 && t1.code === "auth-jwt/replay-no-jti");

  // exp present → jti auto-minted → first verify ok, second is a replay.
  var repTok = await b.auth.jwt.sign({ sub: "u1" },
    { privateKey: ml.privateKey, algorithm: "ML-DSA-87", expiresInSec: 3600, now: realNowMs });
  var okFirst = await b.auth.jwt.verify(repTok, {
    publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], replayStore: store, now: realNowMs,
  });
  check("core jwt: first use of a jti verifies with replayStore", okFirst && okFirst.sub === "u1");
  var t2 = null;
  try {
    await b.auth.jwt.verify(repTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], replayStore: store, now: realNowMs,
    });
  } catch (e) { t2 = e; }
  check("core jwt: second use of the same jti refused (auth-jwt/replay)",
        t2 && t2.code === "auth-jwt/replay");

  // A store lacking checkAndInsert is a config error.
  var t3 = null;
  try {
    await b.auth.jwt.verify(repTok, {
      publicKey: ml.publicKey, algorithms: ["ML-DSA-87"], replayStore: {}, now: realNowMs,
    });
  } catch (e) { t3 = e; }
  check("core jwt: replayStore missing checkAndInsert refused (auth-jwt/bad-replay-store)",
        t3 && t3.code === "auth-jwt/bad-replay-store");

  if (typeof store.close === "function") store.close();
}

async function run() {
  await testAlgConfusionAllowlistBypass();
  await testSignRefusesMismatchedAlgKey();
  testCoreJwtDecodeMalformed();
  await testCoreJwtKeyResolution();
  await testCoreJwtCritAndTyp();
  await testCoreJwtAlgAllowlist();
  await testCoreJwtTamperedSignature();
  await testCoreJwtTimeClaims();
  await testCoreJwtClaimAssertions();
  await testCoreJwtReplay();
  await testJwtExternalNonFiniteSkewRejected();
  await testOauthCreateNonFiniteSkewRejected();
  await testNullJoseHeaderTypedError();
  await testAlgKtyMismatchRsaWithEs256();
  await testAlgKtyMismatchEcCurveConfusion();
  await testCrossRealmIssRefused();
  await testUnknownAlgRefusedBeforeLookup();
  testAalAmrWebauthnIsHwk();
  testFal2RequiresInjectionProtection();
  testPasskeyCompareBackupState();
  testPrfSaltLengthCap();
  await testPasskeyExtensionsAllowlist();
  testPrmHttpsEnforced();
  testPrmSignedMetadataEmits();
  await testCibaParseNotificationLowercaseOnly();
  testDpopMiddlewareShutdownExposed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
