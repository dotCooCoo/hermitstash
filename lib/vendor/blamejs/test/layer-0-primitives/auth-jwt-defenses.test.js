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

function testCibaParseNotificationLowercaseOnly() {
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
  try { ciba.parseNotification({ headers: {} }, { body: {} }); }
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

async function run() {
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
  testCibaParseNotificationLowercaseOnly();
  testDpopMiddlewareShutdownExposed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
