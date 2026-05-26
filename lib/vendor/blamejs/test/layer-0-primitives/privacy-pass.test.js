"use strict";
/**
 * Layer 0 — b.privacyPass (Privacy Pass origin side, RFC 9577 / 9578).
 * The oracle is the published RFC 9578 §8.2 test vector for token type
 * 0x0002 (Blind RSA): the issuer public key, the TokenChallenge, and the
 * issued token. A wrong token_input layout or PSS parameter would fail
 * the real RSASSA-PSS verification, and the build-then-digest round trip
 * reproduces the vector's challenge_digest byte-for-byte.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var crypto = require("node:crypto");

// RFC 9578 §8.2, test vector 1 (token type 0x0002, Blind RSA 2048).
var PKI_SPKI_HEX = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001";
var TOKEN_CHALLENGE_HEX = "0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e6578616d706c65";
var TOKEN_HEX = "0002aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f055969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708bc6a21b533d07294b5e900faf5537dd3eb33cee4e08c9670d1e5358fd184b0e00c637174f5206b14c7bb0e724ebf6b56271e5aa2ed94c051c4a433d302b23bc52460810d489fb050f9de5c868c6c1b06e3849fd087629f704cc724bc0d0984d5c339686fcdd75f9a9cdd25f37f855f6f4c584d84f716864f546b696d620c5bd41a811498de84ff9740ba3003ba2422d26b91eb745c084758974642a42078201543246ddb58030ea8e722376aa82484dca9610a8fb7e018e396165462e17a03e40ea7e128c090a911ecc708066cb201833010c1ebd4e910fc8e27a1be467f78671836a508257123a45e4e0ae2180a434bd1037713466347a8ebe46439d3da1970";

function spki() { return Buffer.from(PKI_SPKI_HEX, "hex"); }
function token() { return Buffer.from(TOKEN_HEX, "hex"); }
function challenge() { return Buffer.from(TOKEN_CHALLENGE_HEX, "hex"); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.privacyPass.verifyToken is a function", typeof b.privacyPass.verifyToken === "function");
  check("b.privacyPass.parseToken is a function", typeof b.privacyPass.parseToken === "function");
  check("b.privacyPass.buildChallenge is a function", typeof b.privacyPass.buildChallenge === "function");
  check("b.privacyPass.TOKEN_TYPE_BLIND_RSA is 0x0002", b.privacyPass.TOKEN_TYPE_BLIND_RSA === 0x0002);
  check("b.privacyPass.PrivacyPassError is the typed error class", typeof b.privacyPass.PrivacyPassError === "function" && code(function () { b.privacyPass.parseToken(Buffer.alloc(2)); }) === "privacy-pass/bad-token");
  var threw = null; try { b.privacyPass.parseToken(Buffer.alloc(2)); } catch (e) { threw = e; }
  check("PrivacyPassError instances are thrown", threw instanceof b.privacyPass.PrivacyPassError);
}

function testParse() {
  var t = b.privacyPass.parseToken(token());
  check("parseToken: token type 0x0002", t.tokenType === 0x0002);
  check("parseToken: 32-byte nonce / digest / key-id", t.nonce.length === 32 && t.challengeDigest.length === 32 && t.tokenKeyId.length === 32);
  check("parseToken: 256-byte authenticator (RSA-2048)", t.authenticator.length === 256);
  // The embedded token_key_id is SHA-256 of the issuer SPKI.
  var keyId = crypto.createHash("sha256").update(spki()).digest();
  check("parseToken: token_key_id == SHA-256(issuer SPKI)", Buffer.compare(keyId, t.tokenKeyId) === 0);
}

function testRealVector() {
  var out = b.privacyPass.verifyToken({ token: token(), issuerPublicKey: spki() });
  check("verifyToken: real RFC 9578 §8.2 Blind RSA token verifies", out.ok && out.tokenType === 0x0002);
  // Bound to the challenge it answers.
  var out2 = b.privacyPass.verifyToken({ token: token(), issuerPublicKey: spki(), challenge: challenge() });
  check("verifyToken: verifies when bound to the matching challenge", out2.ok === true);
}

function testBuildChallengeRoundTrip() {
  // Rebuilding the vector's TokenChallenge reproduces it byte-for-byte,
  // and its SHA-256 is the challenge_digest embedded in the token.
  var rc = challenge().slice(19, 51); // the 32-byte redemption_context (after the 1-byte length at offset 18)
  var c = b.privacyPass.buildChallenge({ issuerName: "issuer.example", originInfo: "origin.example", redemptionContext: rc });
  check("buildChallenge: reproduces the RFC TokenChallenge bytes", Buffer.compare(c.challenge, challenge()) === 0);
  var digest = crypto.createHash("sha256").update(c.challenge).digest();
  var t = b.privacyPass.parseToken(token());
  check("buildChallenge: SHA-256(challenge) == token challenge_digest", Buffer.compare(digest, t.challengeDigest) === 0);
  check("buildChallenge: emits a PrivateToken WWW-Authenticate header", /^PrivateToken challenge="/.test(c.wwwAuthenticate));
  // RFC 9577 §2.1: auth-param values are padded base64url.
  var cv = c.wwwAuthenticate.match(/challenge="([^"]+)"/)[1];
  check("buildChallenge: challenge value is base64url with padding (len % 4 === 0)", cv.length % 4 === 0 && !/[+/]/.test(cv));
  var ck = b.privacyPass.buildChallenge({ issuerName: "issuer.example", tokenKey: spki() });
  check("buildChallenge: token-key value is padded base64url", /token-key="([^"]+)"/.test(ck.wwwAuthenticate) && ck.wwwAuthenticate.match(/token-key="([^"]+)"/)[1].length % 4 === 0);
}

function testPemKeyId() {
  // A PEM-encoded issuer key must derive the same token_key_id as the raw
  // SPKI bytes (Node can re-encode an rsa-pss AlgorithmIdentifier on
  // export, so the PEM body bytes — not a re-export — must be hashed).
  var pem = "-----BEGIN PUBLIC KEY-----\n" + spki().toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END PUBLIC KEY-----\n";
  var out = b.privacyPass.verifyToken({ token: token(), issuerPublicKey: pem });
  check("verifyToken: real token verifies with a PEM issuer key", out.ok === true);
}

function testRefusals() {
  // Tampered authenticator fails.
  check("verifyToken: tampered authenticator refused", code(function () {
    var bad = token(); bad[bad.length - 1] ^= 0xff;
    b.privacyPass.verifyToken({ token: bad, issuerPublicKey: spki() });
  }) === "privacy-pass/bad-authenticator");
  // Wrong issuer key → token_key_id mismatch (caught before signature).
  check("verifyToken: wrong issuer key refused (key-id mismatch)", code(function () {
    var otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
    b.privacyPass.verifyToken({ token: token(), issuerPublicKey: otherKey });
  }) === "privacy-pass/key-id-mismatch");
  // Wrong challenge → challenge_digest mismatch.
  check("verifyToken: mismatched challenge refused", code(function () {
    b.privacyPass.verifyToken({ token: token(), issuerPublicKey: spki(), challenge: Buffer.from("not the challenge") });
  }) === "privacy-pass/challenge-mismatch");
  // Privately verifiable VOPRF (0x0001) is not an origin-verify operation.
  check("verifyToken: token type 0x0001 (VOPRF) refused", code(function () {
    var t = token(); t.writeUInt16BE(0x0001, 0);
    b.privacyPass.verifyToken({ token: t, issuerPublicKey: spki() });
  }) === "privacy-pass/unsupported-token-type");
  // Truncated token refused.
  check("parseToken: short token refused", code(function () { b.privacyPass.parseToken(Buffer.alloc(40)); }) === "privacy-pass/bad-token");
}

async function run() {
  testSurface();
  testParse();
  testRealVector();
  testBuildChallengeRoundTrip();
  testPemKeyId();
  testRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[privacy-pass] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
