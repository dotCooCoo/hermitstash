"use strict";
/**
 * b.credentialHash — envelope-versioned credential hashing.
 *
 * Run standalone: `node test/layer-0-primitives/credential-hash.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var C     = b.constants;

function testSurface() {
  check("b.credentialHash present",            typeof b.credentialHash === "object");
  check("hash is async fn",                    typeof b.credentialHash.hash === "function");
  check("verify is async fn",                  typeof b.credentialHash.verify === "function");
  check("inspect is fn",                       typeof b.credentialHash.inspect === "function");
  check("needsRehash is fn",                   typeof b.credentialHash.needsRehash === "function");
  check("ALGOS frozen",                        Object.isFrozen(b.credentialHash.ALGOS));
  check("ALGOS.SHAKE256",                      b.credentialHash.ALGOS.SHAKE256 === "shake256");
  check("ALGOS.ARGON2ID",                      b.credentialHash.ALGOS.ARGON2ID === "argon2id");
  check("DEFAULTS frozen",                     Object.isFrozen(b.credentialHash.DEFAULTS));
  check("DEFAULTS.algo is shake256",           b.credentialHash.DEFAULTS.algo === "shake256");

  check("CRED_HASH_IDS.SHAKE256 == 0x01",      C.CRED_HASH_IDS.SHAKE256 === 0x01);
  check("CRED_HASH_IDS.ARGON2ID == 0x02",      C.CRED_HASH_IDS.ARGON2ID === 0x02);
  check("ACTIVE.CRED_HASH is SHAKE256",        C.ACTIVE.CRED_HASH === C.CRED_HASH_IDS.SHAKE256);
  check("CREDENTIAL_MAGIC == 0xC1",            C.CREDENTIAL_MAGIC === 0xC1);
}

async function testShake256Roundtrip() {
  var ch = b.credentialHash;
  var env = await ch.hash("hello-world");
  var info = ch.inspect(env);
  check("shake256 default: algoId == 0x01",    info.algoId === 0x01);
  check("shake256 default: algoName shake256", info.algoName === "shake256");
  check("shake256 default: payload 128 bytes", info.payloadBytes === 128);

  check("verify match",                        (await ch.verify("hello-world", env)) === true);
  check("verify mismatch",                     (await ch.verify("hello-WORLD", env)) === false);
}

async function testShake256ConfigurableLength() {
  var ch = b.credentialHash;
  var env64 = await ch.hash("hi", { params: { length: 64 } });
  var env192 = await ch.hash("hi", { params: { length: 192 } });
  check("length 64 honored",                   ch.inspect(env64).payloadBytes === 64);
  check("length 192 honored",                  ch.inspect(env192).payloadBytes === 192);

  // Verify uses payload length to drive recomputation
  check("verify 64-byte envelope",             (await ch.verify("hi", env64)) === true);
  check("verify 192-byte envelope",            (await ch.verify("hi", env192)) === true);
  check("64 envelope can't verify against 192", env64 !== env192);

  // #111 — needsRehash must drive the advertised SHAKE256 length-rotation: a
  // digest stored at the old length must be flagged for rehash when the
  // configured/default length is larger. needsRehash ignored payload length,
  // so raising the output length was a silent no-op.
  check("#111 a 64-byte digest needs rehash under the 128-byte default",
        ch.needsRehash(env64) === true);
  check("#111 a 64-byte digest needs rehash when the target length is raised to 192",
        ch.needsRehash(env64, { params: { length: 192 } }) === true);
  check("#111 a 64-byte digest does NOT need rehash when the target stays 64",
        ch.needsRehash(env64, { params: { length: 64 } }) === false);
  check("#111 a default-length (128) digest does not need rehash at the default",
        ch.needsRehash(await ch.hash("hi")) === false);
  // Upgrade-only, matching the Argon2 needsRehash convention (rehash when the
  // stored strength is BELOW target, never to actively shorten): a 192-byte
  // digest must NOT be rehashed down to a 128-byte target.
  check("#111 a longer (192) digest is NOT rehashed down to a smaller target (128)",
        ch.needsRehash(env192, { params: { length: 128 } }) === false);
}

async function testShake256BufferSecret() {
  var ch = b.credentialHash;
  var secret = Buffer.from([1, 2, 3, 4, 0, 255]);
  var env = await ch.hash(secret);
  check("buffer secret hashes",                (await ch.verify(secret, env)) === true);
  // Buffer-vs-string differing inputs do not collide
  check("buffer/string mismatch separates",
        (await ch.verify("abc", env)) === false);
}

async function testArgon2idRoundtrip() {
  var ch = b.credentialHash;
  var env = await ch.hash("low-entropy-pw", { algo: "argon2id" });
  var info = ch.inspect(env);
  check("argon2id: algoId == 0x02",            info.algoId === 0x02);
  check("argon2id: algoName argon2id",         info.algoName === "argon2id");
  check("argon2id: payload looks like PHC",    info.payloadBytes > 50);

  check("argon2id roundtrip true",             (await ch.verify("low-entropy-pw", env)) === true);
  check("argon2id mismatch false",             (await ch.verify("WRONG", env)) === false);
}

async function testInspectMalformed() {
  var ch = b.credentialHash;
  check("inspect undefined → null",            ch.inspect(undefined) === null);
  check("inspect empty string → null",         ch.inspect("") === null);
  check("inspect garbage → null",              ch.inspect("not-base64-!@#$") === null);
  check("inspect missing magic → null",        ch.inspect(Buffer.from([0x99, 0x01]).toString("base64")) === null);
  check("inspect unknown algo → null",         ch.inspect(Buffer.from([0xC1, 0xFF]).toString("base64")) === null);
}

async function testVerifyMalformed() {
  var ch = b.credentialHash;
  check("verify(null secret) false",
        (await ch.verify(null, "anything")) === false);
  check("verify(undefined secret) false",
        (await ch.verify(undefined, "anything")) === false);
  check("verify('', envelope) false",
        (await ch.verify("", await ch.hash("real"))) === false);
  check("verify(s, garbage envelope) false",
        (await ch.verify("hi", "not-base64")) === false);
  check("verify(s, missing-magic envelope) false",
        (await ch.verify("hi", Buffer.from([0x99, 0x01]).toString("base64"))) === false);
}

async function testNeedsRehash() {
  var ch = b.credentialHash;
  var env = await ch.hash("x");
  check("needsRehash: just-issued shake256 false",
        ch.needsRehash(env) === false);
  // A garbage envelope counts as "needs migration"
  check("needsRehash: garbage true",            ch.needsRehash("garbage") === true);
  check("needsRehash: undefined true",          ch.needsRehash(undefined) === true);
  // If active is shake256 and stored is argon2id, needsRehash is true
  var argEnv = await ch.hash("x", { algo: "argon2id" });
  check("needsRehash: argon2id-stored under shake256-active true",
        ch.needsRehash(argEnv) === true);
  // If we explicitly target argon2id, an argon2id row does NOT need rehash
  check("needsRehash: argon2id-stored under argon2id-target false",
        ch.needsRehash(argEnv, { algo: "argon2id" }) === false);
}

async function testObservabilityEmission() {
  var ch = b.credentialHash;
  var cap = b.testing.captureMetricsTap();
  try {
    var env = await ch.hash("emit-secret");
    await ch.verify("emit-secret", env);
    await ch.verify("WRONG", env);
  } finally {
    cap.restore();
  }
  check("emits credentialHash.hash",       cap.byName("credentialHash.hash").length > 0);
  check("emits credentialHash.verify",     cap.byName("credentialHash.verify").length > 0);

  var hashEvent = cap.byName("credentialHash.hash")[0];
  check("hash event has algo label",       hashEvent && hashEvent.labels.algo === "shake256");

  var verifyEvents = cap.byName("credentialHash.verify");
  var anySuccess = verifyEvents.some(function (e) { return e.labels.outcome === "success"; });
  var anyFailure = verifyEvents.some(function (e) { return e.labels.outcome === "failure"; });
  check("verify emits success outcome",    anySuccess === true);
  check("verify emits failure outcome",    anyFailure === true);
}

async function testRejectsBadOpts() {
  var ch = b.credentialHash;
  function expect(label, fn, code) {
    return fn().then(
      function () { check(label + " — should have thrown", false); },
      function (e) { check(label, e && e.code === code); }
    );
  }
  await expect("hash: empty string secret",
    function () { return ch.hash(""); }, "credential-hash/bad-secret");
  await expect("hash: number secret",
    function () { return ch.hash(42); }, "credential-hash/bad-secret");
  await expect("hash: bad algo name",
    function () { return ch.hash("x", { algo: "md5" }); }, "credential-hash/bad-opt");
  await expect("hash: shake256 length too small",
    function () { return ch.hash("x", { params: { length: 8 } }); }, "credential-hash/bad-opt");
  await expect("hash: non-integer length",
    function () { return ch.hash("x", { params: { length: 64.5 } }); }, "credential-hash/bad-opt");
}

async function run() {
  testSurface();
  await testShake256Roundtrip();
  await testShake256ConfigurableLength();
  await testShake256BufferSecret();
  await testArgon2idRoundtrip();
  await testInspectMalformed();
  await testVerifyMalformed();
  await testNeedsRehash();
  await testObservabilityEmission();
  await testRejectsBadOpts();
  await testVerifyRejectsShortPayload();
}

// v0.6.64 — verify() now enforces the same 16-byte minimum payload that
// hash() enforces. Pre-fix the asymmetry was a real risk: hash() refused
// to *create* a hash shorter than 16 bytes, but verify() silently
// accepted any length, including 1-byte payloads where collision space
// is 256 (brute-forceable in microseconds). A storage bug or attacker
// tampering that truncated the stored envelope produced a verifiable
// but catastrophically weak hash.
async function testVerifyRejectsShortPayload() {
  var ch = b.credentialHash;
  var C = require("../../lib/constants");
  // Hand-craft a 1-byte payload that would have matched
  // SHAKE256("password",1)[0] before the fix.
  var nodeCrypto = require("node:crypto");
  var oneByte = nodeCrypto.createHash("shake256", { outputLength: 1 })
    .update("password").digest();
  var attackEnv = Buffer.from(
    [C.CREDENTIAL_MAGIC, C.CRED_HASH_IDS.SHAKE256, oneByte[0]]
  ).toString("base64");
  check("verify rejects 1-byte payload (pre-fix this was true)",
        (await ch.verify("password", attackEnv)) === false);

  // 15 bytes — one shy of the minimum
  var fifteenBytes = nodeCrypto.createHash("shake256", { outputLength: 15 })
    .update("password").digest();
  var fifteenEnv = Buffer.concat([
    Buffer.from([C.CREDENTIAL_MAGIC, C.CRED_HASH_IDS.SHAKE256]),
    fifteenBytes,
  ]).toString("base64");
  check("verify rejects 15-byte payload (one below minimum)",
        (await ch.verify("password", fifteenEnv)) === false);

  // 16 bytes — at minimum, accepts
  var sixteenHash = await ch.hash("password", { params: { length: 16 } });
  check("verify accepts legitimate 16-byte hash",
        (await ch.verify("password", sixteenHash)) === true);

  // hash() symmetric: rejects < 16
  var threwShort = false;
  try { await ch.hash("password", { params: { length: 15 } }); }
  catch (e) { threwShort = e.code === "credential-hash/bad-opt"; }
  check("hash() rejects length < 16",  threwShort);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
