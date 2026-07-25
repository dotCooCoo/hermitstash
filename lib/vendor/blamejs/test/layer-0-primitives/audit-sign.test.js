// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditSign — the audit-chain signing primitive's error / edge surface.
 *
 * The anchor protocol (anchor / verifyAnchor / verifyAnchorChain) is covered by
 * audit-sign-anchor.test.js; the ml-dsa-65 opt-in by audit-sign-ml-dsa-65.test.js;
 * the full wrapped-DB rotation round-trip by audit-signing-key-rotation.test.js.
 * This file drives the reachable error / edge branches those happy-path files
 * leave uncovered:
 *   - init() argument + on-disk-conflict + mode-mismatch validation,
 *   - plaintext load-existing / corrupt / missing-algorithm key files,
 *   - wrapped-mode first-run, unseal, and the passphrase / schema / missing-alg
 *     failure branches (crafted sealed blobs through the real vault wrap),
 *   - the _requireInit guard on every consumer entry point,
 *   - verify() with a non-Buffer signature and verifier-only (no-init) use,
 *   - reSignAll's default-key / bad-key-error / throwing-onProgress paths,
 *   - _normalizeTip's typed config-time throws,
 *   - anchor()/verifyAnchor() createdAt + empty-format defaulting,
 *   - a mid-chain signature break in verifyAnchorChain,
 *   - the unsealed public-key history: dedup, corrupt-rebuild, unreadable-store.
 *
 * Everything uses ml-dsa-65 (the cheapest PQC keypair) so the per-run keygen +
 * Argon2id wrap stay fast. Every assertion PASSES on the current tree.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var nodeCrypto = require("crypto");
var vaultWrap  = require("../../lib/vault/wrap");

var ALG = "ml-dsa-65";
var PASS = "blamejs-audit-sign-test-passphrase-not-secret";

function _mkdir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }
function _rm(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } }
function _plaintextPath(dir) { return path.join(dir, "audit-sign.key"); }
function _sealedPath(dir) { return path.join(dir, "audit-sign.key.sealed"); }
function _historyPath(dir) { return path.join(dir, "audit-sign.pubkeys.json"); }
function _genPair(alg) {
  return nodeCrypto.generateKeyPairSync(alg, {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}
// Capture the typed error code a thrower emits (or null when it does not throw).
async function _codeOf(fn) {
  try { await fn(); } catch (e) { return e && e.code; }
  return null;
}

// ---- init() argument validation + no-op re-init + dataDir creation ----
async function testInitValidation() {
  var as = b.auditSign;
  as._resetForTest();
  check("init() with no opts throws bad-init",
    (await _codeOf(function () { return as.init(); })) === "audit-sign/bad-init");
  check("init({}) with no dataDir throws bad-init",
    (await _codeOf(function () { return as.init({}); })) === "audit-sign/bad-init");

  var dir = _mkdir("blamejs-as-initval-");
  try {
    check("init() rejects an unknown mode",
      (await _codeOf(function () { return as.init({ dataDir: dir, mode: "bogus" }); })) === "audit-sign/bad-mode");

    as._resetForTest();
    // dataDir points at a not-yet-existing nested path — init() mkdir -p's it.
    var nested = path.join(dir, "does", "not", "exist", "yet");
    await as.init({ dataDir: nested, mode: "plaintext", algorithm: ALG });
    check("init() creates a missing dataDir", fs.existsSync(nested));

    // A second init() with the singleton already booted is a no-op (does not
    // re-read disk, does not throw), and leaves the live key untouched.
    var fp = as.getPublicKeyFingerprint();
    await as.init({ dataDir: _mkdir("blamejs-as-noop-"), mode: "wrapped" });
    check("second init() is a no-op (key unchanged)", as.getPublicKeyFingerprint() === fp);
  } finally {
    as._resetForTest();
    _rm(dir);
  }
}

// ---- on-disk key-file conflict + mode mismatch (checked before any load) ----
async function testConflictAndModeMismatch() {
  var as = b.auditSign;

  var d1 = _mkdir("blamejs-as-conflict-");
  var d2 = _mkdir("blamejs-as-mm1-");
  var d3 = _mkdir("blamejs-as-mm2-");
  try {
    // Both a plaintext and a sealed key file on disk — refuse, don't guess.
    fs.writeFileSync(_plaintextPath(d1), "placeholder");
    fs.writeFileSync(_sealedPath(d1), "placeholder");
    as._resetForTest();
    check("both key files present -> KEY_FILE_CONFLICT",
      (await _codeOf(function () { return as.init({ dataDir: d1, mode: "plaintext" }); })) === "KEY_FILE_CONFLICT");

    // A sealed file exists but the operator asked for plaintext.
    fs.writeFileSync(_sealedPath(d2), "placeholder");
    as._resetForTest();
    check("sealed on disk + mode:plaintext -> MODE_MISMATCH",
      (await _codeOf(function () { return as.init({ dataDir: d2, mode: "plaintext" }); })) === "MODE_MISMATCH");

    // A plaintext file exists but the operator asked for wrapped.
    fs.writeFileSync(_plaintextPath(d3), "placeholder");
    as._resetForTest();
    check("plaintext on disk + mode:wrapped -> MODE_MISMATCH",
      (await _codeOf(function () { return as.init({ dataDir: d3, mode: "wrapped" }); })) === "MODE_MISMATCH");
  } finally {
    as._resetForTest();
    _rm(d1); _rm(d2); _rm(d3);
  }
}

// ---- plaintext: load-existing round-trip + corrupt + missing-algorithm ----
async function testPlaintextLoadAndCorrupt() {
  var as = b.auditSign;

  var dGood = _mkdir("blamejs-as-ptload-");
  var dCorrupt = _mkdir("blamejs-as-ptcorrupt-");
  var dNoAlg = _mkdir("blamejs-as-ptnoalg-");
  try {
    // First run generates + persists; a fresh boot loads the SAME key off disk.
    as._resetForTest();
    await as.init({ dataDir: dGood, mode: "plaintext", algorithm: ALG });
    var fp = as.getPublicKeyFingerprint();
    check("plaintext getMode is 'plaintext'", as.getMode() === "plaintext");
    as._resetForTest();
    await as.init({ dataDir: dGood, mode: "plaintext" });
    check("plaintext load-existing keeps the same fingerprint", as.getPublicKeyFingerprint() === fp);
    check("plaintext load-existing keeps the on-disk algorithm", as.getAlgorithm() === ALG);

    // A key file that is not valid JSON -> KEY_FILE_CORRUPT.
    fs.writeFileSync(_plaintextPath(dCorrupt), "{ this is not valid json");
    as._resetForTest();
    check("corrupt plaintext key file -> KEY_FILE_CORRUPT",
      (await _codeOf(function () { return as.init({ dataDir: dCorrupt, mode: "plaintext" }); })) === "KEY_FILE_CORRUPT");

    // A schema-valid key file that omits the required `algorithm` field.
    var pair = _genPair(ALG);
    fs.writeFileSync(_plaintextPath(dNoAlg),
      JSON.stringify({ publicKey: pair.publicKey, privateKey: pair.privateKey }, null, 2));
    as._resetForTest();
    check("plaintext key missing algorithm -> KEY_FILE_MISSING_ALG",
      (await _codeOf(function () { return as.init({ dataDir: dNoAlg, mode: "plaintext" }); })) === "KEY_FILE_MISSING_ALG");
  } finally {
    as._resetForTest();
    _rm(dGood); _rm(dCorrupt); _rm(dNoAlg);
  }
}

// ---- wrapped mode: first-run seal, unseal, and the three unwrap failures ----
async function testWrappedModeAndErrors() {
  var as = b.auditSign;

  var dSeal = _mkdir("blamejs-as-seal-");
  var dInvalid = _mkdir("blamejs-as-unwrapinvalid-");
  var dNoAlg = _mkdir("blamejs-as-unwrapnoalg-");
  try {
    // First-run wrapped: generate + seal under the operator passphrase. Omit
    // `mode` so the "wrapped" default is exercised (it is the documented default).
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    await as.init({ dataDir: dSeal, algorithm: ALG });
    check("wrapped is the default mode when none is given", as.getMode() === "wrapped");
    check("wrapped first-run wrote the sealed key file", fs.existsSync(_sealedPath(dSeal)));
    var sealFp = as.getPublicKeyFingerprint();

    // A fresh boot unseals the same key (happy path through _initWrapped).
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    await as.init({ dataDir: dSeal, mode: "wrapped" });
    check("wrapped unseal recovers the same fingerprint", as.getPublicKeyFingerprint() === sealFp);
    check("wrapped unseal recovers the on-disk algorithm", as.getAlgorithm() === ALG);

    // Wrong passphrase -> unwrap rejects -> PASSPHRASE_REJECTED.
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "the-wrong-passphrase";
    check("wrapped unseal with a wrong passphrase -> PASSPHRASE_REJECTED",
      (await _codeOf(function () { return as.init({ dataDir: dSeal, mode: "wrapped" }); })) === "PASSPHRASE_REJECTED");

    // A sealed blob whose plaintext is not a valid key object -> UNWRAPPED_INVALID.
    var badBlob = await vaultWrap.wrap("this-plaintext-is-not-json", Buffer.from(PASS));
    fs.writeFileSync(_sealedPath(dInvalid), badBlob);
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    check("wrapped unseal of a non-key plaintext -> UNWRAPPED_INVALID",
      (await _codeOf(function () { return as.init({ dataDir: dInvalid, mode: "wrapped" }); })) === "UNWRAPPED_INVALID");

    // A sealed blob that IS a schema-valid key object but omits `algorithm`.
    var pair = _genPair(ALG);
    var noAlgBlob = await vaultWrap.wrap(
      JSON.stringify({ publicKey: pair.publicKey, privateKey: pair.privateKey }),
      Buffer.from(PASS)
    );
    fs.writeFileSync(_sealedPath(dNoAlg), noAlgBlob);
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    check("wrapped unseal of a key missing algorithm -> UNWRAPPED_MISSING_ALG",
      (await _codeOf(function () { return as.init({ dataDir: dNoAlg, mode: "wrapped" }); })) === "UNWRAPPED_MISSING_ALG");

    // Wrapped rotation archives the OLD sealed file to the advertised history
    // path and records the rotated-out public key so it still resolves.
    as._resetForTest();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    await as.init({ dataDir: dSeal, mode: "wrapped" });
    var beforeFp = as.getPublicKeyFingerprint();
    var beforePub = as.getPublicKey();
    process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = PASS;
    var rot = await as.rotateSigningKey();
    check("wrapped rotation changed the live key", rot.newFingerprint !== beforeFp);
    check("wrapped rotation returned a sealed history path",
      typeof rot.historyPath === "string" && /\.sealed\.history-/.test(rot.historyPath));
    check("wrapped rotation wrote the history file to disk", fs.existsSync(rot.historyPath));
    check("wrapped rotation archived the rotated-out public key",
      as.getPublicKeyByFingerprint(beforeFp) === beforePub);
  } finally {
    as._resetForTest();
    delete process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE;
    _rm(dSeal); _rm(dInvalid); _rm(dNoAlg);
  }
}

// ---- _requireInit guards every consumer entry point ----
async function testRequireInitGuards() {
  var as = b.auditSign;
  as._resetForTest();
  check("getMode() before init returns null", as.getMode() === null);
  var G = "audit-sign/not-initialized";
  check("sign() before init throws not-initialized",
    (await _codeOf(function () { return as.sign("x"); })) === G);
  check("verify() (default key) before init throws not-initialized",
    (await _codeOf(function () { return as.verify("x", Buffer.from("00", "hex")); })) === G);
  check("getPublicKey() before init throws not-initialized",
    (await _codeOf(function () { return as.getPublicKey(); })) === G);
  check("getPublicKeyFingerprint() before init throws not-initialized",
    (await _codeOf(function () { return as.getPublicKeyFingerprint(); })) === G);
  check("getAlgorithm() before init throws not-initialized",
    (await _codeOf(function () { return as.getAlgorithm(); })) === G);
  check("anchor() before init throws not-initialized",
    (await _codeOf(function () { return as.anchor({ counter: 1, tipHash: "h" }); })) === G);
}

// ---- verify() edge inputs: non-Buffer signature + verifier-only (no init) ----
async function testVerifyEdges() {
  var as = b.auditSign;
  var dir = _mkdir("blamejs-as-verify-");
  try {
    as._resetForTest();
    await as.init({ dataDir: dir, mode: "plaintext", algorithm: ALG });
    var payload = Buffer.from("verify-edge-payload", "utf8");
    var sig = as.sign(payload);
    var pub = as.getPublicKey();

    // A non-Buffer signature (byte array) is coerced via Buffer.from().
    check("verify() coerces a non-Buffer signature (byte array)",
      as.verify(payload, Array.from(sig), pub) === true);
    // A non-Buffer payload (string) is coerced too.
    check("verify() coerces a string payload",
      as.verify("verify-edge-payload", sig, pub) === true);

    // A verifier-only process holds a trusted public key but never ran init():
    // supplying an explicit publicKeyPem must NOT require init.
    as._resetForTest();
    check("verify() with an explicit public key works without init()",
      as.verify(payload, sig, pub) === true);
    check("verify() with an explicit public key rejects a tampered payload",
      as.verify(Buffer.from("tampered", "utf8"), sig, pub) === false);

    // Contract: verify() NEVER throws — a malformed / non-PEM publicKeyPem is a
    // verification FAILURE (false), not a crash, so a verifier-only consumer
    // (b.backupManifest.verifyBytes) fed an untrusted key from a signature block
    // can branch on the boolean instead of crashing.
    check("verify() returns false (never throws) on a structurally-PEM but invalid key",
      as.verify(payload, sig, "-----BEGIN PUBLIC KEY-----\nbm90LWEta2V5\n-----END PUBLIC KEY-----") === false);
    check("verify() returns false (never throws) on a non-PEM garbage key string",
      as.verify(payload, sig, "this is not a pem at all") === false);
  } finally {
    as._resetForTest();
    _rm(dir);
  }
}

// ---- reSignAll: default key, error accounting, and a throwing onProgress ----
async function testReSignAllEdges() {
  var as = b.auditSign;
  var dir = _mkdir("blamejs-as-resign-");
  try {
    as._resetForTest();
    await as.init({ dataDir: dir, mode: "plaintext", algorithm: ALG });
    var payload = Buffer.from("resign-edge", "utf8");
    var goodSig = as.sign(payload);

    // No opts, and an entry that omits oldPublicKeyPem -> verify falls back to
    // the current in-memory key, which validates -> the entry is re-signed.
    async function* defaultKeyEntries() {
      yield { id: 1, payload: payload, signature: goodSig };
    }
    var s1 = await as.reSignAll(defaultKeyEntries());
    check("reSignAll with no opts + default-key entry re-signs",
      s1.reSigned === 1 && s1.skipped === 0 && s1.errors === 0);

    // A malformed oldPublicKeyPem no longer throws inside verify() (it honors
    // the never-throw contract and returns false) -> the entry is UNVERIFIABLE
    // and SKIPPED, and the walk continues to the next valid entry.
    async function* badKeyEntries() {
      yield { id: 2, payload: payload, signature: goodSig,
        oldPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----" };
      yield { id: 3, payload: payload, signature: goodSig };   // valid -> re-signed after the skip
    }
    var s2 = await as.reSignAll(badKeyEntries());
    check("reSignAll skips a bad-key (unverifiable) entry and keeps walking",
      s2.skipped === 1 && s2.reSigned === 1 && s2.errors === 0);

    // A throwing onProgress hook is drop-silent — the re-sign still counts.
    var fired = 0;
    async function* okEntries() {
      yield { id: 4, payload: payload, signature: goodSig, oldPublicKeyPem: as.getPublicKey() };
    }
    var s3 = await as.reSignAll(okEntries(), {
      onProgress: function () { fired += 1; throw new Error("hook blew up"); },
    });
    check("reSignAll swallows a throwing onProgress (still re-signed)",
      s3.reSigned === 1 && s3.errors === 0 && fired === 1);
  } finally {
    as._resetForTest();
    _rm(dir);
  }
}

// ---- _normalizeTip typed config-time throws + anchor/verify defaulting ----
async function testAnchorInputEdges() {
  var as = b.auditSign;
  var dir = _mkdir("blamejs-as-anchoredge-");
  try {
    as._resetForTest();
    await as.init({ dataDir: dir, mode: "plaintext", algorithm: ALG });

    check("anchor(null) -> ANCHOR_BAD_TIP",
      (await _codeOf(function () { return as.anchor(null); })) === "ANCHOR_BAD_TIP");
    check("anchor(non-object) -> ANCHOR_BAD_TIP",
      (await _codeOf(function () { return as.anchor("not-a-tip"); })) === "ANCHOR_BAD_TIP");
    check("anchor negative counter -> ANCHOR_BAD_COUNTER",
      (await _codeOf(function () { return as.anchor({ counter: -1, tipHash: "h" }); })) === "ANCHOR_BAD_COUNTER");
    check("anchor non-integer counter -> ANCHOR_BAD_COUNTER",
      (await _codeOf(function () { return as.anchor({ counter: 1.5, tipHash: "h" }); })) === "ANCHOR_BAD_COUNTER");
    check("anchor non-string prevTipHash -> ANCHOR_BAD_PREV",
      (await _codeOf(function () { return as.anchor({ counter: 1, tipHash: "h", prevTipHash: 123 }); })) === "ANCHOR_BAD_PREV");

    // An explicit finite createdAt is recorded verbatim; an empty format string
    // falls back to the default anchor magic.
    var aFixed = as.anchor({ counter: 5, tipHash: "e1" }, { createdAt: 123456, format: "" });
    check("anchor records an explicit finite createdAt", aFixed.createdAt === 123456);
    check("anchor with an empty format falls back to the default magic",
      aFixed.format === "blamejs-chain-anchor-v1" && as.verifyAnchor(aFixed).ok === true);

    // A non-empty custom format is domain-separated verbatim into the anchor
    // and round-trips through verification.
    var aFmt = as.anchor({ counter: 8, tipHash: "e4" }, { format: "my-app-ledger-v1" });
    check("anchor honors a non-empty custom format",
      aFmt.format === "my-app-ledger-v1" && as.verifyAnchor(aFmt).ok === true);

    // A non-finite createdAt (Infinity) falls back to Date.now().
    var aInf = as.anchor({ counter: 6, tipHash: "e2" }, { createdAt: Infinity });
    check("anchor with a non-finite createdAt falls back to a real timestamp",
      typeof aInf.createdAt === "number" && isFinite(aInf.createdAt) && as.verifyAnchor(aInf).ok === true);

    // verifyAnchor rebuilds an empty stored format as the default magic, so a
    // clean anchor whose format field was blanked still verifies.
    var aClean = as.anchor({ counter: 7, tipHash: "e3" });
    check("verifyAnchor treats an empty stored format as the default magic",
      as.verifyAnchor(Object.assign({}, aClean, { format: "" })).ok === true);

    // A mid-chain signature break (a tampered interior anchor) is reported at
    // its index with the signature-failure reason — the linkage checks never
    // get a chance to run because the per-anchor signature check fails first.
    var c1 = as.anchor({ counter: 1, tipHash: "c1" });
    var c2 = as.anchor({ counter: 2, tipHash: "c2", prevTipHash: "c1" });
    var c2tampered = Object.assign({}, c2, { tipHash: "c2-tampered" });
    var chain = as.verifyAnchorChain([c1, c2tampered]);
    check("verifyAnchorChain reports a mid-chain signature break at its index",
      chain.ok === false && chain.breakAt === 1 && chain.anchorsVerified === 1 &&
      /signature/.test(chain.reason));
  } finally {
    as._resetForTest();
    _rm(dir);
  }
}

// ---- unsealed public-key history: dedup, corrupt-rebuild, unreadable store ----
async function testPublicHistoryEdges() {
  var as = b.auditSign;

  var dDedup = _mkdir("blamejs-as-histdedup-");
  var dCorrupt = _mkdir("blamejs-as-histcorrupt-");
  var dDir = _mkdir("blamejs-as-histdir-");
  var dNonArray = _mkdir("blamejs-as-histnonarray-");
  try {
    // Dedup: a rotation whose to-be-archived fingerprint is ALREADY recorded in
    // the history does not append a duplicate entry.
    as._resetForTest();
    await as.init({ dataDir: dDedup, mode: "plaintext", algorithm: ALG });
    var curFp = as.getPublicKeyFingerprint();
    var curPub = as.getPublicKey();
    fs.writeFileSync(_historyPath(dDedup), JSON.stringify([
      { fingerprint: curFp, publicKey: curPub, algorithm: ALG, rotatedAt: new Date().toISOString() },
    ], null, 2));
    await as.rotateSigningKey();
    var afterDedup = JSON.parse(fs.readFileSync(_historyPath(dDedup), "utf8"));
    check("rotation does not re-append an already-recorded public key",
      Array.isArray(afterDedup) && afterDedup.length === 1);

    // Corrupt history: a non-JSON registry is rebuilt from the rotated-out key
    // rather than aborting the rotation.
    as._resetForTest();
    await as.init({ dataDir: dCorrupt, mode: "plaintext", algorithm: ALG });
    fs.writeFileSync(_historyPath(dCorrupt), "{{ corrupt not json");
    var rc = await as.rotateSigningKey();
    var afterCorrupt = JSON.parse(fs.readFileSync(_historyPath(dCorrupt), "utf8"));
    check("rotation rebuilds a corrupt public-key history",
      !!rc.newFingerprint && Array.isArray(afterCorrupt) && afterCorrupt.length === 1);

    // Unreadable/unwritable store: the history PATH is a directory, so the
    // best-effort read AND write both fail — the rotation still succeeds and
    // the fingerprint resolver returns null rather than throwing.
    as._resetForTest();
    await as.init({ dataDir: dDir, mode: "plaintext", algorithm: ALG });
    var dirFp = as.getPublicKeyFingerprint();
    fs.mkdirSync(_historyPath(dDir));
    var rd = await as.rotateSigningKey();
    check("rotation survives an unwritable public-key history",
      !!rd.newFingerprint && rd.newFingerprint !== dirFp);
    check("getPublicKeyByFingerprint returns null when the history store is unreadable",
      as.getPublicKeyByFingerprint(dirFp) === null);

    // A history file holding valid JSON that is NOT an array resolves to null.
    as._resetForTest();
    await as.init({ dataDir: dNonArray, mode: "plaintext", algorithm: ALG });
    fs.writeFileSync(_historyPath(dNonArray), JSON.stringify({ notAnArray: true }));
    check("getPublicKeyByFingerprint returns null for a non-array history",
      as.getPublicKeyByFingerprint("deadbeefdeadbeef") === null);
  } finally {
    as._resetForTest();
    _rm(dDedup); _rm(dCorrupt); _rm(dDir); _rm(dNonArray);
  }
}

async function run() {
  b.auditSign._resetForTest();
  try {
    await testInitValidation();
    await testConflictAndModeMismatch();
    await testPlaintextLoadAndCorrupt();
    await testWrappedModeAndErrors();
    await testRequireInitGuards();
    await testVerifyEdges();
    await testReSignAllEdges();
    await testAnchorInputEdges();
    await testPublicHistoryEdges();
  } finally {
    try { b.auditSign._resetForTest(); } catch (_e) { /* best-effort */ }
    delete process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE;
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("OK - audit-sign tests (" + helpers.getChecks() + " checks)");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
