// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backupManifest rejection-path coverage.
 *
 * Covers the schema guards that had no failing case (an absent
 * encryptedPath, an odd-length hex salt, a signature block missing its
 * algorithm), the signer-unavailable and signer-threw refusals, and every
 * rejection reason `verifySignature` / `verifyBytes` can return.
 *
 * The centrepiece is the `expectedFingerprint` pin. The block's own
 * `fingerprint` field is attacker-controlled, so the pin is checked against
 * the fingerprint RECOMPUTED from the block's publicKey — the key the
 * signature is actually verified under. These tests drive that binding from
 * both sides: a block that lies about its fingerprint still verifies when
 * pinned to the truth, and a block signed by a foreign key is refused even
 * when it claims the trusted fingerprint.
 */

var nodeCrypto = require("node:crypto");
var nodeFs = require("node:fs");
var nodeOs = require("node:os");
var nodePath = require("node:path");
var helpers = require("../helpers");

var b = helpers.b;
var check = helpers.check;

// A schema-valid manifest input. Individual tests clone this and break one
// field so each assertion pins exactly one guard.
function _validArgs() {
  return {
    vaultKeySalt: "0011aabb",
    vaultKeyEnc:  Buffer.from("not-real-cipher").toString("base64"),
    files: [{
      relativePath:  "db.enc",
      encryptedPath: "files/db.enc.bin",
      size:          100,
      encryptedSize: 132,
      checksum:      "ab".repeat(64),   // 128-char hex (sha3-512)
      salt:          "ccdd",
      kind:          "raw",
    }],
    metadata: { reason: "coverage" },
  };
}

function _validManifest() {
  return b.backupManifest.create(_validArgs());
}

// validate() reports rather than throws, so assert on the cited field.
function _errorsFor(mutate) {
  var m = _validManifest();
  mutate(m);
  return b.backupManifest.validate(m);
}

function _refuses(label, fn, code) {
  var err = null;
  try { fn(); } catch (e) { err = e; }
  check(label,
    !!err && err.name === "BackupManifestError" && err.code === code);
}

// ---------------------------------------------------------------------------
// validate() guards that no existing fixture reached.
// ---------------------------------------------------------------------------
function testValidateResidualGuards() {
  // An ABSENT encryptedPath — distinct from the traversal-shaped one that
  // existing fixtures cover; this is the required-non-empty-string arm.
  var missingEnc = _errorsFor(function (m) { delete m.files[0].encryptedPath; });
  check("validate: absent encryptedPath is refused",
    missingEnc.ok === false &&
    missingEnc.errors.some(function (e) {
      return /files\[0\]\.encryptedPath: required non-empty string/.test(e);
    }));

  var emptyEnc = _errorsFor(function (m) { m.files[0].encryptedPath = ""; });
  check("validate: empty encryptedPath is refused",
    emptyEnc.ok === false &&
    emptyEnc.errors.some(function (e) {
      return /files\[0\]\.encryptedPath: required non-empty string/.test(e);
    }));

  // Odd-length hex: every hex character is valid but a half byte is not a
  // salt. This is the even-length arm of the hex guard, which a non-hex
  // fixture never reaches (it fails the character test first).
  var oddSalt = _errorsFor(function (m) { m.files[0].salt = "abc"; });
  check("validate: odd-length hex salt is refused (half a byte is not a salt)",
    oddSalt.ok === false &&
    oddSalt.errors.some(function (e) { return /files\[0\]\.salt: required hex string/.test(e); }));

  // A hex salt of even length stays accepted — proves the guard above keys on
  // length parity, not on rejecting short salts generally.
  var evenSalt = _errorsFor(function (m) { m.files[0].salt = "abcd"; });
  check("validate: even-length hex salt is accepted", evenSalt.ok === true);

  // A signature block present but missing `algorithm`. Every sub-field is
  // required once the block exists — a partial block is refused rather than
  // silently treated as unsigned.
  var noAlg = _errorsFor(function (m) {
    m.signature = {
      publicKey:   "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
      fingerprint: "aa".repeat(16),
      value:       Buffer.from("sig").toString("base64"),
      signedAt:    new Date().toISOString(),
    };
  });
  check("validate: signature block without algorithm is refused",
    noAlg.ok === false &&
    noAlg.errors.some(function (e) { return /signature\.algorithm: required non-empty string/.test(e); }));

  var emptyAlg = _errorsFor(function (m) {
    m.signature = {
      algorithm:   "",
      publicKey:   "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
      fingerprint: "aa".repeat(16),
      value:       Buffer.from("sig").toString("base64"),
      signedAt:    new Date().toISOString(),
    };
  });
  check("validate: signature block with empty algorithm is refused",
    emptyAlg.ok === false &&
    emptyAlg.errors.some(function (e) { return /signature\.algorithm: required non-empty string/.test(e); }));
}

// ---------------------------------------------------------------------------
// create() honours caller-supplied provenance fields rather than defaulting.
// ---------------------------------------------------------------------------
function testCreateHonoursSuppliedFields() {
  var args = _validArgs();
  args.frameworkVersion = "9.8.7";
  args.createdAt = "2020-01-02T03:04:05.000Z";
  var m = b.backupManifest.create(args);
  check("create: supplied frameworkVersion is preserved", m.frameworkVersion === "9.8.7");
  check("create: supplied createdAt is preserved", m.createdAt === "2020-01-02T03:04:05.000Z");

  // Empty string is not a usable version — it falls back to the framework's.
  var args2 = _validArgs();
  args2.frameworkVersion = "";
  var m2 = b.backupManifest.create(args2);
  check("create: empty frameworkVersion falls back to the framework version",
    typeof m2.frameworkVersion === "string" && m2.frameworkVersion.length > 0);

  // Omitted createdAt is stamped now, and round-trips through the ISO guard.
  var m3 = _validManifest();
  check("create: omitted createdAt is stamped as a valid ISO-8601 instant",
    new Date(m3.createdAt).toISOString() === m3.createdAt);
}

// ---------------------------------------------------------------------------
// sign()/signBytes() input refusals (no signer needed — these throw first).
// ---------------------------------------------------------------------------
function testSignInputRefusals() {
  _refuses("sign: an invalid manifest is refused before any signing",
    function () { b.backupManifest.sign({}); }, "backup-manifest/invalid");

  _refuses("signBytes: a number is refused",
    function () { b.backupManifest.signBytes(123); }, "backup-manifest/bad-input");
  _refuses("signBytes: null is refused",
    function () { b.backupManifest.signBytes(null); }, "backup-manifest/bad-input");
  _refuses("signBytes: a plain object is refused",
    function () { b.backupManifest.signBytes({ bytes: "x" }); }, "backup-manifest/bad-input");
}

// ---------------------------------------------------------------------------
// Verifier input guards — these return a verdict rather than throwing, so a
// caller can branch on an untrusted manifest without a try/catch.
// ---------------------------------------------------------------------------
function testVerifyInputGuards() {
  var nullRes = b.backupManifest.verifySignature(null);
  check("verifySignature(null) → ok:false citing the manifest type",
    nullRes.ok === false && /manifest must be an object/.test(nullRes.reason));

  var numRes = b.backupManifest.verifySignature(42);
  check("verifySignature(42) → ok:false citing the manifest type",
    numRes.ok === false && /manifest must be an object/.test(numRes.reason));

  var unsigned = b.backupManifest.verifySignature(_validManifest());
  check("verifySignature on an unsigned manifest → ok:false citing the missing block",
    unsigned.ok === false && /no signature block/.test(unsigned.reason));

  var badBytes = b.backupManifest.verifyBytes(123, { algorithm: "x" });
  check("verifyBytes(number) → ok:false citing canonicalBytes",
    badBytes.ok === false && /canonicalBytes must be a string or Buffer/.test(badBytes.reason));

  var nullBytes = b.backupManifest.verifyBytes(null, { algorithm: "x" });
  check("verifyBytes(null) → ok:false citing canonicalBytes",
    nullBytes.ok === false && /canonicalBytes must be a string or Buffer/.test(nullBytes.reason));
}

// ---------------------------------------------------------------------------
// Signature-block shape rejections. Every sub-field is required before any
// cryptography runs, so a malformed block is refused rather than fed to the
// verifier.
// ---------------------------------------------------------------------------
function testSignatureBlockShapeRejections(bytes, block) {
  var notObj = b.backupManifest.verifyBytes(bytes, null);
  check("verifyBytes: a null signature block → ok:false",
    notObj.ok === false && /signature block must be an object/.test(notObj.reason));

  var arr = b.backupManifest.verifyBytes(bytes, ["not", "a", "block"]);
  check("verifyBytes: an array signature block → ok:false",
    arr.ok === false && /signature\.algorithm is required/.test(arr.reason));

  function _without(field) {
    var copy = Object.assign({}, block);
    delete copy[field];
    return b.backupManifest.verifyBytes(bytes, copy);
  }

  var noAlg = _without("algorithm");
  check("verifyBytes: a block without algorithm → ok:false",
    noAlg.ok === false && /signature\.algorithm is required/.test(noAlg.reason));

  var noKey = _without("publicKey");
  check("verifyBytes: a block without publicKey → ok:false",
    noKey.ok === false && /signature\.publicKey is required/.test(noKey.reason));

  var noVal = _without("value");
  check("verifyBytes: a block without value → ok:false",
    noVal.ok === false && /signature\.value is required/.test(noVal.reason));

  // An empty string is as unusable as an absent field.
  var emptyKey = Object.assign({}, block, { publicKey: "" });
  var emptyKeyRes = b.backupManifest.verifyBytes(bytes, emptyKey);
  check("verifyBytes: a block with an empty publicKey → ok:false",
    emptyKeyRes.ok === false && /signature\.publicKey is required/.test(emptyKeyRes.reason));
}

// ---------------------------------------------------------------------------
// expectedFingerprint pinning — the binding that makes a rotated or foreign
// key refusable. The block's self-asserted `fingerprint` must never be what
// the pin is compared against.
// ---------------------------------------------------------------------------
function testFingerprintPinning(bytes, block, trustedFp) {
  var pinned = b.backupManifest.verifyBytes(bytes, block, { expectedFingerprint: trustedFp });
  check("pinning: the active key's fingerprint verifies",
    pinned.ok === true && pinned.fingerprint === trustedFp);

  var wrongPin = b.backupManifest.verifyBytes(bytes, block, { expectedFingerprint: "deadbeef" });
  check("pinning: a different expected fingerprint is refused",
    wrongPin.ok === false && /does not match expectedFingerprint=deadbeef/.test(wrongPin.reason));
  // The verdict reports the key actually presented, not the pin that failed —
  // an operator reading the reason learns which key signed it.
  check("pinning: a refused pin still reports the DERIVED fingerprint",
    wrongPin.fingerprint === trustedFp);

  // The block lies about its own fingerprint while carrying the honest
  // publicKey. Pinning to the truth must still succeed, which is only
  // possible if the pin ignores the self-asserted field.
  var lying = Object.assign({}, block, { fingerprint: "00".repeat(16) });
  var lyingRes = b.backupManifest.verifyBytes(bytes, lying, { expectedFingerprint: trustedFp });
  check("pinning: a block lying about its fingerprint still verifies when pinned to the real key",
    lyingRes.ok === true && lyingRes.fingerprint === trustedFp);

  // The key-substitution attack: a foreign keypair signs the same bytes and
  // claims the trusted fingerprint. The signature verifies under ITS OWN key,
  // so only the derived-fingerprint binding refuses it.
  var attacker = nodeCrypto.generateKeyPairSync("ml-dsa-65");
  var attackerPem = attacker.publicKey.export({ type: "spki", format: "pem" });
  var attackerSig = nodeCrypto.sign(null, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8"),
    attacker.privateKey);
  var forged = {
    algorithm:   block.algorithm,
    publicKey:   attackerPem,
    fingerprint: trustedFp,               // the lie
    value:       attackerSig.toString("base64"),
    signedAt:    new Date().toISOString(),
  };

  // Unpinned, the forgery verifies — it is a real signature, just by the
  // wrong key. This is precisely why the pin exists.
  var unpinnedForgery = b.backupManifest.verifyBytes(bytes, forged);
  check("pinning: an unpinned forged block verifies under its own key (why the pin exists)",
    unpinnedForgery.ok === true);
  check("pinning: the unpinned verdict reports the ATTACKER's derived fingerprint, not the claimed one",
    unpinnedForgery.fingerprint !== trustedFp);

  var pinnedForgery = b.backupManifest.verifyBytes(bytes, forged, { expectedFingerprint: trustedFp });
  check("pinning: a foreign key claiming the trusted fingerprint is REFUSED",
    pinnedForgery.ok === false && /does not match expectedFingerprint/.test(pinnedForgery.reason));
  check("pinning: the refusal reports the attacker's real fingerprint, not the claimed one",
    typeof pinnedForgery.fingerprint === "string" && pinnedForgery.fingerprint !== trustedFp);
}

// ---------------------------------------------------------------------------
// Fingerprint derivation failures. Both are reported as a refusal, never as a
// thrown error — the verifier's contract is a verdict.
// ---------------------------------------------------------------------------
function testFingerprintDerivationFailures(bytes, block, trustedFp) {
  var origFp = b.auditSign.fingerprintOf;
  try {
    b.auditSign.fingerprintOf = function () { throw new Error("fingerprint backend down"); };
    var threw = b.backupManifest.verifyBytes(bytes, block);
    check("derivation: a throwing fingerprintOf is reported as a refusal, not raised",
      threw.ok === false && /could not derive fingerprint from publicKey: fingerprint backend down/.test(threw.reason));

    // Absent (not throwing) fingerprintOf: verification still works unpinned,
    // but a pin cannot be honoured, so it fails closed rather than skipping.
    b.auditSign.fingerprintOf = undefined;
    var unpinned = b.backupManifest.verifyBytes(bytes, block);
    check("derivation: without fingerprintOf an UNPINNED verify still succeeds",
      unpinned.ok === true);

    var pinnedNoFp = b.backupManifest.verifyBytes(bytes, block, { expectedFingerprint: trustedFp });
    check("derivation: without fingerprintOf a PINNED verify fails closed",
      pinnedNoFp.ok === false && /fingerprint pinning requires audit-sign\.fingerprintOf \(unavailable\)/.test(pinnedNoFp.reason));
  } finally {
    b.auditSign.fingerprintOf = origFp;
  }
}

// ---------------------------------------------------------------------------
// Verifier dispatch: audit-sign when present, node:crypto otherwise, and the
// two failure shapes (verifier threw / signature simply did not verify).
// ---------------------------------------------------------------------------
function testVerifyDispatchAndFailures(bytes, block, trustedFp) {
  var origVerify = b.auditSign.verify;
  try {
    // A verifier process that never loaded audit-sign's verify still checks
    // the block through node:crypto with the block's own public key.
    b.auditSign.verify = undefined;
    var viaNode = b.backupManifest.verifyBytes(bytes, block);
    check("dispatch: with no audit-sign verify, node:crypto verifies the block",
      viaNode.ok === true && viaNode.fingerprint === trustedFp);

    var tamperedViaNode = b.backupManifest.verifyBytes(Buffer.from("tampered-payload", "utf8"), block);
    check("dispatch: the node:crypto fallback still rejects tampered bytes",
      tamperedViaNode.ok === false);

    // A verifier that raises is reported, not propagated.
    b.auditSign.verify = function () { throw new Error("verifier exploded"); };
    var threw = b.backupManifest.verifyBytes(bytes, block);
    check("dispatch: a throwing verifier is reported as a refusal",
      threw.ok === false && /verify threw: verifier exploded/.test(threw.reason));
  } finally {
    b.auditSign.verify = origVerify;
  }

  // A signature that is well-formed but does not cover these bytes.
  var tampered = b.backupManifest.verifyBytes(Buffer.from("different-bytes", "utf8"), block);
  check("dispatch: bytes the signature does not cover → ok:false",
    tampered.ok === false && /signature did not verify under provided publicKey/.test(tampered.reason));
  check("dispatch: the non-verifying verdict reports the derived fingerprint",
    tampered.fingerprint === trustedFp);
}

// ---------------------------------------------------------------------------
// Signer-unavailable refusals. Restored in a finally so the shared module is
// left exactly as found.
// ---------------------------------------------------------------------------
function testSignerUnavailableRefusals() {
  var origSign = b.auditSign.sign;
  try {
    b.auditSign.sign = undefined;
    _refuses("sign: an unavailable signer is refused",
      function () { b.backupManifest.sign(_validManifest()); }, "backup-manifest/no-signer");
    _refuses("signBytes: an unavailable signer is refused",
      function () { b.backupManifest.signBytes(Buffer.from("payload")); }, "backup-manifest/no-signer");

    b.auditSign.sign = function () { throw new Error("hsm offline"); };
    var err = null;
    try { b.backupManifest.sign(_validManifest()); } catch (e) { err = e; }
    check("sign: a throwing signer surfaces as sign-failed carrying the cause",
      !!err && err.code === "backup-manifest/sign-failed" && /hsm offline/.test(err.message));
  } finally {
    b.auditSign.sign = origSign;
  }
}

// ---------------------------------------------------------------------------
// A signed manifest verifies end to end, and serialize() refuses to emit one
// that would not validate.
// ---------------------------------------------------------------------------
function testSignedManifestRoundTrip() {
  var m = _validManifest();
  b.backupManifest.sign(m);
  check("round-trip: signing attaches a complete block",
    !!m.signature && typeof m.signature.algorithm === "string" &&
    typeof m.signature.value === "string" && m.signature.value.length > 0);

  var verdict = b.backupManifest.verifySignature(m);
  check("round-trip: the signed manifest verifies", verdict.ok === true);

  // The signature covers the canonical bytes WITHOUT the signature field, so
  // attaching it does not invalidate what was signed.
  var payload = b.backupManifest.signingPayload(m);
  check("round-trip: the signing payload excludes the signature block",
    payload.indexOf("\"signature\"") === -1);
  check("round-trip: verifyBytes agrees with verifySignature over that payload",
    b.backupManifest.verifyBytes(payload, m.signature).ok === true);

  // Mutating a signed field breaks verification.
  var tampered = JSON.parse(JSON.stringify(m));
  tampered.files[0].size = 101;
  check("round-trip: a mutated signed field fails verification",
    b.backupManifest.verifySignature(tampered).ok === false);

  _refuses("serialize: a manifest that no longer validates is refused",
    function () {
      var broken = _validManifest();
      broken.files = [];
      b.backupManifest.serialize(broken);
    }, "backup-manifest/invalid");
}

async function run() {
  testValidateResidualGuards();
  testCreateHonoursSuppliedFields();
  testSignInputRefusals();
  testVerifyInputGuards();

  // The signature paths need a live keypair. Reset first so the fixture is
  // this test's own key regardless of what the runner initialized, and reset
  // again at the end so the process is left as found.
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "bmc-sign-"));
  b.auditSign._resetForTest();
  try {
    await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });

    var bytes = Buffer.from("canonical-header-bytes-for-coverage", "utf8");
    var block = b.backupManifest.signBytes(bytes);
    var trustedFp = b.auditSign.fingerprintOf(block.publicKey);
    check("fixture: signBytes produced a block over the test keypair",
      !!block && block.publicKey.indexOf("-----BEGIN") === 0 && typeof trustedFp === "string");
    check("fixture: the honest block verifies", b.backupManifest.verifyBytes(bytes, block).ok === true);
    check("fixture: signBytes accepts a string payload identically",
      b.backupManifest.verifyBytes("abc", b.backupManifest.signBytes("abc")).ok === true);

    testSignatureBlockShapeRejections(bytes, block);
    testFingerprintPinning(bytes, block, trustedFp);
    testFingerprintDerivationFailures(bytes, block, trustedFp);
    testVerifyDispatchAndFailures(bytes, block, trustedFp);
    testSignedManifestRoundTrip();
    testSignerUnavailableRefusals();
  } finally {
    b.auditSign._resetForTest();
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-manifest-coverage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
