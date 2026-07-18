// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Backup-manifest signature — ML-DSA-87 / SLH-DSA-SHAKE-256f signed
 * manifest with detached signature block. Covers F-BUDR-3.
 */

var helpers = require("../helpers");
var nodeCrypto = require("node:crypto");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("backupManifest.sign is fn",            typeof b.backupManifest.sign === "function");
  check("backupManifest.verifySignature is fn", typeof b.backupManifest.verifySignature === "function");
  check("backupManifest.signingPayload is fn",  typeof b.backupManifest.signingPayload === "function");
  check("backupManifest.signBytes is fn",       typeof b.backupManifest.signBytes === "function");
  check("backupManifest.verifyBytes is fn",     typeof b.backupManifest.verifyBytes === "function");
  check("backupBundle.verifyManifestSignature is fn",
    typeof b.backup.verifyManifestSignature === "function");

  // ---- Parser / builder adversarial coverage (manifest.js) ----
  // Every malformed / truncated / version-mismatched / tampered / oversized /
  // adversarial input must produce a TYPED BackupManifestError (parse / create /
  // serialize) or an { ok:false, errors } verdict (validate) — never an
  // uncaught crash, never a fail-open acceptance. These drive the real
  // b.backupManifest.* consumer path and need no signer, so they run before the
  // audit-sign gate below.
  function _covValidArgs() {
    return {
      vaultKeySalt: "0011aabb",
      vaultKeyEnc:  Buffer.from("cipher-bytes").toString("base64"),
      files: [{
        relativePath:  "db.enc",
        encryptedPath: "files/db.enc.bin",
        size:          100,
        encryptedSize: 132,
        checksum:      "ab".repeat(64),   // 128-char hex (sha3-512)
        salt:          "ccdd",
        kind:          "raw",
      }],
      metadata: { reason: "cov" },
    };
  }
  function _covRefuses(label, fn, code) {
    var err = null;
    try { fn(); } catch (e) { err = e; }
    check(label + " → typed BackupManifestError",
      !!err && err.name === "BackupManifestError" && (!code || err.code === code));
  }
  // Tamper a field on a fresh VALID manifest object (create() returns a valid
  // one; mutating the returned object escapes create-time validation), then
  // assert validate() renders a fail-closed verdict citing the field.
  function _covValidateErr(label, mutate, rx) {
    var o = b.backupManifest.create(_covValidArgs());
    mutate(o);
    var v = b.backupManifest.validate(o);
    check(label + " → ok:false + cites field",
      v.ok === false && v.errors.some(function (e) { return rx.test(e); }));
  }

  // A canonical valid manifest we tamper field-by-field via JSON round-trip
  // to drive the real parse() trust-boundary path.
  var covBase = b.backupManifest.create(_covValidArgs());
  var covJson = b.backupManifest.serialize(covBase);
  function _covTamperedJson(mutate) {
    var o = JSON.parse(covJson);
    mutate(o);
    return JSON.stringify(o);
  }

  // create() fails closed with nothing supplied — never a half-built manifest.
  _covRefuses("create() with no args refuses", function () {
    b.backupManifest.create();
  }, "backup-manifest/invalid");

  // Malformed / truncated / empty JSON.
  _covRefuses("parse truncated JSON refuses", function () {
    b.backupManifest.parse('{"version":1,');
  }, "backup-manifest/bad-json");
  _covRefuses("parse empty-string refuses", function () {
    b.backupManifest.parse("");
  }, "backup-manifest/bad-json");

  // JSON 'null' → validate sees a non-object manifest; typed invalid, no crash.
  _covRefuses("parse of JSON null refuses (non-object manifest)", function () {
    b.backupManifest.parse("null");
  }, "backup-manifest/invalid");

  // Missing every required key.
  _covRefuses("parse of {} refuses (missing required keys)", function () {
    b.backupManifest.parse("{}");
  }, "backup-manifest/invalid");

  // Version mismatch (adversarial downgrade/upgrade of an otherwise-valid one).
  _covRefuses("parse rejects version mismatch", function () {
    b.backupManifest.parse(_covTamperedJson(function (o) { o.version = 99; }));
  }, "backup-manifest/invalid");

  // Framework substitution.
  _covRefuses("parse rejects wrong framework", function () {
    b.backupManifest.parse(_covTamperedJson(function (o) { o.framework = "evil"; }));
  }, "backup-manifest/invalid");

  // metadata must be a plain object — an array is refused, not silently used.
  _covRefuses("parse rejects array metadata", function () {
    b.backupManifest.parse(_covTamperedJson(function (o) { o.metadata = [1, 2, 3]; }));
  }, "backup-manifest/invalid");
  _covValidateErr("validate rejects null metadata",
    function (o) { o.metadata = null; }, /metadata/);

  // Hand-edited PARTIAL signature block (operator forged a signature field) —
  // every sub-field is required; a partial block is refused, not accepted.
  _covRefuses("parse rejects partial signature block", function () {
    b.backupManifest.parse(_covTamperedJson(function (o) { o.signature = { algorithm: "x" }; }));
  }, "backup-manifest/invalid");
  _covRefuses("parse rejects non-object signature", function () {
    b.backupManifest.parse(_covTamperedJson(function (o) { o.signature = "not-a-block"; }));
  }, "backup-manifest/invalid");
  _covValidateErr("validate flags non-base64 signature.value",
    function (o) { o.signature = { algorithm: "ml-dsa", publicKey: "k", fingerprint: "fp",
      value: "not base64 !@#", signedAt: new Date().toISOString() }; }, /signature\.value/);
  _covValidateErr("validate flags non-ISO signature.signedAt",
    function (o) { o.signature = { algorithm: "ml-dsa", publicKey: "k", fingerprint: "fp",
      value: Buffer.from("v").toString("base64"), signedAt: "whenever" }; }, /signature\.signedAt/);

  // Top-level field-shape branches.
  _covValidateErr("validate flags empty frameworkVersion",
    function (o) { o.frameworkVersion = ""; }, /frameworkVersion/);
  _covValidateErr("validate flags non-hex vaultKeySalt",
    function (o) { o.vaultKeySalt = "zznothex"; }, /vaultKeySalt/);
  _covValidateErr("validate flags files not-an-array",
    function (o) { o.files = "nope"; }, /files: required array/);

  // Adversarial file entries.
  _covValidateErr("validate flags a null file entry",
    function (o) { o.files = [null]; }, /files\[0\]: must be an object/);
  _covValidateErr("validate flags a numeric file entry",
    function (o) { o.files = [42]; }, /files\[0\]: must be an object/);
  _covValidateErr("validate flags a missing relativePath",
    function (o) { delete o.files[0].relativePath; }, /relativePath/);
  _covValidateErr("validate flags encryptedPath traversal",
    function (o) { o.files[0].encryptedPath = "../escape.bin"; }, /encryptedPath/);
  _covValidateErr("validate flags a missing encryptedSize",
    function (o) { delete o.files[0].encryptedSize; }, /encryptedSize/);
  _covValidateErr("validate flags a negative encryptedSize",
    function (o) { o.files[0].encryptedSize = -5; }, /encryptedSize/);
  _covValidateErr("validate flags a non-integer size",
    function (o) { o.files[0].size = 1.5; }, /size/);
  _covValidateErr("validate flags a non-finite size",
    function (o) { o.files[0].size = Infinity; }, /size/);
  _covValidateErr("validate flags a hex-but-wrong-length checksum",
    function (o) { o.files[0].checksum = "ab".repeat(60); }, /checksum/);   // 120 chars, not 128
  _covValidateErr("validate flags a non-hex salt",
    function (o) { o.files[0].salt = "zznothex"; }, /salt/);
  _covValidateErr("validate flags a missing kind",
    function (o) { delete o.files[0].kind; }, /kind/);
  _covValidateErr("validate flags a duplicate encryptedPath",
    function (o) { o.files.push({ relativePath: "other.enc", encryptedPath: "files/db.enc.bin",
      size: 1, encryptedSize: 1, checksum: "cd".repeat(64), salt: "ee", kind: "raw" }); },
    /duplicate/);

  // Fail-open fix: a Windows drive-absolute path is NOT relative and must be
  // refused (it escapes dataDir on restore, path.resolve honors the drive).
  var covDrive = "C:" + "\\" + "Windows" + "\\" + "evil";
  _covValidateErr("validate refuses drive-absolute relativePath",
    function (o) { o.files[0].relativePath = covDrive; }, /relativePath/);
  _covValidateErr("validate refuses drive-absolute encryptedPath",
    function (o) { o.files[0].encryptedPath = covDrive; }, /encryptedPath/);
  // An NTFS alternate-data-stream marker (a colon anywhere, not just a leading
  // drive letter) is refused at validate() too, matching the safePath sink so a
  // caller pre-screening a tampered manifest with validate()/inspect() also
  // fails closed rather than deferring the rejection to restore.
  _covValidateErr("validate refuses an NTFS-ADS relativePath (colon)",
    function (o) { o.files[0].relativePath = "db.enc:evil"; }, /relativePath/);
  _covValidateErr("validate refuses an NTFS-ADS encryptedPath (colon)",
    function (o) { o.files[0].encryptedPath = "files/db.enc.bin:stream"; }, /encryptedPath/);

  // serialize() on a tampered-invalid manifest fails closed too.
  _covRefuses("serialize refuses an invalid manifest", function () {
    var o = b.backupManifest.create(_covValidArgs());
    o.version = 5;
    b.backupManifest.serialize(o);
  }, "backup-manifest/invalid");

  // aadBound (blob-remap defense marker) round-trips through create/serialize/parse.
  var covAad = b.backupManifest.create(Object.assign(_covValidArgs(), { aadBound: true }));
  check("create honors aadBound flag", covAad.aadBound === true);
  var covAadJson = b.backupManifest.serialize(covAad);
  check("serialize emits aadBound", /"aadBound": true/.test(covAadJson));
  check("parse round-trips aadBound", b.backupManifest.parse(covAadJson).aadBound === true);

  // Prototype-pollution attempt via a __proto__ manifest key — parse strips it
  // (safeJson trust-boundary) and does not pollute Object.prototype nor crash.
  var covPollJson = covJson.replace(/^\{/, '{"__proto__":{"polluted":true},');
  var covPolled = b.backupManifest.parse(covPollJson);
  check("parse strips __proto__ (no prototype pollution)",
    ({}).polluted === undefined && covPolled.version === 1);

  // Oversized manifest (> the 16 MiB parse cap) is refused, not OOM'd.
  _covRefuses("parse refuses an oversized manifest (>16 MiB)", function () {
    b.backupManifest.parse('{"version":1,"blob":"' + "a".repeat(0x1100000) + '"}');
  }, "backup-manifest/bad-json");

  // We need an audit-sign-initialized process to sign. helpers.b
  // initializes audit-sign during the smoke runner setup; if not
  // initialized, this test is a smoke-skipped no-op that logs and
  // returns.
  if (!b.auditSign || typeof b.auditSign.sign !== "function") {
    check("audit-sign not wired in this runner — skipping signature test", true);
    return;
  }

  // Build a valid manifest fixture (no signature)
  var fixture = b.backupManifest.create({
    vaultKeySalt: "0011aabb",
    vaultKeyEnc:  Buffer.from("not-real-cipher").toString("base64"),
    files: [
      {
        relativePath:  "db.enc",
        encryptedPath: "files/db.enc.bin",
        size:          100,
        encryptedSize: 132,
        checksum:      "ab".repeat(64),                                            // 128-char hex
        salt:          "ccdd",
        kind:          "raw",
      },
    ],
    metadata: { reason: "test" },
  });
  check("create() succeeds without signature", fixture.signature === undefined);

  // Sign — best-effort. When audit-sign is not initialized in this
  // smoke runner (CLI / standalone test), the manifest signer surfaces
  // either backup-manifest/no-signer or backup-manifest/sign-failed
  // depending on how the audit-sign module was loaded. Either path
  // means the runner doesn't have a live keypair; skip the rest.
  try { b.backupManifest.sign(fixture); }
  catch (e) {
    var skipCodes = ["backup-manifest/no-signer", "backup-manifest/sign-failed"];
    if (e && skipCodes.indexOf(e.code) !== -1) {
      check("audit-sign not initialized — skipping sign assertion", true);
      return;
    }
    throw e;
  }
  check("sign() attaches signature block",     !!fixture.signature);
  check("signature carries algorithm",         typeof fixture.signature.algorithm === "string");
  check("signature carries publicKey PEM",     fixture.signature.publicKey.indexOf("-----BEGIN") === 0);
  check("signature carries fingerprint",       typeof fixture.signature.fingerprint === "string");
  check("signature carries base64 value",      typeof fixture.signature.value === "string" && fixture.signature.value.length > 0);

  // Verify clean manifest
  var clean = b.backupManifest.verifySignature(fixture);
  check("verifySignature on clean manifest → ok", clean.ok === true);

  // Tamper a metadata field — verification must fail
  var tampered = JSON.parse(JSON.stringify(fixture));
  tampered.metadata.reason = "tampered";
  var bad = b.backupManifest.verifySignature(tampered);
  check("verifySignature on tampered manifest → ok=false", bad.ok === false);

  // Pin fingerprint mismatch
  var badFp = b.backupManifest.verifySignature(fixture, { expectedFingerprint: "deadbeef" });
  check("verifySignature with wrong expectedFingerprint → ok=false", badFp.ok === false);

  // Round-trip via parse/serialize preserves signature
  var serialized = b.backupManifest.serialize(fixture);
  var reparsed = b.backupManifest.parse(serialized);
  check("serialize+parse preserves signature.algorithm",
    reparsed.signature && reparsed.signature.algorithm === fixture.signature.algorithm);
  var roundTrip = b.backupManifest.verifySignature(reparsed);
  check("round-tripped manifest verifies", roundTrip.ok === true);

  // verifyManifestSignature accepts a parsed manifest
  var viaWrapper = b.backup.verifyManifestSignature({ manifest: reparsed });
  check("backup.verifyManifestSignature accepts parsed manifest", viaWrapper.ok === true);

  // #351 — schema-agnostic signBytes/verifyBytes: a consumer with a bespoke
  // (non-manifest) format signs its OWN canonical bytes with the same keypair +
  // fingerprint pinning, without adopting the v1 manifest schema.
  var customBytes = Buffer.from("custom-header\x00v=2\x00payload=" + "ab".repeat(40), "utf8");
  var sigBlock = b.backupManifest.signBytes(customBytes);
  check("signBytes returns a detached signature block",
    sigBlock && typeof sigBlock.algorithm === "string" &&
    sigBlock.publicKey.indexOf("-----BEGIN") === 0 &&
    typeof sigBlock.fingerprint === "string" &&
    typeof sigBlock.value === "string" && sigBlock.value.length > 0);

  var okBytes = b.backupManifest.verifyBytes(customBytes, sigBlock);
  check("verifyBytes on the exact bytes → ok", okBytes.ok === true && okBytes.fingerprint === sigBlock.fingerprint);

  // A string with the SAME bytes verifies too (UTF-8 normalization parity).
  var okStr = b.backupManifest.verifyBytes(customBytes.toString("utf8"), sigBlock);
  check("verifyBytes accepts an equivalent string payload", okStr.ok === true);

  // Tamper one byte → verification fails.
  var tamperedBytes = Buffer.from(customBytes); tamperedBytes[0] = tamperedBytes[0] ^ 0x01;
  var badBytes = b.backupManifest.verifyBytes(tamperedBytes, sigBlock);
  check("verifyBytes on tampered bytes → ok=false", badBytes.ok === false);

  // Fingerprint pinning: a wrong expected fingerprint refuses even valid bytes.
  var pinned = b.backupManifest.verifyBytes(customBytes, sigBlock, { expectedFingerprint: sigBlock.fingerprint });
  check("verifyBytes with the correct pinned fingerprint → ok", pinned.ok === true);
  var pinnedBad = b.backupManifest.verifyBytes(customBytes, sigBlock, { expectedFingerprint: "deadbeef" });
  check("verifyBytes with a wrong pinned fingerprint → ok=false", pinnedBad.ok === false);

  // A malformed signature block is refused, not thrown.
  var noBlock = b.backupManifest.verifyBytes(customBytes, { algorithm: "x" });
  check("verifyBytes with an incomplete block → ok=false", noBlock.ok === false);
  // signBytes rejects a non-string/Buffer payload at the boundary.
  var threwIn = null;
  try { b.backupManifest.signBytes({ not: "bytes" }); } catch (e) { threwIn = e; }
  check("signBytes rejects a non-bytes payload", threwIn && threwIn.code === "backup-manifest/bad-input");

  // Manifest without signature returns ok:false (no signature to verify)
  var unsigned = b.backupManifest.create({
    vaultKeySalt: "0011",
    vaultKeyEnc:  Buffer.from("x").toString("base64"),
    files: [{
      relativePath:  "x", encryptedPath: "files/x", size: 0, encryptedSize: 0,
      checksum: "00".repeat(64), salt: "00", kind: "raw",
    }],
  });
  var noSig = b.backupManifest.verifySignature(unsigned);
  check("verifySignature on unsigned manifest → ok=false", noSig.ok === false);

  // Fingerprint-pinning substitution attack: an attacker signs arbitrary bytes
  // with their OWN key, then sets the block's self-asserted `fingerprint` field
  // to the trusted value. The pin MUST be checked against the fingerprint
  // recomputed from the block's publicKey (the key the signature verifies
  // under), not the attacker-controlled `fingerprint` string, or the forged
  // block passes pinning.
  var trustedFp = b.auditSign.getPublicKeyFingerprint();
  var atkBytes = Buffer.from("attacker-controlled-payload", "utf8");
  var atk = nodeCrypto.generateKeyPairSync("ed25519");
  var atkPubPem = atk.publicKey.export({ type: "spki", format: "pem" }).toString();
  var atkSig = nodeCrypto.sign(null, atkBytes, atk.privateKey);
  var forged = {
    algorithm: "ed25519", publicKey: atkPubPem,
    fingerprint: trustedFp,                     // the lie
    value: atkSig.toString("base64"), signedAt: new Date(0).toISOString(),
  };
  // The forged signature genuinely verifies under the attacker's own key.
  check("forged signature verifies under the attacker key (precondition)",
        nodeCrypto.verify(null, atkBytes, atkPubPem, atkSig) === true);
  // ...but pinning to the trusted fingerprint MUST reject it.
  var forgedRes = b.backupManifest.verifyBytes(atkBytes, forged, { expectedFingerprint: trustedFp });
  check("verifyBytes rejects a forged-fingerprint block under pinning", forgedRes.ok === false);
  check("verifyBytes forged-rejection cites the fingerprint mismatch",
        /does not match expectedFingerprint/.test(forgedRes.reason || ""));
  // verifySignature (manifest path) shares the fix — same substitution refused.
  var forgedManifest = JSON.parse(JSON.stringify(fixture));
  forgedManifest.signature = forged;
  var forgedMRes = b.backupManifest.verifySignature(forgedManifest, { expectedFingerprint: trustedFp });
  check("verifySignature rejects a forged-fingerprint manifest under pinning", forgedMRes.ok === false);

  // b.auditSign.fingerprintOf recomputes the fingerprint from a PEM, no init.
  check("auditSign.fingerprintOf is a function", typeof b.auditSign.fingerprintOf === "function");
  check("auditSign.fingerprintOf(active pubkey) == active fingerprint",
        b.auditSign.fingerprintOf(b.auditSign.getPublicKey()) === trustedFp);

  // Verifier-only path: a process that never ran auditSign.init() must still be
  // able to verify a detached block (it holds only a trusted public key). Reset
  // LAST so earlier checks keep their initialized signer.
  var honestBytes = Buffer.from("downstream-verifier-payload", "utf8");
  var honestBlock = b.backupManifest.signBytes(honestBytes);
  b.auditSign._resetForTest();
  var reThrew = null;
  try { b.auditSign.getPublicKey(); } catch (e) { reThrew = e; }
  check("verifier-only precondition: audit-sign is uninitialized", reThrew !== null);
  check("verifyBytes works in a verifier-only process (no init)",
        b.backupManifest.verifyBytes(honestBytes, honestBlock).ok === true);
  check("verifyBytes pinned works in a verifier-only process",
        b.backupManifest.verifyBytes(honestBytes, honestBlock, { expectedFingerprint: trustedFp }).ok === true);
  check("verifyBytes still rejects tampered bytes in a verifier-only process",
        b.backupManifest.verifyBytes(Buffer.from("tampered"), honestBlock).ok === false);
}

module.exports = { run: run };
