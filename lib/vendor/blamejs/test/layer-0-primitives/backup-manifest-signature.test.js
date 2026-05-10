"use strict";
/**
 * Backup-manifest signature — ML-DSA-87 / SLH-DSA-SHAKE-256f signed
 * manifest with detached signature block. Covers F-BUDR-3.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("backupManifest.sign is fn",            typeof b.backupManifest.sign === "function");
  check("backupManifest.verifySignature is fn", typeof b.backupManifest.verifySignature === "function");
  check("backupManifest.signingPayload is fn",  typeof b.backupManifest.signingPayload === "function");
  check("backupBundle.verifyManifestSignature is fn",
    typeof b.backup.verifyManifestSignature === "function");

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
}

module.exports = { run: run };
