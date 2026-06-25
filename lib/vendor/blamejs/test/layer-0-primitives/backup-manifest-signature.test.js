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
