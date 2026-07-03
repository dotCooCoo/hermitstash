// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.archive.wrap + b.archive.unwrap + bundleAdapterStorage
 * cryptoStrategy: "recipient" + posture-enforced encryption.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testWrapUnwrapRoundTrip() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = Buffer.from("opaque archive bytes ".repeat(50));
  var sealed = b.archive.wrap(src, { recipient: pair });
  check("archive.wrap: output carries BAWRP magic",
    sealed.slice(0, 5).toString("ascii") === "BAWRP");
  check("archive.wrap: output version byte present",
    sealed[5] === 0x01);
  var recovered = b.archive.unwrap(sealed, { recipient: pair });
  check("archive.wrap → unwrap: bytes round-trip losslessly",
    recovered.equals(src));
}

async function testWrapRefusesBadMagic() {
  var notSealed = Buffer.from("this is not a wrap envelope");
  var refused = null;
  try {
    b.archive.unwrap(notSealed, { recipient: b.crypto.generateEncryptionKeyPair() });
  } catch (e) { refused = e; }
  check("archive.unwrap: non-BAWRP input refused with bad-magic",
    refused && /bad-magic/.test(refused.code || refused.message));
  check("archive.unwrap: refusal is a b.archive.ArchiveWrapError",
    refused instanceof b.archive.ArchiveWrapError);
}

async function testWrapRefusesWrongKey() {
  var sender = b.crypto.generateEncryptionKeyPair();
  var attacker = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("PHI"), { recipient: sender });
  var refused = null;
  try { b.archive.unwrap(sealed, { recipient: attacker }); } catch (e) { refused = e; }
  check("archive.unwrap: wrong recipient key refused",
    refused && /decrypt-failed/.test(refused.code || refused.message));
}

async function testWrapRefusesPartialStaticRecipient() {
  // Codex P2 on v0.12.10 PR #161 — partial recipient ({ publicKey }
  // alone) silently triggered b.crypto.encrypt's ML-KEM-only
  // fallback, degrading the documented hybrid contract.
  var pair = b.crypto.generateEncryptionKeyPair();
  var refused = null;
  try {
    b.archive.wrap(Buffer.from("bytes"), { recipient: { publicKey: pair.publicKey } });
  } catch (e) { refused = e; }
  check("archive.wrap: refuses partial static recipient (missing ecPublicKey)",
    refused && /hybrid-required/.test(refused.code || refused.message));
}

async function testBackupRecipientDirectoryRefused() {
  // Codex P1 on v0.12.10 PR #161 — recipient strategy + directory
  // format would write plaintext per-file; refuse upfront.
  var refused = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      format:         "directory",
      cryptoStrategy: "recipient",
      recipient:      b.crypto.generateEncryptionKeyPair(),
    });
  } catch (e) { refused = e; }
  check("backup: recipient + directory format refused upfront",
    refused && /recipient-strategy-needs-bundled-format/.test(refused.code || refused.message));
}

async function testWrapRequiresRecipient() {
  var refused = null;
  try { b.archive.wrap(Buffer.from("bytes"), {}); } catch (e) { refused = e; }
  check("archive.wrap: missing recipient refused upfront",
    refused && /no-recipient/.test(refused.code || refused.message));
}

async function testTenantStrategyRoundTrip() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-tenant-"));
  try {
    await helpers.setupVaultOnly(tmpDir);
    var src = Buffer.from("per-tenant sealed archive bytes ".repeat(40));

    // wrap → unwrap round-trips for the same tenant, no key-pair managed.
    var sealed = b.archive.wrap(src, { recipient: "tenant", tenantId: "alpha" });
    check("archive.wrap tenant: BAWRP magic",
      sealed.slice(0, 5).toString("ascii") === "BAWRP");
    check("archive.wrap tenant: version byte is 0x02 (tenant)",
      sealed[5] === 0x02);
    var recovered = b.archive.unwrap(sealed, { recipient: "tenant", tenantId: "alpha" });
    check("archive.wrap tenant: round-trips losslessly", recovered.equals(src));
    // recipient may be omitted on unwrap (version byte selects the path).
    var recovered2 = b.archive.unwrap(sealed, { tenantId: "alpha" });
    check("archive.wrap tenant: unwrap works with tenantId alone", recovered2.equals(src));

    // Cross-tenant isolation — a different tenant's derived key (and AAD)
    // cannot open tenant alpha's envelope.
    var crossErr = null;
    try { b.archive.unwrap(sealed, { recipient: "tenant", tenantId: "beta" }); }
    catch (e) { crossErr = e; }
    check("archive.wrap tenant: another tenant cannot decrypt",
      crossErr && /decrypt-failed/.test(crossErr.code || crossErr.message));

    // Missing tenantId on wrap throws a clear config error.
    var noIdErr = null;
    try { b.archive.wrap(src, { recipient: "tenant" }); }
    catch (e) { noIdErr = e; }
    check("archive.wrap tenant: missing tenantId throws no-tenant-id",
      noIdErr && /no-tenant-id/.test(noIdErr.code || noIdErr.message));

    // Passing a key-pair recipient to a tenant envelope is refused.
    var mismatchErr = null;
    try { b.archive.unwrap(sealed, { recipient: { privateKey: "x", ecPrivateKey: "y" } }); }
    catch (e) { mismatchErr = e; }
    check("archive.wrap tenant: key-pair recipient on tenant envelope refused",
      mismatchErr && /recipient-mismatch/.test(mismatchErr.code || mismatchErr.message));

    // Determinism — re-wrapping the same bytes for the same tenant yields
    // a DIFFERENT envelope (fresh nonce) that still opens to the same plaintext.
    var sealed2 = b.archive.wrap(src, { recipient: "tenant", tenantId: "alpha" });
    check("archive.wrap tenant: fresh nonce per wrap (envelopes differ)",
      !sealed2.equals(sealed));
    check("archive.wrap tenant: second envelope also round-trips",
      b.archive.unwrap(sealed2, { tenantId: "alpha" }).equals(src));
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testRewrapTenantRotationRoundTrip() {
  // A recipient: "tenant" blob is keyed off the vault root. Rotating
  // the vault keypair changes the root, so the old envelope no longer
  // opens — the operator must re-wrap each stored blob old-root ->
  // new-root via b.archive.rewrapTenant before retiring the old keypair.
  var oldDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-rewrap-old-"));
  var newDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-rewrap-new-"));
  try {
    await helpers.setupVaultOnly(oldDir);
    var oldRoot = b.vault.getKeysJson();
    var src = Buffer.from("per-tenant sealed archive bytes ".repeat(40));
    var sealedOld = b.archive.wrap(src, { recipient: "tenant", tenantId: "alpha" });
    check("rewrapTenant: pre-rotation blob opens under the old root",
      b.archive.unwrap(sealedOld, { tenantId: "alpha" }).equals(src));

    // Simulate a vault rotation: a fresh keypair (new dir) is now live.
    await helpers.setupVaultOnly(newDir);
    var newRoot = b.vault.getKeysJson();
    check("rewrapTenant: rotation produced a distinct vault root", oldRoot !== newRoot);

    // The old blob is now stranded under the live (new) root — this is
    // the data-loss class the primitive defends.
    var stranded = null;
    try { b.archive.unwrap(sealedOld, { tenantId: "alpha" }); } catch (e) { stranded = e; }
    check("rewrapTenant: old blob no longer opens under the new live root",
      stranded && /decrypt-failed/.test(stranded.code || stranded.message));

    var rewrapped = b.archive.rewrapTenant({
      blob:        sealedOld,
      oldRootJson: oldRoot,
      newRootJson: newRoot,
      tenantId:    "alpha",
    });
    check("rewrapTenant: output carries BAWRP magic",
      rewrapped.slice(0, 5).toString("ascii") === "BAWRP");
    check("rewrapTenant: output keeps the tenant version byte 0x02",
      rewrapped[5] === 0x02);
    check("rewrapTenant: re-wrapped blob opens under the new live root via standard unwrap",
      b.archive.unwrap(rewrapped, { tenantId: "alpha" }).equals(src));

    // Cross-tenant isolation survives the re-wrap: another tenant's key
    // (and AAD) cannot open the re-wrapped envelope.
    var crossErr = null;
    try { b.archive.unwrap(rewrapped, { tenantId: "beta" }); } catch (e) { crossErr = e; }
    check("rewrapTenant: re-wrapped blob refuses another tenant",
      crossErr && /decrypt-failed/.test(crossErr.code || crossErr.message));
  } finally {
    helpers.teardownVaultOnly(oldDir);
    helpers.teardownVaultOnly(newDir);
  }
}

async function testRewrapTenantRefusals() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-rewrap-refuse-"));
  try {
    await helpers.setupVaultOnly(tmpDir);
    var root = b.vault.getKeysJson();
    var src = Buffer.from("tenant bytes");

    // Non-tenant envelope (a key-pair recipient, version 0x01) must be
    // refused — rewrapTenant only handles root-keyed tenant blobs.
    var pair = b.crypto.generateEncryptionKeyPair();
    var recipientBlob = b.archive.wrap(src, { recipient: pair });
    var notTenantErr = null;
    try {
      b.archive.rewrapTenant({ blob: recipientBlob, oldRootJson: root, newRootJson: root, tenantId: "alpha" });
    } catch (e) { notTenantErr = e; }
    check("rewrapTenant: refuses a recipient (key-pair) envelope",
      notTenantErr && /not-tenant-envelope/.test(notTenantErr.code || notTenantErr.message));

    // A passphrase envelope (different magic) is refused with bad-magic.
    var passBlob = await b.archive.wrapWithPassphrase(src, {
      passphrase:     "operator-supplied-long-passphrase-2026",
      minEntropyBits: 0,
    });
    var badMagicErr = null;
    try {
      b.archive.rewrapTenant({ blob: passBlob, oldRootJson: root, newRootJson: root, tenantId: "alpha" });
    } catch (e) { badMagicErr = e; }
    check("rewrapTenant: refuses a passphrase (BAWPP) envelope with bad-magic",
      badMagicErr && /bad-magic/.test(badMagicErr.code || badMagicErr.message));

    // Wrong old root → the blob does not open → decrypt-failed.
    var sealed = b.archive.wrap(src, { recipient: "tenant", tenantId: "alpha" });
    var wrongRootJson = b.vault.getKeysJson().replace(/[A-Za-z]/, function (c) {
      return c === "A" ? "B" : "A";
    });
    var wrongRootErr = null;
    try {
      b.archive.rewrapTenant({ blob: sealed, oldRootJson: wrongRootJson, newRootJson: root, tenantId: "alpha" });
    } catch (e) { wrongRootErr = e; }
    check("rewrapTenant: wrong old root refused with decrypt-failed",
      wrongRootErr && /decrypt-failed/.test(wrongRootErr.code || wrongRootErr.message));

    // Missing roots / tenantId throw config errors.
    var noRootErr = null;
    try {
      b.archive.rewrapTenant({ blob: sealed, newRootJson: root, tenantId: "alpha" });
    } catch (e) { noRootErr = e; }
    check("rewrapTenant: missing oldRootJson throws bad-root",
      noRootErr && /bad-root/.test(noRootErr.code || noRootErr.message));

    var noIdErr = null;
    try {
      b.archive.rewrapTenant({ blob: sealed, oldRootJson: root, newRootJson: root });
    } catch (e) { noIdErr = e; }
    check("rewrapTenant: missing tenantId throws no-tenant-id",
      noIdErr && /no-tenant-id/.test(noIdErr.code || noIdErr.message));

    var badBlobErr = null;
    try {
      b.archive.rewrapTenant({ blob: "not a buffer", oldRootJson: root, newRootJson: root, tenantId: "alpha" });
    } catch (e) { badBlobErr = e; }
    check("rewrapTenant: non-Buffer blob throws bad-input",
      badBlobErr && /bad-input/.test(badBlobErr.code || badBlobErr.message));
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testAadRotationDescriptor() {
  var aw = require("../../lib/archive-wrap");
  var desc = aw.AAD_ROTATION;
  check("AAD_ROTATION: descriptor present", desc && typeof desc === "object");
  check("AAD_ROTATION: backend is external (operator-placed blobs)", desc.backend === "external");
  check("AAD_ROTATION: rowIdField + schemaVersion + table declared",
    desc.table === "archive-wrap:tenant-blobs" && desc.rowIdField === "id" && desc.schemaVersion === "1");
  check("AAD_ROTATION: reseal is a function", typeof desc.reseal === "function");

  var oldDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-reseal-old-"));
  var newDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aw-reseal-new-"));
  try {
    await helpers.setupVaultOnly(oldDir);
    var oldRoot = b.vault.getKeysJson();
    var srcA = Buffer.from("alpha archive ".repeat(20));
    var srcB = Buffer.from("beta archive ".repeat(20));
    var blobs = {
      a1: b.archive.wrap(srcA, { recipient: "tenant", tenantId: "alpha" }),
      b1: b.archive.wrap(srcB, { recipient: "tenant", tenantId: "beta" }),
    };

    await helpers.setupVaultOnly(newDir);
    var newRoot = b.vault.getKeysJson();

    // Operator-supplied backing store: list() enumerates the blobs the
    // operator placed; put() writes the re-wrapped bytes back.
    var store = {
      list: function () {
        return [
          { id: "a1", blob: blobs.a1, tenantId: "alpha" },
          { id: "b1", blob: blobs.b1, tenantId: "beta" },
        ];
      },
      put: function (id, blob) { blobs[id] = blob; },
    };
    var result = desc.reseal({ store: store, oldRootJson: oldRoot, newRootJson: newRoot });
    check("AAD_ROTATION.reseal: re-sealed every store entry", result.resealed === 2);
    check("AAD_ROTATION.reseal: alpha blob opens under the new root",
      b.archive.unwrap(blobs.a1, { tenantId: "alpha" }).equals(srcA));
    check("AAD_ROTATION.reseal: beta blob opens under the new root",
      b.archive.unwrap(blobs.b1, { tenantId: "beta" }).equals(srcB));

    var badStoreErr = null;
    try { desc.reseal({ store: {}, oldRootJson: oldRoot, newRootJson: newRoot }); }
    catch (e) { badStoreErr = e; }
    check("AAD_ROTATION.reseal: store without list/put refused",
      badStoreErr && /bad-store/.test(badStoreErr.code || badStoreErr.message));
  } finally {
    helpers.teardownVaultOnly(oldDir);
    helpers.teardownVaultOnly(newDir);
  }
}

async function testBackupRecipientRoundTrip() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-wrap-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-wrap-dest-"));
  var verify = path.join(os.tmpdir(), "bjs-wrap-verify-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"patient\":42,\"dx\":\"redacted\"}");
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bundleId = "2026-05-23T18-15-00-000Z-bbbbbbbb";
    await storage.writeBundle(bundleId, src);
    var sealed = fs.readFileSync(path.join(dest, bundleId, "bundle.tar.gz"));
    check("backup recipient: bundle on disk carries BAWRP magic (not gzip)",
      sealed.slice(0, 5).toString("ascii") === "BAWRP");
    await storage.readBundle(bundleId, verify);
    check("backup recipient: phi.json round-trips after unwrap+gunzip+untar",
      fs.readFileSync(path.join(verify, "phi.json"), "utf-8") === "{\"patient\":42,\"dx\":\"redacted\"}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBackupRecipientStrategyRequiresKeys() {
  var refused = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      cryptoStrategy: "recipient",
    });
  } catch (e) { refused = e; }
  check("backup: cryptoStrategy: recipient without keys refused upfront",
    refused && /no-recipient/.test(refused.code || refused.message));
}

async function testBackupPostureRefusesPlaintext() {
  var refused = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      posture: "hipaa",
      cryptoStrategy: "none",
    });
  } catch (e) { refused = e; }
  check("backup: HIPAA posture refuses cryptoStrategy: none",
    refused && /posture-requires-encryption/.test(refused.code || refused.message));
  var refused2 = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      posture: "pci-dss",
    });
  } catch (e) { refused2 = e; }
  check("backup: PCI-DSS posture refuses default cryptoStrategy",
    refused2 && /posture-requires-encryption/.test(refused2.code || refused2.message));
}

async function run() {
  await testWrapUnwrapRoundTrip();
  await testWrapRefusesBadMagic();
  await testWrapRefusesWrongKey();
  await testWrapRefusesPartialStaticRecipient();
  await testWrapRequiresRecipient();
  await testTenantStrategyRoundTrip();
  await testRewrapTenantRotationRoundTrip();
  await testRewrapTenantRefusals();
  await testAadRotationDescriptor();
  await testBackupRecipientRoundTrip();
  await testBackupRecipientStrategyRequiresKeys();
  await testBackupRecipientDirectoryRefused();
  await testBackupPostureRefusesPlaintext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-wrap] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
