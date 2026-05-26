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

async function testTenantStrategyDeferred() {
  var refused = null;
  try {
    b.archive.wrap(Buffer.from("bytes"), { recipient: "tenant", tenantId: "alpha" });
  } catch (e) { refused = e; }
  check("archive.wrap: tenant strategy deferred to v0.12.11 with explicit message",
    refused && /tenant-strategy-deferred/.test(refused.code || refused.message));
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
  await testTenantStrategyDeferred();
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
