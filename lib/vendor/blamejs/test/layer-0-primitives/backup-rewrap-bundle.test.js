"use strict";
/**
 * Layer 0 — bundleAdapterStorage.rewrapBundle key rotation without
 * restore/rewrite of inner archive bytes.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testRewrapRecipientRotation() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-dest-"));
  var verify = path.join(os.tmpdir(), "rw-v-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.json"), "{\"v\":1}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    var bid = "2026-05-24T06-00-00-000Z-aabbccdd";
    await storage.writeBundle(bid, src);
    var rw = await storage.rewrapBundle(bid, { newRecipient: newPair });
    check("rewrapBundle: returns oldEnvelopeKind + newEnvelopeKind",
      rw.oldEnvelopeKind === "recipient" && rw.newEnvelopeKind === "recipient");
    check("rewrapBundle: bytesRewritten > 0", rw.bytesRewritten > 0);
    // Open a fresh storage with newPair + restore
    var rotated = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      newPair,
    });
    await rotated.readBundle(bid, verify);
    check("rewrapBundle: bundle restores under newRecipient after rotation",
      fs.readFileSync(path.join(verify, "a.json"), "utf-8") === "{\"v\":1}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapPassphraseRotation() {
  var oldPass = "aLongCorrectHorseBatteryStaple9876!Phrase";
  var newPass = "completelyDifferentPassphraseEvenLonger123!@#";
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-p-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-p-dest-"));
  var verify = path.join(os.tmpdir(), "rw-p-v-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.json"), "{\"v\":2}", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     oldPass,
    });
    var bid = "2026-05-24T06-30-00-000Z-eeffaabb";
    await storage.writeBundle(bid, src);
    var rw = await storage.rewrapBundle(bid, { newPassphrase: newPass });
    check("rewrapBundle: passphrase rotation reports passphrase envelope",
      rw.oldEnvelopeKind === "passphrase" && rw.newEnvelopeKind === "passphrase");
    var rotated = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     newPass,
    });
    await rotated.readBundle(bid, verify);
    check("rewrapBundle: bundle restores under newPassphrase after rotation",
      fs.readFileSync(path.join(verify, "a.json"), "utf-8") === "{\"v\":2}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapRefusesPlaintextBundle() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-pt-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-pt-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bid = "2026-05-24T06-45-00-000Z-99887766";
    await storage.writeBundle(bid, src);
    var refused = null;
    try {
      await storage.rewrapBundle(bid, {
        newRecipient: b.crypto.generateEncryptionKeyPair(),
      });
    } catch (e) { refused = e; }
    check("rewrapBundle: plaintext bundle refused with no-envelope-to-rewrap",
      refused && /no-envelope-to-rewrap/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapHipaaPreservesEntropyFloor() {
  // Codex P1 on v0.12.21 PR #172 — under HIPAA posture, the
  // storage's effective entropy floor is 128 bits. rewrapBundle
  // must enforce that floor regardless of what
  // opts.passphraseMinEntropyBits says — otherwise a rotation to
  // a weak passphrase that writeBundle would refuse slips through.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-hipaa-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-hipaa-dest-"));
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"id\":42}", { mode: 0o600 });
    var strongPass = "aLongCorrectHorseBatteryStaple9876!Phrase";   // ~227 bits
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     strongPass,
      posture:        "hipaa",
    });
    var bid = "2026-05-24T07-30-00-000Z-bbbb1111";
    await storage.writeBundle(bid, src);
    // Try rotating to a passphrase that's ~100 bits — passes the
    // default 80-bit floor but should be refused under HIPAA's
    // 128-bit floor.
    var weakPass = "lowercaseonlyword123";  // 20 chars, lower+digit alphabet=36 → ~103 bits — above 80, below 128
    var refused = null;
    try {
      await storage.rewrapBundle(bid, { newPassphrase: weakPass });
    } catch (e) { refused = e; }
    check("rewrapBundle: HIPAA posture's 128-bit entropy floor enforced across rotation",
      refused && /weak-passphrase/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapWithLegacyAdapter() {
  // Codex P2 on v0.12.21 PR #172 — adapters without readPartial
  // get envelopeKind: "unknown" from bundleInfo. rewrapBundle
  // must fall back to sniffing the loaded sealed bytes rather
  // than refusing with no-envelope-to-rewrap.
  var pair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-leg-src-"));
  var fullDest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-leg-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    // Bootstrap with the full fsAdapter to get a valid bundle.
    var bootstrap = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: fullDest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bid = "2026-05-24T07-45-00-000Z-cccc2222";
    await bootstrap.writeBundle(bid, src);
    // Re-wrap the bundle bytes through a legacy adapter that
    // exposes only the minimum contract (no readPartial / statKey).
    var fullAdapter = b.backup.bundleAdapterStorage.fsAdapter({ root: fullDest });
    var legacyAdapter = {
      writeFile: fullAdapter.writeFile,
      readFile:  fullAdapter.readFile,
      listKeys:  fullAdapter.listKeys,
      deleteKey: fullAdapter.deleteKey,
      hasKey:    fullAdapter.hasKey,
      // Intentionally omit readPartial + statKey.
    };
    var legacyStorage = b.backup.bundleAdapterStorage({
      adapter:        legacyAdapter,
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var rw = await legacyStorage.rewrapBundle(bid, { newRecipient: newPair });
    check("rewrapBundle: legacy adapter (no readPartial) succeeds via fallback sniff",
      rw.oldEnvelopeKind === "recipient" && rw.newEnvelopeKind === "recipient");
  } finally {
    try { fs.rmSync(src,      { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(fullDest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testRewrapRefusesMissingNewRecipient() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "rw-nr-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "rw-nr-dest-"));
  try {
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
    });
    var bid = "2026-05-24T07-00-00-000Z-aabbcc01";
    await storage.writeBundle(bid, src);
    var refused = null;
    try { await storage.rewrapBundle(bid, {}); } catch (e) { refused = e; }
    check("rewrapBundle: missing newRecipient refused upfront",
      refused && /no-new-recipient/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testRewrapRecipientRotation();
  await testRewrapPassphraseRotation();
  await testRewrapRefusesPlaintextBundle();
  await testRewrapRefusesMissingNewRecipient();
  await testRewrapHipaaPreservesEntropyFloor();
  await testRewrapWithLegacyAdapter();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-rewrap-bundle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
