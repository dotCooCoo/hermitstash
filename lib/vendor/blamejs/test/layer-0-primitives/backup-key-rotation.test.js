"use strict";
/**
 * Layer 0 — bundleAdapterStorage.keyRotation: whole-repository
 * envelope rotation (composes rewrapAllBundles) + post-rotation
 * read-back under the new key (composes verifyAllBundles), so a
 * rotation that corrupts a bundle surfaces immediately rather than at
 * restore time.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _mk(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }
function _rm(d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }

async function testKeyRotationRecipient() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = _mk("kr-src-");
  var dest = _mk("kr-dest-");
  try {
    fs.writeFileSync(path.join(src, "a"), "payload", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
      audit:          false,
    });
    var ids = ["2026-05-24T09-00-00-000Z-aa000001", "2026-05-24T09-15-00-000Z-aa000002"];
    for (var i = 0; i < ids.length; i += 1) await storage.writeBundle(ids[i], src);

    var report = await storage.keyRotation({ newRecipient: newPair });
    check("keyRotation: rotated every bundle", report.total === 2 && report.rotated === 2 && report.failed === 0);
    check("keyRotation: post-rotation verify read every bundle under the new key",
      report.verified === 2 && report.verifyFailed === 0);
    check("keyRotation: carries a rotationId + rotatedAt", /^rotation-/.test(report.rotationId) && typeof report.rotatedAt === "string");

    // Independent confirmation: a fresh storage under the NEW key reads all bundles.
    var fresh = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      newPair,
      audit:          false,
    });
    var v = await fresh.verifyAllBundles();
    check("keyRotation: rotation landed — new-key storage verifies all", v.ok === 2 && v.failed === 0);
  } finally { _rm(src); _rm(dest); }
}

async function testKeyRotationPassphrase() {
  var oldPass = b.crypto.generateBytes(32).toString("hex");
  var newPass = b.crypto.generateBytes(32).toString("hex");
  var src = _mk("kr-pp-src-");
  var dest = _mk("kr-pp-dest-");
  try {
    fs.writeFileSync(path.join(src, "a"), "payload", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     oldPass,
      audit:          false,
    });
    await storage.writeBundle("2026-05-24T11-00-00-000Z-bb000001", src);
    var report = await storage.keyRotation({ oldPassphrase: oldPass, newPassphrase: newPass });
    check("keyRotation: passphrase rotation rotated + verified",
      report.rotated === 1 && report.failed === 0 && report.verified === 1 && report.verifyFailed === 0);
  } finally { _rm(src); _rm(dest); }
}

async function testKeyRotationVerifyOptOut() {
  var oldPair = b.crypto.generateEncryptionKeyPair();
  var newPair = b.crypto.generateEncryptionKeyPair();
  var src = _mk("kr-nov-src-");
  var dest = _mk("kr-nov-dest-");
  try {
    fs.writeFileSync(path.join(src, "a"), "payload", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      oldPair,
      audit:          false,
    });
    await storage.writeBundle("2026-05-24T12-00-00-000Z-cc000001", src);
    var report = await storage.keyRotation({ newRecipient: newPair, verify: false });
    check("keyRotation: verify:false skips read-back (verified null)", report.rotated === 1 && report.verified === null && report.verifyFailed === 0);
  } finally { _rm(src); _rm(dest); }
}

async function testKeyRotationRefusals() {
  var dest = _mk("kr-ref-dest-");
  try {
    // cryptoStrategy "none" — nothing to rotate.
    var plain = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }), audit: false,
    });
    var none = null;
    try { await plain.keyRotation({ newRecipient: b.crypto.generateEncryptionKeyPair() }); } catch (e) { none = e; }
    check("keyRotation: refuses on cryptoStrategy none", none && none.code === "backup/no-envelope-to-rewrap");

    var rec = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      cryptoStrategy: "recipient",
      recipient:      b.crypto.generateEncryptionKeyPair(),
      audit:          false,
    });
    // Missing newRecipient.
    var noNew = null;
    try { await rec.keyRotation({}); } catch (e) { noNew = e; }
    check("keyRotation: refuses without newRecipient", noNew && noNew.code === "backup/no-recipient");

    // dualWrap deferred-with-condition.
    var dual = null;
    try { await rec.keyRotation({ newRecipient: b.crypto.generateEncryptionKeyPair(), dualWrap: true }); } catch (e) { dual = e; }
    check("keyRotation: dualWrap refused (deferred — needs multi-recipient envelopes)",
      dual && dual.code === "backup/dual-wrap-unsupported");
  } finally { _rm(dest); }
}

async function run() {
  await testKeyRotationRecipient();
  await testKeyRotationPassphrase();
  await testKeyRotationVerifyOptOut();
  await testKeyRotationRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-key-rotation] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
