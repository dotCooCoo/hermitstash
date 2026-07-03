// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.backup.bundleAdapterStorage#verifyBundle integrity
 * check across plaintext + recipient + passphrase + directory.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _mkSrcDir(name, contents) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-src-"));
  fs.writeFileSync(path.join(dir, name), contents, { mode: 0o600 });
  return dir;
}

async function testVerifyTarGzRecipientOk() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var src = _mkSrcDir("a.json", "{\"x\":1}");
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "recipient",
      recipient:      pair,
    });
    var bid = "2026-05-24T01-00-00-000Z-aaaa1111";
    await storage.writeBundle(bid, src);
    var v = await storage.verifyBundle(bid);
    check("verifyBundle: tar.gz + recipient bundle reports ok=true",
      v.ok === true);
    check("verifyBundle: format reported", v.format === "tar.gz");
    check("verifyBundle: envelopeKind reported", v.envelopeKind === "recipient");
    check("verifyBundle: entryCount populated", v.entryCount === 1);
    check("verifyBundle: errors array empty", v.errors.length === 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyTarPassphraseOk() {
  var src = _mkSrcDir("a.json", "{\"x\":1}");
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-p-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    var bid = "2026-05-24T01-15-00-000Z-bbbb2222";
    await storage.writeBundle(bid, src);
    var v = await storage.verifyBundle(bid);
    check("verifyBundle: tar + passphrase ok",
      v.ok === true && v.envelopeKind === "passphrase" && v.entryCount === 1);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyPlaintextTarOk() {
  var src = _mkSrcDir("a.json", "{\"x\":1}");
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-pt-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar",
    });
    var bid = "2026-05-24T01-30-00-000Z-cccc3333";
    await storage.writeBundle(bid, src);
    var v = await storage.verifyBundle(bid);
    check("verifyBundle: plaintext tar ok",
      v.ok === true && v.envelopeKind === "none" && v.entryCount === 1);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyWrongPassphraseFails() {
  var src = _mkSrcDir("a.json", "{\"x\":1}");
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-wp-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar",
      cryptoStrategy: "passphrase",
      passphrase:     "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    var bid = "2026-05-24T01-45-00-000Z-dddd4444";
    await storage.writeBundle(bid, src);
    var v = await storage.verifyBundle(bid, {
      passphrase: "wrongPassphrase!CompletelyDifferent987654321",
    });
    check("verifyBundle: wrong passphrase reports ok=false with error",
      v.ok === false && v.errors.length > 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyCorruptedTarFails() {
  // Write a tar bundle, corrupt the tar header, verify reports failure.
  var src = _mkSrcDir("a.json", "{\"x\":1}");
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-cor-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar",
    });
    var bid = "2026-05-24T02-00-00-000Z-eeee5555";
    await storage.writeBundle(bid, src);
    var tarPath = path.join(dest, bid, "bundle.tar");
    // Corrupt the first 257 bytes (header field) so ustar magic + chksum break.
    var bytes = fs.readFileSync(tarPath);
    bytes[257] = 0x42; bytes[258] = 0x42; bytes[259] = 0x42;
    fs.writeFileSync(tarPath, bytes, { mode: 0o600 });
    var v = await storage.verifyBundle(bid);
    check("verifyBundle: corrupted tar reports ok=false with error",
      v.ok === false && v.errors.length > 0);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyDirectoryOk() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dir-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dir-dest-"));
  try {
    fs.writeFileSync(path.join(src, "manifest.json"), "{\"v\":1}", { mode: 0o600 });
    fs.writeFileSync(path.join(src, "a"), "x", { mode: 0o600 });
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "directory",
    });
    var bid = "2026-05-24T02-15-00-000Z-ffff6666";
    await storage.writeBundle(bid, src);
    var v = await storage.verifyBundle(bid);
    check("verifyBundle: directory format reports ok=true (manifest existence is the verification)",
      v.ok === true && v.format === "directory" && v.entryCount === null);
  } finally {
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testVerifyMissingBundleFails() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "vb-dest-mb-"));
  try {
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
    });
    var v = await storage.verifyBundle("2026-05-24T02-30-00-000Z-99999999");
    check("verifyBundle: missing bundle reports ok=false with bundle-not-found",
      v.ok === false && /bundle-not-found/.test(v.errors[0] || ""));
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testVerifyTarGzRecipientOk();
  await testVerifyTarPassphraseOk();
  await testVerifyPlaintextTarOk();
  await testVerifyWrongPassphraseFails();
  await testVerifyCorruptedTarFails();
  await testVerifyDirectoryOk();
  await testVerifyMissingBundleFails();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-verify-bundle] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
