// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.archive.tar write + b.archive.read.tar +
 * b.guardArchive.tarEntryPolicy + b.backup.migrate.
 *
 * Round-trip coverage: write tar via b.archive.tar(), read back via
 * b.archive.read.tar(buffer adapter), extract via b.safeArchive.extract
 * (format auto-detect lands on tar). Refusal: oversize entry, dangerous
 * typeflag refusal by default. Migration: write a directory bundle in
 * one storage, migrate to tar bundle in another, verify content.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");

async function testTarRoundTrip() {
  var t = b.archive.tar();
  t.addFile("readme.txt", "Hello, tar!\n");
  t.addFile("data/numbers.csv", "n,sq\n1,1\n2,4\n");
  t.addDirectory("docs/");
  t.addFile("docs/nested/deep.txt", "payload\n");
  var bytes = t.toBuffer();

  check("archive.tar: tar bytes round to 512", bytes.length % 512 === 0);
  check("archive.tar: ustar magic at offset 257",
    bytes.slice(257, 263).toString().indexOf("ustar") === 0);

  var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
  var entries = await reader.inspect();
  check("archive.read.tar.inspect: 4 entries",   entries.length === 4);
  check("archive.read.tar.inspect: file type",   entries[0].entryType === "file");
  check("archive.read.tar.inspect: directory type", entries[2].entryType === "directory");
}

async function testSafeArchiveTarExtract() {
  var t = b.archive.tar();
  t.addFile("a.txt", "alpha");
  t.addFile("nested/b.txt", "beta");
  var bytes = t.toBuffer();

  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tar-extract-"));
  try {
    var result = await b.safeArchive.extract({
      source:       bytes,
      destination:  dest,
      guardProfile: "balanced",
    });
    check("safeArchive.extract: format=tar autodetected", result.format === "tar");
    check("safeArchive.extract: 2 entries written",       result.entries.length === 2);
    var a = fs.readFileSync(path.join(dest, "a.txt"), "utf8");
    var bb = fs.readFileSync(path.join(dest, "nested", "b.txt"), "utf8");
    check("safeArchive.extract: a.txt contents",          a === "alpha");
    check("safeArchive.extract: nested b.txt contents",   bb === "beta");
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

function testTarEntryPolicy() {
  var p = b.guardArchive.tarEntryPolicy({ symlinks: true });
  check("tarEntryPolicy: symlinks opted in",      p.symlinks === true);
  check("tarEntryPolicy: hardlinks default off",   p.hardlinks === false);
  check("tarEntryPolicy: devices default off",     p.devices === false);
  check("tarEntryPolicy: fifos default off",       p.fifos === false);
  check("tarEntryPolicy: sockets default off",     p.sockets === false);
}

async function testTarChecksumDetection() {
  // Build a valid tar, corrupt the chksum field, verify reader refuses.
  var t = b.archive.tar();
  t.addFile("payload.txt", "hello\n");
  var bytes = t.toBuffer();
  // Corrupt the checksum field of the first header (offset 148, 8 bytes).
  bytes[148] = 0x39;   // change first chksum digit
  var refused = null;
  try {
    var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
    await reader.inspect();
  } catch (e) { refused = e; }
  check("archive.read.tar: corrupted chksum refused",
    refused && /chksum|bad-octal/.test(refused.code || refused.message));
  check("archive.read.tar: chksum refusal is a b.archive.TarError",
    refused instanceof b.archive.TarError);
}

async function testBackupMigrateDirectoryToTar() {
  var fromRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-from-"));
  var toRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-to-"));
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-src-"));
  var verifyDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-verify-"));
  fs.rmSync(verifyDir, { recursive: true });    // backend wants non-existent dest
  try {
    fs.writeFileSync(path.join(srcDir, "manifest.json"), JSON.stringify({ v: 1 }));
    fs.mkdirSync(path.join(srcDir, "files"));
    fs.writeFileSync(path.join(srcDir, "files", "blob.bin"), Buffer.from([1, 2, 3]));

    var from = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: fromRoot }),
      format:  "directory",
    });
    var to = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: toRoot }),
      format:  "tar",
    });

    var bundleId = "2026-05-23T15-00-00-000Z-deadbeef";
    await from.writeBundle(bundleId, srcDir);
    check("migrate: source-bundle exists pre-migrate", await from.hasBundle(bundleId));
    check("migrate: dest-bundle absent pre-migrate", !(await to.hasBundle(bundleId)));

    var report = await b.backup.migrate({ from: from, to: to });
    check("migrate: 1 migrated", report.migrated === 1 && report.skipped === 0);
    check("migrate: dest-bundle present post-migrate", await to.hasBundle(bundleId));

    // Idempotency: second run skips.
    var second = await b.backup.migrate({ from: from, to: to });
    check("migrate: idempotent (1 skipped)", second.migrated === 0 && second.skipped === 1);

    // Read back from destination, verify file contents.
    await to.readBundle(bundleId, verifyDir);
    var manifest = JSON.parse(fs.readFileSync(path.join(verifyDir, "manifest.json"), "utf8"));
    check("migrate: manifest round-tripped", manifest.v === 1);
    var blob = fs.readFileSync(path.join(verifyDir, "files", "blob.bin"));
    check("migrate: blob round-tripped",
      blob.length === 3 && blob[0] === 1 && blob[2] === 3);
  } finally {
    try { fs.rmSync(fromRoot,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(toRoot,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(srcDir,     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verifyDir,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBackupTarFormatDefault() {
  // Write a bundle via the v0.12.8-default format (tar) + verify the
  // tar key landed on disk.
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-tar-default-"));
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-tar-src-"));
  try {
    fs.writeFileSync(path.join(src, "manifest.json"), JSON.stringify({ v: 1 }));
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: root }),
      // format defaults to "tar" in v0.12.8
    });
    var bid = "2026-05-23T15-30-00-000Z-cafebabe";
    await storage.writeBundle(bid, src);
    var tarKeyPresent = fs.existsSync(path.join(root, bid, "bundle.tar"));
    check("bundleAdapterStorage default format: tar key on disk", tarKeyPresent);
    check("bundleAdapterStorage default format: hasBundle true",
      await storage.hasBundle(bid));
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(src,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testTarTruncationRefused() {
  // Codex P1 on v0.12.8 PR #159 — declare 11 bytes in the header
  // but truncate the buffer to 8 payload bytes. The walker must
  // refuse upfront rather than emitting a partial entry.
  var t = b.archive.tar();
  t.addFile("payload.txt", Buffer.from("hello world"));    // 11 bytes
  var bytes = t.toBuffer();
  // First header block is at offset 0-511; first data block at
  // 512-1023 (padded to 512 bytes from the declared 11). Truncate to
  // 768 bytes: header survives intact but the data block ends
  // halfway — walker must refuse before slicing partial bytes as
  // a "complete" file.
  var truncated = bytes.slice(0, 768);
  var refused = null;
  try {
    var reader = b.archive.read.tar(b.archive.adapters.buffer(truncated));
    await reader.extract({
      destination: fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tar-trunc-")),
    });
  } catch (e) { refused = e; }
  check("archive.read.tar: truncated entry refused with typed error",
    refused && /truncated-entry/.test(refused.code || refused.message));
}

async function testBackupBundleTooLargeRefused() {
  // Codex P2 on v0.12.8 PR #159 — bundleAdapterStorage with a
  // tight maxBundleBytes cap must refuse oversized payloads upfront
  // rather than OOM during in-memory tar materialization.
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-bulk-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-bk-bulk-dest-"));
  try {
    fs.writeFileSync(path.join(srcDir, "big.bin"), Buffer.alloc(64 * 1024));
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar",
      maxBundleBytes: 16 * 1024,
    });
    var refused = null;
    try {
      await storage.writeBundle("2026-05-23T00-00-00-000Z-abcdef12", srcDir);
    } catch (e) { refused = e; }
    check("backup: bundle exceeding maxBundleBytes refused upfront",
      refused && /bundle-too-large/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(srcDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testTarRoundTrip();
  await testSafeArchiveTarExtract();
  testTarEntryPolicy();
  await testTarChecksumDetection();
  await testTarTruncationRefused();
  await testBackupMigrateDirectoryToTar();
  await testBackupTarFormatDefault();
  await testBackupBundleTooLargeRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-tar] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
