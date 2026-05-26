"use strict";
/**
 * Layer 0 — b.archive.gz write + b.archive.read.gz read +
 * tar.gz composition + bundleAdapterStorage tar.gz format.
 *
 * Coverage: round-trip standalone gzip, safeDecompress bomb caps,
 * magic refusal, asTar/asZip composition, backup tar.gz end-to-end.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testGzRoundTrip() {
  var src = Buffer.from("hello world ".repeat(100));
  var compressed = b.archive.gz(src).toBuffer();
  check("archive.gz: compressed shorter than source",
    compressed.length < src.length);
  check("archive.gz: gzip magic 0x1f 0x8b",
    compressed[0] === 0x1f && compressed[1] === 0x8b);
  var reader = b.archive.read.gz(b.archive.adapters.buffer(compressed));
  var roundTrip = await reader.toBuffer();
  check("archive.read.gz: round-trip preserves bytes",
    roundTrip.equals(src));
}

async function testGzBadMagicRefused() {
  var notGzip = Buffer.from("this is not gzipped content at all");
  var refused = null;
  try {
    var reader = b.archive.read.gz(b.archive.adapters.buffer(notGzip));
    await reader.toBuffer();
  } catch (e) { refused = e; }
  check("archive.read.gz: non-gzip input refused with typed error",
    refused && /bad-magic/.test(refused.code || refused.message));
  check("archive.read.gz: refusal is a b.archive.ArchiveGzError",
    refused instanceof b.archive.ArchiveGzError);
}

async function testGzBombCapRefused() {
  // Build a 64 KiB gzip stream of all-zeros (high compression ratio).
  // Cap the decompressed size to 16 KiB → must refuse.
  var src = Buffer.alloc(64 * 1024);
  var compressed = b.archive.gz(src).toBuffer();
  var reader = b.archive.read.gz(b.archive.adapters.buffer(compressed), {
    maxDecompressedBytes: 16 * 1024,
  });
  var refused = null;
  try { await reader.toBuffer(); } catch (e) { refused = e; }
  check("archive.read.gz: maxDecompressedBytes cap refuses bomb",
    refused !== null);
}

async function testTarToGzip() {
  var t = b.archive.tar();
  t.addFile("payload.txt", "hello world");
  // toAdapter expects an archive-adapter shape: write(bytes) + close().
  var chunks = [];
  var adapter = {
    write: async function (bytes) { chunks.push(bytes); },
    close: async function () { /* noop */ },
  };
  await t.toGzip(adapter);
  var assembled = Buffer.concat(chunks);
  check("archive.tar().toGzip: produces gzip magic",
    assembled[0] === 0x1f && assembled[1] === 0x8b);
  // Round-trip through read.gz.asTar
  var reader = b.archive.read.gz(b.archive.adapters.buffer(assembled));
  var tarReader = reader.asTar();
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tgz-"));
  try {
    await tarReader.extract({ destination: dest });
    check("archive.tar().toGzip → read.gz.asTar.extract: file restored",
      fs.readFileSync(path.join(dest, "payload.txt"), "utf-8") === "hello world");
  } finally {
    try { fs.rmSync(dest, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBackupTarGzHighRatioRoundTrip() {
  // Codex P1 on v0.12.9 PR #160 — a zero-filled file compresses
  // at >100× ratio; the default safeDecompress ratio cap was
  // refusing legitimate self-authored bundles on read.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tgzr-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tgzr-dest-"));
  var verify = path.join(os.tmpdir(), "bjs-tgzr-verify-" + Date.now());
  try {
    // 1 MiB of zeros — gzip should compress this to a few hundred
    // bytes (ratio ~ 5000×), well past the 100× default.
    fs.writeFileSync(path.join(src, "zeros.bin"), Buffer.alloc(1024 * 1024));
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bundleId = "2026-05-23T17-30-00-000Z-11223344";
    await storage.writeBundle(bundleId, src);
    await storage.readBundle(bundleId, verify);
    check("backup tar.gz: high-ratio bundle restores past the 100× default",
      fs.readFileSync(path.join(verify, "zeros.bin")).length === 1024 * 1024);
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBackupTarGzRoundTrip() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tgz-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-tgz-dest-"));
  var verify = path.join(os.tmpdir(), "bjs-tgz-verify-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "a.txt"), "hello world ".repeat(100));
    fs.writeFileSync(path.join(src, "b.txt"), "goodbye ".repeat(50));
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:  "tar.gz",
    });
    var bundleId = "2026-05-23T17-00-00-000Z-aabbccdd";
    await storage.writeBundle(bundleId, src);
    var bundleDir = path.join(dest, bundleId);
    check("backup tar.gz: bundle.tar.gz key written",
      fs.existsSync(path.join(bundleDir, "bundle.tar.gz")));
    var gzBytes = fs.readFileSync(path.join(bundleDir, "bundle.tar.gz"));
    check("backup tar.gz: payload carries gzip magic",
      gzBytes[0] === 0x1f && gzBytes[1] === 0x8b);
    check("backup tar.gz: hasBundle true for tar.gz format",
      await storage.hasBundle(bundleId));
    await storage.readBundle(bundleId, verify);
    check("backup tar.gz: a.txt round-trips",
      fs.readFileSync(path.join(verify, "a.txt"), "utf-8") === "hello world ".repeat(100));
    check("backup tar.gz: b.txt round-trips",
      fs.readFileSync(path.join(verify, "b.txt"), "utf-8") === "goodbye ".repeat(50));
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testGzRoundTrip();
  await testGzBadMagicRefused();
  await testGzBombCapRefused();
  await testTarToGzip();
  await testBackupTarGzRoundTrip();
  await testBackupTarGzHighRatioRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-gz] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
