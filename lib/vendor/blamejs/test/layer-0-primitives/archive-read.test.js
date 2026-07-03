// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.archive read substrate + safe-extract orchestrator +
 * guard-archive policy builders + b.guardFilename.verifyExtractionPath
 * + b.backup.bundleAdapterStorage.
 *
 * Round-trip coverage: write a ZIP via the existing write side, read
 * it back via b.archive.read.zip (random-access buffer adapter), extract
 * via b.safeArchive.extract into a quarantine directory, verify file
 * contents. Refusal coverage: zip-slip entry name, oversize entries,
 * NUL byte, PATH_MAX overflow.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");

async function testRoundTripExtract() {
  var z = b.archive.zip();
  z.addFile("readme.txt", "Hello, archive-read!\n");
  z.addFile("data/numbers.csv", "n,sq\n1,1\n2,4\n3,9\n");
  z.addFile("docs/nested/deep.txt", Buffer.from("payload\n"));
  var bytes = z.toBuffer();

  // Inspect via buffer adapter — verifies adapter contract + EOCD walk +
  // CD-walk + LFH/CD skew check.
  var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes));
  var entries = await reader.inspect();
  check("archive.read.zip.inspect: 3 entries",         entries.length === 3);
  check("archive.read.zip.inspect: name + size",        entries[0].name === "readme.txt" && entries[0].size === 21);
  check("archive.read.zip.inspect: nested name",        entries[2].name === "docs/nested/deep.txt");

  // Extract via safeArchive orchestrator.
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-archive-test-"));
  try {
    var result = await b.safeArchive.extract({
      source:       bytes,
      destination:  dest,
      guardProfile: "balanced",
    });
    check("safeArchive.extract: 3 entries written",      result.entries.length === 3);
    check("safeArchive.extract: format=zip",             result.format === "zip");
    var readme = fs.readFileSync(path.join(dest, "readme.txt"), "utf8");
    check("safeArchive.extract: readme contents match",  readme === "Hello, archive-read!\n");
    var nested = fs.readFileSync(path.join(dest, "docs/nested/deep.txt"), "utf8");
    check("safeArchive.extract: nested file restored",   nested === "payload\n");
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

function testSafeArchiveErrorClass() {
  // Sanity-check that the typed-error class is exported + an instance
  // can be constructed with a code + message.
  var err = new b.safeArchive.SafeArchiveError("safe-archive/test", "test instance");
  check("SafeArchiveError: code carried",     err.code === "safe-archive/test");
  check("SafeArchiveError: is Error subclass", err instanceof Error);
}

async function testSafeArchiveInspect() {
  var z = b.archive.zip();
  z.addFile("a.txt", "alpha");
  z.addFile("b.txt", "beta");
  var bytes = z.toBuffer();
  var summary = await b.safeArchive.inspect({ source: bytes });
  check("safeArchive.inspect: format=zip",                summary.format === "zip");
  check("safeArchive.inspect: 2 entries",                 summary.entries.length === 2);
  check("safeArchive.inspect: totalUncompressedBytes",    summary.totalUncompressedBytes === 9);
}

async function testZipBombPolicy() {
  var policy = b.guardArchive.zipBombPolicy({
    maxTotalDecompressedBytes: 8,
    maxExpansionRatio:         100,
  });
  check("zipBombPolicy: maxTotalDecompressedBytes carries",  policy.maxTotalDecompressedBytes === 8);
  check("zipBombPolicy: defaults applied",                   policy.maxEntries === 65535);
  // 9-byte archive payload exceeds the 8-byte total cap.
  var z = b.archive.zip();
  z.addFile("big.txt", "123456789");
  var bytes = z.toBuffer();
  var refused = null;
  try {
    var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes), {
      bombPolicy: policy,
    });
    await reader.inspect();
  } catch (e) { refused = e; }
  check("bombPolicy: maxTotalDecompressedBytes trips",
    refused && /total-too-large|entry-too-large/.test(refused.code || refused.message));
}

function testEntryTypePolicy() {
  var p = b.guardArchive.entryTypePolicy({ symlinks: true });
  check("entryTypePolicy: symlinks opted in",   p.symlinks === true);
  check("entryTypePolicy: hardlinks default off", p.hardlinks === false);
  check("entryTypePolicy: devices default off",   p.devices === false);
}

function testVerifyExtractionPathHappy() {
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-verifyx-"));
  try {
    var resolved = b.guardFilename.verifyExtractionPath("docs/readme.txt", dest);
    check("verifyExtractionPath: ok resolved", resolved.indexOf(dest) === 0);
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

function testVerifyExtractionPathRefusals() {
  var refusals = 0;
  function r(name, root) {
    try { b.guardFilename.verifyExtractionPath(name, root); }
    catch (_e) { refusals += 1; }
  }
  r("../etc/passwd", "/tmp");                       // zip slip
  r("/etc/passwd", "/tmp");                         // absolute
  r("docs/../../etc/passwd", "/tmp");               // mid-segment ..
  // PATH_MAX overflow (4097 chars).
  var oversize = new Array(4098).join("a");
  r(oversize, "/tmp");
  check("verifyExtractionPath: 4 refusals", refusals === 4);
}

// Per-segment Windows-extraction hazards — refused even though they stay
// inside the extraction root (within-root write-target redirection /
// collision that the containment + realpath checks can't see). Platform-
// unconditional, with per-check opt-outs for Linux-only targets.
function testVerifyExtractionPathWindowsHazards() {
  function expectCode(name, code, opts) {
    var e = null;
    try { b.guardFilename.verifyExtractionPath(name, "/tmp", opts); }
    catch (err) { e = err; }
    check("verifyExtractionPath refuses " + JSON.stringify(name) + " (" + code + ")",
      e && (e.code || "").indexOf(code) !== -1);
  }
  // Windows reserved device names (bare + with extension + nested segment).
  expectCode("CON", "filename.extraction-reserved-name");
  expectCode("aux.txt", "filename.extraction-reserved-name");
  expectCode("subdir/NUL", "filename.extraction-reserved-name");
  expectCode("logs/COM1.log", "filename.extraction-reserved-name");
  // Superscript-digit COM/LPT spoof (U+00B9/B2/B3 — Windows folds to 1/2/3).
  // Built from codepoints so the test source stays pure-ASCII.
  expectCode("COM" + String.fromCharCode(0xB9), "filename.extraction-reserved-name");
  expectCode("sub/LPT" + String.fromCharCode(0xB3), "filename.extraction-reserved-name");
  // NTFS alternate data streams.
  expectCode("file.txt:evil.exe", "filename.extraction-ntfs-ads");
  expectCode("dir/data.bin:$DATA", "filename.extraction-ntfs-ads");
  // Trailing dot / leading-or-trailing whitespace (Windows strips → collision).
  expectCode("secret.txt.", "filename.extraction-leading-trailing");
  expectCode("name with trailing space ", "filename.extraction-leading-trailing");

  // Opt-outs accept the name (then pass the realpath leg into a real root).
  function expectAccept(name, opts) {
    var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vx-"));
    var ok = false, code = null;
    try { ok = b.guardFilename.verifyExtractionPath(name, dest, opts).indexOf(dest) === 0; }
    catch (e) { code = e && e.code; }
    finally { fs.rmSync(dest, { recursive: true, force: true }); }
    check("verifyExtractionPath accepts " + JSON.stringify(name) + " with opt-out" +
      (code ? " (threw " + code + ")" : ""), ok === true);
  }
  expectAccept("CON", { reservedNamePolicy: "allow" });
  expectAccept("file.txt:evil.exe", { adsPolicy: "allow" });
  expectAccept("secret.txt.", { leadingTrailingPolicy: "allow" });
}

async function testExtractRefusesOverwrite() {
  // Codex P1 on v0.12.7 PR #158 — the catch-block cleanup deleted
  // PRE-EXISTING destination files on abort because the rename-onto-
  // canonical-path path overwrote them first, then `written[].path`
  // got rm'd. Fix is to refuse overwrite up front; this regression
  // test verifies the new refusal fires + that the pre-existing file
  // is left untouched.
  var z = b.archive.zip();
  z.addFile("readme.txt", "from-archive\n");
  var bytes = z.toBuffer();
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-overwrite-test-"));
  try {
    var collidePath = path.join(dest, "readme.txt");
    fs.writeFileSync(collidePath, "operator's pre-existing file\n");
    var refused = null;
    try {
      await b.safeArchive.extract({ source: bytes, destination: dest });
    } catch (e) { refused = e; }
    check("extract: refuses pre-existing destination file",
      refused && /destination-exists/.test(refused.code || refused.message));
    var stillThere = fs.readFileSync(collidePath, "utf8");
    check("extract: pre-existing file untouched on refusal",
      stillThere === "operator's pre-existing file\n");
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

async function testSafeArchiveRefusesTrustedStreamSource() {
  // Codex P2 on v0.12.7 PR #158 — safeArchive.extract accepted
  // trusted-stream adapters via the input-shape validator but the
  // implementation called the random-access reader, which threw the
  // wrong-entry-point error. Fix is to refuse trusted-stream sources
  // upfront with a typed safe-archive code.
  var nodeStream = require("node:stream");
  var fakeReadable = new nodeStream.Readable({ read: function () {} });
  var adapter = b.archive.adapters.trustedStream(fakeReadable);
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trusted-refusal-"));
  try {
    var refused = null;
    try {
      await b.safeArchive.extract({
        source:      adapter,
        destination: dest,
      });
    } catch (e) { refused = e; }
    check("safeArchive.extract: trusted-stream upfront refused",
      refused && /trusted-stream-unsupported/.test(refused.code || refused.message));
  } finally {
    fakeReadable.destroy();
    fs.rmSync(dest, { recursive: true, force: true });
  }
}

async function testFromTrustedStreamRoundTrip() {
  var nodeStream = require("node:stream");
  var z = b.archive.zip();
  z.addFile("readme.txt", "trusted stream readme\n");
  z.addFile("data/n.csv", "a,b\n1,2\n");
  var bytes = z.toBuffer();

  // inspect over a Readable via the trusted-stream adapter (no manual
  // buffering by the caller — the reader collects + decodes).
  var reader = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)));
  check("fromTrustedStream: kind tag", reader.kind === "zip-trusted-sequential");
  var entries = await reader.inspect();
  check("fromTrustedStream: inspect sees both entries", entries.length === 2);
  check("fromTrustedStream: entry name round-trips",
    entries.some(function (e) { return e.name === "readme.txt"; }));

  // extractEntries over a fresh stream recovers the bytes.
  var reader2 = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)));
  var got = {};
  for await (var ent of reader2.extractEntries()) {
    got[ent.name] = Buffer.isBuffer(ent.bytes) ? ent.bytes.toString("utf8") : null;
  }
  check("fromTrustedStream: extractEntries recovers content",
    got["readme.txt"] === "trusted stream readme\n" && got["data/n.csv"] === "a,b\n1,2\n");

  // bombPolicy is honored through the delegated decode — a tiny
  // per-entry cap refuses the archive.
  var reader3 = b.archive.read.zip.fromTrustedStream(
    b.archive.adapters.trustedStream(nodeStream.Readable.from(bytes)),
    { bombPolicy: { maxEntryDecompressedBytes: 4 } });
  var bombErr = null;
  try { await reader3.inspect(); for await (var _e of reader3.extractEntries()) { void _e; } }
  catch (e) { bombErr = e; }
  check("fromTrustedStream: bombPolicy applies on decode", bombErr !== null);

  // bad adapter (random-access) refused.
  var badErr = null;
  try { b.archive.read.zip.fromTrustedStream(b.archive.adapters.buffer(bytes)); }
  catch (e) { badErr = e; }
  check("fromTrustedStream: non-trusted-stream adapter refused",
    badErr && /bad-adapter/.test(badErr.code || badErr.message));
}

async function testGuardArchiveInspect() {
  var z = b.archive.zip();
  z.addFile("safe.txt", "safe");
  var bytes = z.toBuffer();
  var summary = await b.guardArchive.inspect(b.archive.adapters.buffer(bytes), {
    profile: "balanced",
  });
  check("guardArchive.inspect: 1 entry",       summary.entries.length === 1);
  check("guardArchive.inspect: issues array",   Array.isArray(summary.issues));
}

async function testBundleAdapterStorageRoundTrip() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-root-"));
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-src-"));
  var destDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-backup-adapter-dest-"));
  try {
    // Populate a small bundle source.
    fs.writeFileSync(path.join(srcDir, "manifest.json"), JSON.stringify({ v: 1 }));
    fs.mkdirSync(path.join(srcDir, "files"));
    fs.writeFileSync(path.join(srcDir, "files", "blob.bin"), Buffer.from([1, 2, 3]));

    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: rootDir }),
    });
    check("bundleAdapterStorage: name=adapter", storage.name === "adapter");

    var bundleId = "2026-05-23T07-00-00-000Z-deadbeef";
    await storage.writeBundle(bundleId, srcDir);
    check("bundleAdapterStorage: hasBundle after write", await storage.hasBundle(bundleId));
    fs.rmSync(destDir, { recursive: true });
    await storage.readBundle(bundleId, destDir);
    var restored = fs.readFileSync(path.join(destDir, "files", "blob.bin"));
    check("bundleAdapterStorage: roundtrip bytes match", restored[0] === 1 && restored.length === 3);
    var list = await storage.listBundles();
    check("bundleAdapterStorage: listBundles returns the bundle", list.length === 1 && list[0].bundleId === bundleId);
    await storage.deleteBundle(bundleId);
    check("bundleAdapterStorage: hasBundle false after delete", !(await storage.hasBundle(bundleId)));
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(srcDir,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(destDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

// In-memory extraction (serverless / read-only FS): reader.extractEntries()
// yields decompressed bytes without ever writing to disk, and those bytes are
// byte-identical to what disk extract() produces.
async function testExtractEntriesInMemory() {
  var z = b.archive.zip();
  z.addFile("readme.txt", "Hello, in-memory!\n");
  z.addFile("data/nums.csv", "n,sq\n2,4\n");
  z.addFile("docs/deep.bin", Buffer.from([0, 1, 2, 3, 255]));
  var bytes = z.toBuffer();

  // Spy: no fs write may happen during the in-memory path.
  var wrote = false;
  var origWrite = fs.writeFileSync;
  fs.writeFileSync = function () { wrote = true; return origWrite.apply(fs, arguments); };
  var collected = {};
  try {
    var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes));
    for await (var e of reader.extractEntries()) { collected[e.name] = e.bytes; }
  } finally {
    fs.writeFileSync = origWrite;
  }
  check("zip extractEntries: no disk write", wrote === false);
  check("zip extractEntries: 3 file entries (dir skipped)", Object.keys(collected).length === 3);
  check("zip extractEntries: text bytes match", collected["readme.txt"].toString("utf8") === "Hello, in-memory!\n");
  check("zip extractEntries: binary bytes match", collected["docs/deep.bin"].equals(Buffer.from([0, 1, 2, 3, 255])));

  // Byte-equality with disk extract().
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-archive-mem-"));
  try {
    await b.safeArchive.extract({ source: bytes, destination: dest, guardProfile: "balanced" });
    var diskBin = fs.readFileSync(path.join(dest, "docs/deep.bin"));
    check("zip extractEntries bytes == disk extract bytes", collected["docs/deep.bin"].equals(diskBin));
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  // tar in-memory.
  var t = b.archive.tar();
  t.addFile("x.txt", "world\n");
  t.addFile("sub/y.dat", Buffer.from([9, 8, 7]));
  var tbytes = t.toBuffer();
  var tcollected = {};
  var tr = b.archive.read.tar(b.archive.adapters.buffer(tbytes));
  for await (var te of tr.extractEntries()) { tcollected[te.name] = te.bytes; }
  check("tar extractEntries: 2 entries", Object.keys(tcollected).length === 2);
  check("tar extractEntries: text matches", tcollected["x.txt"].toString("utf8") === "world\n");
  check("tar extractEntries: binary matches", tcollected["sub/y.dat"].equals(Buffer.from([9, 8, 7])));
}

async function testExtractToMemoryOrchestrator() {
  // zip in-memory orchestrator — byte-equal to disk extract(), no fs write.
  var z = b.archive.zip();
  z.addFile("readme.txt", "serverless!\n");
  z.addFile("d/deep.bin", Buffer.from([5, 6, 7, 255]));
  var zbytes = z.toBuffer();

  var wrote = false;
  var origWrite = fs.writeFileSync;
  fs.writeFileSync = function () { wrote = true; return origWrite.apply(fs, arguments); };
  var collected = {};
  try {
    for await (var e of b.safeArchive.extractToMemory({ source: zbytes, guardProfile: "balanced" })) {
      collected[e.name] = e.bytes;
    }
  } finally {
    fs.writeFileSync = origWrite;
  }
  check("extractToMemory zip: no disk write",                wrote === false);
  check("extractToMemory zip: 2 file entries (dir skipped)", Object.keys(collected).length === 2);
  check("extractToMemory zip: text bytes match",             collected["readme.txt"].toString("utf8") === "serverless!\n");
  check("extractToMemory zip: binary bytes match",           collected["d/deep.bin"].equals(Buffer.from([5, 6, 7, 255])));

  // Byte-equality with the disk extract() path.
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sa-mem-"));
  try {
    await b.safeArchive.extract({ source: zbytes, destination: dest, guardProfile: "balanced" });
    check("extractToMemory bytes == disk extract bytes",
          collected["d/deep.bin"].equals(fs.readFileSync(path.join(dest, "d/deep.bin"))));
  } finally {
    fs.rmSync(dest, { recursive: true, force: true });
  }

  // tar source auto-detected.
  var t = b.archive.tar();
  t.addFile("a.txt", "alpha\n");
  t.addFile("p/b.dat", Buffer.from([1, 2]));
  var tbytes = t.toBuffer();
  var tcollected = {};
  for await (var te of b.safeArchive.extractToMemory({ source: tbytes })) { tcollected[te.name] = te.bytes; }
  check("extractToMemory tar: 2 entries auto-detected", Object.keys(tcollected).length === 2);
  check("extractToMemory tar: text matches",            tcollected["a.txt"].toString("utf8") === "alpha\n");

  // tar.gz — explicit format. Auto-sniff yields "gzip", which the disk
  // path also treats as unsupported, so the documented contract needs
  // the explicit hint (extractToMemory mirrors extract()'s dispatch).
  var gzBytes = b.archive.gz(tbytes).toBuffer();
  var gcollected = {};
  for await (var ge of b.safeArchive.extractToMemory({ source: gzBytes, format: "tar.gz" })) { gcollected[ge.name] = ge.bytes; }
  check("extractToMemory tar.gz: inner tar entries", Object.keys(gcollected).length === 2);
  check("extractToMemory tar.gz: binary matches",    gcollected["p/b.dat"].equals(Buffer.from([1, 2])));

  // bombPolicy refusal propagates from the composed reader.
  var bombThrew = null;
  try {
    var tinyBomb = b.guardArchive.zipBombPolicy({ maxTotalDecompressedBytes: 4 });
    for await (var be of b.safeArchive.extractToMemory({ source: zbytes, bombPolicy: tinyBomb })) { void be; }
  } catch (e) { bombThrew = e; }
  check("extractToMemory: bombPolicy refusal propagates", bombThrew !== null);

  // passphrase-wrap envelope auto-unwrapped (shared resolve path), then yielded.
  var sealed = await b.archive.wrapWithPassphrase(zbytes, { passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase" });
  var wcollected = {};
  for await (var we of b.safeArchive.extractToMemory({ source: sealed, passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase" })) { wcollected[we.name] = we.bytes; }
  check("extractToMemory: passphrase envelope auto-unwrapped + yielded",
        wcollected["readme.txt"] && wcollected["readme.txt"].toString("utf8") === "serverless!\n");

  // A raw b.crypto.encryptPacked blob is NOT an archive-wrap envelope (it
  // carries no BAWRP/BAWPP magic, only a 1-byte XChaCha20 format header), so
  // the orchestrator sniffs it as unknown and refuses cleanly rather than
  // pretending to auto-unwrap a phantom "EPACK" format.
  var packed = b.crypto.encryptPacked(zbytes, b.crypto.generateBytes(32));
  var packedThrew = null;
  try { for await (var pe of b.safeArchive.extractToMemory({ source: packed })) { void pe; } } catch (e) { packedThrew = e; }
  check("extractToMemory: raw encryptPacked blob refused as unsupported (no phantom EPACK unwrap)",
        packedThrew && /format-unsupported/.test(packedThrew.code || packedThrew.message));

  // trusted-stream source refused upfront — and BP5: the refusal message
  // must no longer name the stale v0.12.8 version.
  var nodeStream = require("node:stream");
  var fakeReadable = new nodeStream.Readable({ read: function () {} });
  var tsAdapter = b.archive.adapters.trustedStream(fakeReadable);
  var tsThrew = null;
  try {
    for await (var tse of b.safeArchive.extractToMemory({ source: tsAdapter })) { void tse; }
  } catch (e) { tsThrew = e; }
  fakeReadable.destroy();
  check("extractToMemory: trusted-stream refused upfront",
        tsThrew && /trusted-stream-unsupported/.test(tsThrew.code || tsThrew.message));
  check("extractToMemory: refusal message dropped the stale v0.12.8 wording",
        tsThrew && tsThrew.message.indexOf("v0.12.8") === -1);
}

// opts.signal (AbortSignal) is documented on b.archive.read.zip — verify
// it actually aborts the read at the entry boundary rather than being a
// dead doc opt.
async function testSignalAbort() {
  var z = b.archive.zip();
  z.addFile("a.txt", "one\n");
  z.addFile("b.txt", "two\n");
  var bytes = z.toBuffer();

  var ac = new AbortController();
  ac.abort();   // already aborted before any read
  var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes), { signal: ac.signal });

  var inspectThrew = null;
  try { await reader.inspect(); } catch (e) { inspectThrew = e; }
  check("zip inspect honors an aborted signal",
        inspectThrew && (inspectThrew.code || "").indexOf("archive-read/aborted") !== -1);

  var extractThrew = null;
  try { for await (var _e of reader.extractEntries()) { void _e; } }
  catch (e) { extractThrew = e; }
  check("zip extractEntries honors an aborted signal",
        extractThrew && (extractThrew.code || "").indexOf("archive-read/aborted") !== -1);

  // Sanity: with no signal the same reader works.
  var ok = b.archive.read.zip(b.archive.adapters.buffer(bytes));
  var n = 0;
  for await (var e2 of ok.extractEntries()) { void e2; n += 1; }
  check("zip extractEntries with no signal still yields entries", n === 2);
}

// ---- ZIP64 read support ---------------------------------------------------
// The write side does not emit ZIP64, so we hand-build minimal ZIP64-form
// archives (infozip / Go archive/zip layout) and assert they decode to the
// same entry shape a classic reader yields, with bomb/name refusals intact.
// APPNOTE 6.3.10 §4.3.14 (EOCD64) / §4.3.15 (locator) / §4.5.3 (extra field).

var METHOD_STORE = 0;
var U32_SENTINEL = 0xffffffff;
var U16_SENTINEL = 0xffff;

// Build a single STORE-method ZIP64 archive whose CD entry carries the
// 0xFFFFFFFF uncompressed/compressed-size sentinels resolved by a §4.5.3
// extra field, fronted by a real ZIP64 EOCD record + locator and a classic
// EOCD with sentinel size/offset fields. `crc` comes from the classic
// archive the framework produced for the same bytes (CRC must agree so the
// LFH/CD skew check passes). `entryCountSentinel` exercises the EOCD64
// totalEntries path.
function buildZip64Store(name, data, crc, opts) {
  opts = opts || {};
  var nameBuf = Buffer.from(name, "utf8");
  var size = data.length;

  // ZIP64 extra field for the LFH: uncompressedSize(8) + compressedSize(8).
  var lfhExtra = Buffer.alloc(4 + 16);
  lfhExtra.writeUInt16LE(0x0001, 0);
  lfhExtra.writeUInt16LE(16, 2);
  lfhExtra.writeBigUInt64LE(BigInt(size), 4);
  lfhExtra.writeBigUInt64LE(BigInt(size), 12);

  // Local file header (30 bytes) with sentinel sizes.
  var lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);    // sig
  lfh.writeUInt16LE(45, 4);            // version needed = 4.5 (ZIP64)
  lfh.writeUInt16LE(0, 6);             // flags
  lfh.writeUInt16LE(METHOD_STORE, 8);  // method
  lfh.writeUInt16LE(0, 10);            // mod time
  lfh.writeUInt16LE(0x21, 12);         // mod date (1980-01-01)
  lfh.writeUInt32LE(crc >>> 0, 14);    // crc32
  lfh.writeUInt32LE(U32_SENTINEL, 18); // csize sentinel
  lfh.writeUInt32LE(U32_SENTINEL, 22); // usize sentinel
  lfh.writeUInt16LE(nameBuf.length, 26);
  lfh.writeUInt16LE(lfhExtra.length, 28);

  var lfhOffset = 0;

  // ZIP64 extra field for the CD: uncompressedSize(8) + compressedSize(8)
  // (+ localHeaderOffset(8) when opted in).
  var includeOffset = opts.offsetSentinel === true;
  var cdExtraDataLen = includeOffset ? 24 : 16;
  var cdExtra = Buffer.alloc(4 + cdExtraDataLen);
  cdExtra.writeUInt16LE(0x0001, 0);
  cdExtra.writeUInt16LE(cdExtraDataLen, 2);
  cdExtra.writeBigUInt64LE(BigInt(size), 4);
  cdExtra.writeBigUInt64LE(BigInt(size), 12);
  if (includeOffset) cdExtra.writeBigUInt64LE(BigInt(lfhOffset), 20);

  // Central directory header (46 bytes) with sentinel sizes.
  var cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);     // sig
  cd.writeUInt16LE(45, 4);             // version made by
  cd.writeUInt16LE(45, 6);             // version needed
  cd.writeUInt16LE(0, 8);              // flags
  cd.writeUInt16LE(METHOD_STORE, 10);  // method
  cd.writeUInt16LE(0, 12);             // mod time
  cd.writeUInt16LE(0x21, 14);          // mod date
  cd.writeUInt32LE(crc >>> 0, 16);     // crc32
  cd.writeUInt32LE(U32_SENTINEL, 20);  // csize sentinel
  cd.writeUInt32LE(U32_SENTINEL, 24);  // usize sentinel
  cd.writeUInt16LE(nameBuf.length, 28);
  cd.writeUInt16LE(cdExtra.length, 30);
  cd.writeUInt16LE(0, 32);             // comment len
  cd.writeUInt16LE(0, 34);             // disk start
  cd.writeUInt16LE(0, 36);             // internal attrs
  cd.writeUInt32LE(0, 38);             // external attrs
  cd.writeUInt32LE(includeOffset ? U32_SENTINEL : lfhOffset, 42);  // lfh offset (sentinel when opted in)

  var cdBytesBefore = Buffer.concat([lfh, nameBuf, lfhExtra, data]);
  var cdOffset = cdBytesBefore.length;
  var cdRecord = Buffer.concat([cd, nameBuf, cdExtra]);
  var cdSize = cdRecord.length;

  // ZIP64 EOCD record (56 bytes through cdOffset).
  var eocd64 = Buffer.alloc(56);
  eocd64.writeUInt32LE(0x06064b50, 0);          // sig
  eocd64.writeBigUInt64LE(BigInt(56 - 12), 4);  // size of remaining record
  eocd64.writeUInt16LE(45, 12);                 // version made by
  eocd64.writeUInt16LE(45, 14);                 // version needed
  eocd64.writeUInt32LE(0, 16);                  // disk number
  eocd64.writeUInt32LE(0, 20);                  // cd start disk
  eocd64.writeBigUInt64LE(1n, 24);              // entries this disk
  eocd64.writeBigUInt64LE(1n, 32);              // total entries
  eocd64.writeBigUInt64LE(BigInt(cdSize), 40);  // cd size
  eocd64.writeBigUInt64LE(BigInt(cdOffset), 48);// cd offset

  var eocd64Offset = cdOffset + cdSize;

  // ZIP64 EOCD locator (20 bytes).
  var locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50, 0);             // sig
  locator.writeUInt32LE(0, 4);                      // disk with eocd64
  locator.writeBigUInt64LE(BigInt(eocd64Offset), 8);// eocd64 offset
  locator.writeUInt32LE(1, 16);                     // total disks

  // Classic EOCD (22 bytes) with sentinels.
  var entryCountSentinel = opts.entryCountSentinel === true;
  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);   // sig
  eocd.writeUInt16LE(0, 4);            // disk number
  eocd.writeUInt16LE(0, 6);            // cd disk
  eocd.writeUInt16LE(entryCountSentinel ? U16_SENTINEL : 1, 8);   // entries this disk
  eocd.writeUInt16LE(entryCountSentinel ? U16_SENTINEL : 1, 10);  // total entries
  eocd.writeUInt32LE(U32_SENTINEL, 12);// cd size sentinel
  eocd.writeUInt32LE(U32_SENTINEL, 16);// cd offset sentinel
  eocd.writeUInt16LE(0, 20);          // comment len

  return Buffer.concat([cdBytesBefore, cdRecord, eocd64, locator, eocd]);
}

async function testZip64Read() {
  var payload = Buffer.from("ZIP64 round-trip payload — same bytes a classic reader yields.\n", "utf8");

  // Get a real CRC32 for the payload by reading it back through a classic
  // STORE archive the framework produced.
  var z = b.archive.zip();
  z.addFile("z64.txt", payload);
  var classicBytes = z.toBuffer();
  var classicReader = b.archive.read.zip(b.archive.adapters.buffer(classicBytes));
  var classicEntries = await classicReader.inspect();
  var crc = classicEntries[0].crc;

  // Size-sentinel ZIP64 form decodes to the same entry shape.
  var z64 = buildZip64Store("z64.txt", payload, crc);
  var reader = b.archive.read.zip(b.archive.adapters.buffer(z64));
  var entries = await reader.inspect();
  check("zip64: inspect sees 1 entry",          entries.length === 1);
  check("zip64: name round-trips",              entries[0].name === "z64.txt");
  check("zip64: resolved size matches payload", entries[0].size === payload.length);

  // extractEntries recovers byte-identical content (LFH/CD ZIP64 skew check
  // passes against resolved sizes).
  var got = null;
  for await (var ent of reader.extractEntries()) { got = ent; }
  check("zip64: extractEntries recovers exact bytes", got && got.bytes.equals(payload));

  // localHeaderOffset sentinel + ZIP64 extra resolution.
  var z64Off = buildZip64Store("z64.txt", payload, crc, { offsetSentinel: true });
  var readerOff = b.archive.read.zip(b.archive.adapters.buffer(z64Off));
  var gotOff = null;
  for await (var entO of readerOff.extractEntries()) { gotOff = entO; }
  check("zip64: lfhOffset sentinel resolved + bytes recovered",
    gotOff && gotOff.bytes.equals(payload));

  // EOCD64 totalEntries path — classic EOCD entry-count is the 0xFFFF
  // sentinel; the true count comes from the ZIP64 EOCD record.
  var z64Count = buildZip64Store("z64.txt", payload, crc, { entryCountSentinel: true });
  var readerCount = b.archive.read.zip(b.archive.adapters.buffer(z64Count));
  var entriesCount = await readerCount.inspect();
  check("zip64: EOCD64 totalEntries resolved from sentinel", entriesCount.length === 1);

  // Bomb cap still fires on the resolved 64-bit size.
  var bombErr = null;
  try {
    var bombReader = b.archive.read.zip(b.archive.adapters.buffer(z64), {
      bombPolicy: { maxEntryDecompressedBytes: 4 },
    });
    await bombReader.inspect();
  } catch (e) { bombErr = e; }
  check("zip64: bomb cap fires on resolved size",
    bombErr && /entry-too-large|total-too-large/.test(bombErr.code || bombErr.message));

  // Zip-Slip name refusal still fires on a ZIP64-form archive.
  var slip = buildZip64Store("../../etc/passwd", payload, crc);
  var slipDest = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-zip64-slip-"));
  var slipErr = null;
  try {
    var slipReader = b.archive.read.zip(b.archive.adapters.buffer(slip));
    await slipReader.extract({ destination: slipDest });
  } catch (e) { slipErr = e; }
  finally { fs.rmSync(slipDest, { recursive: true, force: true }); }
  check("zip64: zip-slip name still refused", slipErr !== null);

  // A classic EOCD claiming ZIP64 (sentinel) but missing the ZIP64 trailer
  // is refused, not read with a sentinel taken literally.
  var truncated = z64.slice(0, z64.length - 20 - 56 - 22);  // drop eocd64 + locator + classic eocd
  var orphanEocd = Buffer.alloc(22);
  orphanEocd.writeUInt32LE(0x06054b50, 0);
  orphanEocd.writeUInt16LE(U16_SENTINEL, 8);
  orphanEocd.writeUInt16LE(U16_SENTINEL, 10);
  orphanEocd.writeUInt32LE(U32_SENTINEL, 12);
  orphanEocd.writeUInt32LE(U32_SENTINEL, 16);
  var orphan = Buffer.concat([truncated, orphanEocd]);
  var orphanErr = null;
  try {
    var orphanReader = b.archive.read.zip(b.archive.adapters.buffer(orphan));
    await orphanReader.inspect();
  } catch (e) { orphanErr = e; }
  check("zip64: missing ZIP64 trailer refused (no literal-sentinel read)",
    orphanErr && /zip64/.test(orphanErr.code || orphanErr.message));
}

async function run() {
  await testZip64Read();
  await testRoundTripExtract();
  await testExtractEntriesInMemory();
  await testExtractToMemoryOrchestrator();
  await testSignalAbort();
  testSafeArchiveErrorClass();
  await testSafeArchiveInspect();
  await testZipBombPolicy();
  testEntryTypePolicy();
  testVerifyExtractionPathHappy();
  testVerifyExtractionPathRefusals();
  testVerifyExtractionPathWindowsHazards();
  await testExtractRefusesOverwrite();
  await testSafeArchiveRefusesTrustedStreamSource();
  await testFromTrustedStreamRoundTrip();
  await testGuardArchiveInspect();
  await testBundleAdapterStorageRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-read] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
