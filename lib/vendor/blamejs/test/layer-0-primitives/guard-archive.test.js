// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-archive — archive content-safety primitive (b.guardArchive).
 *
 * Covers: surface; registry parity; zip-slip path traversal; absolute-
 * path entries; symlink + hardlink escape; symlink + hardlink reject
 * policies; compression-ratio bombs (per-entry + aggregate); total-size
 * + entry-count + per-entry-size caps; nested-archive detection;
 * duplicate-entry-name; case-insensitive collision; encryption-claim
 * mismatch; sparse entries; magic-byte detection (zip / gzip / bzip2 /
 * xz / 7z / rar / tar); checkExtractionPath helper; gate decision
 * shapes; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardArchiveSurface() {
  check("guardArchive is an object",                 typeof b.guardArchive === "object");
  check("guardArchive.NAME === 'archive'",           b.guardArchive.NAME === "archive");
  check("guardArchive.MIME_TYPES has application/zip",
        b.guardArchive.MIME_TYPES.indexOf("application/zip") !== -1);
  check("guardArchive.EXTENSIONS has .zip",          b.guardArchive.EXTENSIONS.indexOf(".zip") !== -1);
  check("guardArchive.PROFILES has strict",          !!b.guardArchive.PROFILES["strict"]);
  check("guardArchive.PROFILES has balanced",        !!b.guardArchive.PROFILES["balanced"]);
  check("guardArchive.PROFILES has permissive",      !!b.guardArchive.PROFILES["permissive"]);
  check("guardArchive.COMPLIANCE_POSTURES has hipaa", !!b.guardArchive.COMPLIANCE_POSTURES["hipaa"]);
  check("guardArchive.validateEntries is a function", typeof b.guardArchive.validateEntries === "function");
  check("guardArchive.inspectMagic is a function",    typeof b.guardArchive.inspectMagic === "function");
  check("guardArchive.checkExtractionPath is a function",
        typeof b.guardArchive.checkExtractionPath === "function");
  check("guardArchive.gate is a function",           typeof b.guardArchive.gate === "function");
  check("guardArchive.GuardArchiveError is a function",
        typeof b.guardArchive.GuardArchiveError === "function");
  check("frameworkError.GuardArchiveError exposed",
        typeof b.frameworkError.GuardArchiveError === "function");
}

function testGuardArchiveRegistryParity() {
  check("guardArchive registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "archive"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "archive"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: archive supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: archive supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardArchiveZipSlip() {
  var inputs = ["../etc/passwd", "../../boot.ini", "subdir/../../etc/shadow"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardArchive.validateEntries(
      [{ name: inputs[i], size: 100, compressedSize: 50 }],
      { profile: "strict" });
    check("zip slip detected: " + JSON.stringify(inputs[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "zip-slip"; }));
  }
}

function testGuardArchiveAbsolutePath() {
  var inputs = ["/etc/passwd", "\\windows\\system32\\config\\sam", "C:\\evil.exe"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardArchive.validateEntries(
      [{ name: inputs[i], size: 100, compressedSize: 50 }],
      { profile: "strict" });
    check("absolute path detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) { return issue.kind === "absolute-path"; }));
  }
}

function testGuardArchiveSymlinkRejectStrict() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "target" }],
    { profile: "strict" });
  check("symlink rejected under strict",
        rv.issues.some(function (issue) { return issue.kind === "symlink-reject"; }));
}

function testGuardArchiveSymlinkEscape() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "../etc/passwd" }],
    { profile: "balanced" });
  check("symlink escape detected (balanced)",
        rv.issues.some(function (issue) { return issue.kind === "symlink-escape"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isSymlink: true, linkTarget: "/etc/shadow" }],
    { profile: "balanced" });
  check("symlink-absolute escape detected (balanced)",
        rv2.issues.some(function (issue) { return issue.kind === "symlink-escape"; }));
}

function testGuardArchiveHardlinkEscape() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isHardlink: true, linkTarget: "target" }],
    { profile: "strict" });
  check("hardlink rejected under strict",
        rv.issues.some(function (issue) { return issue.kind === "hardlink-reject"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "link", size: 0, isHardlink: true, linkTarget: "../etc/passwd" }],
    { profile: "permissive" });
  check("hardlink escape detected (permissive — CVE-2026-26960 class)",
        rv2.issues.some(function (issue) { return issue.kind === "hardlink-escape"; }));
}

function testGuardArchiveCompressionRatioBomb() {
  // Single-entry 1 GB / 1 KB = 1,000,000:1 ratio.
  var rv = b.guardArchive.validateEntries(
    [{ name: "bomb.txt", size: 1000000000, compressedSize: 1024 }],
    { profile: "strict" });
  check("compression-ratio bomb detected",
        rv.issues.some(function (issue) { return issue.kind === "compression-ratio-bomb"; }));
}

function testGuardArchiveAggregateRatioBomb() {
  // Many small entries that aggregate to a large ratio. Set sizes to
  // stay under per-entry caps but blow the aggregate.
  var entries = [];
  for (var i = 0; i < 50; i++) {
    entries.push({
      name: "f" + i + ".txt",
      size: 1000000,        // 1 MB each = 50 MB total
      compressedSize: 100,  // 100 bytes each = 5 KB total
    });
  }
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("aggregate-ratio bomb detected",
        rv.issues.some(function (issue) { return issue.kind === "aggregate-ratio-bomb"; }));
}

function testGuardArchiveTotalSizeCap() {
  var entries = [];
  for (var i = 0; i < 5; i++) {
    entries.push({ name: "f" + i, size: 30000000, compressedSize: 10000000 });
  }
  // Strict cap is 100 MiB; 5 × 30 MB = 150 MB exceeds.
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("total-size cap detected",
        rv.issues.some(function (issue) { return issue.kind === "total-size-cap"; }));
}

function testGuardArchiveEntryCountCap() {
  var entries = [];
  for (var i = 0; i < 200; i++) {
    entries.push({ name: "f" + i + ".txt", size: 1, compressedSize: 1 });
  }
  // Strict cap is 100 entries.
  var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
  check("entry-count cap detected",
        rv.issues.some(function (issue) { return issue.kind === "entry-count-cap"; }));
}

function testGuardArchiveNestedArchive() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "inner.zip", size: 1000, compressedSize: 500 }],
    { profile: "strict" });
  check("nested archive detected (strict, maxNestedDepth=0)",
        rv.issues.some(function (issue) { return issue.kind === "nested-archive"; }));

  var rv2 = b.guardArchive.validateEntries(
    [{ name: "inner.tar.gz", size: 1000, compressedSize: 500 }],
    { profile: "strict" });
  check("nested .tar.gz detected",
        rv2.issues.some(function (issue) { return issue.kind === "nested-archive"; }));
}

function testGuardArchiveDuplicateNames() {
  var rv = b.guardArchive.validateEntries([
    { name: "config.json", size: 100, compressedSize: 50 },
    { name: "config.json", size: 200, compressedSize: 100 },
  ], { profile: "strict" });
  check("duplicate-entry-name detected",
        rv.issues.some(function (issue) { return issue.kind === "duplicate-entry-name"; }));
}

function testGuardArchiveCaseInsensitiveCollision() {
  var rv = b.guardArchive.validateEntries([
    { name: "README.txt", size: 100, compressedSize: 50 },
    { name: "readme.txt", size: 100, compressedSize: 50 },
  ], { profile: "strict" });
  check("case-insensitive collision detected (strict)",
        rv.issues.some(function (issue) { return issue.kind === "case-insensitive-collision"; }));
}

function testGuardArchiveEncryptionMismatch() {
  var rv = b.guardArchive.validateEntries([
    { name: "secret.txt", size: 100, compressedSize: 50, isEncrypted: true },
    { name: "public.txt", size: 100, compressedSize: 50, isEncrypted: false },
  ], { profile: "strict" });
  check("encryption-claim mismatch detected",
        rv.issues.some(function (issue) { return issue.kind === "encryption-claim-mismatch"; }));
}

function testGuardArchiveSparseEntry() {
  var rv = b.guardArchive.validateEntries(
    [{ name: "sparse.bin", size: 1000000, compressedSize: 100,
       attrs: { sparse: true } }],
    { profile: "strict" });
  check("sparse entry detected (strict)",
        rv.issues.some(function (issue) { return issue.kind === "sparse-entry"; }));
}

function testGuardArchiveInspectMagic() {
  // ZIP local file header magic.
  check("inspectMagic: zip detected",
        b.guardArchive.inspectMagic(Buffer.from([0x50, 0x4B, 0x03, 0x04])).format === "zip");
  check("inspectMagic: gzip detected",
        b.guardArchive.inspectMagic(Buffer.from([0x1F, 0x8B])).format === "gzip");
  check("inspectMagic: bzip2 detected",
        b.guardArchive.inspectMagic(Buffer.from([0x42, 0x5A, 0x68])).format === "bzip2");
  check("inspectMagic: xz detected",
        b.guardArchive.inspectMagic(Buffer.from([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])).format === "xz");
  check("inspectMagic: 7z detected",
        b.guardArchive.inspectMagic(Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])).format === "7z");
  check("inspectMagic: rar4 detected",
        b.guardArchive.inspectMagic(
          Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00])).format === "rar4");
  check("inspectMagic: zstd detected",
        b.guardArchive.inspectMagic(
          Buffer.from([0x28, 0xB5, 0x2F, 0xFD])).format === "zstd");
  check("inspectMagic: unknown returns null",
        b.guardArchive.inspectMagic(Buffer.from([0xFF, 0xFE, 0xFD, 0xFC])) === null);

  // tar — "ustar" at offset 257 within first 512-byte header.
  var tarBuf = Buffer.alloc(512);
  tarBuf.write("ustar", 257);
  check("inspectMagic: tar via ustar offset detected",
        b.guardArchive.inspectMagic(tarBuf).format === "tar");
}

function testGuardArchiveCheckExtractionPath() {
  check("checkExtractionPath: clean entry returns ok",
        b.guardArchive.checkExtractionPath("safe/file.txt", "/extract").ok === true);
  check("checkExtractionPath: traversal returns false",
        b.guardArchive.checkExtractionPath("../escape", "/extract").ok === false);
  check("checkExtractionPath: absolute path returns false",
        b.guardArchive.checkExtractionPath("/etc/passwd", "/extract").ok === false);
  check("checkExtractionPath: empty name returns false",
        b.guardArchive.checkExtractionPath("", "/extract").ok === false);
  var nb = String.fromCharCode(0);
  check("checkExtractionPath: null byte returns false",
        b.guardArchive.checkExtractionPath("file" + nb + ".txt", "/extract").ok === false);
}

function testGuardArchiveCleanArchive() {
  // Use entry names that avoid the shell-exec-ext warn list (.js / .lnk
  // / .dll / etc. trigger warn-severity issues per guard-filename's
  // executable-extension family). The point of "clean" here is no
  // critical / high severity issues — warns are auditable but don't
  // flip ok=false.
  var rv = b.guardArchive.validateEntries([
    { name: "README.md",    size: 1000,  compressedSize: 500, isDirectory: false },
    { name: "src/main.txt", size: 2000,  compressedSize: 800, isDirectory: false },
    { name: "src/",         size: 0,     compressedSize: 0,   isDirectory: true },
  ], { profile: "strict" });
  var noCritOrHigh = !rv.issues.some(function (i) {
    return i.severity === "critical" || i.severity === "high";
  });
  check("clean archive → ok=true",   rv.ok === true && noCritOrHigh);
}

async function testGuardArchiveGate() {
  var g = b.guardArchive.gate({ profile: "strict" });
  var clean = await g.check({
    entries: [{ name: "safe.txt", size: 100, compressedSize: 50 }],
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var slip = await g.check({
    entries: [{ name: "../etc/passwd", size: 100, compressedSize: 50 }],
  });
  check("gate zip-slip → action=refuse (no safe sanitization for archives)",
        slip.action === "refuse");

  // bytes only, no entries — refuse-no-entry-list path.
  var bytesOnly = await g.check({
    bytes: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
  });
  check("gate: bytes without entries → refuse with no-entry-list issue",
        bytesOnly.action === "refuse" &&
        bytesOnly.issues.some(function (i) { return i.kind === "no-entry-list"; }));
}

function testGuardArchiveCompliancePosture() {
  var hipaa = b.guardArchive.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.symlinkPolicy === "reject" &&
        hipaa.hardlinkPolicy === "reject" &&
        hipaa.traversalPolicy === "reject");

  var threw = null;
  try { b.guardArchive.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardArchiveBadProfile() {
  var threw = null;
  try { b.guardArchive.validateEntries([], { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validateEntries: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

async function run() {
  testGuardArchiveSurface();
  testGuardArchiveRegistryParity();
  testGuardArchiveZipSlip();
  testGuardArchiveAbsolutePath();
  testGuardArchiveSymlinkRejectStrict();
  testGuardArchiveSymlinkEscape();
  testGuardArchiveHardlinkEscape();
  testGuardArchiveCompressionRatioBomb();
  testGuardArchiveAggregateRatioBomb();
  testGuardArchiveTotalSizeCap();
  testGuardArchiveEntryCountCap();
  testGuardArchiveNestedArchive();
  testGuardArchiveDuplicateNames();
  testGuardArchiveCaseInsensitiveCollision();
  testGuardArchiveEncryptionMismatch();
  testGuardArchiveSparseEntry();
  testGuardArchiveInspectMagic();
  testGuardArchiveCheckExtractionPath();
  testGuardArchiveCleanArchive();
  testGuardArchiveCompliancePosture();
  testGuardArchiveBadProfile();
  await testGuardArchiveGate();
}

module.exports = { run: run };
