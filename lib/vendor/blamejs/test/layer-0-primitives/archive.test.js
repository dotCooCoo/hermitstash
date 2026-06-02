"use strict";
/**
 * b.archive — ZIP creation.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var check = helpers.check;
var zlib  = require("node:zlib");

function _readU32LE(buf, off) {
  return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24) >>> 0;
}
function _readU16LE(buf, off) {
  return buf[off] | (buf[off + 1] << 8);
}

async function run() {
  // ---- Surface ----
  check("b.archive namespace present",     typeof b.archive === "object");
  check("b.archive.zip is fn",             typeof b.archive.zip === "function");
  check("b.archive.ArchiveError is class", typeof b.archive.ArchiveError === "function");

  // ---- CRC-32 known vector ----
  // CRC32("123456789") = 0xCBF43926 (IEEE 802.3)
  check("crc32: known vector",
        b.archive._crc32ForTest(Buffer.from("123456789")) === 0xCBF43926);
  // CRC32("") = 0
  check("crc32: empty buffer",
        b.archive._crc32ForTest(Buffer.alloc(0)) === 0);

  // ---- zip().addFile + toBuffer ----
  var archive = b.archive.zip();
  archive.addFile("readme.txt", "Hello, world!\n");
  archive.addFile("data/users.csv", "id,name\n1,alice\n2,bob\n");
  archive.addFile("avatars/me.png", Buffer.from([0x89, 0x50, 0x4e, 0x47]), { method: "store" });
  check("addFile: entryCount",            archive.entryCount === 3);

  var buf = archive.toBuffer();
  check("toBuffer: returns Buffer",        Buffer.isBuffer(buf));
  check("toBuffer: signature is PK",       buf[0] === 0x50 && buf[1] === 0x4b);

  // EOCD signature lives near the end. Find it (it's at offset bytes-22
  // for archives with no comment).
  var eocdSig = _readU32LE(buf, buf.length - 22);
  check("toBuffer: EOCD signature",        eocdSig === 0x06054b50);
  var totalEntries = _readU16LE(buf, buf.length - 22 + 10);
  check("toBuffer: EOCD entry count",      totalEntries === 3);

  // ---- addFile rejects bad input ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("addFile reject: " + label,  threw && codeRe.test(threw.code || ""));
  }
  rejects("empty name",     function () { b.archive.zip().addFile("", "x"); }, /archive\/bad-name/);
  rejects("non-string name",function () { b.archive.zip().addFile(42, "x"); }, /archive\/bad-name/);
  rejects("null byte",      function () { b.archive.zip().addFile("a\0b", "x"); }, /archive\/bad-name/);
  rejects(".. segment",     function () { b.archive.zip().addFile("../etc/passwd", "x"); }, /archive\/bad-name/);
  rejects("non-buffer-non-string content",
                            function () { b.archive.zip().addFile("a.txt", 42); }, /archive\/bad-content/);

  // ---- writeTo (real disk I/O) ----
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-arch-"));
  try {
    var arc = b.archive.zip();
    arc.addFile("note.txt", "test content");
    var zipPath = path.join(tmpDir, "out.zip");
    var bytesWritten = arc.writeTo(zipPath);
    var onDisk = fs.readFileSync(zipPath);
    check("writeTo: returned byte count matches file size",  bytesWritten === onDisk.length);
    check("writeTo: starts with PK signature",                 onDisk[0] === 0x50 && onDisk[1] === 0x4b);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // ---- Round-trip: extract via stdlib (manually parse one local file header
  //                  and inflate to verify content)
  var rt = b.archive.zip();
  rt.addFile("hello.txt", "Hello, blamejs!\n");
  var rtBuf = rt.toBuffer();

  // Local file header at offset 0:
  //   sig (4), version (2), flags (2), method (2), mtime (2), mdate (2),
  //   crc (4), csize (4), usize (4), nameLen (2), extraLen (2)
  check("rt: LFH signature",        _readU32LE(rtBuf, 0) === 0x04034b50);
  var method  = _readU16LE(rtBuf, 8);
  var csize   = _readU32LE(rtBuf, 18);
  var usize   = _readU32LE(rtBuf, 22);
  var nameLen = _readU16LE(rtBuf, 26);
  var nameStart = 30;
  var nameInZip = rtBuf.slice(nameStart, nameStart + nameLen).toString("utf8");
  check("rt: LFH name round-trip",  nameInZip === "hello.txt");
  var dataStart = nameStart + nameLen;
  var stored = rtBuf.slice(dataStart, dataStart + csize);
  var inflated;
  if (method === 8) inflated = zlib.inflateRawSync(stored);
  else              inflated = stored;
  check("rt: payload round-trip",   inflated.toString("utf8") === "Hello, blamejs!\n");
  check("rt: uncompressed-size correct",  usize === 16);

  // ---- Path normalization: backslashes converted to forward slashes ----
  var winLike = b.archive.zip();
  winLike.addFile("data\\nested\\file.txt", "x");
  var wlBuf = winLike.toBuffer();
  var wlNameLen = _readU16LE(wlBuf, 26);
  var wlName = wlBuf.slice(30, 30 + wlNameLen).toString("utf8");
  check("name: backslashes → forward",  wlName === "data/nested/file.txt");

  // ---- Leading slash stripped ----
  var ls = b.archive.zip();
  ls.addFile("/abs/path.txt", "x");
  var lsBuf = ls.toBuffer();
  var lsNameLen = _readU16LE(lsBuf, 26);
  var lsName = lsBuf.slice(30, 30 + lsNameLen).toString("utf8");
  check("name: leading slash stripped", lsName === "abs/path.txt");

  // ---- digest() returns a hex SHA3-512 ----
  var d1 = b.archive.zip();
  d1.addFile("a", "x");
  var dig = d1.digest();
  check("digest: hex string",          /^[0-9a-f]{128}$/.test(dig));

  // ---- Empty archive is valid ZIP ----
  var emptyBuf = b.archive.zip().toBuffer();
  check("empty archive: just EOCD (22 bytes)",  emptyBuf.length === 22);
  check("empty archive: EOCD signature",        _readU32LE(emptyBuf, 0) === 0x06054b50);

  await testZip64Write();
}

// ZIP64 write (APPNOTE 6.3.10 §4.3.14 EOCD64 / §4.3.15 locator / §4.4.8
// size fields / §4.5.3 extended-information extra). The writer emits
// ZIP64 only when needed; small archives stay classic byte-for-byte, and
// what it emits round-trips through the v0.14.18 random-access reader.
var SIG_EOCD64         = Buffer.from([0x50, 0x4b, 0x06, 0x06]);
var SIG_EOCD64_LOCATOR = Buffer.from([0x50, 0x4b, 0x06, 0x07]);
var METHOD_STORE       = 0;

async function testZip64Write() {
  // ---- Classic archives carry no ZIP64 trailer or per-entry extra ----
  var classic = b.archive.zip();
  classic.addFile("readme.txt", "Hello, world!\n");
  classic.addFile("data/users.csv", "id,name\n1,alice\n2,bob\n");
  var classicBuf = classic.toBuffer();
  check("zip64-write: small archive has no ZIP64 EOCD",
        classicBuf.indexOf(SIG_EOCD64) === -1);
  check("zip64-write: small archive has no ZIP64 locator",
        classicBuf.indexOf(SIG_EOCD64_LOCATOR) === -1);
  check("zip64-write: small archive ends in classic 22-byte EOCD",
        _readU32LE(classicBuf, classicBuf.length - 22) === 0x06054b50);
  check("zip64-write: first LFH carries no extra field",
        _readU16LE(classicBuf, 28) === 0);

  // ---- Byte-stable: same inputs + mtimes emit identical bytes ----
  var fixedMtime = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  function buildFixed() {
    var z = b.archive.zip();
    z.addFile("a.txt", "alpha", { mtime: fixedMtime });
    z.addFile("b.txt", "beta",  { mtime: fixedMtime });
    return z.toBuffer();
  }
  check("zip64-write: classic output is byte-stable",
        buildFixed().equals(buildFixed()));

  // ---- >65535 entries forces the ZIP64 EOCD record + locator, and the
  //      classic EOCD entry-count fields carry the 0xFFFF sentinel. The
  //      reader resolves the true count from the ZIP64 EOCD record. ----
  var many = b.archive.zip();
  var manyCount = 65536;
  for (var i = 0; i < manyCount; i++) many.addFile("f" + i + ".txt", "x");
  check("zip64-write: entryCount tracks 65536 entries", many.entryCount === manyCount);
  var manyBuf = many.toBuffer();
  check("zip64-write: >65535 entries emits ZIP64 EOCD record",
        manyBuf.indexOf(SIG_EOCD64) !== -1);
  check("zip64-write: >65535 entries emits ZIP64 EOCD locator",
        manyBuf.indexOf(SIG_EOCD64_LOCATOR) !== -1);
  check("zip64-write: classic EOCD entry count is 0xFFFF sentinel",
        _readU16LE(manyBuf, manyBuf.length - 22 + 10) === 0xffff);

  var manyReader = b.archive.read.zip(b.archive.adapters.buffer(manyBuf), {
    bombPolicy: { maxEntries: 2000000 },
  });
  var manyEntries = await manyReader.inspect();
  check("zip64-write: reader resolves true count from ZIP64 EOCD",
        manyEntries.length === manyCount);
  check("zip64-write: first/last names round-trip",
        manyEntries[0].name === "f0.txt" &&
        manyEntries[manyCount - 1].name === "f65535.txt");

  // Round-trip recovers byte-identical content for a sampled entry.
  var firstBytes = null;
  for await (var rEnt of manyReader.extractEntries({ allowEncrypted: false })) {
    firstBytes = rEnt.bytes;
    break;
  }
  check("zip64-write: extractEntries recovers content from a ZIP64 archive",
        firstBytes && firstBytes.equals(Buffer.from("x")));

  // ---- Per-entry ZIP64 extended-information extra field (§4.5.3) ----
  // Real >4 GiB entries are impractical in a unit test; the writer's
  // extra-field builder is exercised at logical sizes/offsets above the
  // 32-bit limit, and the produced extra is fed to the v0.14.18 reader,
  // which resolves the full 64-bit value back. The entry-count + EOCD64
  // paths above already round-trip the EOCD64/locator end to end.
  var z64 = b.archive._zip64ForTest;
  check("zip64-write: U32_MAX is NOT an overflow (boundary)",
        z64.entryNeedsZip64(z64.U32_MAX, 0, 0) === false);
  check("zip64-write: size above U32_MAX overflows",
        z64.entryNeedsZip64(0, z64.U32_MAX + 1, 0) === true);
  check("zip64-write: offset above U32_MAX overflows",
        z64.entryNeedsZip64(0, 0, z64.U32_MAX + 1) === true);

  // No overflow → empty extra (classic stays classic).
  check("zip64-write: no-overflow extra is empty",
        z64.buildExtra(100, 100, 100, true).length === 0);

  // CD extra (offset included) at overflowing usize+csize → 16-byte data
  // block (uncompressedSize, compressedSize), header id 0x0001.
  var big = z64.U32_MAX + 1234;
  var cdExtra = z64.buildExtra(big, big, 0, true);
  check("zip64-write: CD extra header id is 0x0001",
        cdExtra.readUInt16LE(0) === z64.EXTRA_HEADER_ID);
  check("zip64-write: CD extra data length is 16 (usize+csize)",
        cdExtra.readUInt16LE(2) === 16);
  check("zip64-write: CD extra carries usize then csize (APPNOTE order)",
        cdExtra.readBigUInt64LE(4) === BigInt(big) &&
        cdExtra.readBigUInt64LE(12) === BigInt(big));

  // Offset overflow too → 24-byte data block (usize, csize, offset).
  var bigOff = z64.U32_MAX + 7;
  var cdExtraOff = z64.buildExtra(big, big, bigOff, true);
  check("zip64-write: CD extra widens to 24 bytes when offset overflows",
        cdExtraOff.readUInt16LE(2) === 24 &&
        cdExtraOff.readBigUInt64LE(20) === BigInt(bigOff));

  // LFH extra never carries the offset (§4.5.3) — 16 bytes even when the
  // offset overflows.
  var lfhExtra = z64.buildExtra(big, big, bigOff, false);
  check("zip64-write: LFH extra omits the offset field",
        lfhExtra.readUInt16LE(2) === 16);

  // End to end: a synthetic single-entry archive whose LFH + CD ZIP64
  // extra blocks come from the writer's builder, with the classic size
  // fields set to the sentinel, resolves through the real reader to the
  // full 64-bit logical size.
  var payload = Buffer.from("ZIP64 writer-extra resolution payload.\n", "utf8");
  var name    = "z64w.txt";
  var nameBuf = Buffer.from(name, "utf8");
  var crc     = b.archive._crc32ForTest(payload);
  var logical = z64.U32_MAX + payload.length;  // > 4 GiB

  var lfhExtraBig = z64.buildExtra(logical, logical, 0, false);
  var lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);
  lfh.writeUInt16LE(45, 4);
  lfh.writeUInt16LE(0, 6);
  lfh.writeUInt16LE(METHOD_STORE, 8);
  lfh.writeUInt16LE(0, 10);
  lfh.writeUInt16LE(0x21, 12);
  lfh.writeUInt32LE(crc >>> 0, 14);
  lfh.writeUInt32LE(z64.U32_SENTINEL, 18);
  lfh.writeUInt32LE(z64.U32_SENTINEL, 22);
  lfh.writeUInt16LE(nameBuf.length, 26);
  lfh.writeUInt16LE(lfhExtraBig.length, 28);

  var cdExtraBig = z64.buildExtra(logical, logical, 0, true);
  var cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(45, 4);
  cd.writeUInt16LE(45, 6);
  cd.writeUInt16LE(0, 8);
  cd.writeUInt16LE(METHOD_STORE, 10);
  cd.writeUInt16LE(0, 12);
  cd.writeUInt16LE(0x21, 14);
  cd.writeUInt32LE(crc >>> 0, 16);
  cd.writeUInt32LE(z64.U32_SENTINEL, 20);
  cd.writeUInt32LE(z64.U32_SENTINEL, 24);
  cd.writeUInt16LE(nameBuf.length, 28);
  cd.writeUInt16LE(cdExtraBig.length, 30);
  cd.writeUInt16LE(0, 32);
  cd.writeUInt16LE(0, 34);
  cd.writeUInt16LE(0, 36);
  cd.writeUInt32LE(0, 38);
  cd.writeUInt32LE(0, 42);

  var localPart = Buffer.concat([lfh, nameBuf, lfhExtraBig, payload]);
  var cdOffset  = localPart.length;
  var cdRecord  = Buffer.concat([cd, nameBuf, cdExtraBig]);
  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdRecord.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  var synthetic = Buffer.concat([localPart, cdRecord, eocd]);

  var z64Reader = b.archive.read.zip(b.archive.adapters.buffer(synthetic), {
    bombPolicy: {
      maxEntryDecompressedBytes: logical + 16,
      maxTotalDecompressedBytes: logical + 16,
    },
  });
  var z64Entries = await z64Reader.inspect();
  check("zip64-write: reader resolves writer-built extra to 64-bit size",
        z64Entries.length === 1 && z64Entries[0].size === logical);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
