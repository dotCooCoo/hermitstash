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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
