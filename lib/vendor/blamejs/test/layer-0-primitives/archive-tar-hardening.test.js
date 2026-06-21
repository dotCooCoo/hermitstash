"use strict";
/**
 * b.archive.read.tar hardening — uncapped random-access read + PAX `size`
 * NaN walker-desync.
 *
 *   - random-access cap: the random-access adapter branch read the WHOLE
 *     source with `adapter.range(0, size)` and no ceiling — a multi-GiB
 *     source is an OOM lever. It now refuses a source larger than the bomb
 *     policy's maxTotalDecompressedBytes.
 *   - PAX size NaN: a PAX extended header carrying a non-numeric `size`
 *     ("abc") was `parseInt`'d to NaN, which silently bypassed the
 *     entry-size bomb check (`NaN > max` is false) AND desynced the 512-byte
 *     block walker (`Math.ceil(NaN / 512)` is NaN). It now refuses a
 *     malformed PAX size.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var BLOCK = 512;

// Minimal ustar header builder with a valid POSIX checksum (sum of all 512
// bytes with the chksum field treated as 8 spaces). Enough for the reader's
// _parseHeader (magic + chksum validated).
function _octal(n, width) {
  var s = n.toString(8);
  while (s.length < width - 1) s = "0" + s;
  return s; // caller pads with NUL
}
function _header(name, size, typeflag) {
  var buf = Buffer.alloc(BLOCK, 0);
  buf.write(name, 0, Math.min(name.length, 100), "ascii");
  buf.write("0000644\0", 100, 8, "ascii");          // mode
  buf.write("0000000\0", 108, 8, "ascii");          // uid
  buf.write("0000000\0", 116, 8, "ascii");          // gid
  buf.write(_octal(size, 12) + "\0", 124, 12, "ascii");   // size (11 octal + NUL)
  buf.write("00000000000\0", 136, 12, "ascii");     // mtime
  buf.write(typeflag, 156, 1, "ascii");             // typeflag
  buf.write("ustar\0", 257, 6, "ascii");            // magic
  buf.write("00", 263, 2, "ascii");                 // version
  // checksum: chksum field = 8 spaces while summing
  for (var i = 148; i < 156; i++) buf[i] = 0x20;
  var sum = 0;
  for (var j = 0; j < BLOCK; j++) sum += buf[j];
  var oct = sum.toString(8);
  while (oct.length < 6) oct = "0" + oct;
  buf.write(oct + "\0 ", 148, 8, "ascii");          // 6 octal + NUL + space
  return buf;
}
function _pad512(buf) {
  var rem = buf.length % BLOCK;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(BLOCK - rem, 0)]);
}
// Build a tar whose first entry is a PAX extended header (typeflag 'x')
// carrying `size=<paxSizeValue>`, followed by a real file entry.
function _paxTar(paxSizeValue, fileBody) {
  var rec = " size=" + paxSizeValue + "\n";
  // PAX record = "<total-length> size=<value>\n"; total counts its own digits.
  var total = rec.length;
  while (String(total).length + rec.length !== total) total = String(total).length + rec.length;
  var paxBody = Buffer.from(String(total) + rec, "ascii");
  var paxHdr = _header("PaxHeader/file.txt", paxBody.length, "x");
  var fileHdr = _header("file.txt", fileBody.length, "0");
  return Buffer.concat([
    paxHdr, _pad512(paxBody),
    fileHdr, _pad512(Buffer.from(fileBody)),
    Buffer.alloc(BLOCK * 2, 0),   // end-of-archive
  ]);
}

function _codeOf(p) {
  return p.then(function () { return null; }, function (e) { return (e && e.code) || (e && e.message) || "threw"; });
}

async function testRandomAccessReadIsCapped() {
  var t = b.archive.tar();
  t.addFile("a.txt", "hello world payload that is comfortably over a hundred bytes long ............................");
  var bytes = t.toBuffer();   // ~2 KiB, random-access buffer adapter
  // A tiny bomb policy → the 2 KiB source exceeds the read cap → refuse.
  var code = await _codeOf(
    b.archive.read.tar(b.archive.adapters.buffer(bytes), {
      bombPolicy: { maxTotalDecompressedBytes: 100 },
    }).inspect());
  check("read.tar refuses a random-access source over the read cap (OOM defense)",
    code === "archive-tar/source-too-large");

  // A generous cap still reads it (no over-rejection).
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(bytes), {
    bombPolicy: { maxTotalDecompressedBytes: 64 * 1024 * 1024 },
  }).inspect();
  check("read.tar still reads within the cap", entries.length === 1);
}

async function testPaxMalformedSizeRefused() {
  // Truthy-but-non-integer PAX size values that reach the parser (an empty
  // string is correctly treated as "no override" by the `if (pax.size)` guard).
  var malformed = ["abc", "1e9", "100abc", "-5"];
  for (var i = 0; i < malformed.length; i++) {
    var tar = _paxTar(malformed[i], "x");
    var code = await _codeOf(b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect());
    check("read.tar refuses malformed PAX size " + JSON.stringify(malformed[i]) +
      " (no NaN bomb-bypass / walker desync)", code === "archive-tar/bad-pax-size");
  }
}

async function testPaxValidSizeAccepted() {
  // A well-formed PAX size override is honored (no over-rejection).
  var tar = _paxTar("1", "x");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(tar)).inspect();
  check("read.tar accepts a valid PAX size override", entries.length >= 1);
}

// Build a tar whose first entry is a PAX extended header ('x') declaring a
// LARGE body size, followed by a real file. The per-entry decompressed-bytes
// cap previously only guarded regular entries (the check sat after the PAX
// `continue`), so a PAX header body escaped it.
function _largePaxBodyTar(bodyLen) {
  var paxBody = Buffer.alloc(bodyLen, 0x41);            // content irrelevant — cap fires before parse
  var paxHdr  = _header("PaxHeader/file.txt", paxBody.length, "x");
  var fileHdr = _header("file.txt", 1, "0");
  return Buffer.concat([
    paxHdr, _pad512(paxBody),
    fileHdr, _pad512(Buffer.from("x")),
    Buffer.alloc(BLOCK * 2, 0),
  ]);
}

async function testPaxBodyRespectsPerEntryCap() {
  // A 4 KiB PAX header body under a 1 KiB per-entry cap must be refused — it
  // previously bypassed maxEntryDecompressedBytes (which a regular 4 KiB entry
  // would trip), forcing an over-cap string + record-Object materialization.
  var tar = _largePaxBodyTar(4096);
  var code = await _codeOf(b.archive.read.tar(b.archive.adapters.buffer(tar), {
    bombPolicy: { maxEntryDecompressedBytes: 1024 },
  }).inspect());
  check("read.tar caps an oversized PAX header body (no per-entry-cap bypass)",
    code === "archive-tar/entry-too-large");

  // A small PAX body under the cap still parses (no over-rejection).
  var okTar = _paxTar("1", "x");
  var entries = await b.archive.read.tar(b.archive.adapters.buffer(okTar), {
    bombPolicy: { maxEntryDecompressedBytes: 1024 },
  }).inspect();
  check("read.tar still accepts a small PAX body under the cap", entries.length >= 1);
}

async function run() {
  await testRandomAccessReadIsCapped();
  await testPaxMalformedSizeRefused();
  await testPaxValidSizeAccepted();
  await testPaxBodyRespectsPerEntryCap();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
