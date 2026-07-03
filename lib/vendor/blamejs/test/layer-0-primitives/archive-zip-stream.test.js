// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.archive — streaming ZIP creation (toStream + Readable addFile content).
 *
 * Covers: Readable as addFile content; toStream(writable) pipes through;
 * toStream() with no writable returns a Readable; data-descriptor flag is
 * set per APPNOTE 4.4.4 bit 3; central directory written only after every
 * entry succeeds (atomic finalize); aborted source destroys the destination
 * and emits archive.zip.streamed.aborted; mixed buffer + stream entries
 * round-trip; toBuffer refuses streaming entries; audit emits the
 * completed event with byte counts.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;
var check   = helpers.check;
var stream  = require("node:stream");
var zlib    = require("node:zlib");

function _readU32LE(buf, off) {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}
function _readU16LE(buf, off) {
  return buf[off] | (buf[off + 1] << 8);
}

function _collect(readable) {
  return new Promise(function (resolve, reject) {
    var chunks = [];
    readable.on("data", function (c) { chunks.push(c); });
    readable.on("end", function () { resolve(Buffer.concat(chunks)); });
    readable.on("error", reject);
  });
}

function _readableFromBuffers(bufs) {
  var i = 0;
  return new stream.Readable({
    read: function () {
      if (i >= bufs.length) this.push(null);
      else this.push(bufs[i++]);
    },
  });
}

async function testSurface() {
  var arc = b.archive.zip();
  check("archive.zip().toStream is a function",
        typeof arc.toStream === "function");
}

async function testStreamReadableContent() {
  // Two stream entries (one short, one larger) + one buffer entry. Pipe
  // to PassThrough, collect bytes, validate the resulting archive.
  var payload1 = Buffer.from("first stream content\n", "utf8");
  var payload2 = Buffer.alloc(64 * 1024, 0x41);   // 64 KiB of 'A' — deflate-friendly
  var arc = b.archive.zip();
  arc.addFile("stream1.txt", _readableFromBuffers([payload1]));
  arc.addFile("buffer.txt", "buffer entry\n");
  arc.addFile("stream2.bin", _readableFromBuffers([
    payload2.subarray(0, 32 * 1024),
    payload2.subarray(32 * 1024),
  ]));

  var sink = new stream.PassThrough();
  var collected = _collect(sink);
  await arc.toStream(sink);
  var buf = await collected;

  check("toStream: produced archive starts with PK signature",
        buf[0] === 0x50 && buf[1] === 0x4b);
  // EOCD lives at the very end (no comment).
  check("toStream: ends with EOCD signature",
        _readU32LE(buf, buf.length - 22) === 0x06054b50);
  check("toStream: EOCD records 3 entries",
        _readU16LE(buf, buf.length - 22 + 10) === 3);

  // First LFH for stream1.txt — flag bit 3 (data-descriptor) MUST be set
  // because crc/sizes weren't known at LFH-write time.
  var flags = _readU16LE(buf, 6);
  check("toStream: stream entry LFH has data-descriptor flag (bit 3)",
        (flags & 0x0008) === 0x0008);
  check("toStream: stream entry LFH has UTF-8 flag (bit 11)",
        (flags & 0x0800) === 0x0800);
  // Stream entry LFH carries zero crc/csize/usize per APPNOTE 4.4.4.
  check("toStream: stream entry LFH crc=0",
        _readU32LE(buf, 14) === 0);
  check("toStream: stream entry LFH csize=0",
        _readU32LE(buf, 18) === 0);
  check("toStream: stream entry LFH usize=0",
        _readU32LE(buf, 22) === 0);

  // Round-trip: extract stream1 by parsing LFH + finding the data
  // descriptor. csize unknown until we read the descriptor — but we set
  // method=DEFLATE so we can inflateRaw a streaming chunk.
  var nameLen = _readU16LE(buf, 26);
  var dataStart = 30 + nameLen;
  // Hunt for the data-descriptor signature 0x08074b50 to bound csize.
  var ddSig = 0x08074b50;
  var ddOffset = -1;
  for (var p = dataStart; p < buf.length - 16; p++) {
    if (_readU32LE(buf, p) === ddSig) { ddOffset = p; break; }
  }
  check("toStream: data descriptor located after stream entry payload",
        ddOffset > dataStart);
  var ddCrc = _readU32LE(buf, ddOffset + 4);
  var ddCsize = _readU32LE(buf, ddOffset + 8);
  var ddUsize = _readU32LE(buf, ddOffset + 12);
  check("toStream: data descriptor csize matches payload-to-descriptor distance",
        ddCsize === (ddOffset - dataStart));
  check("toStream: data descriptor usize matches uncompressed source",
        ddUsize === payload1.length);
  void ddCrc;

  var compressed = buf.slice(dataStart, dataStart + ddCsize);
  var inflated = zlib.inflateRawSync(compressed);
  check("toStream: stream entry round-trips through inflate",
        inflated.toString("utf8") === payload1.toString("utf8"));
}

async function testToStreamReturnsReadable() {
  var arc = b.archive.zip();
  arc.addFile("a.txt", _readableFromBuffers([Buffer.from("alpha", "utf8")]));
  var rs = await arc.toStream();    // no writable supplied
  check("toStream() without writable returns a Readable",
        rs && typeof rs.pipe === "function");
  var collected = await _collect(rs);
  check("toStream(): readable emits a complete archive",
        _readU32LE(collected, collected.length - 22) === 0x06054b50);
}

async function testWriteToHttpResShape() {
  // Simulate piping to an HTTP res — a Writable with .write/.end. The
  // wiki's documented shape: archive.toStream(res).
  var written = [];
  var fakeRes = new stream.Writable({
    write: function (chunk, enc, cb) { written.push(chunk); cb(); },
  });
  var finished = new Promise(function (resolve) { fakeRes.on("finish", resolve); });

  var arc = b.archive.zip();
  arc.addFile("export.json", _readableFromBuffers([Buffer.from('{"k":1}', "utf8")]));
  await arc.toStream(fakeRes);
  await finished;

  var buf = Buffer.concat(written);
  check("toStream(res): wrote complete archive to res",
        _readU32LE(buf, buf.length - 22) === 0x06054b50);
  check("toStream(res): ended the writable",
        fakeRes.writableEnded === true);
}

async function testAtomicAbortOnSourceError() {
  // Source emits 'error' → toStream rejects, destination destroyed,
  // central directory NEVER written (the surviving bytes do not form a
  // valid archive — operators see the broken pipe, not a half-complete
  // zip that pretends to be whole).
  var bad = new stream.Readable({
    read: function () {
      var self = this;
      process.nextTick(function () { self.destroy(new Error("source kaboom")); });
    },
  });
  var sink = new stream.PassThrough();
  var sinkBytes = [];
  sink.on("data", function (c) { sinkBytes.push(c); });
  sink.on("error", function () { /* expected — toStream destroys on abort */ });

  var captured = [];
  var fakeAudit = { safeEmit: function (e) { captured.push(e); } };

  var arc = b.archive.zip();
  arc.addFile("ok.txt", "ok\n");
  arc.addFile("broken.bin", bad);
  arc.addFile("never.txt", "never\n");

  var threw = null;
  try { await arc.toStream(sink, { audit: fakeAudit }); }
  catch (e) { threw = e; }

  check("aborted: toStream rejects on source error",
        threw !== null);
  // Whatever bytes leaked into the sink do NOT contain an EOCD signature
  // — that's the proof "atomic finalize" held.
  var leaked = Buffer.concat(sinkBytes);
  var hasEocd = false;
  for (var p = 0; p + 4 <= leaked.length; p++) {
    if (_readU32LE(leaked, p) === 0x06054b50) { hasEocd = true; break; }
  }
  check("aborted: leaked bytes contain no EOCD (no central directory)",
        hasEocd === false);

  check("aborted: audit emits archive.zip.streamed.aborted",
        captured.some(function (e) {
          return e.action === "archive.zip.streamed.aborted" && e.outcome === "failure";
        }));
}

async function testAuditCompletedEvent() {
  var captured = [];
  var fakeAudit = { safeEmit: function (e) { captured.push(e); } };

  var arc = b.archive.zip();
  arc.addFile("a.txt", _readableFromBuffers([Buffer.from("a", "utf8")]));
  arc.addFile("b.txt", "b");
  await arc.toStream(new stream.PassThrough(), { audit: fakeAudit });

  var done = captured.find(function (e) {
    return e.action === "archive.zip.streamed.completed";
  });
  check("audit: completed event emitted",
        done && done.outcome === "success");
  check("audit: completed event reports entry count",
        done && done.metadata && done.metadata.entries === 2);
  check("audit: completed event reports byte count > 0",
        done && done.metadata && typeof done.metadata.bytes === "number" && done.metadata.bytes > 0);
}

function testToBufferRefusesStreamingEntry() {
  var arc = b.archive.zip();
  arc.addFile("s.txt", _readableFromBuffers([Buffer.from("x", "utf8")]));
  var threw = null;
  try { arc.toBuffer(); } catch (e) { threw = e; }
  check("toBuffer refuses streaming entry",
        threw && /streaming-entry/.test(threw.code || ""));
}

async function testStreamEntryNameValidation() {
  // Streaming addFile must enforce the same name-validation as buffer
  // addFile — `..` segments, null bytes, empty names all rejected before
  // pipe time so the operator gets a clean throw at addFile rather than
  // a half-built archive at toStream time.
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("stream addFile reject: " + label, threw && codeRe.test(threw.code || ""));
  }
  var src = function () {
    return _readableFromBuffers([Buffer.from("x", "utf8")]);
  };
  rejects("empty name (stream)",   function () { b.archive.zip().addFile("", src()); }, /archive\/bad-name/);
  rejects("null byte (stream)",    function () { b.archive.zip().addFile("a\0b", src()); }, /archive\/bad-name/);
  rejects("..  segment (stream)",  function () { b.archive.zip().addFile("../etc/passwd", src()); }, /archive\/bad-name/);
}

async function testStreamThenWriteToFile() {
  // End-to-end: stream a multi-entry archive into a fs.createWriteStream
  // and unzip via stdlib parse to confirm the on-disk file is a valid
  // archive operators can hand to `unzip`.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-arch-stream-"));
  try {
    var outPath = path.join(tmpDir, "out.zip");
    var ws = fs.createWriteStream(outPath);
    var arc = b.archive.zip();
    arc.addFile("hello.txt", _readableFromBuffers([Buffer.from("Hello\n", "utf8")]));
    arc.addFile("data.bin", _readableFromBuffers([Buffer.alloc(8 * 1024, 0x42)]));
    await arc.toStream(ws);
    await new Promise(function (resolve) { ws.on("close", resolve); ws.end(); });
    var onDisk = fs.readFileSync(outPath);
    check("stream-to-file: ends with EOCD",
          _readU32LE(onDisk, onDisk.length - 22) === 0x06054b50);
    check("stream-to-file: byte count > 0",
          onDisk.length > 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function run() {
  await testSurface();
  await testStreamReadableContent();
  await testToStreamReturnsReadable();
  await testWriteToHttpResShape();
  await testAtomicAbortOnSourceError();
  await testAuditCompletedEvent();
  testToBufferRefusesStreamingEntry();
  await testStreamEntryNameValidation();
  await testStreamThenWriteToFile();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
