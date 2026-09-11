// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.archive
 * @nav    Tools
 * @title  Archive
 *
 * @intro
 *   ZIP archive creation primitive. Operator-data-export shape
 *   ("download my data as a zip"), log bundling, plain-zip exports for
 *   end users.
 *
 *   Two output paths:
 *     - `toBuffer()` builds the whole archive in memory — good for
 *       small-to-medium exports that fit comfortably in process RSS.
 *     - `toStream(writable)` deflates each entry through a piped
 *       zlib transform and writes the central directory only after
 *       every entry finalizes, so multi-GB exports never need to
 *       fit in memory. If any source errors mid-pipe, the destination
 *       is destroyed with `archive/aborted` — consumers see a broken
 *       stream rather than a half-archive that pretends to be complete.
 *
 *   Compression:
 *     - `deflate` (default) via node:zlib's `deflateRawSync` —
 *       falls back to STORE when deflate didn't shrink the input.
 *     - `store` — no compression, for already-compressed bytes
 *       (PNG / JPEG / mp4).
 *
 *   Format guarantees:
 *     - Deterministic insertion order (entries appear in the order
 *       `addFile` is called; central directory matches).
 *     - UTF-8 file names with the APPNOTE 6.3.4 EFS bit set.
 *     - Path-traversal refused at `addFile`: leading `/`, backslashes,
 *       null bytes, and `..` segments throw `archive/bad-name`.
 *     - No symlink emission — only regular file entries are produced.
 *     - SHA3-512 fingerprint via `digest()` for operator integrity logs.
 *     - ZIP64 (APPNOTE 6.3.10 §4.3.14 / §4.3.15 / §4.4.8 / §4.5.3) is
 *       emitted automatically when an archive exceeds 65535 entries or
 *       any entry's compressed/uncompressed size or local-header offset
 *       exceeds 4 GiB: the classic field carries the 0xFFFF/0xFFFFFFFF
 *       sentinel, a ZIP64 extended-information extra field supplies the
 *       64-bit value, and the ZIP64 EOCD record + locator precede the
 *       classic EOCD. Archives below those limits stay classic
 *       byte-for-byte. `b.archive.read.zip` reads the produced ZIP64
 *       form transparently.
 *
 *   Out of scope (v1):
 *     - ZIP-native password encryption (broken-by-design); operators
 *       wrap the produced bytes via `b.crypto.encryptPacked` for
 *       encryption-at-rest.
 *
 * @card
 *   ZIP archive creation primitive.
 */
var zlib = require("node:zlib");
var nodeCrypto = require("node:crypto");
var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var C = require("./constants");
var { defineClass } = require("./framework-error");
var auditEmit = require("./audit-emit");
var atomicFile = require("./atomic-file");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");

var ArchiveError = defineClass("ArchiveError", { alwaysPermanent: true });

var SIG_LFH = 0x04034b50;
var SIG_CFH = 0x02014b50;
var SIG_EOCD = 0x06054b50;
var SIG_EOCD64         = 0x06064b50;
var SIG_EOCD64_LOCATOR = 0x07064b50;

var ZIP64_U16_SENTINEL = 0xffff;
var ZIP64_U32_SENTINEL = 0xffffffff;
var ZIP64_U32_MAX           = 0xffffffff;
var ZIP64_MAX_CLASSIC_ENTRIES = 65535;
var ZIP64_VERSION_NEEDED    = 45;
var ZIP64_EXTRA_HEADER_ID   = 0x0001;
var ZIP64_EXTRA_FIELD_BYTES = 8;
var ZIP64_EOCD64_BYTES      = 56;
var ZIP64_EOCD64_LOCATOR_BYTES = 20;

var METHOD_STORE_ID   = 0;
var METHOD_DEFLATE_ID = 8;

var CRC32_TABLE_LEN = 256;
var CRC32_BIT_ITER  = 8;
var CRC32_TABLE = (function () {
  var t = new Uint32Array(CRC32_TABLE_LEN);
  for (var i = 0; i < CRC32_TABLE_LEN; i++) {
    var c = i;
    for (var j = 0; j < CRC32_BIT_ITER; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();

function _crc32(buf) {
  var crc = 0xffffffff;
  for (var i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function _msdosDateTime(date) {
  var d = date instanceof Date ? date : new Date(date);
  if (isNaN(d.getTime())) d = new Date();
  var dosTime = ((d.getHours() & 0x1f) << 11) |
                ((d.getMinutes() & 0x3f) << 5) |
                ((Math.floor(d.getSeconds() / 2)) & 0x1f);
  var dosDate = (((d.getFullYear() - 1980) & 0x7f) << 9) |
                (((d.getMonth() + 1) & 0xf) << 5) |
                (d.getDate() & 0x1f);
  return { time: dosTime, date: dosDate };
}

function _overflows32(n) { return n > ZIP64_U32_MAX; }

function _entryNeedsZip64(csize, usize, lfhOffset) {
  return _overflows32(csize) || _overflows32(usize) || _overflows32(lfhOffset);
}

function _buildZip64Extra(csize, usize, lfhOffset, includeOffset) {
  var needUsize  = _overflows32(usize);
  var needCsize  = _overflows32(csize);
  var needOffset = includeOffset && _overflows32(lfhOffset);
  if (!needUsize && !needCsize && !needOffset) return Buffer.alloc(0);
  var fields = 0;
  if (needUsize)  fields += 1;
  if (needCsize)  fields += 1;
  if (needOffset) fields += 1;
  var dataLen = fields * ZIP64_EXTRA_FIELD_BYTES;
  var extra = Buffer.alloc(C.BYTES.bytes(4 + dataLen));
  extra.writeUInt16LE(ZIP64_EXTRA_HEADER_ID, C.BYTES.bytes(0));
  extra.writeUInt16LE(dataLen, C.BYTES.bytes(2));
  var q = 4;
  if (needUsize)  { extra.writeBigUInt64LE(BigInt(usize),     C.BYTES.bytes(q)); q += ZIP64_EXTRA_FIELD_BYTES; }
  if (needCsize)  { extra.writeBigUInt64LE(BigInt(csize),     C.BYTES.bytes(q)); q += ZIP64_EXTRA_FIELD_BYTES; }
  if (needOffset) { extra.writeBigUInt64LE(BigInt(lfhOffset), C.BYTES.bytes(q)); q += ZIP64_EXTRA_FIELD_BYTES; }
  return extra;
}

/**
 * @primitive b.archive.zip
 * @signature b.archive.zip()
 * @since     0.4.0
 * @status    stable
 * @related   b.crypto.encryptPacked
 *
 * Create a new ZIP archive builder. The returned object exposes
 * `addFile(name, content, opts?)`, `toBuffer()`, `toStream(writable?)`,
 * `writeTo(path)`, `digest()`, and `entryCount`. Entries appear in the
 * archive's central directory in insertion order — same byte output
 * given the same input sequence and mtimes.
 *
 * `content` may be a `Buffer`, a UTF-8 `string`, or a `Readable`; only
 * `toStream()` can finalize archives containing `Readable` sources
 * (`toBuffer()` throws `archive/streaming-entry`).
 *
 * @example
 *   var archive = b.archive.zip();
 *   archive.addFile("readme.txt",     "Hello\n");
 *   archive.addFile("data/users.csv", Buffer.from("name,age\nAda,36\n"));
 *   archive.addFile("avatars/me.png", Buffer.from([0x89, 0x50, 0x4e, 0x47]),
 *                   { method: "store" });   // already-compressed
 *   var zipBytes = archive.toBuffer();
 *   archive.entryCount;            // → 3
 *   typeof archive.digest();       // → "string"  (sha3-512 hex)
 *
 *   // Stream a multi-GB export directly to an HTTP response.
 *   var fs = require("node:fs");
 *   var big = b.archive.zip();
 *   big.addFile("logs/2026-q1.ndjson", fs.createReadStream("/var/log/q1.ndjson"));
 *   // await big.toStream(res);
 */
function zip() {
  var entries = [];

  function _normalizeName(name) {
    if (typeof name !== "string" || name.length === 0) {
      throw new ArchiveError("archive/bad-name", "addFile: name must be a non-empty string");
    }
    if (name.indexOf("\0") !== -1) {
      throw new ArchiveError("archive/bad-name", "addFile: name contains null byte");
    }
    if (safeBuffer.hasCrlf(name)) {
      throw new ArchiveError("archive/bad-name", "addFile: name contains CR/LF");
    }
    var normalized = name.replace(/\\/g, "/").replace(/^\/+/, "");
    var segs = normalized.split("/");
    for (var si = 0; si < segs.length; si++) {
      if (segs[si] === "..") {
        throw new ArchiveError("archive/bad-name", "addFile: name contains '..' segment");
      }
    }
    return normalized;
  }

  function _isReadableStream(o) {
    return !!o && (o instanceof nodeStream.Readable ||
      (typeof o.pipe === "function" && typeof o.on === "function"));
  }

  function addFile(name, content, opts) {
    var normalized = _normalizeName(name);
    opts = opts || {};
    var method = opts.method === "store" ? METHOD_STORE_ID : METHOD_DEFLATE_ID;
    var mtime = opts.mtime instanceof Date ? opts.mtime : new Date();

    if (_isReadableStream(content)) {
      entries.push({
        name:    normalized,
        method:  method,
        mtime:   mtime,
        source:  content,
        kind:    "stream",
      });
      return;
    }

    var bodyBuf;
    if (Buffer.isBuffer(content)) bodyBuf = content;
    else if (typeof content === "string") bodyBuf = Buffer.from(content, "utf8");
    else throw new ArchiveError("archive/bad-content",
      "addFile: content must be a Buffer, string, or Readable, got " + typeof content);

    var crc = _crc32(bodyBuf);
    var stored = bodyBuf;
    if (method === METHOD_DEFLATE_ID) {
      stored = zlib.deflateRawSync(bodyBuf);
      if (stored.length >= bodyBuf.length) {
        stored = bodyBuf;
        method = METHOD_STORE_ID;
      }
    }

    entries.push({
      name:           normalized,
      method:         method,
      mtime:          mtime,
      crc:            crc,
      stored:         stored,
      uncompressedSize: bodyBuf.length,
      kind:           "buffer",
    });
  }

  var FLAG_UTF8_NAME = 0x0800;
  var FLAG_DATA_DESCRIPTOR = 0x0008;
  var SIG_DATA_DESCRIPTOR = 0x08074b50;

  function _buildLocalFileHeader(entry, opts) {
    var streaming = !!(opts && opts.streaming);
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var flags = FLAG_UTF8_NAME | (streaming ? FLAG_DATA_DESCRIPTOR : 0);
    var csize = streaming ? 0 : entry.stored.length;
    var usize = streaming ? 0 : entry.uncompressedSize;
    var zip64 = !streaming && _entryNeedsZip64(csize, usize, 0);
    var zip64Extra = zip64 ? _buildZip64Extra(csize, usize, 0, false) : Buffer.alloc(0);
    var hdr = Buffer.alloc(C.BYTES.bytes(30));
    hdr.writeUInt32LE(SIG_LFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(zip64 ? ZIP64_VERSION_NEEDED : 20, C.BYTES.bytes(4));
    hdr.writeUInt16LE(flags, C.BYTES.bytes(6));
    hdr.writeUInt16LE(entry.method, C.BYTES.bytes(0x08));
    hdr.writeUInt16LE(dt.time, C.BYTES.bytes(10));
    hdr.writeUInt16LE(dt.date, C.BYTES.bytes(12));
    hdr.writeUInt32LE(streaming ? 0 : entry.crc, C.BYTES.bytes(14));
    hdr.writeUInt32LE(_overflows32(csize) ? ZIP64_U32_SENTINEL : csize, C.BYTES.bytes(18));
    hdr.writeUInt32LE(_overflows32(usize) ? ZIP64_U32_SENTINEL : usize, C.BYTES.bytes(22));
    hdr.writeUInt16LE(nameBuf.length, C.BYTES.bytes(26));
    hdr.writeUInt16LE(zip64Extra.length, C.BYTES.bytes(28));
    return Buffer.concat([hdr, nameBuf, zip64Extra]);
  }

  function _buildDataDescriptor(crc, csize, usize) {
    var zip64 = _overflows32(csize) || _overflows32(usize);
    if (!zip64) {
      var dd = Buffer.alloc(C.BYTES.bytes(16));
      dd.writeUInt32LE(SIG_DATA_DESCRIPTOR, C.BYTES.bytes(0));
      dd.writeUInt32LE(crc, C.BYTES.bytes(4));
      dd.writeUInt32LE(csize, C.BYTES.bytes(0x08));
      dd.writeUInt32LE(usize, C.BYTES.bytes(12));
      return dd;
    }
    var dd64 = Buffer.alloc(C.BYTES.bytes(24));
    dd64.writeUInt32LE(SIG_DATA_DESCRIPTOR, C.BYTES.bytes(0));
    dd64.writeUInt32LE(crc, C.BYTES.bytes(4));
    dd64.writeBigUInt64LE(BigInt(csize), C.BYTES.bytes(0x08));
    dd64.writeBigUInt64LE(BigInt(usize), C.BYTES.bytes(0x10));
    return dd64;
  }

  function _buildCentralDirectoryEntry(entry, lfhOffset) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var flags = FLAG_UTF8_NAME | (entry.kind === "stream" ? FLAG_DATA_DESCRIPTOR : 0);
    var csize = entry.stored.length;
    var usize = entry.uncompressedSize;
    var zip64 = _entryNeedsZip64(csize, usize, lfhOffset);
    var zip64Extra = zip64 ? _buildZip64Extra(csize, usize, lfhOffset, true) : Buffer.alloc(0);
    var hdr = Buffer.alloc(C.BYTES.bytes(46));
    hdr.writeUInt32LE(SIG_CFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(0x033f, C.BYTES.bytes(4));
    hdr.writeUInt16LE(zip64 ? ZIP64_VERSION_NEEDED : 20, C.BYTES.bytes(6));
    hdr.writeUInt16LE(flags, C.BYTES.bytes(0x08));
    hdr.writeUInt16LE(entry.method, C.BYTES.bytes(10));
    hdr.writeUInt16LE(dt.time, C.BYTES.bytes(12));
    hdr.writeUInt16LE(dt.date, C.BYTES.bytes(14));
    hdr.writeUInt32LE(entry.crc, C.BYTES.bytes(0x10));
    hdr.writeUInt32LE(_overflows32(csize) ? ZIP64_U32_SENTINEL : csize, C.BYTES.bytes(20));
    hdr.writeUInt32LE(_overflows32(usize) ? ZIP64_U32_SENTINEL : usize, C.BYTES.bytes(0x18));
    hdr.writeUInt16LE(nameBuf.length, C.BYTES.bytes(28));
    hdr.writeUInt16LE(zip64Extra.length, C.BYTES.bytes(30));
    hdr.writeUInt16LE(0, C.BYTES.bytes(0x20));
    hdr.writeUInt16LE(0, C.BYTES.bytes(34));
    hdr.writeUInt16LE(0, C.BYTES.bytes(36));
    hdr.writeUInt32LE(0, C.BYTES.bytes(38));
    hdr.writeUInt32LE(_overflows32(lfhOffset) ? ZIP64_U32_SENTINEL : lfhOffset, C.BYTES.bytes(42));
    return Buffer.concat([hdr, nameBuf, zip64Extra]);
  }

  function _buildEndOfCentralDirectory(totalEntries, cdSize, cdStart) {
    var needZip64 = totalEntries > ZIP64_MAX_CLASSIC_ENTRIES ||
      _overflows32(cdSize) || _overflows32(cdStart);
    if (!needZip64) {
      var eocdClassic = Buffer.alloc(C.BYTES.bytes(22));
      eocdClassic.writeUInt32LE(SIG_EOCD, C.BYTES.bytes(0));
      eocdClassic.writeUInt16LE(0, C.BYTES.bytes(4));
      eocdClassic.writeUInt16LE(0, C.BYTES.bytes(6));
      eocdClassic.writeUInt16LE(totalEntries, C.BYTES.bytes(0x08));
      eocdClassic.writeUInt16LE(totalEntries, C.BYTES.bytes(10));
      eocdClassic.writeUInt32LE(cdSize, C.BYTES.bytes(12));
      eocdClassic.writeUInt32LE(cdStart, C.BYTES.bytes(0x10));
      eocdClassic.writeUInt16LE(0, C.BYTES.bytes(20));
      return eocdClassic;
    }
    var eocd64 = Buffer.alloc(C.BYTES.bytes(ZIP64_EOCD64_BYTES));
    eocd64.writeUInt32LE(SIG_EOCD64, C.BYTES.bytes(0));
    eocd64.writeBigUInt64LE(BigInt(ZIP64_EOCD64_BYTES - 12), C.BYTES.bytes(4));
    eocd64.writeUInt16LE(0x033f, C.BYTES.bytes(12));
    eocd64.writeUInt16LE(ZIP64_VERSION_NEEDED, C.BYTES.bytes(14));
    eocd64.writeUInt32LE(0, C.BYTES.bytes(16));
    eocd64.writeUInt32LE(0, C.BYTES.bytes(20));
    eocd64.writeBigUInt64LE(BigInt(totalEntries), C.BYTES.bytes(24));
    eocd64.writeBigUInt64LE(BigInt(totalEntries), C.BYTES.bytes(32));
    eocd64.writeBigUInt64LE(BigInt(cdSize), C.BYTES.bytes(40));
    eocd64.writeBigUInt64LE(BigInt(cdStart), C.BYTES.bytes(48));
    var eocd64Offset = cdStart + cdSize;
    var locator = Buffer.alloc(C.BYTES.bytes(ZIP64_EOCD64_LOCATOR_BYTES));
    locator.writeUInt32LE(SIG_EOCD64_LOCATOR, C.BYTES.bytes(0));
    locator.writeUInt32LE(0, C.BYTES.bytes(4));
    locator.writeBigUInt64LE(BigInt(eocd64Offset), C.BYTES.bytes(0x08));
    locator.writeUInt32LE(1, C.BYTES.bytes(16));
    var eocd = Buffer.alloc(C.BYTES.bytes(22));
    eocd.writeUInt32LE(SIG_EOCD, C.BYTES.bytes(0));
    eocd.writeUInt16LE(0, C.BYTES.bytes(4));
    eocd.writeUInt16LE(0, C.BYTES.bytes(6));
    eocd.writeUInt16LE(totalEntries > ZIP64_MAX_CLASSIC_ENTRIES
      ? ZIP64_U16_SENTINEL : totalEntries, C.BYTES.bytes(0x08));
    eocd.writeUInt16LE(totalEntries > ZIP64_MAX_CLASSIC_ENTRIES
      ? ZIP64_U16_SENTINEL : totalEntries, C.BYTES.bytes(10));
    eocd.writeUInt32LE(_overflows32(cdSize) ? ZIP64_U32_SENTINEL : cdSize, C.BYTES.bytes(12));
    eocd.writeUInt32LE(_overflows32(cdStart) ? ZIP64_U32_SENTINEL : cdStart, C.BYTES.bytes(0x10));
    eocd.writeUInt16LE(0, C.BYTES.bytes(20));
    return Buffer.concat([eocd64, locator, eocd]);
  }

  function toBuffer() {
    for (var k = 0; k < entries.length; k++) {
      if (entries[k].kind === "stream") {
        throw new ArchiveError("archive/streaming-entry",
          "toBuffer cannot finalize streaming entry " + JSON.stringify(entries[k].name) +
          "; use archive.toStream(writable) for archives containing Readable sources");
      }
    }
    var pieces = [];
    var offsets = [];
    var totalLocalBytes = 0;
    for (var i = 0; i < entries.length; i++) {
      offsets.push(totalLocalBytes);
      var lfh = _buildLocalFileHeader(entries[i]);
      pieces.push(lfh);
      pieces.push(entries[i].stored);
      totalLocalBytes += lfh.length + entries[i].stored.length;
    }
    var cdStart = totalLocalBytes;
    var cdSize = 0;
    for (var j = 0; j < entries.length; j++) {
      var cdh = _buildCentralDirectoryEntry(entries[j], offsets[j]);
      pieces.push(cdh);
      cdSize += cdh.length;
    }
    pieces.push(_buildEndOfCentralDirectory(entries.length, cdSize, cdStart));
    return Buffer.concat(pieces);
  }

  function writeTo(filepath) {
    var buf = toBuffer();
    atomicFile.writeSync(filepath, buf, { fileMode: 0o600 });
    return buf.length;
  }

  var _emitAudit = auditEmit.emitToSink;

  function _writeChunk(writable, chunk) {
    return safeAsync.writeChunk(writable, chunk);
  }

  async function _streamEntry(entry, writable) {
    var lfh = _buildLocalFileHeader(entry, { streaming: true });
    await _writeChunk(writable, lfh);

    var crc = 0xffffffff;
    var usize = 0;
    var csize = 0;
    var method = entry.method;

    function _crcChunk(chunk) {
      for (var i = 0; i < chunk.length; i++) {
        crc = CRC32_TABLE[(crc ^ chunk[i]) & 0xff] ^ (crc >>> 8);
      }
    }

    var crcTap = new nodeStream.Transform({
      transform: function (chunk, enc, cb) {
        usize += chunk.length;
        _crcChunk(chunk);
        cb(null, chunk);
      },
    });

    if (method === METHOD_DEFLATE_ID) {
      var deflater = zlib.createDeflateRaw();
      var sinkWritable = new nodeStream.Writable({
        write: function (chunk, enc, cb) {
          csize += chunk.length;
          safeAsync.writeChunk(writable, chunk).then(function () { cb(); }, cb);
        },
      });
      try {
        await streamPromises.pipeline(entry.source, crcTap, deflater, sinkWritable);
      } catch (e) {
        throw new ArchiveError("archive/source-error",
          "stream entry " + JSON.stringify(entry.name) + " failed: " + (e && e.message));
      }
    } else {
      var storeCollect = new nodeStream.Writable({
        write: function (chunk, enc, cb) {
          csize += chunk.length;
          safeAsync.writeChunk(writable, chunk).then(function () { cb(); }, cb);
        },
      });
      try {
        await streamPromises.pipeline(entry.source, crcTap, storeCollect);
      } catch (e) {
        throw new ArchiveError("archive/source-error",
          "stream entry " + JSON.stringify(entry.name) + " failed: " + (e && e.message));
      }
    }

    crc = (crc ^ 0xffffffff) >>> 0;
    var dd = _buildDataDescriptor(crc, csize, usize);
    await _writeChunk(writable, dd);

    entry.crc = crc;
    entry.stored = { length: csize };
    entry.uncompressedSize = usize;

    return lfh.length + csize + dd.length;
  }

  async function toStream(writable, opts) {
    opts = opts || {};
    var returnReadable = !writable;
    var dest = writable;
    if (returnReadable) {
      dest = new nodeStream.PassThrough();
    } else if (typeof writable.write !== "function") {
      throw new ArchiveError("archive/bad-writable",
        "toStream: writable must be a Writable (or omit to receive a Readable)");
    }

    var run = (async function () {
      var offsets = [];
      var totalLocalBytes = 0;
      try {
        for (var i = 0; i < entries.length; i++) {
          offsets.push(totalLocalBytes);
          var entry = entries[i];
          if (entry.kind === "stream") {
            totalLocalBytes += await _streamEntry(entry, dest);
          } else {
            var lfh = _buildLocalFileHeader(entry);
            await _writeChunk(dest, lfh);
            await _writeChunk(dest, entry.stored);
            totalLocalBytes += lfh.length + entry.stored.length;
          }
        }
        var cdStart = totalLocalBytes;
        var cdSize = 0;
        for (var j = 0; j < entries.length; j++) {
          var cdh = _buildCentralDirectoryEntry(entries[j], offsets[j]);
          await _writeChunk(dest, cdh);
          cdSize += cdh.length;
        }
        var eocd = _buildEndOfCentralDirectory(entries.length, cdSize, cdStart);
        await _writeChunk(dest, eocd);
        if (typeof dest.end === "function") dest.end();
        _emitAudit(opts, "archive.zip.streamed.completed", "success", {
          entries: entries.length,
          bytes:   totalLocalBytes + cdSize + eocd.length,
        });
      } catch (e) {
        _emitAudit(opts, "archive.zip.streamed.aborted", "failure", {
          entries: entries.length,
          error:   e && (e.code || e.message) || String(e),
        });
        if (typeof dest.destroy === "function") {
          dest.destroy(e instanceof ArchiveError ? e : new ArchiveError(
            "archive/aborted", "archive stream aborted: " + (e && e.message || e)));
        }
        if (!returnReadable) throw e;
      }
    })();

    if (returnReadable) {
      run.catch(function () { /* already routed via dest.destroy */ });
      return dest;
    }
    await run;
    return undefined;
  }

  function digest() {
    return nodeCrypto.createHash("sha3-512").update(toBuffer()).digest("hex");
  }

  return {
    addFile:    addFile,
    toBuffer:   toBuffer,
    toStream:   toStream,
    writeTo:    writeTo,
    digest:     digest,
    get entryCount() { return entries.length; },
  };
}

var archiveRead = require("./archive-read");
var archiveTar = require("./archive-tar");
var archiveTarRead = require("./archive-tar-read");
var archiveGz = require("./archive-gz");
var archiveWrap = require("./archive-wrap");

module.exports = {
  zip:                  zip,
  tar:                  archiveTar.tar,
  gz:                   archiveGz.gz,
  wrap:                 archiveWrap.wrap,
  unwrap:               archiveWrap.unwrap,
  rewrapTenant:         archiveWrap.rewrapTenant,
  wrapWithPassphrase:   archiveWrap.wrapWithPassphrase,
  unwrapWithPassphrase: archiveWrap.unwrapWithPassphrase,
  sniffEnvelope:        archiveWrap.sniffEnvelope,
  ArchiveError:      ArchiveError,
  TarError:          archiveTar.TarError,
  ArchiveGzError:    archiveGz.ArchiveGzError,
  ArchiveWrapError:  archiveWrap.ArchiveWrapError,
  read: {
    zip:                 archiveRead.zip,
    tar:                 archiveTarRead.tar,
    gz:                  archiveGz.read.gz,
    fromGzip:            archiveGz.read.gz,
    ArchiveReadError:    archiveRead.ArchiveReadError,
    DEFAULT_BOMB_POLICY: archiveRead.DEFAULT_BOMB_POLICY,
    DEFAULT_ENTRY_TYPE_POLICY: archiveRead.DEFAULT_ENTRY_TYPE_POLICY,
  },
  _crc32ForTest: _crc32,
  _zip64ForTest: {
    entryNeedsZip64: _entryNeedsZip64,
    buildExtra:      _buildZip64Extra,
    U16_SENTINEL:    ZIP64_U16_SENTINEL,
    U32_SENTINEL:    ZIP64_U32_SENTINEL,
    U32_MAX:         ZIP64_U32_MAX,
    EXTRA_HEADER_ID: ZIP64_EXTRA_HEADER_ID,
  },
};
