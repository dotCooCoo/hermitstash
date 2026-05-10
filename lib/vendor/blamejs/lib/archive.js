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
 *
 *   Out of scope (v1):
 *     - ZIP64 (>4 GiB archives, >65535 files) — `toBuffer` and
 *       `toStream` throw `archive/too-many-entries` past the limit;
 *       operators at that scale bring their own toolset.
 *     - ZIP-native password encryption (broken-by-design); operators
 *       wrap the produced bytes via `b.crypto.encryptPacked` for
 *       encryption-at-rest.
 *     - Reading / extraction — write-only; operators use yauzl or
 *       `unzip` for read paths.
 *
 * @card
 *   ZIP archive creation primitive.
 */
var zlib = require("node:zlib");
var fs   = require("node:fs");
var nodeCrypto = require("node:crypto");
var stream = require("node:stream");
var streamPromises = require("node:stream/promises");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var ArchiveError = defineClass("ArchiveError", { alwaysPermanent: true });

// ZIP signatures (APPNOTE 4.3 — file-format-fixed magic dwords)
var SIG_LFH = 0x04034b50;   // local file header
var SIG_CFH = 0x02014b50;   // central directory file header
var SIG_EOCD = 0x06054b50;  // end of central directory

// Compression methods (APPNOTE 4.4.5 — protocol-fixed method IDs)
var METHOD_STORE_ID   = 0;
var METHOD_DEFLATE_ID = 8;

// CRC-32 — IEEE 802.3 polynomial. node:crypto has no native CRC32, so
// we vendor the standard table-driven implementation.
var CRC32_TABLE_LEN = 256;   // entries (one per byte value)
var CRC32_BIT_ITER  = 8;     // bits per byte during table build
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

// MS-DOS date/time encoding — APPNOTE 4.4.6
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
    // No path traversal — relative paths only, no leading slash, no ".." segments.
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
    // Duck-type: Readable instance or any object exposing .pipe + .on +
    // a `readable` flag / readableState. Avoids importing every consumer's
    // stream class; matches Node's own stream-detection pattern.
    return !!o && (o instanceof stream.Readable ||
      (typeof o.pipe === "function" && typeof o.on === "function"));
  }

  function addFile(name, content, opts) {
    var normalized = _normalizeName(name);
    opts = opts || {};
    var method = opts.method === "store" ? METHOD_STORE_ID : METHOD_DEFLATE_ID;
    var mtime = opts.mtime instanceof Date ? opts.mtime : new Date();

    if (_isReadableStream(content)) {
      // Streaming entry — content is finalized at toStream() time. CRC,
      // sizes, and method-fallback-to-STORE are computed during the pipe.
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
      // If deflate didn't shrink it (small/already-compressed inputs),
      // fall back to STORE to save the operator a few bytes.
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

  // FLAG_DATA_DESCRIPTOR — APPNOTE 4.4.4 bit 3. Set when crc / csize /
  // usize are not known at LFH-write time and a 16-byte descriptor
  // follows the compressed data.
  var FLAG_UTF8_NAME = 0x0800;
  var FLAG_DATA_DESCRIPTOR = 0x0008;
  var SIG_DATA_DESCRIPTOR = 0x08074b50;   // optional but conventional

  function _buildLocalFileHeader(entry, opts) {
    var streaming = !!(opts && opts.streaming);
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var flags = FLAG_UTF8_NAME | (streaming ? FLAG_DATA_DESCRIPTOR : 0);
    // APPNOTE 4.3.7 — local file header. Offsets are byte positions
    // within the 30-byte fixed header; each route through C.BYTES.bytes
    // so the framework's byte-math discipline applies even to format-
    // fixed offsets.
    var hdr = Buffer.alloc(C.BYTES.bytes(30));
    hdr.writeUInt32LE(SIG_LFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(20, C.BYTES.bytes(4));            // version needed
    hdr.writeUInt16LE(flags, C.BYTES.bytes(6));         // flags: bit 11 UTF-8, bit 3 data-descriptor
    hdr.writeUInt16LE(entry.method, C.BYTES.bytes(0x08));
    hdr.writeUInt16LE(dt.time, C.BYTES.bytes(10));
    hdr.writeUInt16LE(dt.date, C.BYTES.bytes(12));
    hdr.writeUInt32LE(streaming ? 0 : entry.crc, C.BYTES.bytes(14));
    hdr.writeUInt32LE(streaming ? 0 : entry.stored.length, C.BYTES.bytes(18));
    hdr.writeUInt32LE(streaming ? 0 : entry.uncompressedSize, C.BYTES.bytes(22));
    hdr.writeUInt16LE(nameBuf.length, C.BYTES.bytes(26));
    hdr.writeUInt16LE(0, C.BYTES.bytes(28));            // extra field length
    return Buffer.concat([hdr, nameBuf]);
  }

  function _buildDataDescriptor(crc, csize, usize) {
    // APPNOTE 4.3.9 — 16-byte data descriptor (with optional sig dword).
    var dd = Buffer.alloc(C.BYTES.bytes(16));
    dd.writeUInt32LE(SIG_DATA_DESCRIPTOR, C.BYTES.bytes(0));
    dd.writeUInt32LE(crc, C.BYTES.bytes(4));
    dd.writeUInt32LE(csize, C.BYTES.bytes(0x08));
    dd.writeUInt32LE(usize, C.BYTES.bytes(12));
    return dd;
  }

  function _buildCentralDirectoryEntry(entry, lfhOffset) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var flags = FLAG_UTF8_NAME | (entry.kind === "stream" ? FLAG_DATA_DESCRIPTOR : 0);
    // APPNOTE 4.3.12 — central directory file header (46-byte fixed prefix).
    var hdr = Buffer.alloc(C.BYTES.bytes(46));
    hdr.writeUInt32LE(SIG_CFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(0x033f, C.BYTES.bytes(4));        // version made by (UNIX | 6.3)
    hdr.writeUInt16LE(20, C.BYTES.bytes(6));            // version needed
    hdr.writeUInt16LE(flags, C.BYTES.bytes(0x08));      // flags: bit 11 UTF-8, bit 3 data-descriptor (stream)
    hdr.writeUInt16LE(entry.method, C.BYTES.bytes(10));
    hdr.writeUInt16LE(dt.time, C.BYTES.bytes(12));
    hdr.writeUInt16LE(dt.date, C.BYTES.bytes(14));
    hdr.writeUInt32LE(entry.crc, C.BYTES.bytes(0x10));
    hdr.writeUInt32LE(entry.stored.length, C.BYTES.bytes(20));
    hdr.writeUInt32LE(entry.uncompressedSize, C.BYTES.bytes(0x18));
    hdr.writeUInt16LE(nameBuf.length, C.BYTES.bytes(28));
    hdr.writeUInt16LE(0, C.BYTES.bytes(30));            // extra field length
    hdr.writeUInt16LE(0, C.BYTES.bytes(0x20));          // file comment length
    hdr.writeUInt16LE(0, C.BYTES.bytes(34));            // disk number start
    hdr.writeUInt16LE(0, C.BYTES.bytes(36));            // internal file attributes
    hdr.writeUInt32LE(0, C.BYTES.bytes(38));            // external file attributes
    hdr.writeUInt32LE(lfhOffset, C.BYTES.bytes(42));
    return Buffer.concat([hdr, nameBuf]);
  }

  function toBuffer() {
    if (entries.length > 65535) {
      throw new ArchiveError("archive/too-many-entries",
        "ZIP archive cannot contain more than 65535 entries (ZIP64 unsupported in v1)");
    }
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
    // APPNOTE 4.3.16 — end of central directory record (22-byte fixed).
    var eocd = Buffer.alloc(C.BYTES.bytes(22));
    eocd.writeUInt32LE(SIG_EOCD, C.BYTES.bytes(0));
    eocd.writeUInt16LE(0, C.BYTES.bytes(4));                    // disk number
    eocd.writeUInt16LE(0, C.BYTES.bytes(6));                    // disk where CD starts
    eocd.writeUInt16LE(entries.length, C.BYTES.bytes(0x08));    // entries on this disk
    eocd.writeUInt16LE(entries.length, C.BYTES.bytes(10));      // total entries
    eocd.writeUInt32LE(cdSize, C.BYTES.bytes(12));              // size of central directory
    eocd.writeUInt32LE(cdStart, C.BYTES.bytes(0x10));           // offset of central directory
    eocd.writeUInt16LE(0, C.BYTES.bytes(20));                   // comment length
    pieces.push(eocd);
    return Buffer.concat(pieces);
  }

  function writeTo(filepath) {
    var buf = toBuffer();
    fs.writeFileSync(filepath, buf);
    return buf.length;
  }

  function _emitAudit(opts, action, outcome, metadata) {
    if (!opts || !opts.audit || typeof opts.audit.safeEmit !== "function") return;
    try {
      opts.audit.safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: metadata,
      });
    } catch (_e) { /* drop-silent — audit sinks must never crash the producer */ }
  }

  function _writeChunk(writable, chunk) {
    return new Promise(function (resolve, reject) {
      function onError(e) {
        writable.removeListener("drain", onDrain);
        reject(e);
      }
      function onDrain() {
        writable.removeListener("error", onError);
        resolve();
      }
      var ok = writable.write(chunk);
      if (ok) {
        // Already flushed — no need to wait for drain.
        resolve();
        return;
      }
      writable.once("drain", onDrain);
      writable.once("error", onError);
    });
  }

  async function _streamEntry(entry, writable) {
    var lfh = _buildLocalFileHeader(entry, { streaming: true });
    await _writeChunk(writable, lfh);

    var crc = 0xffffffff;
    var usize = 0;
    var csize = 0;
    var method = entry.method;

    // Per-byte CRC table walk reused from _crc32 (kept inline here so
    // we operate on Buffer chunks rather than allocating a full body).
    function _crcChunk(chunk) {
      for (var i = 0; i < chunk.length; i++) {
        crc = CRC32_TABLE[(crc ^ chunk[i]) & 0xff] ^ (crc >>> 8);
      }
    }

    // CRC tap — a passthrough Transform that observes uncompressed bytes
    // and updates usize / CRC before forwarding to the next stage. Avoids
    // consuming the source twice via parallel listeners.
    var crcTap = new stream.Transform({
      transform: function (chunk, enc, cb) {
        usize += chunk.length;
        _crcChunk(chunk);
        cb(null, chunk);
      },
    });

    if (method === METHOD_DEFLATE_ID) {
      var deflater = zlib.createDeflateRaw();
      // Pipe source -> crcTap -> deflater -> writable directly. CRC is
      // computed on uncompressed bytes via the tap. Atomicity is held by
      // the central-directory-after-all-entries pattern: partial bytes
      // may leak to dest on failure, but no EOCD is ever written, so
      // consumers see a broken stream rather than a half-archive that
      // pretends to be complete.
      var sinkWritable = new stream.Writable({
        write: function (chunk, enc, cb) {
          csize += chunk.length;
          var ok = writable.write(chunk);
          if (ok) cb();
          else writable.once("drain", function () { cb(); });
        },
      });
      try {
        await streamPromises.pipeline(entry.source, crcTap, deflater, sinkWritable);
      } catch (e) {
        throw new ArchiveError("archive/source-error",
          "stream entry " + JSON.stringify(entry.name) + " failed: " + (e && e.message));
      }
    } else {
      // STORE: pipe source -> crcTap -> writable. csize === usize.
      var storeCollect = new stream.Writable({
        write: function (chunk, enc, cb) {
          csize += chunk.length;
          var ok = writable.write(chunk);
          if (ok) cb();
          else writable.once("drain", function () { cb(); });
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

    // Mutate entry with finalized values so the central-directory
    // build pass writes correct sizes/crc.
    entry.crc = crc;
    entry.stored = { length: csize };               // CDH only reads .length
    entry.uncompressedSize = usize;

    return lfh.length + csize + dd.length;
  }

  async function toStream(writable, opts) {
    opts = opts || {};
    var returnReadable = !writable;
    var dest = writable;
    if (returnReadable) {
      dest = new stream.PassThrough();
    } else if (typeof writable.write !== "function") {
      throw new ArchiveError("archive/bad-writable",
        "toStream: writable must be a Writable (or omit to receive a Readable)");
    }

    if (entries.length > 65535) {
      throw new ArchiveError("archive/too-many-entries",
        "ZIP archive cannot contain more than 65535 entries (ZIP64 unsupported in v1)");
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
        // Atomic finalize — central directory only after every entry succeeded.
        var cdStart = totalLocalBytes;
        var cdSize = 0;
        for (var j = 0; j < entries.length; j++) {
          var cdh = _buildCentralDirectoryEntry(entries[j], offsets[j]);
          await _writeChunk(dest, cdh);
          cdSize += cdh.length;
        }
        var eocd = Buffer.alloc(C.BYTES.bytes(22));
        eocd.writeUInt32LE(SIG_EOCD, C.BYTES.bytes(0));
        eocd.writeUInt16LE(0, C.BYTES.bytes(4));
        eocd.writeUInt16LE(0, C.BYTES.bytes(6));
        eocd.writeUInt16LE(entries.length, C.BYTES.bytes(0x08));
        eocd.writeUInt16LE(entries.length, C.BYTES.bytes(10));
        eocd.writeUInt32LE(cdSize, C.BYTES.bytes(12));
        eocd.writeUInt32LE(cdStart, C.BYTES.bytes(0x10));
        eocd.writeUInt16LE(0, C.BYTES.bytes(20));
        await _writeChunk(dest, eocd);
        if (typeof dest.end === "function") dest.end();
        _emitAudit(opts, "archive.zip.streamed.completed", "success", {
          entries: entries.length,
          bytes:   totalLocalBytes + cdSize + eocd.length,
        });
      } catch (e) {
        // Aborted — destroy the destination so partial output is not
        // mistaken for a complete archive (no central directory written).
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
      // Operator gets a Readable; surface stream errors via the
      // PassThrough's 'error' event (run() does not throw in that path).
      run.catch(function () { /* already routed via dest.destroy */ });
      return dest;
    }
    await run;
    return undefined;
  }

  function digest() {
    // SHA3-512 of the produced archive bytes — useful for operator-side
    // integrity logging on exported bundles. Matches the framework's
    // PQC-first hash posture; operators reconciling against an external
    // SHA-256 can hash the bytes themselves.
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

module.exports = {
  zip:           zip,
  ArchiveError:  ArchiveError,
  // Test-only export — operators don't call this; it's here for unit-testing
  // the CRC implementation against known vectors.
  _crc32ForTest: _crc32,
};
