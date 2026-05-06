"use strict";
/**
 * archive — ZIP creation. Operator-data-export shape ("download my
 * data as a zip"), log archives, plain-zip exports for users.
 *
 *   var archive = b.archive.zip();
 *   archive.addFile("readme.txt",     "Hello\n");
 *   archive.addFile("data/users.csv", csvBytes, { method: "deflate" });
 *   archive.addFile("avatars/me.png", pngBuf,   { method: "store" });   // already-compressed
 *   var zipBytes = archive.toBuffer();
 *
 *   // OR write directly to disk:
 *   archive.writeTo("/tmp/export.zip");
 *
 * Format support:
 *   - Stored (no compression — for already-compressed inputs like
 *     PNG / JPEG / mp4)
 *   - Deflate via node:zlib's deflateRawSync (default for everything else)
 *   - File names with / are honored — directory entries are implicit;
 *     extractors create the directory structure on demand
 *   - UTF-8 file names (sets the EFS bit per APPNOTE 6.3.4)
 *   - Modification time defaults to "now"; operators override per file
 *
 * Out of scope:
 *   - ZIP64 (>4 GiB archives, >65535 files) — operators at that scale
 *     bring their own toolset
 *   - Encryption — `b.crypto.encryptPacked` produces a sealed bundle
 *     for the operator's encryption-at-rest needs; ZIP-native
 *     password encryption is broken-by-design
 *   - Streaming write (toStream) — toBuffer() covers the "download my
 *     data" shape; operators streaming gigabytes use the operator-side
 *     toolset
 *   - Reading / extraction — write-only; operators use node:zlib +
 *     yauzl (or unzip in shell) for read paths
 */
var zlib = require("node:zlib");
var fs   = require("node:fs");
var nodeCrypto = require("node:crypto");
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

function zip() {
  var entries = [];

  function addFile(name, content, opts) {
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
    var bodyBuf;
    if (Buffer.isBuffer(content)) bodyBuf = content;
    else if (typeof content === "string") bodyBuf = Buffer.from(content, "utf8");
    else throw new ArchiveError("archive/bad-content",
      "addFile: content must be a Buffer or string, got " + typeof content);

    opts = opts || {};
    var method = opts.method === "store" ? METHOD_STORE_ID : METHOD_DEFLATE_ID;
    var mtime = opts.mtime instanceof Date ? opts.mtime : new Date();

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
    });
  }

  function _buildLocalFileHeader(entry) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    // APPNOTE 4.3.7 — local file header. Offsets are byte positions
    // within the 30-byte fixed header; each route through C.BYTES.bytes
    // so the framework's byte-math discipline applies even to format-
    // fixed offsets.
    var hdr = Buffer.alloc(C.BYTES.bytes(30));
    hdr.writeUInt32LE(SIG_LFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(20, C.BYTES.bytes(4));            // version needed
    hdr.writeUInt16LE(0x0800, C.BYTES.bytes(6));        // flags: bit 11 = UTF-8 name
    hdr.writeUInt16LE(entry.method, C.BYTES.bytes(0x08));
    hdr.writeUInt16LE(dt.time, C.BYTES.bytes(10));
    hdr.writeUInt16LE(dt.date, C.BYTES.bytes(12));
    hdr.writeUInt32LE(entry.crc, C.BYTES.bytes(14));
    hdr.writeUInt32LE(entry.stored.length, C.BYTES.bytes(18));
    hdr.writeUInt32LE(entry.uncompressedSize, C.BYTES.bytes(22));
    hdr.writeUInt16LE(nameBuf.length, C.BYTES.bytes(26));
    hdr.writeUInt16LE(0, C.BYTES.bytes(28));            // extra field length
    return Buffer.concat([hdr, nameBuf]);
  }

  function _buildCentralDirectoryEntry(entry, lfhOffset) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    // APPNOTE 4.3.12 — central directory file header (46-byte fixed prefix).
    var hdr = Buffer.alloc(C.BYTES.bytes(46));
    hdr.writeUInt32LE(SIG_CFH, C.BYTES.bytes(0));
    hdr.writeUInt16LE(0x033f, C.BYTES.bytes(4));        // version made by (UNIX | 6.3)
    hdr.writeUInt16LE(20, C.BYTES.bytes(6));            // version needed
    hdr.writeUInt16LE(0x0800, C.BYTES.bytes(0x08));     // flags: bit 11 = UTF-8
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
