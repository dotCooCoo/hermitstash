"use strict";
/**
 * archive-tar — POSIX pax tar write + read. Sibling of lib/archive.js
 * the way lib/archive-read.js is — the `b.archive.tar` and
 * `b.archive.read.tar` primitives both live in the `b.archive`
 * namespace declared in lib/archive.js; this file just carries the
 * tar-format wire-format implementation.
 *
 * POSIX pax tar format — second archive format in the family, sits
 * alongside `b.archive.zip` (write-only ZIP) + `b.archive.read.zip`
 * (read-side ZIP, v0.12.7).
 *
 *   Two output paths mirror the ZIP write side:
 *     - `toBuffer()` — whole archive in memory.
 *     - `toStream(writable)` — block-by-block streaming.
 *     - `toAdapter(adapter)` — write through the v0.12.7 adapter contract.
 *
 *   Two input paths for read:
 *     - `b.archive.read.tar(adapter)` — random-access OR sequential.
 *       Tar has no central directory, so sequential header-by-header
 *       walk IS the canonical adversarial-safe path. Trusted-stream
 *       adapters are first-class here (unlike ZIP read where they
 *       carry a documented trust boundary).
 *     - `b.archive.adapters.trustedStream(readable)` — preferred for
 *       multi-gibibyte tar streams that don't fit in memory.
 *
 *   Format guarantees:
 *     - ustar magic + version "00" at byte offset 257 of every header.
 *     - Names ≤ 100 chars + sizes ≤ 8 GiB fit in the fixed ustar header.
 *     - Longer names + larger sizes get a pax extended header (POSIX.1-
 *       2001 §4.18) preceding the entry: "len key=value\n" records.
 *     - Two zero blocks (1024 bytes) terminate the archive.
 *     - Path-traversal refused at `addFile` (mirrors ZIP write).
 *     - Deterministic insertion order; deterministic mtime opt-in.
 *
 *   Entry-type policy (typeflag handling on read):
 *     - 0 / '\0' (regular file): extract.
 *     - 5 (directory): extract (mkdir -p).
 *     - 1 (hardlink): refused by default; `allowDangerous: { hardlinks:
 *       true }` opt-in routes link target through
 *       `b.guardFilename.verifyExtractionPath`.
 *     - 2 (symlink): same as hardlink — refused by default; opt-in
 *       with realpath-on-target check.
 *     - 3 / 4 / 6 / 7 (char-device / block-device / FIFO / contiguous):
 *       refused unconditionally — no use case in application archives.
 *     - x (pax extended header): consumed by reader; merged into next
 *       entry's metadata.
 *     - g (pax global header): consumed; applies to all following.
 *
 *   Defends:
 *     - CVE-2026-23745 / CVE-2026-24842 (node-tar symlink+hardlink
 *       path-resolution divergence between safety check + creation).
 *     - CVE-2025-4517 PATH_MAX TOCTOU (carries v0.12.7's
 *       `verifyExtractionPath` dual-check).
 *     - CVE-2025-11001 / 11002 (7-Zip symlink TOCTOU on extract).
 *     - CVE-2024-12905 / CVE-2025-48387 (tar-fs path traversal).
 *     - CVE-2025-4138 / 4330 (Python tarfile data filter bypass).
 *
 *   Compression is via `b.archive.gz` composition (tar.gz). Out of scope
 *   (v1):
 *     - Sparse-file emission (read reconstructs them; write doesn't
 *       produce sparse).
 *     - BSD-tar extensions beyond pax.
 *
 * @card
 *   POSIX pax tar archive — write + read with the same defense surface as the ZIP family.
 */

var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var TarError = defineClass("TarError", { alwaysPermanent: true });

void streamPromises; void nodeStream;

// Lazy because archive-gz lazy-imports archive-tar-read (sibling read
// module) — a top-of-file `require("./archive-gz")` would create a
// load-order cycle that depends on file-walk order.
var archiveGz = lazyRequire(function () { return require("./archive-gz"); });

// ---- Wire-format constants -----------------------------------------------

var BLOCK_SIZE = C.BYTES.bytes(512);     // tar block size (POSIX)
var USTAR_MAGIC = "ustar\u0000";          // 6 bytes including the trailing NUL
var USTAR_VERSION = "00";                 // 2 bytes
var NAME_MAX = C.BYTES.bytes(100);        // ustar name field cap
var PREFIX_MAX = C.BYTES.bytes(155);      // ustar prefix field cap
var LINKNAME_MAX = C.BYTES.bytes(100);    // ustar linkname field cap
var USTAR_SIZE_MAX = 0o77777777777;       // 11 octal digits = 8 GiB - 1 per ustar size-field width

// Header field byte offsets (POSIX.1-1988 ustar; same in POSIX.1-2001 pax)
var H_NAME = C.BYTES.bytes(0);
var H_MODE = C.BYTES.bytes(100);
var H_UID = C.BYTES.bytes(108);
var H_GID = C.BYTES.bytes(116);
var H_SIZE = C.BYTES.bytes(124);
var H_MTIME = C.BYTES.bytes(136);
var H_CHKSUM = C.BYTES.bytes(148);
var H_TYPEFLAG = C.BYTES.bytes(156);
var H_LINKNAME = C.BYTES.bytes(157);
var H_MAGIC = C.BYTES.bytes(257);
var H_VERSION = C.BYTES.bytes(263);
var H_UNAME = C.BYTES.bytes(265);
var H_GNAME = C.BYTES.bytes(297);
var H_DEVMAJOR = C.BYTES.bytes(329);
var H_DEVMINOR = C.BYTES.bytes(337);
var H_PREFIX = C.BYTES.bytes(345);

// Field widths
var W_MODE = C.BYTES.bytes(8);
var W_UID = C.BYTES.bytes(8);
var W_GID = C.BYTES.bytes(8);
var W_SIZE = C.BYTES.bytes(12);
var W_MTIME = C.BYTES.bytes(12);
var W_CHKSUM = C.BYTES.bytes(8);
var W_UNAME = C.BYTES.bytes(32);
var W_GNAME = C.BYTES.bytes(32);

// Typeflags — write side emits only TF_REGULAR / TF_DIRECTORY /
// TF_PAX_EXTENDED. The full POSIX typeflag set lives in
// lib/archive-tar-read.js (the reader has to classify every typeflag
// the wild produces). H_DEVMAJOR / H_DEVMINOR offsets stay for the
// shared _parseHeader call site even though the write side never
// emits typeflag 3/4 (char/block device) entries.
var TF_REGULAR = "0";
var TF_DIRECTORY = "5";
var TF_PAX_EXTENDED = "x";

void H_DEVMAJOR; void H_DEVMINOR;

// ---- Helpers -------------------------------------------------------------

function _padBlock(buf) {
  // Pad buf to the next 512-byte boundary with NUL bytes.
  var rem = buf.length % BLOCK_SIZE;
  if (rem === 0) return buf;
  var pad = Buffer.alloc(BLOCK_SIZE - rem);
  return Buffer.concat([buf, pad]);
}

function _writeOctal(buf, value, offset, width) {
  // ustar octal fields: 6-11 octal digits + space or NUL terminator.
  // For width=8, that's 7 octal digits + terminator. For width=12, 11
  // digits + terminator.
  var digits = width - 1;
  var oct = value.toString(8);                                                       // radix=8 for octal stringify per ustar field format
  if (oct.length > digits) {
    throw new TarError("archive-tar/octal-overflow",
      "value " + value + " (octal " + oct + ") exceeds field width " + digits);
  }
  // Left-pad with '0' to fill the digits.
  while (oct.length < digits) oct = "0" + oct;
  buf.write(oct, offset, digits, "ascii");
  buf.writeUInt8(0x20, offset + digits);     // ASCII space (' ') terminator per ustar
}

function _writeString(buf, value, offset, width) {
  // ASCII-encoded; truncated if longer than width. NUL terminates if
  // shorter than width.
  var ascii = String(value);
  var bytes = Buffer.from(ascii, "utf8");
  if (bytes.length > width) {
    throw new TarError("archive-tar/field-overflow",
      "string " + JSON.stringify(value) + " (" + bytes.length + " bytes) exceeds field width " + width);
  }
  bytes.copy(buf, offset);
  // Remaining bytes already NUL from Buffer.alloc.
}

function _readOctal(buf, offset, width) {
  // Read an octal-encoded field. Terminator may be space or NUL.
  var s = "";
  for (var i = 0; i < width; i += 1) {
    var c = buf[offset + i];
    if (c === 0x20 || c === 0) break;                                                // ASCII space (0x20) + NUL (0x00) field terminators
    if (c < 0x30 || c > 0x37) {                                                      // ASCII '0' (0x30) .. '7' (0x37) octal digits
      throw new TarError("archive-tar/bad-octal",
        "non-octal byte 0x" + c.toString(16) + " at offset " + (offset + i));        // radix=16 for diagnostic hex format
    }
    s += String.fromCharCode(c);
  }
  if (s.length === 0) return 0;
  return parseInt(s, 8);                                                             // radix=8 for octal parse per ustar field format
}

function _readString(buf, offset, width) {
  // Read NUL-terminated ASCII / UTF-8 from the field. Truncates at
  // the first NUL byte.
  var end = offset;
  var limit = offset + width;
  while (end < limit && buf[end] !== 0) end += 1;
  return buf.slice(offset, end).toString("utf8");
}

function _computeChecksum(buf) {
  // ustar checksum: sum of every byte in the 512-byte header, with the
  // chksum field itself treated as 8 spaces (0x20). Stored as 6 octal
  // digits + NUL + space (per the spec — historically GNU tar writes
  // it that way; modern parsers accept several variants).
  var sum = 0;
  for (var i = 0; i < BLOCK_SIZE; i += 1) {
    if (i >= H_CHKSUM && i < H_CHKSUM + W_CHKSUM) {
      sum += 0x20;                                                                   // chksum field treated as 8 spaces per POSIX.1-1988
    } else {
      sum += buf[i];
    }
  }
  return sum;
}

function _writeChecksum(buf) {
  // Write 6 octal digits + NUL + space into the chksum field.
  var sum = _computeChecksum(buf);
  var oct = sum.toString(8);                                                         // radix=8 for octal stringify per ustar chksum field format
  while (oct.length < 6) oct = "0" + oct;                                            // chksum field is 6 octal digits per POSIX ustar
  if (oct.length > 6) {                                                              // chksum field is 6 octal digits per POSIX ustar
    // Header is corrupt / oversized somewhere; surface a typed error.
    throw new TarError("archive-tar/chksum-overflow",
      "chksum " + sum + " (" + oct + ") exceeds 6 octal digits");
  }
  buf.write(oct, H_CHKSUM, 6, "ascii");                                              // chksum field is 6 octal digits per POSIX ustar
  buf.writeUInt8(0, H_CHKSUM + 6);                                                   // chksum field: 6 digits + NUL + space per POSIX ustar
  buf.writeUInt8(0x20, H_CHKSUM + 7);                                                // chksum field: 6 digits + NUL + space per POSIX ustar
}

function _verifyChecksum(buf) {
  // Parse the stored chksum + compare against recomputed.
  var stored = _readOctal(buf, H_CHKSUM, W_CHKSUM);
  var computed = _computeChecksum(buf);
  return stored === computed;
}

function _normalizeName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TarError("archive-tar/bad-name", "addFile: name must be non-empty string");
  }
  if (name.indexOf("\u0000") !== -1) {
    throw new TarError("archive-tar/bad-name", "addFile: name contains null byte");
  }
  var normalized = name.replace(/\\/g, "/").replace(/^\/+/, "");
  var segs = normalized.split("/");
  for (var i = 0; i < segs.length; i += 1) {
    if (segs[i] === "..") {
      throw new TarError("archive-tar/bad-name", "addFile: name contains '..' segment");
    }
  }
  return normalized;
}

// ---- Pax extended header -----------------------------------------------

function _buildPaxRecord(key, value) {
  // POSIX.1-2001 §4.18 — "len key=value\n" where len is the total
  // length of the record (including len itself + space + key + '=' +
  // value + '\n'). Compute len iteratively because len encodes itself.
  var keyVal = key + "=" + value + "\n";
  // Initial guess: len contributes ≤ 3 digits; iterate until stable.
  var lenStr = String(keyVal.length + 1 + 1);   // +1 for space, +1 for len digit
  var len = parseInt(lenStr, 10) + keyVal.length;
  while (true) {
    var encoded = String(len) + " " + keyVal;
    if (encoded.length === len) return encoded;
    len = encoded.length;
  }
}

function _buildPaxExtendedHeader(records, prefixName) {
  // records: array of [key, value] pairs.
  // Emit the records as the body, then build a typeflag-'x' ustar
  // header pointing at the body.
  var body = "";
  for (var i = 0; i < records.length; i += 1) {
    body += _buildPaxRecord(records[i][0], records[i][1]);
  }
  var bodyBuf = Buffer.from(body, "utf8");
  var hdr = _buildUstarHeader({
    name:      prefixName || "PaxHeader/extended",
    typeflag:  TF_PAX_EXTENDED,
    size:      bodyBuf.length,
    mtime:     0,
    mode:      0o644,
  });
  return Buffer.concat([hdr, _padBlock(bodyBuf)]);
}

function _parsePaxRecords(buf) {
  // Parse "len key=value\n" records from a pax extended-header body.
  var out = Object.create(null);
  var pos = 0;
  var s = buf.toString("utf8");
  while (pos < s.length) {
    var spaceIdx = s.indexOf(" ", pos);
    if (spaceIdx < 0) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " missing length-space delimiter");
    }
    var lenStr = s.slice(pos, spaceIdx);
    var len = parseInt(lenStr, 10);
    if (!Number.isFinite(len) || len <= 0) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record length " + JSON.stringify(lenStr) + " is not a positive integer");
    }
    var record = s.slice(pos, pos + len);
    if (record[record.length - 1] !== "\n") {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " not newline-terminated");
    }
    var eqIdx = record.indexOf("=", spaceIdx - pos + 1);
    if (eqIdx < 0) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " missing key=value delimiter");
    }
    var key = record.slice(spaceIdx - pos + 1, eqIdx);
    var value = record.slice(eqIdx + 1, record.length - 1);
    out[key] = value;
    pos += len;
  }
  return out;
}

// ---- ustar header build --------------------------------------------------

function _buildUstarHeader(entry) {
  var buf = Buffer.alloc(BLOCK_SIZE);
  // name + prefix split for names > 100 chars
  var name = entry.name;
  var prefix = "";
  if (name.length > NAME_MAX) {
    // Try splitting on a '/' so prefix + '/' + name <= 100 + 155
    var splitIdx = name.lastIndexOf("/", NAME_MAX);
    if (splitIdx > 0 && (name.length - splitIdx - 1) <= NAME_MAX &&
        splitIdx <= PREFIX_MAX) {
      prefix = name.slice(0, splitIdx);
      name = name.slice(splitIdx + 1);
    } else {
      // Won't fit in ustar — pax extended header handles it; the
      // ustar header carries a "PaxHeader/data" sentinel name.
      name = "PaxHeader/data";
    }
  }
  _writeString(buf, name, H_NAME, NAME_MAX);
  _writeOctal(buf, entry.mode || 0o644, H_MODE, W_MODE);
  _writeOctal(buf, entry.uid || 0, H_UID, W_UID);
  _writeOctal(buf, entry.gid || 0, H_GID, W_GID);
  _writeOctal(buf, entry.size || 0, H_SIZE, W_SIZE);
  _writeOctal(buf, entry.mtime || 0, H_MTIME, W_MTIME);
  // chksum field — written as 8 spaces during computation, then
  // replaced with the computed value below.
  buf.fill(0x20, H_CHKSUM, H_CHKSUM + W_CHKSUM);                                     // pre-fill chksum field with spaces per POSIX
  buf.write(entry.typeflag || TF_REGULAR, H_TYPEFLAG, 1, "ascii");
  if (entry.linkname) _writeString(buf, entry.linkname, H_LINKNAME, LINKNAME_MAX);
  buf.write(USTAR_MAGIC, H_MAGIC, 6, "ascii");                                       // ustar magic is 6 bytes per POSIX
  buf.write(USTAR_VERSION, H_VERSION, 2, "ascii");                                   // ustar version is 2 bytes per POSIX
  if (entry.uname) _writeString(buf, entry.uname, H_UNAME, W_UNAME);
  if (entry.gname) _writeString(buf, entry.gname, H_GNAME, W_GNAME);
  if (prefix) _writeString(buf, prefix, H_PREFIX, PREFIX_MAX);
  _writeChecksum(buf);
  return buf;
}

// ---- Public tar builder ---------------------------------------------------

/**
 * @primitive b.archive.tar
 * @signature b.archive.tar()
 * @since     0.12.8
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.archive.zip, b.archive.read.tar
 *
 * POSIX pax tar archive builder. Mirrors `b.archive.zip()`'s
 * `addFile / addDirectory / toBuffer / toStream / toAdapter / digest`
 * contract.
 *
 * @example
 *   var t = b.archive.tar();
 *   t.addFile("readme.txt", "Hello\n");
 *   t.addFile("data/numbers.csv", "n,sq\n1,1\n2,4\n");
 *   var bytes = t.toBuffer();
 *   t.entryCount;       // → 2
 */
function tarBuilder() {
  var entries = [];

  function addFile(name, content, opts) {
    var normalized = _normalizeName(name);
    opts = opts || {};
    var bodyBuf;
    if (Buffer.isBuffer(content)) bodyBuf = content;
    else if (typeof content === "string") bodyBuf = Buffer.from(content, "utf8");
    else throw new TarError("archive-tar/bad-content",
      "addFile: content must be Buffer or string, got " + typeof content);
    entries.push({
      name:      normalized,
      kind:      "file",
      typeflag:  TF_REGULAR,
      body:      bodyBuf,
      size:      bodyBuf.length,
      mode:      opts.mode || 0o644,
      mtime:     opts.mtime !== undefined ? opts.mtime
                : Math.floor((opts.fixedMtime || Date.now()) / C.TIME.seconds(1)),
      uid:       opts.uid  || 0,
      gid:       opts.gid  || 0,
      uname:     opts.uname || "",
      gname:     opts.gname || "",
    });
  }

  function addDirectory(name, opts) {
    var normalized = _normalizeName(name);
    if (normalized[normalized.length - 1] !== "/") normalized = normalized + "/";
    opts = opts || {};
    entries.push({
      name:      normalized,
      kind:      "directory",
      typeflag:  TF_DIRECTORY,
      body:      Buffer.alloc(0),
      size:      0,
      mode:      opts.mode || 0o755,
      mtime:     opts.mtime !== undefined ? opts.mtime : Math.floor(Date.now() / C.TIME.seconds(1)),
      uid:       opts.uid  || 0,
      gid:       opts.gid  || 0,
      uname:     opts.uname || "",
      gname:     opts.gname || "",
    });
  }

  function _entryBytes(entry) {
    // Determine if we need a pax extended header.
    var paxRecords = [];
    if (entry.name.length > NAME_MAX) {
      // Check if ustar prefix/name split would work.
      var splitIdx = entry.name.lastIndexOf("/", NAME_MAX);
      var fits = splitIdx > 0 &&
                 (entry.name.length - splitIdx - 1) <= NAME_MAX &&
                 splitIdx <= PREFIX_MAX;
      if (!fits) paxRecords.push(["path", entry.name]);
    }
    if (entry.size > USTAR_SIZE_MAX) {
      paxRecords.push(["size", String(entry.size)]);
    }
    var pieces = [];
    if (paxRecords.length > 0) {
      pieces.push(_buildPaxExtendedHeader(paxRecords, "PaxHeader/" + entry.name.slice(0, 80)));  // pax header name fits in ustar 100-char field with 20-char prefix budget
    }
    var hdr = _buildUstarHeader({
      name:      entry.name,
      mode:      entry.mode,
      uid:       entry.uid,
      gid:       entry.gid,
      size:      Math.min(entry.size, USTAR_SIZE_MAX),
      mtime:     entry.mtime,
      typeflag:  entry.typeflag,
      linkname:  entry.linkname,
      uname:     entry.uname,
      gname:     entry.gname,
    });
    pieces.push(hdr);
    if (entry.body.length > 0) {
      pieces.push(_padBlock(entry.body));
    }
    return Buffer.concat(pieces);
  }

  function toBuffer() {
    var pieces = [];
    for (var i = 0; i < entries.length; i += 1) {
      pieces.push(_entryBytes(entries[i]));
    }
    // Two zero blocks terminate the archive (POSIX requirement).
    pieces.push(Buffer.alloc(BLOCK_SIZE * 2));                                       // POSIX requires 2 trailing zero blocks
    return Buffer.concat(pieces);
  }

  async function toAdapter(adapter) {
    if (!adapter || typeof adapter.write !== "function") {
      throw new TarError("archive-tar/bad-adapter",
        "toAdapter: adapter must expose a write(bytes) method");
    }
    for (var i = 0; i < entries.length; i += 1) {
      await adapter.write(_entryBytes(entries[i]));
    }
    await adapter.write(Buffer.alloc(BLOCK_SIZE * 2));                               // 2 trailing zero blocks
    if (typeof adapter.end === "function") await adapter.end();
  }

  function toStream(writable) {
    return new Promise(function (resolve, reject) {
      try {
        writable.write(toBuffer());
        writable.end();
        writable.once("finish", resolve);
        writable.once("error", reject);
      } catch (e) { reject(e); }
    });
  }

  function digest() {
    var nodeCrypto = require("node:crypto");
    return nodeCrypto.createHash("sha3-512").update(toBuffer()).digest("hex");
  }

  async function toGzip(adapter, gzOpts) {
    // Convenience composition: materialize the tar then wrap through
    // b.archive.gz. archive-gz is lazy-required at module top to break
    // the load-order cycle with archive-tar-read.
    return archiveGz().gz(toBuffer(), gzOpts || {}).toAdapter(adapter);
  }

  return {
    addFile:      addFile,
    addDirectory: addDirectory,
    toBuffer:     toBuffer,
    toStream:     toStream,
    toAdapter:    toAdapter,
    toGzip:       toGzip,
    digest:       digest,
    get entryCount() { return entries.length; },
  };
}

// ---- Shared read-side helper --------------------------------------------
//
// Sibling module lib/archive-tar-read.js imports _parseHeader via
// these exports. The reader lives in a separate file so the
// validator can pair the b.archive.read.tar primitive cleanly
// (sibling shape to lib/archive-read.js for ZIP). _parseHeader
// lives here so the write side's checksum + header-field encoding
// has its inverse in the same wire-format module.

function _parseHeader(buf) {
  var magic = buf.slice(H_MAGIC, H_MAGIC + C.BYTES.bytes(5)).toString("ascii");
  if (magic !== "ustar") {
    throw new TarError("archive-tar/bad-magic",
      "header magic " + JSON.stringify(magic) + " is not ustar");
  }
  if (!_verifyChecksum(buf)) {
    throw new TarError("archive-tar/bad-chksum",
      "header checksum mismatch");
  }
  var name = _readString(buf, H_NAME, NAME_MAX);
  var prefix = _readString(buf, H_PREFIX, PREFIX_MAX);
  if (prefix.length > 0) name = prefix + "/" + name;
  return {
    name:      name,
    mode:      _readOctal(buf, H_MODE, W_MODE),
    uid:       _readOctal(buf, H_UID, W_UID),
    gid:       _readOctal(buf, H_GID, W_GID),
    size:      _readOctal(buf, H_SIZE, W_SIZE),
    mtime:     _readOctal(buf, H_MTIME, W_MTIME),
    typeflag:  String.fromCharCode(buf[H_TYPEFLAG]),
    linkname:  _readString(buf, H_LINKNAME, LINKNAME_MAX),
    uname:     _readString(buf, H_UNAME, W_UNAME),
    gname:     _readString(buf, H_GNAME, W_GNAME),
  };
}

module.exports = {
  tar:                tarBuilder,
  TarError:           TarError,
  // Exposed for sibling modules + tests
  _buildUstarHeader:  _buildUstarHeader,
  _parseHeader:       _parseHeader,
  _readOctal:         _readOctal,
  _readString:        _readString,
  _verifyChecksum:    _verifyChecksum,
};
