// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *     - 0 / '\0' (regular file): extract. A 0, '\0' or 7 entry whose
 *       name ends in "/" is read as a directory.
 *     - 5 (directory): extract (mkdir -p).
 *     - 1 / 2 / 3 / 4 / 5 / 6 entries, and directories named with a
 *       trailing "/", must declare size 0 in the header and in any pax
 *       size record; any other size is refused.
 *     - 1 (hardlink): refused by default; `allowDangerous: { hardlinks:
 *       true }` opt-in routes link target through
 *       `b.guardFilename.verifyExtractionPath`.
 *     - 2 (symlink): same as hardlink — refused by default; opt-in
 *       with realpath-on-target check.
 *     - 3 / 4 / 6 (char-device / block-device / FIFO): refused
 *       unconditionally.
 *     - 7 (contiguous file): extracted as a regular file.
 *     - D (GNU dumpdir): read as a directory.
 *     - x (pax extended header) and X (Solaris extended header):
 *       consumed by reader; merged into next entry's metadata. A
 *       `GNU.sparse.name` key names the entry ahead of `path`, and an
 *       entry with any `GNU.sparse.*`, `SCHILY.realsize` or
 *       `SUN.holesdata` key reads as entryType "unknown". A pax key
 *       holding a NUL byte or starting with a blank, and a NUL inside a
 *       `path`, `linkpath` or `GNU.sparse.name` value, are refused.
 *     - g (pax global header): consumed. A `g` header with a `path`,
 *       `linkpath`, `size`, `GNU.sparse.*`, `SCHILY.realsize` or
 *       `SUN.holesdata` key is refused; other keys do not change any
 *       entry.
 *     - L / K (GNU long name / long link): consumed by reader. The body,
 *       read up to its first NUL, becomes the next entry's name (L) or
 *       link target (K). See `b.archive.read.tar` for the records the
 *       reader refuses.
 *     - Any other typeflag (GNU sparse S, multi-volume M, volume label
 *       V, Solaris ACL A, old GNU long name N, vendor letters): `inspect()`
 *       lists it with entryType "unknown"; `extract` and `extractEntries`
 *       refuse it under every `entryTypePolicy`. A pax header or L / K
 *       record followed by a V or A header is refused, because bsdtar
 *       applies it to the entry after that header and GNU tar applies it
 *       to the header itself. A V header written by `tar --format=gnu --label` has an
 *       empty magic field; the reader accepts that header when its
 *       checksum is valid and refuses every other header without the
 *       ustar magic.
 *     - A GNU-format header (magic "ustar  \0") keeps access and change
 *       times where ustar keeps the name prefix; the reader does not
 *       join that field onto the name.
 *     - S (GNU sparse) with the isextended byte set: the extension
 *       blocks after the header are read before the data.
 *     - A GNU-format header with any other typeflag whose old GNU sparse
 *       map, isextended byte or realsize field holds a nonzero byte
 *       reads as entryType "unknown", the same as a typeflag S entry.
 *     - Names and link targets must be valid UTF-8.
 *     - The first all-zero block ends the archive.
 *     - A header's magic and version must be "ustar\0" followed by any
 *       two version bytes, or the GNU "ustar  \0"; every other header,
 *       except the GNU volume label above, is refused. This refuses
 *       V7-format archives (`tar --format=v7`), whose headers have no
 *       magic.
 *     - An octal numeric field ends at its first space or NUL, and every
 *       byte after that must be a space or NUL.
 *     - The mode, uid, gid, size and mtime fields are read as octal, or
 *       as base-256 when the first byte is 0x80 (positive) or 0xff
 *       (negative), as GNU tar and bsdtar write values that do not fit
 *       in octal (an mtime before 1970 or after 2242, a uid over
 *       2097151, a size of 8 GiB or more). A base-256 value outside the
 *       field's range is refused: a negative size, mode, uid or gid, a
 *       mode, uid or gid over 4294967295, a size over
 *       Number.MAX_SAFE_INTEGER, or an mtime outside the range a Date
 *       can hold.
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
 *     - Sparse files. The writer does not produce them, and the reader
 *       refuses GNU sparse entries (typeflag S, and pax GNU.sparse.*
 *       entries) on extract.
 *     - BSD-tar extensions beyond pax.
 *
 * @card
 *   POSIX pax tar archive — write + read with the same defense surface as the ZIP family.
 */

var nodeBuffer = require("node:buffer");
var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var { defineClass } = require("./framework-error");

var TarError = defineClass("TarError", { alwaysPermanent: true });

void streamPromises; void nodeStream;

// Lazy because archive-gz lazy-imports archive-tar-read (sibling read
// module) — a top-of-file `require("./archive-gz")` would create a
// load-order cycle that depends on file-walk order.
var archiveGz = lazyRequire(function () { return require("./archive-gz"); });

var BLOCK_SIZE = C.BYTES.bytes(512);
var USTAR_MAGIC = "ustar\u0000";
var USTAR_VERSION = "00";
var GNU_MAGIC = "ustar  \u0000";
var NAME_MAX = C.BYTES.bytes(100);
var PREFIX_MAX = C.BYTES.bytes(155);
var LINKNAME_MAX = C.BYTES.bytes(100);
var USTAR_SIZE_MAX = 0o77777777777;

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

var W_MODE = C.BYTES.bytes(8);
var W_UID = C.BYTES.bytes(8);
var W_GID = C.BYTES.bytes(8);
var W_SIZE = C.BYTES.bytes(12);
var W_MTIME = C.BYTES.bytes(12);
var W_CHKSUM = C.BYTES.bytes(8);
var W_UNAME = C.BYTES.bytes(32);
var W_GNAME = C.BYTES.bytes(32);
var W_MAGIC_VERSION = C.BYTES.bytes(8);
var W_MAGIC = C.BYTES.bytes(6);

var BASE256_POSITIVE = 0x80;
var BASE256_NEGATIVE = 0xff;
var BASE256_MARKER_BIT = 0x80;
var BYTE_RADIX = 256;
var UINT32_MAX = 0xffffffff;
var DATE_RANGE_SECONDS = C.TIME.days(100000000) / C.TIME.seconds(1);
var NUMERIC_RANGES = Object.freeze({
  mode:  [0, UINT32_MAX],
  uid:   [0, UINT32_MAX],
  gid:   [0, UINT32_MAX],
  size:  [0, Number.MAX_SAFE_INTEGER],
  mtime: [-DATE_RANGE_SECONDS, DATE_RANGE_SECONDS],
});

var TF_REGULAR = "0";
var TF_DIRECTORY = "5";
var TF_PAX_EXTENDED = "x";
var TF_GNU_VOLHDR = "V";

void H_DEVMAJOR; void H_DEVMINOR;

function _padBlock(buf) {
  var rem = buf.length % BLOCK_SIZE;
  if (rem === 0) return buf;
  var pad = Buffer.alloc(BLOCK_SIZE - rem);
  return Buffer.concat([buf, pad]);
}

function _writeOctal(buf, value, offset, width) {
  var digits = width - 1;
  var oct = value.toString(8);
  if (oct.length > digits) {
    throw new TarError("archive-tar/octal-overflow",
      "value " + value + " (octal " + oct + ") exceeds field width " + digits);
  }
  while (oct.length < digits) oct = "0" + oct;
  buf.write(oct, offset, digits, "ascii");
  buf.writeUInt8(0x20, offset + digits);
}

function _writeString(buf, value, offset, width) {
  var ascii = String(value);
  var bytes = Buffer.from(ascii, "utf8");
  if (bytes.length > width) {
    throw new TarError("archive-tar/field-overflow",
      "string " + JSON.stringify(value) + " (" + bytes.length + " bytes) exceeds field width " + width);
  }
  bytes.copy(buf, offset);
}

function _readOctal(buf, offset, width) {
  var i = 0;
  while (i < width && buf[offset + i] === 0x20) i += 1;
  var s = "";
  for (; i < width; i += 1) {
    var c = buf[offset + i];
    if (c === 0x20 || c === 0) break;
    if (c < 0x30 || c > 0x37) {
      throw new TarError("archive-tar/bad-octal",
        "non-octal byte 0x" + c.toString(16) + " at offset " + (offset + i));
    }
    s += String.fromCharCode(c);
  }
  for (var t = i + 1; t < width; t += 1) {
    var trailing = buf[offset + t];
    if (trailing !== 0x20 && trailing !== 0) {
      throw new TarError("archive-tar/bad-octal",
        "numeric field at offset " + offset + " has byte 0x" + trailing.toString(16) +
        " after its terminator at offset " + (offset + i) + "; GNU tar ignores it and bsdtar refuses the header");
    }
  }
  if (s.length === 0) return 0;
  return parseInt(s, 8);
}

function _readBase256(buf, offset, width) {
  var first = buf[offset];
  if (first !== BASE256_POSITIVE && first !== BASE256_NEGATIVE) {
    throw new TarError("archive-tar/bad-octal",
      "numeric field at offset " + offset + " starts with byte 0x" + first.toString(16) +
      ", which is neither an octal digit nor a base-256 marker (0x80 or 0xff)");
  }
  var radix = BigInt(BYTE_RADIX);
  var value = BigInt(0);
  for (var i = 1; i < width; i += 1) value = value * radix + BigInt(buf[offset + i]);
  if (first === BASE256_NEGATIVE) value -= radix ** BigInt(width - 1);
  return value;
}

function _readNumeric(buf, offset, width, field) {
  if ((buf[offset] & BASE256_MARKER_BIT) === 0) return _readOctal(buf, offset, width);
  var value = _readBase256(buf, offset, width);
  var range = NUMERIC_RANGES[field];
  if (value < BigInt(range[0]) || value > BigInt(range[1])) {
    throw new TarError("archive-tar/numeric-out-of-range",
      "base-256 " + field + " value " + value.toString() + " is outside " + range[0] + ".." + range[1]);
  }
  return Number(value);
}

function _fieldBytes(buf, offset, width) {
  var end = offset;
  var limit = offset + width;
  while (end < limit && buf[end] !== 0) end += 1;
  return buf.subarray(offset, end);
}

function _readString(buf, offset, width) {
  return _fieldBytes(buf, offset, width).toString("utf8");
}

function _computeChecksum(buf) {
  var sum = 0;
  for (var i = 0; i < BLOCK_SIZE; i += 1) {
    if (i >= H_CHKSUM && i < H_CHKSUM + W_CHKSUM) {
      sum += 0x20;
    } else {
      sum += buf[i];
    }
  }
  return sum;
}

function _writeChecksum(buf) {
  var sum = _computeChecksum(buf);
  var oct = sum.toString(8);
  while (oct.length < 6) oct = "0" + oct;
  if (oct.length > 6) {
    throw new TarError("archive-tar/chksum-overflow",
      "chksum " + sum + " (" + oct + ") exceeds 6 octal digits");
  }
  buf.write(oct, H_CHKSUM, 6, "ascii");
  buf.writeUInt8(0, H_CHKSUM + 6);
  buf.writeUInt8(0x20, H_CHKSUM + 7);
}

function _verifyChecksum(buf) {
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
  if (safeBuffer.hasCrlf(name)) {
    throw new TarError("archive-tar/bad-name", "addFile: name contains CR/LF");
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

function _buildPaxRecord(key, value) {
  var keyVal = key + "=" + value + "\n";
  var bodyBytes = Buffer.byteLength(keyVal, "utf8");
  var len = bodyBytes + 2;
  while (true) {
    var total = String(len).length + 1 + bodyBytes;
    if (total === len) return String(len) + " " + keyVal;
    len = total;
  }
}

function _ustarNameSplit(name) {
  if (Buffer.byteLength(name, "utf8") <= NAME_MAX) return { name: name, prefix: "" };
  for (var idx = name.lastIndexOf("/"); idx > 0; idx = name.lastIndexOf("/", idx - 1)) {
    var prefix = name.slice(0, idx);
    var rest = name.slice(idx + 1);
    if (rest.length > 0 && Buffer.byteLength(rest, "utf8") <= NAME_MAX &&
        Buffer.byteLength(prefix, "utf8") <= PREFIX_MAX) {
      return { name: rest, prefix: prefix };
    }
  }
  return null;
}

function _utf8Prefix(str, maxBytes) {
  var out = "";
  var used = 0;
  for (var ch of str) {
    var n = Buffer.byteLength(ch, "utf8");
    if (used + n > maxBytes) break;
    out += ch;
    used += n;
  }
  return out;
}

function _buildPaxExtendedHeader(records, prefixName) {
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

function _buildUstarHeader(entry) {
  var buf = Buffer.alloc(BLOCK_SIZE);
  var split = _ustarNameSplit(entry.name);
  var name = split === null ? "PaxHeader/data" : split.name;
  var prefix = split === null ? "" : split.prefix;
  _writeString(buf, name, H_NAME, NAME_MAX);
  _writeOctal(buf, entry.mode || 0o644, H_MODE, W_MODE);
  _writeOctal(buf, entry.uid || 0, H_UID, W_UID);
  _writeOctal(buf, entry.gid || 0, H_GID, W_GID);
  _writeOctal(buf, entry.size || 0, H_SIZE, W_SIZE);
  _writeOctal(buf, entry.mtime || 0, H_MTIME, W_MTIME);
  buf.fill(0x20, H_CHKSUM, H_CHKSUM + W_CHKSUM);
  buf.write(entry.typeflag || TF_REGULAR, H_TYPEFLAG, 1, "ascii");
  if (entry.linkname) _writeString(buf, entry.linkname, H_LINKNAME, LINKNAME_MAX);
  buf.write(USTAR_MAGIC, H_MAGIC, 6, "ascii");
  buf.write(USTAR_VERSION, H_VERSION, 2, "ascii");
  if (entry.uname) _writeString(buf, entry.uname, H_UNAME, W_UNAME);
  if (entry.gname) _writeString(buf, entry.gname, H_GNAME, W_GNAME);
  if (prefix) _writeString(buf, prefix, H_PREFIX, PREFIX_MAX);
  _writeChecksum(buf);
  return buf;
}

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
    var paxRecords = [];
    if (_ustarNameSplit(entry.name) === null) paxRecords.push(["path", entry.name]);
    if (entry.size > USTAR_SIZE_MAX) {
      paxRecords.push(["size", String(entry.size)]);
    }
    var pieces = [];
    if (paxRecords.length > 0) {
      pieces.push(_buildPaxExtendedHeader(paxRecords, "PaxHeader/" + _utf8Prefix(entry.name, 80)));
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
    pieces.push(Buffer.alloc(BLOCK_SIZE * 2));
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
    await adapter.write(Buffer.alloc(BLOCK_SIZE * 2));
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

function _isGnuVolumeLabelWithoutMagic(buf) {
  if (String.fromCharCode(buf[H_TYPEFLAG]) !== TF_GNU_VOLHDR) return false;
  for (var i = H_MAGIC; i < H_MAGIC + W_MAGIC_VERSION; i += 1) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function _parseHeader(buf) {
  var magicVersion = buf.subarray(H_MAGIC, H_MAGIC + W_MAGIC_VERSION).toString("latin1");
  var isGnu = magicVersion === GNU_MAGIC || _isGnuVolumeLabelWithoutMagic(buf);
  if (!isGnu && magicVersion.slice(0, W_MAGIC) !== USTAR_MAGIC) {
    throw new TarError("archive-tar/bad-magic",
      "header magic and version " + JSON.stringify(magicVersion) + " are neither \"ustar\\u0000\" " +
      "followed by a version nor the GNU \"ustar  \\u0000\"");
  }
  if (!_verifyChecksum(buf)) {
    throw new TarError("archive-tar/bad-chksum",
      "header checksum mismatch");
  }
  var nameBytes = _fieldBytes(buf, H_NAME, NAME_MAX);
  var nameIsUtf8 = nodeBuffer.isUtf8(nameBytes);
  var name = nameBytes.toString("utf8");
  if (!isGnu) {
    var prefixBytes = _fieldBytes(buf, H_PREFIX, PREFIX_MAX);
    if (prefixBytes.length > 0) {
      name = prefixBytes.toString("utf8") + "/" + name;
      nameIsUtf8 = nameIsUtf8 && nodeBuffer.isUtf8(prefixBytes);
    }
  }
  var linknameBytes = _fieldBytes(buf, H_LINKNAME, LINKNAME_MAX);
  return {
    name:      name,
    mode:      _readNumeric(buf, H_MODE, W_MODE, "mode"),
    uid:       _readNumeric(buf, H_UID, W_UID, "uid"),
    gid:       _readNumeric(buf, H_GID, W_GID, "gid"),
    size:      _readNumeric(buf, H_SIZE, W_SIZE, "size"),
    mtime:     _readNumeric(buf, H_MTIME, W_MTIME, "mtime"),
    typeflag:  String.fromCharCode(buf[H_TYPEFLAG]),
    linkname:  linknameBytes.toString("utf8"),
    uname:     _readString(buf, H_UNAME, W_UNAME),
    gname:     _readString(buf, H_GNAME, W_GNAME),
    _nameIsUtf8:     nameIsUtf8,
    _linknameIsUtf8: nodeBuffer.isUtf8(linknameBytes),
  };
}

module.exports = {
  tar:                tarBuilder,
  TarError:           TarError,
  _buildUstarHeader:  _buildUstarHeader,
  _parseHeader:       _parseHeader,
  _readOctal:         _readOctal,
  _readString:        _readString,
  _verifyChecksum:    _verifyChecksum,
  _DATE_RANGE_SECONDS: DATE_RANGE_SECONDS,
};
