// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeBuffer = require("node:buffer");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var archiveTar = require("./archive-tar");
var archiveEntryPolicy = require("./archive-entry-policy");
var atomicFile = require("./atomic-file");
var auditEmit = require("./audit-emit");

var TarError = archiveTar.TarError;
var _parseHeader = archiveTar._parseHeader;

var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var guardArchive = lazyRequire(function () { return require("./guard-archive"); });

var BLOCK_SIZE = C.BYTES.bytes(512);

var TF_REGULAR = "0";
var TF_REGULAR_LEGACY = "\u0000";
var TF_HARDLINK = "1";
var TF_SYMLINK = "2";
var TF_CHARDEV = "3";
var TF_BLOCKDEV = "4";
var TF_DIRECTORY = "5";
var TF_FIFO = "6";
var TF_CONTIGUOUS = "7";
var TF_PAX_EXTENDED = "x";
var TF_PAX_GLOBAL = "g";
var TF_SOLARIS_EXTENDED = "X";
var TF_GNU_LONGNAME = "L";
var TF_GNU_LONGLINK = "K";
var TF_GNU_DUMPDIR = "D";
var TF_GNU_VOLHDR = "V";
var TF_SOLARIS_ACL = "A";
var TYPEFLAGS_BSDTAR_EXTENSION_ENTRY = Object.freeze([TF_GNU_VOLHDR, TF_SOLARIS_ACL]);

var GNU_LONG_RECORD_MAX_BYTES = C.BYTES.kib(64);
var PAX_GNU_SPARSE_PREFIX = "GNU.sparse.";
var PAX_GNU_SPARSE_NAME = "GNU.sparse.name";
var PAX_STAR_SPARSE_KEYS = Object.freeze(["SCHILY.realsize", "SUN.holesdata"]);
var PAX_GLOBAL_REFUSED_KEYS = Object.freeze(["path", "linkpath", "size"].concat(PAX_STAR_SPARSE_KEYS));
var PAX_NAME_KEYS = Object.freeze(["path", "linkpath", PAX_GNU_SPARSE_NAME]);
var TYPEFLAGS_WITHOUT_BODY = Object.freeze([
  TF_HARDLINK, TF_SYMLINK, TF_CHARDEV, TF_BLOCKDEV, TF_DIRECTORY, TF_FIFO,
]);
var TYPEFLAGS_SLASH_DIRECTORY = Object.freeze([TF_REGULAR, TF_REGULAR_LEGACY, TF_CONTIGUOUS]);

var TF_GNU_SPARSE = "S";
var GNU_MAGIC_VERSION = "ustar  \u0000";
var H_MAGIC = C.BYTES.bytes(257);
var W_MAGIC_VERSION = C.BYTES.bytes(8);
var H_GNU_SPARSE_MAP = C.BYTES.bytes(386);
var H_GNU_SPARSE_ISEXTENDED = C.BYTES.bytes(482);
var H_GNU_REALSIZE_END = C.BYTES.bytes(495);
var X_GNU_SPARSE_ISEXTENDED = C.BYTES.bytes(504);
var GNU_SPARSE_ENTRY_BYTES = C.BYTES.bytes(24);
var GNU_SPARSE_OFFSET_BYTES = C.BYTES.bytes(12);
var GNU_SPARSE_HEADER_ENTRIES = 4;
var GNU_SPARSE_EXTENSION_ENTRIES = 21;

var BYTE_NUL = 0x00;
var BYTE_TAB = 0x09;
var BYTE_SPACE = 0x20;
var BYTE_NEWLINE = 0x0a;
var BYTE_EQUALS = 0x3d;
var BYTE_DIGIT_ZERO = 0x30;
var BYTE_DIGIT_NINE = 0x39;
var DECIMAL_RADIX = 10;
var PAX_TIME_PATTERN = /^-?[0-9]{1,20}(?:\.[0-9]{1,20})?$/;
var DATE_RANGE_SECONDS = archiveTar._DATE_RANGE_SECONDS;

void TF_CHARDEV; void TF_BLOCKDEV; void TF_FIFO; void TF_CONTIGUOUS;

var DEFAULT_BOMB_POLICY = Object.freeze({
  maxEntries:                65535,
  maxEntryDecompressedBytes: C.BYTES.mib(128),
  maxTotalDecompressedBytes: C.BYTES.gib(4),
  maxExpansionRatio:         100,
});

var DEFAULT_ENTRY_TYPE_POLICY = archiveEntryPolicy.DEFAULT_ENTRY_TYPE_POLICY;

function _normalizeBombPolicy(p) {
  if (!p) return DEFAULT_BOMB_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_BOMB_POLICY, p));
}

var _normalizeEntryTypePolicy = archiveEntryPolicy.normalize;

var _emitAudit = auditEmit.emitToSink;

function _isZeroBlock(buf) {
  for (var i = 0; i < BLOCK_SIZE; i += 1) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function _parsePaxRecords(buf) {
  var out = Object.create(null);
  var pos = 0;
  while (pos < buf.length) {
    var remaining = buf.length - pos;
    var cursor = pos;
    var len = 0;
    while (cursor < buf.length && buf[cursor] >= BYTE_DIGIT_ZERO && buf[cursor] <= BYTE_DIGIT_NINE) {
      len = len * DECIMAL_RADIX + (buf[cursor] - BYTE_DIGIT_ZERO);
      if (len > remaining) {
        throw new TarError("archive-tar/bad-pax-record",
          "pax record at byte " + pos + " declares a length past the end of the header body (" +
          remaining + " bytes remain)");
      }
      cursor += 1;
    }
    if (cursor === pos || cursor >= buf.length || buf[cursor] !== BYTE_SPACE) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " does not start with a decimal length followed by a space");
    }
    var keyStart = cursor + 1;
    var end = pos + len;
    if (end - 1 <= keyStart || buf[end - 1] !== BYTE_NEWLINE) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " with length " + len + " does not end in a newline");
    }
    var eqIdx = buf.indexOf(BYTE_EQUALS, keyStart);
    if (eqIdx < 0 || eqIdx >= end - 1) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " missing key=value delimiter");
    }
    if (eqIdx === keyStart) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " has an empty key");
    }
    if (buf[keyStart] === BYTE_SPACE || buf[keyStart] === BYTE_TAB) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " has a blank before its key; GNU tar skips the blank and " +
        "bsdtar keeps it in the key");
    }
    if (buf.subarray(keyStart, eqIdx).indexOf(BYTE_NUL) !== -1) {
      throw new TarError("archive-tar/bad-pax-record",
        "pax record at byte " + pos + " has a NUL byte in its key; bsdtar reads the key up to the " +
        "NUL and GNU tar refuses the record");
    }
    var key = buf.toString("utf8", keyStart, eqIdx);
    var valueBytes = buf.subarray(eqIdx + 1, end - 1);
    if (PAX_NAME_KEYS.indexOf(key) !== -1) {
      if (valueBytes.indexOf(BYTE_NUL) !== -1) {
        throw new TarError("archive-tar/bad-pax-name",
          "pax record at byte " + pos + " carries a " + key + " value with a NUL byte; GNU tar and " +
          "bsdtar stop the value at the NUL");
      }
      if (key === "linkpath" && valueBytes.length === 0) {
        throw new TarError("archive-tar/bad-pax-name",
          "pax record at byte " + pos + " carries an empty linkpath; GNU tar sets an empty link " +
          "target and bsdtar keeps the header link target");
      }
      if (!nodeBuffer.isUtf8(valueBytes)) {
        throw new TarError("archive-tar/name-not-utf8",
          "pax record at byte " + pos + " carries a " + key + " value that is not valid UTF-8");
      }
    }
    out[key] = valueBytes.toString("utf8");
    pos = end;
  }
  return out;
}

function _paxSize(raw) {
  var s = String(raw);
  var digitsOnly = s.length > 0;
  for (var i = 0; i < s.length && digitsOnly; i += 1) {
    var c = s.charCodeAt(i);
    digitsOnly = c >= BYTE_DIGIT_ZERO && c <= BYTE_DIGIT_NINE;
  }
  var n = digitsOnly ? parseInt(s, DECIMAL_RADIX) : NaN;
  if (!Number.isSafeInteger(n) || String(n) !== s) {
    throw new TarError("archive-tar/bad-pax-size",
      "PAX size attribute " + JSON.stringify(raw) + " is not a non-negative integer");
  }
  return n;
}

function _paxTime(raw) {
  if (typeof raw !== "string" || !PAX_TIME_PATTERN.test(raw)) return null;
  var seconds = Number(raw);
  if (!Number.isFinite(seconds) || Math.abs(seconds) > DATE_RANGE_SECONDS) return null;
  return seconds;
}

function _readExtensionBody(bytes, pos, hdr, maxBytes, limitLabel, label) {
  if (hdr.size > maxBytes) {
    throw new TarError("archive-tar/entry-too-large",
      label + " body size=" + hdr.size + " exceeds " + limitLabel + "=" + maxBytes);
  }
  var end = pos + Math.ceil(hdr.size / BLOCK_SIZE) * BLOCK_SIZE;
  if (end > bytes.length) {
    throw new TarError("archive-tar/truncated-entry",
      label + " declares size=" + hdr.size +
      " bytes but only " + (bytes.length - pos) +
      " bytes remain after header; archive truncated mid-stream");
  }
  return { body: bytes.slice(pos, pos + hdr.size), end: end };
}

function _sparseMapFull(block, offset, count) {
  for (var i = 0; i < count; i += 1) {
    var at = offset + i * GNU_SPARSE_ENTRY_BYTES;
    if (block[at] === 0 || block[at + GNU_SPARSE_OFFSET_BYTES] === 0) return false;
  }
  return true;
}

function _skipGnuSparseExtensions(bytes, pos, block, name) {
  if (!_hasGnuMagic(block) || !_sparseMapFull(block, H_GNU_SPARSE_MAP, GNU_SPARSE_HEADER_ENTRIES)) {
    throw new TarError("archive-tar/bad-sparse-header",
      "GNU sparse entry " + JSON.stringify(name) + " sets isextended without a GNU magic and four " +
      "sparse map entries; GNU tar and bsdtar disagree on whether extension blocks follow");
  }
  var more = true;
  while (more) {
    if (pos + BLOCK_SIZE > bytes.length) {
      throw new TarError("archive-tar/truncated-entry",
        "GNU sparse entry " + JSON.stringify(name) + " has an extension block chain that runs past the " +
        "end of the archive");
    }
    var ext = bytes.subarray(pos, pos + BLOCK_SIZE);
    pos += BLOCK_SIZE;
    more = ext[X_GNU_SPARSE_ISEXTENDED] !== 0;
    if (more && !_sparseMapFull(ext, 0, GNU_SPARSE_EXTENSION_ENTRIES)) {
      throw new TarError("archive-tar/bad-sparse-header",
        "GNU sparse entry " + JSON.stringify(name) + " has an extension block that sets isextended " +
        "with an empty map entry; GNU tar and bsdtar disagree on whether another block follows");
    }
  }
  return pos;
}

function _hasGnuMagic(block) {
  return block.subarray(H_MAGIC, H_MAGIC + W_MAGIC_VERSION).toString("latin1") === GNU_MAGIC_VERSION;
}

function _oldGnuSparseFieldsSet(block) {
  if (!_hasGnuMagic(block)) return false;
  for (var i = H_GNU_SPARSE_MAP; i < H_GNU_REALSIZE_END; i += 1) {
    if (block[i] !== 0) return true;
  }
  return false;
}

function _isSparseKey(key) {
  return key.indexOf(PAX_GNU_SPARSE_PREFIX) === 0 || PAX_STAR_SPARSE_KEYS.indexOf(key) !== -1;
}

function _hasSparseKey(records) {
  if (!records) return false;
  return Object.keys(records).some(_isSparseKey);
}

function _globalEntryAttribute(records) {
  var keys = Object.keys(records);
  for (var i = 0; i < keys.length; i += 1) {
    if (PAX_GLOBAL_REFUSED_KEYS.indexOf(keys[i]) !== -1 || _isSparseKey(keys[i])) {
      return keys[i];
    }
  }
  return null;
}

function _paxEntryName(entryPax) {
  if (entryPax && entryPax[PAX_GNU_SPARSE_NAME]) return entryPax[PAX_GNU_SPARSE_NAME];
  if (entryPax && entryPax.path) return entryPax.path;
  return null;
}

function _gnuLongValue(body, label) {
  var nul = body.indexOf(0);
  var bytes = nul === -1 ? body : body.subarray(0, nul);
  if (bytes.length === 0) {
    throw new TarError("archive-tar/bad-long-record",
      label + " carries an empty value");
  }
  if (!nodeBuffer.isUtf8(bytes)) {
    throw new TarError("archive-tar/name-not-utf8",
      label + " carries a value that is not valid UTF-8");
  }
  return bytes.toString("utf8");
}

async function _collectAdapterBytes(adapter, maxBytes) {
  if (adapter.kind === "random-access") {
    var size = adapter.size;
    if (size == null && typeof adapter.resolveSize === "function") {
      size = await adapter.resolveSize();
    }
    if (typeof size !== "number" || !Number.isFinite(size) || size <= 0) return Buffer.alloc(0);
    if (typeof maxBytes === "number" && size > maxBytes) {
      throw new TarError("archive-tar/source-too-large",
        "read.tar: random-access source size=" + size +
        " exceeds the read cap " + maxBytes);
    }
    return adapter.range(0, size);
  }
  if (adapter.kind === "trusted-sequential") {
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:   C.BYTES.gib(1),
      errorClass: TarError,
      sizeCode:   "archive-tar/trusted-stream-too-large",
    });
    for await (var chunk of adapter.readable) {
      collector.push(chunk);
    }
    return collector.result();
  }
  throw new TarError("archive-tar/bad-adapter",
    "read.tar: adapter kind " + adapter.kind + " not supported");
}

function _classifyTypeflag(tf) {
  if (tf === TF_REGULAR || tf === TF_REGULAR_LEGACY) return "file";
  if (tf === TF_DIRECTORY || tf === TF_GNU_DUMPDIR) return "directory";
  if (tf === TF_SYMLINK) return "symlink";
  if (tf === TF_HARDLINK) return "hardlink";
  if (tf === TF_CHARDEV || tf === TF_BLOCKDEV) return "device";
  if (tf === TF_FIFO) return "fifo";
  if (tf === TF_CONTIGUOUS) return "file";
  return "unknown";
}

function _classifyEntry(entry) {
  if (entry._gnuSparse) return "unknown";
  if (entry._slashDirectory) return "directory";
  return _classifyTypeflag(entry.typeflag);
}

/**
 * @primitive b.archive.read.tar
 * @signature b.archive.read.tar(adapter, opts?)
 * @since     0.12.8
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.archive.read.zip, b.safeArchive.extract, b.guardArchive.tarEntryPolicy
 *
 * POSIX pax tar reader. Walks 512-byte header blocks sequentially +
 * extracts via the same bomb-cap / path-traversal / entry-type policy
 * surface as the v0.12.7 ZIP reader. Random-access and trusted-stream
 * adapters are both first-class (tar has no central directory, so
 * sequential header-by-header is the canonical adversarial-safe
 * path).
 *
 * The reader applies pax extended headers (`x`), Solaris extended
 * headers (`X`, read the same way as `x`) and GNU long-name (`L`) and
 * long-link (`K`) records to the next entry header and does not return
 * them as entries. It reads pax global headers (`g`) without returning
 * them as entries. A pax record's length counts bytes, and its key and
 * value are decoded as UTF-8 after the record is cut out of the header
 * body. A pax `GNU.sparse.name` key in an `x` or `X` header
 * names the entry ahead of a pax `path`, as it does in GNU tar and
 * bsdtar. An entry whose `x` or `X` header carries any `GNU.sparse.*`
 * key is a GNU sparse file: its stored body is a sparse map followed
 * by data blocks, so `inspect()` lists it with `entryType: "unknown"`.
 * An entry with a `SCHILY.realsize` or `SUN.holesdata` key is listed the
 * same way, because bsdtar writes a file of a different length from it
 * than GNU tar does. For the same reason, a GNU-format header with a
 * typeflag other than `S` is listed with `entryType: "unknown"` when
 * any byte of its old GNU sparse map, isextended byte or realsize field
 * is nonzero: bsdtar reads those fields for every GNU-format header and
 * GNU tar reads them only for typeflag `S`. Two records with the same key in one header are
 * accepted and the last one applies, as in GNU tar and bsdtar; a key
 * that differs from a known key by case or by a trailing blank is
 * ignored, as both tools ignore it.
 * An `L` or `K` body is read up to its first
 * NUL and may be at most `bombPolicy.maxEntryDecompressedBytes` or
 * 64 KiB, whichever is smaller. `inspect()`, `extract()`,
 * `extractEntries()` and the guard check that runs before extraction
 * all see the name and link target that GNU tar and bsdtar extract to.
 * A GNU-format header (magic `"ustar  \0"`) does not have its prefix
 * field joined onto the name. Typeflag `D` (GNU dumpdir) is read as a
 * directory. A volume label `V` header written by
 * `tar --format=gnu --label` has an empty magic field; `inspect()` lists
 * it with `entryType: "unknown"` when its checksum is valid. A Solaris
 * ACL `A` header is listed with `entryType: "unknown"`: GNU tar extracts
 * its body as a regular file, and bsdtar reads the body as the ACL of the
 * next entry and does not list the `A` header as an entry.
 * An entry with typeflag `0`, NUL or `7` whose name ends in `/` is a
 * directory, as it is in GNU tar and bsdtar. The extension blocks that
 * follow a GNU sparse (`S`) header with its isextended byte set are read
 * as part of that header. The archive ends at the first all-zero block,
 * and nothing after it is read. The mode, uid, gid, size and mtime
 * fields are read as octal, or as base-256 when their first byte is 0x80
 * or 0xff; GNU tar and bsdtar write base-256 for an mtime before 1970 or
 * after 2242, a uid or gid over 2097151, and a size of 8 GiB or more.
 * A pax `mtime` record that is a decimal number of seconds, with an
 * optional fraction, within the range a `Date` can hold replaces the
 * header mtime; any other `mtime` value leaves the header mtime in place.
 *
 * `extract()` and `extractEntries()` refuse devices and FIFOs, refuse
 * symlinks and hardlinks unless `entryTypePolicy` or `allowDangerous`
 * allows them, and refuse every typeflag the reader classifies as
 * `"unknown"`: GNU sparse files (typeflag `S`, written by
 * `tar --format=gnu -S`, pax `GNU.sparse.*` entries, written by
 * `tar --format=posix -S`, pax `SCHILY.realsize` or `SUN.holesdata`
 * entries, and GNU-format entries with old GNU sparse fields set),
 * multi-volume (`M`), volume label (`V`), Solaris ACL (`A`), old
 * GNU long name (`N`) and vendor letters. `entryTypePolicy` and
 * `allowDangerous` do not allow any of them. `inspect()` lists those
 * entries with `entryType: "unknown"`.
 *
 * Construction throws `archive-tar/bad-adapter` for an adapter that is
 * not from `b.archive.adapters.*`. `inspect()`, `extract()` and
 * `extractEntries()` reject with:
 * `archive-tar/source-too-large` (random-access source over
 * `maxTotalDecompressedBytes`), `archive-tar/trusted-stream-too-large`,
 * `archive-tar/bad-magic` (a header whose magic and version are neither
 * `"ustar\0"` followed by any two version bytes nor the GNU
 * `"ustar  \0"`, other than the GNU volume label above; this includes
 * every header of a V7-format archive, as `tar --format=v7` writes no
 * magic),
 * `archive-tar/bad-chksum`,
 * `archive-tar/bad-octal` (a numeric field that is neither octal nor
 * base-256 with a first byte of 0x80 or 0xff, or an octal field with a
 * byte other than a space or NUL after its terminating space or NUL),
 * `archive-tar/numeric-out-of-range` (a base-256 mode, uid, gid or size
 * below zero, a mode, uid or gid over 4294967295, a size over
 * `Number.MAX_SAFE_INTEGER`, or an mtime outside the range a `Date` can
 * hold),
 * `archive-tar/bad-pax-record` (a pax record whose length is not a
 * decimal byte count followed by a space, runs past the header body or
 * does not end in a newline, or whose key is missing, empty, starts
 * with a space or tab, or holds a NUL byte),
 * `archive-tar/bad-pax-name` (a pax `path`, `linkpath` or
 * `GNU.sparse.name` value holding a NUL byte, or an empty pax
 * `linkpath`),
 * `archive-tar/bad-pax-size` (a pax `size` value that is empty, holds
 * anything other than decimal digits, including spaces, or starts with
 * a zero followed by more digits), `archive-tar/entry-too-large`,
 * `archive-tar/size-on-non-file` (a hardlink, symlink, device, directory
 * or FIFO entry, including a typeflag `0`, NUL or `7` entry whose name
 * ends in `/`, with a nonzero header or pax size),
 * `archive-tar/name-not-utf8` (an entry name or link target from the
 * header, an `L` or `K` record, or a pax `path`, `linkpath` or
 * `GNU.sparse.name` record that is not valid UTF-8, including under pax
 * `hdrcharset=BINARY`),
 * `archive-tar/bad-sparse-header` (a GNU sparse `S` header that sets
 * isextended without the GNU magic and four filled map entries, or an
 * extension block that sets isextended with an empty map entry),
 * `archive-tar/truncated-entry` (also a GNU sparse extension block chain
 * that runs past the end of the archive), `archive-tar/too-many-entries`,
 * `archive-tar/bad-long-record` (empty `L` / `K` value, or two `L` or
 * two `K` records before one header),
 * `archive-tar/long-name-pax-conflict` (an `L` value that differs from
 * the pax `GNU.sparse.name` or `path`, or a `K` value that differs from
 * the pax `linkpath`),
 * `archive-tar/redundant-extended-header` (two pax `x` or `X` headers
 * before one entry header),
 * `archive-tar/global-entry-attribute` (a pax global `g` header carrying
 * a `path`, `linkpath`, `size`, `GNU.sparse.*`, `SCHILY.realsize` or
 * `SUN.holesdata` key),
 * `archive-tar/link-target-on-non-link` (a `K` record or pax `linkpath`
 * before an entry that is not a symlink or hardlink), and
 * `archive-tar/dangling-extended-header` (a pax header or `L` / `K`
 * record with no entry header after it, or followed by a GNU volume
 * label `V` header or a Solaris ACL `A` header). `extract()` and
 * `extractEntries()` also reject with `archive-tar/guard-refused`,
 * `archive-tar/entry-type-refused` and `archive-tar/total-too-large`;
 * `extract()` also rejects with `archive-tar/no-destination` and
 * `archive-tar/destination-exists`.
 *
 * @opts
 *   bombPolicy:       { maxEntries, maxEntryDecompressedBytes,
 *                       maxTotalDecompressedBytes, maxExpansionRatio },
 *   entryTypePolicy:  { symlinks, hardlinks, devices, fifos, sockets },
 *   allowDangerous:   { symlinks, hardlinks },
 *   guardProfile:     "strict" | "balanced" | "permissive",
 *   audit:            b.audit,
 *
 * @example
 *   var reader  = b.archive.read.tar(b.archive.adapters.buffer(Buffer.alloc(0)));
 *   var entries = await reader.inspect();
 *   void entries;
 */
function tar(adapter, opts) {
  if (!adapter || (adapter.kind !== "random-access" && adapter.kind !== "trusted-sequential")) {
    throw new TarError("archive-tar/bad-adapter",
      "read.tar(adapter): adapter must come from b.archive.adapters.*");
  }
  opts = opts || {};
  var bombPolicy = _normalizeBombPolicy(opts.bombPolicy);
  var entryTypePolicy = _normalizeEntryTypePolicy(opts.entryTypePolicy);

  async function _walk() {
    var bytes = await _collectAdapterBytes(adapter, bombPolicy.maxTotalDecompressedBytes);
    if (bytes.length === 0) return { entries: [], bytes: bytes };
    var pos = 0;
    var entries = [];
    var pendingPax = null;
    var pendingLongName = null;
    var pendingLongLink = null;
    while (pos + BLOCK_SIZE <= bytes.length) {
      var block = bytes.slice(pos, pos + BLOCK_SIZE);
      pos += BLOCK_SIZE;
      if (_isZeroBlock(block)) break;
      var hdr = _parseHeader(block);
      if (hdr.typeflag === TF_PAX_EXTENDED || hdr.typeflag === TF_SOLARIS_EXTENDED ||
          hdr.typeflag === TF_PAX_GLOBAL) {
        var paxRead = _readExtensionBody(bytes, pos, hdr,
          bombPolicy.maxEntryDecompressedBytes, "maxEntryDecompressedBytes",
          "pax extended header");
        var records = _parsePaxRecords(paxRead.body);
        if (hdr.typeflag !== TF_PAX_GLOBAL) {
          if (pendingPax) {
            throw new TarError("archive-tar/redundant-extended-header",
              "a second pax extended header precedes the same entry header; GNU tar keeps the " +
              "last one and bsdtar refuses the archive");
          }
          pendingPax = records;
        } else {
          var globalKey = _globalEntryAttribute(records);
          if (globalKey !== null) {
            throw new TarError("archive-tar/global-entry-attribute",
              "a pax global header carries the key " + JSON.stringify(globalKey) + "; GNU tar " +
              "applies it to every following entry and bsdtar refuses the archive");
          }
        }
        pos = paxRead.end;
        continue;
      }
      if (hdr.typeflag === TF_GNU_LONGNAME || hdr.typeflag === TF_GNU_LONGLINK) {
        var isLongName = hdr.typeflag === TF_GNU_LONGNAME;
        var longLabel = isLongName ? "GNU long-name (L) record" : "GNU long-link (K) record";
        if ((isLongName ? pendingLongName : pendingLongLink) !== null) {
          throw new TarError("archive-tar/bad-long-record",
            "a second " + longLabel + " precedes the same entry header");
        }
        var longCap = Math.min(bombPolicy.maxEntryDecompressedBytes, GNU_LONG_RECORD_MAX_BYTES);
        var longRead = _readExtensionBody(bytes, pos, hdr, longCap,
          longCap === GNU_LONG_RECORD_MAX_BYTES ? "the L / K record cap" : "maxEntryDecompressedBytes",
          longLabel);
        var longValue = _gnuLongValue(longRead.body, longLabel);
        if (isLongName) pendingLongName = longValue;
        else pendingLongLink = longValue;
        pos = longRead.end;
        continue;
      }
      if (TYPEFLAGS_BSDTAR_EXTENSION_ENTRY.indexOf(hdr.typeflag) !== -1 &&
          (pendingPax || pendingLongName !== null || pendingLongLink !== null)) {
        throw new TarError("archive-tar/dangling-extended-header",
          "a pax extended header or GNU L / K record precedes a " +
          (hdr.typeflag === TF_SOLARIS_ACL ? "Solaris ACL (A)" : "volume label (V)") +
          " header; GNU tar applies it to that header and bsdtar applies it to the entry after it");
      }
      var entryPax = pendingPax;
      var longName = pendingLongName;
      var longLink = pendingLongLink;
      pendingPax = null;
      pendingLongName = null;
      pendingLongLink = null;
      var headerSize = hdr.size;
      var paxSize = 0;
      if (entryPax) {
        if ("size" in entryPax) {
          paxSize = _paxSize(entryPax.size);
          hdr.size = paxSize;
        }
        if (entryPax.linkpath) hdr.linkname = entryPax.linkpath;
        var paxMtime = _paxTime(entryPax.mtime);
        if (paxMtime !== null) hdr.mtime = paxMtime;
      }
      var paxName = _paxEntryName(entryPax);
      if (paxName) hdr.name = paxName;
      hdr._gnuSparse = _hasSparseKey(entryPax) ||
        (hdr.typeflag !== TF_GNU_SPARSE && _oldGnuSparseFieldsSet(block));
      if (longName !== null) {
        if (paxName && paxName !== longName) {
          throw new TarError("archive-tar/long-name-pax-conflict",
            "entry name " + JSON.stringify(longName) + " from a GNU L record differs from pax name " +
            JSON.stringify(paxName) + "; GNU tar and bsdtar disagree on which one names the entry");
        }
        hdr.name = longName;
      }
      if (longLink !== null) {
        var paxLinkpath = entryPax && entryPax.linkpath;
        if (paxLinkpath && paxLinkpath !== longLink) {
          throw new TarError("archive-tar/long-name-pax-conflict",
            "link target " + JSON.stringify(longLink) + " from a GNU K record differs from pax linkpath " +
            JSON.stringify(paxLinkpath) + "; GNU tar and bsdtar disagree on which one is the target");
        }
        hdr.linkname = longLink;
      }
      if (paxName === null && longName === null && !hdr._nameIsUtf8) {
        throw new TarError("archive-tar/name-not-utf8",
          "entry header name " + JSON.stringify(hdr.name) + " is not valid UTF-8");
      }
      if ((hdr.typeflag === TF_SYMLINK || hdr.typeflag === TF_HARDLINK) && longLink === null &&
          !(entryPax && entryPax.linkpath) && !hdr._linknameIsUtf8) {
        throw new TarError("archive-tar/name-not-utf8",
          "entry " + JSON.stringify(hdr.name) + " has a header link target that is not valid UTF-8");
      }
      hdr._slashDirectory = TYPEFLAGS_SLASH_DIRECTORY.indexOf(hdr.typeflag) !== -1 &&
        hdr.name.charAt(hdr.name.length - 1) === "/";
      if ((TYPEFLAGS_WITHOUT_BODY.indexOf(hdr.typeflag) !== -1 || hdr._slashDirectory) &&
          (headerSize !== 0 || paxSize !== 0)) {
        throw new TarError("archive-tar/size-on-non-file",
          "entry " + JSON.stringify(hdr.name) + " with typeflag " + JSON.stringify(hdr.typeflag) +
          " declares size=" + (paxSize !== 0 ? paxSize : headerSize) + "; GNU tar and bsdtar do not " +
          "skip a body for a link, device, directory or FIFO entry");
      }
      if ((longLink !== null || (entryPax && entryPax.linkpath)) &&
          hdr.typeflag !== TF_SYMLINK && hdr.typeflag !== TF_HARDLINK) {
        throw new TarError("archive-tar/link-target-on-non-link",
          "entry " + JSON.stringify(hdr.name) + " with typeflag " + JSON.stringify(hdr.typeflag) +
          " carries a link target from a GNU K record or pax linkpath; bsdtar extracts such an " +
          "entry as a hardlink");
      }
      if (entries.length >= bombPolicy.maxEntries) {
        throw new TarError("archive-tar/too-many-entries",
          "archive has more than " + bombPolicy.maxEntries + " entries");
      }
      if (hdr.size > bombPolicy.maxEntryDecompressedBytes) {
        throw new TarError("archive-tar/entry-too-large",
          "entry " + JSON.stringify(hdr.name) +
          " size=" + hdr.size + " exceeds maxEntryDecompressedBytes=" +
          bombPolicy.maxEntryDecompressedBytes);
      }
      if (hdr.typeflag === TF_GNU_SPARSE && block[H_GNU_SPARSE_ISEXTENDED] !== 0) {
        pos = _skipGnuSparseExtensions(bytes, pos, block, hdr.name);
      }
      var bodyStart = pos;
      var paddedSize = Math.ceil(hdr.size / BLOCK_SIZE) * BLOCK_SIZE;
      if (bodyStart + paddedSize > bytes.length) {
        throw new TarError("archive-tar/truncated-entry",
          "entry " + JSON.stringify(hdr.name) +
          " declares size=" + hdr.size + " (padded=" + paddedSize +
          ") but only " + (bytes.length - bodyStart) +
          " bytes remain after header; archive truncated mid-stream");
      }
      hdr._bodyStart = bodyStart;
      hdr._paddedSize = paddedSize;
      entries.push(hdr);
      pos += paddedSize;
    }
    if (pendingPax || pendingLongName !== null || pendingLongLink !== null) {
      throw new TarError("archive-tar/dangling-extended-header",
        "archive ends after a pax extended header or GNU L / K record with no entry header " +
        "following it");
    }
    return { entries: entries, bytes: bytes };
  }

  async function inspect() {
    var walked = await _walk();
    var entries = walked.entries;
    return entries.map(function (e) {
      return {
        name:      e.name,
        size:      e.size,
        mtime:     new Date(e.mtime * C.TIME.seconds(1)),
        mode:      e.mode,
        typeflag:  e.typeflag,
        linkname:  e.linkname,
        uname:     e.uname,
        gname:     e.gname,
        entryType: _classifyEntry(e),
      };
    });
  }

  function _assertEntryTypeAllowed(entry, allowDangerous) {
    var type = _classifyEntry(entry);
    if (type === "device" || type === "fifo" || type === "socket") {
      throw new TarError("archive-tar/entry-type-refused",
        "entry " + JSON.stringify(entry.name) + " is a " + type +
        "; refused unconditionally (no application use case)");
    }
    if (type === "unknown" && entry._gnuSparse) {
      throw new TarError("archive-tar/entry-type-refused",
        "entry " + JSON.stringify(entry.name) + " is a sparse file (pax GNU.sparse.*, SCHILY.realsize " +
        "or SUN.holesdata keys, or old GNU sparse map, isextended or realsize header fields); " +
        "its stored body is a sparse map and data blocks, not the file contents");
    }
    if (type === "unknown") {
      throw new TarError("archive-tar/entry-type-refused",
        "entry " + JSON.stringify(entry.name) + " has typeflag " + JSON.stringify(entry.typeflag) +
        "; GNU sparse (S), multi-volume (M), volume label (V), Solaris ACL (A) and other typeflags the " +
        "reader does not interpret are refused");
    }
    if (type === "symlink" && !(allowDangerous.symlinks || entryTypePolicy.symlinks)) {
      throw new TarError("archive-tar/entry-type-refused",
        "entry " + JSON.stringify(entry.name) + " is a symlink; refused by entryTypePolicy " +
        "(opt in via allowDangerous: { symlinks: true })");
    }
    if (type === "hardlink" && !(allowDangerous.hardlinks || entryTypePolicy.hardlinks)) {
      throw new TarError("archive-tar/entry-type-refused",
        "entry " + JSON.stringify(entry.name) + " is a hardlink; refused by entryTypePolicy " +
        "(opt in via allowDangerous: { hardlinks: true })");
    }
    return type;
  }

  function _assertGuardMetadata(entries, auditAction) {
    if (opts.guardProfile === false) return;
    var profile = opts.guardProfile || "balanced";
    var guardEntries = entries.map(function (e) {
      var type = _classifyEntry(e);
      return {
        name:           e.name,
        size:           e.size,
        compressedSize: e.size,
        isSymlink:      type === "symlink",
        isHardlink:     type === "hardlink",
        linkTarget:     e.linkname,
        isDirectory:    type === "directory",
        isEncrypted:    false,
        attrs:          { mode: e.mode },
      };
    });
    var guardResult = guardArchive().validateEntries(guardEntries, { profile: profile });
    if (!guardResult || !Array.isArray(guardResult.issues)) return;
    var critical = guardResult.issues.filter(function (i) { return i.severity === "critical"; });
    if (critical.length === 0) return;
    _emitAudit(opts, auditAction, "refused", {
      entries: entries.length,
      issues:  critical.map(function (i) { return i.ruleId; }),
    });
    throw new TarError("archive-tar/guard-refused",
      "extract refused: " + critical.length + " critical guard issue(s)");
  }

  async function* extractEntries(extractOpts) {
    extractOpts = extractOpts || {};
    var allowDangerous = extractOpts.allowDangerous || {};
    var walked = await _walk();
    var entries = walked.entries;
    var bytes = walked.bytes;
    _assertGuardMetadata(entries, "archive.read.tar.extract_entries.refused");
    var totalDecompressed = 0;
    var yielded = 0;
    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      var type = _assertEntryTypeAllowed(entry, allowDangerous);
      if (type === "directory" || type === "symlink" || type === "hardlink") continue;
      var body = Buffer.from(bytes.subarray(entry._bodyStart, entry._bodyStart + entry.size));
      totalDecompressed += body.length;
      if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
        throw new TarError("archive-tar/total-too-large",
          "cumulative uncompressed=" + totalDecompressed +
          " exceeds maxTotalDecompressedBytes during extractEntries");
      }
      yielded += 1;
      yield { name: entry.name, bytes: body, size: body.length };
    }
    _emitAudit(opts, "archive.read.tar.extract_entries.completed", "success", { entries: yielded });
  }

  async function extract(extractOpts) {
    extractOpts = extractOpts || {};
    if (typeof extractOpts.destination !== "string" || extractOpts.destination.length === 0) {
      throw new TarError("archive-tar/no-destination",
        "extract: opts.destination must be non-empty string");
    }
    var destination = nodePath.resolve(extractOpts.destination);
    if (!nodeFs.existsSync(destination)) {
      nodeFs.mkdirSync(destination, { recursive: true });
    }
    var allowDangerous = extractOpts.allowDangerous || {};
    var walked = await _walk();
    var entries = walked.entries;
    var bytes = walked.bytes;
    _assertGuardMetadata(entries, "archive.read.tar.extract.refused");
    var written = [];
    var bytesExtracted = 0;
    var totalDecompressed = 0;
    try {
      for (var i = 0; i < entries.length; i += 1) {
        var entry = entries[i];
        var type = _assertEntryTypeAllowed(entry, allowDangerous);
        var resolvedPath = guardFilename().verifyExtractionPath(entry.name, destination);
        if (type === "directory") {
          nodeFs.mkdirSync(resolvedPath, { recursive: true });
          continue;
        }
        if (nodeFs.existsSync(resolvedPath)) {
          throw new TarError("archive-tar/destination-exists",
            "extract: destination file already exists at " +
            JSON.stringify(resolvedPath) + "; refusing to overwrite");
        }
        if (type === "symlink" || type === "hardlink") {
          guardFilename().verifyExtractionPath(entry.linkname, destination);
          if (type === "symlink") {
            nodeFs.symlinkSync(entry.linkname, resolvedPath);
          } else {
            var hardlinkTarget = nodePath.join(destination, entry.linkname);
            nodeFs.linkSync(hardlinkTarget, resolvedPath);
          }
          written.push({ name: entry.name, bytesWritten: 0, path: resolvedPath });
          continue;
        }
        var parentDir = nodePath.dirname(resolvedPath);
        if (!nodeFs.existsSync(parentDir)) {
          nodeFs.mkdirSync(parentDir, { recursive: true });
        }
        var body = bytes.slice(entry._bodyStart, entry._bodyStart + entry.size);
        totalDecompressed += body.length;
        if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
          throw new TarError("archive-tar/total-too-large",
            "cumulative uncompressed=" + totalDecompressed +
            " exceeds maxTotalDecompressedBytes during extract");
        }
        atomicFile.writeSync(resolvedPath, body);
        written.push({ name: entry.name, bytesWritten: body.length, path: resolvedPath });
        bytesExtracted += body.length;
      }
    } catch (extractErr) {
      try {
        for (var w = 0; w < written.length; w += 1) {
          if (nodeFs.existsSync(written[w].path)) {
            nodeFs.rmSync(written[w].path);
          }
        }
      } catch (_e) { /* drop-silent */ }
      _emitAudit(opts, "archive.read.tar.extract.aborted", "failure", {
        entries: entries.length,
        written: written.length,
        error:   extractErr && (extractErr.code || extractErr.message),
      });
      throw extractErr;
    }
    _emitAudit(opts, "archive.read.tar.extract.completed", "success", {
      entries:        entries.length,
      bytesExtracted: bytesExtracted,
    });
    return {
      entries:         written,
      destinationRoot: destination,
      bytesExtracted:  bytesExtracted,
    };
  }

  return {
    kind:           "tar-reader",
    inspect:        inspect,
    extract:        extract,
    extractEntries: extractEntries,
  };
}

module.exports = {
  tar:                       tar,
  DEFAULT_BOMB_POLICY:       DEFAULT_BOMB_POLICY,
  DEFAULT_ENTRY_TYPE_POLICY: DEFAULT_ENTRY_TYPE_POLICY,
};
