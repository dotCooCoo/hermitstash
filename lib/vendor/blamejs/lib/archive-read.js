// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var nodeBuffer = require("node:buffer");
var zlib = require("node:zlib");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");
var numericBounds = require("./numeric-bounds");
var atomicFile = require("./atomic-file");

var ArchiveReadError = defineClass("ArchiveReadError", { alwaysPermanent: true });

// Lazy because guard-archive + guard-filename pull in the full
// guard-family validator chain — the reader's read-only paths don't
// need them; only extract() does.
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var guardArchive  = lazyRequire(function () { return require("./guard-archive"); });
var safeDecompress = lazyRequire(function () { return require("./safe-decompress"); });
var safeBuffer     = lazyRequire(function () { return require("./safe-buffer"); });
var archiveAdapters = lazyRequire(function () { return require("./archive-adapters"); });
var archiveEntryPolicy = require("./archive-entry-policy");
var auditEmit = require("./audit-emit");

var SIG_LFH                 = 0x04034b50;
var SIG_CFH                 = 0x02014b50;
var SIG_EOCD                = 0x06054b50;
var SIG_EOCD64              = 0x06064b50;
var SIG_EOCD64_LOCATOR      = 0x07064b50;
var SIG_DATA_DESCRIPTOR     = 0x08074b50;

var ZIP64_U16_SENTINEL      = 0xffff;
var ZIP64_U32_SENTINEL      = 0xffffffff;

var EOCD64_LOCATOR_BYTES    = C.BYTES.bytes(20);
var EOCD64_FIXED_BYTES      = C.BYTES.bytes(56);
var EOCD64_LEAD_BYTES       = C.BYTES.bytes(12);
var ZIP64_EXTRA_HEADER_ID   = 0x0001;
var EXTRA_FIELD_HEADER_BYTES= C.BYTES.bytes(4);
var UNICODE_PATH_EXTRA_ID   = 0x7075;
var UNICODE_PATH_VERSION    = 1;
var UNICODE_PATH_FIXED_BYTES= C.BYTES.bytes(5);
var LFH_READ_WINDOW_BYTES   = C.BYTES.kib(64);
var CP437_FIRST_HIGH_BYTE   = 0x80;
var CP437_HIGH_HALF         = [
  0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
  0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
  0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
  0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
  0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
  0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

var METHOD_STORE_ID         = 0;
var METHOD_DEFLATE_ID       = 8;

var FLAG_ENCRYPTED          = 0x0001;
var FLAG_DATA_DESCRIPTOR    = 0x0008;
var FLAG_STRONG_ENCRYPTION  = 0x0040;
var FLAG_MASKED_LOCAL_HEADER= 0x2000;
var FLAG_UTF8_NAME          = 0x0800;
var FLAGS_THAT_MUST_AGREE   = FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR |
                              FLAG_STRONG_ENCRYPTION | FLAG_MASKED_LOCAL_HEADER |
                              FLAG_UTF8_NAME;
var SLASH_BYTE              = 0x2f;

var DD_SIG_BYTES            = C.BYTES.bytes(4);
var DD_NARROW_BYTES         = C.BYTES.bytes(12);
var DD_WIDE_BYTES           = C.BYTES.bytes(20);
var DD_MAX_BYTES            = DD_SIG_BYTES + DD_WIDE_BYTES;

var EOCD_MIN_BYTES          = C.BYTES.bytes(22);
var EOCD_MAX_COMMENT_BYTES  = C.BYTES.kib(64);
var EOCD_SCAN_BYTES         = EOCD_MIN_BYTES + EOCD_MAX_COMMENT_BYTES;

var LFH_FIXED_BYTES         = C.BYTES.bytes(30);
var CFH_FIXED_BYTES         = C.BYTES.bytes(46);

var EMBEDDED_SCAN_WINDOW_BYTES = C.BYTES.mib(1);
var ZIP_SIGNATURE_LEAD      = Buffer.from([0x50, 0x4b]);
var DD_SIGNATURE_BYTES      = Buffer.from([0x50, 0x4b, 0x07, 0x08]);
var DD_CRC_FIELD_BYTES      = C.BYTES.bytes(4);
var DD_DENSE_RUN_BYTES      = C.BYTES.bytes(256);
var CRC32_REFLECTED_POLY    = 0xedb88320;
var CRC32_SLICES            = 4;
var CRC32_SLICE_STRIDE      = 256;
var CRC32_SLICE_1           = CRC32_SLICE_STRIDE;
var CRC32_SLICE_2           = CRC32_SLICE_STRIDE * 2;
var CRC32_SLICE_3           = CRC32_SLICE_STRIDE * 3;
var CRC32_SLICE_TABLE       = _buildCrc32SliceTable();
var KNOWN_METHOD_IDS        = Object.freeze([
  0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 16, 18, 19, 20, 93, 94, 95, 96, 97, 98, 99,
]);

var MSDOS_EPOCH_YEAR        = 1980;

var DEFAULT_BOMB_POLICY = Object.freeze({
  maxEntries:                1048576,
  maxEntryDecompressedBytes: C.BYTES.mib(128),
  maxTotalDecompressedBytes: C.BYTES.gib(4),
  maxExpansionRatio:         100,
});

var DEFAULT_ENTRY_TYPE_POLICY = archiveEntryPolicy.DEFAULT_ENTRY_TYPE_POLICY;

function _msdosToDate(dosDate, dosTime) {
  var year   = ((dosDate >>> 9)  & 0x7f) + MSDOS_EPOCH_YEAR;
  var month  = ((dosDate >>> 5)  & 0x0f) - 1;
  var day    = (dosDate          & 0x1f);
  var hour   = ((dosTime >>> 11) & 0x1f);
  var minute = ((dosTime >>> 5)  & 0x3f);
  var second = (dosTime          & 0x1f) * 2;
  return new Date(year, month, day, hour, minute, second);
}

function _readZip64U64(buf, off, fieldLabel) {
  var big = buf.readBigUInt64LE(off);
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ArchiveReadError("archive-read/zip64-value-too-large",
      "ZIP64 " + fieldLabel + "=" + big.toString() +
      " exceeds the addressable Number.MAX_SAFE_INTEGER ceiling");
  }
  return Number(big);
}

function _isUnixSymlinkAttrs(externalAttrs) {
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0xa000;
}

function _isUnixSocketAttrs(externalAttrs) {
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0xc000;
}

function _isUnixFifoAttrs(externalAttrs) {
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0x1000;
}

function _isUnixCharDevAttrs(externalAttrs) {
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0x2000;
}

function _isUnixBlockDevAttrs(externalAttrs) {
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0x6000;
}

function _isDirectoryEntry(name, externalAttrs) {
  if (name.length > 0 && name[name.length - 1] === "/") return true;
  var unixMode = (externalAttrs >>> 16) & 0xffff;
  if ((unixMode & 0xf000) === 0x4000) return true;
  return false;
}

function _classifyEntryType(entry) {
  if (_isUnixSymlinkAttrs(entry.externalAttrs))  return "symlink";
  if (_isUnixSocketAttrs(entry.externalAttrs))   return "socket";
  if (_isUnixFifoAttrs(entry.externalAttrs))     return "fifo";
  if (_isUnixCharDevAttrs(entry.externalAttrs))  return "device";
  if (_isUnixBlockDevAttrs(entry.externalAttrs)) return "device";
  if (_isDirectoryEntry(entry.name, entry.externalAttrs)) return "directory";
  return "file";
}

async function _locateEocd(adapter) {
  var size = adapter.size;
  if (size == null && typeof adapter.resolveSize === "function") {
    size = await adapter.resolveSize();
  }
  if (typeof size !== "number" || size < EOCD_MIN_BYTES) {
    throw new ArchiveReadError("archive-read/too-small",
      "ZIP file too small to contain EOCD record (size=" + size + ", min=" + EOCD_MIN_BYTES + ")");
  }
  var scanLen = Math.min(EOCD_SCAN_BYTES, size);
  var scanOffset = size - scanLen;
  var tail = await adapter.range(scanOffset, scanLen);
  for (var i = tail.length - EOCD_MIN_BYTES; i >= 0; i -= 1) {
    if (tail.readUInt32LE(i) === SIG_EOCD) {
      var commentLen = tail.readUInt16LE(i + 20);
      if (i + EOCD_MIN_BYTES + commentLen === tail.length) {
        var eocd = {
          eocdOffset:           scanOffset + i,
          diskNumber:           tail.readUInt16LE(i + 4),
          cdDiskNumber:         tail.readUInt16LE(i + 6),
          entriesOnThisDisk:    tail.readUInt16LE(i + 8),
          totalEntries:         tail.readUInt16LE(i + 10),
          cdSize:               tail.readUInt32LE(i + 12),
          cdOffset:             tail.readUInt32LE(i + 16),
          commentLength:        commentLen,
          isZip64:              false,
          eocd64Offset:         null,
          archiveSize:          size,
        };
        if (eocd.entriesOnThisDisk !== eocd.totalEntries) {
          throw new ArchiveReadError("archive-read/eocd-inconsistent",
            "EOCD entries-on-this-disk=" + eocd.entriesOnThisDisk +
            " disagrees with total entries=" + eocd.totalEntries + " on a single-disk archive");
        }
        await _refuseEmbeddedStructures(adapter, eocd.eocdOffset + EOCD_MIN_BYTES, size, size,
          "in the EOCD comment", true);
        if (_hasZip64Sentinel(eocd) || await _hasZip64Locator(adapter, eocd.eocdOffset)) {
          await _resolveZip64Eocd(adapter, eocd, size);
        }
        return eocd;
      }
    }
  }
  throw new ArchiveReadError("archive-read/no-eocd",
    "End-of-central-directory record not found in trailing " + scanLen + " bytes");
}

function _hasZip64Sentinel(eocd) {
  return eocd.totalEntries === ZIP64_U16_SENTINEL ||
    eocd.cdSize === ZIP64_U32_SENTINEL ||
    eocd.cdOffset === ZIP64_U32_SENTINEL;
}

async function _hasZip64Locator(adapter, eocdOffset) {
  if (eocdOffset < EOCD64_LOCATOR_BYTES) return false;
  var probe = await adapter.range(eocdOffset - EOCD64_LOCATOR_BYTES, C.BYTES.bytes(4));
  return probe.length === C.BYTES.bytes(4) && probe.readUInt32LE(0) === SIG_EOCD64_LOCATOR;
}

function _requireClassicAgrees(classicValue, sentinel, zip64Value, fieldLabel) {
  if (classicValue === sentinel) return;
  if (classicValue !== zip64Value) {
    throw new ArchiveReadError("archive-read/eocd-inconsistent",
      "classic EOCD " + fieldLabel + "=" + classicValue +
      " disagrees with the ZIP64 EOCD record value " + zip64Value);
  }
}

async function _resolveZip64Eocd(adapter, eocd, archiveSize) {
  var locatorOffset = eocd.eocdOffset - EOCD64_LOCATOR_BYTES;
  if (locatorOffset < 0) {
    throw new ArchiveReadError("archive-read/zip64-locator-missing",
      "classic EOCD carries a ZIP64 sentinel but no room for the ZIP64 locator before it");
  }
  var locator = await adapter.range(locatorOffset, EOCD64_LOCATOR_BYTES);
  if (locator.readUInt32LE(0) !== SIG_EOCD64_LOCATOR) {
    throw new ArchiveReadError("archive-read/zip64-locator-missing",
      "expected ZIP64 EOCD locator signature before classic EOCD, got 0x" +
      locator.readUInt32LE(0).toString(16));
  }
  if (locator.readUInt32LE(4) !== 0 || locator.readUInt32LE(16) > 1) {
    throw new ArchiveReadError("archive-read/multi-disk",
      "multi-disk ZIP64 archives are not supported (totalDisks=" +
      locator.readUInt32LE(16) + ")");
  }
  var eocd64Offset = _readZip64U64(locator, 8, "EOCD64 record offset");
  if (eocd64Offset + EOCD64_FIXED_BYTES > archiveSize) {
    throw new ArchiveReadError("archive-read/zip64-eocd-out-of-range",
      "ZIP64 EOCD record offset=" + eocd64Offset + " overflows archive size=" + archiveSize);
  }
  var rec = await adapter.range(eocd64Offset, EOCD64_FIXED_BYTES);
  if (rec.readUInt32LE(0) !== SIG_EOCD64) {
    throw new ArchiveReadError("archive-read/zip64-eocd-bad-signature",
      "ZIP64 EOCD record has bad signature 0x" + rec.readUInt32LE(0).toString(16));
  }
  var recordSize = _readZip64U64(rec, 4, "EOCD64 record size");
  if (recordSize < EOCD64_FIXED_BYTES - EOCD64_LEAD_BYTES ||
      eocd64Offset + EOCD64_LEAD_BYTES + recordSize !== locatorOffset) {
    throw new ArchiveReadError("archive-read/zip64-eocd-not-adjacent",
      "ZIP64 EOCD record at offset=" + eocd64Offset + " with size=" + recordSize +
      " does not end at the ZIP64 locator (offset=" + locatorOffset + ")");
  }
  var entriesOnDisk = _readZip64U64(rec, 24, "entriesOnThisDisk");
  var totalEntries  = _readZip64U64(rec, 32, "totalEntries");
  var cdSize        = _readZip64U64(rec, 40, "centralDirSize");
  var cdOffset      = _readZip64U64(rec, 48, "centralDirOffset");
  if (entriesOnDisk !== totalEntries) {
    throw new ArchiveReadError("archive-read/eocd-inconsistent",
      "ZIP64 EOCD entries-on-this-disk=" + entriesOnDisk +
      " disagrees with total entries=" + totalEntries + " on a single-disk archive");
  }
  _requireClassicAgrees(eocd.totalEntries, ZIP64_U16_SENTINEL, totalEntries, "totalEntries");
  _requireClassicAgrees(eocd.cdSize, ZIP64_U32_SENTINEL, cdSize, "centralDirSize");
  _requireClassicAgrees(eocd.cdOffset, ZIP64_U32_SENTINEL, cdOffset, "centralDirOffset");
  eocd.diskNumber   = rec.readUInt32LE(16);
  eocd.cdDiskNumber = rec.readUInt32LE(20);
  eocd.totalEntries = totalEntries;
  eocd.cdSize       = cdSize;
  eocd.cdOffset     = cdOffset;
  eocd.eocd64Offset = eocd64Offset;
  eocd.isZip64      = true;
}

function _applyZip64Extra(classic, extraFields) {
  var resolved = {
    uncompressedSize: classic.uncompressedSize,
    compressedSize:   classic.compressedSize,
    lfhOffset:        classic.lfhOffset,
  };
  var needUncompressed = classic.uncompressedSize === ZIP64_U32_SENTINEL;
  var needCompressed   = classic.compressedSize   === ZIP64_U32_SENTINEL;
  var needLfhOffset    = classic.lfhOffset        === ZIP64_U32_SENTINEL;
  var needDiskStart    = classic.diskStart        === ZIP64_U16_SENTINEL;
  if (!needUncompressed && !needCompressed && !needLfhOffset && !needDiskStart) {
    return resolved;
  }
  var p = 0;
  while (p + EXTRA_FIELD_HEADER_BYTES <= extraFields.length) {
    var id   = extraFields.readUInt16LE(p);
    var dataSize = extraFields.readUInt16LE(p + 2);
    var dataStart = p + EXTRA_FIELD_HEADER_BYTES;
    if (dataStart + dataSize > extraFields.length) break;
    if (id === ZIP64_EXTRA_HEADER_ID) {
      var q = dataStart;
      var end = dataStart + dataSize;
      if (needUncompressed) {
        if (q + 8 > end) {
          throw new ArchiveReadError("archive-read/zip64-extra-truncated",
            "ZIP64 extra field too short for uncompressedSize");
        }
        resolved.uncompressedSize = _readZip64U64(extraFields, q, "extra uncompressedSize");
        q += 8;
      }
      if (needCompressed) {
        if (q + 8 > end) {
          throw new ArchiveReadError("archive-read/zip64-extra-truncated",
            "ZIP64 extra field too short for compressedSize");
        }
        resolved.compressedSize = _readZip64U64(extraFields, q, "extra compressedSize");
        q += 8;
      }
      if (needLfhOffset) {
        if (q + 8 > end) {
          throw new ArchiveReadError("archive-read/zip64-extra-truncated",
            "ZIP64 extra field too short for localHeaderOffset");
        }
        resolved.lfhOffset = _readZip64U64(extraFields, q, "extra localHeaderOffset");
        q += 8;
      }
      if (needDiskStart) {
        if (q + 4 > end) {
          throw new ArchiveReadError("archive-read/zip64-extra-truncated",
            "ZIP64 extra field too short for diskStart");
        }
        if (extraFields.readUInt32LE(q) !== 0) {
          throw new ArchiveReadError("archive-read/multi-disk",
            "ZIP64 entry references a non-zero disk start (multi-disk unsupported)");
        }
        q += 4;
      }
      return resolved;
    }
    p = dataStart + dataSize;
  }
  throw new ArchiveReadError("archive-read/zip64-extra-missing",
    "central directory entry carries a ZIP64 sentinel size but no ZIP64 extended-information extra field (id 0x0001)");
}

function _effectiveNameBytes(extraFields, nameBytes, generalFlags, where) {
  var found = null;
  var p = 0;
  while (p + EXTRA_FIELD_HEADER_BYTES <= extraFields.length) {
    var id = extraFields.readUInt16LE(p);
    var dataSize = extraFields.readUInt16LE(p + 2);
    var dataStart = p + EXTRA_FIELD_HEADER_BYTES;
    if (dataStart + dataSize > extraFields.length) {
      if (id === UNICODE_PATH_EXTRA_ID) {
        _refuseUnicodePath(where, nameBytes, "declares " + dataSize + " byte(s) of data, more than the " +
          (extraFields.length - dataStart) + " left in the extra block");
      }
      break;
    }
    if (id === UNICODE_PATH_EXTRA_ID) {
      if (found) _refuseUnicodePath(where, nameBytes, "appears more than once");
      found = extraFields.subarray(dataStart, dataStart + dataSize);
    }
    p = dataStart + dataSize;
  }
  if (p + 2 <= extraFields.length && p + EXTRA_FIELD_HEADER_BYTES > extraFields.length &&
      extraFields.readUInt16LE(p) === UNICODE_PATH_EXTRA_ID) {
    _refuseUnicodePath(where, nameBytes, "is cut off by the end of the extra block");
  }
  if (!found) return nameBytes;
  if (found.length < UNICODE_PATH_FIXED_BYTES) {
    _refuseUnicodePath(where, nameBytes, "is " + found.length + " byte(s), shorter than its version and CRC-32");
  }
  if (found[0] !== UNICODE_PATH_VERSION) _refuseUnicodePath(where, nameBytes, "has version " + found[0]);
  if (found.readUInt32LE(1) !== (zlib.crc32(nameBytes) >>> 0)) return nameBytes;
  var unicodePath = found.subarray(UNICODE_PATH_FIXED_BYTES);
  if (unicodePath.length === 0) _refuseUnicodePath(where, nameBytes, "holds an empty path");
  if (!nodeBuffer.isUtf8(unicodePath)) _refuseUnicodePath(where, nameBytes, "holds a path that is not valid UTF-8");
  if (unicodePath.equals(nameBytes)) return nameBytes;
  if ((generalFlags & FLAG_UTF8_NAME) !== 0) {
    _refuseUnicodePath(where, nameBytes, "names " + JSON.stringify(unicodePath.toString("utf8")) +
      " while general-purpose flag bit 11 marks the name field as UTF-8");
  }
  var nameIsDirectory = nameBytes.length > 0 && nameBytes[nameBytes.length - 1] === SLASH_BYTE;
  if ((unicodePath[unicodePath.length - 1] === SLASH_BYTE) !== nameIsDirectory) {
    _refuseUnicodePath(where, nameBytes, "names " + JSON.stringify(unicodePath.toString("utf8")) +
      ", and only one of the two names ends in a slash");
  }
  return unicodePath;
}

function _decodeCp437(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i += 1) {
    out += String.fromCharCode(bytes[i] < CP437_FIRST_HIGH_BYTE
      ? bytes[i] : CP437_HIGH_HALF[bytes[i] - CP437_FIRST_HIGH_BYTE]);
  }
  return out;
}

function _nameFieldDecodes(nameBytes, name, generalFlags) {
  var decodes = [];
  if ((generalFlags & FLAG_UTF8_NAME) !== 0) return decodes;
  var cp437 = _decodeCp437(nameBytes);
  if (cp437 !== name) decodes.push(cp437);
  if (nodeBuffer.isUtf8(nameBytes)) {
    var utf8 = nameBytes.toString("utf8");
    if (utf8 !== name && utf8 !== cp437) decodes.push(utf8);
  }
  return decodes;
}

function _refuseUnicodePath(where, nameBytes, problem) {
  throw new ArchiveReadError("archive-read/unicode-path-mismatch",
    where + " for " + JSON.stringify(nameBytes.toString("utf8")) +
    " has an Info-ZIP Unicode Path extra field (0x7075) that " + problem);
}

function _windowedRange(adapter, archiveSize) {
  var windowStart = 0;
  var windowBuf = null;
  return async function range(offset, length) {
    if (windowBuf && offset >= windowStart && offset + length <= windowStart + windowBuf.length) {
      return windowBuf.subarray(offset - windowStart, offset - windowStart + length);
    }
    var readLength = Math.max(length, Math.min(LFH_READ_WINDOW_BYTES, archiveSize - offset));
    var buf = await adapter.range(offset, readLength);
    windowStart = offset;
    windowBuf = buf;
    return buf.subarray(0, length);
  };
}

async function _readCentralDirectory(adapter, eocd) {
  if (eocd.diskNumber !== 0 || eocd.cdDiskNumber !== 0) {
    throw new ArchiveReadError("archive-read/multi-disk",
      "multi-disk archives are not supported (diskNumber=" + eocd.diskNumber + ")");
  }
  if (eocd.totalEntries === ZIP64_U16_SENTINEL ||
      eocd.cdSize === ZIP64_U32_SENTINEL ||
      eocd.cdOffset === ZIP64_U32_SENTINEL) {
    throw new ArchiveReadError("archive-read/zip64-eocd-unresolved",
      "classic EOCD carries a ZIP64 sentinel but the ZIP64 EOCD record did not resolve it");
  }
  var cdEnd = eocd.isZip64 ? eocd.eocd64Offset : eocd.eocdOffset;
  if (eocd.cdOffset + eocd.cdSize !== cdEnd) {
    throw new ArchiveReadError("archive-read/cd-position-mismatch",
      "central directory at offset=" + eocd.cdOffset + " size=" + eocd.cdSize +
      " does not end where the " + (eocd.isZip64 ? "ZIP64 EOCD record" : "EOCD record") +
      " begins (offset=" + cdEnd + "); prepended data, trailing data before the EOCD, " +
      "or a second archive body is present");
  }
  if (eocd.cdSize === 0 || eocd.totalEntries === 0) {
    if (eocd.cdSize !== 0 || eocd.totalEntries !== 0) {
      throw new ArchiveReadError("archive-read/cd-size-mismatch",
        "EOCD records totalEntries=" + eocd.totalEntries + " over a central directory of " +
        eocd.cdSize + " bytes");
    }
    await _refuseEmbeddedArchive(adapter, eocd.cdOffset, eocd.archiveSize);
    return [];
  }
  var cdBytes = await adapter.range(eocd.cdOffset, eocd.cdSize);
  var entries = [];
  var pos = 0;
  for (var n = 0; n < eocd.totalEntries; n += 1) {
    if (pos + CFH_FIXED_BYTES > cdBytes.length) {
      throw new ArchiveReadError("archive-read/cd-truncated",
        "central directory truncated at entry " + n + "/" + eocd.totalEntries);
    }
    if (cdBytes.readUInt32LE(pos) !== SIG_CFH) {
      throw new ArchiveReadError("archive-read/bad-cd-signature",
        "central directory entry " + n + " has bad signature " +
        "0x" + cdBytes.readUInt32LE(pos).toString(16));
    }
    var generalFlags     = cdBytes.readUInt16LE(pos + 8);
    var method           = cdBytes.readUInt16LE(pos + 10);
    var dosTime          = cdBytes.readUInt16LE(pos + 12);
    var dosDate          = cdBytes.readUInt16LE(pos + 14);
    var crc32            = cdBytes.readUInt32LE(pos + 16);
    var compressedSize   = cdBytes.readUInt32LE(pos + 20);
    var uncompressedSize = cdBytes.readUInt32LE(pos + 24);
    var nameLen          = cdBytes.readUInt16LE(pos + 28);
    var extraLen         = cdBytes.readUInt16LE(pos + 30);
    var commentLen       = cdBytes.readUInt16LE(pos + 32);
    var diskStart        = cdBytes.readUInt16LE(pos + 34);
    var externalAttrs    = cdBytes.readUInt32LE(pos + 38);
    var lfhOffset        = cdBytes.readUInt32LE(pos + 42);
    var nameStart        = pos + CFH_FIXED_BYTES;
    var extraStart       = nameStart + nameLen;
    var totalLen         = CFH_FIXED_BYTES + nameLen + extraLen + commentLen;
    if (pos + totalLen > cdBytes.length) {
      throw new ArchiveReadError("archive-read/cd-truncated",
        "central directory entry " + n + " variable-length fields overflow CD");
    }
    var nameBytes = cdBytes.slice(nameStart, nameStart + nameLen);
    var extraFields = cdBytes.slice(extraStart, extraStart + extraLen);
    if ((generalFlags & FLAG_UTF8_NAME) !== 0 && !nodeBuffer.isUtf8(nameBytes)) {
      throw new ArchiveReadError("archive-read/bad-utf8-name",
        "central directory entry " + n + " sets general-purpose flag bit 11 (UTF-8 name), but its name field " +
        JSON.stringify(_decodeCp437(nameBytes)) + " (shown in code page 437) is not valid UTF-8");
    }
    var effectiveNameBytes = _effectiveNameBytes(extraFields, nameBytes, generalFlags,
      "central directory entry " + n);
    var name = nodeBuffer.isUtf8(effectiveNameBytes)
      ? effectiveNameBytes.toString("utf8") : _decodeCp437(effectiveNameBytes);
    var altNames = _nameFieldDecodes(nameBytes, name, generalFlags);
    var resolved = _applyZip64Extra({
      uncompressedSize: uncompressedSize,
      compressedSize:   compressedSize,
      lfhOffset:        lfhOffset,
      diskStart:        diskStart,
    }, extraFields);
    entries.push({
      name:             name,
      altNames:         altNames,
      method:           method,
      generalFlags:     generalFlags,
      crc:              crc32,
      compressedSize:   resolved.compressedSize,
      uncompressedSize: resolved.uncompressedSize,
      mtime:            _msdosToDate(dosDate, dosTime),
      externalAttrs:    externalAttrs,
      extraFields:      extraFields,
      lfhOffset:        resolved.lfhOffset,
      isEncrypted:      (generalFlags & FLAG_ENCRYPTED) !== 0,
      hasDataDescriptor:(generalFlags & FLAG_DATA_DESCRIPTOR) !== 0,
      _nameBytes:       nameBytes,
      _effectiveNameBytes: effectiveNameBytes,
      _entryType:       null,
      _spanLimit:       null,
      _dataStart:       null,
    });
    pos += totalLen;
  }
  if (pos !== eocd.cdSize) {
    throw new ArchiveReadError("archive-read/cd-size-mismatch",
      "central directory holds " + (eocd.cdSize - pos) + " byte(s) past the " +
      eocd.totalEntries + " entries the EOCD records");
  }
  var firstLocal = _assignEntrySpans(entries, eocd.cdOffset);
  await _refuseEmbeddedArchive(adapter, firstLocal, eocd.archiveSize);
  return entries;
}

function _embeddedStructureAt(buf, i, abs, archiveSize, anyEocd) {
  var sig = buf.readUInt32LE(i);
  if (sig === SIG_LFH) {
    if (i + LFH_FIXED_BYTES > buf.length) return null;
    if (KNOWN_METHOD_IDS.indexOf(buf.readUInt16LE(i + 8)) === -1) return null;
    var lfhNameLen = buf.readUInt16LE(i + 26);
    var lfhHeaderEnd = abs + LFH_FIXED_BYTES + lfhNameLen + buf.readUInt16LE(i + 28);
    if (lfhNameLen === 0 || lfhHeaderEnd > archiveSize) return null;
    var lfhCsize = buf.readUInt32LE(i + 18);
    if ((buf.readUInt16LE(i + 6) & FLAG_DATA_DESCRIPTOR) === 0 && lfhCsize !== ZIP64_U32_SENTINEL &&
        lfhHeaderEnd + lfhCsize > archiveSize) {
      return null;
    }
    return "local file header";
  }
  if (sig === SIG_CFH) {
    if (i + CFH_FIXED_BYTES > buf.length) return null;
    if (KNOWN_METHOD_IDS.indexOf(buf.readUInt16LE(i + 10)) === -1) return null;
    var cfhNameLen = buf.readUInt16LE(i + 28);
    var cfhEnd = abs + CFH_FIXED_BYTES + cfhNameLen + buf.readUInt16LE(i + 30) + buf.readUInt16LE(i + 32);
    if (cfhNameLen === 0 || cfhEnd > archiveSize) return null;
    var cfhLocal = buf.readUInt32LE(i + 42);
    var cfhCsize = buf.readUInt32LE(i + 20);
    if (cfhLocal !== ZIP64_U32_SENTINEL) {
      if (cfhLocal >= abs) return null;
      if (cfhCsize !== ZIP64_U32_SENTINEL && cfhLocal + LFH_FIXED_BYTES + cfhCsize > abs) return null;
    }
    return "central directory header";
  }
  if (sig === SIG_EOCD) {
    if (i + EOCD_MIN_BYTES > buf.length) return null;
    if (anyEocd) return "end-of-central-directory record";
    if (buf.readUInt16LE(i + 4) !== 0 || buf.readUInt16LE(i + 6) !== 0) return null;
    if (buf.readUInt16LE(i + 8) !== buf.readUInt16LE(i + 10)) return null;
    if (buf.readUInt32LE(i + 16) + buf.readUInt32LE(i + 12) !== abs) return null;
    return "end-of-central-directory record";
  }
  return null;
}

async function _refuseEmbeddedStructures(adapter, start, end, archiveSize, where, anyEocd, checkAbort) {
  var windowStart = start;
  while (windowStart < end) {
    if (checkAbort) checkAbort();
    var windowEnd = Math.min(windowStart + EMBEDDED_SCAN_WINDOW_BYTES, end);
    var readEnd = Math.min(windowEnd + CFH_FIXED_BYTES, archiveSize);
    var buf = await adapter.range(windowStart, readEnd - windowStart);
    var i = buf.indexOf(ZIP_SIGNATURE_LEAD);
    while (i !== -1 && windowStart + i < windowEnd) {
      if (i + C.BYTES.bytes(4) <= buf.length) {
        var kind = _embeddedStructureAt(buf, i, windowStart + i, archiveSize, anyEocd);
        if (kind) {
          throw new ArchiveReadError("archive-read/embedded-archive",
            "the bytes " + where + " hold a ZIP " + kind + " at offset=" + (windowStart + i) +
            "; a second archive is present");
        }
      }
      i = buf.indexOf(ZIP_SIGNATURE_LEAD, i + 1);
    }
    windowStart = windowEnd;
  }
}

function _refuseEmbeddedArchive(adapter, prefixEnd, archiveSize) {
  return _refuseEmbeddedStructures(adapter, 0, prefixEnd, archiveSize,
    "before the first local header the central directory references (offset=" + prefixEnd + ")", false);
}

async function _verifyLocalLayout(adapter, entries, archiveSize, checkAbort) {
  var windowed = { range: _windowedRange(adapter, archiveSize) };
  var order = entries.slice().sort(function (x, y) { return x.lfhOffset - y.lfhOffset; });
  for (var i = 0; i < order.length; i += 1) {
    checkAbort();
    var entry = order[i];
    var local = await _verifyLfhMatchesCd(windowed, entry);
    entry._dataStart = local.dataStart;
    await _refuseEmbeddedStructures(windowed, local.layoutEnd, entry._spanLimit, archiveSize,
      "after entry " + JSON.stringify(entry.name) + " and before offset=" + entry._spanLimit, false, checkAbort);
  }
}

function _assignEntrySpans(entries, cdOffset) {
  var order = entries.slice().sort(function (x, y) { return x.lfhOffset - y.lfhOffset; });
  for (var i = 0; i < order.length; i += 1) {
    var e = order[i];
    if (e.lfhOffset >= cdOffset) {
      throw new ArchiveReadError("archive-read/entry-out-of-range",
        "entry " + JSON.stringify(e.name) + " local header offset=" + e.lfhOffset +
        " is not before the central directory (offset=" + cdOffset + ")");
    }
    var limit = cdOffset;
    if (i + 1 < order.length && order[i + 1].lfhOffset < limit) limit = order[i + 1].lfhOffset;
    if (e.lfhOffset + LFH_FIXED_BYTES + e.compressedSize > limit) {
      throw new ArchiveReadError("archive-read/entry-overlap",
        "entry " + JSON.stringify(e.name) + " at offset=" + e.lfhOffset +
        " with compressedSize=" + e.compressedSize +
        " overlaps the next local header or the central directory (offset=" + limit + ")");
    }
    e._spanLimit = limit;
  }
  return order.length > 0 ? order[0].lfhOffset : cdOffset;
}

async function _verifyLfhMatchesCd(adapter, entry) {
  var lfhPrefix = await adapter.range(entry.lfhOffset, LFH_FIXED_BYTES);
  if (lfhPrefix.readUInt32LE(0) !== SIG_LFH) {
    throw new ArchiveReadError("archive-read/bad-lfh-signature",
      "local file header for " + JSON.stringify(entry.name) +
      " has bad signature 0x" + lfhPrefix.readUInt32LE(0).toString(16));
  }
  var lfhFlags   = lfhPrefix.readUInt16LE(6);
  var lfhMethod  = lfhPrefix.readUInt16LE(8);
  var lfhCrc     = lfhPrefix.readUInt32LE(14);
  var lfhCsize   = lfhPrefix.readUInt32LE(18);
  var lfhUsize   = lfhPrefix.readUInt32LE(22);
  var lfhNameLen = lfhPrefix.readUInt16LE(26);
  var lfhExtraLen= lfhPrefix.readUInt16LE(28);
  var hasDataDescriptor = entry.hasDataDescriptor;
  if (lfhMethod !== entry.method) {
    throw new ArchiveReadError("archive-read/lfh-cd-skew",
      "entry " + JSON.stringify(entry.name) + " method skew: LFH=" +
      lfhMethod + " CD=" + entry.method);
  }
  if ((lfhFlags & FLAGS_THAT_MUST_AGREE) !== (entry.generalFlags & FLAGS_THAT_MUST_AGREE)) {
    throw new ArchiveReadError("archive-read/lfh-cd-skew",
      "entry " + JSON.stringify(entry.name) + " general-purpose flag skew: LFH=0x" +
      lfhFlags.toString(16) + " CD=0x" + entry.generalFlags.toString(16) +
      " (encryption, data-descriptor, masked-header and UTF-8 name bits must agree)");
  }
  var dataStart = entry.lfhOffset + LFH_FIXED_BYTES + lfhNameLen + lfhExtraLen;
  var dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > entry._spanLimit) {
    throw new ArchiveReadError("archive-read/entry-overlap",
      "entry " + JSON.stringify(entry.name) + " data ends at offset=" + dataEnd +
      " past the next local header or the central directory (offset=" + entry._spanLimit + ")");
  }
  var lfhVariable = lfhNameLen + lfhExtraLen > 0
    ? await adapter.range(entry.lfhOffset + LFH_FIXED_BYTES, lfhNameLen + lfhExtraLen)
    : Buffer.alloc(0);
  var lfhNameBuf = lfhVariable.subarray(0, lfhNameLen);
  var lfhExtra = lfhVariable.subarray(lfhNameLen);
  if (!hasDataDescriptor &&
      (lfhUsize === ZIP64_U32_SENTINEL || lfhCsize === ZIP64_U32_SENTINEL)) {
    var lfhResolved = _applyZip64Extra({
      uncompressedSize: lfhUsize,
      compressedSize:   lfhCsize,
      lfhOffset:        0,
      diskStart:        0,
    }, lfhExtra);
    lfhUsize = lfhResolved.uncompressedSize;
    lfhCsize = lfhResolved.compressedSize;
  }
  if (hasDataDescriptor) {
    if (lfhCrc !== 0 && lfhCrc !== entry.crc) {
      throw new ArchiveReadError("archive-read/lfh-cd-skew",
        "entry " + JSON.stringify(entry.name) + " CRC skew: LFH=" +
        lfhCrc + " CD=" + entry.crc + " (data-descriptor entry)");
    }
    _requireDeferredSizeAgrees(entry, lfhCsize, entry.compressedSize, "compressed-size");
    _requireDeferredSizeAgrees(entry, lfhUsize, entry.uncompressedSize, "uncompressed-size");
  } else {
    if (lfhCrc !== entry.crc) {
      throw new ArchiveReadError("archive-read/lfh-cd-skew",
        "entry " + JSON.stringify(entry.name) + " CRC skew: LFH=" +
        lfhCrc + " CD=" + entry.crc);
    }
    if (lfhCsize !== entry.compressedSize) {
      throw new ArchiveReadError("archive-read/lfh-cd-skew",
        "entry " + JSON.stringify(entry.name) + " compressed-size skew: LFH=" +
        lfhCsize + " CD=" + entry.compressedSize);
    }
    if (lfhUsize !== entry.uncompressedSize) {
      throw new ArchiveReadError("archive-read/lfh-cd-skew",
        "entry " + JSON.stringify(entry.name) + " uncompressed-size skew: LFH=" +
        lfhUsize + " CD=" + entry.uncompressedSize);
    }
  }
  if (!lfhNameBuf.equals(entry._nameBytes)) {
    throw new ArchiveReadError("archive-read/lfh-cd-skew",
      "entry name skew: LFH=" + JSON.stringify(lfhNameBuf.toString("utf8")) +
      " CD=" + JSON.stringify(entry._nameBytes.toString("utf8")) + " (name fields compared byte for byte)");
  }
  var lfhEffectiveName = _effectiveNameBytes(lfhExtra, lfhNameBuf, lfhFlags,
    "local header at offset=" + entry.lfhOffset);
  if (!lfhEffectiveName.equals(entry._effectiveNameBytes)) {
    throw new ArchiveReadError("archive-read/unicode-path-mismatch",
      "entry " + JSON.stringify(entry.name) + " is named " +
      JSON.stringify(lfhEffectiveName.toString("utf8")) + " by its local header; " +
      "the Info-ZIP Unicode Path extra fields (0x7075) of the local header and the " +
      "central directory resolve the name field to different names");
  }
  var layoutEnd = dataEnd;
  if (hasDataDescriptor) {
    layoutEnd += await _verifyDataDescriptor(adapter, entry, dataEnd);
  }
  return {
    dataStart: dataStart,
    layoutEnd: layoutEnd,
  };
}

function _requireDeferredSizeAgrees(entry, lfhValue, cdValue, fieldLabel) {
  if (lfhValue === 0 || lfhValue === ZIP64_U32_SENTINEL || lfhValue === cdValue) return;
  throw new ArchiveReadError("archive-read/lfh-cd-skew",
    "entry " + JSON.stringify(entry.name) + " " + fieldLabel + " skew: LFH=" +
    lfhValue + " CD=" + cdValue + " (data-descriptor entry)");
}

function _dataDescriptorMatches(dd, p, entry) {
  if (p + DD_NARROW_BYTES <= dd.length &&
      dd.readUInt32LE(p) === entry.crc &&
      dd.readUInt32LE(p + 4) === entry.compressedSize &&
      dd.readUInt32LE(p + 8) === entry.uncompressedSize) {
    return DD_NARROW_BYTES;
  }
  if (p + DD_WIDE_BYTES <= dd.length &&
      dd.readUInt32LE(p) === entry.crc &&
      dd.readBigUInt64LE(p + 4) === BigInt(entry.compressedSize) &&
      dd.readBigUInt64LE(p + 12) === BigInt(entry.uncompressedSize)) {
    return DD_WIDE_BYTES;
  }
  return 0;
}

async function _verifyDataDescriptor(adapter, entry, dataEnd) {
  var avail = Math.min(DD_MAX_BYTES, entry._spanLimit - dataEnd);
  var dd = avail > 0 ? await adapter.range(dataEnd, avail) : Buffer.alloc(0);
  if (dd.length >= DD_SIG_BYTES && dd.readUInt32LE(0) === SIG_DATA_DESCRIPTOR) {
    var signedLen = _dataDescriptorMatches(dd, DD_SIG_BYTES, entry);
    if (signedLen > 0) return DD_SIG_BYTES + signedLen;
  }
  var unsignedLen = _dataDescriptorMatches(dd, 0, entry);
  if (unsignedLen > 0) return unsignedLen;
  throw new ArchiveReadError("archive-read/lfh-cd-skew",
    "entry " + JSON.stringify(entry.name) + " data descriptor is missing or disagrees " +
    "with the central directory (crc=" + entry.crc + " compressedSize=" +
    entry.compressedSize + " uncompressedSize=" + entry.uncompressedSize + ")");
}

function _enforceEntryTypePolicy(entry, policy) {
  var type = entry._entryType || (entry._entryType = _classifyEntryType(entry));
  if (type === "symlink"  && !policy.symlinks)  return "symlink";
  if (type === "device"   && !policy.devices)   return "device";
  if (type === "fifo"     && !policy.fifos)     return "fifo";
  if (type === "socket"   && !policy.sockets)   return "socket";
  void policy.hardlinks;
  return null;
}

function _enforceBombPolicy(entries, policy) {
  if (entries.length > policy.maxEntries) {
    throw new ArchiveReadError("archive-read/too-many-entries",
      "archive contains " + entries.length + " entries — exceeds maxEntries=" + policy.maxEntries);
  }
  var totalDecompressed = 0;
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    if (e.uncompressedSize > policy.maxEntryDecompressedBytes) {
      throw new ArchiveReadError("archive-read/entry-too-large",
        "entry " + JSON.stringify(e.name) + " uncompressed=" + e.uncompressedSize +
        " exceeds maxEntryDecompressedBytes=" + policy.maxEntryDecompressedBytes);
    }
    totalDecompressed += e.uncompressedSize;
    if (totalDecompressed > policy.maxTotalDecompressedBytes) {
      throw new ArchiveReadError("archive-read/total-too-large",
        "cumulative uncompressed=" + totalDecompressed +
        " (after entry " + JSON.stringify(e.name) + ") exceeds maxTotalDecompressedBytes=" + policy.maxTotalDecompressedBytes);
    }
    if (e.compressedSize > 0) {
      var ratio = e.uncompressedSize / e.compressedSize;
      if (ratio > policy.maxExpansionRatio) {
        throw new ArchiveReadError("archive-read/expansion-ratio",
          "entry " + JSON.stringify(e.name) + " expansion ratio=" +
          ratio.toFixed(2) + " exceeds maxExpansionRatio=" + policy.maxExpansionRatio);
      }
    }
  }
}

function _buildCrc32SliceTable() {
  var table = new Int32Array(CRC32_SLICE_STRIDE * CRC32_SLICES);
  for (var n = 0; n < CRC32_SLICE_STRIDE; n += 1) {
    var reg = n;
    for (var bit = 0; bit < 8; bit += 1) {
      reg = (reg & 1) ? (CRC32_REFLECTED_POLY ^ (reg >>> 1)) : (reg >>> 1);
    }
    table[n] = reg | 0;
  }
  for (var s = 1; s < CRC32_SLICES; s += 1) {
    for (var m = 0; m < CRC32_SLICE_STRIDE; m += 1) {
      var prev = table[(s - 1) * CRC32_SLICE_STRIDE + m];
      table[s * CRC32_SLICE_STRIDE + m] = (prev >>> 8) ^ table[prev & 0xff];
    }
  }
  return table;
}

function _crc32Advance(reg, region, from, to) {
  var t = CRC32_SLICE_TABLE;
  var p = from;
  for (; p + CRC32_SLICES <= to; p += CRC32_SLICES) {
    reg ^= region[p] | (region[p + 1] << 8) | (region[p + 2] << 16) | (region[p + 3] << 24);
    reg = t[CRC32_SLICE_3 + (reg & 0xff)] ^ t[CRC32_SLICE_2 + ((reg >>> 8) & 0xff)] ^
          t[CRC32_SLICE_1 + ((reg >>> 16) & 0xff)] ^ t[reg >>> 24];
  }
  for (; p < to; p += 1) reg = t[(reg ^ region[p]) & 0xff] ^ (reg >>> 8);
  return reg;
}

function _refuseEarlyDescriptor(entry, region) {
  var stop = Math.min(entry.compressedSize, region.length - DD_SIG_BYTES - DD_CRC_FIELD_BYTES + 1);
  var crc = 0;
  var pos = 0;
  var k = stop > 0 ? region.indexOf(DD_SIGNATURE_BYTES) : -1;
  while (k !== -1 && k < stop) {
    if (k > pos) crc = zlib.crc32(region.subarray(pos, k), crc) >>> 0;
    pos = k;
    var reg = ~crc;
    var searched = k;
    while (k !== -1) {
      if (k > pos) {
        reg = _crc32Advance(reg, region, pos, k);
        pos = k;
      }
      var c = k + DD_SIG_BYTES;
      if ((region[c] | (region[c + 1] << 8) | (region[c + 2] << 16) | (region[c + 3] << 24)) === ~reg) {
        throw new ArchiveReadError("archive-read/ambiguous-entry-end",
          "stored entry " + JSON.stringify(entry.name) + " holds a data descriptor at data offset=" + k +
          " whose CRC-32 matches the bytes before it; a reader that walks the file ends the entry there " +
          "instead of at compressedSize=" + entry.compressedSize);
      }
      searched = Math.min(k + DD_DENSE_RUN_BYTES, stop);
      var from = k + 1;
      k = -1;
      for (var p = from; p < searched; p += 1) {
        if (region[p] !== 0x50) continue;
        if (region[p + 1] === 0x4b && region[p + 2] === 0x07 && region[p + 3] === 0x08) {
          k = p;
          break;
        }
      }
    }
    crc = ~reg >>> 0;
    k = searched < stop ? region.indexOf(DD_SIGNATURE_BYTES, searched) : -1;
  }
}

async function _decompressEntry(adapter, entry, dataStart, bombPolicy) {
  var body = await _readEntryBody(adapter, entry, dataStart, bombPolicy);
  if (!entry.isEncrypted) {
    var actualCrc = zlib.crc32(body) >>> 0;
    if (actualCrc !== entry.crc) {
      throw new ArchiveReadError("archive-read/crc-mismatch",
        "entry " + JSON.stringify(entry.name) + " CRC-32 mismatch (declared=" +
        entry.crc + " actual=" + actualCrc + ")");
    }
  }
  return body;
}

async function _readEntryBody(adapter, entry, dataStart, bombPolicy) {
  if (entry.compressedSize === 0 && entry.uncompressedSize === 0) {
    return Buffer.alloc(0);
  }
  var raw;
  if (entry.method === METHOD_STORE_ID && entry.hasDataDescriptor) {
    var lookahead = Math.min(DD_SIG_BYTES + C.BYTES.bytes(4),
      entry._spanLimit - (dataStart + entry.compressedSize));
    var region = await adapter.range(dataStart, entry.compressedSize + Math.max(lookahead, 0));
    _refuseEarlyDescriptor(entry, region);
    raw = region.subarray(0, entry.compressedSize);
  } else {
    raw = await adapter.range(dataStart, entry.compressedSize);
  }
  if (entry.method === METHOD_STORE_ID) {
    if (raw.length !== entry.uncompressedSize) {
      throw new ArchiveReadError("archive-read/store-size-mismatch",
        "entry " + JSON.stringify(entry.name) + " stored size mismatch (csize=" +
        raw.length + " usize=" + entry.uncompressedSize + ")");
    }
    return raw;
  }
  if (entry.method === METHOD_DEFLATE_ID) {
    var maxOutput = Math.min(
      bombPolicy.maxEntryDecompressedBytes,
      entry.uncompressedSize + C.BYTES.bytes(1)
    );
    var decompressed;
    try {
      decompressed = safeDecompress().safeDecompress(raw, {
        algorithm:          "deflate-raw",
        maxOutputBytes:     maxOutput,
        maxCompressedBytes: entry.compressedSize,
        maxRatio:           bombPolicy.maxExpansionRatio,
        requireFullInput:   true,
      });
    } catch (e) {
      if (e && e.code === "safe-decompress/trailing-input") {
        var short = new ArchiveReadError("archive-read/ambiguous-entry-end",
          "entry " + JSON.stringify(entry.name) + " deflate stream ends before compressedSize=" +
          entry.compressedSize + "; " + e.message);
        short.cause = e;
        throw short;
      }
      throw e;
    }
    if (decompressed.length !== entry.uncompressedSize) {
      throw new ArchiveReadError("archive-read/inflate-size-mismatch",
        "entry " + JSON.stringify(entry.name) +
        " inflated size mismatch (declared=" + entry.uncompressedSize +
        " actual=" + decompressed.length + ")");
    }
    return decompressed;
  }
  throw new ArchiveReadError("archive-read/unsupported-method",
    "entry " + JSON.stringify(entry.name) + " uses method=" + entry.method +
    " — only STORE (0) and DEFLATE (8) are supported");
}

var _BOMB_POLICY_INT_CAPS = ["maxEntries", "maxEntryDecompressedBytes",
                             "maxTotalDecompressedBytes"];

function _validateBombPolicy(p, label, errorClass, code) {
  if (!p) return p;
  for (var i = 0; i < _BOMB_POLICY_INT_CAPS.length; i += 1) {
    var key = _BOMB_POLICY_INT_CAPS[i];
    numericBounds.requireNonNegativeFiniteIntIfPresent(p[key], label + ": " + key,
      errorClass, code);
  }
  numericBounds.requirePositiveFiniteNumberIfPresent(p.maxExpansionRatio,
    label + ": maxExpansionRatio", errorClass, code);
  return p;
}

function _normalizeBombPolicy(p) {
  if (!p) return DEFAULT_BOMB_POLICY;
  _validateBombPolicy(p, "bombPolicy", ArchiveReadError, "archive-read/bad-bomb-policy");
  return Object.freeze(Object.assign({}, DEFAULT_BOMB_POLICY, p));
}

var _normalizeEntryTypePolicy = archiveEntryPolicy.normalize;

var _emitAudit = auditEmit.emitToSink;

/**
 * @primitive b.archive.read.zip
 * @signature b.archive.read.zip(adapter, opts?)
 * @since     0.12.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.archive.adapters.fs, b.safeArchive.extract, b.guardArchive.inspect
 *
 * Random-access ZIP reader. Walks the end-of-central-directory record,
 * validates every CD entry against its local file header, and exposes
 * `inspect()` (entry-list enumeration after the local-header checks,
 * without decompressing) +
 * `extract(opts)` (full decompression with bomb caps + path-traversal +
 * entry-type policy).
 *
 * ZIP64 (APPNOTE 6.3.10 §4.3.14 EOCD64 / §4.3.15 locator / §4.5.3
 * extended-information extra field) is read transparently: archives
 * whose entry count exceeds 65535 or whose sizes/offsets exceed 4 GiB
 * carry the ZIP64 trailer, which is resolved into the same entry shape
 * a classic archive yields. The classic-format default entry cap is
 * lifted to 2^20; operators raise it through `bombPolicy.maxEntries`.
 *
 * Defends:
 *   - Zip Slip / path traversal (CVE-2025-3445 / 11569 / 23084 / 27210
 *     / 11001 / 11002 / 26960 + 2024 jszip / mholt / Python tarfile)
 *   - LFH/CD skew (malformed-zip class), including a data descriptor
 *     that disagrees with the central directory, and general-purpose
 *     flag bits 0, 3, 6, 11 and 13 (encryption, data descriptor, strong
 *     encryption, UTF-8 name, masked local header) that differ between
 *     the local header and the central directory. The local and central name
 *     fields are compared byte for byte.
 *   - One entry named two ways: an entry's name is the name Info-ZIP
 *     unzip, 7-Zip and bsdtar extract. When a header carries an Info-ZIP
 *     Unicode Path extra field (0x7075) of version 1 whose CRC-32 matches
 *     that header's name field, the name is the field's UTF-8 path;
 *     otherwise the name is the name field. A name field flagged UTF-8
 *     (bit 11) that is not valid UTF-8 is refused. A name field with bit
 *     11 clear that is not valid UTF-8 is decoded as code page 437, so no
 *     name holds U+FFFD. `inspect()` lists that name,
 *     the guard judges it and `extract` writes it, so a 7-Zip archive
 *     whose name field is in the OEM code page reads under its UTF-8
 *     names. The local header and the central directory must resolve to
 *     the same name, and their name fields must also agree byte for
 *     byte. A Unicode Path field that is shorter than 5 bytes, has a
 *     version other than 1, appears twice in one header, or holds an
 *     empty path or one that is not valid UTF-8 is refused. A Unicode
 *     Path that differs from a name field flagged UTF-8 (bit 11), or
 *     ends in a slash when the name field does not (or the reverse), is
 *     refused. A Unicode Path field whose declared size runs past the
 *     end of the extra block, or whose header is cut off by it, is
 *     refused. The Info-ZIP Unicode Comment field (0x6375) is not read.
 *     Each entry also carries `altNames`, the other names a reader may
 *     extract it under. When general-purpose bit 11 is clear, other
 *     readers decode the name field in two ways. Java's `java.util.zip`
 *     and bsdtar use UTF-8, and so do unzip and 7-Zip for an entry made
 *     on Unix. Python's `zipfile`, and 7-Zip for an entry made on FAT or
 *     NTFS, use code page 437. Java and Python 3.11 ignore the Unicode
 *     Path field. `altNames` holds the code page 437 decode and, when the
 *     name field is valid UTF-8, the UTF-8 decode, leaving out any that
 *     equals `name` or each other. It is empty when bit 11 is set. The
 *     guard judges `name` and every alternate name, including duplicates
 *     and case-insensitive collisions across all of them, and `extract`
 *     passes each alternate name to
 *     `b.guardFilename.verifyExtractionPath`. A name field such as
 *     `../../evil.txt` or one holding a right-to-left override under a
 *     Unicode Path of `docs/readme.txt` is refused, and so are two name
 *     fields that collide only in code page 437.
 *   - Ambiguous archive layout (CVE-2025-8291 class): the central
 *     directory must end exactly where the EOCD record (or the ZIP64
 *     EOCD record) begins, the ZIP64 EOCD record must end where its
 *     locator begins, and classic EOCD fields must agree with the ZIP64
 *     record. The reader always reads a ZIP64 locator that sits directly
 *     before the EOCD, including one inside the last central-directory
 *     comment.
 *   - A second archive hidden in the file: the bytes before the first
 *     local header the central directory references must not hold a
 *     local header, central-directory header or EOCD record that parses,
 *     including one whose fixed header runs into that first local
 *     header. The EOCD comment must not hold an EOCD signature followed
 *     by a full 22-byte record, or a local or central-directory header
 *     that parses. The reader accepts a self-extractor stub whose offsets
 *     were adjusted with `zip -A`, and refuses prepended data whose
 *     offsets were not adjusted. `inspect()`, `entries()`, `extract` and
 *     `extractEntries` also read every local header, directories
 *     included, check it against its central directory entry, and refuse
 *     a ZIP structure that parses in the bytes between one entry's data
 *     (and data descriptor) and the next local header or the central
 *     directory, before they return, yield or write any entry. The pass
 *     reads the local headers in file order through 64 KiB windows, and
 *     the local headers that fall in one window cost one adapter read.
 *     A reader
 *     makes this pass once and shares it between its methods, including
 *     calls that run at the same time; a pass that fails runs again on
 *     the next call.
 *   - Overlapping entries: every entry's local header and data must lie
 *     before the central directory and before the next entry's header
 *   - An entry that ends early for a reader that walks the file front to
 *     back: when an entry is extracted, a deflate stream must end exactly
 *     at the compressed size the central directory records, and the data
 *     of a stored entry with a data descriptor (flag bit 3) must not hold
 *     a signed data descriptor whose CRC-32 matches the bytes before it
 *   - Altered entry data: every extracted entry is checked against the
 *     CRC-32 its central directory records
 *   - Decompression bomb (OWASP zip-bomb top-cases)
 *   - PATH_MAX TOCTOU (CVE-2025-4517) via `b.guardFilename.
 *     verifyExtractionPath`
 *   - Symlink + hardlink + device entries (refused by default)
 *
 * Errors are `ArchiveReadError` instances. Constructing the reader
 * throws `archive-read/bad-adapter` for an adapter that does not come
 * from `b.archive.adapters.*`, `archive-read/wrong-entry-point` for a
 * trusted-stream adapter, and `archive-read/bad-bomb-policy` for a
 * `bombPolicy` cap that is not a non-negative number. The returned
 * methods reject with
 * `archive-read/cd-position-mismatch` when the central directory does not
 * end at the EOCD, `archive-read/cd-size-mismatch` when the directory
 * holds bytes past the entries the EOCD counts,
 * `archive-read/eocd-inconsistent` when EOCD fields disagree with each
 * other or with the ZIP64 record, `archive-read/zip64-eocd-not-adjacent`
 * when the ZIP64 record does not end at its locator,
 * `archive-read/embedded-archive` when the bytes before the first
 * referenced local header, the EOCD comment, or the gaps between
 * entries hold another archive's structures,
 * `archive-read/entry-out-of-range` and `archive-read/entry-overlap` for
 * entries placed at or past the central directory or over another entry,
 * `archive-read/bad-lfh-signature` when an entry's offset does not hold
 * a local header,
 * `archive-read/lfh-cd-skew` when a local header (including those flag
 * bits) or data descriptor disagrees with the central directory,
 * `archive-read/unicode-path-mismatch` when a Unicode Path extra field
 * is malformed, declares more bytes than its extra block holds, has a
 * version other than 1, or is one that Info-ZIP
 * unzip, 7-Zip and bsdtar read differently, or when the local header
 * and the central directory resolve to different names,
 * `archive-read/bad-utf8-name` when a name field flagged UTF-8 (bit 11)
 * is not valid UTF-8,
 * `archive-read/aborted` when `opts.signal` is aborted before or during
 * a read, including the local-header pass,
 * `archive-read/ambiguous-entry-end`
 * when an extracted entry's deflate stream ends before its compressed
 * size or its stored data holds a matching data descriptor, and
 * `archive-read/crc-mismatch`
 * when an extracted entry's bytes do not match its CRC-32. Encrypted
 * entries extracted with `allowEncrypted` are returned without the CRC
 * check, because the stored bytes are ciphertext. `extract` and
 * `extractEntries` reject with `archive-read/guard-refused` when the
 * guard reports a critical issue for either name of an entry, and
 * `extract` rethrows the `filename/*` error that
 * `b.guardFilename.verifyExtractionPath` throws for either name.
 *
 * @opts
 *   bombPolicy:       { maxEntries, maxEntryDecompressedBytes,
 *                       maxTotalDecompressedBytes, maxExpansionRatio },
 *   entryTypePolicy:  { symlinks, hardlinks, devices, fifos, sockets },
 *   guardProfile:     "strict" | "balanced" | "permissive" | "hipaa" | ...,
 *   audit:            b.audit,
 *   signal:           AbortSignal,
 *
 * @example
 *   var adapter = b.archive.adapters.fs("/var/uploads/payload.zip");
 *   var reader  = b.archive.read.zip(adapter);
 *   var entries = await reader.inspect();
 *   //  → [{ name, size, compressedSize, crc, method, mtime, ... }, ...]
 *
 *   var dest    = b.archive.adapters.fs("/var/quarantine");
 *   var result  = await reader.extract({ destination: "/var/quarantine" });
 *   //  → { entries: [{ name, bytesWritten }, ...], bytesExtracted }
 */
function zip(adapter, opts) {
  if (!adapter || (adapter.kind !== "random-access" && adapter.kind !== "trusted-sequential")) {
    throw new ArchiveReadError("archive-read/bad-adapter",
      "b.archive.read.zip(adapter): adapter must come from b.archive.adapters.* " +
      "— got " + (adapter && adapter.kind));
  }
  if (adapter.kind === "trusted-sequential") {
    throw new ArchiveReadError("archive-read/wrong-entry-point",
      "trusted-sequential adapters MUST be passed to b.archive.read.zip." +
      "fromTrustedStream(adapter, opts) — the random-access entry point " +
      "requires { size, range(offset, length) }");
  }
  opts = opts || {};
  var bombPolicy      = _normalizeBombPolicy(opts.bombPolicy);
  var entryTypePolicy = _normalizeEntryTypePolicy(opts.entryTypePolicy);
  var cdPromise       = null;

  function _throwIfAborted() {
    if (opts.signal && opts.signal.aborted) {
      throw new ArchiveReadError("archive-read/aborted",
        "archive read aborted via opts.signal" +
        (opts.signal.reason !== undefined ? ": " + String(opts.signal.reason) : ""));
    }
  }

  function _loadCD() {
    if (!cdPromise) {
      var pending = (async function () {
        var eocd = await _locateEocd(adapter);
        var entries = await _readCentralDirectory(adapter, eocd);
        return { eocd: eocd, entries: entries, layoutPromise: null };
      })();
      cdPromise = pending;
      pending.catch(function () { if (cdPromise === pending) cdPromise = null; });
    }
    return cdPromise;
  }

  function _verifyLayoutOnce(loaded) {
    if (!loaded.layoutPromise) {
      var pending = _verifyLocalLayout(adapter, loaded.entries, loaded.eocd.archiveSize, _throwIfAborted);
      loaded.layoutPromise = pending;
      pending.catch(function () { if (loaded.layoutPromise === pending) loaded.layoutPromise = null; });
    }
    return loaded.layoutPromise;
  }

  async function inspect() {
    _throwIfAborted();
    var loaded = await _loadCD();
    _enforceBombPolicy(loaded.entries, bombPolicy);
    await _verifyLayoutOnce(loaded);
    _emitAudit(opts, "archive.read.inspect", "success", {
      entries: loaded.entries.length,
      cdSize:  loaded.eocd.cdSize,
    });
    return loaded.entries.map(function (e) {
      return {
        name:             e.name,
        altNames:         e.altNames.slice(),
        size:             e.uncompressedSize,
        compressedSize:   e.compressedSize,
        crc:              e.crc,
        method:           e.method === METHOD_DEFLATE_ID ? "deflate"
                        : e.method === METHOD_STORE_ID ? "store"
                        : ("method-" + e.method),
        mtime:            e.mtime,
        isEncrypted:      e.isEncrypted,
        externalAttrs:    e.externalAttrs,
        extraFields:      e.extraFields,
        entryType:        _classifyEntryType(e),
      };
    });
  }

  async function* entries() {
    _throwIfAborted();
    var loaded = await _loadCD();
    _enforceBombPolicy(loaded.entries, bombPolicy);
    await _verifyLayoutOnce(loaded);
    for (var i = 0; i < loaded.entries.length; i += 1) {
      _throwIfAborted();
      yield loaded.entries[i];
    }
  }

  function _assertGuardMetadata(loadedEntries, auditAction) {
    if (opts.guardProfile === false) return;
    var guardEntries = loadedEntries.map(function (e) {
      return {
        name:           e.name,
        altNames:       e.altNames,
        size:           e.uncompressedSize,
        compressedSize: e.compressedSize,
        isSymlink:      _isUnixSymlinkAttrs(e.externalAttrs),
        isHardlink:     false,
        linkTarget:     null,
        isDirectory:    _isDirectoryEntry(e.name, e.externalAttrs),
        isEncrypted:    e.isEncrypted,
        attrs:          { externalAttrs: e.externalAttrs },
      };
    });
    var profile = opts.guardProfile || "balanced";
    var guardResult = guardArchive().validateEntries(guardEntries, { profile: profile });
    if (!guardResult || !Array.isArray(guardResult.issues) || guardResult.issues.length === 0) return;
    var critical = guardResult.issues.filter(function (i) { return i.severity === "critical"; });
    if (critical.length === 0) return;
    _emitAudit(opts, auditAction, "refused", {
      entries: loadedEntries.length,
      issues:  critical.map(function (i) { return i.ruleId; }),
    });
    throw new ArchiveReadError("archive-read/guard-refused",
      "extract refused — " + critical.length + " critical guard issue(s): " +
      critical.map(function (i) { return i.ruleId + " (" + i.snippet + ")"; }).join("; "));
  }

  async function* extractEntries(extractOpts) {
    extractOpts = extractOpts || {};
    var loaded = await _loadCD();
    _enforceBombPolicy(loaded.entries, bombPolicy);
    _assertGuardMetadata(loaded.entries, "archive.read.extract_entries.refused");
    await _verifyLayoutOnce(loaded);
    var totalDecompressed = 0;
    var yielded = 0;
    for (var i = 0; i < loaded.entries.length; i += 1) {
      _throwIfAborted();
      var entry = loaded.entries[i];
      if (entry.isEncrypted && !extractOpts.allowEncrypted) {
        throw new ArchiveReadError("archive-read/encrypted-entry",
          "entry " + JSON.stringify(entry.name) + " is encrypted — not decrypted on the in-memory path");
      }
      var typeRefusal = _enforceEntryTypePolicy(entry, entryTypePolicy);
      if (typeRefusal) {
        throw new ArchiveReadError("archive-read/entry-type-refused",
          "entry " + JSON.stringify(entry.name) + " is a " + typeRefusal +
          " — refused by entryTypePolicy");
      }
      if (_isDirectoryEntry(entry.name, entry.externalAttrs)) continue;
      var body = await _decompressEntry(adapter, entry, entry._dataStart, bombPolicy);
      totalDecompressed += body.length;
      if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
        throw new ArchiveReadError("archive-read/total-too-large",
          "cumulative uncompressed=" + totalDecompressed +
          " exceeds maxTotalDecompressedBytes during extractEntries");
      }
      yielded += 1;
      yield { name: entry.name, bytes: body, size: body.length };
    }
    _emitAudit(opts, "archive.read.extract_entries.completed", "success", { entries: yielded });
  }

  async function extract(extractOpts) {
    extractOpts = extractOpts || {};
    if (typeof extractOpts.destination !== "string" || extractOpts.destination.length === 0) {
      throw new ArchiveReadError("archive-read/no-destination",
        "extract: opts.destination must be a non-empty string (target directory)");
    }
    var destination = nodePath.resolve(extractOpts.destination);
    if (!nodeFs.existsSync(destination)) {
      nodeFs.mkdirSync(destination, { recursive: true });
    }
    var loaded = await _loadCD();
    _enforceBombPolicy(loaded.entries, bombPolicy);
    _assertGuardMetadata(loaded.entries, "archive.read.extract.refused");
    await _verifyLayoutOnce(loaded);
    var written = [];
    var bytesExtracted = 0;
    var totalDecompressed = 0;
    try {
      for (var i = 0; i < loaded.entries.length; i += 1) {
        _throwIfAborted();
        var entry = loaded.entries[i];
        if (entry.isEncrypted && !extractOpts.allowEncrypted) {
          throw new ArchiveReadError("archive-read/encrypted-entry",
            "entry " + JSON.stringify(entry.name) + " is encrypted — this " +
            "low-level reader does not decrypt; use b.safeArchive for " +
            "encrypted-archive handling, or pass allowEncrypted to extract " +
            "the raw entry");
        }
        var typeRefusal = _enforceEntryTypePolicy(entry, entryTypePolicy);
        if (typeRefusal) {
          throw new ArchiveReadError("archive-read/entry-type-refused",
            "entry " + JSON.stringify(entry.name) + " is a " + typeRefusal +
            " — refused by entryTypePolicy (opt in via b.guardArchive.entryTypePolicy({ " +
            typeRefusal + "s: true }))");
        }
        for (var a = 0; a < entry.altNames.length; a += 1) {
          guardFilename().verifyExtractionPath(entry.altNames[a], destination);
        }
        if (_isDirectoryEntry(entry.name, entry.externalAttrs)) {
          var dirPath = guardFilename().verifyExtractionPath(entry.name, destination);
          nodeFs.mkdirSync(dirPath, { recursive: true });
          continue;
        }
        var resolvedPath = guardFilename().verifyExtractionPath(entry.name, destination);
        var parentDir = nodePath.dirname(resolvedPath);
        if (!nodeFs.existsSync(parentDir)) {
          nodeFs.mkdirSync(parentDir, { recursive: true });
        }
        if (nodeFs.existsSync(resolvedPath)) {
          throw new ArchiveReadError("archive-read/destination-exists",
            "extract: destination file already exists at " +
            JSON.stringify(resolvedPath) + " — refuse to overwrite; pass an " +
            "empty / fresh destination directory or remove the existing file");
        }
        var body = await _decompressEntry(adapter, entry, entry._dataStart, bombPolicy);
        totalDecompressed += body.length;
        if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
          throw new ArchiveReadError("archive-read/total-too-large",
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
      } catch (_e) { /* drop-silent — cleanup best-effort */ }
      _emitAudit(opts, "archive.read.extract.aborted", "failure", {
        entries:    loaded.entries.length,
        written:    written.length,
        bytesExtracted: bytesExtracted,
        error:      extractErr && (extractErr.code || extractErr.message) || String(extractErr),
      });
      throw extractErr;
    }
    _emitAudit(opts, "archive.read.extract.completed", "success", {
      entries:        loaded.entries.length,
      bytesExtracted: bytesExtracted,
    });
    return {
      entries:        written,
      destinationRoot: destination,
      bytesExtracted: bytesExtracted,
    };
  }

  return {
    kind:           "zip-random-access",
    inspect:        inspect,
    entries:        entries,
    extract:        extract,
    extractEntries: extractEntries,
  };
}

/**
 * @primitive b.archive.read.zip.fromTrustedStream
 * @signature b.archive.read.zip.fromTrustedStream(adapter, opts?)
 * @since     0.12.7
 * @status    experimental
 * @related   b.archive.read.zip, b.archive.adapters.trustedStream
 *
 * ZIP reader for a Readable source — pass `b.archive.adapters.trustedStream(readable)`
 * instead of buffering the stream yourself. The bytes are collected
 * into a size-capped buffer (1 GiB hard ceiling, like the tar
 * trusted-stream reader) and then read through the same bomb-cap /
 * path-traversal / entry-policy decode as the random-access reader, so
 * `bombPolicy`, `guardProfile`, `entryTypePolicy`, and `audit` all
 * apply. "Trusted" means the source size is bounded by the operator —
 * the collection ceiling is the only guard against an unbounded
 * producer; adversarial archives are still fully bomb-capped on decode.
 *
 * The collection ceiling means this is not zero-buffer streaming (the
 * whole archive is held in memory, capped); a future bounded-memory
 * forward-inflate walker would lift that, shared with the tar reader.
 *
 * @opts
 *   bombPolicy:       { maxEntries, maxEntryDecompressedBytes,
 *                       maxTotalDecompressedBytes, maxExpansionRatio },
 *   entryTypePolicy:  { ... },
 *   guardProfile:     "strict" | "balanced" | "permissive",
 *   audit:            b.audit,
 *
 * @example
 *   var reader  = b.archive.read.zip.fromTrustedStream(b.archive.adapters.trustedStream(readable));
 *   var entries = await reader.inspect();
 *   void entries;
 */
function fromTrustedStream(adapter, opts) {
  if (!adapter || adapter.kind !== "trusted-sequential") {
    throw new ArchiveReadError("archive-read/bad-adapter",
      "fromTrustedStream: adapter must come from b.archive.adapters.trustedStream(readable)");
  }
  opts = opts || {};

  var readerPromise = null;
  function _reader() {
    if (!readerPromise) {
      readerPromise = (async function () {
        var collector = safeBuffer().boundedChunkCollector({
          maxBytes:   C.BYTES.gib(1),
          errorClass: ArchiveReadError,
          sizeCode:   "archive-read/trusted-stream-too-large",
        });
        for await (var chunk of adapter.readable) { collector.push(chunk); }
        return zip(archiveAdapters().buffer(collector.result()), opts);
      })();
    }
    return readerPromise;
  }

  async function inspect() { return (await _reader()).inspect(); }
  async function* entries() {
    var r = await _reader();
    for await (var e of r.entries()) { yield e; }
  }
  async function extract(extractOpts) { return (await _reader()).extract(extractOpts); }
  async function* extractEntries(extractOpts) {
    var r = await _reader();
    for await (var e of r.extractEntries(extractOpts)) { yield e; }
  }

  return {
    kind:           "zip-trusted-sequential",
    inspect:        inspect,
    entries:        entries,
    extract:        extract,
    extractEntries: extractEntries,
  };
}

zip.fromTrustedStream = fromTrustedStream;

module.exports = {
  zip:                       zip,
  ArchiveReadError:          ArchiveReadError,
  DEFAULT_BOMB_POLICY:       DEFAULT_BOMB_POLICY,
  DEFAULT_ENTRY_TYPE_POLICY: DEFAULT_ENTRY_TYPE_POLICY,
  _locateEocd:               _locateEocd,
  _readCentralDirectory:     _readCentralDirectory,
  _validateBombPolicy:       _validateBombPolicy,
};
