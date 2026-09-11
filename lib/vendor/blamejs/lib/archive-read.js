// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");
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
var ZIP64_EXTRA_HEADER_ID   = 0x0001;
var EXTRA_FIELD_HEADER_BYTES= C.BYTES.bytes(4);

var METHOD_STORE_ID         = 0;
var METHOD_DEFLATE_ID       = 8;

var FLAG_ENCRYPTED          = 0x0001;
var FLAG_DATA_DESCRIPTOR    = 0x0008;
var FLAG_UTF8_NAME          = 0x0800;
void FLAG_UTF8_NAME;
void SIG_DATA_DESCRIPTOR;

var EOCD_MIN_BYTES          = C.BYTES.bytes(22);
var EOCD_MAX_COMMENT_BYTES  = C.BYTES.kib(64);
var EOCD_SCAN_BYTES         = EOCD_MIN_BYTES + EOCD_MAX_COMMENT_BYTES;

var LFH_FIXED_BYTES         = C.BYTES.bytes(30);
var CFH_FIXED_BYTES         = C.BYTES.bytes(46);

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
        };
        if (eocd.totalEntries === ZIP64_U16_SENTINEL ||
            eocd.cdSize === ZIP64_U32_SENTINEL ||
            eocd.cdOffset === ZIP64_U32_SENTINEL) {
          await _resolveZip64Eocd(adapter, eocd, size);
        }
        return eocd;
      }
    }
  }
  throw new ArchiveReadError("archive-read/no-eocd",
    "End-of-central-directory record not found in trailing " + scanLen + " bytes");
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
  eocd.diskNumber   = rec.readUInt32LE(16);
  eocd.cdDiskNumber = rec.readUInt32LE(20);
  eocd.totalEntries = _readZip64U64(rec, 32, "totalEntries");
  eocd.cdSize       = _readZip64U64(rec, 40, "centralDirSize");
  eocd.cdOffset     = _readZip64U64(rec, 48, "centralDirOffset");
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
  if (eocd.cdSize === 0 || eocd.totalEntries === 0) {
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
    var name = cdBytes.slice(nameStart, nameStart + nameLen).toString("utf8");
    var extraFields = cdBytes.slice(extraStart, extraStart + extraLen);
    var resolved = _applyZip64Extra({
      uncompressedSize: uncompressedSize,
      compressedSize:   compressedSize,
      lfhOffset:        lfhOffset,
      diskStart:        diskStart,
    }, extraFields);
    entries.push({
      name:             name,
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
      _entryType:       null,
    });
    pos += totalLen;
  }
  return entries;
}

async function _verifyLfhMatchesCd(adapter, entry) {
  var lfhPrefix = await adapter.range(entry.lfhOffset, LFH_FIXED_BYTES);
  if (lfhPrefix.readUInt32LE(0) !== SIG_LFH) {
    throw new ArchiveReadError("archive-read/bad-lfh-signature",
      "local file header for " + JSON.stringify(entry.name) +
      " has bad signature 0x" + lfhPrefix.readUInt32LE(0).toString(16));
  }
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
  if (!hasDataDescriptor &&
      (lfhUsize === ZIP64_U32_SENTINEL || lfhCsize === ZIP64_U32_SENTINEL)) {
    var lfhExtra = await adapter.range(entry.lfhOffset + LFH_FIXED_BYTES + lfhNameLen, lfhExtraLen);
    var lfhResolved = _applyZip64Extra({
      uncompressedSize: lfhUsize,
      compressedSize:   lfhCsize,
      lfhOffset:        0,
      diskStart:        0,
    }, lfhExtra);
    lfhUsize = lfhResolved.uncompressedSize;
    lfhCsize = lfhResolved.compressedSize;
  }
  if (!hasDataDescriptor) {
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
  var lfhNameBuf = await adapter.range(entry.lfhOffset + LFH_FIXED_BYTES, lfhNameLen);
  var lfhName = lfhNameBuf.toString("utf8");
  if (lfhName !== entry.name) {
    throw new ArchiveReadError("archive-read/lfh-cd-skew",
      "entry name skew: LFH=" + JSON.stringify(lfhName) +
      " CD=" + JSON.stringify(entry.name));
  }
  return {
    dataStart: entry.lfhOffset + LFH_FIXED_BYTES + lfhNameLen + lfhExtraLen,
  };
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

async function _decompressEntry(adapter, entry, dataStart, bombPolicy) {
  if (entry.compressedSize === 0 && entry.uncompressedSize === 0) {
    return Buffer.alloc(0);
  }
  var raw = await adapter.range(dataStart, entry.compressedSize);
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
    var decompressed = safeDecompress().safeDecompress(raw, {
      algorithm:          "deflate-raw",
      maxOutputBytes:     maxOutput,
      maxCompressedBytes: entry.compressedSize,
      maxRatio:           bombPolicy.maxExpansionRatio,
    });
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

function _normalizeBombPolicy(p) {
  if (!p) return DEFAULT_BOMB_POLICY;
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
 * `inspect()` (entry-list enumeration without decompressing) +
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
 *   - LFH/CD skew (malformed-zip class)
 *   - Decompression bomb (OWASP zip-bomb top-cases)
 *   - PATH_MAX TOCTOU (CVE-2025-4517) via `b.guardFilename.
 *     verifyExtractionPath`
 *   - Symlink + hardlink + device entries (refused by default)
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
  var cdCache         = null;

  function _throwIfAborted() {
    if (opts.signal && opts.signal.aborted) {
      throw new ArchiveReadError("archive-read/aborted",
        "archive read aborted via opts.signal" +
        (opts.signal.reason !== undefined ? ": " + String(opts.signal.reason) : ""));
    }
  }

  async function _loadCD() {
    if (cdCache) return cdCache;
    var eocd = await _locateEocd(adapter);
    var entries = await _readCentralDirectory(adapter, eocd);
    cdCache = { eocd: eocd, entries: entries };
    return cdCache;
  }

  async function inspect() {
    _throwIfAborted();
    var loaded = await _loadCD();
    _enforceBombPolicy(loaded.entries, bombPolicy);
    _emitAudit(opts, "archive.read.inspect", "success", {
      entries: loaded.entries.length,
      cdSize:  loaded.eocd.cdSize,
    });
    return loaded.entries.map(function (e) {
      return {
        name:             e.name,
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
    _assertGuardMetadata(loaded.entries, "archive.read.extractEntries.refused");
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
      var lfhResult = await _verifyLfhMatchesCd(adapter, entry);
      var body = await _decompressEntry(adapter, entry, lfhResult.dataStart, bombPolicy);
      totalDecompressed += body.length;
      if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
        throw new ArchiveReadError("archive-read/total-too-large",
          "cumulative uncompressed=" + totalDecompressed +
          " exceeds maxTotalDecompressedBytes during extractEntries");
      }
      yielded += 1;
      yield { name: entry.name, bytes: body, size: body.length };
    }
    _emitAudit(opts, "archive.read.extractEntries.completed", "success", { entries: yielded });
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
        var lfhResult = await _verifyLfhMatchesCd(adapter, entry);
        var body = await _decompressEntry(adapter, entry, lfhResult.dataStart, bombPolicy);
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
};
