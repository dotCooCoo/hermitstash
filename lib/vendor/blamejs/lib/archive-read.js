"use strict";
/**
 * archive-read — random-access + trusted-sequential ZIP reader.
 *
 * Internal module exposed through `b.archive.read.zip(adapter, opts)`.
 * Implements two paths against the same wire-format vocabulary:
 *
 *   - Random-access — `adapter.range(offset, length)` calls walk the
 *     EOCD trailer, validate the central directory against every
 *     local file header (LFH/CD skew defense), and seek per-entry
 *     for decompression. Adversarial-safe.
 *   - Trusted sequential — `adapter.readable` is forward-scanned LFH-
 *     by-LFH. No CD comparison; operators acknowledge the trust
 *     boundary by reaching for `b.archive.read.zip.fromTrustedStream`.
 *
 * Wire-format reference: APPNOTE.TXT (PKWARE ZIP File Format
 * Specification, latest 6.3.10). Constants are kept aligned with the
 * write-side `lib/archive.js` so a single APPNOTE bump cascades to
 * both paths.
 *
 * Zip-bomb defenses are enforced as four parallel caps on `extract()`:
 *
 *   maxEntries                    (entry-count cap)
 *   maxEntryDecompressedBytes     (per-entry cap)
 *   maxTotalDecompressedBytes     (aggregate cap)
 *   maxExpansionRatio             (compressed → decompressed cap)
 *
 * Caps abort streaming inflate immediately; partial entry files are
 * fs.rm-ed before the error throws so a failed extract leaves no
 * half-written state on disk.
 *
 * Path-traversal defense routes every entry name through
 * `b.guardFilename.verifyExtractionPath(name, root)` — the dual-check
 * (string + fs.realpath agreement) that defends the CVE-2025-4517
 * PATH_MAX TOCTOU class. Symlink + hardlink + device entries are
 * refused unconditionally by default; `entryTypePolicy` opt-ins
 * route the entry through an additional realpath-on-target check.
 */

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var ArchiveReadError = defineClass("ArchiveReadError", { alwaysPermanent: true });

// Lazy because guard-archive + guard-filename pull in the full
// guard-family validator chain — the reader's read-only paths don't
// need them; only extract() does.
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var guardArchive  = lazyRequire(function () { return require("./guard-archive"); });
var safeDecompress = lazyRequire(function () { return require("./safe-decompress"); });

// ---- Wire-format constants ------------------------------------------------
// Aligned with the write-side `lib/archive.js`. APPNOTE.TXT § references
// follow each signature so a future spec bump is mechanical.

var SIG_LFH                 = 0x04034b50;       // allow:raw-byte-literal — APPNOTE §4.3.7 LFH magic dword (wire-format-fixed)
var SIG_CFH                 = 0x02014b50;       // allow:raw-byte-literal — APPNOTE §4.3.12 CFH magic dword (wire-format-fixed)
var SIG_EOCD                = 0x06054b50;       // allow:raw-byte-literal — APPNOTE §4.3.16 EOCD magic dword (wire-format-fixed)
var SIG_EOCD64              = 0x06064b50;       // allow:raw-byte-literal — APPNOTE §4.3.14 ZIP64 EOCD magic dword (wire-format-fixed)
var SIG_EOCD64_LOCATOR      = 0x07064b50;       // allow:raw-byte-literal — APPNOTE §4.3.15 ZIP64 EOCD locator magic dword (wire-format-fixed)
var SIG_DATA_DESCRIPTOR     = 0x08074b50;       // allow:raw-byte-literal — APPNOTE §4.3.9 data-descriptor magic dword (wire-format-fixed)
void SIG_EOCD64; void SIG_EOCD64_LOCATOR;

var METHOD_STORE_ID         = 0;
var METHOD_DEFLATE_ID       = 8;

var FLAG_ENCRYPTED          = 0x0001;           // §4.4.4 bit 0 — encrypted entry
var FLAG_DATA_DESCRIPTOR    = 0x0008;           // §4.4.4 bit 3 — data descriptor follows
var FLAG_UTF8_NAME          = 0x0800;           // §4.4.4 bit 11 — UTF-8 name/comment
void FLAG_UTF8_NAME;
void SIG_DATA_DESCRIPTOR;

// EOCD record is 22 bytes minimum (§4.3.16); operator-supplied comments
// can extend it by up to 64 KiB. We search the trailing 64 KiB + 22
// bytes from EOF for the signature.
var EOCD_MIN_BYTES          = C.BYTES.bytes(22);
var EOCD_MAX_COMMENT_BYTES  = C.BYTES.kib(64);
var EOCD_SCAN_BYTES         = EOCD_MIN_BYTES + EOCD_MAX_COMMENT_BYTES;

// LFH fixed prefix is 30 bytes (§4.3.7); CD fixed prefix is 46 bytes
// (§4.3.12). Variable-length name/extra/comment fields follow.
var LFH_FIXED_BYTES         = C.BYTES.bytes(30);
var CFH_FIXED_BYTES         = C.BYTES.bytes(46);

// MS-DOS epoch — 1980-01-01. Used to map encoded dos-time back to a
// Date object for entry mtime.
var MSDOS_EPOCH_YEAR        = 1980;

// ---- Default zip-bomb / entry caps ---------------------------------------

var DEFAULT_BOMB_POLICY = Object.freeze({
  maxEntries:                65535,                                   // allow:raw-byte-literal — APPNOTE §4.4.21 16-bit entry-count field's max (ZIP64 deferred)
  maxEntryDecompressedBytes: C.BYTES.mib(128),                  // per-entry cap
  maxTotalDecompressedBytes: C.BYTES.gib(4),                    // archive-wide cap
  maxExpansionRatio:         100,                                     // compressed → decompressed ratio cap
});

var DEFAULT_ENTRY_TYPE_POLICY = Object.freeze({
  symlinks:  false,
  hardlinks: false,
  devices:   false,
  fifos:     false,
  sockets:   false,
});

// ---- Helpers --------------------------------------------------------------

function _msdosToDate(dosDate, dosTime) {
  var year   = ((dosDate >>> 9)  & 0x7f) + MSDOS_EPOCH_YEAR;
  var month  = ((dosDate >>> 5)  & 0x0f) - 1;
  var day    = (dosDate          & 0x1f);
  var hour   = ((dosTime >>> 11) & 0x1f);
  var minute = ((dosTime >>> 5)  & 0x3f);
  var second = (dosTime          & 0x1f) * 2;
  return new Date(year, month, day, hour, minute, second);
}

function _isUnixSymlinkAttrs(externalAttrs) {
  // S_IFLNK = 0o120000 (octal). External file attributes' high 16 bits
  // carry the unix mode when "version made by" host == 3 (UNIX).
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

// ---- Random-access EOCD locator -------------------------------------------

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
  // Search backwards for the EOCD signature — comments live after the
  // fixed 22-byte record, so we walk from the latest plausible start
  // down to the earliest.
  for (var i = tail.length - EOCD_MIN_BYTES; i >= 0; i -= 1) {
    if (tail.readUInt32LE(i) === SIG_EOCD) {
      // Verify the comment length field matches our trailing slice —
      // if the operator-supplied EOCD signature embedded in a comment
      // body matched first, the comment-length field will overflow
      // past EOF and we keep scanning.
      var commentLen = tail.readUInt16LE(i + 20);
      if (i + EOCD_MIN_BYTES + commentLen === tail.length) {
        return {
          eocdOffset:           scanOffset + i,
          diskNumber:           tail.readUInt16LE(i + 4),
          cdDiskNumber:         tail.readUInt16LE(i + 6),
          entriesOnThisDisk:    tail.readUInt16LE(i + 8),            // allow:raw-byte-literal — APPNOTE §4.3.16 EOCD field offset
          totalEntries:         tail.readUInt16LE(i + 10),           // allow:raw-byte-literal — APPNOTE §4.3.16 EOCD field offset
          cdSize:               tail.readUInt32LE(i + 12),           // allow:raw-byte-literal — APPNOTE §4.3.16 EOCD field offset
          cdOffset:             tail.readUInt32LE(i + 16),           // allow:raw-byte-literal — APPNOTE §4.3.16 EOCD field offset
          commentLength:        commentLen,
        };
      }
    }
  }
  throw new ArchiveReadError("archive-read/no-eocd",
    "End-of-central-directory record not found in trailing " + scanLen + " bytes");
}

// ---- Random-access central-directory walk ---------------------------------

async function _readCentralDirectory(adapter, eocd) {
  if (eocd.diskNumber !== 0 || eocd.cdDiskNumber !== 0) {
    throw new ArchiveReadError("archive-read/multi-disk",
      "multi-disk archives are not supported (diskNumber=" + eocd.diskNumber + ")");
  }
  if (eocd.totalEntries === 0xffff || eocd.cdSize === 0xffffffff || eocd.cdOffset === 0xffffffff) {
    // ZIP64 sentinel — not supported in v0.12.7. Will land in a
    // follow-up patch when an operator surfaces a need.
    throw new ArchiveReadError("archive-read/zip64-unsupported",
      "ZIP64 archives are not supported in v0.12.7 (operators at >4 GiB / >65535 entries should switch to tar — lands v0.12.8)");
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
        "0x" + cdBytes.readUInt32LE(pos).toString(16));                    // allow:raw-byte-literal — radix=16 for hex parse, not byte count
    }
    var generalFlags     = cdBytes.readUInt16LE(pos + 8);                  // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var method           = cdBytes.readUInt16LE(pos + 10);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var dosTime          = cdBytes.readUInt16LE(pos + 12);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var dosDate          = cdBytes.readUInt16LE(pos + 14);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var crc32            = cdBytes.readUInt32LE(pos + 16);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var compressedSize   = cdBytes.readUInt32LE(pos + 20);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var uncompressedSize = cdBytes.readUInt32LE(pos + 24);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var nameLen          = cdBytes.readUInt16LE(pos + 28);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var extraLen         = cdBytes.readUInt16LE(pos + 30);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var commentLen       = cdBytes.readUInt16LE(pos + 32);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var externalAttrs    = cdBytes.readUInt32LE(pos + 38);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var lfhOffset        = cdBytes.readUInt32LE(pos + 42);                 // allow:raw-byte-literal — APPNOTE §4.3.12 CFH field offset
    var nameStart        = pos + CFH_FIXED_BYTES;
    var extraStart       = nameStart + nameLen;
    var totalLen         = CFH_FIXED_BYTES + nameLen + extraLen + commentLen;
    if (pos + totalLen > cdBytes.length) {
      throw new ArchiveReadError("archive-read/cd-truncated",
        "central directory entry " + n + " variable-length fields overflow CD");
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || lfhOffset === 0xffffffff) {
      throw new ArchiveReadError("archive-read/zip64-unsupported",
        "central directory entry " + n + " carries ZIP64 sentinel sizes (not supported in v0.12.7)");
    }
    // ZIP names are CP437 or UTF-8 (per FLAG_UTF8_NAME bit). Decode
    // as UTF-8 unconditionally — Codex P2 territory if operators in
    // the wild rely on CP437; v0.12.7 ships UTF-8 only and operators
    // with legacy CP437-only producers reach for an external decoder.
    var name = cdBytes.slice(nameStart, nameStart + nameLen).toString("utf8");
    var extraFields = cdBytes.slice(extraStart, extraStart + extraLen);
    entries.push({
      name:             name,
      method:           method,
      generalFlags:     generalFlags,
      crc:              crc32,
      compressedSize:   compressedSize,
      uncompressedSize: uncompressedSize,
      mtime:            _msdosToDate(dosDate, dosTime),
      externalAttrs:    externalAttrs,
      extraFields:      extraFields,
      lfhOffset:        lfhOffset,
      isEncrypted:      (generalFlags & FLAG_ENCRYPTED) !== 0,
      hasDataDescriptor:(generalFlags & FLAG_DATA_DESCRIPTOR) !== 0,
      _entryType:       null,  // memoized on first access
    });
    pos += totalLen;
  }
  return entries;
}

// ---- LFH/CD skew verification --------------------------------------------

async function _verifyLfhMatchesCd(adapter, entry) {
  var lfhPrefix = await adapter.range(entry.lfhOffset, LFH_FIXED_BYTES);
  if (lfhPrefix.readUInt32LE(0) !== SIG_LFH) {
    throw new ArchiveReadError("archive-read/bad-lfh-signature",
      "local file header for " + JSON.stringify(entry.name) +
      " has bad signature 0x" + lfhPrefix.readUInt32LE(0).toString(16));                    // allow:raw-byte-literal — radix=16 for hex parse, not byte count
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
  // When the data-descriptor flag is set, the LFH's crc/csize/usize
  // are all zero per APPNOTE §4.4.4 bit 3 — skip the comparison.
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
  // Name agreement — the LFH MUST carry the same byte sequence as the
  // CD entry. Defends the "two CD entries point at the same LFH" + the
  // "CD says name=X, LFH says name=Y" attack class.
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

// ---- Entry-type policy enforcement ---------------------------------------

function _enforceEntryTypePolicy(entry, policy) {
  var type = entry._entryType || (entry._entryType = _classifyEntryType(entry));
  if (type === "symlink"  && !policy.symlinks)  return "symlink";
  if (type === "device"   && !policy.devices)   return "device";
  if (type === "fifo"     && !policy.fifos)     return "fifo";
  if (type === "socket"   && !policy.sockets)   return "socket";
  // Note: ZIP entries don't carry a hardlink type bit — hardlinks are
  // a tar concept. We model the policy field for parity with v0.12.8
  // tar reader's policy shape; in ZIP read it's always allowed.
  void policy.hardlinks;
  return null;
}

// ---- Bomb-policy enforcement ---------------------------------------------

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
    // Expansion-ratio cap — only meaningful for non-empty compressed data.
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

// ---- Decompress one entry (random-access) ---------------------------------

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
    // Compose b.safeDecompress so the inflate path inherits the bomb
    // gate even if the operator's bombPolicy is generous — defense in
    // depth.
    var maxOutput = Math.min(
      bombPolicy.maxEntryDecompressedBytes,
      entry.uncompressedSize + C.BYTES.bytes(1)  // allow exactly the declared size
    );
    var decompressed = safeDecompress().safeDecompress(raw, {
      algorithm:          "deflate-raw",
      maxOutputBytes:     maxOutput,
      maxCompressedBytes: entry.compressedSize,
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
    " — only STORE (0) and DEFLATE (8) supported in v0.12.7");
}

// ---- Public read.zip factory ---------------------------------------------

function _normalizeBombPolicy(p) {
  if (!p) return DEFAULT_BOMB_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_BOMB_POLICY, p));
}

function _normalizeEntryTypePolicy(p) {
  if (!p) return DEFAULT_ENTRY_TYPE_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_ENTRY_TYPE_POLICY, p));
}

function _emitAudit(opts, action, outcome, metadata) {
  if (!opts || !opts.audit || typeof opts.audit.safeEmit !== "function") return;
  try {
    opts.audit.safeEmit({ action: action, outcome: outcome, metadata: metadata });
  } catch (_e) { /* drop-silent — audit sinks must never crash the reader */ }
}

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

  // Cooperative cancellation — operators pass an AbortSignal to bound a
  // large/slow archive read. Checked between entries (the natural yield
  // point); a long single-entry decompress is already bounded by the
  // bomb policy.
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
    // Return a shallow copy of each entry without the LFH offset (the
    // operator-facing shape doesn't need wire-format internals).
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

  // Run the b.guardArchive metadata cascade and refuse the whole archive on
  // any critical issue. Shared by disk `extract` and in-memory `extractEntries`
  // so both apply the identical posture-aware refusal. `auditAction` names the
  // audit row for the refusal path.
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

  // In-memory extraction: yields each file entry's decompressed bytes WITHOUT
  // writing to disk — for read-only / serverless filesystems. Applies the same
  // bomb-policy, guard cascade, entry-type policy, and per-entry filename
  // safety as `extract`; directory entries are skipped (no bytes). The realpath
  // agreement check is disk-specific and intentionally omitted (no extraction
  // root); the caller owns where, if anywhere, the bytes land.
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
      // Archive-level name threats (Zip-Slip traversal, etc.) are refused for
      // the whole archive by the guardArchive cascade above. The caller owns
      // final placement of the returned bytes; we deliberately do NOT apply the
      // disk-write filename policy (shell-exec extensions / reserved names) here
      // — nothing is written, and over-filtering would drop legitimate names.
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
    // Compose b.guardArchive on the metadata pass — operators with a
    // posture set declared via opts.guardProfile get the cascade.
    _assertGuardMetadata(loaded.entries, "archive.read.extract.refused");
    var written = [];
    var bytesExtracted = 0;
    var totalDecompressed = 0;
    try {
      for (var i = 0; i < loaded.entries.length; i += 1) {
        _throwIfAborted();
        var entry = loaded.entries[i];
        // Skip directory + dangerous-by-default entry types unless the
        // entry-type policy opts in.
        if (entry.isEncrypted && !extractOpts.allowEncrypted) {
          throw new ArchiveReadError("archive-read/encrypted-entry",
            "entry " + JSON.stringify(entry.name) + " is encrypted — " +
            "v0.12.7 does not decrypt; Flavor 1/2/3 land v0.12.10/v0.12.11");
        }
        var typeRefusal = _enforceEntryTypePolicy(entry, entryTypePolicy);
        if (typeRefusal) {
          throw new ArchiveReadError("archive-read/entry-type-refused",
            "entry " + JSON.stringify(entry.name) + " is a " + typeRefusal +
            " — refused by entryTypePolicy (opt in via b.guardArchive.entryTypePolicy({ " +
            typeRefusal + "s: true }))");
        }
        if (_isDirectoryEntry(entry.name, entry.externalAttrs)) {
          // Materialize the directory ahead of any contained-file
          // entries (operator-shipped archives sometimes order entries
          // such that the directory comes after its files; mkdirSync
          // recursive handles that case).
          var dirPath = guardFilename().verifyExtractionPath(entry.name, destination);
          nodeFs.mkdirSync(dirPath, { recursive: true });
          continue;
        }
        // Path safety — dual-check (string + realpath agreement).
        var resolvedPath = guardFilename().verifyExtractionPath(entry.name, destination);
        // Make sure the parent directory exists before write.
        var parentDir = nodePath.dirname(resolvedPath);
        if (!nodeFs.existsSync(parentDir)) {
          nodeFs.mkdirSync(parentDir, { recursive: true });
        }
        // Refuse to overwrite pre-existing files. Atomic-rollback
        // requires that we only ever DELETE files we CREATED; if a
        // later entry fails (LFH/CD skew, bomb-cap trip), the catch
        // block must not erase operator files that lived under the
        // destination before extract ran. The contract is: extract
        // into a fresh / empty subtree, or refuse. Operators with a
        // legitimate merge use case make a copy first.
        if (nodeFs.existsSync(resolvedPath)) {
          throw new ArchiveReadError("archive-read/destination-exists",
            "extract: destination file already exists at " +
            JSON.stringify(resolvedPath) + " — refuse to overwrite; pass an " +
            "empty / fresh destination directory or remove the existing file");
        }
        // Verify LFH matches CD before decompressing.
        var lfhResult = await _verifyLfhMatchesCd(adapter, entry);
        // Decompress.
        var body = await _decompressEntry(adapter, entry, lfhResult.dataStart, bombPolicy);
        totalDecompressed += body.length;
        if (totalDecompressed > bombPolicy.maxTotalDecompressedBytes) {
          throw new ArchiveReadError("archive-read/total-too-large",
            "cumulative uncompressed=" + totalDecompressed +
            " exceeds maxTotalDecompressedBytes during extract");
        }
        // Write entry to disk. Atomic rename via a tmp file so a
        // partial write during inflate doesn't leave a half-file at
        // the canonical name. Pre-existence check above guarantees
        // the rename targets a non-existent path.
        var tmpPath = resolvedPath + ".__blamejs-archive-read-tmp__";
        nodeFs.writeFileSync(tmpPath, body);
        nodeFs.renameSync(tmpPath, resolvedPath);
        written.push({ name: entry.name, bytesWritten: body.length, path: resolvedPath });
        bytesExtracted += body.length;
      }
    } catch (extractErr) {
      // Clean up any partial extract — the destination tree may now
      // contain files from successful entries (we only get here for
      // entries we just CREATED; pre-existence was refused above).
      // rm them so the operator sees an atomic refusal rather than a
      // half-extracted state on disk.
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

// ---- Trusted-stream variant ----------------------------------------------

/**
 * @primitive b.archive.read.zip.fromTrustedStream
 * @signature b.archive.read.zip.fromTrustedStream(adapter, opts?)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.read.zip, b.archive.adapters.trustedStream
 *
 * Forward-scan-only ZIP reader for trusted Readable sources. No
 * central-directory comparison — operators reaching for this primitive
 * are declaring they own the producer (e.g. piping their own
 * `b.archive.zip().toStream()` output back into a reader for round-trip
 * verification).
 *
 * Adversarial input MUST use the random-access entry point with an
 * `fs` / `buffer` / `objectStore` / `http` adapter.
 *
 * @opts
 *   bombPolicy:       { maxEntries, maxEntryDecompressedBytes,
 *                       maxTotalDecompressedBytes, maxExpansionRatio },
 *   audit:            b.audit,
 *
 * @example
 *   var produced = fs.createReadStream("./own-export.zip");
 *   var reader   = b.archive.read.zip.fromTrustedStream(
 *     b.archive.adapters.trustedStream(produced)
 *   );
 *   for await (var e of reader.entries()) console.log(e.name, e.size);
 */
function fromTrustedStream(adapter, opts) {
  if (!adapter || adapter.kind !== "trusted-sequential") {
    throw new ArchiveReadError("archive-read/bad-adapter",
      "fromTrustedStream: adapter must come from b.archive.adapters.trustedStream(readable)");
  }
  opts = opts || {};
  var bombPolicy = _normalizeBombPolicy(opts.bombPolicy);
  void bombPolicy;

  // Trusted stream walks LFH-by-LFH. v0.12.7 ships the API surface +
  // a basic LFH walker for round-trip verification of the framework's
  // own emitted archives. The full feature parity (extraction via
  // streaming inflate, data-descriptor scanning) is intentionally
  // deferred to v0.12.8 alongside the tar reader's sequential mode.
  async function inspect() {
    throw new ArchiveReadError("archive-read/trusted-stream-inspect-deferred",
      "fromTrustedStream.inspect() is deferred to v0.12.8 — use the random-access entry " +
      "point with b.archive.adapters.buffer(await collect(readable)) for v0.12.7");
  }

  async function* entries() {
    throw new ArchiveReadError("archive-read/trusted-stream-entries-deferred",
      "fromTrustedStream.entries() is deferred to v0.12.8 — collect into buffer for v0.12.7");
  }

  async function extract() {
    throw new ArchiveReadError("archive-read/trusted-stream-extract-deferred",
      "fromTrustedStream.extract() is deferred to v0.12.8 — collect into buffer for v0.12.7");
  }

  return {
    kind:    "zip-trusted-sequential",
    inspect: inspect,
    entries: entries,
    extract: extract,
  };
}

zip.fromTrustedStream = fromTrustedStream;

module.exports = {
  zip:                       zip,
  ArchiveReadError:          ArchiveReadError,
  DEFAULT_BOMB_POLICY:       DEFAULT_BOMB_POLICY,
  DEFAULT_ENTRY_TYPE_POLICY: DEFAULT_ENTRY_TYPE_POLICY,
  // exposed for sibling modules (lib/safe-archive.js + tests)
  _locateEocd:               _locateEocd,
  _readCentralDirectory:     _readCentralDirectory,
};
