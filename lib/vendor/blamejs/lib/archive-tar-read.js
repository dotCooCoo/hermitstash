"use strict";
/**
 * archive-tar-read — POSIX pax tar reader. Sibling of lib/archive-tar.js
 * (write side) the way lib/archive-read.js is to lib/archive.js for ZIP.
 * `b.archive.read.tar` lives here so the @module/@primitive validator
 * can pair `function tar(adapter, opts)` cleanly with the @primitive
 * comment block without colliding with the write-side `function
 * tarBuilder()` (which is exported as `b.archive.tar`).
 */

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

void TF_CHARDEV; void TF_BLOCKDEV; void TF_FIFO; void TF_CONTIGUOUS;

var DEFAULT_BOMB_POLICY = Object.freeze({
  maxEntries:                65535,                                                  // operator-friendly default ceiling
  maxEntryDecompressedBytes: C.BYTES.mib(128),
  maxTotalDecompressedBytes: C.BYTES.gib(4),
  maxExpansionRatio:         100,                                                    // tar has no compression-ratio concept, but keep field for orchestrator policy parity
});

var DEFAULT_ENTRY_TYPE_POLICY = archiveEntryPolicy.DEFAULT_ENTRY_TYPE_POLICY;

function _normalizeBombPolicy(p) {
  if (!p) return DEFAULT_BOMB_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_BOMB_POLICY, p));
}

var _normalizeEntryTypePolicy = archiveEntryPolicy.normalize;

var _emitAudit = auditEmit.emitToSink;   // operator-sink audit emit (opts.audit)

function _isZeroBlock(buf) {
  for (var i = 0; i < BLOCK_SIZE; i += 1) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function _parsePaxRecords(buf) {
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

// A PAX `size` attribute is an attacker-controlled ASCII string. `parseInt` of
// a malformed value ("", "abc", "1e9") yields NaN, which then SILENTLY bypasses
// the entry-size bomb check (`NaN > maxEntryDecompressedBytes` is false) AND
// desyncs the block walker (`Math.ceil(NaN / BLOCK_SIZE)` is NaN, so `pos`
// advances by NaN). Reject anything that is not a plain non-negative integer.
function _paxSize(raw) {
  var s = String(raw).trim();
  var n = parseInt(s, 10);
  // Round-trip: a clean non-negative integer survives parseInt → String
  // unchanged. This rejects "", "abc" (NaN), "1e9", "100abc" (parseInt stops
  // early), negatives, leading zeros, and astronomically long strings that
  // overflow to Infinity (String(Infinity) !== s) — every shape that would
  // otherwise yield NaN/garbage and bypass the bomb check + desync the walker.
  if (!Number.isFinite(n) || n < 0 || String(n) !== s) {
    throw new TarError("archive-tar/bad-pax-size",
      "PAX size attribute " + JSON.stringify(raw) + " is not a non-negative integer");
  }
  return n;
}

async function _collectAdapterBytes(adapter, maxBytes) {
  if (adapter.kind === "random-access") {
    var size = adapter.size;
    if (size == null && typeof adapter.resolveSize === "function") {
      size = await adapter.resolveSize();
    }
    if (typeof size !== "number" || !Number.isFinite(size) || size <= 0) return Buffer.alloc(0);
    // Cap the random-access read the same way the trusted-sequential branch
    // caps its collector — a multi-GiB adapter.range(0, size) is an OOM lever
    // (the size comes from the adapter, e.g. an on-disk file's stat or an
    // operator-supplied length). The default ceiling is the bomb policy's
    // total-decompressed cap.
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
  if (tf === TF_DIRECTORY) return "directory";
  if (tf === TF_SYMLINK) return "symlink";
  if (tf === TF_HARDLINK) return "hardlink";
  if (tf === TF_CHARDEV || tf === TF_BLOCKDEV) return "device";
  if (tf === TF_FIFO) return "fifo";
  if (tf === TF_CONTIGUOUS) return "file";
  return "unknown";
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
    var globalPax = null;
    var zeroBlockCount = 0;
    while (pos + BLOCK_SIZE <= bytes.length) {
      var block = bytes.slice(pos, pos + BLOCK_SIZE);
      pos += BLOCK_SIZE;
      if (_isZeroBlock(block)) {
        zeroBlockCount += 1;
        if (zeroBlockCount >= 2) break;
        continue;
      }
      zeroBlockCount = 0;
      var hdr = _parseHeader(block);
      if (hdr.typeflag === TF_PAX_EXTENDED || hdr.typeflag === TF_PAX_GLOBAL) {
        // The per-entry bomb cap below (line ~252) is AFTER the PAX `continue`,
        // so a PAX header body (its size is the attacker-controlled ustar octal
        // field, up to ~8 GiB) escaped it — a multi-hundred-MiB UTF-8 string +
        // record Object materialization above the cap operators set. Legitimate
        // PAX/global bodies are tiny, so bound them by the same per-entry cap.
        if (hdr.size > bombPolicy.maxEntryDecompressedBytes) {
          throw new TarError("archive-tar/entry-too-large",
            "pax header body size=" + hdr.size + " exceeds maxEntryDecompressedBytes=" +
            bombPolicy.maxEntryDecompressedBytes);
        }
        var bodyEnd = pos + Math.ceil(hdr.size / BLOCK_SIZE) * BLOCK_SIZE;
        if (bodyEnd > bytes.length) {
          throw new TarError("archive-tar/truncated-entry",
            "pax extended header declares size=" + hdr.size +
            " bytes but only " + (bytes.length - pos) +
            " bytes remain after header — archive truncated mid-stream");
        }
        var paxBody = bytes.slice(pos, pos + hdr.size);
        var records = _parsePaxRecords(paxBody);
        if (hdr.typeflag === TF_PAX_EXTENDED) pendingPax = records;
        else globalPax = records;
        pos = bodyEnd;
        continue;
      }
      if (globalPax) {
        if (globalPax.path) hdr.name = globalPax.path;
        if (globalPax.size) hdr.size = _paxSize(globalPax.size);
        if (globalPax.linkpath) hdr.linkname = globalPax.linkpath;
      }
      if (pendingPax) {
        if (pendingPax.path) hdr.name = pendingPax.path;
        if (pendingPax.size) hdr.size = _paxSize(pendingPax.size);
        if (pendingPax.linkpath) hdr.linkname = pendingPax.linkpath;
        pendingPax = null;
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
      var bodyStart = pos;
      var paddedSize = Math.ceil(hdr.size / BLOCK_SIZE) * BLOCK_SIZE;
      // Refuse truncated archives upfront.
      // The walker advances `pos` by the declared padded block size; if
      // the buffer ends mid-body, extract() would silently slice a
      // partial payload (header says 11 bytes, buffer holds 8 — without
      // this check we'd write the 8-byte prefix as if it were the
      // complete file). Detector: archive-tar-truncated-walker-without-bounds-check.
      if (bodyStart + paddedSize > bytes.length) {
        throw new TarError("archive-tar/truncated-entry",
          "entry " + JSON.stringify(hdr.name) +
          " declares size=" + hdr.size + " (padded=" + paddedSize +
          ") but only " + (bytes.length - bodyStart) +
          " bytes remain after header — archive truncated mid-stream");
      }
      hdr._bodyStart = bodyStart;
      hdr._paddedSize = paddedSize;
      entries.push(hdr);
      pos += paddedSize;
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
        entryType: _classifyTypeflag(e.typeflag),
      };
    });
  }

  // Shared b.guardArchive metadata cascade — disk `extract` + in-memory
  // `extractEntries` refuse the whole archive identically on a critical issue.
  function _assertGuardMetadata(entries, auditAction) {
    if (opts.guardProfile === false) return;
    var profile = opts.guardProfile || "balanced";
    var guardEntries = entries.map(function (e) {
      return {
        name:           e.name,
        size:           e.size,
        compressedSize: e.size,
        isSymlink:      e.typeflag === TF_SYMLINK,
        isHardlink:     e.typeflag === TF_HARDLINK,
        linkTarget:     e.linkname,
        isDirectory:    e.typeflag === TF_DIRECTORY,
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
      "extract refused — " + critical.length + " critical guard issue(s)");
  }

  // In-memory extraction: yields each regular file entry's bytes without
  // writing to disk (read-only / serverless filesystems). Same guard cascade,
  // type-policy refusals, filename safety, and bomb cap as `extract`; directory
  // and (validated) link entries carry no content and are not yielded.
  async function* extractEntries(extractOpts) {
    extractOpts = extractOpts || {};
    var allowDangerous = extractOpts.allowDangerous || {};
    var walked = await _walk();
    var entries = walked.entries;
    var bytes = walked.bytes;
    _assertGuardMetadata(entries, "archive.read.tar.extractEntries.refused");
    var totalDecompressed = 0;
    var yielded = 0;
    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      var type = _classifyTypeflag(entry.typeflag);
      if (type === "device" || type === "fifo" || type === "socket") {
        throw new TarError("archive-tar/entry-type-refused",
          "entry " + JSON.stringify(entry.name) + " is a " + type + " — refused unconditionally");
      }
      if (type === "symlink" && !(allowDangerous.symlinks || entryTypePolicy.symlinks)) {
        throw new TarError("archive-tar/entry-type-refused",
          "entry " + JSON.stringify(entry.name) + " is a symlink — refused by entryTypePolicy");
      }
      if (type === "hardlink" && !(allowDangerous.hardlinks || entryTypePolicy.hardlinks)) {
        throw new TarError("archive-tar/entry-type-refused",
          "entry " + JSON.stringify(entry.name) + " is a hardlink — refused by entryTypePolicy");
      }
      // Directories + (now-permitted) links carry no content bytes.
      if (type === "directory" || type === "symlink" || type === "hardlink") continue;
      // Archive-level name threats are refused by the guardArchive cascade
      // above; the caller owns placement of the returned bytes, so the
      // disk-write filename policy is intentionally not applied here.
      // COPY the slice — bytes.subarray/slice shares the full collected-archive
      // backing store, so a caller retaining one entry would pin the whole
      // archive in memory, defeating the serverless memory goal. Buffer.from
      // gives the entry its own backing store (matching the ZIP path, whose
      // _decompressEntry already returns a fresh buffer).
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
    _emitAudit(opts, "archive.read.tar.extractEntries.completed", "success", { entries: yielded });
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
        var type = _classifyTypeflag(entry.typeflag);
        if (type === "device" || type === "fifo" || type === "socket") {
          throw new TarError("archive-tar/entry-type-refused",
            "entry " + JSON.stringify(entry.name) + " is a " + type +
            " — refused unconditionally (no application use case)");
        }
        if (type === "symlink" && !(allowDangerous.symlinks || entryTypePolicy.symlinks)) {
          throw new TarError("archive-tar/entry-type-refused",
            "entry " + JSON.stringify(entry.name) + " is a symlink — refused by entryTypePolicy " +
            "(opt in via allowDangerous: { symlinks: true })");
        }
        if (type === "hardlink" && !(allowDangerous.hardlinks || entryTypePolicy.hardlinks)) {
          throw new TarError("archive-tar/entry-type-refused",
            "entry " + JSON.stringify(entry.name) + " is a hardlink — refused by entryTypePolicy " +
            "(opt in via allowDangerous: { hardlinks: true })");
        }
        var resolvedPath = guardFilename().verifyExtractionPath(entry.name, destination);
        if (type === "directory") {
          nodeFs.mkdirSync(resolvedPath, { recursive: true });
          continue;
        }
        if (nodeFs.existsSync(resolvedPath)) {
          throw new TarError("archive-tar/destination-exists",
            "extract: destination file already exists at " +
            JSON.stringify(resolvedPath) + " — refuse to overwrite");
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
        // Atomic, symlink-refusing write. The previous hand-rolled form staged
        // into a PREDICTABLE temp name (resolvedPath +
        // ".__blamejs-archive-tar-tmp__") via a plain writeFileSync, so a
        // symlink pre-planted at that exact path would be followed (CWE-59).
        // writeSync uses a CSPRNG temp opened O_EXCL | O_NOFOLLOW + rename.
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
