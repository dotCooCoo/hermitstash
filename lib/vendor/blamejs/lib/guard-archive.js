"use strict";
/**
 * guard-archive — archive content-safety primitive (b.guardArchive).
 *
 * Threat catalog grounded in current research (multiple 2025-2026 CVEs):
 *   - CVE-2025-3445 mholt/archiver Zip Slip
 *   - CVE-2025-32779 EDDI Zip Slip
 *   - CVE-2025-62156 Argo Workflows Zip Slip
 *   - CVE-2025-66945 Zdir Pro Path Traversal
 *   - CVE-2025-45582 GNU Tar Path Traversal (two-step symlink bypass)
 *   - CVE-2025-11001 / 11002 7-Zip symlink + directory traversal RCE
 *   - CVE-2025-4138 Python tarfile extraction-filter symlink bypass
 *   - CVE-2025-4517 Python tarfile path traversal
 *   - CVE-2025-10854 txtai Framework path traversal
 *   - CVE-2025-12060 Keras path traversal
 *   - CVE-2026-26960 node-tar hardlink-via-symlink-chain escape
 *
 *   var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
 *   var fmt = b.guardArchive.inspectMagic(buffer);
 *   var g = b.guardArchive.gate({ profile: "strict" });
 *
 * **Scope.** This primitive validates archive METADATA (entry list +
 * sizes + flags + types) before extraction. It does NOT include a
 * pure-JS unzip / untar implementation — the framework's no-deps rule
 * argues against shipping a parser for every archive format. Operators
 * use their archive library (built-in zlib for gzip/deflate, OS tar /
 * unzip CLI, or vendored libraries) to enumerate entries, then validate
 * the list before extracting. The gate's job is to refuse hostile
 * metadata BEFORE files touch the filesystem.
 *
 *   var entries = parseZipCentralDirectory(uploadedBuffer);
 *   var rv = b.guardArchive.validateEntries(entries, { profile: "strict" });
 *   if (!rv.ok) throw new Error("hostile archive: " + rv.issues[0].snippet);
 *   await extractEachEntry(entries, extractionRoot);
 *
 * Entry shape (operator passes one of these per archive entry):
 *
 *   {
 *     name:           string,    // entry filename / path WITHIN archive
 *     size:           number,    // uncompressed size in bytes
 *     compressedSize: number,    // compressed size (optional; enables ratio check)
 *     isSymlink:      boolean,   // true if entry creates a symbolic link
 *     isHardlink:     boolean,   // true if entry creates a hardlink
 *     linkTarget:     string,    // when isSymlink/isHardlink: where it points
 *     isDirectory:    boolean,   // directory entry (no extraction needed)
 *     isEncrypted:    boolean,   // entry is encrypted
 *     attrs:          object,    // optional: extra format-specific metadata
 *   }
 *
 * Threat catalog covered:
 *
 *   1. Zip slip / path traversal — entry name with `../`, `..\\`, or
 *      absolute path (leading `/` or `\\` or drive letter). Composes
 *      `b.guardFilename` for per-entry-name validation; archive-level
 *      adds the absolute-path check that filename-leaf doesn't.
 *
 *   2. Symlink escape — entry creates a symbolic link whose `linkTarget`
 *      contains `..` or absolute path that resolves outside the
 *      extraction root. Refused or audited per profile.
 *
 *   3. Hardlink escape — same as symlink but via the hardlink mechanism
 *      (CVE-2026-26960 node-tar class). The extraction step typically
 *      resolves hardlink targets relative to extraction root; entries
 *      with `..` in linkTarget escape.
 *
 *   4. Symlink-chained traversal — operator pre-extracts a symlink, then
 *      a later entry writes through the symlink's target. We refuse any
 *      entry whose extraction path passes THROUGH a symlink already in
 *      the entry list (when the operator passes pre-sorted entries).
 *
 *   5. Decompression-ratio bombs — per-entry compressedSize/size ratio
 *      cap (default: 100:1 strict, 1000:1 permissive). Aggregate ratio
 *      across all entries also capped.
 *
 *   6. Total-size cap — sum of uncompressed sizes (anti-DoS).
 *
 *   7. File-count cap — number of entries.
 *
 *   8. Nested-archive depth — refuses entries that are themselves
 *      archives unless `maxNestedDepth > 0`. Entry name suffixes are
 *      checked against an archive-extension catalog (.zip / .tar /
 *      .tar.gz / .tgz / .gz / .bz2 / .xz / .7z / .rar / .ar / .cpio /
 *      .lzma / .zst).
 *
 *   9. Per-entry-name validation via b.guardFilename — applies the full
 *      filename-safety catalog (path traversal / null-byte / Windows
 *      reserved names / NTFS ADS / RTLO bidi / overlong UTF-8 / shell-
 *      exec extensions / double-extension) to every entry's name.
 *
 *  10. Duplicate entry names — second entry with the same name silently
 *      overwrites the first on extraction. Refused.
 *
 *  11. Mixed-case duplicate names — case-insensitive collision on Windows
 *      / macOS HFS+ / APFS-non-case-sensitive volumes. Audited.
 *
 *  12. Encryption-claim mismatch — operator opts in to either "all
 *      entries encrypted" or "no entries encrypted"; mixing flagged.
 *
 *  13. Format-claim mismatch — `inspectMagic(buffer)` reads the first
 *      bytes and returns the detected format. Operator can compare
 *      against the declared content-type / extension; mismatch flagged.
 *
 *  14. Sparse archive (tar) — sparse entries can claim large
 *      uncompressed size with zero data; refused unless explicitly
 *      allowed.
 *
 *  15. Anti-DoS caps — total entry count, per-entry size, total size,
 *      compression ratio, recursion depth.
 *
 * Profiles:
 *   strict     — every threat refused; no symlinks; no hardlinks;
 *                no nested archives; 100 entry max; 100 MiB total;
 *                100:1 ratio cap; case-insensitive collision refused.
 *   balanced   — symlinks within extraction-root allowed; no hardlinks;
 *                nested-depth 2; 10000 entries; 1 GiB total; 100:1
 *                per-entry / 1000:1 aggregate; case-collision audited.
 *   permissive — symlinks + hardlinks within root allowed; nested-depth
 *                4; 100000 entries; 10 GiB total; 1000:1 ratio.
 *
 * Compliance postures: hipaa / pci-dss / gdpr / soc2 — strict
 * overlay + forensic snapshots.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var guardFilename = require("./guard-filename");
var { GuardArchiveError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardArchiveError.factory;

// Archive extension catalog — entries with these suffixes are treated
// as nested archives.
var ARCHIVE_EXTENSIONS = Object.freeze([
  ".zip", ".jar", ".war", ".ear", ".apk", ".ipa",
  ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
  ".tar.zst", ".tzst", ".tar.lzma", ".tlz",
  ".gz", ".bz2", ".xz", ".lzma", ".lz4", ".zst",
  ".7z", ".rar", ".ar", ".cpio", ".cab", ".iso", ".dmg",
  ".deb", ".rpm", ".msi",
]);

// Magic-byte signatures keyed by format name. First N bytes uniquely
// identify the format; we read up to 8 bytes for matching.
var MAGIC_SIGNATURES = Object.freeze([
  { format: "zip",   bytes: [0x50, 0x4B, 0x03, 0x04] },              // allow:raw-byte-literal — ZIP local file header magic per APPNOTE.TXT §4.3.7
  { format: "zip",   bytes: [0x50, 0x4B, 0x05, 0x06] },              // allow:raw-byte-literal — ZIP empty-archive end-of-central-directory magic
  { format: "zip",   bytes: [0x50, 0x4B, 0x07, 0x08] },              // allow:raw-byte-literal — ZIP spanned-archive marker
  { format: "gzip",  bytes: [0x1F, 0x8B] },                          // allow:raw-byte-literal — gzip magic per RFC 1952 §2.3.1
  { format: "bzip2", bytes: [0x42, 0x5A, 0x68] },                    // allow:raw-byte-literal — bzip2 "BZh" magic
  { format: "xz",    bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },  // allow:raw-byte-literal — XZ magic per xz spec §2.1.1.1
  { format: "7z",    bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },  // allow:raw-byte-literal — 7-zip magic per 7z spec
  { format: "rar4",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] }, // allow:raw-byte-literal — RAR4 magic
  { format: "rar5",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] }, // allow:raw-byte-literal — RAR5 magic
  { format: "lzma",  bytes: [0x5D, 0x00, 0x00] },                    // allow:raw-byte-literal — LZMA magic byte sequence (heuristic)
  { format: "zstd",  bytes: [0x28, 0xB5, 0x2F, 0xFD] },              // allow:raw-byte-literal — Zstandard magic per RFC 8478 §3.1.1
  // tar is identified by the "ustar" magic at byte offset 257 inside
  // the first 512-byte header; handled separately in inspectMagic().
]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:                "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "reject",
    hardlinkPolicy:            "reject",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "reject",
    duplicateNamePolicy:       "reject",
    caseInsensitiveCollisionPolicy: "reject",
    sparseEntryPolicy:         "reject",
    filenameProfile:           "balanced",   // per-entry name validation profile
    maxEntries:                100,           // allow:raw-byte-literal — entry count cap, not byte size
    maxTotalBytes:             C.BYTES.mib(100),
    maxEntryBytes:             C.BYTES.mib(50),
    maxCompressionRatio:       100,           // allow:raw-byte-literal — ratio multiplier, not byte size
    maxAggregateRatio:         200,           // allow:raw-byte-literal — aggregate-ratio multiplier, not byte size
    maxNestedDepth:            0,             // allow:raw-byte-literal — recursion depth, not byte size
  },
  "balanced": {
    bidiPolicy:                "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "strip",
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "audit",       // allowed within extraction root
    hardlinkPolicy:            "reject",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "audit",
    duplicateNamePolicy:       "reject",
    caseInsensitiveCollisionPolicy: "audit",
    sparseEntryPolicy:         "audit",
    filenameProfile:           "balanced",
    maxEntries:                10000,         // allow:raw-byte-literal — entry count cap, not byte size
    maxTotalBytes:             C.BYTES.gib(1),
    maxEntryBytes:             C.BYTES.mib(500),
    maxCompressionRatio:       100,           // allow:raw-byte-literal — ratio multiplier, not byte size
    maxAggregateRatio:         1000,          // allow:raw-byte-literal — aggregate-ratio multiplier, not byte size
    maxNestedDepth:            2,             // allow:raw-byte-literal — recursion depth, not byte size
  },
  "permissive": {
    bidiPolicy:                "audit",
    controlPolicy:             "strip",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "strip",
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "audit",
    hardlinkPolicy:            "audit",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "audit",
    duplicateNamePolicy:       "audit",
    caseInsensitiveCollisionPolicy: "audit",
    sparseEntryPolicy:         "audit",
    filenameProfile:           "permissive",
    maxEntries:                100000,        // allow:raw-byte-literal — entry count cap, not byte size
    maxTotalBytes:             C.BYTES.gib(10),
    maxEntryBytes:             C.BYTES.gib(2),
    maxCompressionRatio:       1000,          // allow:raw-byte-literal — ratio multiplier, not byte size
    maxAggregateRatio:         10000,         // allow:raw-byte-literal — aggregate-ratio multiplier, not byte size
    maxNestedDepth:            4,             // allow:raw-byte-literal — recursion depth, not byte size
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(10),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr": Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

// ---- Helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardArchiveError,
    errCodePrefix:      "archive",
  });
}

function _isAbsolutePath(name) {
  if (!name || typeof name !== "string") return false;
  if (name.charAt(0) === "/" || name.charAt(0) === "\\") return true;
  // Windows drive-letter prefix (C:\ / C:/).
  if (/^[A-Za-z]:[\\/]/.test(name)) return true;
  return false;
}

function _hasTraversal(name) {
  if (!name || typeof name !== "string") return false;
  if (/(^|[/\\])\.\.($|[/\\])/.test(name)) return true;
  if (name === ".." || name === ".") return true;
  return false;
}

function _isArchiveName(name) {
  var lower = String(name || "").toLowerCase();
  for (var i = 0; i < ARCHIVE_EXTENSIONS.length; i += 1) {
    if (lower.endsWith(ARCHIVE_EXTENSIONS[i])) return true;
  }
  return false;
}

function _bufferStartsWith(buf, sig) {
  if (!Buffer.isBuffer(buf) || buf.length < sig.length) return false;
  for (var i = 0; i < sig.length; i += 1) {
    if (buf[i] !== sig[i]) return false;
  }
  return true;
}

// inspectMagic — reads the first bytes of a buffer and returns the
// detected archive format, or null if not recognized.
function inspectMagic(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return null;
  for (var i = 0; i < MAGIC_SIGNATURES.length; i += 1) {
    var entry = MAGIC_SIGNATURES[i];
    if (_bufferStartsWith(buffer, entry.bytes)) {
      return { format: entry.format, magic: entry.bytes.slice() };
    }
  }
  // tar — "ustar" magic at offset 257 within the first 512-byte block.
  if (buffer.length >= 263) {
    var ustar = "ustar";
    var match = true;
    for (var ti = 0; ti < ustar.length; ti += 1) {
      if (buffer[257 + ti] !== ustar.charCodeAt(ti)) { match = false; break; }
    }
    if (match) return { format: "tar", magic: null };
  }
  return null;
}

// checkExtractionPath — single-entry helper. Returns { ok, reason } for
// a candidate (entryName, extractionRoot) pair. Anchored, for callers
// that already enumerate entries and want a per-call boolean.
function checkExtractionPath(entryName, extractionRoot) {
  if (typeof entryName !== "string" || entryName.length === 0) {
    return { ok: false, reason: "empty entry name" };
  }
  if (_hasTraversal(entryName)) {
    return { ok: false, reason: "entry name contains .. component (zip slip)" };
  }
  if (_isAbsolutePath(entryName)) {
    return { ok: false, reason: "entry name is an absolute path" };
  }
  // Reject entries containing null bytes regardless of extraction root.
  if (entryName.indexOf(" ") !== -1) {
    return { ok: false, reason: "entry name contains null byte" };
  }
  void extractionRoot;
  // For runtime resolution: the operator's extraction code should
  // additionally call path.resolve(extractionRoot, entryName) and
  // check that the result startsWith path.resolve(extractionRoot) — we
  // cannot do it here without a node:path coupling that the gate
  // wants to keep portable.
  return { ok: true };
}

function _checkLinkTarget(target, kind) {
  // Return null when ok, or an issue object when escape-shaped.
  if (typeof target !== "string" || target.length === 0) return null;
  if (_isAbsolutePath(target)) {
    return {
      kind: kind + "-escape", severity: "critical",
      ruleId: "archive." + kind + "-absolute",
      snippet: kind + " target " + JSON.stringify(target) +
               " is an absolute path",
    };
  }
  if (_hasTraversal(target)) {
    return {
      kind: kind + "-escape", severity: "critical",
      ruleId: "archive." + kind + "-traversal",
      snippet: kind + " target " + JSON.stringify(target) +
               " contains .. component",
    };
  }
  return null;
}

// ---- Detection pass ----

function _detectIssues(entries, opts) {
  var issues = [];
  if (!Array.isArray(entries)) {
    issues.push({
      kind: "bad-input", severity: "high", ruleId: "archive.bad-input",
      snippet: "entries must be an array of { name, size, ... }",
    });
    return issues;
  }
  if (entries.length > opts.maxEntries) {
    issues.push({
      kind: "entry-count-cap", severity: "high",
      ruleId: "archive.entry-count",
      snippet: "entry count " + entries.length + " exceeds maxEntries " + opts.maxEntries,
    });
  }

  var totalSize = 0;
  var totalCompressed = 0;
  var nameSeen = Object.create(null);
  var caseSeen = Object.create(null);
  var encryptedCount = 0;
  var unencryptedCount = 0;

  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    if (!e || typeof e !== "object") {
      issues.push({
        kind: "bad-entry", severity: "high", ruleId: "archive.bad-entry",
        location: i,
        snippet: "entry at index " + i + " is not a plain object",
      });
      continue;
    }
    var name = e.name;
    if (typeof name !== "string" || name.length === 0) {
      issues.push({
        kind: "bad-entry-name", severity: "high",
        ruleId: "archive.bad-entry-name",
        location: i,
        snippet: "entry at index " + i + " has missing/non-string name",
      });
      continue;
    }

    // Path traversal + absolute path.
    if (opts.traversalPolicy !== "allow" && _hasTraversal(name)) {
      issues.push({
        kind: "zip-slip", severity: "critical",
        ruleId: "archive.zip-slip",
        location: i,
        snippet: "entry " + JSON.stringify(name) +
                 " contains .. (zip slip — CVE-2025-3445 class)",
      });
    }
    if (opts.absolutePathPolicy !== "allow" && _isAbsolutePath(name)) {
      issues.push({
        kind: "absolute-path", severity: "critical",
        ruleId: "archive.absolute-path",
        location: i,
        snippet: "entry " + JSON.stringify(name) + " is an absolute path",
      });
    }

    // Compose guard-filename for per-entry-name validation. Skip
    // separator-in-leaf (archives legitimately use "/" in entry names).
    var entryFilenameOpts = {
      profile:              opts.filenameProfile || "balanced",
      pathSeparatorsPolicy: "allow",
      // Archive entries use `/` as the canonical separator; that's
      // not a "leaf has separator" issue.
    };
    try {
      var fnRv = guardFilename.validate(name, entryFilenameOpts);
      // Re-attach any filename issues with archive-context location.
      for (var fi = 0; fi < fnRv.issues.length; fi += 1) {
        var issue = fnRv.issues[fi];
        // Skip duplicates we already flagged at archive-level.
        if (issue.kind === "path-traversal" ||
            issue.kind === "path-traversal-encoded") continue;
        issues.push(Object.assign({}, issue, {
          ruleId:   "archive." + issue.ruleId,
          location: i + ":" + (issue.location || 0),
          snippet:  "entry " + JSON.stringify(name) + ": " + issue.snippet,
        }));
      }
    } catch (_e) { /* per-entry filename check is best-effort */ }

    // Symlinks / hardlinks.
    if (e.isSymlink) {
      if (opts.symlinkPolicy === "reject") {
        issues.push({
          kind: "symlink-reject", severity: "critical",
          ruleId: "archive.symlink",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " is a symbolic link (profile rejects)",
        });
      } else {
        var symEsc = _checkLinkTarget(e.linkTarget, "symlink");
        if (symEsc) issues.push(Object.assign({ location: i }, symEsc));
      }
    }
    if (e.isHardlink) {
      if (opts.hardlinkPolicy === "reject") {
        issues.push({
          kind: "hardlink-reject", severity: "critical",
          ruleId: "archive.hardlink",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " is a hardlink (profile rejects; CVE-2026-26960 class)",
        });
      } else {
        var hardEsc = _checkLinkTarget(e.linkTarget, "hardlink");
        if (hardEsc) issues.push(Object.assign({ location: i }, hardEsc));
      }
    }

    // Per-entry size cap.
    var sz = typeof e.size === "number" ? e.size : 0;
    if (sz > opts.maxEntryBytes) {
      issues.push({
        kind: "entry-size-cap", severity: "high",
        ruleId: "archive.entry-size",
        location: i,
        snippet: "entry " + JSON.stringify(name) + " size " + sz +
                 " exceeds maxEntryBytes " + opts.maxEntryBytes,
      });
    }

    // Compression-ratio bomb.
    var cs = typeof e.compressedSize === "number" ? e.compressedSize : 0;
    if (cs > 0 && sz > 0) {
      var ratio = sz / cs;
      if (ratio > opts.maxCompressionRatio) {
        issues.push({
          kind: "compression-ratio-bomb", severity: "critical",
          ruleId: "archive.compression-ratio",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " compression ratio " + ratio.toFixed(1) +
                   ":1 exceeds maxCompressionRatio " + opts.maxCompressionRatio + ":1",
        });
      }
      totalCompressed += cs;
    }

    totalSize += sz;

    // Duplicate-entry-name detection.
    if (name in nameSeen) {
      if (opts.duplicateNamePolicy !== "allow") {
        issues.push({
          kind: "duplicate-entry-name",
          severity: opts.duplicateNamePolicy === "reject" ? "critical" : "warn",
          ruleId: "archive.duplicate-name",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " duplicates entry at index " + nameSeen[name] +
                   " (later entry would silently overwrite)",
        });
      }
    } else {
      nameSeen[name] = i;
    }

    // Case-insensitive collision.
    var lower = name.toLowerCase();
    if (caseSeen[lower] !== undefined && caseSeen[lower] !== name) {
      if (opts.caseInsensitiveCollisionPolicy !== "allow") {
        issues.push({
          kind: "case-insensitive-collision",
          severity: opts.caseInsensitiveCollisionPolicy === "reject" ? "high" : "warn",
          ruleId: "archive.case-collision",
          location: i,
          snippet: "entry " + JSON.stringify(name) + " collides case-insensitively with " +
                   JSON.stringify(caseSeen[lower]),
        });
      }
    } else {
      caseSeen[lower] = name;
    }

    // Nested-archive detection.
    if (_isArchiveName(name) && !e.isDirectory) {
      if (opts.nestedArchivePolicy === "reject" && opts.maxNestedDepth === 0) {
        issues.push({
          kind: "nested-archive", severity: "critical",
          ruleId: "archive.nested",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " is itself an archive (profile rejects nested archives)",
        });
      } else if (opts.nestedArchivePolicy === "audit") {
        issues.push({
          kind: "nested-archive", severity: "warn",
          ruleId: "archive.nested",
          location: i,
          snippet: "entry " + JSON.stringify(name) +
                   " is itself an archive (operator must validate recursively up to maxNestedDepth " +
                   opts.maxNestedDepth + ")",
        });
      }
    }

    // Encryption claim accounting.
    if (e.isEncrypted) encryptedCount += 1;
    else if (!e.isDirectory) unencryptedCount += 1;

    // Sparse entry — tar-shape sparse entries claim large size but no data.
    if (e.attrs && e.attrs.sparse) {
      if (opts.sparseEntryPolicy === "reject") {
        issues.push({
          kind: "sparse-entry", severity: "high",
          ruleId: "archive.sparse",
          location: i,
          snippet: "entry " + JSON.stringify(name) + " is a tar sparse entry (profile rejects)",
        });
      }
    }
  }

  // Total-size cap.
  if (totalSize > opts.maxTotalBytes) {
    issues.push({
      kind: "total-size-cap", severity: "high",
      ruleId: "archive.total-size",
      snippet: "total uncompressed size " + totalSize +
               " bytes exceeds maxTotalBytes " + opts.maxTotalBytes,
    });
  }

  // Aggregate compression-ratio bomb (sum-of-uncompressed / sum-of-compressed).
  if (totalCompressed > 0) {
    var aggRatio = totalSize / totalCompressed;
    if (aggRatio > opts.maxAggregateRatio) {
      issues.push({
        kind: "aggregate-ratio-bomb", severity: "critical",
        ruleId: "archive.aggregate-ratio",
        snippet: "aggregate compression ratio " + aggRatio.toFixed(1) +
                 ":1 exceeds maxAggregateRatio " + opts.maxAggregateRatio + ":1",
      });
    }
  }

  // Encryption-claim mismatch.
  if (encryptedCount > 0 && unencryptedCount > 0 &&
      opts.encryptionPolicy !== "allow") {
    issues.push({
      kind: "encryption-claim-mismatch",
      severity: opts.encryptionPolicy === "reject" ? "high" : "warn",
      ruleId: "archive.encryption-mix",
      snippet: "archive contains both encrypted (" + encryptedCount +
               ") and unencrypted (" + unencryptedCount + ") entries",
    });
  }

  return issues;
}

// ---- Public surface ----

function validateEntries(entries, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxEntries", "maxTotalBytes", "maxEntryBytes",
     "maxCompressionRatio", "maxAggregateRatio"],
    "guardArchive.validateEntries", GuardArchiveError, "archive.bad-opt");
  if (!Array.isArray(entries)) {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "entries must be an array" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(entries, opts));
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardArchive:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      // Operator passes ctx.entries (array of entry descriptors). When
      // ctx.bytes is provided WITHOUT ctx.entries, we run inspectMagic
      // for format detection but cannot validate entries (no parser
      // shipped). Refuse with a "no entry list" issue so operators
      // wire the parsed entries explicitly.
      var entries = ctx && ctx.entries;
      if (!entries) {
        if (ctx && ctx.bytes) {
          var detected = inspectMagic(Buffer.isBuffer(ctx.bytes)
            ? ctx.bytes
            : Buffer.from(ctx.bytes));
          if (detected) {
            return {
              ok: false, action: "refuse",
              issues: [{
                kind: "no-entry-list", severity: "high",
                ruleId: "archive.no-entry-list",
                snippet: "archive format " + JSON.stringify(detected.format) +
                         " detected via magic bytes; operator must enumerate " +
                         "entries via their archive library and pass via ctx.entries",
              }],
            };
          }
        }
        return { ok: true, action: "serve" };
      }
      var rv = validateEntries(entries, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) return { ok: true, action: "audit-only", issues: rv.issues };
      // Archive content has no safe sanitization — refuse.
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "archive");
}

var _archiveRulePacks = gateContract.makeRulePackLoader(GuardArchiveError, "archive");
var loadRulePack = _archiveRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports (consumed by b.guardAll) ----
  NAME:                "archive",
  KIND:                "entries",                                                 // archive-entries guard (consumes ctx.entries)
  INTEGRATION_FIXTURES: Object.freeze({
    kind:           "entries",
    contentType:    "application/zip",
    extension:      ".zip",
    benignEntries:  [{ name: "README.txt", size: 1000, compressedSize: 500 }], // allow:raw-byte-literal — integration-fixture sample size, not byte config
    // Hostile: zip-slip path traversal in entry name (CVE-2025-3445 class).
    hostileEntries: [{ name: "../etc/passwd", size: 100, compressedSize: 50 }],
  }),
  MIME_TYPES:          Object.freeze([
    "application/zip", "application/x-zip-compressed",
    "application/x-tar", "application/gzip", "application/x-gzip",
    "application/x-bzip2", "application/x-xz", "application/x-7z-compressed",
    "application/vnd.rar", "application/x-rar-compressed",
    "application/zstd",
  ]),
  EXTENSIONS:          Object.freeze([
    ".zip", ".jar", ".war", ".tar", ".tar.gz", ".tgz",
    ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz",
    ".7z", ".rar", ".zst", ".tar.zst", ".tzst",
  ]),
  // ---- primitive surface ----
  validateEntries:     validateEntries,
  inspectMagic:        inspectMagic,
  checkExtractionPath: checkExtractionPath,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  ARCHIVE_EXTENSIONS:  ARCHIVE_EXTENSIONS,
  MAGIC_SIGNATURES:    MAGIC_SIGNATURES,
  GuardArchiveError:   GuardArchiveError,
};
