// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardArchive
 * @nav    Guards
 * @title  Guard Archive
 *
 * @intro
 *   Archive content-safety guard — refuses hostile archive metadata
 *   BEFORE files touch the filesystem. Validates an operator-supplied
 *   entry list (the framework ships no pure-JS unzip / untar parser per
 *   the no-deps rule) plus an optional magic-byte inspection on raw
 *   bytes. Operators enumerate entries via their archive library
 *   (built-in zlib, OS tar / unzip CLI, vendored mupdf-of-archives) and
 *   pass `[{ name, size, compressedSize, isSymlink, isHardlink,
 *   linkTarget, isDirectory, isEncrypted, attrs }, ...]` to
 *   `validateEntries`.
 *
 *   Zip-slip / path-traversal: entry names containing `..` segments,
 *   leading `/` or `\\`, or Windows drive-letter prefixes (`C:\\`) are
 *   refused under every profile. Composes `b.guardFilename` for the
 *   full leaf-safety catalog (null-byte, Windows reserved names, NTFS
 *   ADS, RTLO bidi, overlong UTF-8, shell-exec extensions, double-
 *   extension). Tracks the 2025-2026 CVE class: CVE-2025-3445
 *   (mholt/archiver), CVE-2025-32779 (EDDI), CVE-2025-62156 (Argo
 *   Workflows), CVE-2025-66945 (Zdir Pro), CVE-2025-45582 (GNU Tar
 *   two-step symlink bypass), CVE-2025-11001 / 11002 (7-Zip RCE),
 *   CVE-2025-4138 / 4517 (Python tarfile), CVE-2025-10854 (txtai),
 *   CVE-2025-12060 (Keras), CVE-2026-26960 (node-tar hardlink-via-
 *   symlink chain).
 *
 *   Symlink / hardlink escape: entries whose `linkTarget` contains `..`
 *   or is absolute are refused. `strict` rejects symlinks AND hardlinks
 *   outright; `balanced` permits in-root symlinks and rejects hardlinks
 *   (CVE-2026-26960 class); `permissive` audits both.
 *
 *   Decompression amplification: per-entry `compressedSize`/`size` ratio
 *   cap defaults 100:1 (strict) / 100:1 (balanced) / 1000:1 (permissive).
 *   Aggregate ratio across all entries also capped (`maxAggregateRatio`).
 *   Entry-count cap (`maxEntries`), per-entry size cap (`maxEntryBytes`),
 *   total uncompressed cap (`maxTotalBytes`).
 *
 *   NTFS ADS, overlong UTF-8, leaf-bidi: routed through `b.guardFilename`
 *   on every entry name with `pathSeparatorsPolicy: "allow"` (archive
 *   entries legitimately use `/` as separator).
 *
 *   Nested archives: entries with archive extensions (`.zip`, `.tar.gz`,
 *   `.7z`, `.rar`, `.zst`, ...) refused under `strict` (`maxNestedDepth:
 *   0`); audited under `balanced` (depth 2) / `permissive` (depth 4) so
 *   the operator can recurse.
 *
 *   Duplicate-name + case-insensitive collision detection — the second
 *   entry with the same name silently overwrites on extraction (refused);
 *   case-insensitive collisions on Windows / HFS+ / APFS-non-case-
 *   sensitive volumes (audited / refused per profile).
 *
 *   `inspectMagic(buffer)` returns `{ format, magic }` for ZIP / GZIP /
 *   BZIP2 / XZ / 7Z / RAR4 / RAR5 / LZMA / ZSTD / TAR (the latter via
 *   the "ustar" magic at offset 257). `checkExtractionPath(name, root)`
 *   provides a single-entry boolean for callers that already enumerate.
 *
 *   Profiles `strict` / `balanced` / `permissive` and compliance
 *   postures `hipaa` / `pci-dss` / `gdpr` / `soc2` overlay on the
 *   profile baseline.
 *
 * @card
 *   Archive content-safety guard — refuses hostile archive metadata BEFORE files touch the filesystem.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var guardFilename = require("./guard-filename");
var archiveRead = lazyRequire(function () { return require("./archive-read"); });
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
  { format: "zip",   bytes: [0x50, 0x4B, 0x03, 0x04] },              // ZIP local file header magic per APPNOTE.TXT §4.3.7
  { format: "zip",   bytes: [0x50, 0x4B, 0x05, 0x06] },              // ZIP empty-archive end-of-central-directory magic
  { format: "zip",   bytes: [0x50, 0x4B, 0x07, 0x08] },              // ZIP spanned-archive marker
  { format: "gzip",  bytes: [0x1F, 0x8B] },                          // gzip magic per RFC 1952 §2.3.1
  { format: "bzip2", bytes: [0x42, 0x5A, 0x68] },                    // bzip2 "BZh" magic
  { format: "xz",    bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },  // XZ magic per xz spec §2.1.1.1
  { format: "7z",    bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },  // 7-zip magic per 7z spec
  { format: "rar4",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] }, // RAR4 magic
  { format: "rar5",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] }, // RAR5 magic
  { format: "lzma",  bytes: [0x5D, 0x00, 0x00] },                    // LZMA magic byte sequence (heuristic)
  { format: "zstd",  bytes: [0x28, 0xB5, 0x2F, 0xFD] },              // Zstandard magic per RFC 8478 §3.1.1
  // tar is identified by the "ustar" magic at byte offset 257 inside
  // the first 512-byte header; handled separately in inspectMagic().
]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
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
    maxEntries:                100,           // entry count cap, not byte size
    maxTotalBytes:             C.BYTES.mib(100),
    maxEntryBytes:             C.BYTES.mib(50),
    maxCompressionRatio:       100,           // ratio multiplier, not byte size
    maxAggregateRatio:         200,           // aggregate-ratio multiplier, not byte size
    maxNestedDepth:            0,             // recursion depth, not byte size
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
    maxEntries:                10000,         // entry count cap, not byte size
    maxTotalBytes:             C.BYTES.gib(1),
    maxEntryBytes:             C.BYTES.mib(500),
    maxCompressionRatio:       100,           // ratio multiplier, not byte size
    maxAggregateRatio:         1000,          // aggregate-ratio multiplier, not byte size
    maxNestedDepth:            2,             // recursion depth, not byte size
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
    maxEntries:                100000,        // entry count cap, not byte size
    maxTotalBytes:             C.BYTES.gib(10),
    maxEntryBytes:             C.BYTES.gib(2),
    maxCompressionRatio:       1000,          // ratio multiplier, not byte size
    maxAggregateRatio:         10000,         // aggregate-ratio multiplier, not byte size
    maxNestedDepth:            4,             // recursion depth, not byte size
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs: C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

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

/**
 * @primitive b.guardArchive.inspectMagic
 * @signature b.guardArchive.inspectMagic(buffer)
 * @since     0.7.8
 * @status    stable
 * @related   b.guardArchive.validateEntries, b.guardArchive.gate
 *
 * Read the first bytes of `buffer` and return
 * `{ format, magic }` when the buffer matches a known archive-format
 * signature (`zip` / `gzip` / `bzip2` / `xz` / `7z` / `rar4` / `rar5` /
 * `lzma` / `zstd` / `tar`). TAR is detected via the `"ustar"` magic
 * at offset 257 within the first 512-byte header block. Returns
 * `null` on unrecognized input or non-Buffer / empty input. Pure
 * inspection — never mutates the buffer or throws.
 *
 * Operators compare the detected format against the declared
 * Content-Type / extension to surface format-claim mismatches before
 * routing the bytes to a parser.
 *
 * @example
 *   var zipBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00]);
 *   var hit = b.guardArchive.inspectMagic(zipBytes);
 *   hit.format;                                         // → "zip"
 *
 *   var noise = Buffer.from([0x00, 0x01, 0x02, 0x03]);
 *   b.guardArchive.inspectMagic(noise);                 // → null
 */
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

/**
 * @primitive b.guardArchive.checkExtractionPath
 * @signature b.guardArchive.checkExtractionPath(entryName, extractionRoot)
 * @since     0.7.8
 * @status    stable
 * @related   b.guardArchive.validateEntries, b.guardArchive.gate
 *
 * Single-entry boolean check: returns `{ ok, reason }` for a candidate
 * `(entryName, extractionRoot)` pair. Refuses entries whose name
 * contains a `..` component (zip slip — CVE-2025-3445 class), is an
 * absolute path (leading `/`, `\\`, or `C:\\` drive-letter prefix),
 * carries a null byte, or is empty. The framework cannot resolve
 * `path.resolve(extractionRoot, entryName)` without a `node:path`
 * coupling that the gate keeps portable; the operator's extraction
 * code is expected to additionally call `path.resolve` and confirm
 * the result starts with `path.resolve(extractionRoot)`.
 *
 * Use when the operator already enumerates archive entries and wants
 * a per-call boolean rather than running the full
 * `validateEntries` issue list.
 *
 * @example
 *   b.guardArchive.checkExtractionPath("docs/readme.txt", "/var/extract").ok;
 *   //                                                   → true
 *
 *   var bad = b.guardArchive.checkExtractionPath("../etc/passwd", "/var/extract");
 *   bad.ok;                                              // → false
 *   bad.reason;                                          // → "entry name contains .. component (zip slip)"
 */
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
  if (entryName.indexOf("\u0000") !== -1) {
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

/**
 * @primitive  b.guardArchive.validateEntries
 * @signature  b.guardArchive.validateEntries(entries, opts)
 * @since      0.7.8
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardArchive.gate, b.guardArchive.inspectMagic, b.guardFilename.validate
 *
 * Inspect an operator-supplied `entries` array (one entry per archive
 * member: `{ name, size, compressedSize, isSymlink, isHardlink,
 * linkTarget, isDirectory, isEncrypted, attrs }`) and return
 * `{ ok, issues }`. Issues carry `{ kind, severity, ruleId, location,
 * snippet }` with severity `"warn"` / `"high"` / `"critical"`.
 * Detected: zip-slip, absolute path, symlink / hardlink escape,
 * compression-ratio bombs (per-entry + aggregate), per-entry size
 * cap, total-size cap, entry-count cap, nested-archive entries,
 * duplicate names, case-insensitive collisions, encryption-claim
 * mismatch, sparse-tar entries, plus the full `b.guardFilename`
 * leaf-safety catalog re-attached with archive-context locations.
 * Pure inspection — never mutates input or throws on hostile entries.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   traversalPolicy:                "reject"|"audit"|"allow",
 *   absolutePathPolicy:             "reject"|"audit"|"allow",
 *   symlinkPolicy:                  "reject"|"audit"|"allow",
 *   hardlinkPolicy:                 "reject"|"audit"|"allow",
 *   nestedArchivePolicy:            "reject"|"audit"|"allow",
 *   duplicateNamePolicy:            "reject"|"audit"|"allow",
 *   caseInsensitiveCollisionPolicy: "reject"|"audit"|"allow",
 *   encryptionPolicy:               "reject"|"audit"|"allow",
 *   sparseEntryPolicy:              "reject"|"audit"|"allow",
 *   filenameProfile:                "balanced"|"strict"|"permissive",
 *   maxEntries:           number,   // strict 100, balanced 10000, permissive 100000
 *   maxTotalBytes:        number,   // strict 100 MiB, balanced 1 GiB, permissive 10 GiB
 *   maxEntryBytes:        number,   // strict 50 MiB, balanced 500 MiB, permissive 2 GiB
 *   maxCompressionRatio:  number,   // strict / balanced 100, permissive 1000
 *   maxAggregateRatio:    number,   // strict 200, balanced 1000, permissive 10000
 *   maxNestedDepth:       number,   // strict 0, balanced 2, permissive 4
 *
 * @example
 *   var rv = b.guardArchive.validateEntries([
 *     { name: "docs/readme.txt", size: 1000, compressedSize: 500 },
 *     { name: "../etc/passwd",   size: 100,  compressedSize: 50 },
 *   ], { profile: "strict" });
 *   rv.ok;                                               // → false
 *   rv.issues[0].kind;                                   // → "zip-slip"
 *   rv.issues[0].severity;                               // → "critical"
 *
 *   // Compression-ratio bomb — 50 MiB uncompressed from 50 KiB compressed
 *   // is 1000:1, far above the 100:1 strict cap.
 *   var bomb = b.guardArchive.validateEntries([
 *     { name: "bomb.bin", size: 52428800, compressedSize: 51200 },
 *   ], { profile: "strict" });
 *   bomb.issues.some(function (i) { return i.kind === "compression-ratio-bomb"; });
 *   //                                                   → true
 */
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
  // "raw" contract — entries is an array the detector type-checks itself.
  return gateContract.runIssueValidator(entries, opts, _detectIssues, "raw");
}

/**
 * @primitive  b.guardArchive.gate
 * @signature  b.guardArchive.gate(opts)
 * @since      0.7.8
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardArchive.validateEntries, b.guardArchive.inspectMagic, b.fileUpload, b.staticServe
 *
 * Build a `b.gateContract` gate suitable for `b.fileUpload({ contentSafety:
 * { "application/zip": gate } })` or `b.staticServe`. Operators pass
 * `ctx.entries` (the enumerated entry list from their archive library)
 * — when only `ctx.bytes` is supplied, the gate runs `inspectMagic` to
 * confirm the format and refuses with a `"no-entry-list"` issue
 * directing the operator to enumerate entries explicitly (the
 * framework ships no parser for any archive format).
 *
 * Action chain: `serve` (no issues) → `audit-only` (warn-only) →
 * `refuse` (any critical/high). Archive content has no safe
 * sanitization — there is no `sanitize` action in the chain.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,
 *   ...:        any validateEntries opt
 *
 * @example
 *   var archiveGate = b.guardArchive.gate({ profile: "strict" });
 *
 *   var verdict = await archiveGate.check({
 *     entries: [
 *       { name: "docs/readme.txt", size: 1000, compressedSize: 500 },
 *       { name: "../etc/passwd",   size: 100,  compressedSize: 50 },
 *     ],
 *   });
 *   verdict.action;                                      // → "refuse"
 *
 *   // Bytes-only call without an entry list — operator must enumerate.
 *   var zipBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00]);
 *   var v2 = await archiveGate.check({ bytes: zipBytes });
 *   v2.action;                                           // → "refuse"
 *   v2.issues[0].kind;                                   // → "no-entry-list"
 */
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
      // Archive content has no safe sanitization — serve / audit-only / refuse.
      return gateContract.severityDisposition(rv.issues);
    });
}

/**
 * @primitive b.guardArchive.buildProfile
 * @signature b.guardArchive.buildProfile(opts)
 * @since     0.7.8
 * @status    stable
 * @related   b.guardArchive.compliancePosture, b.guardArchive.gate
 *
 * Resolve a named profile against the guard's PROFILES catalog and
 * return the merged options bag. Operators introspecting the active
 * caps (without calling `validateEntries` / `gate`) use this. Throws
 * `GuardArchiveError("archive.bad-profile")` on unknown name.
 *
 * @opts
 *   profile: "strict"|"balanced"|"permissive",
 *
 * @example
 *   var resolved = b.guardArchive.buildProfile({ profile: "strict" });
 *   resolved.maxEntries;                                 // → 100
 *   resolved.symlinkPolicy;                              // → "reject"
 *   resolved.maxCompressionRatio;                        // → 100
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardArchive.compliancePosture
 * @signature  b.guardArchive.compliancePosture(name)
 * @since      0.7.8
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardArchive.gate, b.guardArchive.buildProfile
 *
 * Return the option overlay for a named compliance posture
 * (`"hipaa"` / `"pci-dss"` / `"gdpr"` / `"soc2"`). Composes over a
 * base profile to harden defaults per regulatory regime. Throws
 * `GuardArchiveError("archive.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardArchive.compliancePosture("hipaa");
 *   posture.symlinkPolicy;                               // → "reject"
 *   posture.hardlinkPolicy;                              // → "reject"
 *   posture.forensicSnippetBytes;                        // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "archive");
}

var _archiveRulePacks = gateContract.makeRulePackLoader(GuardArchiveError, "archive");
/**
 * @primitive b.guardArchive.loadRulePack
 * @signature b.guardArchive.loadRulePack(pack)
 * @since     0.7.8
 * @status    stable
 * @related   b.guardArchive.gate
 *
 * Register an operator-supplied rule pack with the guard-archive
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardArchiveError("archive.bad-opt")` when
 * `pack` is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardArchive.loadRulePack({
 *     id: "kb-2026-archive",
 *     extraReservedNames: ["system32"],
 *     rules: [
 *       { id: "no-windows-system", severity: "critical",
 *         reason: "entry name targets Windows system directory" },
 *     ],
 *   });
 *   pack.id;                                             // → "kb-2026-archive"
 */
var loadRulePack = _archiveRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports (consumed by b.guardAll) ----
  NAME:                "archive",
  KIND:                "entries",                                                 // archive-entries guard (consumes ctx.entries)
  INTEGRATION_FIXTURES: Object.freeze({
    kind:           "entries",
    contentType:    "application/zip",
    extension:      ".zip",
    benignEntries:  [{ name: "README.txt", size: 1000, compressedSize: 500 }], // integration-fixture sample size, not byte config
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
  inspect:             inspect,
  zipBombPolicy:       zipBombPolicy,
  entryTypePolicy:     entryTypePolicy,
  tarEntryPolicy:      tarEntryPolicy,
};

// ---- extensions ---------------------------------------------------

/**
 * @primitive b.guardArchive.inspect
 * @signature b.guardArchive.inspect(adapter, opts?)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.read.zip, b.guardArchive.validateEntries
 *
 * Bridge primitive: runs `b.archive.read.zip(adapter).inspect()` to
 * enumerate the entry list (no decompression), then hands the list to
 * `validateEntries` for the full posture-aware gate. Returns
 * `{ entries, issues, decisions }` so the caller decides whether to
 * proceed.
 *
 * Operators using the lower-level read primitive directly call this
 * to combine the metadata pass with the guard pass; `b.safeArchive.
 * extract` does the same composition inline under the hood.
 *
 * @opts
 *   profile:        "strict" | "balanced" | "permissive" | "hipaa" | ...,
 *   format:         "zip" (v0.12.7 — tar v0.12.8, gz v0.12.9),
 *   audit:          b.audit,
 *
 * @example
 *   var adapter = b.archive.adapters.fs("/var/uploads/payload.zip");
 *   var summary = await b.guardArchive.inspect(adapter, { profile: "strict" });
 *   if (summary.issues.length > 0) refuse(summary.issues);
 */
async function inspect(adapter, opts) {
  opts = opts || {};
  var format = opts.format || "zip";
  if (format !== "zip") {
    throw new GuardArchiveError("archive/format-unsupported",
      "guardArchive.inspect: format=" + JSON.stringify(format) +
      " — v0.12.7 ships ZIP only (tar v0.12.8, gz v0.12.9)");
  }
  var reader = archiveRead().zip(adapter, { audit: opts.audit });
  var rawEntries = await reader.inspect();
  // Project the read-primitive's entry shape into validateEntries'
  // expected `{ name, size, compressedSize, isSymlink, ... }` shape.
  var guardEntries = rawEntries.map(function (e) {
    return {
      name:           e.name,
      size:           e.size,
      compressedSize: e.compressedSize,
      isSymlink:      e.entryType === "symlink",
      isHardlink:     false,
      linkTarget:     null,
      isDirectory:    e.entryType === "directory",
      isEncrypted:    e.isEncrypted,
      attrs:          { externalAttrs: e.externalAttrs },
    };
  });
  var profile = opts.profile || "balanced";
  var result = validateEntries(guardEntries, { profile: profile });
  return {
    entries:   rawEntries,
    issues:    (result && result.issues) || [],
    decisions: (result && result.decisions) || {},
  };
}

/**
 * @primitive b.guardArchive.zipBombPolicy
 * @signature b.guardArchive.zipBombPolicy(opts)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.read.zip, b.safeArchive.extract
 *
 * Policy-object builder for decompression-bomb caps. Operators
 * declare the cap set once + reuse it across `b.archive.read.zip` /
 * `b.safeArchive.extract` call sites. Defaults match the cap shape
 * in `lib/archive-read.js` `DEFAULT_BOMB_POLICY`.
 *
 * @opts
 *   maxEntries:                65535,
 *   maxEntryDecompressedBytes: 128 * MiB,
 *   maxTotalDecompressedBytes: 4 * GiB,
 *   maxExpansionRatio:         100,
 *
 * @example
 *   var policy = b.guardArchive.zipBombPolicy({
 *     maxTotalDecompressedBytes: 256 * 1024 * 1024,
 *     maxExpansionRatio: 50,
 *   });
 *   await b.safeArchive.extract({ source, destination, bombPolicy: policy });
 */
function zipBombPolicy(opts) {
  opts = opts || {};
  return Object.freeze({
    maxEntries:                opts.maxEntries                || 65535,
    maxEntryDecompressedBytes: opts.maxEntryDecompressedBytes || C.BYTES.mib(128),
    maxTotalDecompressedBytes: opts.maxTotalDecompressedBytes || C.BYTES.gib(4),
    maxExpansionRatio:         opts.maxExpansionRatio         || 100,
  });
}

/**
 * @primitive b.guardArchive.entryTypePolicy
 * @signature b.guardArchive.entryTypePolicy(opts)
 * @since     0.12.7
 * @status    stable
 * @related   b.archive.read.zip, b.safeArchive.extract
 *
 * Policy-object builder for entry-type allowlist. Defaults refuse
 * every "interesting" entry type (symlink / hardlink / device / fifo
 * / socket); operators opt in per-type and route through the
 * additional realpath-on-target check in `b.guardFilename.
 * verifyExtractionPath`.
 *
 * Symlinks + hardlinks under default settings are refused
 * unconditionally — CVE-2025-11001 / 11002 / 26960 class.
 *
 * @opts
 *   symlinks:   false,
 *   hardlinks:  false,
 *   devices:    false,
 *   fifos:      false,
 *   sockets:    false,
 *
 * @example
 *   var policy = b.guardArchive.entryTypePolicy({ symlinks: true });
 *   await b.safeArchive.extract({ source, destination, entryTypePolicy: policy });
 */
function entryTypePolicy(opts) {
  opts = opts || {};
  return Object.freeze({
    symlinks:  opts.symlinks  === true,
    hardlinks: opts.hardlinks === true,
    devices:   opts.devices   === true,
    fifos:     opts.fifos     === true,
    sockets:   opts.sockets   === true,
  });
}

/**
 * @primitive b.guardArchive.tarEntryPolicy
 * @signature b.guardArchive.tarEntryPolicy(opts)
 * @since     0.12.8
 * @status    stable
 * @related   b.guardArchive.entryTypePolicy, b.archive.read.tar
 *
 * Tar-specific entry-type policy. Same shape as `entryTypePolicy`
 * but explicitly named for tar's typeflag vocabulary (1=hardlink,
 * 2=symlink, 3=char-device, 4=block-device, 6=FIFO, 7=contiguous-
 * file) so call sites read clearly when the operator's intent is
 * tar-specific. Defaults refuse every dangerous typeflag. Operators
 * opting symlinks / hardlinks in get the link target routed through
 * `b.guardFilename.verifyExtractionPath`'s realpath-on-target check
 * (defends CVE-2026-23745 / 24842 node-tar path-resolution divergence
 * class).
 *
 * @opts
 *   symlinks:   false,
 *   hardlinks:  false,
 *   devices:    false,
 *   fifos:      false,
 *   sockets:    false,
 *
 * @example
 *   var policy = b.guardArchive.tarEntryPolicy({ symlinks: true });
 *   await b.safeArchive.extract({
 *     source, destination, entryTypePolicy: policy,
 *     allowDangerous: { symlinks: true },
 *   });
 */
function tarEntryPolicy(opts) {
  // Same shape as entryTypePolicy; aliased for tar-specific call-site
  // readability. The implementation is intentionally identical — the
  // policy-object shape is format-neutral, only the typeflag mapping
  // in the reader differs.
  return entryTypePolicy(opts);
}
