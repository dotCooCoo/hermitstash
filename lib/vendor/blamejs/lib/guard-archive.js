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
 *   sensitive volumes (audited / refused per profile). Names that are
 *   equal after Unicode NFC normalization, after each backslash is read
 *   as `/`, or after empty and `.` path segments are dropped count as
 *   duplicates. A path segment with a trailing dot or leading or
 *   trailing whitespace is reported, because Windows strips it, and so
 *   is a path segment that is a Windows reserved device name (`CON`,
 *   `aux.txt`, `COM1`).
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

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardFilename = require("./guard-filename");
var archiveRead = lazyRequire(function () { return require("./archive-read"); });
var { GuardArchiveError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardArchiveError.factory;

var EQUIVALENT_NAMES_NOTE = " as another reader decodes the names, Unicode-normalizes them (NFC)," +
  " reads a backslash as a path separator, or drops empty and '.' path segments";

var RESERVED_BASES = Object.create(null);
var RESERVED_BASE_MIN = Infinity;
var RESERVED_BASE_MAX = 0;
guardFilename.WIN_RESERVED_NAMES.forEach(function (reserved) {
  RESERVED_BASES[reserved] = true;
  RESERVED_BASE_MIN = Math.min(RESERVED_BASE_MIN, reserved.length);
  RESERVED_BASE_MAX = Math.max(RESERVED_BASE_MAX, reserved.length);
});
var RESERVED_PORT_PREFIXES = ["COM", "LPT"];
var RESERVED_PORT_LENGTH = 4;
var SUPERSCRIPT_DIGITS = String.fromCharCode(0xB9, 0xB2, 0xB3);

var ARCHIVE_EXTENSIONS = Object.freeze([
  ".zip", ".jar", ".war", ".ear", ".apk", ".ipa",
  ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
  ".tar.zst", ".tzst", ".tar.lzma", ".tlz",
  ".gz", ".bz2", ".xz", ".lzma", ".lz4", ".zst",
  ".7z", ".rar", ".ar", ".cpio", ".cab", ".iso", ".dmg",
  ".deb", ".rpm", ".msi",
]);

var MAGIC_SIGNATURES = Object.freeze([
  { format: "zip",   bytes: [0x50, 0x4B, 0x03, 0x04] },
  { format: "zip",   bytes: [0x50, 0x4B, 0x05, 0x06] },
  { format: "zip",   bytes: [0x50, 0x4B, 0x07, 0x08] },
  { format: "gzip",  bytes: [0x1F, 0x8B] },
  { format: "bzip2", bytes: [0x42, 0x5A, 0x68] },
  { format: "xz",    bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },
  { format: "7z",    bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
  { format: "rar4",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] },
  { format: "rar5",  bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] },
  { format: "lzma",  bytes: [0x5D, 0x00, 0x00] },
  { format: "zstd",  bytes: [0x28, 0xB5, 0x2F, 0xFD] },
]);

var PROFILES = Object.freeze({
  "strict": {
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "reject",
    hardlinkPolicy:            "reject",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "reject",
    duplicateNamePolicy:       "reject",
    caseInsensitiveCollisionPolicy: "reject",
    reservedNamePolicy:        "reject",
    sparseEntryPolicy:         "reject",
    filenameProfile:           "balanced",
    maxEntries:                100,
    maxTotalBytes:             C.BYTES.mib(100),
    maxEntryBytes:             C.BYTES.mib(50),
    maxCompressionRatio:       100,
    maxAggregateRatio:         200,
    maxNestedDepth:            0,
  },
  "balanced": {
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "audit",
    hardlinkPolicy:            "reject",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "audit",
    duplicateNamePolicy:       "reject",
    caseInsensitiveCollisionPolicy: "audit",
    reservedNamePolicy:        "reject",
    sparseEntryPolicy:         "audit",
    filenameProfile:           "balanced",
    maxEntries:                10000,
    maxTotalBytes:             C.BYTES.gib(1),
    maxEntryBytes:             C.BYTES.mib(500),
    maxCompressionRatio:       100,
    maxAggregateRatio:         1000,
    maxNestedDepth:            2,
  },
  "permissive": {
    traversalPolicy:           "reject",
    absolutePathPolicy:        "reject",
    symlinkPolicy:             "audit",
    hardlinkPolicy:            "audit",
    encryptionPolicy:          "audit",
    nestedArchivePolicy:       "audit",
    duplicateNamePolicy:       "audit",
    caseInsensitiveCollisionPolicy: "audit",
    reservedNamePolicy:        "reject",
    sparseEntryPolicy:         "audit",
    filenameProfile:           "permissive",
    maxEntries:                100000,
    maxTotalBytes:             C.BYTES.gib(10),
    maxEntryBytes:             C.BYTES.gib(2),
    maxCompressionRatio:       1000,
    maxAggregateRatio:         10000,
    maxNestedDepth:            4,
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs: C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var INT_OPTS = ["maxEntries", "maxTotalBytes", "maxEntryBytes",
                "maxCompressionRatio", "maxAggregateRatio"];

var POLICY_ENUM = gateContract.policyVocabulary([
  "traversalPolicy", "absolutePathPolicy", "symlinkPolicy", "hardlinkPolicy",
  "nestedArchivePolicy", "duplicateNamePolicy", "caseInsensitiveCollisionPolicy",
  "reservedNamePolicy", "encryptionPolicy", "sparseEntryPolicy",
], ["reject", "audit", "allow"]);

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardArchiveError,
    errCodePrefix:      "archive",
    intOpts:            INT_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
    enumOpts:           POLICY_ENUM,
  });
}

function _isAbsolutePath(name) {
  if (!name || typeof name !== "string") return false;
  if (name.charAt(0) === "/" || name.charAt(0) === "\\") return true;
  return codepointClass.isAsciiLetter(name.charCodeAt(0)) && name.charAt(1) === ":" &&
         _isSeparator(name.charAt(2));
}

function _isSeparator(ch) { return ch === "/" || ch === "\\"; }

function _hasTraversal(name) {
  if (!name || typeof name !== "string") return false;
  for (var i = name.indexOf(".."); i !== -1; i = name.indexOf("..", i + 1)) {
    var openedBySeparator = i === 0 || _isSeparator(name.charAt(i - 1));
    var closedBySeparator = i + 2 === name.length || _isSeparator(name.charAt(i + 2));
    if (openedBySeparator && closedBySeparator) return true;
  }
  return name === ".." || name === ".";
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
  if (entryName.indexOf("\u0000") !== -1) {
    return { ok: false, reason: "entry name contains null byte" };
  }
  void extractionRoot;
  return { ok: true };
}

function _checkLinkTarget(target, kind) {
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

function _isNamedSegment(seg) {
  return seg !== "" && seg !== "." && seg !== "..";
}

function _mayHaveTrimmableEdge(seg) {
  var ws = codepointClass.WHITESPACE_RANGES;
  return codepointClass.inRanges(seg.charCodeAt(0), ws) ||
         codepointClass.inRanges(seg.charCodeAt(seg.length - 1), ws) ||
         seg.charAt(seg.length - 1) === ".";
}

function _mayBeReservedName(seg) {
  var dot = seg.indexOf(".");
  var base = dot === -1 ? seg : seg.slice(0, dot);
  if (base.length < RESERVED_BASE_MIN || base.length > RESERVED_BASE_MAX) return false;
  var upper = base.toUpperCase();
  if (RESERVED_BASES[upper] === true) return true;
  return upper.length === RESERVED_PORT_LENGTH &&
         RESERVED_PORT_PREFIXES.indexOf(upper.slice(0, RESERVED_PORT_LENGTH - 1)) !== -1 &&
         SUPERSCRIPT_DIGITS.indexOf(upper.charAt(RESERVED_PORT_LENGTH - 1)) !== -1;
}

function _segmentIssue(seg, kind, filenameOpts) {
  try {
    var found = guardFilename.validate(seg, filenameOpts).issues;
    for (var f = 0; f < found.length; f += 1) {
      if (found[f].kind === kind) return found[f];
    }
  } catch (_e) { /* per-segment filename check is best-effort */ }
  return null;
}

function _withReservedNamePolicy(issue, opts) {
  if (issue.kind !== "reserved-name") return issue;
  if (opts.reservedNamePolicy === "allow") return null;
  return opts.reservedNamePolicy === "audit" ? Object.assign({}, issue, { severity: "warn" }) : issue;
}

function _pushSegmentIssues(issues, name, label, i, filenameOpts, done, opts) {
  var segs = codepointClass.replaceAny(name, "\\", "/").split("/");
  var want = { "leading-trailing-strip": !done.edge, "reserved-name": !done.reserved };
  var tests = { "leading-trailing-strip": _mayHaveTrimmableEdge, "reserved-name": _mayBeReservedName };
  var kinds = Object.keys(want);
  for (var s = 0; s < segs.length && (want[kinds[0]] || want[kinds[1]]); s += 1) {
    var seg = segs[s];
    if (!_isNamedSegment(seg)) continue;
    for (var k = 0; k < kinds.length; k += 1) {
      if (!want[kinds[k]] || !tests[kinds[k]](seg)) continue;
      var hit = _segmentIssue(seg, kinds[k], filenameOpts);
      if (hit === null) continue;
      want[kinds[k]] = false;
      hit = _withReservedNamePolicy(hit, opts);
      if (hit === null) continue;
      issues.push(Object.assign({}, hit, {
        ruleId:   "archive." + hit.ruleId,
        location: i + ":" + (hit.location || 0),
        snippet:  label + ": path segment " + JSON.stringify(seg) + ": " + hit.snippet,
      }));
    }
  }
}

function _pushNameIssues(issues, name, label, i, e, opts) {
  if (opts.traversalPolicy !== "allow" && _hasTraversal(name)) {
    issues.push({
      kind: "zip-slip", severity: "critical",
      ruleId: "archive.zip-slip",
      location: i,
      snippet: label + " contains .. (zip slip, CVE-2025-3445 class)",
    });
  }
  if (opts.absolutePathPolicy !== "allow" && _isAbsolutePath(name)) {
    issues.push({
      kind: "absolute-path", severity: "critical",
      ruleId: "archive.absolute-path",
      location: i,
      snippet: label + " is an absolute path",
    });
  }

  var entryFilenameOpts = {
    profile:              opts.filenameProfile || "balanced",
    pathSeparatorsPolicy: "allow",
  };
  var reported = { edge: false, reserved: false };
  try {
    var fnRv = guardFilename.validate(name, entryFilenameOpts);
    for (var fi = 0; fi < fnRv.issues.length; fi += 1) {
      var issue = fnRv.issues[fi];
      if (issue.kind === "path-traversal" ||
          issue.kind === "path-traversal-encoded") continue;
      if (issue.kind === "leading-trailing-strip") reported.edge = true;
      if (issue.kind === "reserved-name") reported.reserved = true;
      issue = _withReservedNamePolicy(issue, opts);
      if (issue === null) continue;
      issues.push(Object.assign({}, issue, {
        ruleId:   "archive." + issue.ruleId,
        location: i + ":" + (issue.location || 0),
        snippet:  label + ": " + issue.snippet,
      }));
    }
  } catch (_e) { /* per-entry filename check is best-effort */ }
  _pushSegmentIssues(issues, name, label, i, entryFilenameOpts, reported, opts);

  if (_isArchiveName(name) && !e.isDirectory) {
    if (opts.nestedArchivePolicy === "reject" && opts.maxNestedDepth === 0) {
      issues.push({
        kind: "nested-archive", severity: "critical",
        ruleId: "archive.nested",
        location: i,
        snippet: label + " is itself an archive (profile rejects nested archives)",
      });
    } else if (opts.nestedArchivePolicy === "audit") {
      issues.push({
        kind: "nested-archive", severity: "warn",
        ruleId: "archive.nested",
        location: i,
        snippet: label + " is itself an archive (operator must validate recursively up to maxNestedDepth " +
                 opts.maxNestedDepth + ")",
      });
    }
  }
}

function _pushCollisionIssues(issues, name, label, scope, i, seen, caseSeen, opts) {
  var found = { duplicate: false, caseCollision: false };
  if (name in seen) {
    if (opts.duplicateNamePolicy !== "allow") {
      found.duplicate = true;
      issues.push({
        kind: "duplicate-entry-name",
        severity: opts.duplicateNamePolicy === "reject" ? "critical" : "warn",
        ruleId: "archive.duplicate-name",
        location: i,
        snippet: label + " duplicates entry at index " + seen[name] + scope +
                 " (later entry would silently overwrite)",
      });
    }
  } else {
    seen[name] = i;
  }

  var lower = name.toLowerCase();
  if (caseSeen[lower] !== undefined && caseSeen[lower] !== name) {
    if (opts.caseInsensitiveCollisionPolicy !== "allow") {
      found.caseCollision = true;
      issues.push({
        kind: "case-insensitive-collision",
        severity: opts.caseInsensitiveCollisionPolicy === "reject" ? "high" : "warn",
        ruleId: "archive.case-collision",
        location: i,
        snippet: label + " collides case-insensitively with " + JSON.stringify(caseSeen[lower]) + scope,
      });
    }
  } else {
    caseSeen[lower] = name;
  }
  return found;
}

function _altLabel(name, value) {
  return "entry " + JSON.stringify(name) + (value === name ? "" : " (also read as " + JSON.stringify(value) + ")");
}

function _isPathSegment(seg) {
  return seg !== "" && seg !== ".";
}

function _segmentForm(slashed) {
  if (slashed.indexOf("//") === -1 && slashed.indexOf("/./") === -1 &&
      slashed.charAt(0) !== "/" && slashed.slice(0, 2) !== "./" &&
      slashed.slice(-2) !== "/." && slashed !== ".") {
    return slashed;
  }
  var joined = slashed.split("/").filter(_isPathSegment).join("/");
  if (joined === "") return null;
  return slashed.charAt(slashed.length - 1) === "/" ? joined + "/" : joined;
}

function _withEquivalentForms(names) {
  var out = names.slice();
  for (var n = 0; n < names.length; n += 1) {
    var nfc = names[n].normalize("NFC");
    var slashed = codepointClass.replaceAny(names[n], "\\", "/");
    var forms = [nfc, slashed, _segmentForm(slashed)];
    if (nfc !== names[n]) {
      var nfcSlashed = codepointClass.replaceAny(nfc, "\\", "/");
      forms.push(nfcSlashed, _segmentForm(nfcSlashed));
    }
    for (var f = 0; f < forms.length; f += 1) {
      if (forms[f] !== null && out.indexOf(forms[f]) === -1) out.push(forms[f]);
    }
  }
  return out;
}

function _pushAltCollisionIssues(issues, name, altNames, i, seen, caseSeen, opts, already) {
  var all = _withEquivalentForms([name].concat(altNames));
  var dup = null;
  var folded = null;
  for (var k = 0; k < all.length; k += 1) {
    var lower = all[k].toLowerCase();
    if (dup === null && all[k] in seen) dup = { value: all[k], index: seen[all[k]] };
    if (folded === null && caseSeen[lower] !== undefined && caseSeen[lower].value !== all[k]) {
      folded = { value: all[k], other: caseSeen[lower].value };
    }
  }
  var dupReported = dup !== null && opts.duplicateNamePolicy !== "allow";
  if (dupReported && !already.duplicate) {
    issues.push({
      kind: "duplicate-entry-name",
      severity: opts.duplicateNamePolicy === "reject" ? "critical" : "warn",
      ruleId: "archive.duplicate-name",
      location: i,
      snippet: _altLabel(name, dup.value) + " duplicates a name of entry at index " + dup.index +
               EQUIVALENT_NAMES_NOTE + " (later entry would silently overwrite)",
    });
  }
  if (folded !== null && opts.caseInsensitiveCollisionPolicy !== "allow" &&
      !already.duplicate && !already.caseCollision && !dupReported) {
    issues.push({
      kind: "case-insensitive-collision",
      severity: opts.caseInsensitiveCollisionPolicy === "reject" ? "high" : "warn",
      ruleId: "archive.case-collision",
      location: i,
      snippet: _altLabel(name, folded.value) + " collides case-insensitively with " +
               JSON.stringify(folded.other) + EQUIVALENT_NAMES_NOTE,
    });
  }
  for (var m = 0; m < all.length; m += 1) {
    if (!(all[m] in seen)) seen[all[m]] = i;
    var low = all[m].toLowerCase();
    if (caseSeen[low] === undefined) caseSeen[low] = { value: all[m] };
  }
}

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
  var allSeen = Object.create(null);
  var allCaseSeen = Object.create(null);
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

    var altNames = [];
    if (e.altNames !== undefined && e.altNames !== null) {
      var altValid = Array.isArray(e.altNames) && e.altNames.every(function (alt) {
        return typeof alt === "string" && alt.length > 0;
      });
      if (!altValid) {
        issues.push({
          kind: "bad-entry-name", severity: "high",
          ruleId: "archive.bad-entry-name",
          location: i,
          snippet: "entry " + JSON.stringify(name) + " has altNames that is not an array of non-empty strings",
        });
      } else {
        for (var ai = 0; ai < e.altNames.length; ai += 1) {
          if (e.altNames[ai] !== name && altNames.indexOf(e.altNames[ai]) === -1) altNames.push(e.altNames[ai]);
        }
      }
    }

    _pushNameIssues(issues, name, "entry " + JSON.stringify(name), i, e, opts);
    for (var an = 0; an < altNames.length; an += 1) {
      _pushNameIssues(issues, altNames[an],
        "entry " + JSON.stringify(name) + " (also read as " + JSON.stringify(altNames[an]) + ")", i, e, opts);
    }

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

    var collided = _pushCollisionIssues(issues, name, "entry " + JSON.stringify(name), "", i,
      nameSeen, caseSeen, opts);
    _pushAltCollisionIssues(issues, name, altNames, i, allSeen, allCaseSeen, opts, collided);

    if (e.isEncrypted) encryptedCount += 1;
    else if (!e.isDirectory) unencryptedCount += 1;

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

  if (totalSize > opts.maxTotalBytes) {
    issues.push({
      kind: "total-size-cap", severity: "high",
      ruleId: "archive.total-size",
      snippet: "total uncompressed size " + totalSize +
               " bytes exceeds maxTotalBytes " + opts.maxTotalBytes,
    });
  }

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

/**
 * @primitive  b.guardArchive.validateEntries
 * @signature  b.guardArchive.validateEntries(entries, opts)
 * @since      0.7.8
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardArchive.gate, b.guardArchive.inspectMagic, b.guardFilename.validate
 *
 * Inspect an operator-supplied `entries` array (one entry per archive
 * member: `{ name, altNames, size, compressedSize, isSymlink, isHardlink,
 * linkTarget, isDirectory, isEncrypted, attrs }`) and return
 * `{ ok, issues }`. `altNames` is optional: an array of other names an
 * archive reader may extract the entry under. The path checks (zip-slip,
 * absolute path, the `b.guardFilename` catalog and nested-archive names)
 * run on `name` and on every entry of `altNames`. Duplicate names and
 * case-insensitive collisions are checked again across every name and
 * alternate name of every entry, and across the Unicode NFC form of each
 * of them. Two names with the same NFC form, such as one that holds
 * U+00E9 where the other holds `e` followed by U+0301, are reported as `archive.duplicate-name` under `duplicateNamePolicy`. APFS
 * and HFS+ extract both to one file. The same holds for two names that
 * are equal once each backslash is read as `/`, such as `d\a.txt` and
 * `d/a.txt`, which an extractor on Windows writes to one file. Two names
 * that are equal once empty and `.` path segments are dropped, such as
 * `d/a.txt`, `d/./a.txt`, `d//a.txt` and `./d/a.txt`, are duplicates too,
 * because unzip, bsdtar, 7-Zip and Python's `zipfile` extract them to one
 * file. Every path segment of every name, not only the last, is checked
 * for a trailing dot or leading or trailing whitespace, reported as
 * `archive.filename.leading-trailing` (high), and for a Windows reserved
 * device name such as `CON`, `aux.txt` or `LPT1`, in any case and with or
 * without an extension, reported as `archive.filename.reserved-name`
 * (critical). `a/CON` and `CON/a.txt` are reported the same way as `CON`,
 * and `b.archive.read.zip` `extractEntries()` refuses them, as
 * `b.safeArchive.extract` does. `b.archive.read.zip` `inspect()` sets
 * `altNames` to the code page 437 and UTF-8 decodes of a ZIP name field
 * whose general-purpose bit 11 is clear. An `altNames` that is not an
 * array of non-empty strings is reported as
 * `archive.bad-entry-name`. Issues carry `{ kind, severity, ruleId, location,
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
 *   reservedNamePolicy:             "reject"|"audit"|"allow",  // Windows device names (CON, AUX, ...) in any path segment; "allow" for Linux-only targets
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
    "guardArchive.validateEntries", GuardArchiveError, "archive/bad-opt");
  if (!Array.isArray(entries)) {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "entries must be an array" }],
    };
  }
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
 * `GuardArchiveError("archive/bad-profile")` on unknown name.
 *
 * @opts
 *   extends: "strict"|"balanced"|"permissive",   // base profile name(s)
 *
 * @example
 *   var resolved = b.guardArchive.buildProfile({ extends: "strict" });
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
 * `GuardArchiveError("archive/bad-posture")` on unknown name.
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
 * success; throws `GuardArchiveError("archive/bad-opt")` when
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
  NAME:                "archive",
  KIND:                "entries",
  POLICY_VOCABULARY:   POLICY_ENUM,
  INTEGRATION_FIXTURES: Object.freeze({
    kind:           "entries",
    contentType:    "application/zip",
    extension:      ".zip",
    benignEntries:  [{ name: "README.txt", size: 1000, compressedSize: 500 }],
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
  validateEntries:     validateEntries,
  inspectMagic:        inspectMagic,
  checkExtractionPath: checkExtractionPath,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            gateContract.freezePolicy(PROFILES),
  DEFAULTS:            gateContract.freezePolicy(DEFAULTS),
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  ARCHIVE_EXTENSIONS:  ARCHIVE_EXTENSIONS,
  MAGIC_SIGNATURES:    MAGIC_SIGNATURES,
  GuardArchiveError:   GuardArchiveError,
  inspect:             inspect,
  zipBombPolicy:       zipBombPolicy,
  entryTypePolicy:     entryTypePolicy,
  tarEntryPolicy:      tarEntryPolicy,
};

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
 * `inspect` reads the central directory, every local header and data
 * descriptor, and the bytes between one entry's data and the next local
 * header, but does not decompress entry data. It rejects with the same
 * `archive-read/*` codes as `b.archive.read.zip` `inspect()`: for the
 * end records, the central directory, entry placement, the bytes before
 * the first local header, the EOCD comment and the gaps between entries,
 * and `archive-read/bad-lfh-signature` or `archive-read/lfh-cd-skew`
 * when a local header or data descriptor disagrees with the central
 * directory on the name bytes, method, CRC-32, sizes or general-purpose
 * flag bits 0, 3, 6, 11 and 13. The entry names it judges are the names
 * Info-ZIP unzip, 7-Zip and bsdtar extract: the UTF-8 path of an Info-ZIP
 * Unicode Path extra field (0x7075) of version 1 whose CRC-32 matches
 * the name field, otherwise the name field. `validateEntries` also judges
 * each entry's `altNames`: the other decodes of a name field whose
 * general-purpose bit 11 is clear (see `b.archive.read.zip`). It rejects with
 * `archive-read/unicode-path-mismatch` when such a field is malformed,
 * declares more bytes than its extra block holds, or is one those tools
 * read differently, or when the local header and the central directory
 * resolve to different names, with `archive-read/bad-utf8-name` when a
 * name field flagged UTF-8 (bit 11) is not valid UTF-8, and with
 * `archive-read/aborted` when `opts.signal` is aborted before or during
 * that pass. A name field with bit 11 clear that is not valid UTF-8 is
 * judged as its code page 437 decode.
 *
 * Every option other than `format`, `audit` and `signal` goes to
 * `validateEntries` with the entry list, so the caps, the per-rule
 * policies and `compliancePosture` apply. `inspect` checks those options
 * before it reads the archive. It throws `archive/format-unsupported`
 * for a `format` other than `"zip"`, `archive/bad-profile` for a
 * `profile` that is not `"strict"`, `"balanced"` or `"permissive"`,
 * `archive/bad-posture` for an unknown `compliancePosture`, and
 * `archive/bad-opt` for a cap that is not a positive integer or a
 * policy outside its vocabulary.
 *
 * `inspect` does not check entry data against its CRC-32.
 * `b.archive.read.zip` `extract` / `extractEntries` and
 * `b.safeArchive.extract` check each entry's CRC-32 as they extract it.
 *
 * Operators using the lower-level read primitive directly call this
 * to combine the metadata pass with the guard pass; `b.safeArchive.
 * extract` does the same composition inline under the hood.
 *
 * @opts
 *   profile:        "strict" | "balanced" | "permissive",  // default: "balanced"
 *   format:         "zip" (v0.12.7 — tar v0.12.8, gz v0.12.9),
 *   audit:          b.audit,
 *   signal:         AbortSignal,
 *   ...:            any b.guardArchive.validateEntries opt,
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
  var guardOpts = Object.assign({}, opts, { profile: opts.profile || "balanced" });
  delete guardOpts.format;
  delete guardOpts.audit;
  delete guardOpts.signal;
  _resolveOpts(guardOpts);
  var reader = archiveRead().zip(adapter, { audit: opts.audit, signal: opts.signal });
  var rawEntries = await reader.inspect();
  var guardEntries = rawEntries.map(function (e) {
    return {
      name:           e.name,
      altNames:       e.altNames,
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
  var result = validateEntries(guardEntries, guardOpts);
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
  archiveRead()._validateBombPolicy(opts, "guardArchive.zipBombPolicy",
    GuardArchiveError, "guard-archive/bad-bomb-policy");
  return Object.freeze(validateOpts.applyDefaults(opts, {
    maxEntries:                65535,
    maxEntryDecompressedBytes: C.BYTES.mib(128),
    maxTotalDecompressedBytes: C.BYTES.gib(4),
    maxExpansionRatio:         100,
  }));
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
  return entryTypePolicy(opts);
}
