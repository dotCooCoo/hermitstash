// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardFilename
 * @nav    Guards
 * @title  Guard Filename
 *
 * @intro
 *   Filename content-safety primitive (KIND="filename"). Validates
 *   user-supplied filenames before they reach disk, network paths,
 *   or Content-Disposition headers. Standalone primitive — does NOT
 *   register into `b.guardAll`'s content-type-routed dispatch (no
 *   canonical mime / ext); operators wire it directly via
 *   `b.fileUpload({ filenameSafety: gate })` and similar host opts.
 *
 *   Path-traversal defense: `..` / `../` / `..\\`, percent-encoded
 *   `%2e%2e`, double-encoded `%252e%252e`, and UTF-8 overlong
 *   sequences `0xC0 0xAE` (for `.`) and `0xC0 0xAF` (for `/`) ALWAYS
 *   throw — no profile downgrades the refusal. Threat catalog
 *   grounded in OWASP Path Traversal + WSTG file-inclusion testing
 *   guides; CWE-22 / 23 / 35 / 73 / 78 / 434 / 36; PortSwigger
 *   File-path-traversal series (null-byte bypass + extension
 *   validation); Memento-RTLO + RTL-Spiegel filename-spoofing
 *   reports (CVE-2021-42574 in filename context); Kevin Boone
 *   overlong UTF-8 write-up.
 *
 *   Universal-throw security floor: null-byte truncation
 *   (`file.txt\x00.exe`), NTFS alternate data streams
 *   (`file.txt:hidden.exe`), UNC paths (`\\server\share\file` and
 *   `//host/share/file`), and overlong UTF-8 byte sequences ALL
 *   throw `GuardFilenameError` regardless of profile — there is no
 *   sanitize-action that repairs these classes. Windows reserved
 *   device names (CON / PRN / AUX / NUL / COM1-9 / LPT1-9 / CLOCK$
 *   / CONFIG$) refuse under strict and balanced (even with
 *   extensions — `CON.txt` collides with the device).
 *
 *   Unicode hygiene: BIDI / RTLO refuses at every profile (Memento-
 *   RTLO `Photo01By<U+202E>gpj.SCR` displays as `Photo01ByRCS.jpg` while
 *   the OS opens `.SCR`). Zero-width and invisible-formatting strip
 *   under balanced/permissive, refuse under strict. Homoglyph
 *   (Cyrillic / Greek / fullwidth Latin mixed with ASCII letters)
 *   refuses under strict, audits under balanced/permissive.
 *
 *   Extension policy: operator-supplied `extensionAllowlist`
 *   catches double-extension bypass (`file.jpg.exe` lands at the
 *   last `.exe` and refuses). Shell-shortcut / executable extensions
 *   (`.lnk` / `.url` / `.desktop` / `.scr` / `.bat` / `.cmd` /
 *   `.com` / `.pif` / `.vbs` / `.js` / `.jse` / `.wsf` / `.wsh` /
 *   `.ps1` / `.psm1` / `.app` / `.deb` / `.rpm` / `.msi` and the
 *   broader native-binary family) refuse under strict, audit under
 *   balanced/permissive.
 *
 *   Length caps: 64 bytes (strict), 255 bytes (balanced/permissive).
 *   Path separators in the leaf refuse under strict/balanced;
 *   permissive opts in to multi-component paths via
 *   `pathSeparatorsPolicy: "audit"` and `maxComponents > 1`.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Threat-detection
 *   regex literals composed programmatically from numeric codepoint
 *   range tables (`lib/codepoint-class`); source file never embeds
 *   attack characters.
 *
 * @card
 *   Filename content-safety primitive (KIND="filename").
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardFilenameError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardFilenameError.factory;

// Reserved characters that must not appear in a filename leaf.
//   Windows: < > : " / \ | ? *
//   Unix:    /
//   Both:    null and C0 controls (handled separately via codepoint-class)
// `replaceAny` removes EVERY occurrence, which is what reservedCharPolicy
// "strip" means (CodeQL js/incomplete-multi-character-sanitization).
var RESERVED_CHARS = "<>:\"/\\|?*";
// The subset Windows refuses in a name but that is legal in a path, so the
// checks that run after the path separators have been accounted for look at
// this rather than the full set.
var RESERVED_CHARS_NO_SLASH = "<>:\"|?*";

// Windows reserved device names (case-insensitive). Match either the
// bare name or `<name>.<anything>`.
var WIN_RESERVED_NAMES = Object.freeze([
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
  "CLOCK$", "CONFIG$",
]);

// Windows folds the superscript digits U+00B9 / U+00B2 / U+00B3 to
// 1 / 2 / 3 when matching COM/LPT device names, so a superscript-digit
// form resolves to the same device. Built from numeric codepoints so
// the source stays pure-ASCII (guard-family rule).
var _SUPERSCRIPT_DIGIT_MAP = (function () {
  var m = {};
  m[String.fromCharCode(0xB9)] = "1";
  m[String.fromCharCode(0xB2)] = "2";
  m[String.fromCharCode(0xB3)] = "3";
  return m;
})();
var _SUPERSCRIPT_DIGITS = String.fromCharCode(0xB9, 0xB2, 0xB3);

// Path separators, either platform's.
var PATH_SEPARATORS = "/\\";

// Percent-encoded traversal and separator spellings. Matched without regard to
// ASCII case, since a browser and a filesystem both accept either.
var PERCENT_ENCODED_TRAVERSALS = ["%2e%2e", "%252e%252e", "%c0%ae", "%c0%af"];
var URL_ENCODED_SLASHES = ["%2f", "%5c", "%c0%af", "%c1%9c"];

// Shell-shortcut / executable extension family — refused under strict,
// audited under balanced/permissive.
var SHELL_EXEC_EXTS = Object.freeze([
  ".lnk", ".url", ".desktop", ".scr", ".bat", ".cmd", ".com", ".pif",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
  ".app", ".deb", ".rpm", ".msi", ".dmg", ".pkg", ".bin", ".sh",
  ".exe", ".dll", ".so", ".dylib", ".jar", ".class",
  ".reg", ".cpl", ".inf", ".hta", ".chm", ".scf",
]);

var HEX_RADIX = 16;                                                 // base-16 radix, not byte size

// Visual-confusable letter ranges that homoglyph against ASCII —
// Cyrillic / Greek / fullwidth Latin. Only flagged when mixed with
// ASCII letters in the same filename.
var HOMOGLYPH_RANGES = [[0x0400, 0x04FF], [0x0370, 0x03FF], [0xFF21, 0xFF5A]];

// Everything outside printable ASCII. Reported, not refused, under the
// nonAsciiPolicy.
var NON_PRINTABLE_ASCII_RANGES = [[0x0000, 0x001F], [0x007F, 0x10FFFF]];

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    homoglyphPolicy:      "reject",
    traversalPolicy:      "reject",
    reservedCharPolicy:   "reject",
    reservedNamePolicy:   "reject",
    adsPolicy:            "reject",
    leadingTrailingPolicy: "reject",
    shellExecExtPolicy:   "reject",
    pathSeparatorsPolicy: "reject",         // forbid path components, leaf-name only
    unicodeNormalization: "NFC",
    requireAscii:         true,
    extensionAllowlist:   null,             // null = any single extension
    requireSingleDot:     true,             // ".tar.gz" not allowed
    maxBytes:             64,               // leaf-name byte cap, not byte size
    maxComponents:        1,                // single leaf only, not bytes
  },
  "balanced": {
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "strip",
    homoglyphPolicy:      "audit",
    traversalPolicy:      "reject",
    reservedCharPolicy:   "reject",
    reservedNamePolicy:   "reject",
    adsPolicy:            "reject",
    leadingTrailingPolicy: "strip",
    shellExecExtPolicy:   "audit",
    pathSeparatorsPolicy: "reject",
    unicodeNormalization: "NFC",
    requireAscii:         false,
    extensionAllowlist:   null,
    requireSingleDot:     false,            // ".tar.gz" allowed
    maxBytes:             255,              // POSIX max-component, not byte size
    maxComponents:        1,                // single leaf only, not bytes
  },
  "permissive": {
    bidiPolicy:           "reject",
    controlPolicy:        "strip",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "strip",
    homoglyphPolicy:      "audit",
    traversalPolicy:      "reject",
    reservedCharPolicy:   "strip",
    reservedNamePolicy:   "audit",          // operator may want to accept on non-Windows targets
    adsPolicy:            "reject",
    leadingTrailingPolicy: "strip",
    shellExecExtPolicy:   "audit",
    pathSeparatorsPolicy: "audit",          // operator opts in to multi-component paths
    unicodeNormalization: "NFC",
    requireAscii:         false,
    extensionAllowlist:   null,
    requireSingleDot:     false,
    maxBytes:             255,              // POSIX max-component, not byte size
    maxComponents:        16,               // multi-component path cap, not bytes
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(5),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256, overlays: { gdpr: { bidiPolicy: "strip", controlPolicy: "strip" } } });

// ---- Helpers ----

// Delegates to the guard's own resolver rather than repeating its binding, so
// every entry point below is held to this guard's cap list. See guard-archive.
function _resolveOpts(opts) {
  return module.exports.resolveOpts(opts);
}

function _normalizeNFC(s) {
  try { return s.normalize ? s.normalize("NFC") : s; }
  catch (_e) { return s; }
}

function _isWinReserved(name) {
  // Reserved-name check applies to the base (without extension) AND to
  // the entire leaf — both `CON` and `CON.txt` collide with the device.
  // Windows normalizes the superscript digits U+00B9 / U+00B2 / U+00B3
  // to 1 / 2 / 3 when matching COM/LPT device names, so those superscript
  // forms resolve to the same devices as COM1 / LPT3; fold them to ASCII
  // before comparison so the spoofed forms are caught too. (Source stays
  // pure-ASCII per the guard-family rule — the codepoints are escaped.)
  // Fold COM/LPT superscript-digit spoofs to ASCII before matching
  // (Windows treats them as the device). See _SUPERSCRIPT_DIGIT_* below.
  var upper = _foldSuperscriptDigits(name.toUpperCase());
  for (var i = 0; i < WIN_RESERVED_NAMES.length; i += 1) {
    var r = WIN_RESERVED_NAMES[i];
    if (upper === r) return true;
    if (upper.indexOf(r + ".") === 0) return true;
  }
  return false;
}

function _foldSuperscriptDigits(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    out += _SUPERSCRIPT_DIGITS.indexOf(ch) !== -1 ? _SUPERSCRIPT_DIGIT_MAP[ch] : ch;
  }
  return out;
}

// A `..` segment: the whole name, or bounded by path separators on both sides.
// Bounded, not merely present — `..foo` and `a..b` are ordinary names.
function _hasTraversalSegment(name) {
  for (var i = 0; i + 1 < name.length; i += 1) {
    if (name.charAt(i) !== "." || name.charAt(i + 1) !== ".") continue;
    var beforeOk = i === 0 ||
      PATH_SEPARATORS.indexOf(name.charAt(i - 1)) !== -1;
    var afterOk = i + 2 === name.length ||
      PATH_SEPARATORS.indexOf(name.charAt(i + 2)) !== -1;
    if (beforeOk && afterOk) return true;
  }
  return false;
}

function _hasAnyFolded(name, needles) {
  for (var i = 0; i < needles.length; i += 1) {
    if (codepointClass.containsFolded(name, needles[i])) return true;
  }
  return false;
}

// A UNC path (`\\server\share`) or a protocol-relative one (`//host/path`) —
// both reach a remote host rather than the local directory the caller meant.
function _hasUncPrefix(name) {
  var a = name.charAt(0), b = name.charAt(1);
  return (a === "\\" && b === "\\") || (a === "/" && b === "/");
}

// An NTFS alternate-data-stream suffix: a colon followed by a run with no
// further colon and no separator in it, at the very end of the name.
function _hasAdsSuffix(name) {
  var colon = name.lastIndexOf(":");
  if (colon === -1 || colon === name.length - 1) return false;
  for (var i = colon + 1; i < name.length; i += 1) {
    var ch = name.charAt(i);
    if (ch === ":" || PATH_SEPARATORS.indexOf(ch) !== -1) return false;
  }
  return true;
}

// A leading or trailing whitespace run, or a trailing dot. Windows silently
// trims all three when it creates the file, so the name on disk differs from
// the name that was screened — which is how a screened `report.txt ` becomes
// an existing `report.txt` and overwrites it.
function _hasTrimmableEdge(name) {
  if (name.length === 0) return false;
  var ws = codepointClass.WHITESPACE_RANGES;
  return codepointClass.inRanges(name.charCodeAt(0), ws) ||
         codepointClass.inRanges(name.charCodeAt(name.length - 1), ws) ||
         name.charAt(name.length - 1) === ".";
}

function _hasAsciiLetter(name) {
  for (var i = 0; i < name.length; i += 1) {
    var cc = name.charCodeAt(i);
    if ((cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A)) return true;
  }
  return false;
}

function _countChar(name, ch) {
  var n = 0;
  for (var i = 0; i < name.length; i += 1) if (name.charAt(i) === ch) n += 1;
  return n;
}

// A Windows drive-letter prefix: one ASCII letter, a colon, a separator.
function _hasDriveLetterPrefix(name) {
  var cc = name.charCodeAt(0);
  var isLetter = (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
  return isLetter && name.charAt(1) === ":" &&
         PATH_SEPARATORS.indexOf(name.charAt(2)) !== -1;
}

function _hasOverlongUtf8(buf) {
  // Buffer-level scan for non-shortest UTF-8 sequences — `0xC0 0xXX`
  // and `0xC1 0xXX` are always invalid (would encode ASCII via 2 bytes
  // instead of 1), and `0xE0 0x80-9F` / `0xF0 0x80-8F` are 3/4-byte
  // overlongs. Reject the whole class.
  if (!Buffer.isBuffer(buf)) return false;
  for (var i = 0; i < buf.length - 1; i += 1) {
    var b0 = buf[i];
    if (b0 === 0xC0 || b0 === 0xC1) return true;
    if (b0 === 0xE0 && buf[i + 1] >= 0x80 && buf[i + 1] <= 0x9F) return true;
    if (b0 === 0xF0 && buf[i + 1] >= 0x80 && buf[i + 1] <= 0x8F) return true;
  }
  return false;
}

function _splitExt(name) {
  var idx = name.lastIndexOf(".");
  if (idx <= 0) return { base: name, ext: "" };
  return { base: name.slice(0, idx), ext: name.slice(idx) };
}

// Strip the leading and trailing runs of whitespace-or-dot that Windows would
// trim itself. The whitespace half is the full `\s` set, not the ASCII five —
// a name ending in U+00A0 is trimmed by the filesystem just the same.
function _stripLeadingTrailing(s) {
  var out = codepointClass.trimRanges(s, codepointClass.WHITESPACE_RANGES);
  out = codepointClass.trimChars(out, ".");
  // A dot can sit inside the whitespace run and vice versa (`" . a . "`), so
  // alternate until neither end moves.
  while (true) {
    var next = codepointClass.trimChars(
      codepointClass.trimRanges(out, codepointClass.WHITESPACE_RANGES), ".");
    if (next === out) return out;
    out = next;
  }
}

// ---- Detection pass ----

function _detectIssues(input, opts) {
  var issues = [];

  // Buffer-level checks BEFORE utf8 conversion (overlong encoding
  // would be invisible after toString).
  if (Buffer.isBuffer(input)) {
    if (_hasOverlongUtf8(input)) {
      issues.push({
        kind: "overlong-utf8", severity: "critical",
        ruleId: "filename.overlong-utf8",
        snippet: "non-shortest-form UTF-8 sequence in filename bytes (RFC 3629 §3 prohibits)",
      });
    }
  }

  var name = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : "");

  if (name.length === 0) {
    issues.push({
      kind: "empty", severity: "critical", ruleId: "filename.empty",
      snippet: "filename is empty",
    });
    return issues;
  }

  // 1. Bidi / null / control / zero-width via shared codepoint class. In a
  // filename an invisible char spoofs the name (homoglyph / path confusion), so
  // zero-width is `high` — passed as the zero-width severity.
  issues.push.apply(issues, codepointClass.detectCharThreats(name, opts, "filename"));

  // 2. Path traversal — raw + percent-encoded forms. `name` is bounded
  // by the maxBytes check at the end of this function (issues are
  // reported all-at-once; an oversized name still gets traversal-shape
  // detection so operators see the full failure surface).
  if (opts.traversalPolicy !== "allow") {
    if (_hasTraversalSegment(name) || name === "..") {
      issues.push({
        kind: "path-traversal", severity: "critical",
        ruleId: "filename.traversal",
        snippet: ".. component (CWE-22 / CWE-23)",
      });
    }
    if (_hasAnyFolded(name, PERCENT_ENCODED_TRAVERSALS)) {
      issues.push({
        kind: "path-traversal-encoded", severity: "critical",
        ruleId: "filename.traversal-encoded",
        snippet: "percent-encoded path-traversal sequence detected",
      });
    }
    if (_hasAnyFolded(name, URL_ENCODED_SLASHES)) {
      issues.push({
        kind: "url-encoded-separator", severity: "high",
        ruleId: "filename.url-encoded-separator",
        snippet: "percent-encoded path separator",
      });
    }
  }

  // 3. Path separators in leaf — pathSeparatorsPolicy controls.
  if (opts.pathSeparatorsPolicy !== "allow" && opts.pathSeparatorsPolicy !== "audit") {
    if (name.indexOf("/") !== -1 || name.indexOf("\\") !== -1) {
      issues.push({
        kind: "path-separator-in-leaf", severity: "high",
        ruleId: "filename.path-separator",
        snippet: "filename leaf contains a path separator (/ or \\)",
      });
    }
  }

  // 4. UNC paths — `\\server\share\...` or `//server/share/...`
  if (_hasUncPrefix(name)) {
    issues.push({
      kind: "unc-path", severity: "critical",
      ruleId: "filename.unc",
      snippet: "UNC network path (\\\\server\\share)",
    });
  }

  // 5. Reserved characters — < > : " | ? * (slashes handled separately).
  if (opts.reservedCharPolicy !== "allow") {
    var resIdx = codepointClass.indexOfAny(name, RESERVED_CHARS_NO_SLASH);
    if (resIdx !== -1) {
      issues.push({
        kind: "reserved-char", severity: "high",
        ruleId: "filename.reserved-char",
        location: resIdx,
        snippet: "reserved character " + JSON.stringify(name.charAt(resIdx)) +
                 " (Windows file system)",
      });
    }
  }

  // 6. NTFS alternate data streams — `name:stream`.
  if (opts.adsPolicy !== "allow") {
    if (_hasAdsSuffix(name) && name.charAt(0) !== "/") {
      // Only flag when there's a `:` followed by stream-name characters
      // and we're NOT at the start (relative path indicator).
      issues.push({
        kind: "ntfs-ads", severity: "critical",
        ruleId: "filename.ntfs-ads",
        snippet: "NTFS alternate data stream syntax (name:stream)",
      });
    }
  }

  // 7. Windows reserved device names.
  if (opts.reservedNamePolicy !== "allow") {
    if (_isWinReserved(name)) {
      issues.push({
        kind: "reserved-name", severity: "critical",
        ruleId: "filename.reserved-name",
        snippet: "filename collides with Windows reserved device name",
      });
    }
  }

  // 8. Leading / trailing whitespace + trailing dots — Windows strips them.
  if (opts.leadingTrailingPolicy !== "allow") {
    if (_hasTrimmableEdge(name)) {
      issues.push({
        kind: "leading-trailing-strip", severity: "high",
        ruleId: "filename.leading-trailing",
        snippet: "leading/trailing whitespace or trailing dot (Windows silently strips)",
      });
    }
  }

  // 9. Single-dot leaf-names.
  if (name === "." || name === "..") {
    issues.push({
      kind: "dot-leaf", severity: "critical", ruleId: "filename.dot-leaf",
      snippet: "filename is " + JSON.stringify(name),
    });
  }

  // 10. Homoglyph-with-ASCII mix.
  if (opts.homoglyphPolicy !== "allow" && _hasAsciiLetter(name)) {
    var hIdx = codepointClass.firstInRanges(name, HOMOGLYPH_RANGES);
    if (hIdx !== -1) {
      issues.push({
        kind: "homoglyph", severity: opts.homoglyphPolicy === "reject" ? "critical" : "warn",
        ruleId: "filename.homoglyph",
        location: hIdx,
        snippet: "homoglyph U+" + name.codePointAt(hIdx).toString(HEX_RADIX) +
                 " mixed with ASCII letters in filename",
      });
    }
  }

  // 11. ASCII-only requirement.
  if (opts.requireAscii) {
    var nonAsciiIdx = codepointClass.firstInRanges(name, NON_PRINTABLE_ASCII_RANGES);
    if (nonAsciiIdx !== -1) {
      issues.push({
        kind: "non-ascii", severity: "high",
        ruleId: "filename.non-ascii",
        location: nonAsciiIdx,
        snippet: "non-ASCII character (profile requires ASCII-only)",
      });
    }
  }

  // 12. Length cap.
  var byteLen = Buffer.byteLength(name, "utf8");
  if (byteLen > opts.maxBytes) {
    issues.push({
      kind: "too-long", severity: "high", ruleId: "filename.length",
      snippet: "filename " + byteLen + " bytes exceeds maxBytes " + opts.maxBytes,
    });
  }

  // 13. Multi-dot when requireSingleDot.
  if (opts.requireSingleDot) {
    var dotCount = _countChar(name, ".");
    if (dotCount > 1) {
      issues.push({
        kind: "multiple-dots", severity: "high", ruleId: "filename.multiple-dots",
        snippet: "filename has " + dotCount + " dots (profile requires single)",
      });
    }
  }

  // 14. Extension allowlist.
  if (Array.isArray(opts.extensionAllowlist) && opts.extensionAllowlist.length > 0) {
    var split = _splitExt(name);
    var ext = split.ext.toLowerCase();
    var allowed = opts.extensionAllowlist.map(function (e) { return e.toLowerCase(); });
    if (!ext || allowed.indexOf(ext) === -1) {
      issues.push({
        kind: "ext-not-allowlisted", severity: "critical",
        ruleId: "filename.ext-allowlist",
        snippet: "extension " + JSON.stringify(ext || "") +
                 " not in allowlist " + JSON.stringify(allowed),
      });
    }
  }

  // 15. Shell-shortcut / executable extensions.
  if (opts.shellExecExtPolicy !== "allow") {
    var splitX = _splitExt(name);
    var extX = splitX.ext.toLowerCase();
    if (extX && SHELL_EXEC_EXTS.indexOf(extX) !== -1) {
      issues.push({
        kind: "shell-exec-ext",
        severity: opts.shellExecExtPolicy === "reject" ? "critical" : "warn",
        ruleId: "filename.shell-exec-ext",
        snippet: "shell-shortcut / executable extension " + JSON.stringify(extX),
      });
    }
    // Double-extension: name has two dots and inner is a "harmless"
    // disguise extension while outer is an executable.
    var dotIndices = [];
    for (var di = 0; di < name.length; di += 1) {
      if (name.charAt(di) === ".") dotIndices.push(di);
    }
    if (dotIndices.length >= 2) {
      var lastExt = name.slice(dotIndices[dotIndices.length - 1]).toLowerCase();
      if (SHELL_EXEC_EXTS.indexOf(lastExt) !== -1) {
        issues.push({
          kind: "double-extension", severity: "critical",
          ruleId: "filename.double-extension",
          snippet: "double-extension with executable last segment " + JSON.stringify(lastExt),
        });
      }
    }
  }

  return issues;
}

// ---- Sanitize pass ----

function _sanitize(input, opts) {
  var name = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : "");
  if (name.length === 0) {
    throw _err("filename.empty", "sanitize requires non-empty filename");
  }
  if (Buffer.isBuffer(input) && _hasOverlongUtf8(input)) {
    throw _err("filename.overlong-utf8", "filename has overlong UTF-8 sequence — cannot sanitize");
  }

  // Codepoint-class reject + strip via shared helpers.
  codepointClass.assertNoCharThreats(name, opts, _err, "filename");
  name = codepointClass.applyCharStripPolicies(name, opts);

  // Unicode normalize before further checks.
  if (opts.unicodeNormalization === "NFC") name = _normalizeNFC(name);

  // Reject path traversal even in sanitize — there's no safe sanitization.
  if (opts.traversalPolicy === "reject") {
    if (_hasTraversalSegment(name) || _hasAnyFolded(name, PERCENT_ENCODED_TRAVERSALS) ||
        name === "." || name === "..") {
      throw _err("filename.traversal", "filename contains path-traversal sequence");
    }
  }
  if (_hasUncPrefix(name)) {
    throw _err("filename.unc", "UNC path syntax");
  }

  // Strip leading/trailing whitespace and trailing dots if policy says so.
  if (opts.leadingTrailingPolicy === "strip") {
    name = _stripLeadingTrailing(name);
  } else if (opts.leadingTrailingPolicy === "reject" && _hasTrimmableEdge(name)) {
    throw _err("filename.leading-trailing",
      "filename has leading/trailing whitespace or trailing dot");
  }

  // Strip reserved chars when policy says strip.
  if (opts.reservedCharPolicy === "strip") {
    // One pass over the whole reserved set INCLUDING path separators, so no
    // second pass is needed, and every occurrence goes rather than the first.
    name = codepointClass.replaceAny(name, RESERVED_CHARS, "_");
  } else if (opts.reservedCharPolicy === "reject") {
    if (codepointClass.indexOfAny(name, RESERVED_CHARS_NO_SLASH) !== -1) {
      throw _err("filename.reserved-char", "filename contains reserved character");
    }
    if (opts.pathSeparatorsPolicy === "reject" &&
        (name.indexOf("/") !== -1 || name.indexOf("\\") !== -1)) {
      throw _err("filename.path-separator", "filename leaf contains path separator");
    }
  }

  // Reserved-name check — append underscore prefix to disambiguate.
  if (opts.reservedNamePolicy !== "allow" && _isWinReserved(name)) {
    if (opts.reservedNamePolicy === "reject") {
      throw _err("filename.reserved-name",
        "filename collides with Windows reserved device name");
    }
    name = "_" + name;
  }

  // ADS detection.
  if (opts.adsPolicy === "reject" && _hasAdsSuffix(name)) {
    throw _err("filename.ntfs-ads", "filename contains NTFS alternate data stream syntax");
  }

  // Length cap.
  if (Buffer.byteLength(name, "utf8") > opts.maxBytes) {
    throw _err("filename.length", "filename exceeds maxBytes " + opts.maxBytes);
  }

  if (name.length === 0) {
    throw _err("filename.empty", "sanitize produced empty filename");
  }
  return name;
}

// ---- Public surface ----

/**
 * @primitive  b.guardFilename.validate
 * @signature  b.guardFilename.validate(input, opts?)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardFilename.sanitize, b.guardFilename.gate
 *
 * Inspect a filename (string or Buffer) and return
 * `{ ok, issues }`. Each issue carries
 * `{ kind, severity, ruleId, location, snippet }` with severity in
 * `"warn"|"high"|"critical"`. Detected: path-traversal raw and
 * percent-encoded, null-byte truncation, NTFS ADS, UNC path,
 * overlong UTF-8, Windows reserved-name, reserved character,
 * leading/trailing whitespace + trailing dot, BIDI / control /
 * zero-width / homoglyph, non-ASCII (when `requireAscii`), length
 * cap, multi-dot violation, extension allowlist miss, double-
 * extension with executable last segment, shell-shortcut extension.
 * Pure inspection — never throws.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:           "reject"|"strip"|"allow",
 *   controlPolicy:        "reject"|"strip"|"allow",
 *   nullBytePolicy:       "reject",                       // always reject
 *   zeroWidthPolicy:      "reject"|"strip"|"allow",
 *   homoglyphPolicy:      "reject"|"audit"|"allow",
 *   traversalPolicy:      "reject",                       // always reject
 *   reservedCharPolicy:   "reject"|"strip"|"allow",
 *   reservedNamePolicy:   "reject"|"audit"|"allow",
 *   adsPolicy:            "reject",                       // always reject
 *   leadingTrailingPolicy: "reject"|"strip"|"allow",
 *   shellExecExtPolicy:   "reject"|"audit"|"allow",
 *   pathSeparatorsPolicy: "reject"|"audit"|"allow",
 *   unicodeNormalization: "NFC"|null,
 *   requireAscii:         boolean,
 *   extensionAllowlist:   string[]|null,
 *   requireSingleDot:     boolean,
 *   maxBytes:             number,    // leaf-name byte cap
 *   maxComponents:        number,    // path-component count
 *
 * @example
 *   var rv = b.guardFilename.validate("../etc/passwd", { profile: "strict" });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.kind === "path-traversal"; });   // → true
 *
 *   var ok = b.guardFilename.validate("report-2026-Q1.txt", { profile: "strict" });
 *   ok.ok;                                             // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxComponents"],
    "guardFilename.validate", GuardFilenameError, "filename.bad-opt");

  // "bytes" contract — accept string/Buffer and pass it RAW: _detectIssues
  // inspects bytes (overlong-UTF-8) before any utf8 conversion, so coercing to
  // text first would hide the encoding attack.
  return gateContract.runIssueValidator(input, opts, _detectIssues, "bytes");
}

function _sanitizeStripMode(input, opts) {
  // mode: "strip" — operator-friendly Content-Disposition path. C0 control
  // chars (CR / LF / etc., excluding NUL — null-byte truncation is never
  // sanitizable) and bidi-override codepoints are replaced with "_". The
  // security floor still applies: path traversal, null-byte, NTFS ADS,
  // UNC, and overlong UTF-8 throw at every profile level.
  if (Buffer.isBuffer(input) && _hasOverlongUtf8(input)) {
    throw _err("filename.overlong-utf8", "filename has overlong UTF-8 sequence — cannot sanitize");
  }
  var name = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : "");
  if (name.length === 0) {
    throw _err("filename.empty", "sanitize requires non-empty filename");
  }
  if (name.indexOf("\0") !== -1) {
    throw _err("filename.null-byte", "filename contains null byte — null-byte truncation is never sanitizable");
  }
  // Replace control chars + bidi codepoints with "_". Zero-width is
  // also stripped (visible-name spoofing has no value if the bytes
  // round-trip silently). CR (U+0D) / LF (U+0A) are NOT in the shared
  // C0 table (they're dialect-shaped chars elsewhere) but they're the
  // exact chars that enable Content-Disposition response splitting,
  // which is the primary use case for strip mode — replace explicitly.
  name = codepointClass.replaceAny(name, "\r\n\t\v\f", "_");
  // CTRL_RANGES covers U+007F DELETE alongside the C0 block, matching what the
  // detector reports — otherwise a filename validated as carrying a control
  // character came back from sanitize still carrying it.
  name = codepointClass.replaceRanges(name, codepointClass.CTRL_RANGES, "_");
  name = codepointClass.replaceRanges(name, codepointClass.BIDI_RANGES, "_");
  name = codepointClass.replaceRanges(name, codepointClass.ZERO_WIDTH_RANGES, "_");
  // Unicode Tags follows the zero-width policy where the guard names none of
  // its own, so strip mode replaces it on the same terms — a name that reads
  // as one thing and carries another is the case this mode exists for. The
  // policy comes from the shared resolver so an explicit `tagsPolicy: "allow"`
  // is honored rather than overridden by the zero-width setting.
  if (codepointClass.resolveTagsPolicy(opts) !== "allow") {
    name = codepointClass.replaceRanges(name, codepointClass.TAG_RANGES, "_");
  }
  if (opts.unicodeNormalization === "NFC") name = _normalizeNFC(name);

  // Security floor — never sanitizable.
  if (_hasTraversalSegment(name) || _hasAnyFolded(name, PERCENT_ENCODED_TRAVERSALS) ||
      name === "." || name === "..") {
    throw _err("filename.traversal", "filename contains path-traversal sequence");
  }
  if (_hasUncPrefix(name)) {
    throw _err("filename.unc", "UNC path syntax");
  }
  if (_hasAdsSuffix(name) && name.charAt(0) !== "/") {
    throw _err("filename.ntfs-ads", "filename contains NTFS alternate data stream syntax");
  }
  if (Buffer.byteLength(name, "utf8") > opts.maxBytes) {
    throw _err("filename.length", "filename exceeds maxBytes " + opts.maxBytes);
  }
  if (name.length === 0) {
    throw _err("filename.empty", "sanitize produced empty filename");
  }
  return name;
}

/**
 * @primitive  b.guardFilename.sanitize
 * @signature  b.guardFilename.sanitize(input, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardFilename.validate, b.guardFilename.gate
 *
 * Best-effort cleanup of a filename. Two modes: `"enforce"` (default;
 * applies the profile's strip/reject policies and throws on
 * unsanitizable refusals) and `"strip"` (operator-friendly
 * Content-Disposition path — replaces control / bidi / zero-width
 * codepoints with `_` and applies a security floor).
 *
 * The security floor ALWAYS throws regardless of mode/profile:
 * path-traversal raw and percent-encoded, null-byte, NTFS alternate
 * data streams, UNC paths, overlong UTF-8 sequences, and post-strip
 * length-cap violation. These classes are unrepairable — silently
 * fixing them would mask the attack signal an audit log needs.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   mode:       "enforce"|"strip",
 *   audit:      { safeEmit: function },     // optional sink for strip mode
 *   unicodeNormalization: "NFC"|null,
 *   maxBytes:   number,
 *
 * @example
 *   var safe = b.guardFilename.sanitize("My File.txt", { profile: "balanced" });
 *   safe;                                              // → "My File.txt"
 *
 *   // Path traversal ALWAYS throws — never sanitizable.
 *   try {
 *     b.guardFilename.sanitize("../etc/passwd", { profile: "permissive" });
 *   } catch (e) {
 *     e.code;                                          // → "filename.traversal"
 *   }
 */
function sanitize(input, opts) {
  var rawMode = opts && opts.mode;
  opts = _resolveOpts(opts);
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw _err("filename.bad-input", "sanitize requires string or Buffer input");
  }
  if (rawMode === "strip") {
    var stripped = _sanitizeStripMode(input, opts);
    if (opts.audit && typeof opts.audit.safeEmit === "function") {
      try {
        opts.audit.safeEmit({
          action:   "guardfilename.sanitize.stripped",
          outcome:  "success",
          metadata: {
            originalLength:  Buffer.byteLength(
              typeof input === "string" ? input : input.toString("utf8"), "utf8"),
            sanitizedLength: Buffer.byteLength(stripped, "utf8"),
          },
        });
      } catch (_e) { /* drop-silent — audit sinks must never crash the producer */ }
    }
    return stripped;
  }
  return _sanitize(input, opts);
}

/**
 * @primitive  b.guardFilename.gate
 * @signature  b.guardFilename.gate(opts?)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardFilename.validate, b.guardFilename.sanitize, b.fileUpload.create
 *
 * Build a `b.gateContract` gate that consumes `ctx.filename` (or
 * `ctx.name`). Action chain: `serve` (no filename or clean) →
 * `audit-only` (warn-only issues) → `sanitize` (critical/high but
 * every reject-policy off — strip-eligible classes only) → `refuse`
 * (any reject-policy active or sanitize fails). Path-traversal /
 * null-byte / NTFS-ADS / UNC / overlong-UTF-8 always cause `refuse`
 * — there is no `sanitize` action for those classes, and no policy
 * setting reaches them.
 *
 * Each finding is dispositioned by its own policy and the strongest
 * answer across them decides the action. The repair itself is not
 * per-finding: `sanitize` dispatches to `b.guardFilename.sanitize`,
 * which applies every transform the profile declares, so a name that
 * enters sanitization because one class asked to strip also has the
 * profile's other repairs applied — including to a class whose own
 * policy was `audit`. The verdict's `sanitized` is byte-identical to
 * calling `b.guardFilename.sanitize(name, opts)` directly.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *
 * @example
 *   var fnGate = b.guardFilename.gate({ profile: "strict" });
 *   var verdict = await fnGate.check({ filename: "../etc/passwd" });
 *   verdict.action;                                    // → "refuse"
 *
 *   var ok = await fnGate.check({ filename: "report.txt" });
 *   ok.action;                                         // → "serve"
 */
// Bind each finding to the operator's policy for it. The shared character
// classes resolve through the one family helper; the filename-specific kinds
// map to the policy this guard names for them. A kind with no policy returns
// null and the caller applies the conservative severity answer.
// The classes this guard refuses unconditionally, whatever any policy says.
// Documented on the gate itself: there is no `sanitize` action for them, and a
// name carrying one is not repairable into a safe name — a UNC prefix reaches
// another host, a traversal segment escapes the directory, a NUL truncates the
// name at whichever consumer reads it first, and an ADS suffix names a second
// stream on the same file. Reading these from `traversalPolicy` would let a
// profile that sets it to `audit` serve the name unchanged, which is the
// bypass the floor exists to prevent.
var ALWAYS_REFUSE_KINDS = Object.freeze({
  "path-traversal":         true,
  "path-traversal-encoded": true,
  "unc-path":               true,
  "ntfs-ads":               true,
  "null-byte":              true,
  "overlong-utf8":          true,
});

function _gateDispositionFor(issue, opts) {
  if (ALWAYS_REFUSE_KINDS[issue.kind]) return "refuse";
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "path-separator-in-leaf":
    case "url-encoded-separator":    return gateContract.policyDisposition(opts.pathSeparatorsPolicy);
    case "reserved-char":            return gateContract.policyDisposition(opts.reservedCharPolicy);
    case "reserved-name":            return gateContract.policyDisposition(opts.reservedNamePolicy);
    case "leading-trailing-strip":   return gateContract.policyDisposition(opts.leadingTrailingPolicy);
    case "homoglyph":                return gateContract.policyDisposition(opts.homoglyphPolicy);
    case "non-ascii":                return gateContract.policyDisposition(opts.nonAsciiPolicy);
    // Both of these fire on the same condition — a last extension in
    // SHELL_EXEC_EXTS — so they are one finding reported twice and answer to
    // one policy. Mapping only the first left the second on the conservative
    // severity default, where `critical` refuses, and a profile asking to
    // audit a disguised executable refused it instead.
    case "shell-exec-ext":
    case "double-extension":         return gateContract.policyDisposition(opts.shellExecExtPolicy);
    // Length, extension allowlisting and the dot-shape findings carry no
    // policy of their own and admit no repair that preserves intent.
    default:                         return null;
  }
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardFilename:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      // Filename-shape ctx — operator passes filename via ctx.filename.
      // Read through the shared reader rather than an `||` chain: the chain
      // cannot tell an ABSENT field from one present as "", and served both,
      // while validate("") refuses an empty filename.
      var name = gateContract.ctxValueFrom(ctx, ["filename", "name"]);
      if (name === undefined || name === null) return { ok: true, action: "serve" };
      var rv = validate(name, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };

      // The action comes from what each finding's OWN policy asks, and the
      // strongest answer across the findings wins. Resolving it from severity
      // instead made `critical` and `high` both refuse, so a profile asking to
      // strip a zero-width character refused the filename rather than cleaning
      // it — and the sanitize-eligibility test below compounded that by being
      // all-or-nothing: one `reject` policy anywhere in the profile made every
      // OTHER policy refuse too, whatever it declared.
      //
      // Taking the strongest disposition keeps that from weakening anything: a
      // traversal finding still refuses on its own policy no matter what the
      // character policies say, which is the case the all-or-nothing test was
      // reaching for.
      var strongest = "serve";
      var RANK = { serve: 0, "audit-only": 1, sanitize: 2, refuse: 3 };
      for (var qi = 0; qi < rv.issues.length; qi += 1) {
        var d = _gateDispositionFor(rv.issues[qi], opts);
        if (d === "audit") d = "audit-only";
        // A finding with no policy of its own carries no instruction, so it
        // falls back to the conservative severity answer rather than serving.
        if (!d) {
          d = (rv.issues[qi].severity === "critical" || rv.issues[qi].severity === "high")
            ? "refuse" : "audit-only";
        }
        if (RANK[d] > RANK[strongest]) strongest = d;
      }
      if (strongest === "serve") return { ok: true, action: "serve", issues: rv.issues };
      if (strongest === "audit-only") return { ok: true, action: "audit-only", issues: rv.issues };

      if (strongest === "sanitize") {
        try {
          var clean = sanitize(name, opts);
          // `sanitized` is the field the gate contract carries through; a
          // guard-specific name is dropped by the verdict builder, which would
          // hand the caller `action: "sanitize"` with nothing to use. This
          // branch was all but unreachable while sanitize-eligibility was
          // all-or-nothing, so the wrong field name never showed.
          return {
            ok: true, action: "sanitize",
            sanitized: clean,
            issues: rv.issues,
          };
        } catch (_e) { /* fall through */ }
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate blocks in gate-contract.js, instantiated
// per guard by the page generator.

// ---- verifyExtractionPath -------------------------------------------------

var nodePath = require("node:path");
var nodeFs   = require("node:fs");

// CVE-2025-4517 PATH_MAX threshold — Python's tarfile filter relied on
// os.path.realpath which silently stops resolving symlinks once the
// resolved path exceeds PATH_MAX (4096 on Linux). The kernel keeps
// resolving past that, so the filter's safety check + the kernel's
// extraction diverge. We refuse paths whose pre-resolve length already
// exceeds PATH_MAX so the operator's realpath behavior is never the
// gating factor.
var PATH_MAX_BYTES = 4096;

/**
 * @primitive b.guardFilename.verifyExtractionPath
 * @signature b.guardFilename.verifyExtractionPath(entryName, extractionRoot, opts?)
 * @since     0.12.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.guardArchive.checkExtractionPath, b.guardArchive.validateEntries, b.archive.read.zip
 *
 * Dual-check extraction path safety: string-check (refuses `..`, leading
 * `/` / `\\`, drive-letter prefix, null byte, PATH_MAX overflow) followed
 * by `fs.realpath` agreement check (the resolved path on disk must
 * land inside the realpath of the extraction root). Returns the
 * resolved absolute path on success; throws `GuardFilenameError` on
 * any refusal.
 *
 * Per-segment Windows-extraction hazards are refused too — these are
 * within-root write-target redirections / collisions that the
 * containment + realpath checks structurally cannot see, so they need
 * a name-level check the disk `validate` / `sanitize` paths already
 * carry: a Windows reserved device name (`CON` / `NUL` / `COM1` / …,
 * which resolves to the device), NTFS alternate-data-stream syntax
 * (`name:stream`, which writes a hidden stream of the base file), and a
 * trailing dot / leading-or-trailing whitespace (`secret.txt.`, which
 * Windows strips so the entry overwrites an existing sibling). The
 * checks are platform-unconditional — the verifier may run on Linux
 * while extraction happens on Windows — and each has an opt-out for
 * Linux-only targets (`reservedNamePolicy` / `adsPolicy` /
 * `leadingTrailingPolicy: "allow"`), mirroring `validate`.
 *
 * Out of this primitive's scope (single-entry, name-only): 8.3 short-name
 * aliasing (`PROGRA~1`), case-insensitive cross-entry collision
 * (`Readme.txt` vs `README.TXT` on a case-preserving FS), and archive
 * symlink/hardlink ENTRY-target validation. The first two are cross-entry
 * properties and the third needs the entry's declared link target, which
 * this function never sees — they belong to the extract orchestrator
 * (`b.archive.read.zip.extract` / `b.safeArchive`), which owns the
 * case-folded seen-set and the link-target gate.
 *
 * Companion to `b.guardArchive.checkExtractionPath` (the string-only
 * portable gate the guard-archive primitive keeps fs-free for use as
 * a posture cascade member). `verifyExtractionPath` deliberately
 * couples to `node:fs` — the deeper realpath check defends the
 * CVE-2025-4517 PATH_MAX TOCTOU class where the operator's path
 * resolution and the kernel's diverge silently past PATH_MAX.
 *
 * `b.archive.read.zip.extract` composes this on every entry; operators
 * extracting via the safeArchive orchestrator never call it directly.
 * Operators rolling their own extract loop call it per entry.
 *
 * @opts
 *   followSymlinks:       boolean,  // default false — symlink in the
 *                                   //   resolved path refuses unless set
 *   reservedNamePolicy:   string,   // "allow" opts out of the Windows
 *                                   //   reserved-device-name segment check
 *   adsPolicy:            string,   // "allow" opts out of the NTFS-ADS check
 *   leadingTrailingPolicy: string,  // "allow" opts out of the trailing-dot /
 *                                   //   leading-or-trailing-whitespace check
 *
 * @example
 *   var resolved = b.guardFilename.verifyExtractionPath(
 *     "docs/readme.txt",
 *     "/var/quarantine"
 *   );
 *   // → "/var/quarantine/docs/readme.txt"
 *
 *   // ../ refuses
 *   b.guardFilename.verifyExtractionPath("../etc/passwd", "/var/quarantine");
 *   // throws GuardFilenameError("filename.extraction-traversal")
 *
 *   // PATH_MAX-overflow refuses BEFORE realpath truncation hits
 *   b.guardFilename.verifyExtractionPath(longName, "/var/quarantine");
 *   // throws GuardFilenameError("filename.extraction-path-max")
 */
function verifyExtractionPath(entryName, extractionRoot, opts) {
  opts = opts || {};
  if (typeof entryName !== "string" || entryName.length === 0) {
    throw new GuardFilenameError("filename.extraction-empty",
      "verifyExtractionPath: entryName must be non-empty string");
  }
  if (typeof extractionRoot !== "string" || extractionRoot.length === 0) {
    throw new GuardFilenameError("filename.extraction-bad-root",
      "verifyExtractionPath: extractionRoot must be non-empty string");
  }
  // PATH_MAX defense — refuse oversize names BEFORE any path operation
  // (mkdir / realpath / open) can truncate silently.
  if (entryName.length > PATH_MAX_BYTES) {
    throw new GuardFilenameError("filename.extraction-path-max",
      "verifyExtractionPath: entryName length " + entryName.length +
      " exceeds PATH_MAX=" + PATH_MAX_BYTES +
      " (CVE-2025-4517 class — operator realpath truncation defense)");
  }
  // String-check first — these checks are portable + don't touch fs.
  // Null byte — POSIX path APIs treat it as a string terminator.
  if (entryName.indexOf("\u0000") !== -1) {
    throw new GuardFilenameError("filename.extraction-null-byte",
      "verifyExtractionPath: entryName contains null byte");
  }
  // Normalize separators so the `..` walk catches Windows-style too.
  var normalized = codepointClass.replaceAny(entryName, "\\", "/");
  // Leading-slash absolute path refuses.
  if (normalized.length > 0 && normalized[0] === "/") {
    throw new GuardFilenameError("filename.extraction-absolute",
      "verifyExtractionPath: entryName is an absolute path");
  }
  // Drive-letter prefix (Windows) refuses.
  if (_hasDriveLetterPrefix(entryName)) {
    throw new GuardFilenameError("filename.extraction-drive-prefix",
      "verifyExtractionPath: entryName starts with a drive-letter prefix");
  }
  // UNC path (Windows) refuses.
  if (entryName.indexOf("\\\\") === 0 || entryName.indexOf("//") === 0) {
    throw new GuardFilenameError("filename.extraction-unc",
      "verifyExtractionPath: entryName starts with a UNC prefix");
  }
  // `..` segment refuses — walk path components. The same walk also
  // refuses per-segment Windows-extraction hazards the disk `validate`
  // / `sanitize` paths already catch but that string-containment +
  // realpath agreement cannot see, because they're WITHIN-root
  // collisions / write-target redirections rather than boundary
  // escapes. These checks are platform-UNCONDITIONAL: the verifier may
  // run on Linux while the archive is extracted on Windows, so a name
  // that's only dangerous on Windows must still be refused here.
  // Operators on a Linux-only target opt out per check, mirroring
  // `validate`'s policy vocabulary.
  var segs = normalized.split("/");
  for (var si = 0; si < segs.length; si += 1) {
    var seg = segs[si];
    if (seg === ".." || seg === "..\\" || seg === "..%2f" || seg === "..%5c") {
      throw new GuardFilenameError("filename.extraction-traversal",
        "verifyExtractionPath: entryName contains .. segment");
    }
    // URL-encoded variants — explicit refusal so operators don't
    // need to percent-decode before passing the entry name in.
    if (codepointClass.containsFolded(seg, "%2e%2e") ||
        codepointClass.containsFolded(seg, "%c0%ae")) {
      throw new GuardFilenameError("filename.extraction-traversal-encoded",
        "verifyExtractionPath: entryName contains encoded .. segment");
    }
    if (seg === "" || seg === ".") continue;   // separators / current-dir — nothing to name-check
    // Windows reserved device name (CON / NUL / COM1 / LPT1 / …): on
    // Windows the segment resolves to the device, redirecting the write.
    if (opts.reservedNamePolicy !== "allow" && _isWinReserved(seg)) {
      throw new GuardFilenameError("filename.extraction-reserved-name",
        "verifyExtractionPath: entryName segment " + JSON.stringify(seg) +
        " collides with a Windows reserved device name");
    }
    // NTFS alternate data stream (name:stream): on Windows the write
    // lands on a hidden stream of the base file, not a normal file.
    if (opts.adsPolicy !== "allow" && _hasAdsSuffix(seg)) {
      throw new GuardFilenameError("filename.extraction-ntfs-ads",
        "verifyExtractionPath: entryName segment " + JSON.stringify(seg) +
        " uses NTFS alternate-data-stream syntax (name:stream)");
    }
    // Trailing dot / leading-or-trailing whitespace: Windows silently
    // strips these, so `secret.txt.` or `secret.txt ` collides with an
    // existing sibling — an in-root overwrite the containment check
    // cannot see.
    if (opts.leadingTrailingPolicy !== "allow" && _hasTrimmableEdge(seg)) {
      throw new GuardFilenameError("filename.extraction-leading-trailing",
        "verifyExtractionPath: entryName segment " + JSON.stringify(seg) +
        " has leading/trailing whitespace or a trailing dot (Windows strips it)");
    }
  }
  // Resolve the destination path against the root via path.resolve
  // (string-level computation; no fs hits).
  var stringResolved = nodePath.resolve(extractionRoot, normalized);
  var rootResolved = nodePath.resolve(extractionRoot);
  // String-level containment check — the resolved path must start
  // with the root + separator (or equal the root for the directory
  // entry itself). path.resolve normalizes separators platform-aware.
  var sep = nodePath.sep;
  if (stringResolved !== rootResolved &&
      stringResolved.indexOf(rootResolved + sep) !== 0) {
    throw new GuardFilenameError("filename.extraction-escape",
      "verifyExtractionPath: resolved path " + JSON.stringify(stringResolved) +
      " escapes extraction root " + JSON.stringify(rootResolved));
  }
  // Realpath-agreement check (fs-coupled). The CVE-2025-4517 class
  // exploits a divergence between the operator's path.resolve view
  // and the kernel's symlink-resolution. We resolve the longest
  // existing ancestor + verify the realpath agrees with our string
  // view.
  if (nodeFs.existsSync(rootResolved)) {
    var realRoot;
    try {
      realRoot = nodeFs.realpathSync(rootResolved);
    } catch (e) {
      throw new GuardFilenameError("filename.extraction-root-realpath",
        "verifyExtractionPath: cannot realpath extractionRoot " +
        JSON.stringify(rootResolved) + ": " + (e && e.message));
    }
    // Walk up from the target until we find an existing parent —
    // every ancestor that EXISTS must realpath inside realRoot. Once
    // we hit a non-existent path, the create-and-extract step will
    // populate it; the operator-supplied target name doesn't pre-
    // exist, so the deepest existing ancestor is the boundary check.
    var probe = nodePath.dirname(stringResolved);
    var safetyCounter = 0;
    var SAFETY_LIMIT = 4096;     // guards against probe walking past root forever
    while (probe.length >= rootResolved.length && safetyCounter < SAFETY_LIMIT) {
      safetyCounter += 1;
      if (nodeFs.existsSync(probe)) {
        var realProbe;
        try { realProbe = nodeFs.realpathSync(probe); }
        catch (e2) {
          throw new GuardFilenameError("filename.extraction-realpath",
            "verifyExtractionPath: cannot realpath probe " +
            JSON.stringify(probe) + ": " + (e2 && e2.message));
        }
        // Two cases for the realpath comparison:
        //   a) The probe's realpath stays inside realRoot — the symlink
        //      (if any) is OS-level filesystem layout (macOS /var →
        //      /private/var, Linux /tmp -> tmpfs mount) and the
        //      ancestor was already canonicalized when we hashed
        //      realRoot at the top. Accept.
        //   b) The probe's realpath escapes realRoot — the symlink
        //      resolves outside the trust boundary. Refuse (this is
        //      the actual CVE-2025-4517 PATH_MAX TOCTOU class
        //      defense).
        // Also normalize probe through path.resolve(realRoot, relative
        // -- to -- realRoot) so we compare against the SAME canonicalized
        // root, not the operator-supplied form. Computing `probeRealRel`
        // via the realRoot prefix avoids treating OS-level /var -> /private
        // /var as an escape just because realProbe doesn't textually share
        // the rootResolved prefix.
        var probeInsideRoot = (realProbe === realRoot) ||
                              (realProbe.indexOf(realRoot + sep) === 0);
        if (!probeInsideRoot) {
          throw new GuardFilenameError("filename.extraction-realpath-escape",
            "verifyExtractionPath: realpath of " + JSON.stringify(probe) +
            " (" + JSON.stringify(realProbe) + ") escapes realpath of root " +
            JSON.stringify(realRoot) +
            " — CVE-2025-4517 PATH_MAX TOCTOU class");
        }
        // Symlink-anywhere-in-chain refusal was removed: macOS /
        // *BSD filesystems carry OS-level symlinks in standard paths
        // (/var → /private/var, /tmp → /private/tmp) that legitimate
        // operator usage routinely crosses. The realpath-agreement
        // check above is the load-bearing defense; if the resolved
        // chain STAYS inside realRoot, the symlinks resolved within
        // the trust boundary and the extraction is safe. Hostile
        // symlinks that escape are caught by the escape branch.
        void opts.followSymlinks;
        break;
      }
      var parent = nodePath.dirname(probe);
      if (parent === probe) break;   // hit fs root
      probe = parent;
    }
  }
  return stringResolved;
}

// ---- guard-* family identity ----
// Filename is a different axis from content-bytes (operators typically
// apply both: guardFilename on the upload's name, plus guardCsv /
// guardHtml / guardSvg / etc. on the body). guard-filename is therefore
// a STANDALONE primitive — it does NOT register into b.guardAll's
// content-type-routed dispatch (no canonical mime / ext per the registry
// contract). Operators wire it directly via b.fileUpload({ filenameSafety:
// gate }) and similar host opts.
var INTEGRATION_FIXTURES = Object.freeze({
  kind:            "filename",
  benignFilename:  "report-2026-Q1.txt",
  // Hostile: path-traversal in filename (CWE-22 class).
  hostileFilename: "../etc/passwd",
});

// Assembled from the gate-contract guard factory. KIND "filename" makes
// the default gate read ctx.filename || ctx.name, but this guard passes
// its own bespoke `gate` (the per-policy canSanitize matrix), so the
// factory only supplies the error class, registry exports, buildProfile /
// compliancePosture / loadRulePack wiring, and the verifyExtractionPath /
// WIN_RESERVED_NAMES / SHELL_EXEC_EXTS extras.
module.exports = gateContract.defineGuard({
  name:        "filename",
  kind:        "filename",
  charRepair:  true,
  errorClass:  GuardFilenameError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  // Genuine caps, where zero is not a setting — see guard-csv. maxRuntimeMs is
  // deliberately absent: zero there means no runtime budget.
  intOpts:     ["maxBytes", "maxComponents"],
  gate:        gate,
  extra: {
    WIN_RESERVED_NAMES:   WIN_RESERVED_NAMES,
    SHELL_EXEC_EXTS:      SHELL_EXEC_EXTS,
    verifyExtractionPath: verifyExtractionPath,
  },
});
