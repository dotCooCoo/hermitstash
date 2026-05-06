"use strict";
/**
 * guard-filename — filename content-safety primitive (b.guardFilename).
 *
 * Threat catalog grounded in current research: OWASP Path Traversal +
 * WSTG file-inclusion testing guides; CWE-22 / CWE-23 / CWE-35 / CWE-73
 * / CWE-78 / CWE-434 / CWE-36; PortSwigger File-path-traversal series
 * (null-byte bypass + extension validation); Memento-RTLO + RTL-Spiegel
 * file-name spoofing reports (CVE-2021-42574 in filename context); Kevin
 * Boone overlong UTF-8 sequence write-up.
 *
 *   var rv = b.guardFilename.validate("../etc/passwd", { profile: "strict" });
 *   var safe = b.guardFilename.sanitize("My File‮.txt", { profile: "balanced" });
 *   var g = b.guardFilename.gate({ profile: "strict" });
 *
 * Threat catalog covered:
 *
 *   1. Path traversal — `..`, `../`, `..\\`, percent-encoded `%2e%2e`,
 *      double-encoded `%252e%252e`, UTF-8 overlong `0xC0 0xAE` for `.`
 *      and `0xC0 0xAF` for `/`. Refused regardless of profile.
 *
 *   2. Null-byte truncation — `file.txt\x00.exe` — string ends at null
 *      in C-shaped APIs while validation sees `.txt`. Refused.
 *
 *   3. Windows reserved device names — CON / PRN / AUX / NUL / COM1-9 /
 *      LPT1-9 / CLOCK$ — even with extensions (CON.txt is reserved).
 *      Case-insensitive match. Refused.
 *
 *   4. NTFS alternate data streams — `file.txt:hidden.exe`. Colon is
 *      the ADS separator on NTFS. Refused.
 *
 *   5. Leading/trailing whitespace + trailing dots — Windows strips
 *      them silently, so `secret.txt ` and `secret.txt.` save as
 *      `secret.txt`. Refused under strict, stripped under balanced.
 *
 *   6. Unicode bidi / RTLO — CVE-2021-42574 in filename context. The
 *      Memento-RTLO toolkit weaponizes this: `Photo01By‮gpj.SCR`
 *      displays as `Photo01ByRCS.jpg` while the OS opens `.SCR`.
 *      Refused regardless of profile.
 *
 *   7. Zero-width / invisible-formatting chars — used to hide the real
 *      extension between the visible name and what the OS sees.
 *
 *   8. Homoglyph chars — Cyrillic / Greek / fullwidth Latin mixed with
 *      ASCII letters in a single name. Operator-decided severity per
 *      profile.
 *
 *   9. Path separators inside a leaf-name — `file/with/slashes` and
 *      `\\` variants. Reserved-character check.
 *
 *  10. Reserved characters — Windows: `< > : " / \ | ? *` plus the C0
 *      controls and DEL. Refused under strict / balanced; permissive
 *      strips and re-checks length.
 *
 *  11. UNC paths — `\\server\share\file` syntax. Refused (network-path
 *      resolution is outside the local-file scope).
 *
 *  12. Length caps — Windows MAX_PATH 260, NTFS 32767, ext4 255 bytes
 *      per component. Default leaf cap 255 bytes; total-path cap 260.
 *
 *  13. Empty / dot components — `..//.//file` after normalization. The
 *      validator surfaces these as path-traversal-shape issues.
 *
 *  14. Single-dot leaf — name === "." or ".." refused.
 *
 *  15. Allowlist mode — operators can pass `extensionAllowlist:
 *      [".png", ".jpg", ".pdf"]` to require a single allowed extension.
 *      The validator catches double-extension bypass: `file.jpg.exe`
 *      lands at the last dot's extension `.exe` and is refused.
 *
 *  16. Shell-shortcut extensions — `.lnk`, `.url`, `.desktop`, `.scr`,
 *      `.bat`, `.cmd`, `.com`, `.pif`, `.vbs`, `.js`, `.jse`, `.wsf`,
 *      `.wsh`, `.ps1`, `.psm1`, `.app`, `.deb`, `.rpm`, `.msi`. Refused
 *      under strict; balanced/permissive emit a warn-level audit issue.
 *
 *  17. UTF-8 overlong encoding — bytes that decode to ASCII separators
 *      via non-shortest-form encoding (Unicode standard prohibits, but
 *      legacy decoders accept them).
 *
 *  18. Anti-DoS caps — total filename byte length, total component
 *      count when the operator allows path-shape (default: leaf only).
 *
 * Threat-detection regex literals composed programmatically from numeric
 * codepoint range tables (lib/codepoint-class). Source file never
 * embeds attack characters.
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
var RESERVED_CHARS_RE = /[<>:"/\\|?*]/;

// Windows reserved device names (case-insensitive). Match either the
// bare name or `<name>.<anything>`.
var WIN_RESERVED_NAMES = Object.freeze([
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
  "CLOCK$", "CONFIG$",
]);

// Path-traversal indicators (anchored matches on raw and percent-decoded
// forms).
var PATH_TRAVERSAL_RE = /(^|[/\\])\.\.($|[/\\])/;
var PERCENT_ENCODED_TRAVERSAL_RE = /%2e%2e|%252e%252e|%c0%ae|%c0%af/i;
var URL_ENCODED_SLASH_RE = /%2f|%5c|%c0%af|%c1%9c/i;

// Shell-shortcut / executable extension family — refused under strict,
// audited under balanced/permissive.
var SHELL_EXEC_EXTS = Object.freeze([
  ".lnk", ".url", ".desktop", ".scr", ".bat", ".cmd", ".com", ".pif",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
  ".app", ".deb", ".rpm", ".msi", ".dmg", ".pkg", ".bin", ".sh",
  ".exe", ".dll", ".so", ".dylib", ".jar", ".class",
  ".reg", ".cpl", ".inf", ".hta", ".chm", ".scf",
]);

var HEX_RADIX = 16;                                                 // allow:raw-byte-literal — base-16 radix, not byte size

// Visual-confusable letter ranges that homoglyph against ASCII —
// Cyrillic / Greek / fullwidth Latin. Only flagged when mixed with
// ASCII letters in the same filename.
var HOMOGLYPH_RANGES = [[0x0400, 0x04FF], [0x0370, 0x03FF], [0xFF21, 0xFF5A]];
var HOMOGLYPH_RE = new RegExp("[" + codepointClass.charClass(HOMOGLYPH_RANGES) + "]"); // allow:dynamic-regex — codepoints from HOMOGLYPH_RANGES literal table

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "reject",
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
    maxBytes:             64,               // allow:raw-byte-literal — leaf-name byte cap, not byte size
    maxComponents:        1,                // allow:raw-byte-literal — single leaf only, not bytes
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
    maxBytes:             255,              // allow:raw-byte-literal — POSIX max-component, not byte size
    maxComponents:        1,                // allow:raw-byte-literal — single leaf only, not bytes
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
    maxBytes:             255,              // allow:raw-byte-literal — POSIX max-component, not byte size
    maxComponents:        16,               // allow:raw-byte-literal — multi-component path cap, not bytes
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(5),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": {
    bidiPolicy: "reject", controlPolicy: "reject", nullBytePolicy: "reject",
    zeroWidthPolicy: "reject", homoglyphPolicy: "reject",
    traversalPolicy: "reject", reservedCharPolicy: "reject",
    reservedNamePolicy: "reject", adsPolicy: "reject",
    leadingTrailingPolicy: "reject", shellExecExtPolicy: "reject",
    pathSeparatorsPolicy: "reject",
    requireAscii: true,
    forensicSnippetBytes: C.BYTES.bytes(256),
  },
  "pci-dss": {
    bidiPolicy: "reject", controlPolicy: "reject", nullBytePolicy: "reject",
    zeroWidthPolicy: "reject", homoglyphPolicy: "reject",
    traversalPolicy: "reject", reservedCharPolicy: "reject",
    reservedNamePolicy: "reject", adsPolicy: "reject",
    leadingTrailingPolicy: "reject", shellExecExtPolicy: "reject",
    pathSeparatorsPolicy: "reject",
    requireAscii: true,
    forensicSnippetBytes: C.BYTES.bytes(256),
  },
  "gdpr": {
    bidiPolicy: "strip", controlPolicy: "strip", nullBytePolicy: "reject",
    zeroWidthPolicy: "strip",
    traversalPolicy: "reject", reservedCharPolicy: "reject",
    leadingTrailingPolicy: "strip",
    forensicSnippetBytes: C.BYTES.bytes(128),
  },
  "soc2": {
    bidiPolicy: "reject", controlPolicy: "reject", nullBytePolicy: "reject",
    zeroWidthPolicy: "reject", traversalPolicy: "reject",
    reservedCharPolicy: "reject", reservedNamePolicy: "reject",
    adsPolicy: "reject", shellExecExtPolicy: "reject",
    pathSeparatorsPolicy: "reject",
    forensicSnippetBytes: C.BYTES.bytes(512),
  },
});

// ---- Helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardFilenameError,
    errCodePrefix:      "filename",
  });
}

function _normalizeNFC(s) {
  try { return s.normalize ? s.normalize("NFC") : s; }
  catch (_e) { return s; }
}

function _isWinReserved(name) {
  // Reserved-name check applies to the base (without extension) AND to
  // the entire leaf — both `CON` and `CON.txt` collide with the device.
  var upper = name.toUpperCase();
  for (var i = 0; i < WIN_RESERVED_NAMES.length; i += 1) {
    var r = WIN_RESERVED_NAMES[i];
    if (upper === r) return true;
    if (upper.indexOf(r + ".") === 0) return true;
  }
  return false;
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

function _stripLeadingTrailing(s) {
  return s.replace(/^[\s.]+|[\s.]+$/g, "");
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

  // 1. Bidi / null / control / zero-width via shared codepoint class.
  issues.push.apply(issues, codepointClass.detectCharThreats(name, opts, "filename"));
  if (opts.zeroWidthPolicy !== "allow" && opts.zeroWidthPolicy !== "strip") {
    var zwMatch = name.match(codepointClass.ZERO_WIDTH_RE);
    if (zwMatch) {
      issues.push({
        kind: "zero-width", severity: "high", ruleId: "filename.zero-width",
        location: zwMatch.index,
        snippet: "zero-width / invisible-formatting char U+" +
                 zwMatch[0].charCodeAt(0).toString(HEX_RADIX),
      });
    }
  }

  // 2. Path traversal — raw + percent-encoded forms. `name` is bounded
  // by the maxBytes check at the end of this function (issues are
  // reported all-at-once; an oversized name still gets traversal-shape
  // detection so operators see the full failure surface).
  if (opts.traversalPolicy !== "allow") {
    if (PATH_TRAVERSAL_RE.test(name) || /^\.\.$/.test(name) || name === "..") {  // allow:regex-no-length-cap — operator-supplied filename, length checked separately
      issues.push({
        kind: "path-traversal", severity: "critical",
        ruleId: "filename.traversal",
        snippet: ".. component (CWE-22 / CWE-23)",
      });
    }
    if (PERCENT_ENCODED_TRAVERSAL_RE.test(name)) {                              // allow:regex-no-length-cap — operator-supplied filename, length checked separately
      issues.push({
        kind: "path-traversal-encoded", severity: "critical",
        ruleId: "filename.traversal-encoded",
        snippet: "percent-encoded path-traversal sequence detected",
      });
    }
    if (URL_ENCODED_SLASH_RE.test(name)) {                                      // allow:regex-no-length-cap — operator-supplied filename, length checked separately
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
  if (/^\\\\|^\/\//.test(name)) {
    issues.push({
      kind: "unc-path", severity: "critical",
      ruleId: "filename.unc",
      snippet: "UNC network path (\\\\server\\share)",
    });
  }

  // 5. Reserved characters — < > : " | ? * (slashes handled separately).
  if (opts.reservedCharPolicy !== "allow") {
    var resMatch = name.match(/[<>:"|?*]/);
    if (resMatch) {
      issues.push({
        kind: "reserved-char", severity: "high",
        ruleId: "filename.reserved-char",
        location: resMatch.index,
        snippet: "reserved character " + JSON.stringify(resMatch[0]) +
                 " (Windows file system)",
      });
    }
  }

  // 6. NTFS alternate data streams — `name:stream`.
  if (opts.adsPolicy !== "allow") {
    if (/:[^:\\/]+$/.test(name) && name.charAt(0) !== "/") {
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
    if (/^\s|\s$|\.$/.test(name)) {
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
  if (opts.homoglyphPolicy !== "allow" && /[A-Za-z]/.test(name)) {
    var hMatch = name.match(HOMOGLYPH_RE);
    if (hMatch) {
      issues.push({
        kind: "homoglyph", severity: opts.homoglyphPolicy === "reject" ? "critical" : "warn",
        ruleId: "filename.homoglyph",
        location: hMatch.index,
        snippet: "homoglyph U+" + hMatch[0].charCodeAt(0).toString(HEX_RADIX) +
                 " mixed with ASCII letters in filename",
      });
    }
  }

  // 11. ASCII-only requirement.
  if (opts.requireAscii) {
    var nonAscii = name.match(/[^\x20-\x7E]/);
    if (nonAscii) {
      issues.push({
        kind: "non-ascii", severity: "high",
        ruleId: "filename.non-ascii",
        location: nonAscii.index,
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
    var dotCount = (name.match(/\./g) || []).length;
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
    // allow:regex-no-length-cap — operator-supplied filename; sanitize caller threw on length above
    if (PATH_TRAVERSAL_RE.test(name) || PERCENT_ENCODED_TRAVERSAL_RE.test(name) ||
        name === "." || name === "..") {
      throw _err("filename.traversal", "filename contains path-traversal sequence");
    }
  }
  if (/^\\\\|^\/\//.test(name)) {
    throw _err("filename.unc", "UNC path syntax");
  }

  // Strip leading/trailing whitespace and trailing dots if policy says so.
  if (opts.leadingTrailingPolicy === "strip") {
    name = _stripLeadingTrailing(name);
  } else if (opts.leadingTrailingPolicy === "reject" &&
             /^\s|\s$|\.$/.test(name)) {
    throw _err("filename.leading-trailing",
      "filename has leading/trailing whitespace or trailing dot");
  }

  // Strip reserved chars when policy says strip.
  if (opts.reservedCharPolicy === "strip") {
    name = name.replace(RESERVED_CHARS_RE, "_");                            // allow:dynamic-regex — RESERVED_CHARS_RE is a compile-time literal
    name = name.replace(/[<>:"|?*]/g, "_");
  } else if (opts.reservedCharPolicy === "reject") {
    if (/[<>:"|?*]/.test(name)) {
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
  if (opts.adsPolicy === "reject" && /:[^:\\/]+$/.test(name)) {
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxComponents"],
    "guardFilename.validate", GuardFilenameError, "filename.bad-opt");

  var bad = gateContract.badInputResultIfNotStringOrBuffer(input);
  if (bad) return bad;
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw _err("filename.bad-input", "sanitize requires string or Buffer input");
  }
  return _sanitize(input, opts);
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardFilename:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      // Filename-shape ctx — operator passes filename via ctx.filename.
      var name = ctx && (ctx.filename || ctx.name || "");
      if (!name) return { ok: true, action: "serve" };
      var rv = validate(name, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) return { ok: true, action: "audit-only", issues: rv.issues };

      // Sanitize-eligibility — every reject-policy must be off.
      var canSanitize = opts.bidiPolicy !== "reject" &&
                        opts.controlPolicy !== "reject" &&
                        opts.nullBytePolicy !== "reject" &&
                        opts.traversalPolicy !== "reject" &&
                        opts.reservedCharPolicy !== "reject" &&
                        opts.reservedNamePolicy !== "reject" &&
                        opts.adsPolicy !== "reject" &&
                        opts.pathSeparatorsPolicy !== "reject" &&
                        opts.leadingTrailingPolicy !== "reject";
      if (canSanitize) {
        try {
          var clean = sanitize(name, opts);
          return {
            ok: true, action: "sanitize",
            sanitizedFilename: clean,
            issues: rv.issues,
          };
        } catch (_e) { /* fall through */ }
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "filename");
}

var _filenameRulePacks = gateContract.makeRulePackLoader(GuardFilenameError, "filename");
var loadRulePack = _filenameRulePacks.load;

module.exports = {
  // ---- guard-* family identity ----
  // Filename is a different axis from content-bytes (operators
  // typically apply both: guardFilename on the upload's name, plus
  // guardCsv / guardHtml / guardSvg / etc. on the body). guard-filename
  // is therefore a STANDALONE primitive — it does NOT register into
  // b.guardAll's content-type-routed dispatch (no canonical mime / ext
  // per the registry contract). Operators wire it directly via
  // b.fileUpload({ filenameSafety: gate }) and similar host opts.
  NAME:                "filename",
  KIND:                "filename",                                                // filename-string guard (consumes ctx.filename)
  INTEGRATION_FIXTURES: Object.freeze({
    kind:            "filename",
    benignFilename:  "report-2026-Q1.txt",
    // Hostile: path-traversal in filename (CWE-22 class).
    hostileFilename: "../etc/passwd",
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  WIN_RESERVED_NAMES:  WIN_RESERVED_NAMES,
  SHELL_EXEC_EXTS:     SHELL_EXEC_EXTS,
  GuardFilenameError:  GuardFilenameError,
};
