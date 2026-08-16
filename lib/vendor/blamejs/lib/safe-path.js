// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.safePath
 * @nav    Filesystem
 * @title  Safe Path
 *
 * @intro
 *   Path-traversal-safe multi-segment resolve. Operators consuming
 *   operator-OR-user-supplied path segments (uploaded filenames,
 *   tarball entries, archive extraction, dynamic include paths) pass
 *   `base + rel` to `b.safePath.resolve` and get back the absolute
 *   canonicalized path — guaranteed to lie strictly within `base` —
 *   or a typed `SafePathError` with a stable `code` on refusal.
 *
 *   Refusal classes (each a documented code, never best-effort):
 *
 *     - `safe-path/absolute-rel`           — rel is absolute, UNC, or carries a drive letter
 *     - `safe-path/escapes-base`           — `..` segments escape base after lexical resolve
 *     - `safe-path/null-byte`              — NUL anywhere (closes Node poison-NUL class)
 *     - `safe-path/control-char`           — C0 control char other than NUL
 *     - `safe-path/bidi`                   — bidi-override codepoint (CVE-2021-42574 Trojan Source)
 *     - `safe-path/win-reserved`           — Windows reserved name (CON/PRN/AUX/NUL/COM0-9/LPT0-9)
 *                                            on EVERY platform — closes CVE-2025-27210 cross-mount class
 *     - `safe-path/win-trailing`           — segment ends with `.` or ` ` under windows-mode resolve
 *     - `safe-path/separator-in-segment`   — encoded path-separator in a segment (URL / fullwidth /
 *                                            overlong UTF-8 / division-slash)
 *     - `safe-path/ads-marker`             — NTFS Alternate Data Stream `foo:bar` marker
 *     - `safe-path/realpath-escapes-base`  — symlink resolution escapes base (opt-in via opts.realpath)
 *
 *   Per-segment filename validation composes `b.guardFilename`'s
 *   reserved-name + overlong UTF-8 + bidi tables; the multi-segment
 *   resolve + base-escape check is the new code.
 *
 * @card
 *   Traversal-safe multi-segment path resolve. Every documented failure mode → coded refusal. Composes b.guardFilename.
 */

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var codepointClass = require("./codepoint-class");
var { defineClass } = require("./framework-error");

var SafePathError = defineClass("SafePathError", { alwaysPermanent: true });

// Windows reserved device names — CON, PRN, AUX, NUL, COM0-COM9,
// LPT0-LPT9, CONIN$, CONOUT$. Enforced on EVERY platform to defend
// the cross-mount case where a POSIX server writes a path that a
// Windows operator later mounts (closes CVE-2025-27210 class).
var WIN_RESERVED_BARE = ["con", "prn", "aux", "nul", "conin$", "conout$"];
var WIN_RESERVED_NUMBERED = ["com", "lpt"];
// Windows folds the superscript digits to 1 / 2 / 3 when it resolves a device
// name, so `com` followed by one of them names the same device.
var SUPERSCRIPT_DIGITS = String.fromCharCode(0xB9, 0xB2, 0xB3);

// Path separators outside the platform-native set — every one of them has to
// be refused as a segment-internal character. Both the percent-encoded
// spellings and the Unicode look-alikes: fullwidth solidus and reverse
// solidus, division slash, big solidus, fraction slash.
var ENCODED_SEPARATORS = ["%2f", "%5c", "%c0%af", "%c1%9c"];
var SEPARATOR_LOOKALIKE_RANGES = [0xFF0F, 0xFF3C, 0x2215, 0x29F8, 0x2044];

// C0 controls and DEL, minus NUL — that one has its own refusal so the error
// code matches the historical poison-NUL class.
var C0_EXCEPT_NUL_RANGES = [[0x0001, 0x001F], 0x007F];

// The characters Windows itself refuses in a path, checked here so a name a
// POSIX server accepts cannot become a different name on a Windows mount.
var DRIVE_SEPARATORS = "\\/";

function _refuse(code, message) {
  throw new SafePathError(code, message);
}

// Is this segment a Windows device name — bare, numbered, or with an
// extension after it? `com1.txt` resolves to the device just as `com1` does.
function _isWinReserved(seg) {
  var lower = seg.toLowerCase();
  var dot = lower.indexOf(".");
  var stem = dot === -1 ? lower : lower.slice(0, dot);
  if (WIN_RESERVED_BARE.indexOf(stem) !== -1) return true;
  for (var i = 0; i < WIN_RESERVED_NUMBERED.length; i += 1) {
    var prefix = WIN_RESERVED_NUMBERED[i];
    if (stem.length !== prefix.length + 1) continue;
    if (stem.slice(0, prefix.length) !== prefix) continue;
    var tail = stem.charAt(prefix.length);
    if ((tail >= "0" && tail <= "9") || SUPERSCRIPT_DIGITS.indexOf(tail) !== -1) {
      return true;
    }
  }
  return false;
}

// A separator spelled some way other than the platform's own: a
// percent-encoded form, or a Unicode character that renders as a slash.
function _hasDisguisedSeparator(rel) {
  for (var i = 0; i < ENCODED_SEPARATORS.length; i += 1) {
    if (codepointClass.containsFolded(rel, ENCODED_SEPARATORS[i])) return true;
  }
  return codepointClass.firstInRanges(rel, SEPARATOR_LOOKALIKE_RANGES) !== -1;
}

// A Windows drive prefix (`C:\`), a UNC prefix (`\\`), or a POSIX
// protocol-relative one (`//`).
function _hasAbsolutePrefix(rel) {
  var cc = rel.charCodeAt(0);
  var isLetter = (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
  if (isLetter && rel.charAt(1) === ":" &&
      DRIVE_SEPARATORS.indexOf(rel.charAt(2)) !== -1) return true;
  var a = rel.charAt(0), b = rel.charAt(1);
  return (a === "\\" && b === "\\") || (a === "/" && b === "/");
}

// Split on the target platform's separators. Windows accepts both.
function _splitSegments(rel, isWin) {
  return isWin ? rel.split("\\").join("/").split("/") : rel.split("/");
}

/**
 * @primitive b.safePath.resolve
 * @signature b.safePath.resolve(base, rel, opts?)
 * @since     0.10.9
 * @status    stable
 * @related   b.safePath.validate, b.guardFilename.validate, b.atomicFile.write
 *
 * Resolve `rel` against `base` and return the absolute canonicalized
 * path — guaranteed to lie strictly within `base`. Throws
 * `SafePathError` with a stable refusal code on any rejection.
 *
 * @opts
 *   realpath:         boolean,         // default false; true → fs.realpathSync check (symlink-escape)
 *   platform:         string,          // "windows" forces win-trailing / UNC refusal regardless of host
 *   allowAbsoluteRel: boolean,         // default false; opt-in for absolute rel that still resolves inside base
 *
 * @example
 *   var p = b.safePath.resolve("/srv/uploads", req.body.path);
 *   // → "/srv/uploads/<safe-rel>"  OR  throws SafePathError on traversal
 */
function resolve(base, rel, opts) {
  return _resolveCore(base, rel, opts || {});
}

/**
 * @primitive b.safePath.resolveOrNull
 * @signature b.safePath.resolveOrNull(base, rel, opts?)
 * @since     0.10.9
 * @status    stable
 * @related   b.safePath.resolve, b.safePath.validate
 *
 * Same contract as `resolve` but returns `null` on refusal instead of
 * throwing. Useful for hot-path callers that want a boolean-ish gate
 * without try/catch overhead.
 *
 * @opts
 *   realpath:         boolean,
 *   platform:         string,
 *   allowAbsoluteRel: boolean,
 *
 * @example
 *   var p = b.safePath.resolveOrNull("/srv/uploads", req.body.path);
 *   if (p === null) { res.statusCode = 400; res.end("bad path"); return; }
 */
function resolveOrNull(base, rel, opts) {
  try { return _resolveCore(base, rel, opts || {}); }
  catch (_e) { return null; }
}

/**
 * @primitive b.safePath.validate
 * @signature b.safePath.validate(base, rel, opts?)
 * @since     0.10.9
 * @status    stable
 * @related   b.safePath.resolve
 *
 * Same gate as `resolve` but returns a verdict object instead of
 * throwing — `{ ok: true, resolved }` on success, `{ ok: false,
 * code, message }` on refusal. Use when the caller wants to log the
 * refusal class without throw/catch.
 *
 * @opts
 *   realpath:         boolean,
 *   platform:         string,
 *   allowAbsoluteRel: boolean,
 *
 * @example
 *   var v = b.safePath.validate("/srv/uploads", req.body.path);
 *   if (!v.ok) { res.end("rejected: " + v.code); return; }
 */
function validate(base, rel, opts) {
  try { return { ok: true, resolved: _resolveCore(base, rel, opts || {}) }; }
  catch (e) { return { ok: false, code: e.code || "safe-path/unknown", message: e.message }; }
}

/**
 * @primitive b.safePath.confineToBase
 * @signature b.safePath.confineToBase(base, rel, opts?)
 * @since     0.17.16
 * @status    stable
 * @related   b.safePath.resolve, b.staticServe.create
 *
 * The lexical traversal-containment core, WITHOUT the user-input
 * strictness of `resolve` (no reserved-name / ADS / bidi / control-char
 * refusal). Resolve `rel` against `base` using the TARGET platform's path
 * semantics and confirm the result stays strictly inside `base`; return
 * the confined absolute path, or `null` if it escapes.
 *
 * This is the barrier `resolve` layers its user-input checks on top of,
 * and the one a consumer composes when it wants ONLY traversal containment
 * and runs its OWN, separately-calibrated filename validation — as
 * b.staticServe does, keeping its per-file basename gate (b.guardFilename)
 * a distinct step rather than fusing `resolve`'s all-segment user-input
 * strictness into the containment barrier.
 *
 * @opts
 *   platform: string,   // "windows" forces win32 path semantics regardless of host
 *
 * @example
 *   var p = b.safePath.confineToBase("/srv/www", "docs/a.html");
 *   // → "/srv/www/docs/a.html"  (null if rel escaped /srv/www)
 */
function confineToBase(base, rel, opts) {
  opts = opts || {};
  if (typeof base !== "string" || base.length === 0) return null;
  if (typeof rel !== "string") return null;
  var platform = opts.platform || process.platform;
  var isWin = platform === "win32" || platform === "windows";
  // Resolve + contain using the TARGET platform's path module, NOT the
  // runtime's: the runtime path module would treat the OTHER platform's
  // separator as an ordinary filename character and miss a backslash
  // traversal on a POSIX host (and inversely false-refuse legitimate paths).
  var pathMod = isWin ? nodePath.win32 : nodePath.posix;
  var baseResolved = pathMod.resolve(base);
  var joined = pathMod.resolve(baseResolved, rel);
  var sepChar = pathMod.sep;
  if (joined !== baseResolved && joined.slice(0, baseResolved.length + 1) !== baseResolved + sepChar) {
    return null;
  }
  return joined;
}

function _resolveCore(base, rel, opts) {
  if (typeof base !== "string" || base.length === 0) {
    _refuse("safe-path/bad-input", "b.safePath.resolve: base must be a non-empty string");
  }
  if (typeof rel !== "string") {
    _refuse("safe-path/bad-input", "b.safePath.resolve: rel must be a string");
  }
  var platform = opts.platform || process.platform;
  var isWin = platform === "win32" || platform === "windows";

  // NUL byte ANYWHERE — its own refusal so the audit code matches
  // the historical Node poison-NUL class.
  if (rel.indexOf("\0") !== -1) {
    _refuse("safe-path/null-byte", "b.safePath.resolve: NUL byte in rel");
  }
  // Other C0 + DEL.
  if (codepointClass.firstInRanges(rel, C0_EXCEPT_NUL_RANGES) !== -1) {
    _refuse("safe-path/control-char", "b.safePath.resolve: C0 control char in rel");
  }
  // Bidi override (Trojan Source). The shared table, so this refuses the same
  // set every other primitive does — the local copy this replaced was missing
  // the Arabic letter mark (U+061C).
  if (codepointClass.firstInRanges(rel, codepointClass.BIDI_RANGES) !== -1) {
    _refuse("safe-path/bidi",
      "b.safePath.resolve: bidi-override codepoint in rel (CVE-2021-42574 class)");
  }
  // Encoded path separators inside what should be a single segment.
  if (_hasDisguisedSeparator(rel)) {
    _refuse("safe-path/separator-in-segment",
      "b.safePath.resolve: encoded path-separator codepoint in rel");
  }
  // Absolute rel (POSIX, Windows drive-letter, UNC) — refuse unless
  // operator opted in.
  var isAbsolute = nodePath.isAbsolute(rel) || _hasAbsolutePrefix(rel);
  if (isAbsolute && !opts.allowAbsoluteRel) {
    _refuse("safe-path/absolute-rel",
      "b.safePath.resolve: rel is absolute/UNC/drive-letter (set opts.allowAbsoluteRel for opt-in)");
  }

  // Per-segment walk. Reserved-name + ADS + win-trailing + segment-
  // shape checks happen here.
  var segments = _splitSegments(rel, isWin);
  for (var si = 0; si < segments.length; si += 1) {
    var seg = segments[si];
    if (seg.length === 0) continue;            // empty (leading/trailing/double-sep)
    if (seg === "." || seg === "..") continue; // resolution handled below
    if (_isWinReserved(seg)) {
      _refuse("safe-path/win-reserved",
        "b.safePath.resolve: segment '" + seg + "' is a Windows reserved name (CVE-2025-27210 class)");
    }
    if (isWin) {
      var last = seg.charAt(seg.length - 1);
      if (last === "." || last === " ") {
        _refuse("safe-path/win-trailing",
          "b.safePath.resolve: segment '" + seg + "' ends with '.' or ' ' (Windows silently strips)");
      }
    }
    // NTFS Alternate Data Stream marker — refuse `foo:bar` ANYWHERE
    // except where the colon is part of a Windows drive prefix (the
    // absolute-rel branch above already refused those).
    if (seg.indexOf(":") !== -1) {
      _refuse("safe-path/ads-marker",
        "b.safePath.resolve: segment '" + seg + "' contains ':' (NTFS Alternate Data Stream marker; CVE-2024-12217 class)");
    }
  }

  // Lexical resolve + containment using the TARGET platform's path semantics
  // (nodePath.win32 / nodePath.posix), NOT the runtime's. The runtime nodePath
  // would treat the OTHER platform's separator as an ordinary filename
  // character — so a Windows-target validation on a POSIX host would NOT collapse
  // `ok\..\..\outside` and would wrongly accept a path that escapes the base
  // when later interpreted with Windows path rules (the cross-platform
  // backslash-traversal hole). The target module collapses the target's
  // separators + `..` and its sep matches the resolved output, which both closes
  // that hole AND stops the inverse false-refusal of legitimate in-base paths.
  var pathMod = isWin ? nodePath.win32 : nodePath.posix;
  var baseResolved = pathMod.resolve(base);
  var joined = confineToBase(base, rel, { platform: platform });
  if (joined === null) {
    _refuse("safe-path/escapes-base",
      "b.safePath.resolve: rel resolves outside base ('" +
      pathMod.resolve(baseResolved, rel) + "' not inside '" + baseResolved + "')");
  }
  if (opts.realpath === true) {
    // realpath resolves symlinks on the RUNTIME filesystem, so it must use the
    // runtime path module and runtime-resolved paths (a foreign-platform path
    // can't be symlink-resolved on this host). The lexical check above already
    // refused a cross-platform escape; this adds the on-disk symlink check.
    var rtBaseResolved = nodePath.resolve(base);
    var rtJoined = nodePath.resolve(rtBaseResolved, rel);
    var rtSep = nodePath.sep;
    var baseRealpath;
    try { baseRealpath = nodeFs.realpathSync.native(rtBaseResolved); }
    catch (e) {
      _refuse("safe-path/realpath-base-unresolvable",
        "b.safePath.resolve: opts.realpath set but base realpath failed: " + (e && e.message));
    }
    // Walk up the joined path from the leaf, finding the longest
    // ancestor that exists, and check its realpath. Operators want
    // refusal when ANY ancestor symlink escapes — nodeFs.realpathSync on a
    // non-existent path would throw.
    var ancestor = rtJoined;
    while (ancestor.length > rtBaseResolved.length) {
      try {
        var ancRealpath = nodeFs.realpathSync.native(ancestor);
        if (ancRealpath !== baseRealpath &&
            ancRealpath.slice(0, baseRealpath.length + 1) !== baseRealpath + rtSep) {
          _refuse("safe-path/realpath-escapes-base",
            "b.safePath.resolve: symlink resolution at '" + ancestor +
            "' escapes base realpath '" + baseRealpath + "'");
        }
        break;
      } catch (_ie) {
        ancestor = nodePath.dirname(ancestor);
      }
    }
  }
  return joined;
}

module.exports = {
  resolve:        resolve,
  resolveOrNull:  resolveOrNull,
  validate:       validate,
  confineToBase:  confineToBase,
  SafePathError:  SafePathError,
};
