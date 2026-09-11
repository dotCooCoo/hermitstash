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

var WIN_RESERVED_BARE = ["con", "prn", "aux", "nul", "conin$", "conout$"];
var WIN_RESERVED_NUMBERED = ["com", "lpt"];
var SUPERSCRIPT_DIGITS = String.fromCharCode(0xB9, 0xB2, 0xB3);

var ENCODED_SEPARATORS = ["%2f", "%5c", "%c0%af", "%c1%9c"];
var SEPARATOR_LOOKALIKE_RANGES = [0xFF0F, 0xFF3C, 0x2215, 0x29F8, 0x2044];

var C0_EXCEPT_NUL_RANGES = [[0x0001, 0x001F], 0x007F];

var DRIVE_SEPARATORS = "\\/";

function _refuse(code, message) {
  throw new SafePathError(code, message);
}

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

function _hasDisguisedSeparator(rel) {
  for (var i = 0; i < ENCODED_SEPARATORS.length; i += 1) {
    if (codepointClass.containsFolded(rel, ENCODED_SEPARATORS[i])) return true;
  }
  return codepointClass.firstInRanges(rel, SEPARATOR_LOOKALIKE_RANGES) !== -1;
}

function _hasAbsolutePrefix(rel) {
  var cc = rel.charCodeAt(0);
  var isLetter = (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
  if (isLetter && rel.charAt(1) === ":" &&
      DRIVE_SEPARATORS.indexOf(rel.charAt(2)) !== -1) return true;
  var a = rel.charAt(0), b = rel.charAt(1);
  return (a === "\\" && b === "\\") || (a === "/" && b === "/");
}

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

  if (rel.indexOf("\0") !== -1) {
    _refuse("safe-path/null-byte", "b.safePath.resolve: NUL byte in rel");
  }
  if (codepointClass.firstInRanges(rel, C0_EXCEPT_NUL_RANGES) !== -1) {
    _refuse("safe-path/control-char", "b.safePath.resolve: C0 control char in rel");
  }
  if (codepointClass.firstInRanges(rel, codepointClass.BIDI_RANGES) !== -1) {
    _refuse("safe-path/bidi",
      "b.safePath.resolve: bidi-override codepoint in rel (CVE-2021-42574 class)");
  }
  if (_hasDisguisedSeparator(rel)) {
    _refuse("safe-path/separator-in-segment",
      "b.safePath.resolve: encoded path-separator codepoint in rel");
  }
  var isAbsolute = nodePath.isAbsolute(rel) || _hasAbsolutePrefix(rel);
  if (isAbsolute && !opts.allowAbsoluteRel) {
    _refuse("safe-path/absolute-rel",
      "b.safePath.resolve: rel is absolute/UNC/drive-letter (set opts.allowAbsoluteRel for opt-in)");
  }

  var segments = _splitSegments(rel, isWin);
  for (var si = 0; si < segments.length; si += 1) {
    var seg = segments[si];
    if (seg.length === 0) continue;
    if (seg === "." || seg === "..") continue;
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
    if (seg.indexOf(":") !== -1) {
      _refuse("safe-path/ads-marker",
        "b.safePath.resolve: segment '" + seg + "' contains ':' (NTFS Alternate Data Stream marker; CVE-2024-12217 class)");
    }
  }

  var pathMod = isWin ? nodePath.win32 : nodePath.posix;
  var baseResolved = pathMod.resolve(base);
  var joined = confineToBase(base, rel, { platform: platform });
  if (joined === null) {
    _refuse("safe-path/escapes-base",
      "b.safePath.resolve: rel resolves outside base ('" +
      pathMod.resolve(baseResolved, rel) + "' not inside '" + baseResolved + "')");
  }
  if (opts.realpath === true) {
    var rtBaseResolved = nodePath.resolve(base);
    var rtJoined = nodePath.resolve(rtBaseResolved, rel);
    var rtSep = nodePath.sep;
    var baseRealpath;
    try { baseRealpath = nodeFs.realpathSync.native(rtBaseResolved); }
    catch (e) {
      _refuse("safe-path/realpath-base-unresolvable",
        "b.safePath.resolve: opts.realpath set but base realpath failed: " + (e && e.message));
    }
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
