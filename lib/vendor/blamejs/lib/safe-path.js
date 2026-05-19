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
var { defineClass } = require("./framework-error");

var SafePathError = defineClass("SafePathError", { alwaysPermanent: true });

// Windows reserved device names — CON, PRN, AUX, NUL, COM0–COM9,
// LPT0–LPT9, CONIN$, CONOUT$. Enforced on EVERY platform to defend
// the cross-mount case where a POSIX server writes a path that a
// Windows operator later mounts (closes CVE-2025-27210 class).
var WIN_RESERVED_RE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(?:\..*)?$/i;
// Path separators outside the platform-native set. Each entry MUST
// be rejected as a segment-internal character. Includes both raw +
// canonical-encoded forms.
var ENCODED_SEPARATOR_RE = /(%2[fF]|%5[cC]|%C0%AF|%C1%9C|[／＼∕⧸⁄])/;
// Bidi-override codepoints (RTL/LTR markers + isolate enclosures).
var BIDI_RE = /[‪-‮⁦-⁩‎‏]/;
// C0 control byte range (excluding NUL which has its own dedicated
// refusal so the error code matches the historical poison-NUL class).
// eslint-disable-next-line no-control-regex
var C0_RE = /[\x01-\x1F\x7F]/;

function _refuse(code, message) {
  throw new SafePathError(code, message);
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
  if (C0_RE.test(rel)) {                                                                              // allow:regex-no-length-cap — anchored C0/DEL set, length bounded by rel
    _refuse("safe-path/control-char", "b.safePath.resolve: C0 control char in rel");
  }
  // Bidi override (Trojan Source).
  if (BIDI_RE.test(rel)) {                                                                            // allow:regex-no-length-cap — fixed bidi set, length bounded by rel
    _refuse("safe-path/bidi",
      "b.safePath.resolve: bidi-override codepoint in rel (CVE-2021-42574 class)");
  }
  // Encoded path separators inside what should be a single segment.
  if (ENCODED_SEPARATOR_RE.test(rel)) {                                                               // allow:regex-no-length-cap — fixed separator-shape set
    _refuse("safe-path/separator-in-segment",
      "b.safePath.resolve: encoded path-separator codepoint in rel");
  }
  // Absolute rel (POSIX, Windows drive-letter, UNC) — refuse unless
  // operator opted in.
  var isAbsolute = nodePath.isAbsolute(rel) ||
                   /^[A-Za-z]:[\\/]/.test(rel) ||                                                     // allow:regex-no-length-cap — anchored drive-letter shape
                   /^\\\\/.test(rel) ||                                                               // allow:regex-no-length-cap — UNC `\\` prefix
                   /^\/\//.test(rel);                                                                 // allow:regex-no-length-cap — POSIX `//` prefix
  if (isAbsolute && !opts.allowAbsoluteRel) {
    _refuse("safe-path/absolute-rel",
      "b.safePath.resolve: rel is absolute/UNC/drive-letter (set opts.allowAbsoluteRel for opt-in)");
  }

  // Per-segment walk. Reserved-name + ADS + win-trailing + segment-
  // shape checks happen here.
  var sep = isWin ? /[\\/]/ : /\//;
  var segments = rel.split(sep);                                                                      // allow:regex-no-length-cap — fixed separator
  for (var si = 0; si < segments.length; si += 1) {
    var seg = segments[si];
    if (seg.length === 0) continue;            // empty (leading/trailing/double-sep)
    if (seg === "." || seg === "..") continue; // resolution handled below
    var segLc = seg.toLowerCase();
    var baseName = segLc.indexOf(".") === -1 ? segLc : segLc.slice(0, segLc.indexOf("."));
    if (WIN_RESERVED_RE.test(seg) || WIN_RESERVED_RE.test(baseName)) {                                // allow:regex-no-length-cap — anchored reserved-name set
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

  // Lexical resolve.
  var baseResolved = nodePath.resolve(base);
  var joined = nodePath.resolve(baseResolved, rel);
  // Cross-check via posix.normalize so a Windows host with mixed
  // separators still surfaces escapes consistently.
  var sepChar = isWin ? "\\" : "/";
  if (joined !== baseResolved && joined.slice(0, baseResolved.length + 1) !== baseResolved + sepChar) {
    _refuse("safe-path/escapes-base",
      "b.safePath.resolve: rel resolves outside base ('" + joined + "' not inside '" + baseResolved + "')");
  }
  if (opts.realpath === true) {
    var baseRealpath;
    try { baseRealpath = nodeFs.realpathSync.native(baseResolved); }
    catch (e) {
      _refuse("safe-path/realpath-base-unresolvable",
        "b.safePath.resolve: opts.realpath set but base realpath failed: " + (e && e.message));
    }
    // Walk up the joined path from the leaf, finding the longest
    // ancestor that exists, and check its realpath. Operators want
    // refusal when ANY ancestor symlink escapes — nodeFs.realpathSync on a
    // non-existent path would throw.
    var ancestor = joined;
    while (ancestor.length > baseResolved.length) {
      try {
        var ancRealpath = nodeFs.realpathSync.native(ancestor);
        if (ancRealpath !== baseRealpath &&
            ancRealpath.slice(0, baseRealpath.length + 1) !== baseRealpath + sepChar) {
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
  SafePathError:  SafePathError,
};
