var b = require("../../lib/vendor/blamejs");

/**
 * Sanitize filename for Content-Disposition headers.
 * Prevents header injection and handles non-ASCII via RFC 5987 encoding.
 */
function safeContentDisposition(filename, type) {
  type = type || "attachment";
  // ASCII-safe fallback: strip dangerous characters
  var safe = String(filename || "download")
    .replace(/["\\\r\n]/g, "_")
    .replace(/[^\x20-\x7E]/g, "_");
  // RFC 5987 encoded version for non-ASCII support
  var encoded = encodeURIComponent(filename || "download");
  return type + '; filename="' + safe + '"; filename*=UTF-8\'\'' + encoded;
}

/**
 * Sanitize a user-provided rename value.
 * Strips control chars, HTML, path traversal, dot attacks.
 * Optionally preserves the original file extension.
 *
 * @param {string} input - raw user input
 * @param {object} [opts] - options
 * @param {string} [opts.originalName] - original filename to preserve extension from
 * @param {number} [opts.maxLength] - max length (default 255)
 * @returns {{ valid: boolean, name: string, error?: string }}
 */
function sanitizeRename(input, opts) {
  opts = opts || {};
  var max = opts.maxLength || 255;
  var name = String(input || "")
    .replace(/[\x00-\x1f\x7f]/g, "")     // strip control characters
    .replace(/[<>"'`]/g, "")              // strip HTML/XSS characters
    .replace(/\s*\.\s*/g, ".")       // collapse whitespace around dots
    .replace(/\.{2,}/g, ".")
    .replace(/[\\\/]/g, "_")             // replace path separators
    .replace(/^[\s.]+/, "")              // strip leading dots/whitespace
    .replace(/\.+$/, "")                 // strip trailing dots
    .trim().slice(0, max);

  if (!name) return { valid: false, name: "", error: "Name required." };

  // Preserve original extension if user dropped it
  if (opts.originalName) {
    var parts = opts.originalName.split(".");
    var origExt = parts.length > 1 ? parts.pop() : null;
    if (origExt) {
      var hasExt = name.lastIndexOf(".") > 0 && name.split(".").pop().length <= 10;
      if (!hasExt) name = name + "." + origExt;
    }
  }

  return { valid: true, name: name };
}

// Permissive filename-sanitiser policy for b.guardFilename. HermitStash
// accepts ANY filename (unicode, long names, multi-dot archives, executables,
// reserved names) — originalName is display metadata, never a disk path
// (storage uses generated ids) — so the strict allowlist policies are relaxed
// to "allow". The byte-level threats that DO matter for a displayed filename
// are neutralised, not rejected: bidi overrides (CVE-2021-42574 "Trojan
// Source"), zero-width characters, and NUL bytes are stripped. Unicode is
// left un-normalised (unicodeNormalization "none") so stored bytes are exact,
// matching the prior helper — NFC-folding would desync replace-detection for
// names already stored in decomposed form. maxComponents is 1 because we
// split the path ourselves and guard each segment.
var FNAME_OPTS = {
  bidiPolicy: "strip", controlPolicy: "strip", nullBytePolicy: "strip", zeroWidthPolicy: "strip",
  homoglyphPolicy: "allow", reservedCharPolicy: "allow", reservedNamePolicy: "allow",
  adsPolicy: "allow", leadingTrailingPolicy: "allow", shellExecExtPolicy: "allow",
  traversalPolicy: "allow", pathSeparatorsPolicy: "allow",
  requireAscii: false, requireSingleDot: false, unicodeNormalization: "none",
  maxBytes: 65536, maxComponents: 1,
};
// b.guardFilename's control strip keeps TAB/CR/LF (it treats them as dialect
// characters) and does not reach DEL; the prior helper stripped the whole
// C0 + DEL range, so strip the remainder here. < > " ' ` are stripped too so
// a stored name is safe to render in HTML.
var RESIDUAL_RE = /[\x09\x0a\x0d\x7f<>"'`]/g;

function cleanSegment(seg) {
  if (!seg) return "";
  var safe;
  try { safe = b.guardFilename.sanitize(seg, FNAME_OPTS); }
  catch (_e) { return ""; }   // defensive: the permissive policy should not throw
  safe = safe.replace(RESIDUAL_RE, "");
  // Drop "." / ".." AFTER stripping, so an obfuscated ".." + zero-width / bidi /
  // NUL that reduces to ".." can never survive as a traversal segment.
  if (safe === "." || safe === "..") return "";
  return safe;
}

/**
 * Sanitize a filename or relative path for safe storage and display.
 * Splits on path separators, drops empty / "." / ".." segments (traversal
 * defence), neutralises spoofing/injection bytes per segment via
 * b.guardFilename, and rejoins with "/". Used at upload time for
 * originalName and relativePath.
 */
function sanitizeFilename(input, maxLength) {
  return String(input || "")
    .split(/[/\\]+/)
    .map(cleanSegment)
    .filter(Boolean)
    .join("/")
    .trim()
    .slice(0, maxLength || 255);
}

module.exports = { safeContentDisposition, sanitizeRename, sanitizeFilename };
