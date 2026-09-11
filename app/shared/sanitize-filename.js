var b = require("../../lib/vendor/blamejs");

/**
 * Sanitize filename for Content-Disposition headers.
 * Prevents header injection and handles non-ASCII via RFC 8187 encoding
 * (the ext-value syntax; RFC 5987 defined it and is obsoleted by RFC 8187).
 */
function safeContentDisposition(filename, type) {
  type = type || "attachment";
  // ASCII-safe fallback: strip dangerous characters
  var safe = String(filename || "download")
    .replace(/["\\\r\n]/g, "_")
    .replace(/[^\x20-\x7E]/g, "_");
  // RFC 8187 encoded version for non-ASCII support
  var encoded = encodeURIComponent(filename || "download");
  return type + '; filename="' + safe + '"; filename*=UTF-8\'\'' + encoded;
}

// Ceiling on the RAW rename value, before sanitizing. Four times the longest
// name sanitizeRename will return, which leaves room for characters the chain
// strips while keeping the scan cheap.
var RENAME_INPUT_MAX = 1024;

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
  var raw = String(input || "");
  // The replace chain below runs over the whole subject and only caps length at
  // the end. `/\s*\.\s*/g` costs O(n^2) on a long run of whitespace, because the
  // engine matches the leading \s* at every position and then fails to find the
  // dot: measured at 3.3s for 100,000 spaces and 57s for 400,000, which blocks
  // the event loop for every other request. `body.name` reaches here unbounded
  // from the rename routes.
  //
  // Refused rather than truncated. Truncating would let the first RENAME_INPUT_MAX
  // characters stand in for a name the caller did not send, and a sanitized name
  // is at most `max` characters anyway, so an input orders of magnitude larger is
  // not a rename.
  if (raw.length > RENAME_INPUT_MAX) {
    return { valid: false, name: "", error: "Name too long." };
  }
  var name = raw
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
// Source") and zero-width characters are stripped. Unicode is left
// un-normalised (unicodeNormalization "none") so stored bytes are exact,
// matching the prior helper — NFC-folding would desync replace-detection for
// names already stored in decomposed form. maxComponents is 1 because we
// split the path ourselves and guard each segment.
//
// A NUL byte and a traversal segment are absent from this block on purpose.
// Both are fixed at reject in the guard and are not configurable, because
// neither has a safe repair: the name a check reads and the name the operating
// system acts on diverge at a NUL, so a stripped name is one nobody validated.
// A refused segment is dropped by cleanSegment below, which is the same outcome
// "." and ".." already get.
var FNAME_OPTS = {
  bidiPolicy: "strip", controlPolicy: "strip", zeroWidthPolicy: "strip",
  homoglyphPolicy: "allow", reservedCharPolicy: "allow", reservedNamePolicy: "allow",
  adsPolicy: "allow", leadingTrailingPolicy: "allow", shellExecExtPolicy: "allow",
  pathSeparatorsPolicy: "allow",
  requireAscii: false, requireSingleDot: false, unicodeNormalization: "none",
  maxBytes: 65536, maxComponents: 1,
};

// Resolve FNAME_OPTS once, here, against a name carrying nothing the guard
// objects to. b.guardFilename validates its option VALUES where the options are
// resolved, so a policy this version of the framework does not accept throws on
// the call rather than at startup, and cleanSegment's catch cannot tell that
// apart from a refused filename: it would return "" for every segment and empty
// every name with nothing logged. Probing at load turns that into a boot
// failure naming the option.
b.guardFilename.sanitize("probe.txt", FNAME_OPTS);
// b.guardFilename's control strip keeps TAB/CR/LF — it treats them as dialect
// characters — so those are stripped here to keep parity with the prior
// helper, which removed the whole C0 range. DEL is no longer in this class:
// the primitive's control table covers it, so listing it here would leave two
// declarations of the same rule to drift apart. < > " ' ` are stripped so a
// stored name is safe to render in HTML.
var RESIDUAL_RE = /[\x09\x0a\x0d<>"'`]/g;

// Returned by cleanSegment when the guard refused the segment for a reason that
// is not traversal. It invalidates the WHOLE path rather than the component,
// because dropping one component silently rewrites the path to a DIFFERENT
// valid one: "docs/<refused>/report.pdf" would become "docs/report.pdf", and a
// sync bundle looks an existing file up by that path and replaces it. A refusal
// must not be able to land on a path the caller did not send.
//
// Traversal is the exception, and only because dropping "." and ".." IS the
// normalisation — that is what the split-and-drop below has always done.
var PATH_REFUSED = null;

function cleanSegment(seg) {
  if (!seg) return "";
  var safe;
  try {
    safe = b.guardFilename.sanitize(seg, FNAME_OPTS);
  } catch (e) {
    if (e && e.code === "filename.traversal") return "";
    return PATH_REFUSED;
  }
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
 *
 * Returns "" when the guard refuses any segment for a reason other than
 * traversal — the whole path is unusable, not just that component. Callers
 * already treat "" as no usable name; it is what ".", ".." and "/" produce.
 */
function sanitizeFilename(input, maxLength) {
  var segments = String(input || "").split(/[/\\]+/).map(cleanSegment);
  if (segments.indexOf(PATH_REFUSED) !== -1) return "";
  return segments
    .filter(Boolean)
    .join("/")
    .trim()
    .slice(0, maxLength || 255);
}

module.exports = { safeContentDisposition, sanitizeRename, sanitizeFilename };
