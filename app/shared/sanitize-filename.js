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
    .replace(/(\s*\.){2,}/g, ".")         // collapse dot chains (". . ." → ".")
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

/**
 * Sanitize a filename for safe storage and display.
 * Strips control chars, HTML characters, null bytes.
 * Used at upload time for originalName and relativePath.
 */
function sanitizeFilename(input, maxLength) {
  return String(input || "")
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[<>"'`]/g, "")
    .split(/[/\\]+/).filter(function (s) { return s && s !== "." && s !== ".."; }).join("/")
    .trim()
    .slice(0, maxLength || 255);
}

module.exports = { safeContentDisposition, sanitizeRename, sanitizeFilename };
