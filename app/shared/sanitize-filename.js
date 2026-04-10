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

module.exports = { safeContentDisposition };
