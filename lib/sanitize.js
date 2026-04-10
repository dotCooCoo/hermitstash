/**
 * Sanitize a filename for use in Content-Disposition headers.
 * Removes CRLF, quotes, backslashes, and null bytes.
 */
function safeFilename(name) {
  return String(name || "download")
    .replace(/[\r\n\0]/g, "")
    .replace(/["\\/]/g, "_");
}

/**
 * Escape HTML special characters for safe embedding.
 */
function escHtml(s) {
  if (!s) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

module.exports = { safeFilename, escHtml };
