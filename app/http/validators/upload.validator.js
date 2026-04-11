/**
 * Upload request validators — shared validation for regular and chunked uploads.
 * Ensures consistent size/count/type enforcement across all upload paths.
 */
var path = require("path");

/**
 * Validate a file against allowed extensions, max size, and empty check.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateFile(filename, fileSize, allowedExtensions, maxFileSize) {
  if (!filename) return { valid: false, reason: "Missing filename." };
  if (fileSize === 0) return { valid: false, reason: "Empty file." };
  if (maxFileSize && fileSize > maxFileSize) return { valid: false, reason: "File too large." };

  var ext = path.extname(filename).toLowerCase();
  if (!ext) return { valid: false, reason: "No file extension." };
  if (allowedExtensions && allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
    return { valid: false, reason: "File type not allowed: " + ext };
  }

  return { valid: true };
}

/**
 * Validate chunk upload parameters.
 */
function validateChunk(chunkIndex, totalChunks, fileId) {
  if (chunkIndex === undefined || chunkIndex === null) return { valid: false, reason: "Missing chunk index." };
  if (!totalChunks || totalChunks <= 0) return { valid: false, reason: "Invalid total chunks." };
  if (totalChunks > 10000) return { valid: false, reason: "Too many chunks." };
  if (chunkIndex < 0 || chunkIndex >= totalChunks) return { valid: false, reason: "Chunk index out of range." };
  if (!fileId || !/^[a-zA-Z0-9]+$/.test(fileId)) return { valid: false, reason: "Invalid file ID." };
  return { valid: true };
}

/**
 * Validate bundle limits (file count, total size).
 */
function validateBundleLimits(fileCount, maxFiles, totalSize, maxBundleSize) {
  if (maxFiles && fileCount > maxFiles) return { valid: false, reason: "Too many files (max " + maxFiles + ")." };
  if (maxBundleSize && totalSize > maxBundleSize) return { valid: false, reason: "Bundle too large." };
  return { valid: true };
}

// ---- Magic byte content validation ----

// Extensions that map to the same detected type
var COMPAT = {
  ".jpeg": ".jpg",
  ".docx": ".zip", ".xlsx": ".zip", ".pptx": ".zip",  // OOXML = ZIP containers
  ".xls": ".ole2", ".ppt": ".ole2", ".doc": ".ole2",   // legacy Office = OLE2
  ".tar.gz": ".gz",
};

// Extensions that have known magic signatures and SHOULD be validated
var RISKY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff",
  ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar.gz", ".bz2",
  ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".svg",
]);

/**
 * Detect actual content type from file buffer (first 512 bytes).
 * Returns extension string (".png", ".jpg", etc.) or null if unrecognized.
 */
function detectContentType(buf) {
  if (!buf || buf.length < 4) return null;
  var b = buf;
  // Images
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return ".png";
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return ".jpg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return ".gif";
  if (b[0] === 0x42 && b[1] === 0x4D) return ".bmp";
  if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return ".ico";
  if ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2A && b[3] === 0x00) ||
      (b[0] === 0x4D && b[1] === 0x4D && b[2] === 0x00 && b[3] === 0x2A)) return ".tiff";
  if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return ".webp";
  // Documents / archives
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return ".pdf";
  if (b[0] === 0x50 && b[1] === 0x4B && (b[2] === 0x03 || b[2] === 0x05)) return ".zip";
  if (b.length >= 6 && b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21 && b[4] === 0x1A && b[5] === 0x07) return ".rar";
  if (b.length >= 6 && b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC && b[3] === 0xAF && b[4] === 0x27 && b[5] === 0x1C) return ".7z";
  if (b[0] === 0x1F && b[1] === 0x8B) return ".gz";
  if (b[0] === 0x42 && b[1] === 0x5A && b[2] === 0x68) return ".bz2";
  if (b.length >= 8 && b[0] === 0xD0 && b[1] === 0xCF && b[2] === 0x11 && b[3] === 0xE0 &&
      b[4] === 0xA1 && b[5] === 0xB1 && b[6] === 0x1A && b[7] === 0xE1) return ".ole2";
  // SVG (text-based)
  if (b.length >= 8) {
    var head = b.subarray(0, Math.min(512, b.length)).toString("utf8").trim();
    if (head.startsWith("<?xml") || head.startsWith("<svg") || head.includes("<svg")) return ".svg";
  }
  return null;
}

/**
 * Validate that file content matches claimed extension.
 * Only checks extensions with known magic signatures — text formats skip validation.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateMagicBytes(filename, buffer) {
  if (!filename || !buffer) return { valid: true };
  var ext = path.extname(filename).toLowerCase();
  if (!RISKY_EXTENSIONS.has(ext)) return { valid: true };
  if (buffer.length < 8) return { valid: false, reason: "File too small to verify content type." };

  var detected = detectContentType(buffer);
  if (!detected) return { valid: false, reason: "File content does not match " + ext + " format." };

  // Normalize both sides through the compatibility map
  var expectedType = COMPAT[ext] || ext;
  var detectedType = COMPAT[detected] || detected;
  if (expectedType === detectedType) return { valid: true };
  // .jpg/.jpeg interchangeable
  if ((expectedType === ".jpg" || expectedType === ".jpeg") && (detectedType === ".jpg" || detectedType === ".jpeg")) return { valid: true };

  return { valid: false, reason: "File content does not match " + ext + " format." };
}

module.exports = { validateFile, validateChunk, validateBundleLimits, detectContentType, validateMagicBytes };
