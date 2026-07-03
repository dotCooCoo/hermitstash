/**
 * Upload request validators — shared validation for regular and chunked uploads.
 * Ensures consistent size/count/type enforcement across all upload paths.
 */
var nodePath = require("node:path");
var b = require("../../../lib/vendor/blamejs");

/**
 * Validate a file against allowed extensions, max size, and empty check.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateFile(filename, fileSize, allowedExtensions, maxFileSize) {
  if (!filename) return { valid: false, reason: "Missing filename." };
  if (fileSize === 0) return { valid: false, reason: "Empty file." };
  if (maxFileSize && fileSize > maxFileSize) return { valid: false, reason: "File too large." };

  var ext = nodePath.extname(filename).toLowerCase();
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

// Raster image types fed to b.guardImage for polyglot / format-integrity
// tightening. SVG is deliberately absent — guardImage refuses SVG bytes via
// an svg-routing issue, and SVG has its own sanitize path (lib/sanitize-svg.js).
// Maps the detected extension to the MIME guardImage's magic table reports so
// the declared-vs-detected mismatch check stays neutral and only the polyglot /
// cap checks can fire (additive: guardImage can only TIGHTEN, never loosen).
var RASTER_IMAGE_MIME = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".bmp": "image/bmp",
  ".ico": "image/x-icon",
  ".tiff": "image/tiff",
};

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
  // PDF: %PDF within first 1024 bytes (per Adobe spec — allows BOM, whitespace, or preamble)
  var pdfLimit = Math.min(1024, b.length - 3);
  for (var pi = 0; pi < pdfLimit; pi++) {
    if (b[pi] === 0x25 && b[pi+1] === 0x50 && b[pi+2] === 0x44 && b[pi+3] === 0x46) return ".pdf";
  }
  // ZIP: any PK signature (local header, central dir, end of central dir, spanned)
  if (b[0] === 0x50 && b[1] === 0x4B) return ".zip";
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
  var ext = nodePath.extname(filename).toLowerCase();
  if (!RISKY_EXTENSIONS.has(ext)) return { valid: true };
  if (buffer.length < 8) return { valid: false, reason: "File too small to verify content type." };

  var detected = detectContentType(buffer);
  if (!detected) return { valid: false, reason: "File content does not match " + ext + " format." };

  // Normalize both sides through the compatibility map
  var expectedType = COMPAT[ext] || ext;
  var detectedType = COMPAT[detected] || detected;
  var extensionMatches = (expectedType === detectedType) ||
    // .jpg/.jpeg interchangeable
    ((expectedType === ".jpg" || expectedType === ".jpeg") && (detectedType === ".jpg" || detectedType === ".jpeg"));

  if (!extensionMatches) {
    return { valid: false, reason: "File content does not match " + ext + " format." };
  }

  // The buffer is a valid image whose extension agrees with its magic bytes.
  // For raster images only, run the polyglot / format-integrity guard — it can
  // only TIGHTEN this result. detectContentType() returns on the first magic
  // match, so a polyglot carrying two valid image signatures is mislabeled and
  // would otherwise pass; guardImage walks every signature and refuses a buffer
  // that matches more than one format. SVG is excluded (it routes through
  // lib/sanitize-svg.js; feeding it here trips a spurious svg-routing refusal).
  var rasterMime = RASTER_IMAGE_MIME[detectedType];
  if (rasterMime) {
    var imageCheck = b.guardImage.validate({ bytes: buffer, declaredMime: rasterMime });
    if (!imageCheck.ok) {
      return { valid: false, reason: "Image failed polyglot/format-integrity check." };
    }
  }

  return { valid: true };
}

// MIME types HS renders INLINE at serve time (mirrors app/domain/uploads/
// file.service.js SAFE_INLINE) and that b.fileType.detect can verify by magic
// bytes. The serve-time inline/download gate reads the STORED mimeType, which is
// the client-advertised multipart Content-Type — so a file declared as an
// inline-rendered type but whose bytes are something else could be steered to an
// inline render regardless of its extension (0.15.58 class). safeServeMime binds
// the stored type to the sniffed reality: a declared inline type whose bytes do
// not match is stored as application/octet-stream (forces download), never
// rejected. (image/svg+xml is absent — SVG is magic-byte-less and always routes
// to the sanitizer; every file response also carries X-Content-Type-Options:
// nosniff, so the browser never sniffs a served body into an active type.)
var INLINE_SNIFFABLE_MIME = new Set([
  "application/pdf", "image/gif", "image/jpeg", "image/png", "image/webp",
]);

function safeServeMime(declaredMime, buffer) {
  if (!declaredMime || typeof declaredMime !== "string") return "application/octet-stream";
  if (!INLINE_SNIFFABLE_MIME.has(declaredMime)) return declaredMime;
  if (!buffer || buffer.length < 4) return "application/octet-stream";
  var sniffed = b.fileType.detect(buffer);
  return (sniffed && sniffed.mime === declaredMime) ? declaredMime : "application/octet-stream";
}

module.exports = { validateFile, validateChunk, validateBundleLimits, detectContentType, validateMagicBytes, safeServeMime };
