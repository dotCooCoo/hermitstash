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

module.exports = { validateFile, validateChunk, validateBundleLimits };
