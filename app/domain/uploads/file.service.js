/**
 * File Service — business logic for file operations.
 * Handles download, preview (with SVG sanitization), and deletion.
 */
var filesRepo = require("../../data/repositories/files.repo");
var storage = require("../../../lib/storage");
var { safeFilename } = require("../../../lib/sanitize");
var { sanitizeSvg } = require("../../../lib/sanitize-svg");
var { NotFoundError, ValidationError, ForbiddenError } = require("../../shared/errors");

// MIME types safe for inline preview
var SAFE_INLINE = new Set(["image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"]);
// Types that MUST be forced-download (never rendered inline)
var FORCE_DOWNLOAD = new Set(["text/html", "application/xhtml+xml", "application/javascript", "text/javascript"]);

// Maximum SVG size to load into memory for sanitization (2 MB)
var SVG_SIZE_LIMIT = 2 * 1024 * 1024;

/**
 * Look up a file by shareId. Throws NotFoundError if missing or incomplete.
 * Optionally checks expiry.
 */
function lookupFile(shareId, opts) {
  opts = opts || {};
  var doc = filesRepo.findAll({ shareId: shareId, status: "complete" })[0];
  if (!doc) throw new NotFoundError("File not found.");
  // Vault files must only be accessed through /vault/ routes
  if (doc.vaultEncrypted === "true") throw new NotFoundError("File not found.");
  if (opts.checkExpiry && doc.expiresAt && doc.expiresAt < new Date().toISOString()) {
    throw new ValidationError("File expired.");
  }
  return doc;
}

/**
 * Increment the download counter for a file.
 */
function incrementDownloads(doc) {
  filesRepo.incrementDownloads(doc._id);
}

/**
 * Get a pre-signed S3 URL for direct download (bypasses app decryption).
 * Returns null if not applicable (file is encrypted, backend is not S3, or direct mode is off).
 */
function getDirectDownloadUrl(doc) {
  if (doc.encryptionKey) return null;
  return storage.getPresignedUrl(doc.storagePath, doc.originalName, doc.mimeType);
}

/**
 * Get a readable stream of decrypted file data + response headers for download.
 * Returns { stream, headers }.
 */
async function getDownloadStream(doc) {
  var stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);
  var headers = {
    "Content-Disposition": "attachment; filename=\"" + safeFilename(doc.originalName) + "\"",
    "Content-Type": doc.mimeType || "application/octet-stream",
  };
  return { stream: stream, headers: headers };
}

/**
 * Determine preview disposition for a file.
 * Returns { mode, mime } where mode is "inline", "sanitized-svg", or "download".
 */
function getPreviewMode(doc) {
  var mime = doc.mimeType || "application/octet-stream";
  if (FORCE_DOWNLOAD.has(mime)) return { mode: "download", mime: mime };
  if (mime === "image/svg+xml") return { mode: "sanitized-svg", mime: mime };
  if (SAFE_INLINE.has(mime)) return { mode: "inline", mime: mime };
  return { mode: "download", mime: mime };
}

/**
 * Get a readable stream + headers for inline preview of safe MIME types.
 * Returns { stream, headers }.
 */
async function getInlinePreviewStream(doc) {
  var stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);
  var headers = {
    "Content-Type": doc.mimeType,
    "Content-Disposition": "inline",
  };
  return { stream: stream, headers: headers };
}

/**
 * Read an SVG file, sanitize it, and return the clean markup.
 * Enforces SVG_SIZE_LIMIT to prevent excessive memory use.
 * Returns { body, headers }.
 */
async function getSanitizedSvg(doc) {
  // Reject oversized SVGs before loading into memory
  if (doc.size && doc.size > SVG_SIZE_LIMIT) {
    throw new ValidationError("SVG too large for preview.");
  }

  var stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);

  return new Promise(function (resolve, reject) {
    var chunks = [];
    var totalBytes = 0;
    stream.on("data", function (c) {
      totalBytes += c.length;
      if (totalBytes > SVG_SIZE_LIMIT) {
        stream.destroy();
        return reject(new ValidationError("SVG too large for preview."));
      }
      chunks.push(c);
    });
    stream.on("error", function (err) { reject(err); });
    stream.on("end", function () {
      var svgRaw = Buffer.concat(chunks).toString("utf8");
      var clean = sanitizeSvg(svgRaw);
      var headers = {
        "Content-Type": "image/svg+xml",
        "Content-Disposition": "inline",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      };
      resolve({ body: clean, headers: headers });
    });
  });
}

/**
 * Get a force-download stream + headers (for HTML/JS or unknown types).
 * Returns { stream, headers }.
 */
async function getForceDownloadStream(doc) {
  var stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);
  var headers = {
    "Content-Disposition": "attachment; filename=\"" + safeFilename(doc.originalName) + "\"",
    "Content-Type": "application/octet-stream",
  };
  return { stream: stream, headers: headers };
}

/**
 * Delete a file from storage and DB.
 * Caller must verify authorization before calling this.
 */
async function deleteFile(doc) {
  if (doc.storagePath) await storage.deleteFile(doc.storagePath);
  filesRepo.remove(doc._id);
}

/**
 * Check if a user is authorized to delete a file.
 * Returns true if owner or admin. Throws ForbiddenError otherwise.
 */
function assertCanDelete(doc, user) {
  if (!user) throw new ForbiddenError("Authentication required.");
  if (doc.uploadedBy === user._id) return true;
  if (user.role === "admin") return true;
  throw new ForbiddenError("Not authorized.");
}

/**
 * Save a file to storage (encrypts with AES-256-GCM, key sealed with ML-KEM-768).
 * Returns { storagePath, encryptionKey }.
 */
async function saveToStorage(buffer, storagePath) {
  var saved = await storage.saveFile(buffer, storagePath);
  return { storagePath: storagePath, encryptionKey: saved.encryptionKey };
}

module.exports = {
  lookupFile: lookupFile,
  incrementDownloads: incrementDownloads,
  getDirectDownloadUrl: getDirectDownloadUrl,
  getDownloadStream: getDownloadStream,
  getPreviewMode: getPreviewMode,
  getInlinePreviewStream: getInlinePreviewStream,
  getSanitizedSvg: getSanitizedSvg,
  getForceDownloadStream: getForceDownloadStream,
  deleteFile: deleteFile,
  assertCanDelete: assertCanDelete,
  saveToStorage: saveToStorage,
  SVG_SIZE_LIMIT: SVG_SIZE_LIMIT,
};
