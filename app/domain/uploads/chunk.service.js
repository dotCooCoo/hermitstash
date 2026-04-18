/**
 * Chunk Service — business logic for chunked file uploads.
 * Handles chunk storage, validation, reassembly, and cleanup.
 */
var fs = require("fs");
var path = require("path");
var config = require("../../../lib/config");
var { files, bundles } = require("../../../lib/db");
var { sha3Hash, generateShareId } = require("../../../lib/crypto");
var storage = require("../../../lib/storage");
var fileService = require("./file.service");
var { validateChunk, validateFile } = require("../../http/validators/upload.validator");
var { ValidationError, NotFoundError } = require("../../shared/errors");

/**
 * Validate chunk metadata fields.
 * Throws ValidationError on bad input.
 */
function validateChunkMeta(fields) {
  var chunkIndex = parseInt(fields.chunkIndex, 10);
  var totalChunks = parseInt(fields.totalChunks, 10);
  var fileId = String(fields.fileId || "");

  if (isNaN(chunkIndex) || isNaN(totalChunks) || !fileId) {
    throw new ValidationError("Missing chunk metadata.");
  }

  // Stricter fileId validation — only safe alphanumeric + dash/underscore
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(fileId)) {
    throw new ValidationError("Invalid file ID.");
  }

  var result = validateChunk(chunkIndex, totalChunks, fileId);
  if (!result.valid) throw new ValidationError(result.reason);

  return { chunkIndex: chunkIndex, totalChunks: totalChunks, fileId: fileId };
}

/**
 * Resolve the chunk temp directory for a given bundle and fileId.
 * Verifies the resolved path stays within the upload directory (path traversal guard).
 * Returns the absolute chunk directory path.
 */
function resolveChunkDir(bundleShareId, fileId) {
  var chunkDir = path.join(storage.uploadDir, "chunks", bundleShareId, fileId);
  var resolvedDir = path.resolve(chunkDir);
  var resolvedBase = path.resolve(storage.uploadDir);
  if (!resolvedDir.startsWith(resolvedBase)) {
    throw new ValidationError("Invalid path.");
  }
  return resolvedDir;
}

/**
 * Write a single chunk to the temp directory.
 * Returns { received, totalChunks, complete } where complete is true
 * when all chunks have been written.
 */
function storeChunk(chunkDir, chunkIndex, data, totalChunks) {
  if (!fs.existsSync(chunkDir)) fs.mkdirSync(chunkDir, { recursive: true });
  fs.writeFileSync(path.join(chunkDir, String(chunkIndex)), data);

  var received = fs.readdirSync(chunkDir).length;
  return { received: received, totalChunks: totalChunks, complete: received >= totalChunks };
}

/**
 * Reassemble all chunks from the temp directory into a single Buffer.
 * Reads chunks 0..totalChunks-1 in order.
 */
function reassembleChunks(chunkDir, totalChunks) {
  var parts = [];
  for (var i = 0; i < totalChunks; i++) {
    var chunkPath = path.join(chunkDir, String(i));
    if (!fs.existsSync(chunkPath)) {
      throw new ValidationError("Missing chunk " + i + ".");
    }
    parts.push(fs.readFileSync(chunkPath));
  }
  return Buffer.concat(parts);
}

/**
 * Clean up chunk temp files and directory after reassembly.
 */
function cleanupChunks(chunkDir, totalChunks) {
  for (var i = 0; i < totalChunks; i++) {
    try { fs.unlinkSync(path.join(chunkDir, String(i))); } catch (_e) { /* best-effort */ }
  }
  try { fs.rmdirSync(chunkDir); } catch (_e) { /* best-effort */ }
}

/**
 * Process a fully reassembled chunked file: validate extension, save to storage,
 * insert DB record, and update the bundle counters.
 *
 * Returns the inserted file record.
 */
async function processReassembledFile(fullData, fields, bundle) {
  var filename = fields.filename || "file";
  var relativePath = fields.relativePath || filename;
  var ext = path.extname(filename).toLowerCase();

  // Validate file extension
  var fileResult = validateFile(filename, fullData.length, config.allowedExtensions, config.maxFileSize);
  if (!fileResult.valid) throw new ValidationError(fileResult.reason);

  var result = await fileService.saveAndCreateFileRecord(fullData, {
    bundleShareId: bundle.shareId, bundleId: bundle._id,
    filename: filename, relativePath: relativePath,
    mimeType: fields.mimeType, uploadedBy: bundle.ownerId || "public",
    uploaderEmail: bundle.uploaderEmail, expiresAt: bundle.expiresAt || null,
  });
  var doc = result.doc;

  bundles.update({ _id: bundle._id }, {
    $set: {
      receivedFiles: bundle.receivedFiles + 1,
      totalSize: bundle.totalSize + fullData.length,
    },
  });

  return doc;
}

/**
 * Full chunk upload pipeline: validate, store, and optionally reassemble + process.
 *
 * Returns either:
 *   { assembled: false, received, totalChunks } — still waiting for more chunks
 *   { assembled: true, file, received } — all chunks received and file saved
 */
async function handleChunkUpload(bundle, chunkData, fields) {
  if (!bundle) throw new NotFoundError("Bundle not found.");
  if (bundle.status === "complete") throw new NotFoundError("Bundle not found.");

  var meta = validateChunkMeta(fields);
  var chunkDir = resolveChunkDir(bundle.shareId, meta.fileId);
  var status = storeChunk(chunkDir, meta.chunkIndex, chunkData, meta.totalChunks);

  if (!status.complete) {
    return { assembled: false, received: status.received, totalChunks: meta.totalChunks };
  }

  // All chunks received — reassemble and process
  var fullData = reassembleChunks(chunkDir, meta.totalChunks);
  cleanupChunks(chunkDir, meta.totalChunks);
  var file = await processReassembledFile(fullData, fields, bundle);

  return { assembled: true, file: file, received: bundle.receivedFiles + 1 };
}

module.exports = {
  validateChunkMeta: validateChunkMeta,
  resolveChunkDir: resolveChunkDir,
  storeChunk: storeChunk,
  reassembleChunks: reassembleChunks,
  cleanupChunks: cleanupChunks,
  processReassembledFile: processReassembledFile,
  handleChunkUpload: handleChunkUpload,
};
