/**
 * Shared upload handlers — used by both /drop and /stash routes.
 * Each function takes a context object with resolved config and identity.
 * Routes remain thin wrappers that resolve auth/config then delegate here.
 */
var path = require("path");
var fs = require("fs");
var config = require("../../../lib/config");
var { sha3Hash, generateShareId } = require("../../../lib/crypto");
var filesRepo = require("../../data/repositories/files.repo");
var bundlesRepo = require("../../data/repositories/bundles.repo");
var storage = require("../../../lib/storage");
var audit = require("../../../lib/audit");
var logger = require("../../shared/logger");
var bundleService = require("./bundle.service");
var uploadValidator = require("../../http/validators/upload.validator");
var ipQuota = require("../../../lib/ip-quota");
var rateLimit = require("../../../lib/rate-limit");
var { sanitizeFilename } = require("../../shared/sanitize-filename");
var syncEmitter = require("../../../lib/sync-emitter");

/**
 * Build structured audit detail JSON for file mutation events.
 */
function auditDetail(obj) {
  return JSON.stringify(obj);
}

/**
 * Resolve stash config overrides, falling back to global config.
 * Pass null for stash to get global config.
 */
function resolveUploadConfig(stash) {
  if (!stash) {
    return {
      maxFileSize: config.maxFileSize,
      maxFiles: config.publicMaxFiles,
      maxBundleSize: config.publicMaxBundleSize,
      allowedExtensions: config.allowedExtensions,
    };
  }
  return {
    maxFileSize: (stash.maxFileSize && stash.maxFileSize > 0) ? stash.maxFileSize : config.maxFileSize,
    maxFiles: (stash.maxFiles && stash.maxFiles > 0) ? stash.maxFiles : config.publicMaxFiles,
    maxBundleSize: (stash.maxBundleSize && stash.maxBundleSize > 0) ? stash.maxBundleSize : config.publicMaxBundleSize,
    allowedExtensions: stash.allowedExtensions ? stash.allowedExtensions.split(",").map(function (e) { return e.trim(); }).filter(Boolean) : config.allowedExtensions,
  };
}

/**
 * Check all quotas (storage, per-user, per-IP) for a file upload.
 * Returns { allowed: true } or { allowed: false, error: string }.
 */
function checkAllQuotas(fileSize, bundle, req) {
  // Storage quota
  try {
    bundleService.checkStorageQuota(fileSize, config.storageQuotaBytes);
  } catch (_e) {
    return { allowed: false, error: _e.message, reason: "storage quota exceeded" };
  }

  // Per-user quota
  if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
    var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
    var userTotal = 0;
    for (var i = 0; i < userFiles.length; i++) { userTotal += Number(userFiles[i].size) || 0; }
    if (userTotal + fileSize > config.perUserQuotaBytes) {
      return { allowed: false, error: "Personal storage quota exceeded.", reason: "per-user quota exceeded" };
    }
  }

  // Per-IP quota (anonymous only)
  if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
    var ipCheck = ipQuota.check(rateLimit.getIp(req), fileSize, config.publicIpQuotaBytes);
    if (!ipCheck.allowed) {
      return { allowed: false, error: "Upload quota exceeded. Try again later.", reason: "per-IP quota exceeded" };
    }
  }

  return { allowed: true };
}

/**
 * Handle single file upload.
 * @param {object} ctx - { bundle, file, fields, limits, uploadedBy, uploaderEmail, expiresAt, auditSuffix, req }
 */
async function handleFileUpload(ctx) {
  var bundle = ctx.bundle;
  var file = ctx.file;
  var fields = ctx.fields;
  var limits = ctx.limits;
  var suffix = ctx.auditSuffix || "";

  // Validate extension + size
  var fileCheck = uploadValidator.validateFile(file.filename, file.size, limits.allowedExtensions, limits.maxFileSize);
  if (!fileCheck.valid) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + fileCheck.reason + suffix, req: ctx.req });
    return { error: fileCheck.reason };
  }

  // Magic bytes
  try {
    var magicCheck = uploadValidator.validateMagicBytes(file.filename, file.data);
    if (!magicCheck.valid) {
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + suffix, req: ctx.req });
      return { error: magicCheck.reason };
    }
  } catch (_e) { logger.error("Magic byte validation error", { file: file.filename, error: _e.message }); }

  // Bundle limits
  var limitsCheck = uploadValidator.validateBundleLimits(bundle.receivedFiles + 1, limits.maxFiles, bundle.totalSize + file.size, limits.maxBundleSize);
  if (!limitsCheck.valid) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + limitsCheck.reason + suffix, req: ctx.req });
    return { error: limitsCheck.reason };
  }

  // Quotas
  var quota = checkAllQuotas(file.size, bundle, ctx.req);
  if (!quota.allowed) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + quota.reason + suffix, req: ctx.req });
    return { error: quota.error };
  }

  // Save file
  var ext = path.extname(file.filename).toLowerCase();
  var fileShareId = generateShareId();
  var storagePath = "bundles/" + bundle.shareId + "/" + Date.now() + "-" + fileShareId + ext;
  var checksum = sha3Hash(file.data);
  var saved = await storage.saveFile(file.data, storagePath);
  var cleanRelPath = sanitizeFilename(fields.relativePath || file.filename, 500);
  var now = new Date().toISOString();

  // Sync bundle: check for existing file with same relativePath → replace
  var replaced = false;
  var oldSize = 0;
  if (bundle.bundleType === "sync") {
    var existing = filesRepo.findAll({ bundleId: bundle._id })
      .filter(function (f) { return f.relativePath === cleanRelPath && !f.deletedAt; });
    if (existing.length > 0) {
      var old = existing[0];
      oldSize = old.size || 0;
      // Delete old encrypted blob and sealed key
      try { await storage.deleteFile(old.storagePath); } catch (_e) {}
      // Update in place: new key, new content, new checksum
      filesRepo.update(old._id, { $set: {
        originalName: sanitizeFilename(file.filename),
        storagePath: storagePath, mimeType: file.mimetype, size: file.size,
        checksum: checksum, encryptionKey: saved.encryptionKey,
        updatedAt: now, seq: (bundle.seq || 0) + 1,
      }});
      replaced = true;
    }
  }

  if (!replaced) {
    try {
      filesRepo.create({
        shareId: fileShareId,
        bundleId: bundle._id,
        bundleShareId: bundle.shareId,
        originalName: sanitizeFilename(file.filename),
        relativePath: cleanRelPath,
        storagePath: storagePath, mimeType: file.mimetype, size: file.size,
        checksum: checksum, encryptionKey: saved.encryptionKey,
        uploadedBy: ctx.uploadedBy, uploaderEmail: ctx.uploaderEmail,
        downloads: 0, status: "complete",
        createdAt: now, updatedAt: now,
        seq: (bundle.seq || 0) + 1,
        expiresAt: ctx.expiresAt,
      });
    } catch (dbErr) {
      await storage.deleteFile(storagePath);
      throw dbErr;
    }
  }

  // Track IP after save
  if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
    ipQuota.record(rateLimit.getIp(ctx.req), file.size);
  }

  var action = replaced ? "file_replaced" : "file_added";
  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: auditDetail({ action: action, bundleId: bundle._id, file: file.filename, relativePath: cleanRelPath, size: file.size, checksum: checksum }), req: ctx.req });

  // Update bundle counters and seq
  var sizeChange = replaced ? (file.size - oldSize) : file.size;
  var fileCountChange = replaced ? 0 : 1;
  bundlesRepo.update(bundle._id, {
    $set: {
      receivedFiles: bundle.receivedFiles + fileCountChange,
      totalSize: bundle.totalSize + sizeChange,
      seq: (bundle.seq || 0) + 1,
    },
  });

  // Emit sync event for WebSocket subscribers
  if (bundle.bundleType === "sync") {
    var newSeq = (bundle.seq || 0) + 1;
    syncEmitter.emit("sync:" + bundle._id, {
      type: action, fileId: replaced ? existing[0]._id : fileShareId,
      relativePath: cleanRelPath, checksum: checksum, size: file.size, seq: newSeq,
    });
  }

  return { success: true, replaced: replaced, received: bundle.receivedFiles + fileCountChange, total: bundle.expectedFiles };
}

/**
 * Handle chunked upload.
 * @param {object} ctx - { bundle, chunk, fields, limits, uploadedBy, uploaderEmail, expiresAt, auditSuffix, req }
 */
async function handleChunkUpload(ctx) {
  var bundle = ctx.bundle;
  var chunk = ctx.chunk;
  var fields = ctx.fields;
  var limits = ctx.limits;
  var suffix = ctx.auditSuffix || "";

  var chunkIndex = parseInt(fields.chunkIndex, 10);
  var totalChunks = parseInt(fields.totalChunks, 10);
  var fileId = String(fields.fileId || "");
  if (isNaN(chunkIndex) || isNaN(totalChunks) || !fileId) {
    return { error: "Missing chunk metadata." };
  }
  var chunkCheck = uploadValidator.validateChunk(chunkIndex, totalChunks, fileId);
  if (!chunkCheck.valid) return { error: chunkCheck.reason };
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(fileId)) return { error: "Invalid file ID." };

  // Early extension validation
  var earlyFilename = fields.filename || "file";
  var earlyExt = path.extname(earlyFilename).toLowerCase();
  if (earlyExt && limits.allowedExtensions && limits.allowedExtensions.length > 0 && !limits.allowedExtensions.includes(earlyExt)) {
    return { error: "File type not allowed: " + earlyExt };
  }

  // Per-chunk size limit — prevent disk exhaustion before reassembly-time quota check
  var maxChunkSize = Math.max(limits.maxFileSize || 10485760, 10485760); // at least 10MB per chunk
  if (chunk.data.length > maxChunkSize) {
    return { error: "Chunk too large." };
  }

  // Store chunk
  var chunkDir = path.join(config.storage.uploadDir, "chunks", bundle.shareId, fileId);
  var resolvedDir = path.resolve(chunkDir);
  var resolvedBase = path.resolve(config.storage.uploadDir);
  if (!resolvedDir.startsWith(resolvedBase)) return { error: "Invalid path." };
  if (!fs.existsSync(chunkDir)) fs.mkdirSync(chunkDir, { recursive: true });
  fs.writeFileSync(path.join(chunkDir, String(chunkIndex)), chunk.data);

  // Check if all chunks received
  var received = fs.readdirSync(chunkDir).length;
  if (received < totalChunks) {
    return { success: true, chunksReceived: received, totalChunks: totalChunks };
  }

  // Estimate size + check quotas before reassembly
  var estimatedSize = 0;
  for (var ce = 0; ce < totalChunks; ce++) {
    try { estimatedSize += fs.statSync(path.join(chunkDir, String(ce))).size; } catch (_e) {}
  }
  var quota = checkAllQuotas(estimatedSize, bundle, ctx.req);
  if (!quota.allowed) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + quota.reason + " (chunked)" + suffix, req: ctx.req });
    return { error: quota.error };
  }

  // Reassemble
  var reassembled = [];
  for (var ci = 0; ci < totalChunks; ci++) {
    reassembled.push(fs.readFileSync(path.join(chunkDir, String(ci))));
  }
  var fullData = Buffer.concat(reassembled);

  // Clean up chunks
  for (var cj = 0; cj < totalChunks; cj++) {
    try { fs.unlinkSync(path.join(chunkDir, String(cj))); } catch (_e) {}
  }
  try { fs.rmdirSync(chunkDir); } catch (_e) {}

  // Validate reassembled file
  var filename = fields.filename || "file";
  var relativePath = fields.relativePath || filename;
  var ext = path.extname(filename).toLowerCase();
  var fileCheck = uploadValidator.validateFile(filename, fullData.length, limits.allowedExtensions, limits.maxFileSize);
  if (!fileCheck.valid) return { error: fileCheck.reason };

  try {
    var magicCheck = uploadValidator.validateMagicBytes(filename, fullData);
    if (!magicCheck.valid) {
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + " (chunked)" + suffix, req: ctx.req });
      return { error: magicCheck.reason };
    }
  } catch (_e) { logger.error("Magic byte validation error (chunked)", { file: filename, error: _e.message }); }

  // Save
  var chunkFileShareId = generateShareId();
  var storagePath = "bundles/" + bundle.shareId + "/" + Date.now() + "-" + chunkFileShareId + ext;
  var checksum = sha3Hash(fullData);
  var saved = await storage.saveFile(fullData, storagePath);

  try {
    filesRepo.create({
      shareId: chunkFileShareId,
      bundleId: bundle._id,
      bundleShareId: bundle.shareId,
      originalName: sanitizeFilename(filename),
      relativePath: sanitizeFilename(relativePath, 500),
      storagePath: storagePath, mimeType: fields.mimeType || "application/octet-stream",
      size: fullData.length, checksum: checksum, encryptionKey: saved.encryptionKey,
      uploadedBy: ctx.uploadedBy, uploaderEmail: ctx.uploaderEmail,
      downloads: 0, status: "complete",
      createdAt: new Date().toISOString(),
      expiresAt: ctx.expiresAt,
    });
  } catch (dbErr) {
    await storage.deleteFile(storagePath);
    throw dbErr;
  }

  if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
    ipQuota.record(rateLimit.getIp(ctx.req), fullData.length);
  }

  bundlesRepo.update(bundle._id, {
    $set: { receivedFiles: bundle.receivedFiles + 1, totalSize: bundle.totalSize + fullData.length },
  });

  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: auditDetail({ action: "file_added", bundleId: bundle._id, file: filename, size: fullData.length, chunks: totalChunks, checksum: checksum }), req: ctx.req });
  return { success: true, assembled: true, received: bundle.receivedFiles + 1 };
}

/**
 * Handle bundle finalization — email notifications, webhooks, audit.
 * @param {object} ctx - { bundleId, token, uploaderName, sendUploaderEmail, stashSlug, stashId, auditSuffix, req }
 */
function handleFinalize(ctx) {
  var usersRepo = require("../../data/repositories/users.repo");
  var emailService = require("../integrations/email.service");
  var webhook = require("../integrations/webhook.service");
  var { host } = require("../../../middleware/send");
  var suffix = ctx.auditSuffix || "";

  var existing = bundlesRepo.findById(ctx.bundleId);
  if (!existing) return { error: "Bundle not found.", status: 404 };
  if (existing.status === "complete") {
    return { success: true, shareId: existing.shareId, shareUrl: host(ctx.req) + "/b/" + existing.shareId, emailSent: false };
  }

  var refreshed;
  try {
    refreshed = bundleService.finalizeBundle(ctx.bundleId, ctx.token);
  } catch (err) {
    if (err.statusCode === 403 || err.name === "ForbiddenError") return { error: err.message, status: 403 };
    if (err.statusCode === 404 || err.name === "NotFoundError") return { error: err.message, status: 404 };
    return { error: err.message, status: 400 };
  }

  var bundleUrl = host(ctx.req) + "/b/" + refreshed.shareId;
  var emailSent = false;

  if (refreshed.receivedFiles > 0) {
    var uploadedFiles = filesRepo.findAll({ bundleShareId: refreshed.shareId, status: "complete" })
      .map(function (f) { return { path: f.relativePath || f.originalName, size: f.size }; });

    var emailData = {
      uploaderName: ctx.uploaderName || refreshed.uploaderName || "Anonymous",
      uploaderEmail: ctx.sendUploaderEmail ? refreshed.uploaderEmail : null,
      bundleUrl: bundleUrl,
      uploadedCount: refreshed.receivedFiles, uploadedFiles: uploadedFiles,
      skippedCount: refreshed.skippedCount || 0, skippedFiles: refreshed.skippedFiles || [],
      totalSize: refreshed.totalSize,
    };

    // Send uploader confirmation if enabled and email present
    if (ctx.sendUploaderEmail && refreshed.uploaderEmail) {
      var recipients = refreshed.uploaderEmail.split(",").map(function (e) { return e.trim(); }).filter(Boolean);
      recipients.forEach(function (r) {
        emailService.sendUploaderConfirmation({ to: r, ...emailData }).catch(function (e) { logger.error("Email send failed", { error: e.message }); });
      });
      emailSent = true;
    }

    // Admin notification
    var adminUsers = usersRepo.findAll({ role: "admin" }).map(function (u) { return u.email; }).filter(Boolean);
    if (adminUsers.length > 0) {
      emailService.sendAdminNotification({ adminEmails: adminUsers, ...emailData }).catch(function (e) { logger.error("Email send failed", { error: e.message }); });
    }
  }

  var webhookData = { shareId: refreshed.shareId, uploaderName: ctx.uploaderName || refreshed.uploaderName || "Anonymous", files: refreshed.receivedFiles, size: refreshed.totalSize };
  if (ctx.stashSlug) webhookData.stashSlug = ctx.stashSlug;
  webhook.fire("bundle_finalized", webhookData);

  audit.log(audit.ACTIONS.BUNDLE_FINALIZED, { targetId: existing._id, targetEmail: refreshed.uploaderEmail, details: auditDetail({ action: "bundle_finalized", bundleId: existing._id, files: refreshed.receivedFiles, size: refreshed.totalSize, emailSent: emailSent }), req: ctx.req });

  return { success: true, shareId: refreshed.shareId, shareUrl: bundleUrl, emailSent: emailSent, refreshed: refreshed };
}

/**
 * Handle file deletion from a sync bundle (soft delete with tombstone).
 * @param {object} ctx - { bundle, fileId, req }
 */
async function handleSyncFileDelete(ctx) {
  var bundle = ctx.bundle;
  if (bundle.bundleType !== "sync") return { error: "Only sync bundles support file deletion." };

  var file = filesRepo.findById(ctx.fileId);
  if (!file || file.bundleId !== bundle._id) return { error: "File not found.", status: 404 };
  if (file.deletedAt) return { error: "File already deleted.", status: 404 };

  // Delete encrypted blob and sealed key from storage
  try { await storage.deleteFile(file.storagePath); } catch (_e) {}

  // Tombstone: set deletedAt, keep sealed fields for event emission
  var now = new Date().toISOString();
  var newSeq = (bundle.seq || 0) + 1;
  filesRepo.update(file._id, { $set: {
    deletedAt: now, updatedAt: now, seq: newSeq,
    storagePath: null, encryptionKey: null,
  }});

  // Update bundle counters
  bundlesRepo.update(bundle._id, { $set: {
    receivedFiles: Math.max(0, bundle.receivedFiles - 1),
    totalSize: Math.max(0, bundle.totalSize - (file.size || 0)),
    seq: newSeq,
  }});

  audit.log(audit.ACTIONS.FILE_DELETED, { targetId: file._id, details: auditDetail({ action: "file_removed", bundleId: bundle._id, file: file.originalName, relativePath: file.relativePath }), req: ctx.req });

  // Emit sync event
  syncEmitter.emit("sync:" + bundle._id, {
    type: "file_removed", fileId: file._id, relativePath: file.relativePath, seq: newSeq,
  });

  return { success: true, seq: newSeq };
}

/**
 * Handle sync file rename/move — update relativePath without re-uploading.
 * The encrypted blob stays unchanged; only metadata is updated.
 *
 * ctx: { bundleId, oldRelativePath, newRelativePath, req }
 */
async function handleSyncFileRename(ctx) {
  var bundle = bundlesRepo.findById(ctx.bundleId);
  if (!bundle) return { error: "Bundle not found.", status: 404 };
  if (bundle.bundleType !== "sync") return { error: "Only sync bundles support rename.", status: 400 };

  var oldPath = String(ctx.oldRelativePath || "").replace(/\\/g, "/");
  var newPath = String(ctx.newRelativePath || "").replace(/\\/g, "/");
  if (!oldPath || !newPath) return { error: "Both oldRelativePath and newRelativePath required.", status: 400 };

  // Sanitize new path
  var { sanitizeFilename } = require("../../shared/sanitize-filename");
  var segments = newPath.split("/");
  segments = segments.map(function (s) { return sanitizeFilename(s); }).filter(Boolean);
  if (segments.length === 0) return { error: "Invalid new path.", status: 400 };
  newPath = segments.join("/");

  // Find existing file by oldRelativePath
  var allFiles = filesRepo.findAll({ bundleId: bundle._id }).filter(function (f) {
    return !f.deletedAt && f.relativePath === oldPath;
  });
  if (allFiles.length === 0) return { error: "File not found at old path.", status: 404 };

  var file = allFiles[0];
  var now = new Date().toISOString();
  var newSeq = (bundle.seq || 0) + 1;
  var newName = segments[segments.length - 1];

  // Update file metadata
  filesRepo.update(file._id, { $set: {
    relativePath: newPath,
    originalName: newName,
    updatedAt: now,
    seq: newSeq,
  }});

  // Update bundle seq
  bundlesRepo.update(bundle._id, { $set: { seq: newSeq } });

  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, {
    targetId: bundle._id,
    details: auditDetail({ action: "file_renamed", bundleId: bundle._id, from: oldPath, to: newPath }),
    req: ctx.req,
  });

  // Emit sync event
  syncEmitter.emit("sync:" + bundle._id, {
    type: "file_renamed", fileId: file._id,
    oldRelativePath: oldPath, relativePath: newPath,
    checksum: file.checksum, size: file.size, seq: newSeq,
  });

  return { success: true, seq: newSeq, relativePath: newPath };
}

module.exports = { resolveUploadConfig, checkAllQuotas, handleFileUpload, handleChunkUpload, handleFinalize, handleSyncFileDelete, handleSyncFileRename };
