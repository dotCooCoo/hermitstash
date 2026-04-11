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

  try {
    filesRepo.create({
      shareId: fileShareId,
      bundleId: bundle._id,
      bundleShareId: bundle.shareId,
      originalName: sanitizeFilename(file.filename),
      relativePath: sanitizeFilename(fields.relativePath || file.filename, 500),
      storagePath: storagePath, mimeType: file.mimetype, size: file.size,
      checksum: checksum, encryptionKey: saved.encryptionKey,
      uploadedBy: ctx.uploadedBy, uploaderEmail: ctx.uploaderEmail,
      downloads: 0, status: "complete",
      createdAt: new Date().toISOString(),
      expiresAt: ctx.expiresAt,
    });
  } catch (dbErr) {
    await storage.deleteFile(storagePath);
    throw dbErr;
  }

  // Track IP after save
  if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
    ipQuota.record(rateLimit.getIp(ctx.req), file.size);
  }

  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: auditDetail({ action: "file_added", bundleId: bundle._id, file: file.filename, size: file.size, checksum: checksum }), req: ctx.req });

  bundlesRepo.update(bundle._id, {
    $set: { receivedFiles: bundle.receivedFiles + 1, totalSize: bundle.totalSize + file.size },
  });

  return { success: true, received: bundle.receivedFiles + 1, total: bundle.expectedFiles };
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

module.exports = { resolveUploadConfig, checkAllQuotas, handleFileUpload, handleChunkUpload, handleFinalize };
