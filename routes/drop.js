const path = require("path");
const config = require("../lib/config");
const { sha3Hash, generateShareId } = require("../lib/crypto");
var usersRepo = require("../app/data/repositories/users.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
const { parseMultipart, parseJson } = require("../lib/multipart");
const storage = require("../lib/storage");
const { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var webhook = require("../app/domain/integrations/webhook.service");
var rateLimit = require("../lib/rate-limit");
var bundleService = require("../app/domain/uploads/bundle.service");
var uploadValidator = require("../app/http/validators/upload.validator");
var emailService = require("../app/domain/integrations/email.service");
var { requireScope } = require("../app/security/scope-policy");
var ipQuota = require("../lib/ip-quota");

module.exports = function (app) {
  // Drop page
  app.get("/drop", (req, res) => {
    if (!config.publicUpload) return send(res, "error", { title: "Disabled", message: "Public uploads are disabled.", user: req.user }, 403);
    // Pass vault state so the template can show the vault toggle for logged-in users
    var vaultEnabled = false;
    var vaultPublicKey = null;
    if (req.user) {
      var u = usersRepo.findById(req.user._id);
      if (u && u.vaultEnabled === "true" && u.vaultPublicKey) {
        vaultEnabled = true;
        vaultPublicKey = u.vaultPublicKey;
      }
    }
    send(res, "public-upload", {
      user: req.user, maxSize: config.maxFileSize,
      maxFiles: config.publicMaxFiles, maxBundleSize: config.publicMaxBundleSize,
      allowedExtensions: config.allowedExtensions,
      uploadTimeout: config.uploadTimeout, uploadConcurrency: config.uploadConcurrency,
      uploadRetries: config.uploadRetries,
      dropTitle: config.dropTitle, dropSubtitle: config.dropSubtitle,
      vaultEnabled: vaultEnabled, vaultPublicKey: vaultPublicKey,
    });
  });

  // Init bundle
  app.post("/drop/init", rateLimit.middleware("drop-init", 20, 60000), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) return res.status(403).json({ error: "Disabled." });
    const body = await parseJson(req);
    var rawEmail = body.uploaderEmail ? String(body.uploaderEmail).slice(0, 254) : null;
    var rawName = String(body.uploaderName || "Anonymous").slice(0, 200);

    // If logged in, always use the user's identity and assign files to their account
    var ownerId = req.user ? req.user._id : null;
    if (req.user) {
      rawName = req.user.displayName || rawName;
      rawEmail = req.user.email || rawEmail;
    }

    var result = await bundleService.initBundle({
      uploaderName: rawName,
      uploaderEmail: rawEmail,
      ownerId: ownerId,
      password: body.password,
      message: body.message,
      expiryDays: body.expiryDays,
      defaultExpiryDays: config.fileExpiryDays,
      fileCount: body.fileCount,
      skippedCount: body.skippedCount,
      skippedFiles: body.skippedFiles,
    });
    audit.log(audit.ACTIONS.BUNDLE_INITIALIZED, { targetId: result.bundleId, targetEmail: rawEmail, details: "expected: " + (body.fileCount || 0), req: req });
    res.json({ bundleId: result.bundleId, shareId: result.shareId, finalizeToken: result.finalizeToken });
  });

  // Upload single file to bundle
  app.post("/drop/file/:bundleId", rateLimit.middleware("upload", 200, 60000), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) return res.status(403).json({ error: "Disabled." });
    try {
      const bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });

      const { fields, files: uploaded } = await parseMultipart(req, config.maxFileSize);
      const file = uploaded[0];
      if (!file) return res.status(400).json({ error: "No file." });

      // Validate file extension and size
      var fileCheck = uploadValidator.validateFile(file.filename, file.size, config.allowedExtensions, config.maxFileSize);
      if (!fileCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + fileCheck.reason, req: req });
        return res.status(400).json({ error: fileCheck.reason });
      }

      // Validate file content matches extension
      var magicCheck = uploadValidator.validateMagicBytes(file.filename, file.data);
      if (!magicCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason, req: req });
        return res.status(400).json({ error: magicCheck.reason });
      }

      // Validate bundle limits (file count)
      var limitsCheck = uploadValidator.validateBundleLimits(bundle.receivedFiles + 1, config.publicMaxFiles, bundle.totalSize + file.size, config.publicMaxBundleSize);
      if (!limitsCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + limitsCheck.reason, req: req });
        return res.status(400).json({ error: limitsCheck.reason });
      }

      // Storage quota check
      try {
        bundleService.checkStorageQuota(file.size, config.storageQuotaBytes);
      } catch (quotaErr) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: storage quota exceeded", req: req });
        return res.status(400).json({ error: quotaErr.message });
      }

      // Per-user quota check
      if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
        var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
        var userTotal = 0;
        for (var ui = 0; ui < userFiles.length; ui++) { userTotal += Number(userFiles[ui].size) || 0; }
        if (userTotal + file.size > config.perUserQuotaBytes) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-user quota exceeded, user: " + bundle.ownerId, req: req });
          return res.status(400).json({ error: "Personal storage quota exceeded." });
        }
      }

      // Per-IP quota check (anonymous uploads only)
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        var ipCheck = ipQuota.check(rateLimit.getIp(req), file.size, config.publicIpQuotaBytes);
        if (!ipCheck.allowed) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-IP quota exceeded", req: req });
          return res.status(400).json({ error: "Upload quota exceeded. Try again later." });
        }
      }

      var ext = path.extname(file.filename).toLowerCase();
      const fileShareId = generateShareId();
      const storagePath = "bundles/" + bundle.shareId + "/" + Date.now() + "-" + fileShareId + ext;
      var checksum = sha3Hash(file.data);
      var saved = await storage.saveFile(file.data, storagePath);

      try {
        filesRepo.create({
          shareId: fileShareId,
          bundleId: bundle._id,
          bundleShareId: bundle.shareId,
          originalName: file.filename, relativePath: fields.relativePath || file.filename,
          storagePath: storagePath, mimeType: file.mimetype, size: file.size,
          checksum: checksum, encryptionKey: saved.encryptionKey,
          uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
          downloads: 0, status: "complete",
          createdAt: new Date().toISOString(),
          expiresAt: config.fileExpiryDays > 0 ? new Date(Date.now() + config.fileExpiryDays * 86400000).toISOString() : null,
        });
      } catch (dbErr) {
        await storage.deleteFile(storagePath);
        throw dbErr;
      }

      // Track IP usage after successful save
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        ipQuota.record(rateLimit.getIp(req), file.size);
      }

      audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: "file: " + file.filename + ", size: " + file.size, req: req });

      bundlesRepo.update(bundle._id, {
        $set: { receivedFiles: bundle.receivedFiles + 1, totalSize: bundle.totalSize + file.size },
      });

      res.json({ success: true, received: bundle.receivedFiles + 1, total: bundle.expectedFiles });
    } catch (e) {
      logger.error("Drop file error", { error: e.message || String(e) });
      res.status(500).json({ error: "Upload failed." });
    }
  });

  // Chunked upload — for large files split client-side
  // POST /drop/chunk/:bundleId with fields: chunkIndex, totalChunks, fileId, relativePath, filename
  app.post("/drop/chunk/:bundleId", rateLimit.middleware("chunk", 500, 60000), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) return res.status(403).json({ error: "Disabled." });
    try {
      const bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });

      const { fields, files: uploaded } = await parseMultipart(req, config.maxFileSize);
      const chunk = uploaded[0];
      if (!chunk) return res.status(400).json({ error: "No chunk." });

      var chunkIndex = parseInt(fields.chunkIndex, 10);
      var totalChunks = parseInt(fields.totalChunks, 10);
      var fileId = String(fields.fileId || "");
      if (isNaN(chunkIndex) || isNaN(totalChunks) || !fileId) {
        return res.status(400).json({ error: "Missing chunk metadata." });
      }
      // Validate chunk parameters (fileId format, chunkIndex range, totalChunks cap)
      var chunkCheck = uploadValidator.validateChunk(chunkIndex, totalChunks, fileId);
      if (!chunkCheck.valid) {
        return res.status(400).json({ error: chunkCheck.reason });
      }
      // Additional path traversal guard for fileId with underscores/hyphens
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(fileId)) {
        return res.status(400).json({ error: "Invalid file ID." });
      }

      // Store chunk to temp path
      var chunkDir = path.join(config.storage.uploadDir, "chunks", bundle.shareId, fileId);
      var fs = require("fs");
      // Verify resolved path is within upload directory
      var resolvedDir = path.resolve(chunkDir);
      var resolvedBase = path.resolve(config.storage.uploadDir);
      if (!resolvedDir.startsWith(resolvedBase)) {
        return res.status(400).json({ error: "Invalid path." });
      }
      if (!fs.existsSync(chunkDir)) fs.mkdirSync(chunkDir, { recursive: true });
      fs.writeFileSync(path.join(chunkDir, String(chunkIndex)), chunk.data);

      // Check if all chunks received
      var received = fs.readdirSync(chunkDir).length;
      if (received < totalChunks) {
        return res.json({ success: true, chunksReceived: received, totalChunks: totalChunks });
      }

      // Storage quota check
      var estimatedSize = 0;
      for (var ce = 0; ce < totalChunks; ce++) {
        try { estimatedSize += require("fs").statSync(path.join(chunkDir, String(ce))).size; } catch (_e) {}
      }
      try {
        bundleService.checkStorageQuota(estimatedSize, config.storageQuotaBytes);
      } catch (quotaErr) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: storage quota exceeded (chunked)", req: req });
        return res.status(400).json({ error: quotaErr.message });
      }

      // Per-user quota check (chunked)
      if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
        var estimatedChunkedSize = 0;
        for (var ce2 = 0; ce2 < totalChunks; ce2++) {
          try { estimatedChunkedSize += require("fs").statSync(path.join(chunkDir, String(ce2))).size; } catch (_e) {}
        }
        var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
        var userTotal = 0;
        for (var ui = 0; ui < userFiles.length; ui++) { userTotal += Number(userFiles[ui].size) || 0; }
        if (userTotal + estimatedChunkedSize > config.perUserQuotaBytes) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-user quota exceeded (chunked), user: " + bundle.ownerId, req: req });
          return res.status(400).json({ error: "Personal storage quota exceeded." });
        }
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

      // Process like a normal file
      var filename = fields.filename || "file";
      var relativePath = fields.relativePath || filename;
      var ext = path.extname(filename).toLowerCase();
      var fileCheck = uploadValidator.validateFile(filename, fullData.length, config.allowedExtensions, config.maxFileSize);
      if (!fileCheck.valid) {
        return res.status(400).json({ error: fileCheck.reason });
      }
      var magicCheck = uploadValidator.validateMagicBytes(filename, fullData);
      if (!magicCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + " (chunked)", req: req });
        return res.status(400).json({ error: magicCheck.reason });
      }

      // Per-IP quota check (chunked, anonymous)
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        var ipCheck = ipQuota.check(rateLimit.getIp(req), fullData.length, config.publicIpQuotaBytes);
        if (!ipCheck.allowed) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-IP quota exceeded (chunked)", req: req });
          return res.status(400).json({ error: "Upload quota exceeded. Try again later." });
        }
      }

      var chunkFileShareId = generateShareId();
      var storagePath = "bundles/" + bundle.shareId + "/" + Date.now() + "-" + chunkFileShareId + ext;
      var checksum = sha3Hash(fullData);
      var saved = await storage.saveFile(fullData, storagePath);

      try {
        filesRepo.create({
          shareId: chunkFileShareId,
          bundleId: bundle._id,
          bundleShareId: bundle.shareId,
          originalName: filename, relativePath: relativePath,
          storagePath: storagePath, mimeType: fields.mimeType || "application/octet-stream",
          size: fullData.length, checksum: checksum, encryptionKey: saved.encryptionKey,
          uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
          downloads: 0, status: "complete",
          createdAt: new Date().toISOString(),
          expiresAt: bundle.expiresAt || null,
        });
      } catch (dbErr) {
        await storage.deleteFile(storagePath);
        throw dbErr;
      }

      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        ipQuota.record(rateLimit.getIp(req), fullData.length);
      }

      bundlesRepo.update(bundle._id, {
        $set: { receivedFiles: bundle.receivedFiles + 1, totalSize: bundle.totalSize + fullData.length },
      });

      audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: "chunked file: " + filename + ", size: " + fullData.length + ", chunks: " + totalChunks, req: req });
      res.json({ success: true, assembled: true, received: bundle.receivedFiles + 1 });
    } catch (e) {
      logger.error("Chunk upload error", { error: e.message || String(e) });
      res.status(500).json({ error: "Chunk upload failed." });
    }
  });

  // Finalize bundle (requires token from init to prevent unauthorized finalization)
  app.post("/drop/finalize/:bundleId", rateLimit.middleware("finalize", 20, 60000), requireScope("upload"), async (req, res) => {
    // Pre-check: handle already-complete bundles before parsing body
    var existingBundle = bundlesRepo.findById(req.params.bundleId);
    if (!existingBundle) return res.status(404).json({ error: "Bundle not found." });
    if (existingBundle.status === "complete") {
      return res.json({ success: true, shareId: existingBundle.shareId, shareUrl: host(req) + "/b/" + existingBundle.shareId, emailSent: false });
    }

    var body = await parseJson(req);
    var token = String(body.finalizeToken || req.query.finalizeToken || "");

    var refreshed;
    try {
      refreshed = bundleService.finalizeBundle(req.params.bundleId, token);
    } catch (err) {
      if (err.statusCode === 403 || err.name === "ForbiddenError") return res.status(403).json({ error: err.message });
      if (err.statusCode === 404 || err.name === "NotFoundError") return res.status(404).json({ error: err.message });
      return res.status(400).json({ error: err.message });
    }

    const bundleUrl = host(req) + "/b/" + refreshed.shareId;
    let emailSent = false;

    if (refreshed.receivedFiles > 0) {
      const uploadedFiles = filesRepo.findAll({ bundleShareId: refreshed.shareId, status: "complete" })
        .map(f => ({ path: f.relativePath || f.originalName, size: f.size }));

      const emailData = {
        uploaderName: refreshed.uploaderName || "Anonymous", uploaderEmail: refreshed.uploaderEmail, bundleUrl,
        uploadedCount: refreshed.receivedFiles, uploadedFiles,
        skippedCount: refreshed.skippedCount || 0, skippedFiles: refreshed.skippedFiles || [],
        totalSize: refreshed.totalSize,
      };

      if (refreshed.uploaderEmail) {
        // Support comma-separated multiple recipients
        var recipients = refreshed.uploaderEmail.split(",").map(function(e) { return e.trim(); }).filter(Boolean);
        recipients.forEach(function(r) { emailService.sendUploaderConfirmation({ to: r, ...emailData }).catch(function(e) { var logger = require("../app/shared/logger"); logger.error("Email send failed", { error: e.message }); }); });
        emailSent = true;
      }
      var adminUsers = usersRepo.findAll({ role: "admin" }).map(function(u) { return u.email; }).filter(Boolean);
      if (adminUsers.length > 0) {
        emailService.sendAdminNotification({ adminEmails: adminUsers, ...emailData }).catch(function(e) { var logger = require("../app/shared/logger"); logger.error("Email send failed", { error: e.message }); });
      }
    }

    webhook.fire("bundle_finalized", { shareId: refreshed.shareId, uploaderName: refreshed.uploaderName || "Anonymous", files: refreshed.receivedFiles, size: refreshed.totalSize });

    audit.log(audit.ACTIONS.BUNDLE_FINALIZED, { targetId: existingBundle._id, targetEmail: refreshed.uploaderEmail, details: "files: " + refreshed.receivedFiles + ", size: " + refreshed.totalSize + ", emailSent: " + emailSent, req: req });
    res.json({ success: true, shareId: refreshed.shareId, shareUrl: bundleUrl, emailSent });
  });
};
