/**
 * Customer Stash routes — branded upload portals.
 * Public routes for stash page rendering and uploads.
 * Admin routes for CRUD management.
 */
var path = require("path");
var config = require("../lib/config");
var { sha3Hash, generateShareId, hashPassword, verifyPassword } = require("../lib/crypto");
var stashRepo = require("../app/data/repositories/stash.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var usersRepo = require("../app/data/repositories/users.repo");
var { parseMultipart, parseJson } = require("../lib/multipart");
var storage = require("../lib/storage");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var webhook = require("../app/domain/integrations/webhook.service");
var rateLimit = require("../lib/rate-limit");
var bundleService = require("../app/domain/uploads/bundle.service");
var uploadValidator = require("../app/http/validators/upload.validator");
var emailService = require("../app/domain/integrations/email.service");
var requireAdmin = require("../middleware/require-admin");
var ipQuota = require("../lib/ip-quota");
var { sanitizeFilename } = require("../app/shared/sanitize-filename");

module.exports = function (app) {

  // ---- Public routes ----

  // Render stash upload page
  app.get("/stash/:slug", function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") {
      return send(res, "error", { user: req.user || null, title: "Not Found", message: "This page doesn't exist or has been disabled." }, 404);
    }

    // Password protection check
    if (stash.passwordHash && !req.session["stashUnlocked_" + slug]) {
      return send(res, "bundle-locked", {
        user: req.user || null,
        shareId: stash.slug,
        unlockAction: "/stash/" + stash.slug + "/unlock",
        title: stash.title || config.dropTitle,
      });
    }

    // Parse stash overrides
    var maxFileSize = (stash.maxFileSize && stash.maxFileSize > 0) ? stash.maxFileSize : config.maxFileSize;
    var maxFiles = (stash.maxFiles && stash.maxFiles > 0) ? stash.maxFiles : config.publicMaxFiles;
    var maxBundleSize = (stash.maxBundleSize && stash.maxBundleSize > 0) ? stash.maxBundleSize : config.publicMaxBundleSize;
    var allowedExtensions = stash.allowedExtensions ? stash.allowedExtensions.split(",").map(function (e) { return e.trim(); }).filter(Boolean) : config.allowedExtensions;

    send(res, "public-upload", {
      user: req.user,
      maxSize: maxFileSize,
      maxFiles: maxFiles,
      maxBundleSize: maxBundleSize,
      allowedExtensions: allowedExtensions,
      uploadTimeout: config.uploadTimeout,
      uploadConcurrency: config.uploadConcurrency,
      uploadRetries: config.uploadRetries,
      dropTitle: stash.title || config.dropTitle,
      dropSubtitle: stash.subtitle || config.dropSubtitle,
      stashMode: true,
      stashSlug: stash.slug,
      stashAccentColor: stash.accentColor || "",
      stashLogoUrl: stash.logoUrl || "",
      vaultEnabled: false,
      vaultPublicKey: null,
    });
  });

  // Stash password unlock
  app.post("/stash/:slug/unlock", rateLimit.middleware("stash-unlock", 10, 900000), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") return res.status(404).json({ error: "Not found." });

    var body = await parseJson(req);
    var password = String(body.password || "");

    if (!stash.passwordHash) {
      req.session["stashUnlocked_" + slug] = true;
      return res.json({ success: true });
    }

    var valid = await verifyPassword(password, stash.passwordHash);
    if (valid) {
      req.session["stashUnlocked_" + slug] = true;
      return res.json({ success: true });
    }

    return res.status(401).json({ error: "Incorrect password." });
  });

  // Init bundle from stash page
  app.post("/stash/:slug/init", rateLimit.middleware("drop-init", 20, 60000), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") return res.status(404).json({ error: "Not found." });

    // If password-protected, verify session unlocked
    if (stash.passwordHash && !req.session["stashUnlocked_" + slug]) {
      return res.status(403).json({ error: "Stash page is locked." });
    }

    var body = await parseJson(req);
    var expiryDays = (stash.defaultExpiry && stash.defaultExpiry > 0) ? stash.defaultExpiry : config.fileExpiryDays;

    var result = await bundleService.initBundle({
      uploaderName: stash.name || "Anonymous",
      uploaderEmail: null,
      ownerId: null,
      password: null,
      message: body.message || null,
      bundleName: body.bundleName || null,
      expiryDays: expiryDays,
      defaultExpiryDays: config.fileExpiryDays,
      fileCount: body.fileCount,
      skippedCount: body.skippedCount,
      skippedFiles: body.skippedFiles,
    });

    // Set stashId on the bundle
    bundlesRepo.update(result.bundleId, { $set: { stashId: stash._id } });

    audit.log(audit.ACTIONS.BUNDLE_INITIALIZED, { targetId: result.bundleId, details: "stash: " + stash.slug + ", expected: " + (body.fileCount || 0), req: req });
    res.json({ bundleId: result.bundleId, shareId: result.shareId, finalizeToken: result.finalizeToken });
  });

  // Upload single file to stash bundle
  app.post("/stash/:slug/file/:bundleId", rateLimit.middleware("upload", 200, 60000), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") return res.status(404).json({ error: "Not found." });
    if (stash.passwordHash && !req.session["stashUnlocked_" + slug]) return res.status(403).json({ error: "Stash page is locked." });

    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });
      if (bundle.stashId !== stash._id) return res.status(403).json({ error: "Bundle does not belong to this stash." });

      // Stash overrides
      var maxFileSize = (stash.maxFileSize && stash.maxFileSize > 0) ? stash.maxFileSize : config.maxFileSize;
      var maxFiles = (stash.maxFiles && stash.maxFiles > 0) ? stash.maxFiles : config.publicMaxFiles;
      var maxBundleSize = (stash.maxBundleSize && stash.maxBundleSize > 0) ? stash.maxBundleSize : config.publicMaxBundleSize;
      var allowedExtensions = stash.allowedExtensions ? stash.allowedExtensions.split(",").map(function (e) { return e.trim(); }).filter(Boolean) : config.allowedExtensions;

      var parsed = await parseMultipart(req, maxFileSize);
      var fields = parsed.fields;
      var file = parsed.files[0];
      if (!file) return res.status(400).json({ error: "No file." });

      // Validate file extension and size
      var fileCheck = uploadValidator.validateFile(file.filename, file.size, allowedExtensions, maxFileSize);
      if (!fileCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + fileCheck.reason + ", stash: " + slug, req: req });
        return res.status(400).json({ error: fileCheck.reason });
      }

      // Validate file content matches claimed extension
      try {
        var magicCheck = uploadValidator.validateMagicBytes(file.filename, file.data);
        if (!magicCheck.valid) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + ", stash: " + slug, req: req });
          return res.status(400).json({ error: magicCheck.reason });
        }
      } catch (_magicErr) { logger.error("Magic byte validation error", { file: file.filename, error: _magicErr.message }); }

      // Validate bundle limits
      var limitsCheck = uploadValidator.validateBundleLimits(bundle.receivedFiles + 1, maxFiles, bundle.totalSize + file.size, maxBundleSize);
      if (!limitsCheck.valid) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + limitsCheck.reason + ", stash: " + slug, req: req });
        return res.status(400).json({ error: limitsCheck.reason });
      }

      // Storage quota check
      try {
        bundleService.checkStorageQuota(file.size, config.storageQuotaBytes);
      } catch (quotaErr) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: storage quota exceeded, stash: " + slug, req: req });
        return res.status(400).json({ error: quotaErr.message });
      }

      // Per-user quota check (if an authenticated user uploads through a stash page)
      if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
        var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
        var userTotal = 0;
        for (var ui = 0; ui < userFiles.length; ui++) { userTotal += Number(userFiles[ui].size) || 0; }
        if (userTotal + file.size > config.perUserQuotaBytes) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-user quota exceeded, stash: " + slug, req: req });
          return res.status(400).json({ error: "Personal storage quota exceeded." });
        }
      }

      // Per-IP quota check (anonymous stash uploads)
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        var ipCheck = ipQuota.check(rateLimit.getIp(req), file.size, config.publicIpQuotaBytes);
        if (!ipCheck.allowed) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-IP quota exceeded, stash: " + slug, req: req });
          return res.status(400).json({ error: "Upload quota exceeded. Try again later." });
        }
      }

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
          uploadedBy: "public", uploaderEmail: null,
          downloads: 0, status: "complete",
          createdAt: new Date().toISOString(),
          expiresAt: bundle.expiresAt || null,
        });
      } catch (dbErr) {
        await storage.deleteFile(storagePath);
        throw dbErr;
      }

      // Track IP usage after successful save (anonymous only)
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        ipQuota.record(rateLimit.getIp(req), file.size);
      }

      audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: "file: " + file.filename + ", size: " + file.size + ", stash: " + slug, req: req });

      bundlesRepo.update(bundle._id, {
        $set: { receivedFiles: bundle.receivedFiles + 1, totalSize: bundle.totalSize + file.size },
      });

      res.json({ success: true, received: bundle.receivedFiles + 1, total: bundle.expectedFiles });
    } catch (e) {
      logger.error("Stash file upload error", { error: e.message || String(e), stash: slug });
      res.status(500).json({ error: "Upload failed." });
    }
  });

  // Chunked upload for stash
  app.post("/stash/:slug/chunk/:bundleId", rateLimit.middleware("chunk", 500, 60000), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") return res.status(404).json({ error: "Not found." });
    if (stash.passwordHash && !req.session["stashUnlocked_" + slug]) return res.status(403).json({ error: "Stash page is locked." });

    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });
      if (bundle.stashId !== stash._id) return res.status(403).json({ error: "Bundle does not belong to this stash." });

      // Stash overrides
      var maxFileSize = (stash.maxFileSize && stash.maxFileSize > 0) ? stash.maxFileSize : config.maxFileSize;
      var maxFiles = (stash.maxFiles && stash.maxFiles > 0) ? stash.maxFiles : config.publicMaxFiles;
      var maxBundleSize = (stash.maxBundleSize && stash.maxBundleSize > 0) ? stash.maxBundleSize : config.publicMaxBundleSize;
      var allowedExtensions = stash.allowedExtensions ? stash.allowedExtensions.split(",").map(function (e) { return e.trim(); }).filter(Boolean) : config.allowedExtensions;

      var parsed = await parseMultipart(req, maxFileSize);
      var fields = parsed.fields;
      var chunk = parsed.files[0];
      if (!chunk) return res.status(400).json({ error: "No chunk." });

      var chunkIndex = parseInt(fields.chunkIndex, 10);
      var totalChunks = parseInt(fields.totalChunks, 10);
      var fileId = String(fields.fileId || "");
      if (isNaN(chunkIndex) || isNaN(totalChunks) || !fileId) {
        return res.status(400).json({ error: "Missing chunk metadata." });
      }
      var chunkCheck = uploadValidator.validateChunk(chunkIndex, totalChunks, fileId);
      if (!chunkCheck.valid) {
        return res.status(400).json({ error: chunkCheck.reason });
      }
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(fileId)) {
        return res.status(400).json({ error: "Invalid file ID." });
      }

      // Early extension validation (reject disallowed types before writing any chunks to disk)
      var earlyFilename = fields.filename || "file";
      var earlyExt = path.extname(earlyFilename).toLowerCase();
      if (earlyExt && allowedExtensions && allowedExtensions.length > 0 && !allowedExtensions.includes(earlyExt)) {
        return res.status(400).json({ error: "File type not allowed: " + earlyExt });
      }

      // Store chunk to temp path
      var fs = require("fs");
      var chunkDir = path.join(config.storage.uploadDir, "chunks", bundle.shareId, fileId);
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
        try { estimatedSize += fs.statSync(path.join(chunkDir, String(ce))).size; } catch (_e) {}
      }
      try {
        bundleService.checkStorageQuota(estimatedSize, config.storageQuotaBytes);
      } catch (quotaErr) {
        audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: storage quota exceeded (chunked), stash: " + slug, req: req });
        return res.status(400).json({ error: quotaErr.message });
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
      var fileCheck = uploadValidator.validateFile(filename, fullData.length, allowedExtensions, maxFileSize);
      if (!fileCheck.valid) {
        return res.status(400).json({ error: fileCheck.reason });
      }
      try {
        var magicCheck = uploadValidator.validateMagicBytes(filename, fullData);
        if (!magicCheck.valid) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + " (chunked), stash: " + slug, req: req });
          return res.status(400).json({ error: magicCheck.reason });
        }
      } catch (_magicErr) { logger.error("Magic byte validation error (chunked)", { file: filename, error: _magicErr.message }); }

      // Per-user quota check (chunked, stash)
      if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
        var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
        var userTotal = 0;
        for (var ui = 0; ui < userFiles.length; ui++) { userTotal += Number(userFiles[ui].size) || 0; }
        if (userTotal + fullData.length > config.perUserQuotaBytes) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-user quota exceeded (chunked), stash: " + slug, req: req });
          return res.status(400).json({ error: "Personal storage quota exceeded." });
        }
      }

      // Per-IP quota check (chunked, stash)
      if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
        var ipCheck = ipQuota.check(rateLimit.getIp(req), fullData.length, config.publicIpQuotaBytes);
        if (!ipCheck.allowed) {
          audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: per-IP quota exceeded (chunked), stash: " + slug, req: req });
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
          originalName: sanitizeFilename(filename),
          relativePath: sanitizeFilename(relativePath, 500),
          storagePath: storagePath, mimeType: fields.mimeType || "application/octet-stream",
          size: fullData.length, checksum: checksum, encryptionKey: saved.encryptionKey,
          uploadedBy: "public", uploaderEmail: null,
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

      audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: "chunked file: " + filename + ", size: " + fullData.length + ", chunks: " + totalChunks + ", stash: " + slug, req: req });
      res.json({ success: true, assembled: true, received: bundle.receivedFiles + 1 });
    } catch (e) {
      logger.error("Stash chunk upload error", { error: e.message || String(e), stash: slug });
      res.status(500).json({ error: "Chunk upload failed." });
    }
  });

  // Finalize stash bundle
  app.post("/stash/:slug/finalize/:bundleId", rateLimit.middleware("finalize", 20, 60000), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") return res.status(404).json({ error: "Not found." });
    if (stash.passwordHash && !req.session["stashUnlocked_" + slug]) return res.status(403).json({ error: "Stash page is locked." });

    var existingBundle = bundlesRepo.findById(req.params.bundleId);
    if (!existingBundle) return res.status(404).json({ error: "Bundle not found." });
    if (existingBundle.stashId !== stash._id) return res.status(403).json({ error: "Bundle does not belong to this stash." });
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

    var bundleUrl = host(req) + "/b/" + refreshed.shareId;
    var emailSent = false;

    // Update stash stats (re-read to get current values since fields are sealed)
    var freshStash = stashRepo.findById(stash._id);
    stashRepo.update(stash._id, { $set: {
      bundleCount: (parseInt(freshStash.bundleCount, 10) || 0) + 1,
      totalBytes: (parseInt(freshStash.totalBytes, 10) || 0) + (refreshed.totalSize || 0),
    }});

    if (refreshed.receivedFiles > 0) {
      var uploadedFiles = filesRepo.findAll({ bundleShareId: refreshed.shareId, status: "complete" })
        .map(function (f) { return { path: f.relativePath || f.originalName, size: f.size }; });

      var emailData = {
        uploaderName: stash.name || "Anonymous", uploaderEmail: null, bundleUrl: bundleUrl,
        uploadedCount: refreshed.receivedFiles, uploadedFiles: uploadedFiles,
        skippedCount: refreshed.skippedCount || 0, skippedFiles: refreshed.skippedFiles || [],
        totalSize: refreshed.totalSize,
      };

      // Notify admins about stash upload
      var adminUsers = usersRepo.findAll({ role: "admin" }).map(function (u) { return u.email; }).filter(Boolean);
      if (adminUsers.length > 0) {
        emailService.sendAdminNotification({ adminEmails: adminUsers, ...emailData }).catch(function (e) { logger.error("Email send failed", { error: e.message }); });
      }
    }

    webhook.fire("bundle_finalized", { shareId: refreshed.shareId, uploaderName: stash.name || "Anonymous", files: refreshed.receivedFiles, size: refreshed.totalSize, stashSlug: slug });

    audit.log(audit.ACTIONS.BUNDLE_FINALIZED, { targetId: existingBundle._id, details: "files: " + refreshed.receivedFiles + ", size: " + refreshed.totalSize + ", stash: " + slug + ", emailSent: " + emailSent, req: req });
    res.json({ success: true, shareId: refreshed.shareId, shareUrl: bundleUrl, emailSent: emailSent });
  });

  // ---- Admin routes ----

  // Stash management page
  app.get("/admin/stash", function (req, res) {
    if (!requireAdmin(req, res)) return;
    send(res, "admin-stash", { user: req.user });
  });

  // List all stash pages
  app.get("/admin/stash/api", function (req, res) {
    if (!requireAdmin(req, res)) return;
    var pages = stashRepo.findAll().map(function (p) {
      return {
        _id: p._id,
        slug: p.slug,
        name: p.name,
        title: p.title,
        subtitle: p.subtitle,
        accentColor: p.accentColor,
        logoUrl: p.logoUrl,
        hasPassword: !!p.passwordHash,
        maxFileSize: p.maxFileSize,
        maxFiles: p.maxFiles,
        maxBundleSize: p.maxBundleSize,
        defaultExpiry: p.defaultExpiry,
        allowedExtensions: p.allowedExtensions,
        enabled: p.enabled === "true",
        bundleCount: p.bundleCount || 0,
        totalBytes: p.totalBytes || 0,
        createdAt: p.createdAt,
      };
    });
    res.json({ pages: pages });
  });

  // List bundles for a stash page
  app.get("/admin/stash/:id/bundles", function (req, res) {
    if (!requireAdmin(req, res)) return;
    var stash = stashRepo.findById(req.params.id);
    if (!stash) return res.status(404).json({ error: "Stash page not found." });
    var allBundles = bundlesRepo.findAll({}).filter(function (b) { return b.stashId === stash._id && b.status === "complete"; });
    var result = allBundles.map(function (b) {
      var bundleFiles = filesRepo.findByBundleShareId(b.shareId);
      return {
        _id: b._id,
        shareId: b.shareId,
        uploaderName: b.uploaderName,
        bundleName: b.bundleName,
        message: b.message,
        receivedFiles: b.receivedFiles || 0,
        totalSize: b.totalSize || 0,
        downloads: b.downloads || 0,
        createdAt: b.createdAt,
        fileCount: bundleFiles.length,
      };
    });
    res.json({ bundles: result, total: result.length });
  });

  // List files for a stash bundle
  app.get("/admin/stash/:id/bundles/:bundleId/files", function (req, res) {
    if (!requireAdmin(req, res)) return;
    var stash = stashRepo.findById(req.params.id);
    if (!stash) return res.status(404).json({ error: "Stash page not found." });
    var bundle = bundlesRepo.findById(req.params.bundleId);
    if (!bundle || bundle.stashId !== stash._id) return res.status(404).json({ error: "Bundle not found." });
    var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
    var result = bundleFiles.map(function (f) {
      return {
        _id: f._id,
        shareId: f.shareId,
        originalName: f.originalName,
        relativePath: f.relativePath,
        mimeType: f.mimeType,
        size: f.size || 0,
        downloads: f.downloads || 0,
        createdAt: f.createdAt,
      };
    });
    res.json({ files: result, total: result.length });
  });

  // Delete a stash bundle (and its files)
  app.post("/admin/stash/:id/bundles/:bundleId/delete", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) return res.status(404).json({ error: "Stash page not found." });
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.stashId !== stash._id) return res.status(404).json({ error: "Bundle not found." });
      var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
      for (var i = 0; i < bundleFiles.length; i++) {
        if (bundleFiles[i].storagePath) { try { await storage.deleteFile(bundleFiles[i].storagePath); } catch (_e) {} }
        filesRepo.remove(bundleFiles[i]._id);
      }
      // Decrement stash stats
      stashRepo.update(stash._id, { $set: {
        bundleCount: Math.max(0, (parseInt(stash.bundleCount, 10) || 0) - 1),
        totalBytes: Math.max(0, (parseInt(stash.totalBytes, 10) || 0) - (bundle.totalSize || 0)),
      }});
      bundlesRepo.remove(bundle._id);
      audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, details: "stash bundle deleted, stash: " + stash.slug + ", files: " + bundleFiles.length, req: req });
      res.json({ success: true, filesDeleted: bundleFiles.length });
    } catch (e) {
      logger.error("Stash bundle delete error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to delete bundle." });
    }
  });

  // Create stash page
  app.post("/admin/stash/create", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var name = String(body.name || "").trim().slice(0, 200);
      var slug = String(body.slug || "").trim().toLowerCase().slice(0, 50);

      if (!name) return res.status(400).json({ error: "Name is required." });
      if (!slug) return res.status(400).json({ error: "Slug is required." });
      if (slug.length < 2) return res.status(400).json({ error: "Slug must be at least 2 characters." });

      // Validate slug format
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(slug)) {
        return res.status(400).json({ error: "Slug must be lowercase alphanumeric with optional hyphens (no leading/trailing hyphens)." });
      }
      if (slug.includes("--")) {
        return res.status(400).json({ error: "Slug cannot contain consecutive hyphens." });
      }

      // Check against reserved route slugs
      var reserved = app.getReservedSlugs();
      if (reserved.has(slug)) {
        return res.status(400).json({ error: "This slug is reserved by the system." });
      }

      // Check uniqueness
      if (stashRepo.findBySlug(slug)) {
        return res.status(400).json({ error: "A stash page with this slug already exists." });
      }

      var passwordHash = null;
      if (body.password && String(body.password).trim()) {
        passwordHash = await hashPassword(String(body.password).trim());
      }

      var doc = {
        slug: slug,
        name: name,
        title: String(body.title || "").trim().slice(0, 200),
        subtitle: String(body.subtitle || "").trim().slice(0, 1000),
        accentColor: (function(c) { c = String(c || "").trim(); return /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : ""; })(body.accentColor),
        logoUrl: (function(u) { u = String(u || "").trim().slice(0, 500); return (u && !u.startsWith("https://") && !u.startsWith("/")) ? "" : u; })(body.logoUrl),
        passwordHash: passwordHash,
        maxFileSize: parseInt(body.maxFileSize, 10) || 0,
        maxFiles: parseInt(body.maxFiles, 10) || 0,
        maxBundleSize: parseInt(body.maxBundleSize, 10) || 0,
        defaultExpiry: parseInt(body.defaultExpiry, 10) || 0,
        allowedExtensions: String(body.allowedExtensions || "").trim().slice(0, 1000),
        enabled: "true",
        createdBy: req.user._id,
        bundleCount: 0,
        totalBytes: 0,
        createdAt: new Date().toISOString(),
      };

      var created = stashRepo.create(doc);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page created: " + slug, req: req });
      res.json({ success: true, stash: { _id: created._id, slug: created.slug, name: created.name } });
    } catch (e) {
      logger.error("Stash create error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to create stash page." });
    }
  });

  // Update stash page
  app.post("/admin/stash/:id/update", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) return res.status(404).json({ error: "Stash page not found." });

      var body = await parseJson(req);
      var updates = {};

      if (body.name !== undefined) updates.name = String(body.name).trim().slice(0, 200);
      if (body.title !== undefined) updates.title = String(body.title).trim().slice(0, 200);
      if (body.subtitle !== undefined) updates.subtitle = String(body.subtitle).trim().slice(0, 1000);
      if (body.accentColor !== undefined) { var c = String(body.accentColor).trim(); updates.accentColor = /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : ""; }
      if (body.logoUrl !== undefined) { var lu = String(body.logoUrl).trim().slice(0, 500); updates.logoUrl = (lu && !lu.startsWith("https://") && !lu.startsWith("/")) ? "" : lu; }
      if (body.maxFileSize !== undefined) updates.maxFileSize = parseInt(body.maxFileSize, 10) || 0;
      if (body.maxFiles !== undefined) updates.maxFiles = parseInt(body.maxFiles, 10) || 0;
      if (body.maxBundleSize !== undefined) updates.maxBundleSize = parseInt(body.maxBundleSize, 10) || 0;
      if (body.defaultExpiry !== undefined) updates.defaultExpiry = parseInt(body.defaultExpiry, 10) || 0;
      if (body.allowedExtensions !== undefined) updates.allowedExtensions = String(body.allowedExtensions).trim().slice(0, 1000);

      // Slug update with validation
      if (body.slug !== undefined) {
        var newSlug = String(body.slug).trim().toLowerCase().slice(0, 50);
        if (newSlug !== stash.slug) {
          if (newSlug.length < 2) return res.status(400).json({ error: "Slug must be at least 2 characters." });
          if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(newSlug)) {
            return res.status(400).json({ error: "Slug must be lowercase alphanumeric with optional hyphens." });
          }
          if (newSlug.includes("--")) {
            return res.status(400).json({ error: "Slug cannot contain consecutive hyphens." });
          }
          var reserved = app.getReservedSlugs();
          if (reserved.has(newSlug)) {
            return res.status(400).json({ error: "This slug is reserved by the system." });
          }
          var existing = stashRepo.findBySlug(newSlug);
          if (existing && existing._id !== stash._id) {
            return res.status(400).json({ error: "A stash page with this slug already exists." });
          }
          updates.slug = newSlug;
        }
      }

      // Password handling: empty string = clear, mask = keep, new value = hash
      if (body.password !== undefined) {
        var pw = String(body.password);
        if (pw === "") {
          updates.passwordHash = null;
        } else if (pw !== "********") {
          updates.passwordHash = await hashPassword(pw.trim());
        }
        // If "********", keep existing — don't include in updates
      }

      stashRepo.update(stash._id, { $set: updates });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page updated: " + (updates.slug || stash.slug), req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Stash update error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to update stash page." });
    }
  });

  // Toggle stash enabled/disabled
  app.post("/admin/stash/:id/toggle", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) return res.status(404).json({ error: "Stash page not found." });
      var newEnabled = stash.enabled === "true" ? "false" : "true";
      stashRepo.update(stash._id, { $set: { enabled: newEnabled } });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page " + (newEnabled === "true" ? "enabled" : "disabled") + ": " + stash.slug, req: req });
      res.json({ success: true, enabled: newEnabled === "true" });
    } catch (e) {
      logger.error("Stash toggle error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to toggle stash page." });
    }
  });

  // Purge all stash pages (for recovery from corrupted data)
  app.post("/admin/stash/purge", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var all = stashRepo.findAll();
      for (var i = 0; i < all.length; i++) { stashRepo.remove(all[i]._id); }
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Purged all stash pages (" + all.length + ")", req: req });
      res.json({ success: true, deleted: all.length });
    } catch (e) {
      res.status(500).json({ error: "Purge failed: " + e.message });
    }
  });

  // Upload stash logo
  var fs = require("fs");
  var STASH_LOGO_DIR = path.join(__dirname, "..", "public", "img", "stash");

  app.post("/admin/stash/:id/logo", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) return res.status(404).json({ error: "Stash page not found." });

      var { files: uploaded } = await parseMultipart(req, 2 * 1024 * 1024);
      var file = uploaded[0];
      if (!file) return res.status(400).json({ error: "No file uploaded." });

      var ext = uploadValidator.detectContentType(file.data);
      if (!ext || [".png", ".jpg", ".gif", ".webp", ".svg"].indexOf(ext) === -1) {
        return res.status(400).json({ error: "Invalid image. Upload a PNG, JPG, SVG, WebP, or GIF." });
      }

      var data = file.data;
      if (ext === ".svg") {
        var { sanitizeSvg } = require("../lib/sanitize-svg");
        var clean = sanitizeSvg(data.toString("utf8"));
        if (!clean || clean.length < 10) return res.status(400).json({ error: "SVG rejected — could not sanitize safely." });
        data = Buffer.from(clean, "utf8");
      }

      if (!fs.existsSync(STASH_LOGO_DIR)) fs.mkdirSync(STASH_LOGO_DIR, { recursive: true });

      // Remove old logo for this stash
      try {
        var existing = fs.readdirSync(STASH_LOGO_DIR);
        existing.forEach(function (f) { if (f.startsWith(stash._id)) fs.unlinkSync(path.join(STASH_LOGO_DIR, f)); });
      } catch (_e) {}

      var filename = stash._id + ext;
      fs.writeFileSync(path.join(STASH_LOGO_DIR, filename), data);

      var logoPath = "/img/stash/" + filename;
      stashRepo.update(stash._id, { $set: { logoUrl: logoPath } });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash logo uploaded: " + stash.slug + " (" + data.length + " bytes)", req: req });
      res.json({ success: true, path: logoPath });
    } catch (e) {
      logger.error("Stash logo upload error", { error: e.message || String(e) });
      res.status(500).json({ error: "Upload failed." });
    }
  });

  // Delete stash page
  app.post("/admin/stash/:id/delete", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) return res.status(404).json({ error: "Stash page not found." });
      stashRepo.remove(stash._id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page deleted: " + stash.slug, req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Stash delete error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to delete stash page." });
    }
  });

};
