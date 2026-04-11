/**
 * Customer Stash routes — branded upload portals.
 * Public routes for stash page rendering and uploads.
 * Admin routes for CRUD management.
 */
var path = require("path");
var config = require("../lib/config");
var { hashPassword, verifyPassword } = require("../lib/crypto");
var stashRepo = require("../app/data/repositories/stash.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var { parseMultipart, parseJson } = require("../lib/multipart");
var storage = require("../lib/storage");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var rateLimit = require("../lib/rate-limit");
var bundleService = require("../app/domain/uploads/bundle.service");
var uploadValidator = require("../app/http/validators/upload.validator");
var requireAdmin = require("../middleware/require-admin");
var { resolveUploadConfig, handleFileUpload, handleChunkUpload, handleFinalize } = require("../app/domain/uploads/upload.handler");

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

    var limits = resolveUploadConfig(stash);

    send(res, "public-upload", {
      user: req.user,
      maxSize: limits.maxFileSize,
      maxFiles: limits.maxFiles,
      maxBundleSize: limits.maxBundleSize,
      allowedExtensions: limits.allowedExtensions,
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

      var limits = resolveUploadConfig(stash);
      var parsed = await parseMultipart(req, limits.maxFileSize);
      var file = parsed.files[0];
      if (!file) return res.status(400).json({ error: "No file." });

      var result = await handleFileUpload({
        bundle: bundle, file: file, fields: parsed.fields, limits: limits,
        uploadedBy: "public", uploaderEmail: null,
        expiresAt: bundle.expiresAt || null,
        auditSuffix: ", stash: " + slug, req: req,
      });
      if (result.error) return res.status(400).json({ error: result.error });
      res.json(result);
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

      var limits = resolveUploadConfig(stash);
      var parsed = await parseMultipart(req, limits.maxFileSize);
      var chunk = parsed.files[0];
      if (!chunk) return res.status(400).json({ error: "No chunk." });

      var result = await handleChunkUpload({
        bundle: bundle, chunk: chunk, fields: parsed.fields, limits: limits,
        uploadedBy: "public", uploaderEmail: null,
        expiresAt: bundle.expiresAt || null,
        auditSuffix: ", stash: " + slug, req: req,
      });
      if (result.error) return res.status(400).json({ error: result.error });
      res.json(result);
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

    var body = await parseJson(req);
    var token = String(body.finalizeToken || req.query.finalizeToken || "");
    var result = handleFinalize({
      bundleId: req.params.bundleId, token: token,
      uploaderName: stash.name || "Anonymous", sendUploaderEmail: false,
      stashSlug: slug, stashId: stash._id,
      auditSuffix: ", stash: " + slug, req: req,
    });
    if (result.error) return res.status(result.status || 400).json({ error: result.error });

    // Update stash stats
    var freshStash = stashRepo.findById(stash._id);
    stashRepo.update(stash._id, { $set: {
      bundleCount: (parseInt(freshStash.bundleCount, 10) || 0) + 1,
      totalBytes: (parseInt(freshStash.totalBytes, 10) || 0) + (result.refreshed ? result.refreshed.totalSize || 0 : 0),
    }});

    res.json({ success: true, shareId: result.shareId, shareUrl: result.shareUrl, emailSent: result.emailSent });
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
