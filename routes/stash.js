/**
 * Customer Stash routes — branded upload portals.
 * Public routes for stash page rendering and uploads.
 * Admin routes for CRUD management.
 */
var b = require("../lib/vendor/blamejs");
var nodePath = require("node:path");
var config = require("../lib/config");
var rateLimit = require("../lib/rate-limit");
var stashRepo = require("../app/data/repositories/stash.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var teamsRepo = require("../app/data/repositories/teams.repo");
var { parseMultipart } = require("../lib/multipart");
var storage = require("../lib/storage");
var { send } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var bundleService = require("../app/domain/uploads/bundle.service");
var uploadValidator = require("../app/http/validators/upload.validator");
var requireAdmin = require("../middleware/require-admin");
var { resolveUploadConfig, handleFileUpload, handleChunkUpload, handleFinalize } = require("../app/domain/uploads/upload.handler");
var { TIME, PATHS, BYTES } = require("../lib/constants");
var { validateEmail } = require("../app/shared/validate");
var nodeFs = require("node:fs");
var { sanitizeSvg } = require("../lib/sanitize-svg");
var apiKeysRepo = require("../app/data/repositories/apiKeys.repo");
var db = require("../lib/db");

// Restrict an admin-supplied logo URL to a same-origin path or an explicit
// https:// origin. Rejects javascript:/data: schemes AND protocol-relative
// "//host" (which slips past a bare leading-slash check and loads external
// content). CSP img-src is the outer gate; this is the storage-boundary belt.
function _safeLogoUrl(u) {
  u = String(u || "").trim().slice(0, 500);
  if (!u || u.startsWith("//")) return "";
  if (u.startsWith("/") || u.startsWith("https://")) return u;
  return "";
}
var mtlsCa = require("../lib/mtls-ca");
var { generateEnrollmentCode, certFingerprintSha3 } = require("../lib/cert-utils");

var { isStashLocked } = require("../middleware/require-access");
var accessCodeService = require("../app/domain/access-code.service");
var { AppError, ValidationError, AuthenticationError, ForbiddenError, NotFoundError } = require("../app/shared/errors");

/**
 * Check if an email matches the stash's allowed list.
 * Supports exact email (alice@example.com) and domain patterns (@example.com).
 */
function emailMatchesAllowedList(email, allowedEmails) {
  if (!allowedEmails) return false;
  var list = allowedEmails.split(",").map(function (e) { return e.trim().toLowerCase(); }).filter(Boolean);
  var emailLower = email.toLowerCase();
  var domain = "@" + emailLower.split("@")[1];
  for (var i = 0; i < list.length; i++) {
    if (list[i] === emailLower) return true;
    if (list[i].startsWith("@") && list[i] === domain) return true;
  }
  return false;
}

// Resolve an optional team assignment for a stash. Returns the canonical team
// _id, or null when none is requested. Throws when a non-empty value names a
// team that does not exist (so a typo can't silently produce an orphan FK that
// no team list will ever surface). Caller is already admin-gated.
function resolveStashTeam(rawTeamId) {
  if (!rawTeamId) return null;
  var team = teamsRepo.findTeamById(String(rawTeamId));
  if (!team) throw new ValidationError("Team not found.");
  return team._id;
}

module.exports = function (app) {

  // ---- Public routes ----

  // Render stash upload page
  app.get("/stash/:slug", function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") {
      return send(res, "error", { user: req.user || null, title: "Not Found", message: "This page doesn't exist or has been disabled." }, 404);
    }

    // Access protection (password, email, or both)
    var locked = isStashLocked(stash, req.session);
    if (locked === "email") {
      return send(res, "bundle-email-gate", {
        user: req.user || null,
        shareId: stash.slug,
        requestCodeAction: "/stash/" + stash.slug + "/request-code",
        verifyCodeAction: "/stash/" + stash.slug + "/verify-code",
      });
    }
    if (locked === "password" || locked === "email-then-password") {
      return send(res, "bundle-locked", {
        user: req.user || null,
        shareId: stash.slug,
        unlockAction: "/stash/" + stash.slug + "/unlock",
        title: stash.title || config.dropTitle,
        emailVerified: locked === "email-then-password",
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
  app.post("/stash/:slug/unlock", rateLimit.guard({ max: 10, windowMs: TIME.minutes(15), algorithm: "fixed-window" }), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");

    var body = (await b.parsers.json(req)) || {};
    var password = String(body.password || "");

    if (!stash.passwordHash) {
      // An email-gated stash carries no password; access is granted ONLY via the
      // email access-code flow (which sets { emailVerified }). Treating a missing
      // password as "unlocked" here would bypass the email gate entirely.
      if (stash.accessMode === "email") {
        throw new ForbiddenError("Email verification required.").withExtras({ requiresEmail: true });
      }
      req.session["stashUnlocked_" + slug] = true;
      return res.json({ success: true });
    }

    var valid = await b.auth.password.verify(stash.passwordHash, password);
    if (valid) {
      var mode = stash.accessMode || "password";
      if (mode === "both") {
        var prev = req.session["stashUnlocked_" + slug];
        if (!prev || typeof prev !== "object" || typeof prev.emailVerified !== "string") {
          throw new ForbiddenError("Email verification required first.").withExtras({ requiresEmail: true });
        }
        req.session["stashUnlocked_" + slug] = { emailVerified: prev.emailVerified, passwordVerified: true };
      } else {
        req.session["stashUnlocked_" + slug] = true;
      }
      return res.json({ success: true });
    }

    throw new AuthenticationError("Incorrect password.");
  });

  // Request email access code for stash page
  app.post("/stash/:slug/request-code", rateLimit.guard({ max: 5, windowMs: TIME.minutes(5), algorithm: "fixed-window" }), async function (req, res) {
    var stash = stashRepo.findBySlug(req.params.slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");

    var body = (await b.parsers.json(req)) || {};
    var email = String(body.email || "").trim().toLowerCase();
    if (!validateEmail(email).valid) throw new ValidationError("Valid email required.");

    var genericMsg = "If this email has access, a code has been sent.";
    var mode = stash.accessMode || "open";
    if (mode !== "email" && mode !== "both") return res.json({ success: true, message: genericMsg });

    // Check if email matches allowed list (supports @domain patterns)
    if (!emailMatchesAllowedList(email, stash.allowedEmails)) {
      return res.json({ success: true, message: genericMsg });
    }

    try {
      var result = await accessCodeService.requestCode({
        shareId: "stash:" + stash._id,
        email: email,
        bundleName: stash.name || stash.title || null,
        senderName: null,
      });
      if (result.sent) {
        audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_SENT, { details: "stash: " + stash.slug, req: req });
      }
    } catch (e) { logger.error("Stash access code email failed", { error: e.message || String(e) }); }

    res.json({ success: true, message: genericMsg });
  });

  // Verify email access code for stash page
  app.post("/stash/:slug/verify-code", rateLimit.guard({ max: 10, windowMs: TIME.minutes(15), algorithm: "fixed-window" }), async function (req, res) {
    var stash = stashRepo.findBySlug(req.params.slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");

    var body = (await b.parsers.json(req)) || {};
    var email = String(body.email || "").trim().toLowerCase();
    var code = String(body.code || "").trim();
    if (!email || !code) throw new ValidationError("Email and code required.");

    var result = accessCodeService.verifyCode({ shareId: "stash:" + stash._id, email: email, code: code });
    if (!result.success) {
      if (result.attempts) {
        audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_FAILED, { details: "stash: " + stash.slug + ", attempts: " + result.attempts, req: req });
      }
      throw new AppError(result.error, result.status || 400);
    }

    var mode = stash.accessMode || "email";
    if (mode === "both") {
      req.session["stashUnlocked_" + stash.slug] = { emailVerified: email, passwordVerified: false };
    } else {
      req.session["stashUnlocked_" + stash.slug] = email;
    }

    audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_VERIFIED, { details: "stash: " + stash.slug + ", email verified", req: req });
    res.json({ success: true, needsPassword: mode === "both" });
  });

  // Init bundle from stash page
  app.post("/stash/:slug/init", rateLimit.guard({ max: 20, windowMs: TIME.minutes(1), algorithm: "fixed-window" }), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");

    // Access check
    if (isStashLocked(stash, req.session)) throw new ForbiddenError("Stash page is locked.");

    // Sync-enabled stash: reuse persistent sync bundle
    if (stash.syncEnabled === "true" && stash.syncBundleId) {
      var syncBundle = bundlesRepo.findById(stash.syncBundleId);
      if (syncBundle && syncBundle.bundleType === "sync") {
        return res.json({ bundleId: syncBundle._id, shareId: syncBundle.shareId, finalizeToken: null, syncMode: true });
      }
    }

    var body = (await b.parsers.json(req)) || {};
    var expiryDays = (stash.defaultExpiry && stash.defaultExpiry > 0) ? stash.defaultExpiry : config.fileExpiryDays;
    var isSyncStash = stash.syncEnabled === "true";

    var result = await bundleService.initBundle({
      uploaderName: stash.name || "Anonymous",
      uploaderEmail: null,
      ownerId: null,
      password: null,
      message: body.message || null,
      bundleName: body.bundleName || null,
      bundleType: isSyncStash ? "sync" : "snapshot",
      expiryDays: isSyncStash ? 0 : expiryDays,
      defaultExpiryDays: config.fileExpiryDays,
      fileCount: body.fileCount,
      skippedCount: body.skippedCount,
      skippedFiles: body.skippedFiles,
      // Team-scoped stash: every upload inherits the team so it surfaces in the
      // team's shared file list. null for an unassigned stash.
      teamId: stash.teamId || null,
    });

    // Set stashId on the bundle
    bundlesRepo.update(result.bundleId, { $set: { stashId: stash._id } });

    // If sync-enabled, associate this as the persistent sync bundle
    if (isSyncStash && !stash.syncBundleId) {
      stashRepo.update(stash._id, { $set: { syncBundleId: result.bundleId } });
    }

    audit.log(audit.ACTIONS.BUNDLE_INITIALIZED, { targetId: result.bundleId, details: "stash: " + stash.slug + ", expected: " + (body.fileCount || 0) + (isSyncStash ? ", sync" : ""), req: req });
    res.json({ bundleId: result.bundleId, shareId: result.shareId, finalizeToken: result.finalizeToken, syncMode: isSyncStash });
  });

  // Upload single file to stash bundle
  app.post("/stash/:slug/file/:bundleId", rateLimit.guard({ max: 200, windowMs: TIME.minutes(1), algorithm: "fixed-window" }), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");
    if (isStashLocked(stash, req.session)) throw new ForbiddenError("Stash page is locked.");

    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || (bundle.status === "complete" && bundle.bundleType !== "sync")) throw new NotFoundError("Bundle not found.");
      if (bundle.stashId !== stash._id) throw new ForbiddenError("Bundle does not belong to this stash.");

      var limits = resolveUploadConfig(stash);
      var parsed = await parseMultipart(req, limits.maxFileSize);
      var file = parsed.files[0];
      if (!file) throw new ValidationError("No file.");

      var result = await handleFileUpload({
        bundle: bundle, file: file, fields: parsed.fields, limits: limits,
        uploadedBy: "public", uploaderEmail: null,
        expiresAt: bundle.expiresAt || null,
        auditSuffix: ", stash: " + slug, req: req,
      });
      if (result.error) throw new ValidationError(result.error);
      res.json(result);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash file upload error", { error: e.message || String(e), stash: slug });
      throw new AppError("Upload failed.", 500, "UPLOAD_FAILED");
    }
  });

  // Chunked upload for stash
  app.post("/stash/:slug/chunk/:bundleId", rateLimit.guard({ max: 500, windowMs: TIME.minutes(1), algorithm: "fixed-window" }), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");
    if (isStashLocked(stash, req.session)) throw new ForbiddenError("Stash page is locked.");

    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || (bundle.status === "complete" && bundle.bundleType !== "sync")) throw new NotFoundError("Bundle not found.");
      if (bundle.stashId !== stash._id) throw new ForbiddenError("Bundle does not belong to this stash.");

      var limits = resolveUploadConfig(stash);
      var parsed = await parseMultipart(req, limits.maxFileSize);
      var chunk = parsed.files[0];
      if (!chunk) throw new ValidationError("No chunk.");

      var result = await handleChunkUpload({
        bundle: bundle, chunk: chunk, fields: parsed.fields, limits: limits,
        uploadedBy: "public", uploaderEmail: null,
        expiresAt: bundle.expiresAt || null,
        auditSuffix: ", stash: " + slug, req: req,
      });
      if (result.error) throw new ValidationError(result.error);
      res.json(result);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash chunk upload error", { error: e.message || String(e), stash: slug });
      throw new AppError("Chunk upload failed.", 500, "CHUNK_UPLOAD_FAILED");
    }
  });

  // Finalize stash bundle
  app.post("/stash/:slug/finalize/:bundleId", rateLimit.guard({ max: 20, windowMs: TIME.minutes(1), algorithm: "fixed-window" }), async function (req, res) {
    var slug = req.params.slug;
    var stash = stashRepo.findBySlug(slug);
    if (!stash || stash.enabled !== "true") throw new NotFoundError("Not found.");
    if (isStashLocked(stash, req.session)) throw new ForbiddenError("Stash page is locked.");

    var existingBundle = bundlesRepo.findById(req.params.bundleId);
    if (!existingBundle) throw new NotFoundError("Bundle not found.");
    if (existingBundle.stashId !== stash._id) throw new ForbiddenError("Bundle does not belong to this stash.");

    var body = (await b.parsers.json(req)) || {};
    var token = String(body.finalizeToken || req.query.finalizeToken || "");
    var result = handleFinalize({
      bundleId: req.params.bundleId, token: token,
      uploaderName: stash.name || "Anonymous", sendUploaderEmail: false,
      stashSlug: slug, stashId: stash._id,
      auditSuffix: ", stash: " + slug, req: req,
    });
    if (result.error) throw new AppError(result.error, result.status || 400);

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
        allowedEmails: p.allowedEmails || "",
        accessMode: p.accessMode || "open",
        syncEnabled: p.syncEnabled === "true",
        syncBundleId: p.syncBundleId || null,
        maxFileSize: p.maxFileSize,
        maxFiles: p.maxFiles,
        maxBundleSize: p.maxBundleSize,
        defaultExpiry: p.defaultExpiry,
        allowedExtensions: p.allowedExtensions,
        teamId: p.teamId || "",
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
    if (!stash) throw new NotFoundError("Stash page not found.");
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
    if (!stash) throw new NotFoundError("Stash page not found.");
    var bundle = bundlesRepo.findById(req.params.bundleId);
    if (!bundle || bundle.stashId !== stash._id) throw new NotFoundError("Bundle not found.");
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
      if (!stash) throw new NotFoundError("Stash page not found.");
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.stashId !== stash._id) throw new NotFoundError("Bundle not found.");
      var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
      for (var i = 0; i < bundleFiles.length; i++) {
        if (bundleFiles[i].storagePath) { try { await storage.deleteFile(bundleFiles[i].storagePath); } catch (_e) { /* cleanup — storage file may already be gone */ } }
        filesRepo.remove(bundleFiles[i]._id);
      }
      // Decrement stash stats
      stashRepo.decrementBundleStats(stash._id, bundle.totalSize);
      bundlesRepo.remove(bundle._id);
      audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, details: "stash bundle deleted, stash: " + stash.slug + ", files: " + bundleFiles.length, req: req });
      res.json({ success: true, filesDeleted: bundleFiles.length });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash bundle delete error", { error: e.message || String(e) });
      throw new AppError("Failed to delete bundle.", 500, "BUNDLE_DELETE_FAILED");
    }
  });

  // Create stash page
  app.post("/admin/stash/create", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var name = String(body.name || "").trim().slice(0, 200);
      var slug = String(body.slug || "").trim().toLowerCase().slice(0, 50);

      if (!name) throw new ValidationError("Name is required.");
      if (!slug) throw new ValidationError("Slug is required.");
      if (slug.length < 2) throw new ValidationError("Slug must be at least 2 characters.");

      // Validate slug format
      if (!/^[a-z0-9][a-z0-9-]*$/.test(slug) || slug.endsWith("-")) {
        throw new ValidationError("Slug must be lowercase alphanumeric with optional hyphens (no leading/trailing hyphens).");
      }
      if (slug.includes("--")) {
        throw new ValidationError("Slug cannot contain consecutive hyphens.");
      }

      // Check against reserved route slugs
      var reserved = app.getReservedSlugs();
      if (reserved.has(slug)) {
        throw new ValidationError("This slug is reserved by the system.");
      }

      // Check uniqueness
      if (stashRepo.findBySlug(slug)) {
        throw new ValidationError("A stash page with this slug already exists.");
      }

      var passwordHash = null;
      if (body.password && String(body.password).trim()) {
        var pw = String(body.password).trim();
        if (pw.length < 4) throw new ValidationError("Password must be at least 4 characters.");
        passwordHash = await b.auth.password.hash(pw);
      }

      // Email-gated access: clean allowed emails/domains
      var allowedEmails = null;
      if (body.allowedEmails) {
        var cleaned = String(body.allowedEmails).split(",")
          .map(function (e) { return e.trim().toLowerCase(); })
          .filter(function (e) { return e && (e.startsWith("@") ? e.length > 1 : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)); });
        if (cleaned.length > 0) allowedEmails = cleaned.join(",");
      }

      var hasPassword = !!passwordHash;
      var hasEmailGate = !!allowedEmails;
      var accessMode = hasPassword && hasEmailGate ? "both" : hasPassword ? "password" : hasEmailGate ? "email" : "open";

      // Optional team assignment: uploads to this stash become visible to the
      // team via GET /teams/:teamId/files. The route is admin-only, so a site
      // admin may assign any existing team; the team must exist.
      var teamId = resolveStashTeam(body.teamId);

      var doc = {
        slug: slug,
        name: name,
        title: String(body.title || "").trim().slice(0, 200),
        subtitle: String(body.subtitle || "").trim().slice(0, 1000),
        accentColor: (function(c) { c = String(c || "").trim(); return /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : ""; })(body.accentColor),
        logoUrl: _safeLogoUrl(body.logoUrl),
        passwordHash: passwordHash,
        allowedEmails: allowedEmails,
        accessMode: accessMode,
        maxFileSize: parseInt(body.maxFileSize, 10) || 0,
        maxFiles: parseInt(body.maxFiles, 10) || 0,
        maxBundleSize: parseInt(body.maxBundleSize, 10) || 0,
        defaultExpiry: parseInt(body.defaultExpiry, 10) || 0,
        allowedExtensions: String(body.allowedExtensions || "").trim().slice(0, 1000),
        teamId: teamId,
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
      if (e.isAppError) throw e;
      logger.error("Stash create error", { error: e.message || String(e) });
      throw new AppError("Failed to create stash page.", 500, "STASH_CREATE_FAILED");
    }
  });

  // Update stash page
  app.post("/admin/stash/:id/update", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");

      var body = (await b.parsers.json(req)) || {};
      var updates = {};

      if (body.name !== undefined) updates.name = String(body.name).trim().slice(0, 200);
      if (body.title !== undefined) updates.title = String(body.title).trim().slice(0, 200);
      if (body.subtitle !== undefined) updates.subtitle = String(body.subtitle).trim().slice(0, 1000);
      if (body.accentColor !== undefined) { var c = String(body.accentColor).trim(); updates.accentColor = /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : ""; }
      if (body.logoUrl !== undefined) updates.logoUrl = _safeLogoUrl(body.logoUrl);
      if (body.maxFileSize !== undefined) updates.maxFileSize = parseInt(body.maxFileSize, 10) || 0;
      if (body.maxFiles !== undefined) updates.maxFiles = parseInt(body.maxFiles, 10) || 0;
      if (body.maxBundleSize !== undefined) updates.maxBundleSize = parseInt(body.maxBundleSize, 10) || 0;
      if (body.defaultExpiry !== undefined) updates.defaultExpiry = parseInt(body.defaultExpiry, 10) || 0;
      if (body.allowedExtensions !== undefined) updates.allowedExtensions = String(body.allowedExtensions).trim().slice(0, 1000);
      // Team assignment: "" clears it, a value (re)assigns to an existing team.
      // Only affects bundles initialized AFTER the change — already-uploaded
      // files keep the team they were uploaded under.
      if (body.teamId !== undefined) updates.teamId = resolveStashTeam(body.teamId);

      // Slug update with validation
      if (body.slug !== undefined) {
        var newSlug = String(body.slug).trim().toLowerCase().slice(0, 50);
        if (newSlug !== stash.slug) {
          if (newSlug.length < 2) throw new ValidationError("Slug must be at least 2 characters.");
          if (!/^[a-z0-9][a-z0-9-]*$/.test(newSlug) || newSlug.endsWith("-")) {
            throw new ValidationError("Slug must be lowercase alphanumeric with optional hyphens.");
          }
          if (newSlug.includes("--")) {
            throw new ValidationError("Slug cannot contain consecutive hyphens.");
          }
          var reserved = app.getReservedSlugs();
          if (reserved.has(newSlug)) {
            throw new ValidationError("This slug is reserved by the system.");
          }
          var existing = stashRepo.findBySlug(newSlug);
          if (existing && existing._id !== stash._id) {
            throw new ValidationError("A stash page with this slug already exists.");
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
          if (pw.trim().length < 4) throw new ValidationError("Password must be at least 4 characters.");
          updates.passwordHash = await b.auth.password.hash(pw.trim());
        }
      }

      // Email-gated access
      if (body.allowedEmails !== undefined) {
        var rawEmails = String(body.allowedEmails).trim();
        if (!rawEmails) {
          updates.allowedEmails = null;
        } else {
          var cleaned = rawEmails.split(",")
            .map(function (e) { return e.trim().toLowerCase(); })
            .filter(function (e) { return e && (e.startsWith("@") ? e.length > 1 : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)); });
          updates.allowedEmails = cleaned.length > 0 ? cleaned.join(",") : null;
        }
      }

      // Sync mode toggle
      if (body.syncEnabled !== undefined) {
        updates.syncEnabled = body.syncEnabled === true || body.syncEnabled === "true" ? "true" : "false";
      }

      // Recompute accessMode from current + updated state
      var finalPassword = updates.passwordHash !== undefined ? updates.passwordHash : stash.passwordHash;
      var finalEmails = updates.allowedEmails !== undefined ? updates.allowedEmails : stash.allowedEmails;
      var hasPass = !!finalPassword;
      var hasEmail = !!finalEmails;
      updates.accessMode = hasPass && hasEmail ? "both" : hasPass ? "password" : hasEmail ? "email" : "open";

      stashRepo.update(stash._id, { $set: updates });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page updated: " + (updates.slug || stash.slug), req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash update error", { error: e.message || String(e) });
      throw new AppError("Failed to update stash page.", 500, "STASH_UPDATE_FAILED");
    }
  });

  // Toggle stash enabled/disabled
  app.post("/admin/stash/:id/toggle", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");
      var newEnabled = stash.enabled === "true" ? "false" : "true";
      stashRepo.update(stash._id, { $set: { enabled: newEnabled } });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page " + (newEnabled === "true" ? "enabled" : "disabled") + ": " + stash.slug, req: req });
      res.json({ success: true, enabled: newEnabled === "true" });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash toggle error", { error: e.message || String(e) });
      throw new AppError("Failed to toggle stash page.", 500, "STASH_TOGGLE_FAILED");
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
      throw new AppError("Purge failed: " + e.message, 500, "STASH_PURGE_FAILED");
    }
  });

  // Upload stash logo — stored in DATA_DIR (writable volume), served via
  // the explicit GET /img/stash/:name route in server.js.
  var STASH_LOGO_DIR = PATHS.STASH_LOGO_DIR;

  app.post("/admin/stash/:id/logo", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");

      var { files: uploaded } = await parseMultipart(req, BYTES.mib(2));
      var file = uploaded[0];
      if (!file) throw new ValidationError("No file uploaded.");

      var ext = uploadValidator.detectContentType(file.data);
      if (!ext || [".gif", ".jpg", ".png", ".svg", ".webp"].indexOf(ext) === -1) {
        throw new ValidationError("Invalid image. Upload a PNG, JPG, SVG, WebP, or GIF.");
      }

      var data = file.data;
      if (ext === ".svg") {
        var clean = sanitizeSvg(data.toString("utf8"));
        if (!clean || clean.length < 10) throw new ValidationError("SVG rejected — could not sanitize safely.");
        data = Buffer.from(clean, "utf8");
      }

      if (!nodeFs.existsSync(STASH_LOGO_DIR)) nodeFs.mkdirSync(STASH_LOGO_DIR, { recursive: true });

      // Remove old logo for this stash
      try {
        var existing = nodeFs.readdirSync(STASH_LOGO_DIR);
        existing.forEach(function (f) { if (f.startsWith(stash._id)) nodeFs.unlinkSync(nodePath.join(STASH_LOGO_DIR, f)); });
      } catch (_e) { /* STASH_LOGO_DIR may not exist on first upload */ }

      var filename = stash._id + ext;
      // Atomic, symlink-refusing write (O_EXCL|O_NOFOLLOW temp + rename) so a
      // pre-planted symlink at the logo path can't redirect the write (CWE-59).
      b.atomicFile.writeExclSync(nodePath.join(STASH_LOGO_DIR, filename), data, { fileMode: 0o600 });

      var logoPath = "/img/stash/" + filename;
      stashRepo.update(stash._id, { $set: { logoUrl: logoPath } });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash logo uploaded: " + stash.slug + " (" + data.length + " bytes)", req: req });
      res.json({ success: true, path: logoPath });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash logo upload error", { error: e.message || String(e) });
      throw new AppError("Upload failed.", 500, "STASH_LOGO_UPLOAD_FAILED");
    }
  });

  // Delete stash page
  app.post("/admin/stash/:id/delete", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");
      stashRepo.remove(stash._id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash page deleted: " + stash.slug, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash delete error", { error: e.message || String(e) });
      throw new AppError("Failed to delete stash page.", 500, "STASH_DELETE_FAILED");
    }
  });

  // Generate a stash-scoped sync token with enrollment code
  app.post("/admin/stash/:id/sync-token", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");

      var rawKey = "hs_" + b.crypto.generateToken(32);
      var prefix = rawKey.substring(0, 7);
      var keyHash = b.crypto.sha3Hash(rawKey);

      apiKeysRepo.create({
        name: "Sync: " + (stash.name || stash.slug),
        keyHash: keyHash,
        prefix: prefix,
        permissions: "sync,upload",
        userId: req.user._id,
        boundStashId: stash._id,
        boundBundleId: null,
        createdAt: new Date().toISOString(),
      });

      // Generate client certificate if CA is available
      var clientCert = null;
      try {
        await mtlsCa.initCA();
        clientCert = await mtlsCa.generateClientCert({ cn: prefix });
        if (clientCert) {
          var createdKey = apiKeysRepo.findOne({ keyHash: keyHash });
          if (createdKey) {
            apiKeysRepo.update(createdKey._id, { $set: {
              certIssuedAt: clientCert.issuedAt,
              certExpiresAt: clientCert.expiresAt,
              certFingerprint: certFingerprintSha3(clientCert.cert),
            }});
          }
        }
      } catch (_e) { /* old key revocation is best-effort — new enrollment still issues */ }

      // Generate enrollment code — short, typeable, one-time use
      var enrollment = generateEnrollmentCode();

      // Store the enrollment record (all sensitive fields vault-sealed by field-crypto)
      db.enrollmentCodes.insert({
        codeHash: enrollment.codeHash,
        apiKey: rawKey,
        clientCert: clientCert ? clientCert.cert : null,
        clientKey: clientCert ? clientCert.key : null,
        caCert: clientCert ? clientCert.ca : null,
        stashId: stash._id,
        bundleId: null,
        createdBy: req.user._id,
        status: "pending",
        expiresAt: new Date(Date.now() + TIME.hours(1)).toISOString(), // 1 hour
        createdAt: new Date().toISOString(),
      });

      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Stash sync enrollment code created: " + stash.slug, req: req });
      res.json({ success: true, enrollmentCode: enrollment.codeRaw, prefix: prefix });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Stash sync token error", { error: e.message || String(e) });
      throw new AppError("Failed to create sync token.", 500, "SYNC_TOKEN_FAILED");
    }
  });

  // List sync API keys for a stash with cert status
  app.get("/admin/stash/:id/sync-keys", function (req, res) {
    if (!requireAdmin(req, res)) return;
    var stash = stashRepo.findById(req.params.id);
    if (!stash) throw new NotFoundError("Stash page not found.");

    var keys = apiKeysRepo.findAll({}).filter(function (k) {
      return k.boundStashId === stash._id && k.permissions && k.permissions.indexOf("sync") !== -1;
    });

    var now = new Date();
    var day30 = new Date(now.getTime() + TIME.days(30));
    var result = keys.map(function (k) {
      var status = "no-cert";
      if (k.certExpiresAt) {
        var exp = new Date(k.certExpiresAt);
        if (exp < now) status = "expired";
        else if (exp < day30) status = "expiring";
        else status = "valid";
      }
      return {
        _id: k._id, prefix: k.prefix, name: k.name,
        certIssuedAt: k.certIssuedAt || null,
        certExpiresAt: k.certExpiresAt || null,
        certStatus: status,
        lastUsed: k.lastUsed || null,
        createdAt: k.createdAt,
      };
    });

    res.json({ keys: result });
  });

  // Re-issue client certificate for an existing API key (repairs broken mTLS without new enrollment)
  app.post("/admin/stash/:id/reissue-cert", rateLimit.guard({ max: 5, windowMs: TIME.minutes(5), algorithm: "fixed-window" }), async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var apiKeyId = body.apiKeyId;
      if (!apiKeyId) throw new ValidationError("apiKeyId required");

      var stash = stashRepo.findById(req.params.id);
      if (!stash) throw new NotFoundError("Stash page not found.");

      var apiKey = apiKeysRepo.findOne({ _id: apiKeyId });
      if (!apiKey) throw new NotFoundError("API key not found.");
      if (apiKey.boundStashId !== stash._id) throw new ForbiddenError("API key does not belong to this stash.");

      await mtlsCa.initCA();
      var newCert = await mtlsCa.generateClientCert({ cn: apiKey.prefix });
      if (!newCert) throw new AppError("Failed to generate certificate — OpenSSL may not be available.", 500, "CERT_GENERATION_FAILED");

      // Store enrollment code FIRST — if this fails, the API key cert fields stay unchanged
      var enrollment = generateEnrollmentCode();

      db.enrollmentCodes.insert({
        codeHash: enrollment.codeHash,
        apiKey: null, // client already has the API key — only re-issuing cert
        clientCert: newCert.cert,
        clientKey: newCert.key,
        caCert: newCert.ca,
        stashId: stash._id,
        bundleId: apiKey.boundBundleId || null,
        createdBy: req.user._id,
        status: "pending",
        reissue: true,
        originalKeyId: apiKeyId,
        expiresAt: new Date(Date.now() + TIME.hours(1)).toISOString(),
        createdAt: new Date().toISOString(),
      });

      // Update cert tracking on the API key only after enrollment insert succeeds
      apiKeysRepo.update(apiKeyId, { $set: {
        certIssuedAt: newCert.issuedAt,
        certExpiresAt: newCert.expiresAt,
        certFingerprint: certFingerprintSha3(newCert.cert),
      }});

      audit.log(audit.ACTIONS.CERT_REISSUED, {
        details: "Reissued mTLS cert for stash " + stash.slug + " (key: " + apiKey.prefix + "...)",
        req: req,
      });

      res.json({ success: true, enrollmentCode: enrollment.codeRaw, prefix: apiKey.prefix, reissue: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Cert reissue error", { error: e.message || String(e) });
      throw new AppError("Failed to reissue certificate.", 500, "CERT_REISSUE_FAILED");
    }
  });

};
