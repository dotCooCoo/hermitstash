var C = require("../lib/constants");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var accessLogRepo = require("../app/data/repositories/bundleAccessLog.repo");
var logger = require("../app/shared/logger");
const config = require("../lib/config");
const { verifyPassword } = require("../lib/crypto");
const { parseJson } = require("../lib/multipart");
const storage = require("../lib/storage");
const { ZipWriter } = require("../lib/zip");
const { safeFilename } = require("../lib/sanitize");
const { safeContentDisposition } = require("../app/shared/sanitize-filename");
const { send } = require("../middleware/send");
var audit = require("../lib/audit");
var rateLimit = require("../lib/rate-limit");
const requireAuth = require("../middleware/require-auth");

var { isBundleLocked, prefersJson } = require("../middleware/require-access");
var db = require("../lib/db");
var { validateEmail } = require("../app/shared/validate");
var { sanitizeRename } = require("../app/shared/sanitize-filename");
var stashRepo = require("../app/data/repositories/stash.repo");
var uploadHandler = require("../app/domain/uploads/upload.handler");
var accessCodeService = require("../app/domain/access-code.service");

// Exponential backoff tracking for bundle password attempts
var bundleLockouts = new Map();
var BUNDLE_LOCKOUT_THRESHOLD = 5;

// Clean up stale lockout entries every 30 minutes
var _lockoutTimer = setInterval(function () {
  var now = Date.now();
  bundleLockouts.forEach(function (entry, key) {
    if (now - entry.lastAttempt > C.TIME.ONE_HOUR) {
      bundleLockouts.delete(key);
    }
  });
}, C.TIME.THIRTY_MIN);
_lockoutTimer.unref();

module.exports = function (app) {
  // Bundle password verification (rate limited to prevent brute force)
  app.post("/b/:shareId/unlock", rateLimit.middleware("bundle-unlock", 10, 900000), async (req, res) => {
    var shareId = req.params.shareId;
    var bundle = bundlesRepo.findByShareId(shareId);
    if (!bundle || bundle.status !== "complete") return res.status(404).json({ error: "Bundle not found." });

    // Check exponential backoff lockout
    var lockout = bundleLockouts.get(shareId);
    if (lockout && lockout.failures >= BUNDLE_LOCKOUT_THRESHOLD) {
      var backoffSeconds = Math.pow(2, lockout.failures - BUNDLE_LOCKOUT_THRESHOLD) * 30;
      var elapsed = (Date.now() - lockout.lastAttempt) / 1000;
      if (elapsed < backoffSeconds) {
        var retryAfter = Math.ceil(backoffSeconds - elapsed);
        res.setHeader("Retry-After", String(retryAfter));
        return res.status(429).json({ error: "Too many failed attempts. Try again in " + retryAfter + " seconds." });
      }
    }

    var body = await parseJson(req);
    var password = String(body.password || "");
    if (!bundle.passwordHash) {
      req.session["bundle_" + shareId] = true;
      return res.json({ success: true });
    }
    var valid = await verifyPassword(password, bundle.passwordHash);
    if (valid) {
      // For "both" mode: preserve the email verification, add password flag
      var mode = bundle.accessMode || "password";
      if (mode === "both") {
        var prev = req.session["bundle_" + shareId];
        req.session["bundle_" + shareId] = { emailVerified: (prev && prev.emailVerified) || true, passwordVerified: true };
      } else {
        req.session["bundle_" + shareId] = true;
      }
      bundleLockouts.delete(shareId);
      return res.json({ success: true });
    }

    // Track failed attempt
    if (!lockout) {
      lockout = { failures: 0, lastAttempt: 0 };
    }
    lockout.failures++;
    lockout.lastAttempt = Date.now();
    bundleLockouts.set(shareId, lockout);

    if (lockout.failures >= BUNDLE_LOCKOUT_THRESHOLD) {
      var retryAfterSec = Math.pow(2, lockout.failures - BUNDLE_LOCKOUT_THRESHOLD) * 30;
      logger.warn("Bundle unlock lockout", { shareId: shareId, failures: lockout.failures, retryAfter: retryAfterSec });
      res.setHeader("Retry-After", String(retryAfterSec));
      return res.status(429).json({ error: "Too many failed attempts. Try again in " + retryAfterSec + " seconds." });
    }

    return res.status(401).json({ error: "Incorrect password." });
  });

  // Request email access code (rate limited)
  app.post("/b/:shareId/request-code", rateLimit.middleware("bundle-email-code", 5, 300000), async (req, res) => {
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle || bundle.status !== "complete") return res.status(404).json({ error: "Bundle not found." });

    var body = await parseJson(req);
    var email = String(body.email || "").trim().toLowerCase();
    var emailCheck = validateEmail(email);
    if (!emailCheck.valid) {
      return res.status(400).json({ error: "Valid email required." });
    }

    // Always return same response to prevent email enumeration
    var genericMsg = "If this email has access, a code has been sent.";
    var mode = bundle.accessMode || "open";
    if (mode !== "email" && mode !== "both") return res.json({ success: true, message: genericMsg });

    // Check if email is in the allowed list
    var allowedList = (bundle.allowedEmails || "").split(",").map(function (e) { return e.trim().toLowerCase(); }).filter(Boolean);
    if (!allowedList.includes(email)) {
      // Anti-enumeration: respond identically
      return res.json({ success: true, message: genericMsg });
    }

    try {
      var result = await accessCodeService.requestCode({
        shareId: bundle.shareId,
        email: email,
        bundleName: bundle.bundleName || null,
        senderName: bundle.uploaderName || null,
      });
      if (result.sent) {
        audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_SENT, { targetId: bundle._id, details: "shareId: " + bundle.shareId, req: req });
      }
    } catch (e) {
      logger.error("Access code email failed", { error: e.message || String(e) });
    }

    res.json({ success: true, message: genericMsg });
  });

  // Verify email access code (rate limited)
  app.post("/b/:shareId/verify-code", rateLimit.middleware("bundle-verify-code", 10, 900000), async (req, res) => {
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle || bundle.status !== "complete") return res.status(404).json({ error: "Bundle not found." });

    var body = await parseJson(req);
    var email = String(body.email || "").trim().toLowerCase();
    var code = String(body.code || "").trim();
    if (!email || !code) return res.status(400).json({ error: "Email and code required." });

    var result = accessCodeService.verifyCode({ shareId: bundle.shareId, email: email, code: code });
    if (!result.success) {
      if (result.attempts) {
        audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_FAILED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", attempts: " + result.attempts, req: req });
      }
      return res.status(result.status).json({ error: result.error });
    }

    // Set session
    var mode = bundle.accessMode || "email";
    if (mode === "both") {
      req.session["bundle_" + bundle.shareId] = { emailVerified: email, passwordVerified: false };
    } else {
      req.session["bundle_" + bundle.shareId] = email;
    }

    // Log verified access
    accessLogRepo.create({
      bundleShareId: bundle.shareId,
      email: email,
      accessedAt: new Date().toISOString(),
      ip: rateLimit.getIp(req),
    });

    audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_VERIFIED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", email verified", req: req });
    res.json({ success: true, needsPassword: mode === "both" });
  });

  // Bundle browse page
  app.get("/b/:shareId", (req, res) => {
    const bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle || bundle.status !== "complete") return send(res, "error", { title: "Not Found", message: "Bundle not found.", user: req.user }, 404);

    // Check expiry
    if (bundle.expiresAt && bundle.expiresAt < new Date().toISOString()) {
      return send(res, "error", { title: "Expired", message: "This bundle has expired.", user: req.user }, 410);
    }

    // Access protection (password, email, or both)
    var locked = isBundleLocked(bundle, req.session);
    if (locked === "email") {
      return send(res, "bundle-email-gate", { shareId: req.params.shareId, user: req.user });
    }
    if (locked === "password" || locked === "email-then-password") {
      var emailVerified = locked === "email-then-password";
      return send(res, "bundle-locked", { shareId: req.params.shareId, user: req.user, emailVerified: emailVerified });
    }
    const bundleFiles = filesRepo.findByBundleShareId(bundle.shareId)
      .filter(f => !f.deletedAt)
      .sort((a, b) => (a.relativePath || "").localeCompare(b.relativePath || ""));
    var verifiedEmail = req.session["bundle_" + req.params.shareId];
    var viewerEmail = (typeof verifiedEmail === "object" && verifiedEmail.emailVerified && typeof verifiedEmail.emailVerified === "string") ? verifiedEmail.emailVerified : (typeof verifiedEmail === "string" ? verifiedEmail : null);
    audit.log(audit.ACTIONS.BUNDLE_VIEWED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + (viewerEmail ? ", viewer: " + viewerEmail : ""), req: req });

    // JSON content negotiation for API/sync clients
    if (prefersJson(req)) {
      return res.json({
        bundleId: bundle._id,
        shareId: bundle.shareId,
        status: bundle.status,
        bundleType: bundle.bundleType || "snapshot",
        bundleName: bundle.bundleName || null,
        uploaderName: bundle.uploaderName || "Anonymous",
        accessMode: bundle.accessMode || "open",
        fileCount: bundleFiles.length,
        totalSize: bundle.totalSize || 0,
        downloads: bundle.downloads || 0,
        createdAt: bundle.createdAt,
        expiresAt: bundle.expiresAt || null,
        files: bundleFiles.map(function (f) {
          return {
            id: f._id,
            shareId: f.shareId,
            name: f.originalName,
            relativePath: f.relativePath || f.originalName,
            size: f.size || 0,
            mime: f.mimeType,
            checksum: f.checksum || null,
            createdAt: f.createdAt,
          };
        }),
      });
    }

    var displayBundle = Object.assign({}, bundle);
    displayBundle.hasPassword = !!bundle.passwordHash;
    displayBundle.accessMode = bundle.accessMode || "open";
    send(res, "bundle", { bundle: displayBundle, files: bundleFiles, user: req.user, host: host(req) });
  });

  // Download single file from bundle
  app.get("/b/:shareId/file/:fileShareId", async (req, res) => {
    const doc = filesRepo.findByShareId(req.params.fileShareId);
    if (!doc || doc.bundleShareId !== req.params.shareId) { res.writeHead(404); return res.end("Not found"); }
    if (doc.expiresAt && doc.expiresAt < new Date().toISOString()) { res.writeHead(410); return res.end("File expired"); }
    // Enforce bundle access protection on single file downloads
    var parentBundle = bundlesRepo.findByShareId(req.params.shareId);
    if (parentBundle && isBundleLocked(parentBundle, req.session)) {
      res.writeHead(401); return res.end("Access restricted");
    }
    filesRepo.incrementDownloads(doc._id);
    audit.log(audit.ACTIONS.BUNDLE_FILE_DOWNLOADED, { targetId: doc._id, details: "file: " + doc.originalName + ", bundle: " + req.params.shareId, req: req });
    // S3 direct mode: redirect to pre-signed URL for files stored without app encryption
    if (!doc.encryptionKey && config.storage.backend === "s3" && config.storage.s3DirectDownloads) {
      var presignedUrl = storage.getPresignedUrl(doc.storagePath, doc.originalName, doc.mimeType);
      if (presignedUrl) { res.writeHead(302, { "Location": presignedUrl, "Cache-Control": "no-store" }); return res.end(); }
    }
    try {
      const stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);
      req.on("close", function () { if (stream.destroy) stream.destroy(); });
      res.writeHead(200, {
        "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
        "Content-Type": doc.mimeType || "application/octet-stream",
      });
      stream.pipe(res);
    } catch (e) {
      logger.error("Download error", { error: e.message || String(e) });
      if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
    }
  });

  // Download entire bundle as ZIP
  app.get("/b/:shareId/download", async (req, res) => {
    const bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle || bundle.status !== "complete") { res.writeHead(404); return res.end("Not found"); }
    // Enforce bundle access protection on ZIP downloads
    if (isBundleLocked(bundle, req.session)) {
      res.writeHead(401); return res.end("Access restricted");
    }
    var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
    if (bundleFiles.length === 0) { res.writeHead(404); return res.end("Empty bundle"); }

    db.rawExec("UPDATE bundles SET downloads = downloads + 1 WHERE _id = ?", bundle._id);
    audit.log(audit.ACTIONS.BUNDLE_ZIP_DOWNLOADED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", files: " + bundleFiles.length, req: req });

    res.writeHead(200, {
      "Content-Type": "application/zip",
      "Content-Disposition": safeContentDisposition((bundle.bundleName || "hermitstash-" + bundle.shareId) + ".zip", "attachment"),
    });

    const zip = new ZipWriter(res);
    var skippedFiles = [];
    for (const f of bundleFiles) {
      try {
        const stream = await storage.getFileStream(f.storagePath, f.encryptionKey);
        await zip.addFile(f.relativePath || f.originalName, stream);
      } catch (e) {
        logger.error("Zip skip", { error: e.message || String(e), file: f.originalName, bundle: bundle.shareId });
        skippedFiles.push(f.relativePath || f.originalName);
      }
    }
    if (skippedFiles.length > 0) {
      var manifest = "The following files could not be included in this download:\n\n" + skippedFiles.join("\n") + "\n";
      await zip.addFile("_MISSING_FILES.txt", Buffer.from(manifest, "utf8"));
    }
    zip.finalize();
  });

  // Download a subfolder from a bundle as ZIP
  app.get("/b/:shareId/folder/*", async (req, res) => {
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle || bundle.status !== "complete") { res.writeHead(404); return res.end("Not found"); }
    if (isBundleLocked(bundle, req.session)) {
      res.writeHead(401); return res.end("Access restricted");
    }
    // The folder prefix is everything after /folder/
    var prefix = req.params[0];
    if (!prefix) { res.writeHead(400); return res.end("Folder path required"); }
    // Normalize: ensure trailing slash for prefix matching
    if (!prefix.endsWith("/")) prefix += "/";

    var allFiles = filesRepo.findByBundleShareId(bundle.shareId);
    var folderFiles = allFiles.filter(function (f) {
      var rel = f.relativePath || f.originalName;
      return rel.startsWith(prefix) || rel === prefix.slice(0, -1);
    });
    if (folderFiles.length === 0) { res.writeHead(404); return res.end("Folder not found"); }

    var folderName = safeFilename(prefix.replace(/\/+$/, "").split("/").pop() || "folder");
    audit.log(audit.ACTIONS.BUNDLE_ZIP_DOWNLOADED, { targetId: bundle._id, details: "folder: " + prefix + ", files: " + folderFiles.length, req: req });

    res.writeHead(200, {
      "Content-Type": "application/zip",
      "Content-Disposition": safeContentDisposition(folderName + ".zip", "attachment"),
    });

    var zip = new ZipWriter(res);
    for (var i = 0; i < folderFiles.length; i++) {
      try {
        var stream = await storage.getFileStream(folderFiles[i].storagePath, folderFiles[i].encryptionKey);
        // Strip the prefix so the ZIP contains relative paths within the folder
        var relPath = (folderFiles[i].relativePath || folderFiles[i].originalName).slice(prefix.length) || folderFiles[i].originalName;
        await zip.addFile(relPath, stream);
      } catch (e) {
        logger.error("Zip skip", { error: e.message || String(e), file: folderFiles[i].originalName });
      }
    }
    zip.finalize();
  });

  // Delete bundle + all its files (owner or admin)
  // Rename bundle
  app.post("/bundles/:shareId/rename", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    if (bundle.ownerId !== req.user._id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized." });
    }
    // parseJson already imported at top
    // sanitizeRename already imported at top
    var body = await parseJson(req);
    var result = sanitizeRename(body.name, { maxLength: 200 });
    if (!result.valid) return res.status(400).json({ error: result.error || "Invalid name." });
    bundlesRepo.update(bundle._id, { $set: { bundleName: result.name } });
    res.json({ success: true, name: result.name });
  });

  // Rename/move a file within a sync bundle (metadata-only, no re-upload)
  app.post("/bundles/:shareId/file/rename", rateLimit.middleware("sync-file-rename", 100, 60000), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    if (bundle.ownerId !== req.user._id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized." });
    }
    var body = await parseJson(req);
    var { handleSyncFileRename } = uploadHandler;
    var result = await handleSyncFileRename({
      bundleId: bundle._id,
      oldRelativePath: body.oldRelativePath,
      newRelativePath: body.newRelativePath,
      req: req,
    });
    if (result.error) return res.status(result.status || 400).json({ error: result.error });
    res.json(result);
  });

  // Delete a single file from a sync bundle (soft delete with tombstone)
  app.post("/bundles/:shareId/file/:fileId/delete", rateLimit.middleware("sync-file-delete", 100, 60000), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    if (bundle.ownerId !== req.user._id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized." });
    }
    var { handleSyncFileDelete } = uploadHandler;
    var result = await handleSyncFileDelete({ bundle: bundle, fileId: req.params.fileId, req: req });
    if (result.error) return res.status(result.status || 400).json({ error: result.error });
    res.json(result);
  });

  app.post("/bundles/:shareId/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    // Only owner or admin can delete
    if (bundle.ownerId !== req.user._id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized." });
    }
    var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
    for (var i = 0; i < bundleFiles.length; i++) {
      try { await storage.deleteFile(bundleFiles[i].storagePath); } catch (_e) {}
      filesRepo.remove(bundleFiles[i]._id);
    }
    // Decrement stash stats if bundle belongs to a stash page
    if (bundle.stashId) {
      try { stashRepo.decrementBundleStats(bundle.stashId, bundle.totalSize); } catch (_e) {}
    }
    bundlesRepo.remove(bundle._id);
    audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, targetEmail: bundle.uploaderEmail, details: "owner delete, shareId: " + bundle.shareId + ", files: " + bundleFiles.length, req: req });
    res.json({ success: true, filesDeleted: bundleFiles.length });
  });
};
