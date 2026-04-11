const config = require("../lib/config");
var usersRepo = require("../app/data/repositories/users.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
const { parseMultipart, parseJson } = require("../lib/multipart");
const { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var rateLimit = require("../lib/rate-limit");
var bundleService = require("../app/domain/uploads/bundle.service");
var { requireScope } = require("../app/security/scope-policy");
var { resolveUploadConfig, handleFileUpload, handleChunkUpload, handleFinalize } = require("../app/domain/uploads/upload.handler");

module.exports = function (app) {
  // Drop page
  app.get("/drop", (req, res) => {
    if (!config.publicUpload) return send(res, "error", { title: "Disabled", message: "Public uploads are disabled.", user: req.user }, 403);
    var vaultEnabled = false;
    var vaultPublicKey = null;
    if (req.user) {
      var u = usersRepo.findById(req.user._id);
      if (u && u.vaultEnabled === "true" && u.vaultPublicKey) {
        vaultEnabled = true;
        vaultPublicKey = u.vaultPublicKey;
      }
    }
    var limits = resolveUploadConfig(null);
    send(res, "public-upload", {
      user: req.user, maxSize: limits.maxFileSize,
      maxFiles: limits.maxFiles, maxBundleSize: limits.maxBundleSize,
      allowedExtensions: limits.allowedExtensions,
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
    var ownerId = req.user ? req.user._id : null;
    if (req.user) {
      rawName = req.user.displayName || rawName;
      rawEmail = req.user.email || rawEmail;
    }

    var result = await bundleService.initBundle({
      uploaderName: rawName, uploaderEmail: rawEmail, ownerId: ownerId,
      password: body.password, message: body.message, bundleName: body.bundleName,
      allowedEmails: body.allowedEmails || null,
      expiryDays: body.expiryDays, defaultExpiryDays: config.fileExpiryDays,
      fileCount: body.fileCount, skippedCount: body.skippedCount, skippedFiles: body.skippedFiles,
    });
    audit.log(audit.ACTIONS.BUNDLE_INITIALIZED, { targetId: result.bundleId, targetEmail: rawEmail, details: "expected: " + (body.fileCount || 0), req: req });
    res.json({ bundleId: result.bundleId, shareId: result.shareId, finalizeToken: result.finalizeToken });
  });

  // Upload single file
  app.post("/drop/file/:bundleId", rateLimit.middleware("upload", 200, 60000), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) return res.status(403).json({ error: "Disabled." });
    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });
      var limits = resolveUploadConfig(null);
      var { fields, files: uploaded } = await parseMultipart(req, limits.maxFileSize);
      var file = uploaded[0];
      if (!file) return res.status(400).json({ error: "No file." });

      var result = await handleFileUpload({
        bundle: bundle, file: file, fields: fields, limits: limits,
        uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
        expiresAt: config.fileExpiryDays > 0 ? new Date(Date.now() + config.fileExpiryDays * 86400000).toISOString() : null,
        req: req,
      });
      if (result.error) return res.status(400).json({ error: result.error });
      res.json(result);
    } catch (e) {
      logger.error("Drop file error", { error: e.message || String(e) });
      res.status(500).json({ error: "Upload failed." });
    }
  });

  // Chunked upload
  app.post("/drop/chunk/:bundleId", rateLimit.middleware("chunk", 500, 60000), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) return res.status(403).json({ error: "Disabled." });
    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || bundle.status === "complete") return res.status(404).json({ error: "Bundle not found." });
      var limits = resolveUploadConfig(null);
      var { fields, files: uploaded } = await parseMultipart(req, limits.maxFileSize);
      var chunk = uploaded[0];
      if (!chunk) return res.status(400).json({ error: "No chunk." });

      var result = await handleChunkUpload({
        bundle: bundle, chunk: chunk, fields: fields, limits: limits,
        uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
        expiresAt: bundle.expiresAt || null,
        req: req,
      });
      if (result.error) return res.status(400).json({ error: result.error });
      res.json(result);
    } catch (e) {
      logger.error("Chunk upload error", { error: e.message || String(e) });
      res.status(500).json({ error: "Chunk upload failed." });
    }
  });

  // Finalize bundle
  app.post("/drop/finalize/:bundleId", rateLimit.middleware("finalize", 20, 60000), requireScope("upload"), async (req, res) => {
    var body = await parseJson(req);
    var token = String(body.finalizeToken || req.query.finalizeToken || "");
    var result = handleFinalize({
      bundleId: req.params.bundleId, token: token, sendUploaderEmail: true, req: req,
    });
    if (result.error) return res.status(result.status || 400).json({ error: result.error });
    res.json({ success: true, shareId: result.shareId, shareUrl: result.shareUrl, emailSent: result.emailSent });
  });
};
