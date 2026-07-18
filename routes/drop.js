var b = require("../lib/vendor/blamejs");
var rateLimit = require("../lib/rate-limit");
var config = require("../lib/config");
var C = require("../lib/constants");
var usersRepo = require("../app/data/repositories/users.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var { parseMultipart } = require("../lib/multipart");
var { send } = require("../middleware/send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var bundleService = require("../app/domain/uploads/bundle.service");
var { requireScope } = require("../app/security/scope-policy");
var { resolveUploadConfig, handleFileUpload, handleChunkUpload, handleFinalize } = require("../app/domain/uploads/upload.handler");
var idempotency = require("../middleware/idempotency");
var { AppError, ValidationError, ForbiddenError, NotFoundError } = require("../app/shared/errors");

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
  app.post("/drop/init", rateLimit.guard({ max: 20, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), idempotency, requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) throw new ForbiddenError("Disabled.");
    // blamejs apiEncrypt populates req.body with the decrypted plaintext;
    // fall through to parseJson(req) only when no upstream middleware has
    // pre-parsed the request (e.g. legacy callers, tests).
    var body = req.body || (await b.parsers.json(req)) || {};
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
      bundleType: body.bundleType || "snapshot",
      expiryDays: body.expiryDays, defaultExpiryDays: config.fileExpiryDays,
      fileCount: body.fileCount, skippedCount: body.skippedCount, skippedFiles: body.skippedFiles,
    });
    audit.log(audit.ACTIONS.BUNDLE_INITIALIZED, { targetId: result.bundleId, targetEmail: rawEmail, details: "expected: " + (body.fileCount || 0), req: req });
    res.json({ bundleId: result.bundleId, shareId: result.shareId, finalizeToken: result.finalizeToken });
  });

  // Upload single file
  app.post("/drop/file/:bundleId", rateLimit.guard({ max: 200, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) throw new ForbiddenError("Disabled.");
    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || (bundle.status === "complete" && bundle.bundleType !== "sync")) throw new NotFoundError("Bundle not found.");
      // Stash-owned bundles must go through the /stash/:slug/file/:bundleId path,
      // which applies per-stash upload caps and isStashLocked() access checks —
      // EXCEPT for sync clients whose API key is already bound to this stash.
      // The stash-binding check (sync-guards) is the same access control the
      // stash endpoint runs; routing them through /stash/:slug/file would just
      // require the client to know the slug, which it doesn't carry.
      if (bundle.stashId && !(req.apiKey && req.apiKey.boundStashId === bundle.stashId)) {
        throw new ForbiddenError("This bundle must be uploaded via its stash endpoint.");
      }
      // Owner-bound (non-stash) bundles — e.g. a user's sync bundle — must only
      // accept writes from the owner or an API key bound to that user. The
      // existence gate above lets a complete sync bundle through; without this an
      // attacker who learns the bundleId could overwrite another user's files
      // (matched by relativePath) and propagate the content to their sync clients.
      if (bundle.ownerId && (!req.user || bundle.ownerId !== req.user._id) && !(req.apiKey && req.apiKey.userId === bundle.ownerId)) {
        throw new ForbiddenError("Forbidden.");
      }
      var limits = resolveUploadConfig(null, req.user);
      // limits.maxFileSize is 0 when the owner has "No limit" file size; the parser
      // rejects a non-positive cap, so fall back to the finite per-request ceiling.
      // (The policy cap is already lifted — the validators treat 0 as unbounded.)
      var { fields, files: uploaded } = await parseMultipart(req, limits.maxFileSize || C.UPLOAD.NO_LIMIT_CEILING_BYTES);
      var file = uploaded[0];
      if (!file) throw new ValidationError("No file.");

      var result = await handleFileUpload({
        bundle: bundle, file: file, fields: fields, limits: limits,
        uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
        // Per-file expiry follows the bundle's server-authoritative, clamped
        // expiresAt — the same source the chunked path uses — so every file in a
        // bundle expires together regardless of which transport carried it.
        expiresAt: bundle.expiresAt || null,
        req: req,
      });
      if (result.error) throw new AppError(result.error, result.status || 400);
      res.json(result);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Drop file error", { error: e.message || String(e) });
      throw new AppError("Upload failed.", 500);
    }
  });

  // Chunked upload
  app.post("/drop/chunk/:bundleId", rateLimit.guard({ max: 500, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), requireScope("upload"), async (req, res) => {
    if (!config.publicUpload) throw new ForbiddenError("Disabled.");
    try {
      var bundle = bundlesRepo.findById(req.params.bundleId);
      if (!bundle || (bundle.status === "complete" && bundle.bundleType !== "sync")) throw new NotFoundError("Bundle not found.");
      if (bundle.stashId && !(req.apiKey && req.apiKey.boundStashId === bundle.stashId)) {
        throw new ForbiddenError("This bundle must be uploaded via its stash endpoint.");
      }
      // Owner-bound (non-stash) bundles — e.g. a user's sync bundle — must only
      // accept writes from the owner or an API key bound to that user. The
      // existence gate above lets a complete sync bundle through; without this an
      // attacker who learns the bundleId could overwrite another user's files
      // (matched by relativePath) and propagate the content to their sync clients.
      if (bundle.ownerId && (!req.user || bundle.ownerId !== req.user._id) && !(req.apiKey && req.apiKey.userId === bundle.ownerId)) {
        throw new ForbiddenError("Forbidden.");
      }
      var limits = resolveUploadConfig(null, req.user);
      // limits.maxFileSize is 0 when the owner has "No limit" file size; the parser
      // rejects a non-positive cap, so fall back to the finite per-request ceiling.
      // (The policy cap is already lifted — the validators treat 0 as unbounded.)
      var { fields, files: uploaded } = await parseMultipart(req, limits.maxFileSize || C.UPLOAD.NO_LIMIT_CEILING_BYTES);
      var chunk = uploaded[0];
      if (!chunk) throw new ValidationError("No chunk.");

      var result = await handleChunkUpload({
        bundle: bundle, chunk: chunk, fields: fields, limits: limits,
        uploadedBy: bundle.ownerId || "public", uploaderEmail: bundle.uploaderEmail,
        expiresAt: bundle.expiresAt || null,
        req: req,
      });
      if (result.error) throw new AppError(result.error, result.status || 400);
      res.json(result);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Chunk upload error", { error: e.message || String(e) });
      throw new AppError("Chunk upload failed.", 500);
    }
  });

  // Finalize bundle
  app.post("/drop/finalize/:bundleId", rateLimit.guard({ max: 20, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), idempotency, requireScope("upload"), async (req, res) => {
    var existing = bundlesRepo.findById(req.params.bundleId);
    if (!existing) throw new NotFoundError("Bundle not found.");
    if (existing.stashId && !(req.apiKey && req.apiKey.boundStashId === existing.stashId)) {
      throw new ForbiddenError("This bundle must be finalized via its stash endpoint.");
    }
    if (existing.ownerId && (!req.user || existing.ownerId !== req.user._id)) throw new ForbiddenError("Forbidden.");

    var body = req.body || (await b.parsers.json(req)) || {};
    // Body only — never accept the finalize secret from the query string (it would
    // leak to access logs / proxies / Referer, CWE-598). Every client (web uploader
    // + sync) sends it in the POST body.
    var token = String(body.finalizeToken || "");
    var result = handleFinalize({
      bundleId: req.params.bundleId, token: token, sendUploaderEmail: true, req: req,
    });
    if (result.error) throw new AppError(result.error, result.status || 400);
    res.json({ success: true, shareId: result.shareId, shareUrl: result.shareUrl, emailSent: result.emailSent });
  });
};
