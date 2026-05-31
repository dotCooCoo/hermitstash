var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");
var logger = require("../app/shared/logger");
var { safeContentDisposition, sanitizeRename } = require("../app/shared/sanitize-filename");
var requireAuth = require("../middleware/require-auth");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var { canEditOwned } = require("../app/shared/authz");
var fileService = require("../app/domain/uploads/file.service");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var C = require("../lib/constants");
var syncGuards = require("../middleware/sync-guards");
var rateLimit = require("../lib/rate-limit");

module.exports = function (app) {
  // Share page
  app.get("/s/:shareId", (req, res) => {
    try {
      var doc = fileService.lookupFile(req.params.shareId);
      send(res, "share", { file: doc, user: req.user, host: host(req) });
    } catch (_e) {
      return send(res, "error", { title: "Not Found", message: "File not found.", user: req.user }, 404);
    }
  });

  // Download file
  app.get("/s/:shareId/download", async (req, res) => {
    var doc;
    try {
      doc = fileService.lookupFile(req.params.shareId, { checkExpiry: true });
    } catch (err) {
      if (err.name === "ValidationError") { res.writeHead(410); return res.end("File expired"); }
      res.writeHead(404); return res.end("Not found");
    }
    fileService.incrementDownloads(doc);
    audit.log(audit.ACTIONS.FILE_DOWNLOADED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", size: " + doc.size, req: req });
    // S3 direct mode: redirect to pre-signed URL for files stored without app encryption
    if (config.storage.backend === "s3" && config.storage.s3DirectDownloads) {
      var presignedUrl = fileService.getDirectDownloadUrl(doc);
      if (presignedUrl) { res.writeHead(302, { "Location": presignedUrl, "Cache-Control": "no-store" }); return res.end(); }
    }
    try {
      var result = await fileService.getDownloadStream(doc);
      res.writeHead(200, {
        "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
        "Content-Type": result.headers["Content-Type"],
      });
      var stream = result.stream;
      req.on("close", function () { if (stream.destroy) stream.destroy(); });
      stream.pipe(res);
    } catch (e) {
      logger.error("Download error", { error: e.message || String(e) });
      if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
    }
  });

  // Preview file (inline for safe types, sanitized SVG, forced download for HTML/JS)
  app.get("/s/:shareId/preview", async (req, res) => {
    var doc;
    try {
      doc = fileService.lookupFile(req.params.shareId, { checkExpiry: true });
    } catch (err) {
      if (err.name === "ValidationError") { res.writeHead(410); return res.end("File expired"); }
      res.writeHead(404); return res.end("Not found");
    }

    var preview = fileService.getPreviewMode(doc);

    try {
      if (preview.mode === "sanitized-svg") {
        // SVG too large for sanitization — fall back to forced download
        if (doc.size && Number(doc.size) > fileService.SVG_SIZE_LIMIT) {
          var dlResult = await fileService.getForceDownloadStream(doc);
          res.writeHead(200, {
            "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
            "Content-Type": "application/octet-stream",
          });
          dlResult.stream.pipe(res);
          return;
        }
        var svgResult = await fileService.getSanitizedSvg(doc);
        res.writeHead(200, svgResult.headers);
        res.end(svgResult.body);
        return;
      }

      if (preview.mode === "inline") {
        var inlineResult = await fileService.getInlinePreviewStream(doc);
        res.writeHead(200, inlineResult.headers);
        inlineResult.stream.pipe(res);
        return;
      }

      // "download" mode — forced download for HTML/JS/unknown types
      var forceResult = await fileService.getForceDownloadStream(doc);
      res.writeHead(200, {
        "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
        "Content-Type": "application/octet-stream",
      });
      forceResult.stream.pipe(res);
    } catch (err) {
      // Storage backend (local fs or S3) or stream decrypt failed. Log so
      // operators can investigate; keep the user-facing body generic.
      logger.error("[files/download] Error", { shareId: req.params.shareId, error: err.message });
      if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
    }
  });

  // Rename file (owner or admin)
  app.post("/files/:shareId/rename", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findAll({ shareId: req.params.shareId, status: "complete" })[0];
    if (!doc) return res.status(404).json({ error: "Not found." });
    if (!canEditOwned(doc, req.user, "uploadedBy")) {
      return res.status(403).json({ error: "Not authorized." });
    }
    var body = (await b.parsers.json(req)) || {};
    var result = sanitizeRename(body.name, { originalName: doc.originalName });
    if (!result.valid) return res.status(400).json({ error: result.error });
    filesRepo.update(doc._id, { $set: { originalName: result.name } });
    res.json({ success: true, name: result.name });
  });

  // Delete file (owner or admin)
  app.post("/files/:shareId/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc;
    try {
      doc = fileService.lookupFile(req.params.shareId);
    } catch (_e) {
      return res.status(404).json({ error: "Not found." });
    }
    try {
      fileService.assertCanDelete(doc, req.user);
    } catch (authErr) {
      return res.status(403).json({ error: authErr.message });
    }
    await fileService.deleteFile(doc);
    audit.log(audit.ACTIONS.FILE_DELETED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", deletedBy: " + (doc.uploadedBy === req.user._id ? "owner" : "admin"), req: req });

    // Auto-cleanup: if this was the last file in a bundle, remove the empty bundle
    if (doc.bundleShareId) {
      var remaining = filesRepo.findByBundleShareId(doc.bundleShareId);
      if (remaining.length === 0) {
        var bundle = bundlesRepo.findByShareId(doc.bundleShareId);
        if (bundle) {
          bundlesRepo.remove(bundle._id);
          audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, details: "auto-cleanup: last file deleted", req: req });
        }
      }
    }

    res.json({ success: true });
  });

  // Sync file download — Bearer + mTLS authed via sync-guards. Path takes
  // the file's _id (sync clients track by id from the change feed). Mirrors
  // /s/:shareId/download semantics (decrypted stream out) but the auth
  // surface is the sync-key pair and bundle binding rather than a bearer
  // shareId. No download counter increment — sync clients pull as part of
  // catch-up, not human downloads.
  app.get("/files/:fileId/download",
    rateLimit.guard({ scope: "sync-file-download", max: 200, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
    syncGuards.requireSyncAuth({ requireBundle: false }),
    async (req, res) => {
      try {
        // Sync WS events broadcast fileShareId on initial upload but _id on
        // catch-up replies (long-standing inconsistency in upload.handler.js
        // vs server-main.js — see line 214 vs 988). Look up by either so the
        // sync client doesn't have to care which event shape it's responding to.
        var doc = filesRepo.findById(req.params.fileId)
                  || filesRepo.findByShareId(req.params.fileId);
        if (!doc) return res.status(404).json({ error: "File not found." });

        var bundle = doc.bundleShareId ? bundlesRepo.findByShareId(doc.bundleShareId) : null;
        if (!bundle) return res.status(404).json({ error: "Bundle not found." });

        var bindErr = syncGuards.enforceBundleBinding(req.apiKey, bundle._id);
        if (bindErr) return res.status(bindErr.status).json({ error: bindErr.error });

        var ownerErr = syncGuards.enforceBundleOwnership(req.apiKey, bundle);
        if (ownerErr) return res.status(ownerErr.status).json({ error: ownerErr.error });

        var result = await fileService.getDownloadStream(doc);
        res.writeHead(200, {
          "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
          "Content-Type": result.headers["Content-Type"],
        });
        var stream = result.stream;
        req.on("close", function () { if (stream.destroy) stream.destroy(); });
        stream.pipe(res);
      } catch (err) {
        logger.error("[files/sync-download] Error", { error: err.message });
        if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
      }
    }
  );

  // Sync file delete — Bearer + mTLS authed via sync-guards. Path takes
  // the file's _id (sync clients track by id), distinct from the cookie-
  // authed POST /files/:shareId/delete which takes the file's shareId.
  // sync-guards enforces scope + cert binding here; bundle binding +
  // ownership are checked inline because the sync client doesn't send a
  // bundleId in the request (it has only the fileId).
  app.delete("/files/:fileId",
    rateLimit.guard({ scope: "sync-file-delete", max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
    syncGuards.requireSyncAuth({ requireBundle: false }),
    async (req, res) => {
      try {
        var doc = filesRepo.findById(req.params.fileId);
        if (!doc) return res.status(404).json({ error: "File not found." });

        // Resolve the file's bundle so binding + ownership can run.
        var bundle = doc.bundleShareId ? bundlesRepo.findByShareId(doc.bundleShareId) : null;
        if (!bundle) return res.status(404).json({ error: "Bundle not found." });

        var bindErr = syncGuards.enforceBundleBinding(req.apiKey, bundle._id);
        if (bindErr) return res.status(bindErr.status).json({ error: bindErr.error });

        var ownerErr = syncGuards.enforceBundleOwnership(req.apiKey, bundle);
        if (ownerErr) return res.status(ownerErr.status).json({ error: ownerErr.error });

        await fileService.deleteFile(doc);
        audit.log(audit.ACTIONS.FILE_DELETED, {
          targetId: doc._id,
          targetEmail: doc.uploaderEmail,
          details: "file: " + doc.originalName + ", deletedBy: sync",
          req: req,
        });
        res.json({ success: true });
      } catch (err) {
        logger.error("[files DELETE] Error", { error: err.message, stack: err.stack });
        res.status(500).json({ error: "Delete failed." });
      }
    }
  );
};
