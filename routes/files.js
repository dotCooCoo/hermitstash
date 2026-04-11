const config = require("../lib/config");
var logger = require("../app/shared/logger");
const { safeContentDisposition } = require("../app/shared/sanitize-filename");
const requireAuth = require("../middleware/require-auth");
const { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var fileService = require("../app/domain/uploads/file.service");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");

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
      result.stream.pipe(res);
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
    } catch (_e) {
      if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
    }
  });

  // Rename file (owner or admin)
  app.post("/files/:shareId/rename", async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findAll({ shareId: req.params.shareId, status: "complete" })[0];
    if (!doc) return res.status(404).json({ error: "Not found." });
    if (doc.uploadedBy !== req.user._id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized." });
    }
    var { parseJson } = require("../lib/multipart");
    var { sanitizeRename } = require("../app/shared/sanitize-filename");
    var body = await parseJson(req);
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
};
