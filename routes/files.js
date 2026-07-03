var b = require("../lib/vendor/blamejs");
var logger = require("../app/shared/logger");
var { safeContentDisposition, sanitizeRename } = require("../app/shared/sanitize-filename");
var requireAuth = require("../middleware/require-auth");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var { canEditOwned } = require("../app/shared/authz");
var { requireScope } = require("../app/security/scope-policy");
var fileService = require("../app/domain/uploads/file.service");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var stashRepo = require("../app/data/repositories/stash.repo");
var C = require("../lib/constants");
var syncGuards = require("../middleware/sync-guards");
var rateLimit = require("../lib/rate-limit");
var { AppError, ValidationError, ForbiddenError, NotFoundError } = require("../app/shared/errors");

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
    try {
      var result = await fileService.getDownloadStream(doc);
      // Count the download + write the audit row only once a stream actually
      // opened — a failed/unavailable read (missing blob, decrypt error, S3
      // outage) must not inflate the counter or assert a phantom success.
      fileService.incrementDownloads(doc);
      audit.log(audit.ACTIONS.FILE_DOWNLOADED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", size: " + doc.size, req: req });
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
          req.on("close", function () { if (dlResult.stream && dlResult.stream.destroy) dlResult.stream.destroy(); });
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
        req.on("close", function () { if (inlineResult.stream && inlineResult.stream.destroy) inlineResult.stream.destroy(); });
        inlineResult.stream.pipe(res);
        return;
      }

      // "download" mode — forced download for HTML/JS/unknown types
      var forceResult = await fileService.getForceDownloadStream(doc);
      res.writeHead(200, {
        "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
        "Content-Type": "application/octet-stream",
      });
      req.on("close", function () { if (forceResult.stream && forceResult.stream.destroy) forceResult.stream.destroy(); });
      forceResult.stream.pipe(res);
    } catch (err) {
      // Storage backend (local fs or S3) or stream decrypt failed. Log so
      // operators can investigate; keep the user-facing body generic.
      logger.error("[files/download] Error", { shareId: req.params.shareId, error: err.message });
      if (!res.writableEnded) { res.writeHead(500); res.end("File unavailable"); }
    }
  });

  // Rename file (owner or admin)
  // requireScope("upload") fails closed for API-key principals: a key minted
  // without a mutate scope (e.g. "read") gets 403 at the boundary. Session
  // callers (no req.apiKey) pass through to the role/ownership check below.
  app.post("/files/:shareId/rename", requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc = filesRepo.findAll({ shareId: req.params.shareId, status: "complete" })[0];
    if (!doc) throw new NotFoundError("Not found.");
    if (!canEditOwned(doc, req.user, "uploadedBy", req)) {
      throw new ForbiddenError("Not authorized.");
    }
    var body = (await b.parsers.json(req)) || {};
    var result = sanitizeRename(body.name, { originalName: doc.originalName });
    if (!result.valid) throw new ValidationError(result.error);
    filesRepo.update(doc._id, { $set: { originalName: result.name } });
    res.json({ success: true, name: result.name });
  });

  // Delete file (owner or admin)
  // requireScope("upload") fails closed for API-key principals — a read-only
  // key can't delete. Session callers pass through to assertCanDelete below.
  app.post("/files/:shareId/delete", requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var doc;
    try {
      doc = fileService.lookupFile(req.params.shareId);
    } catch (_e) {
      throw new NotFoundError("Not found.");
    }
    try {
      fileService.assertCanDelete(doc, req.user, req);
    } catch (authErr) {
      throw new ForbiddenError(authErr.message);
    }
    await fileService.deleteFile(doc);
    audit.log(audit.ACTIONS.FILE_DELETED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", deletedBy: " + (doc.uploadedBy === req.user._id ? "owner" : "admin"), req: req });

    // Auto-cleanup: if this was the last file in a bundle, remove the empty bundle
    if (doc.bundleShareId) {
      var remaining = filesRepo.findByBundleShareId(doc.bundleShareId);
      if (remaining.length === 0) {
        var bundle = bundlesRepo.findByShareId(doc.bundleShareId);
        if (bundle) {
          // Decrement stash stats if the bundle belongs to a stash page, before
          // removing it — mirrors the three sibling delete paths (bundles.js,
          // admin.js, stash.js). Without this the customer_stash.bundleCount /
          // totalBytes aggregates stay permanently inflated when a stash bundle
          // is emptied via this auto-cleanup path.
          if (bundle.stashId) {
            try { stashRepo.decrementBundleStats(bundle.stashId, bundle.totalSize); } catch (_e) {} // allow:silent-catch — best-effort stats decrement; never blocks the delete
          }
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
    rateLimit.guard({ max: 200, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
    syncGuards.requireSyncAuth({ requireBundle: false }),
    async (req, res) => {
      try {
        // Sync WS events broadcast fileShareId on initial upload but _id on
        // catch-up replies (long-standing inconsistency in upload.handler.js
        // vs server-main.js — see line 214 vs 988). Look up by either so the
        // sync client doesn't have to care which event shape it's responding to.
        var doc = filesRepo.findById(req.params.fileId)
                  || filesRepo.findByShareId(req.params.fileId);
        if (!doc) throw new NotFoundError("File not found.");

        var bundle = doc.bundleShareId ? bundlesRepo.findByShareId(doc.bundleShareId) : null;
        if (!bundle) throw new NotFoundError("Bundle not found.");

        var bindErr = syncGuards.enforceBundleBinding(req.apiKey, bundle._id);
        if (bindErr) throw new AppError(bindErr.error, bindErr.status);

        var ownerErr = syncGuards.enforceBundleOwnership(req.apiKey, bundle);
        if (ownerErr) throw new AppError(ownerErr.error, ownerErr.status);

        var result = await fileService.getDownloadStream(doc);
        res.writeHead(200, {
          "Content-Disposition": safeContentDisposition(doc.originalName, "attachment"),
          "Content-Type": result.headers["Content-Type"],
        });
        var stream = result.stream;
        req.on("close", function () { if (stream.destroy) stream.destroy(); });
        stream.pipe(res);
      } catch (err) {
        // Auth/lookup guards throw AppError subclasses — let the centralized
        // error handler render them as RFC 9457 problem-details with their
        // real status (404/403/...). Only storage/stream failures fall through
        // to the generic 500 below.
        if (err && err.isAppError) throw err;
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
    rateLimit.guard({ max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
    syncGuards.requireSyncAuth({ requireBundle: false }),
    async (req, res) => {
      try {
        var doc = filesRepo.findById(req.params.fileId);
        if (!doc) throw new NotFoundError("File not found.");

        // Resolve the file's bundle so binding + ownership can run.
        var bundle = doc.bundleShareId ? bundlesRepo.findByShareId(doc.bundleShareId) : null;
        if (!bundle) throw new NotFoundError("Bundle not found.");

        var bindErr = syncGuards.enforceBundleBinding(req.apiKey, bundle._id);
        if (bindErr) throw new AppError(bindErr.error, bindErr.status);

        var ownerErr = syncGuards.enforceBundleOwnership(req.apiKey, bundle);
        if (ownerErr) throw new AppError(ownerErr.error, ownerErr.status);

        await fileService.deleteFile(doc);
        audit.log(audit.ACTIONS.FILE_DELETED, {
          targetId: doc._id,
          targetEmail: doc.uploaderEmail,
          details: "file: " + doc.originalName + ", deletedBy: sync",
          req: req,
        });
        res.json({ success: true });
      } catch (err) {
        // Auth/lookup guards throw AppError subclasses — let the centralized
        // error handler render them as RFC 9457 problem-details with their
        // real status (404/403/...). Only the delete/storage failure falls
        // through to the generic 500 below.
        if (err && err.isAppError) throw err;
        logger.error("[files DELETE] Error", { error: err.message, stack: err.stack });
        throw new AppError("Delete failed.", 500);
      }
    }
  );
};
