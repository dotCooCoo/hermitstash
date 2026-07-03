var clientIp = require("../lib/client-ip");
var C = require("../lib/constants");
var rateLimit = require("../lib/rate-limit");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var accessLogRepo = require("../app/data/repositories/bundleAccessLog.repo");
var logger = require("../app/shared/logger");
var b = require("../lib/vendor/blamejs");
var storage = require("../lib/storage");
var { safeContentDisposition } = require("../app/shared/sanitize-filename");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var requireAuth = require("../middleware/require-auth");
var { canEditOwned } = require("../app/shared/authz");
var { requireScope } = require("../app/security/scope-policy");
var { AppError, ValidationError, AuthenticationError, ForbiddenError, NotFoundError, RateLimitError } = require("../app/shared/errors");

var { isBundleLocked, prefersJson } = require("../middleware/require-access");
var db = require("../lib/db");
var { validateEmail } = require("../app/shared/validate");
var { sanitizeRename } = require("../app/shared/sanitize-filename");
var stashRepo = require("../app/data/repositories/stash.repo");
var uploadHandler = require("../app/domain/uploads/upload.handler");
var accessCodeService = require("../app/domain/access-code.service");
var accessLockout = require("../lib/access-lockout");

// Persistent exponential backoff for bundle password attempts, keyed on the
// (namespace, shareId, client subnet) tuple. Stored in bundle_access_lockouts
// so counters survive restart and are shared across workers; stale entries
// (> 24h idle) are swept by the scheduled cleanup job in server.js. The same
// shared module backs the stash unlock route under the "stash" namespace.
var BUNDLE_LOCKOUT_NS = "bundle";

// Aggregate ceiling on bytes a single ZIP build may hold resident at once. The
// ZIP routes pre-buffer each decrypted file (to keep per-file skip-on-error
// semantics), so without a running-total cap one request to a large open
// bundle could pin hundreds of MB of plaintext in the single-process heap.
// Once cumulative buffered bytes cross this line the build stops queuing more
// files and emits a truncation notice instead of OOMing the process.
var ZIP_BUFFER_CAP = C.BYTES.mib(512);

// A bundle past its expiresAt is gone for every content route, not only the
// browse page — otherwise a share-link holder can still pull the bytes via
// /download, /file/:fileShareId, or /folder/:prefix after expiry. Single gate
// so the policy can't drift per-route.
function isBundleExpired(bundle) {
  return !!(bundle && bundle.expiresAt && bundle.expiresAt < new Date().toISOString());
}

// Predicate the access gate re-runs every request to re-validate a session's
// verified email against the bundle's CURRENT allowedEmails, so an address
// removed from the list loses access on its next request rather than at session
// expiry. Same exact-membership test the request-code path uses.
function bundleAllowedMatch(bundle) {
  var allowedList = (bundle.allowedEmails || "").split(",").map(function (e) { return e.trim().toLowerCase(); }).filter(Boolean);
  return function (email) { return allowedList.includes(String(email).toLowerCase()); };
}

async function _streamToBuffer(stream) {
  // Cap at 2 GiB — far above the per-file upload limit, but bounds memory
  // against a corrupted/hostile storage stream. The collector enforces the
  // cap at push() time; overflow throws and is caught by the per-file
  // try/catch in the callers (logged + skipped from the archive).
  var collector = b.safeBuffer.boundedChunkCollector({ maxBytes: C.BYTES.gib(2) });
  for await (var chunk of stream) collector.push(chunk);
  return collector.result();
}

module.exports = function (app) {
  // Bundle password verification (rate limited to prevent brute force)
  app.post("/b/:shareId/unlock", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(15), algorithm: "fixed-window" }), async (req, res) => {
    var shareId = req.params.shareId;
    var ip = clientIp.getIp(req);
    var bundle = bundlesRepo.findByShareId(shareId);
    if (!bundle || bundle.status !== "complete") throw new NotFoundError("Bundle not found.");

    // Check exponential backoff lockout (persistent across restarts, per subnet)
    var retryAfter = accessLockout.lockedFor(accessLockout.getLockout(BUNDLE_LOCKOUT_NS, shareId, ip));
    if (retryAfter > 0) {
      throw new RateLimitError("Too many failed attempts. Try again in " + retryAfter + " seconds.", retryAfter);
    }

    var body = (await b.parsers.json(req)) || {};
    var password = String(body.password || "");
    if (!bundle.passwordHash) {
      // An email-gated bundle carries no password; access is granted ONLY via the
      // email access-code flow (which sets { emailVerified }). Treating a missing
      // password as "unlocked" here would bypass the email gate entirely.
      if (bundle.accessMode === "email") {
        throw new ForbiddenError("Email verification required.").withExtras({ requiresEmail: true });
      }
      req.session["bundle_" + shareId] = true;
      return res.json({ success: true });
    }
    var valid = await b.auth.password.verify(bundle.passwordHash, password);
    if (valid) {
      // For "both" mode: require prior email verification before accepting password
      var mode = bundle.accessMode || "password";
      if (mode === "both") {
        var prev = req.session["bundle_" + shareId];
        if (!prev || typeof prev !== "object" || typeof prev.emailVerified !== "string") {
          throw new ForbiddenError("Email verification required first.").withExtras({ requiresEmail: true });
        }
        req.session["bundle_" + shareId] = { emailVerified: prev.emailVerified, passwordVerified: true };
      } else {
        req.session["bundle_" + shareId] = true;
      }
      accessLockout.clearLockout(BUNDLE_LOCKOUT_NS, shareId, ip);
      return res.json({ success: true });
    }

    // Track failed attempt (persistent, per subnet)
    var after = accessLockout.recordFailure(BUNDLE_LOCKOUT_NS, shareId, ip);

    if (after.retryAfter > 0) {
      logger.warn("Bundle unlock lockout", { shareId: shareId, failures: after.failures, retryAfter: after.retryAfter });
      throw new RateLimitError("Too many failed attempts. Try again in " + after.retryAfter + " seconds.", after.retryAfter);
    }

    throw new AuthenticationError("Incorrect password.");
  });

  // Request email access code (rate limited)
  app.post("/b/:shareId/request-code", rateLimit.guard({ max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    var bundle = bundlesRepo.findCompleteByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Bundle not found.");

    var body = (await b.parsers.json(req)) || {};
    var email = String(body.email || "").trim().toLowerCase();
    var emailCheck = validateEmail(email);
    if (!emailCheck.valid) {
      throw new ValidationError("Valid email required.");
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
  app.post("/b/:shareId/verify-code", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(15), algorithm: "fixed-window" }), async (req, res) => {
    var bundle = bundlesRepo.findCompleteByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Bundle not found.");

    var body = (await b.parsers.json(req)) || {};
    var email = String(body.email || "").trim().toLowerCase();
    var code = String(body.code || "").trim();
    if (!email || !code) throw new ValidationError("Email and code required.");

    var result = accessCodeService.verifyCode({ shareId: bundle.shareId, email: email, code: code });
    if (!result.success) {
      if (result.attempts) {
        audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_FAILED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", attempts: " + result.attempts, req: req });
      }
      throw new AppError(result.error, result.status || 400);
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
      ip: clientIp.getIp(req),
    });

    audit.log(audit.ACTIONS.BUNDLE_ACCESS_CODE_VERIFIED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", email verified", req: req });
    res.json({ success: true, needsPassword: mode === "both" });
  });

  // Bundle browse page
  app.get("/b/:shareId", (req, res) => {
    var bundle = bundlesRepo.findCompleteByShareId(req.params.shareId);
    if (!bundle) return send(res, "error", { title: "Not Found", message: "Bundle not found.", user: req.user }, 404);

    // Check expiry
    if (isBundleExpired(bundle)) {
      return send(res, "error", { title: "Expired", message: "This bundle has expired.", user: req.user }, 410);
    }

    // Access protection (password, email, or both)
    var locked = isBundleLocked(bundle, req.session, bundleAllowedMatch(bundle));
    if (locked === "email") {
      return send(res, "bundle-email-gate", { shareId: req.params.shareId, user: req.user });
    }
    if (locked === "password" || locked === "email-then-password") {
      var emailVerified = locked === "email-then-password";
      return send(res, "bundle-locked", { shareId: req.params.shareId, user: req.user, emailVerified: emailVerified });
    }
    var bundleFiles = filesRepo.findLiveByBundleShareId(bundle.shareId)
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
    // Serve only finalized files — an in-flight (chunking) upload must never be
    // streamed to a downloader (partial/garbled bytes, missing encryption key).
    var doc = filesRepo.findCompleteByShareId(req.params.fileShareId);
    if (!doc || doc.bundleShareId !== req.params.shareId) { res.writeHead(404); return res.end("Not found"); }
    if (doc.expiresAt && doc.expiresAt < new Date().toISOString()) { res.writeHead(410); return res.end("File expired"); }
    // Enforce bundle expiry + access protection on single file downloads. A file
    // row can outlive its bundle (orphaned after a bundle delete); without the
    // parent its access protection (password / expiry / lock) can't be evaluated,
    // and `parentBundle && isBundleLocked(...)` would short-circuit to false and
    // serve the file unprotected — so refuse when the parent is gone.
    var parentBundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!parentBundle) { res.writeHead(404); return res.end("Not found"); }
    if (isBundleExpired(parentBundle)) { res.writeHead(410); return res.end("Bundle expired"); }
    if (isBundleLocked(parentBundle, req.session, bundleAllowedMatch(parentBundle))) {
      res.writeHead(401); return res.end("Access restricted");
    }
    try {
      var stream = await storage.getFileStream(doc.storagePath, doc.encryptionKey);
      // Count the download + write the audit row only once a stream actually
      // opened — a failed/unavailable read (missing blob, decrypt error, S3
      // outage) must not inflate the counter or assert a phantom success.
      filesRepo.incrementDownloads(doc._id);
      audit.log(audit.ACTIONS.BUNDLE_FILE_DOWNLOADED, { targetId: doc._id, details: "file: " + doc.originalName + ", bundle: " + req.params.shareId, req: req });
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
  // Rate-limited per subnet like every other /b/ endpoint: the handler buffers
  // each decrypted file to keep the per-file skip-on-error semantic, so an
  // unbounded request rate could pin many large bundles in the single-process
  // heap (memory-exhaustion DoS). The limiter bounds concurrent/looped builds;
  // ZIP_BUFFER_CAP below bounds the bytes any single build can hold at once.
  app.get("/b/:shareId/download", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    var bundle = bundlesRepo.findCompleteByShareId(req.params.shareId);
    if (!bundle) { res.writeHead(404); return res.end("Not found"); }
    if (isBundleExpired(bundle)) { res.writeHead(410); return res.end("Bundle expired"); }
    // Enforce bundle access protection on ZIP downloads
    if (isBundleLocked(bundle, req.session, bundleAllowedMatch(bundle))) {
      res.writeHead(401); return res.end("Access restricted");
    }
    // Exclude sync-bundle tombstones (deletedAt) so the ZIP matches the browse
    // view — a deleted file must not be fed to getFileStream (it would land in
    // the user-visible _MISSING_FILES.txt manifest and leak its name).
    var bundleFiles = filesRepo.findLiveByBundleShareId(bundle.shareId);
    if (bundleFiles.length === 0) { res.writeHead(404); return res.end("Empty bundle"); }

    db.rawExec("UPDATE bundles SET downloads = downloads + 1 WHERE _id = ?", bundle._id);
    audit.log(audit.ACTIONS.BUNDLE_ZIP_DOWNLOADED, { targetId: bundle._id, details: "shareId: " + bundle.shareId + ", files: " + bundleFiles.length, req: req });

    res.writeHead(200, {
      "Content-Type": "application/zip",
      "Content-Disposition": safeContentDisposition((bundle.bundleName || "hermitstash-" + bundle.shareId) + ".zip", "attachment"),
    });

    var zip = b.archive.zip();
    var skippedFiles = [];
    var truncatedFiles = [];
    var bufferedBytes = 0;
    // Buffer each file before queuing — keeps the per-file skip-on-error
    // semantic (b.archive.zip aborts the whole stream if a queued source
    // throws mid-pipe; pre-buffering surfaces source errors here so we
    // can log + skip without poisoning the archive). ZIP_BUFFER_CAP bounds the
    // cumulative resident bytes so one request can't OOM the process.
    for (var f of bundleFiles) {
      if (bufferedBytes >= ZIP_BUFFER_CAP) {
        truncatedFiles.push(f.relativePath || f.originalName);
        continue;
      }
      try {
        var stream = await storage.getFileStream(f.storagePath, f.encryptionKey);
        var buf = await _streamToBuffer(stream);
        bufferedBytes += buf.length;
        zip.addFile(f.relativePath || f.originalName, buf);
      } catch (e) {
        logger.error("Zip skip", { error: e.message || String(e), file: f.originalName, bundle: bundle.shareId });
        skippedFiles.push(f.relativePath || f.originalName);
      }
    }
    var notices = [];
    if (skippedFiles.length > 0) {
      notices.push("The following files could not be included in this download:\n\n" + skippedFiles.join("\n"));
    }
    if (truncatedFiles.length > 0) {
      notices.push("This download exceeded the per-request size limit; the following files were omitted. Download them individually or by folder:\n\n" + truncatedFiles.join("\n"));
    }
    if (notices.length > 0) {
      zip.addFile("_MISSING_FILES.txt", Buffer.from(notices.join("\n\n") + "\n", "utf8"));
    }
    await zip.toStream(res);
  });

  // Download a subfolder from a bundle as ZIP (same DoS posture as /download —
  // rate-limited per subnet, with the same ZIP_BUFFER_CAP aggregate ceiling).
  app.get("/b/:shareId/folder", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    var bundle = bundlesRepo.findCompleteByShareId(req.params.shareId);
    if (!bundle) { res.writeHead(404); return res.end("Not found"); }
    if (isBundleExpired(bundle)) { res.writeHead(410); return res.end("Bundle expired"); }
    if (isBundleLocked(bundle, req.session, bundleAllowedMatch(bundle))) {
      res.writeHead(401); return res.end("Access restricted");
    }
    // The folder path is carried in the query string (?path=a/b), which the router
    // decodes exactly once via searchParams. A nested folder used to ride a single
    // percent-encoded PATH segment (…/folder/a%2Fb), but the hardened router now
    // refuses an encoded separator (%2f/%5c/%00) in the path — and decoding a
    // route param a second time (it is already decoded once) mangled any value
    // containing a literal '%'. The query param avoids both: decoded exactly once,
    // and not subject to the path-separator reject.
    var prefix = String(req.query.path || "");
    if (!prefix) { res.writeHead(400); return res.end("Folder path required"); }
    // Normalize: ensure trailing slash for prefix matching
    if (!prefix.endsWith("/")) prefix += "/";

    var allFiles = filesRepo.findLiveByBundleShareId(bundle.shareId);
    var folderFiles = allFiles.filter(function (f) {
      var rel = f.relativePath || f.originalName;
      return rel.startsWith(prefix) || rel === prefix.slice(0, -1);
    });
    if (folderFiles.length === 0) { res.writeHead(404); return res.end("Folder not found"); }

    var folderName = (prefix.replace(/\/+$/, "").split("/").pop() || "folder");
    audit.log(audit.ACTIONS.BUNDLE_ZIP_DOWNLOADED, { targetId: bundle._id, details: "folder: " + prefix + ", files: " + folderFiles.length, req: req });

    res.writeHead(200, {
      "Content-Type": "application/zip",
      "Content-Disposition": safeContentDisposition(folderName + ".zip", "attachment"),
    });

    var zip = b.archive.zip();
    var truncated = [];
    var folderBufferedBytes = 0;
    for (var i = 0; i < folderFiles.length; i++) {
      if (folderBufferedBytes >= ZIP_BUFFER_CAP) {
        truncated.push((folderFiles[i].relativePath || folderFiles[i].originalName).slice(prefix.length) || folderFiles[i].originalName);
        continue;
      }
      try {
        var stream = await storage.getFileStream(folderFiles[i].storagePath, folderFiles[i].encryptionKey);
        var buf = await _streamToBuffer(stream);
        folderBufferedBytes += buf.length;
        // Strip the prefix so the ZIP contains relative paths within the folder
        var relPath = (folderFiles[i].relativePath || folderFiles[i].originalName).slice(prefix.length) || folderFiles[i].originalName;
        zip.addFile(relPath, buf);
      } catch (e) {
        logger.error("Zip skip", { error: e.message || String(e), file: folderFiles[i].originalName });
      }
    }
    if (truncated.length > 0) {
      var truncNotice = "This download exceeded the per-request size limit; the following files were omitted. Download them individually:\n\n" + truncated.join("\n") + "\n";
      zip.addFile("_MISSING_FILES.txt", Buffer.from(truncNotice, "utf8"));
    }
    await zip.toStream(res);
  });

  // Delete bundle + all its files (owner or admin)
  // Rename bundle
  // requireScope("upload") fails closed for API-key principals: a key without a
  // mutate scope (e.g. "read") is rejected at the boundary before the
  // ownership check, so a least-privilege key can't rename any owner's bundle.
  // Session callers (no req.apiKey) pass straight through.
  app.post("/bundles/:shareId/rename", requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Not found.");
    if (!canEditOwned(bundle, req.user, "ownerId", req)) {
      throw new ForbiddenError("Not authorized.");
    }
    // parseJson already imported at top
    // sanitizeRename already imported at top
    var body = (await b.parsers.json(req)) || {};
    var result = sanitizeRename(body.name, { maxLength: 200 });
    if (!result.valid) throw new ValidationError(result.error || "Invalid name.");
    bundlesRepo.update(bundle._id, { $set: { bundleName: result.name } });
    res.json({ success: true, name: result.name });
  });

  // Rename/move a file within a sync bundle (metadata-only, no re-upload)
  app.post("/bundles/:shareId/file/rename", rateLimit.guard({ max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Not found.");
    if (!canEditOwned(bundle, req.user, "ownerId", req)) {
      throw new ForbiddenError("Not authorized.");
    }
    var body = (await b.parsers.json(req)) || {};
    var { handleSyncFileRename } = uploadHandler;
    var result = await handleSyncFileRename({
      bundleId: bundle._id,
      oldRelativePath: body.oldRelativePath,
      newRelativePath: body.newRelativePath,
      req: req,
    });
    if (result.error) throw new AppError(result.error, result.status || 400);
    res.json(result);
  });

  // Delete a single file from a sync bundle (soft delete with tombstone)
  app.post("/bundles/:shareId/file/:fileId/delete", rateLimit.guard({ max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Not found.");
    if (!canEditOwned(bundle, req.user, "ownerId", req)) {
      throw new ForbiddenError("Not authorized.");
    }
    var { handleSyncFileDelete } = uploadHandler;
    var result = await handleSyncFileDelete({ bundle: bundle, fileId: req.params.fileId, req: req });
    if (result.error) throw new AppError(result.error, result.status || 400);
    res.json(result);
  });

  app.post("/bundles/:shareId/delete", requireScope("upload"), async (req, res) => {
    if (!requireAuth(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) throw new NotFoundError("Not found.");
    // Only owner or admin can delete — and an admin-minted narrow API key
    // (req.apiKey present without admin scope) does NOT inherit the admin
    // ownership override; it must own the bundle. Interactive admin sessions do.
    if (!canEditOwned(bundle, req.user, "ownerId", req)) {
      throw new ForbiddenError("Not authorized.");
    }
    var bundleFiles = filesRepo.findByBundleShareId(bundle.shareId);
    for (var i = 0; i < bundleFiles.length; i++) {
      try { await storage.deleteFile(bundleFiles[i].storagePath); } catch (_e) { /* cleanup — storage file may already be gone */ }
      filesRepo.remove(bundleFiles[i]._id);
    }
    // Decrement stash stats if bundle belongs to a stash page
    if (bundle.stashId) {
      try { stashRepo.decrementBundleStats(bundle.stashId, bundle.totalSize); } catch (_e) {} // allow:silent-catch — best-effort stats decrement; never blocks the delete
    }
    bundlesRepo.remove(bundle._id);
    audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, targetEmail: bundle.uploaderEmail, details: "owner delete, shareId: " + bundle.shareId + ", files: " + bundleFiles.length, req: req });
    res.json({ success: true, filesDeleted: bundleFiles.length });
  });
};
