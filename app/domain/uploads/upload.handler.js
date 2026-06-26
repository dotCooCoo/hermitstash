/**
 * Shared upload handlers — used by both /drop and /stash routes.
 * Each function takes a context object with resolved config and identity.
 * Routes remain thin wrappers that resolve auth/config then delegate here.
 */
var clientIp = require("../../../lib/client-ip");
var b = require("../../../lib/vendor/blamejs");
var nodePath = require("node:path");
var config = require("../../../lib/config");
var C = require("../../../lib/constants");
var filesRepo = require("../../data/repositories/files.repo");
var bundlesRepo = require("../../data/repositories/bundles.repo");
var storage = require("../../../lib/storage");
var audit = require("../../../lib/audit");
var logger = require("../../shared/logger");
var bundleService = require("./bundle.service");
var fileService = require("./file.service");
var uploadValidator = require("../../http/validators/upload.validator");
// Per-IP daily byte quota — lazy-built so the bytesPerDay limit
// follows config hot-reload. b.network.byteQuota.create requires a
// positive bytesPerDay, so the call is gated on publicIpQuotaBytes > 0
// at every call site (matching the prior in-house quota's "0 disables".
var _ipQuota = null;
var _ipQuotaBytes = 0;
function _getIpQuota() {
  if (!_ipQuota || _ipQuotaBytes !== config.publicIpQuotaBytes) {
    _ipQuota = b.network.byteQuota.create({ bytesPerDay: config.publicIpQuotaBytes });
    _ipQuotaBytes = config.publicIpQuotaBytes;
  }
  return _ipQuota;
}

// Per-IP quota bucket key. b.requestHelpers.ipKey keeps IPv4 exact but collapses
// IPv6 to its /64 — an end-site is allocated a whole /64 (RFC 6177 / RFC 4291
// §2.5.4) and rotates the low 64 bits at will, so keying the rolling-24h byte
// budget on the full /128 lets it mint unlimited fresh buckets and upload
// unbounded anonymous bytes past the cap. ipKey returns "" for an unparseable
// input; byteQuota throws on an empty key, so fall back to the raw canonical IP
// (which is exactly today's behavior for a degenerate input).
function _ipQuotaKey(req) {
  var ip = clientIp.getIp(req);
  return b.requestHelpers.ipKey(ip, { ipv6Bits: 64 }) || ip; // allow:raw-byte-literal — IPv6 routing prefix length (RFC 4291 §2.5.4), not a byte size
}
var { sanitizeFilename } = require("../../shared/sanitize-filename");
var syncEmitter = require("../../../lib/sync-emitter");
var usersRepo = require("../../data/repositories/users.repo");
var emailService = require("../integrations/email.service");
var webhook = require("../integrations/webhook.service");
var { host } = require("../../../middleware/send");

/**
 * Build structured audit detail JSON for file mutation events.
 */
function auditDetail(obj) {
  return JSON.stringify(obj);
}

/**
 * Resolve stash config overrides, falling back to global config.
 * Pass null for stash to get global config.
 */
function resolveUploadConfig(stash) {
  if (!stash) {
    return {
      maxFileSize: config.maxFileSize,
      maxFiles: config.publicMaxFiles,
      maxBundleSize: config.publicMaxBundleSize,
      allowedExtensions: config.allowedExtensions,
    };
  }
  return {
    maxFileSize: (stash.maxFileSize && stash.maxFileSize > 0) ? stash.maxFileSize : config.maxFileSize,
    maxFiles: (stash.maxFiles && stash.maxFiles > 0) ? stash.maxFiles : config.publicMaxFiles,
    maxBundleSize: (stash.maxBundleSize && stash.maxBundleSize > 0) ? stash.maxBundleSize : config.publicMaxBundleSize,
    allowedExtensions: stash.allowedExtensions ? stash.allowedExtensions.split(",").map(function (e) { return e.trim(); }).filter(Boolean) : config.allowedExtensions,
  };
}

// Refund a previously-reserved per-IP byte debit when the upload it was
// reserved for fails downstream (validation, save, or a post-write cap breach).
// b.network.byteQuota.record refuses negative byte counts, so the refund goes
// through the documented internal backend seam (the same counter record()
// mutates) with a negative delta. Best-effort: a missed refund only over-counts
// the uploader's OWN rolling-24h budget (fail-closed) and self-heals as bins
// slide, so a refund failure never grants extra quota.
function _refundIpQuota(req, bytes) {
  if (!(config.publicIpQuotaBytes > 0) || !bytes) return;
  try {
    var q = _getIpQuota();
    if (q && q._backend && typeof q._backend.account === "function") {
      q._backend.account(_ipQuotaKey(req), -bytes, q._now ? q._now() : Date.now());
    }
  } catch (_e) { /* refund best-effort — overcount fails closed, never grants quota */ }
}

/**
 * Check all quotas (storage, per-user, per-IP) for a file upload.
 *
 * The per-IP byte budget is RESERVED (debited) here the instant its check
 * passes — not after the save resolves — so concurrent in-flight uploads see
 * each other's debits and can't all pass a stale pre-write total and overrun
 * the cap (read-check-then-record TOCTOU). The reservation is released via
 * _refundIpQuota if the upload subsequently fails. The returned `ipReserved`
 * byte count tells the caller exactly how much to refund on a later failure.
 *
 * Returns { allowed: true, ipReserved } or { allowed: false, error, reason }.
 */
async function checkAllQuotas(fileSize, bundle, req) {
  // Storage quota
  try {
    bundleService.checkStorageQuota(fileSize, config.storageQuotaBytes);
  } catch (_e) {
    return { allowed: false, error: _e.message, reason: "storage quota exceeded" };
  }

  // Per-user quota
  if (config.perUserQuotaBytes > 0 && bundle.ownerId) {
    var userFiles = filesRepo.findAll({ uploadedBy: bundle.ownerId });
    var userTotal = 0;
    for (var i = 0; i < userFiles.length; i++) { userTotal += Number(userFiles[i].size) || 0; }
    if (userTotal + fileSize > config.perUserQuotaBytes) {
      return { allowed: false, error: "Personal storage quota exceeded.", reason: "per-user quota exceeded" };
    }
  }

  // Per-IP quota (anonymous only) — reserve-then-confirm.
  var ipReserved = 0;
  if (config.publicIpQuotaBytes > 0 && !bundle.ownerId) {
    var ipKey = _ipQuotaKey(req);
    var ipCheck = await _getIpQuota().check(ipKey, fileSize);
    if (!ipCheck.allowed) {
      return { allowed: false, error: "Upload quota exceeded. Try again later.", reason: "per-IP quota exceeded" };
    }
    // Debit immediately so the in-flight bytes are visible to a concurrent
    // check before THIS upload's long save window yields the event loop.
    await _getIpQuota().record(ipKey, fileSize);
    ipReserved = fileSize;
  }

  return { allowed: true, ipReserved: ipReserved };
}

/**
 * Handle single file upload.
 * @param {object} ctx - { bundle, file, fields, limits, uploadedBy, uploaderEmail, expiresAt, auditSuffix, req }
 */
async function handleFileUpload(ctx) {
  var bundle = ctx.bundle;
  var file = ctx.file;
  var fields = ctx.fields;
  var limits = ctx.limits;
  var suffix = ctx.auditSuffix || "";

  // Validate extension + size
  var fileCheck = uploadValidator.validateFile(file.filename, file.size, limits.allowedExtensions, limits.maxFileSize);
  if (!fileCheck.valid) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + fileCheck.reason + suffix, req: ctx.req });
    return { error: fileCheck.reason };
  }

  // Magic bytes
  try {
    var magicCheck = uploadValidator.validateMagicBytes(file.filename, file.data);
    if (!magicCheck.valid) {
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + suffix, req: ctx.req });
      return { error: magicCheck.reason };
    }
  } catch (_e) {
    // Fail closed: an internal error in the magic-byte gate must reject, not
    // fall through to the save — a defense-in-depth check that silently accepts
    // on exception is worse than no check at all.
    logger.error("Magic byte validation error", { file: file.filename, error: _e.message });
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: Could not validate file content." + suffix, req: ctx.req });
    return { error: "Could not validate file content." };
  }

  // Bundle limits
  var limitsCheck = uploadValidator.validateBundleLimits(bundle.receivedFiles + 1, limits.maxFiles, bundle.totalSize + file.size, limits.maxBundleSize);
  if (!limitsCheck.valid) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + limitsCheck.reason + suffix, req: ctx.req });
    return { error: limitsCheck.reason };
  }

  // Quotas
  var quota = await checkAllQuotas(file.size, bundle, ctx.req);
  if (!quota.allowed) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + quota.reason + suffix, req: ctx.req });
    return { error: quota.error };
  }

  var cleanRelPath = sanitizeFilename(fields.relativePath || file.filename, 500);
  var fileShareId, checksum, saved;
  var createdFileId = null; // set on the non-replace path; used for post-write rollback

  // Sync bundle: check for existing file with same relativePath → replace
  var replaced = false;
  var oldSize = 0;
  if (bundle.bundleType === "sync") {
    var existing = filesRepo.findAll({ bundleId: bundle._id })
      .filter(function (f) { return f.relativePath === cleanRelPath && !f.deletedAt; });
    if (existing.length > 0) {
      var old = existing[0];
      oldSize = old.size || 0;
      // Save new file, delete old blob, update existing record
      var ext = nodePath.extname(file.filename).toLowerCase();
      fileShareId = b.crypto.generateToken(32);
      var storagePath = "bundles/" + bundle.shareId + "/" + Date.now() + "-" + fileShareId + ext;
      checksum = b.crypto.sha3Hash(file.data);
      saved = await storage.saveFile(file.data, storagePath);
      try { await storage.deleteFile(old.storagePath); } catch (_e) { /* cleanup — old replaced-file may already be gone on S3 */ }
      replaced = true;
    }
  }

  // Atomically increment bundle.seq — must happen AFTER storage.saveFile
  // (which yields the event loop), so the seq we assign to the file + event
  // matches the final DB state even under concurrent uploads. Previously
  // three call sites each computed `(bundle.seq || 0) + 1` from the stale
  // in-memory value, which under concurrency produced duplicate seq numbers
  // and silently dropped events on the WS catch-up nodePath.
  var newSeq = bundlesRepo.incrementSeq(bundle._id);

  var now = new Date().toISOString();
  if (replaced) {
    filesRepo.update(old._id, { $set: {
      originalName: sanitizeFilename(file.filename),
      storagePath: saved.path, mimeType: file.mimetype, size: file.size,
      checksum: checksum, encryptionKey: saved.encryptionKey,
      teamId: bundle.teamId || null,
      updatedAt: now, seq: newSeq,
    }});
  } else {
    var result = await fileService.saveAndCreateFileRecord(file.data, {
      bundleShareId: bundle.shareId, bundleId: bundle._id,
      filename: file.filename, relativePath: cleanRelPath,
      mimeType: file.mimetype, uploadedBy: ctx.uploadedBy,
      uploaderEmail: ctx.uploaderEmail, expiresAt: ctx.expiresAt,
      // Inherit the bundle's team so team-scoped uploads land in the team's
      // shared file list (GET /teams/:teamId/files). null for non-team bundles.
      teamId: bundle.teamId || null,
      seq: newSeq,
    });
    fileShareId = result.shareId;
    checksum = result.checksum;
    saved = result.saved;
    createdFileId = result.doc ? result.doc._id : null;
  }

  // Per-IP byte quota was already debited at reservation time inside
  // checkAllQuotas (reserve-then-confirm), so there's no post-save record here —
  // recording again would double-count. A downstream failure refunds via
  // _refundIpQuota(quota.ipReserved).

  var action = replaced ? "file_replaced" : "file_added";
  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: auditDetail({ action: action, bundleId: bundle._id, file: file.filename, relativePath: cleanRelPath, size: file.size, checksum: checksum }), req: ctx.req });

  // Update counters atomically (seq already bumped atomically above). A plain
  // read-modify-write from the pre-save `bundle` snapshot lost increments under
  // concurrent uploads; incrementCounters does it in one UPDATE ... RETURNING.
  var sizeChange = replaced ? (file.size - oldSize) : file.size;
  var fileCountChange = replaced ? 0 : 1;
  var counters = bundlesRepo.incrementCounters(bundle._id, fileCountChange, sizeChange);

  // Authoritative limit enforcement on the POST-write value. The pre-save
  // validateBundleLimits check (above) reads a stale snapshot, so N concurrent
  // uploads each see the same pre-read receivedFiles/totalSize and all pass —
  // overshooting maxFiles/maxBundleSize by the in-flight concurrency. The atomic
  // incrementCounters RETURNING gives the true committed value; re-check it here
  // and, if THIS write pushed the bundle over a cap, undo the increment, delete
  // the just-saved blob + record, and reject. A replace adds no file and net
  // size delta is bounded by the per-file cap, but it can still grow totalSize,
  // so the size cap is re-checked on both paths.
  if (counters) {
    var postCheck = uploadValidator.validateBundleLimits(counters.receivedFiles, limits.maxFiles, counters.totalSize, limits.maxBundleSize);
    if (!postCheck.valid) {
      // Roll back the exact increment this writer committed.
      bundlesRepo.incrementCounters(bundle._id, -fileCountChange, -sizeChange);
      // Remove the blob + DB record this writer created. On the replace path the
      // old blob was already deleted and the existing record was overwritten in
      // place, so there is nothing to delete here without losing the prior file;
      // only the freshly-created (non-replace) record/blob is rolled back.
      if (!replaced) {
        try { if (saved && saved.path) { await storage.deleteFile(saved.path); } } catch (_e) { /* cleanup — blob may already be gone on S3 */ }
        try { if (createdFileId) { filesRepo.remove(createdFileId); } } catch (_e) { /* cleanup — record removal best-effort */ }
      }
      // Release the per-IP byte reservation — this upload didn't land.
      _refundIpQuota(ctx.req, quota.ipReserved);
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + postCheck.reason + " (post-write)" + suffix, req: ctx.req });
      return { error: postCheck.reason };
    }
  }

  // Emit sync event for WebSocket subscribers
  if (bundle.bundleType === "sync") {
    syncEmitter.emit("sync:" + bundle._id, {
      type: action, fileId: replaced ? existing[0]._id : fileShareId,
      relativePath: cleanRelPath, checksum: checksum, size: file.size, seq: newSeq,
    });
  }

  return { success: true, replaced: replaced, received: counters ? counters.receivedFiles : (bundle.receivedFiles + fileCountChange), total: bundle.expectedFiles };
}

/**
 * Handle chunked upload.
 * @param {object} ctx - { bundle, chunk, fields, limits, uploadedBy, uploaderEmail, expiresAt, auditSuffix, req }
 */
async function handleChunkUpload(ctx) {
  var bundle = ctx.bundle;
  var chunk = ctx.chunk;
  var fields = ctx.fields;
  var limits = ctx.limits;
  var suffix = ctx.auditSuffix || "";

  var chunkIndex = parseInt(fields.chunkIndex, 10);
  var totalChunks = parseInt(fields.totalChunks, 10);
  var fileId = String(fields.fileId || "");
  if (isNaN(chunkIndex) || isNaN(totalChunks) || !fileId) {
    return { error: "Missing chunk metadata." };
  }
  var chunkCheck = uploadValidator.validateChunk(chunkIndex, totalChunks, fileId);
  if (!chunkCheck.valid) return { error: chunkCheck.reason };
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(fileId)) return { error: "Invalid file ID." };

  // Early extension validation
  var earlyFilename = fields.filename || "file";
  var earlyExt = nodePath.extname(earlyFilename).toLowerCase();
  if (earlyExt && limits.allowedExtensions && limits.allowedExtensions.length > 0 && !limits.allowedExtensions.includes(earlyExt)) {
    return { error: "File type not allowed: " + earlyExt };
  }

  // Per-chunk size limit — prevent disk exhaustion before reassembly-time quota check
  var maxChunkSize = Math.max(limits.maxFileSize || C.BYTES.mib(10), C.BYTES.mib(10)); // at least 10MB per chunk
  if (chunk.data.length > maxChunkSize) {
    return { error: "Chunk too large." };
  }

  // Aggregate scratch cap. The per-chunk cap above bounds ONE chunk, but the
  // reassembly-time quota check only runs once ALL chunks arrive — so an attacker
  // could upload many chunks (and never send the last) to fill the scratch disk.
  // Sum the already-saved chunks for this file plus this one and refuse before the
  // write if it would exceed the file-size limit; discard the partial on a breach
  // so the scratch can't accumulate past one file's worth.
  if (limits.maxFileSize) {
    var existingChunks = storage.countChunks(bundle.shareId, fileId);
    var accumulated = chunk.data.length;
    var counted = 0;
    for (var ai = 0; ai < totalChunks && counted < existingChunks; ai++) {
      if (ai === chunkIndex) continue;
      var st = storage.statChunk(bundle.shareId, fileId, ai);
      if (st) { accumulated += st.size; counted++; }
    }
    if (accumulated > limits.maxFileSize) {
      storage.removeChunkAssembly(bundle.shareId, fileId);
      return { error: "Assembled file exceeds the maximum allowed size." };
    }
  }

  // Store chunk in the scratch directory (always local, never S3).
  try {
    storage.saveChunk(bundle.shareId, fileId, chunkIndex, chunk.data);
  } catch (e) {
    logger.error("Chunk save failed", { error: e.message || String(e), bundle: bundle._id });
    return { error: "Invalid nodePath." };
  }

  // Check if all chunks received
  var received = storage.countChunks(bundle.shareId, fileId);
  if (received < totalChunks) {
    return { success: true, chunksReceived: received, totalChunks: totalChunks };
  }

  // Sum chunk sizes before reassembly. A missing chunk stat means the assembly
  // is incomplete/corrupt — refuse rather than silently undercount, which would
  // let an over-cap file slip the quota check and OOM on the Buffer.concat below.
  var estimatedSize = 0;
  for (var ce = 0; ce < totalChunks; ce++) {
    var cs = storage.statChunk(bundle.shareId, fileId, ce);
    if (!cs) {
      storage.removeChunkAssembly(bundle.shareId, fileId);
      return { error: "Upload assembly incomplete or corrupt." };
    }
    estimatedSize += cs.size;
  }
  // Hard size cap BEFORE allocating the reassembly buffer (validateFile re-checks
  // post-concat, but the concat itself is the memory-exhaustion point).
  if (limits.maxFileSize && estimatedSize > limits.maxFileSize) {
    storage.removeChunkAssembly(bundle.shareId, fileId);
    return { error: "Assembled file exceeds the maximum allowed size." };
  }
  var quota = await checkAllQuotas(estimatedSize, bundle, ctx.req);
  if (!quota.allowed) {
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + quota.reason + " (chunked)" + suffix, req: ctx.req });
    return { error: quota.error };
  }

  // Reassemble
  var reassembled = [];
  for (var ci = 0; ci < totalChunks; ci++) {
    reassembled.push(storage.readChunk(bundle.shareId, fileId, ci));
  }
  var fullData = Buffer.concat(reassembled);

  // Clean up — remove the per-file assembly directory entirely.
  storage.removeChunkAssembly(bundle.shareId, fileId);

  // Validate reassembled file
  var filename = fields.filename || "file";
  var relativePath = fields.relativePath || filename;
  var fileCheck = uploadValidator.validateFile(filename, fullData.length, limits.allowedExtensions, limits.maxFileSize);
  if (!fileCheck.valid) {
    // Release the per-IP byte reservation made on estimatedSize above.
    _refundIpQuota(ctx.req, quota.ipReserved);
    return { error: fileCheck.reason };
  }

  try {
    var magicCheck = uploadValidator.validateMagicBytes(filename, fullData);
    if (!magicCheck.valid) {
      _refundIpQuota(ctx.req, quota.ipReserved);
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + magicCheck.reason + " (chunked)" + suffix, req: ctx.req });
      return { error: magicCheck.reason };
    }
  } catch (_e) {
    // Fail closed (chunked path): reject on an internal validation error and
    // release the per-IP byte reservation made on estimatedSize above, mirroring
    // the !magicCheck.valid branch — never fall through to the save.
    logger.error("Magic byte validation error (chunked)", { file: filename, error: _e.message });
    _refundIpQuota(ctx.req, quota.ipReserved);
    audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: Could not validate file content. (chunked)" + suffix, req: ctx.req });
    return { error: "Could not validate file content." };
  }

  // Save file and create DB record
  var chunkResult = await fileService.saveAndCreateFileRecord(fullData, {
    bundleShareId: bundle.shareId, bundleId: bundle._id,
    filename: filename, relativePath: relativePath,
    mimeType: fields.mimeType, uploadedBy: ctx.uploadedBy,
    uploaderEmail: ctx.uploaderEmail, expiresAt: ctx.expiresAt,
    // Inherit the bundle's team so chunked uploads to a team-scoped stash also
    // land in the team's file list (parity with the non-chunked path above).
    teamId: bundle.teamId || null,
  });
  var checksum = chunkResult.checksum;

  // The per-IP byte quota was reserved on estimatedSize at checkAllQuotas above
  // (reserve-then-confirm); no post-save record here. estimatedSize is the sum
  // of the chunk sizes and equals fullData.length, but if they diverge, refund
  // the difference so the debit matches the bytes actually stored.
  if (quota.ipReserved && fullData.length !== quota.ipReserved) {
    _refundIpQuota(ctx.req, quota.ipReserved - fullData.length);
  }

  var chunkCounters = bundlesRepo.incrementCounters(bundle._id, 1, fullData.length);

  // Authoritative POST-write limit enforcement — same TOCTOU close as the
  // single-file path. The reassembly-time checkAllQuotas + size cap above gate
  // on the stale pre-write bundle snapshot, so concurrent chunked finalizations
  // can each pass and overshoot maxFiles/maxBundleSize. Re-check the committed
  // receivedFiles/totalSize and roll this write back if it breached a cap.
  if (chunkCounters) {
    var chunkPostCheck = uploadValidator.validateBundleLimits(chunkCounters.receivedFiles, limits.maxFiles, chunkCounters.totalSize, limits.maxBundleSize);
    if (!chunkPostCheck.valid) {
      bundlesRepo.incrementCounters(bundle._id, -1, -fullData.length);
      try { if (chunkResult.saved && chunkResult.saved.path) { await storage.deleteFile(chunkResult.saved.path); } } catch (_e) { /* cleanup — blob may already be gone on S3 */ }
      try { if (chunkResult.doc && chunkResult.doc._id) { filesRepo.remove(chunkResult.doc._id); } } catch (_e) { /* cleanup — record removal best-effort */ }
      // Release the per-IP byte reservation (reconciled above to fullData.length).
      _refundIpQuota(ctx.req, fullData.length);
      audit.log(audit.ACTIONS.UPLOAD_REJECTED, { targetId: bundle._id, details: "reason: " + chunkPostCheck.reason + " (chunked, post-write)" + suffix, req: ctx.req });
      return { error: chunkPostCheck.reason };
    }
  }

  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, { targetId: bundle._id, details: auditDetail({ action: "file_added", bundleId: bundle._id, file: filename, size: fullData.length, chunks: totalChunks, checksum: checksum }), req: ctx.req });
  return { success: true, assembled: true, received: chunkCounters ? chunkCounters.receivedFiles : (bundle.receivedFiles + 1) };
}

/**
 * Handle bundle finalization — email notifications, webhooks, audit.
 * @param {object} ctx - { bundleId, token, uploaderName, sendUploaderEmail, stashSlug, stashId, auditSuffix, req }
 */
function handleFinalize(ctx) {
  var existing = bundlesRepo.findById(ctx.bundleId);
  if (!existing) return { error: "Bundle not found.", status: 404 };
  if (existing.status === "complete") {
    return { success: true, shareId: existing.shareId, shareUrl: host(ctx.req) + "/b/" + existing.shareId, emailSent: false };
  }

  var refreshed;
  try {
    refreshed = bundleService.finalizeBundle(ctx.bundleId, ctx.token);
  } catch (err) {
    if (err.statusCode === 403 || err.name === "ForbiddenError") return { error: err.message, status: 403 };
    if (err.statusCode === 404 || err.name === "NotFoundError") return { error: err.message, status: 404 };
    return { error: err.message, status: 400 };
  }

  var bundleUrl = host(ctx.req) + "/b/" + refreshed.shareId;
  var emailSent = false;

  if (refreshed.receivedFiles > 0) {
    var uploadedFiles = filesRepo.findAll({ bundleShareId: refreshed.shareId, status: "complete" })
      .map(function (f) { return { path: f.relativePath || f.originalName, size: f.size }; });

    var emailData = {
      uploaderName: ctx.uploaderName || refreshed.uploaderName || "Anonymous",
      uploaderEmail: ctx.sendUploaderEmail ? refreshed.uploaderEmail : null,
      bundleUrl: bundleUrl,
      uploadedCount: refreshed.receivedFiles, uploadedFiles: uploadedFiles,
      skippedCount: refreshed.skippedCount || 0, skippedFiles: refreshed.skippedFiles || [],
      totalSize: refreshed.totalSize,
    };

    // Send uploader confirmation if enabled and email present
    if (ctx.sendUploaderEmail && refreshed.uploaderEmail) {
      var recipients = refreshed.uploaderEmail.split(",").map(function (e) { return e.trim(); }).filter(Boolean);
      recipients.forEach(function (r) {
        emailService.sendUploaderConfirmation({ to: r, ...emailData }).catch(function (e) { logger.error("Email send failed", { error: e.message }); });
      });
      emailSent = true;
    }

    // Admin notification
    var adminUsers = usersRepo.findAll({ role: "admin" }).map(function (u) { return u.email; }).filter(Boolean);
    if (adminUsers.length > 0) {
      emailService.sendAdminNotification({ adminEmails: adminUsers, ...emailData }).catch(function (e) { logger.error("Email send failed", { error: e.message }); });
    }
  }

  var webhookData = { shareId: refreshed.shareId, uploaderName: ctx.uploaderName || refreshed.uploaderName || "Anonymous", files: refreshed.receivedFiles, size: refreshed.totalSize };
  if (ctx.stashSlug) webhookData.stashSlug = ctx.stashSlug;
  webhook.fire("bundle_finalized", webhookData);

  audit.log(audit.ACTIONS.BUNDLE_FINALIZED, { targetId: existing._id, targetEmail: refreshed.uploaderEmail, details: auditDetail({ action: "bundle_finalized", bundleId: existing._id, files: refreshed.receivedFiles, size: refreshed.totalSize, emailSent: emailSent }), req: ctx.req });

  return { success: true, shareId: refreshed.shareId, shareUrl: bundleUrl, emailSent: emailSent, refreshed: refreshed };
}

/**
 * Handle file deletion from a sync bundle (soft delete with tombstone).
 * @param {object} ctx - { bundle, fileId, req }
 */
async function handleSyncFileDelete(ctx) {
  var bundle = ctx.bundle;
  if (bundle.bundleType !== "sync") return { error: "Only sync bundles support file deletion." };

  var file = filesRepo.findById(ctx.fileId);
  if (!file || file.bundleId !== bundle._id) return { error: "File not found.", status: 404 };
  if (file.deletedAt) return { error: "File already deleted.", status: 404 };

  // Delete encrypted blob and sealed key from storage
  try { await storage.deleteFile(file.storagePath); } catch (_e) { /* cleanup — blob may already be gone on S3 */ }

  // Atomically bump bundle.seq — this is the race-safe counterpart of the
  // old read-then-write pattern. The `await storage.deleteFile` above yields
  // the event loop, so a concurrent delete would previously produce the same
  // stale seq. See bundles.repo.incrementSeq().
  var newSeq = bundlesRepo.incrementSeq(bundle._id);

  // Tombstone: set deletedAt, keep sealed fields for event emission
  var now = new Date().toISOString();
  filesRepo.update(file._id, { $set: {
    deletedAt: now, updatedAt: now, seq: newSeq,
    storagePath: null, encryptionKey: null,
  }});

  // Update bundle counters atomically (seq already bumped atomically above) —
  // a snapshot read-modify-write would lose a concurrent increment/decrement.
  bundlesRepo.incrementCounters(bundle._id, -1, -(file.size || 0));

  audit.log(audit.ACTIONS.FILE_DELETED, { targetId: file._id, details: auditDetail({ action: "file_removed", bundleId: bundle._id, file: file.originalName, relativePath: file.relativePath }), req: ctx.req });

  // Emit sync event
  syncEmitter.emit("sync:" + bundle._id, {
    type: "file_removed", fileId: file._id, relativePath: file.relativePath, seq: newSeq,
  });

  return { success: true, seq: newSeq };
}

/**
 * Handle sync file rename/move — update relativePath without re-uploading.
 * The encrypted blob stays unchanged; only metadata is updated.
 *
 * ctx: { bundleId, oldRelativePath, newRelativePath, req }
 */
async function handleSyncFileRename(ctx) {
  var bundle = bundlesRepo.findById(ctx.bundleId);
  if (!bundle) return { error: "Bundle not found.", status: 404 };
  if (bundle.bundleType !== "sync") return { error: "Only sync bundles support rename.", status: 400 };

  var oldPath = String(ctx.oldRelativePath || "").replace(/\\/g, "/");
  var newPath = String(ctx.newRelativePath || "").replace(/\\/g, "/");
  if (!oldPath || !newPath) return { error: "Both oldRelativePath and newRelativePath required.", status: 400 };

  // Sanitize new path
  var segments = newPath.split("/");
  segments = segments.map(function (s) { return sanitizeFilename(s); }).filter(Boolean);
  if (segments.length === 0) return { error: "Invalid new nodePath.", status: 400 };
  newPath = segments.join("/");

  // Find existing file by oldRelativePath
  var allFiles = filesRepo.findAll({ bundleId: bundle._id }).filter(function (f) {
    return !f.deletedAt && f.relativePath === oldPath;
  });
  if (allFiles.length === 0) return { error: "File not found at old nodePath.", status: 404 };

  var file = allFiles[0];
  var now = new Date().toISOString();
  // Atomic seq bump — prevents stale-read duplicates on parallel rename calls.
  var newSeq = bundlesRepo.incrementSeq(bundle._id);
  var newName = segments[segments.length - 1];

  // Update file metadata
  filesRepo.update(file._id, { $set: {
    relativePath: newPath,
    originalName: newName,
    updatedAt: now,
    seq: newSeq,
  }});

  audit.log(audit.ACTIONS.BUNDLE_FILE_UPLOADED, {
    targetId: bundle._id,
    details: auditDetail({ action: "file_renamed", bundleId: bundle._id, from: oldPath, to: newPath }),
    req: ctx.req,
  });

  // Emit sync event
  syncEmitter.emit("sync:" + bundle._id, {
    type: "file_renamed", fileId: file._id,
    oldRelativePath: oldPath, relativePath: newPath,
    checksum: file.checksum, size: file.size, seq: newSeq,
  });

  return { success: true, seq: newSeq, relativePath: newPath };
}

module.exports = { resolveUploadConfig, checkAllQuotas, handleFileUpload, handleChunkUpload, handleFinalize, handleSyncFileDelete, handleSyncFileRename };
