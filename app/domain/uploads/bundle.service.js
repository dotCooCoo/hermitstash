/**
 * Bundle Service — business logic for upload bundles.
 * Handles bundle initialization, finalization, and validation.
 */
var bundlesRepo = require("../../data/repositories/bundles.repo");
var { TIME } = require("../../../lib/constants");
var { hashPassword, sha3Hash, generateShareId, generateToken, timingSafeEqual } = require("../../../lib/crypto");
var { getTotalStorageUsed } = require("../../../lib/db");
var { ValidationError, NotFoundError, ForbiddenError } = require("../../shared/errors");
var { sanitizeRename } = require("../../shared/sanitize-filename");

/**
 * Initialize a new upload bundle.
 * Returns { bundleId, shareId, finalizeToken }.
 */
async function initBundle(opts) {
  var shareId = generateShareId();
  var finalizeToken = generateToken(32);
  var bundlePassword = opts.password ? String(opts.password) : null;
  if (bundlePassword && bundlePassword.length < 4) throw new ValidationError("Password must be at least 4 characters.");
  // Validate uploader email format if provided
  var uploaderEmail = opts.uploaderEmail || null;
  if (uploaderEmail) {
    uploaderEmail = String(uploaderEmail).slice(0, 254);
    var { validateEmail } = require("../../shared/validate");
    // Comma-separated recipients: validate each
    var parts = uploaderEmail.split(",").map(function (e) { return e.trim(); }).filter(Boolean);
    var validParts = parts.filter(function (e) { return validateEmail(e).valid; });
    uploaderEmail = validParts.length > 0 ? validParts.join(",") : null;
  }
  var message = opts.message ? String(opts.message).slice(0, 2000) : null;
  var expiryDays = parseInt(opts.expiryDays, 10) || 0;
  var defaultExpiry = opts.defaultExpiryDays || 0;
  var expiresAt = (expiryDays > 0) ? new Date(Date.now() + expiryDays * TIME.ONE_DAY).toISOString()
    : (defaultExpiry > 0 ? new Date(Date.now() + defaultExpiry * TIME.ONE_DAY).toISOString() : null);

  // Email-gated access: clean and validate allowed emails
  var allowedEmails = null;
  if (opts.allowedEmails) {
    var cleaned = String(opts.allowedEmails).split(",")
      .map(function (e) { return e.trim().toLowerCase(); })
      .filter(function (e) { return e && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); });
    if (cleaned.length > 0) allowedEmails = cleaned.join(",");
  }

  // Compute access mode
  var hasPassword = !!bundlePassword;
  var hasEmailGate = !!allowedEmails;
  var accessMode = hasPassword && hasEmailGate ? "both"
    : hasPassword ? "password"
    : hasEmailGate ? "email"
    : "open";

  var bundle = bundlesRepo.create({
    shareId: shareId,
    uploaderName: opts.uploaderName || "Anonymous",
    uploaderEmail: uploaderEmail,
    ownerId: opts.ownerId || null,
    finalizeTokenHash: sha3Hash(finalizeToken),
    passwordHash: bundlePassword ? await hashPassword(bundlePassword) : null,
    message: message,
    expectedFiles: opts.fileCount || 0,
    receivedFiles: 0,
    skippedCount: opts.skippedCount || 0,
    skippedFiles: opts.skippedFiles || [],
    totalSize: 0,
    downloads: 0,
    status: opts.bundleType === "sync" ? "complete" : "uploading",
    bundleType: opts.bundleType === "sync" ? "sync" : "snapshot",
    seq: 0,
    teamId: opts.teamId || null,
    bundleName: opts.bundleName ? (function() { var r = sanitizeRename(opts.bundleName, { maxLength: 200 }); return r.valid ? r.name : null; })() : null,
    allowedEmails: allowedEmails,
    accessMode: accessMode,
    expiresAt: expiresAt,
    createdAt: new Date().toISOString(),
  });

  return { bundleId: bundle._id, shareId: shareId, finalizeToken: finalizeToken };
}

/**
 * Validate storage quota before allowing an upload.
 * Returns true if within quota, throws if exceeded.
 */
function checkStorageQuota(fileSize, maxStorageQuota) {
  if (!maxStorageQuota || maxStorageQuota <= 0) return true;
  var used = getTotalStorageUsed();
  if (used + fileSize > maxStorageQuota) {
    throw new ValidationError("Storage quota exceeded.");
  }
  return true;
}

/**
 * Finalize a bundle — mark as complete, validate token.
 */
function finalizeBundle(bundleId, token) {
  var bundle = bundlesRepo.findById(bundleId);
  if (!bundle) throw new NotFoundError("Bundle not found.");
  if (bundle.status === "complete" && bundle.bundleType !== "sync") throw new ValidationError("Already finalized.");

  // Verify finalize token (timing-safe)
  var tokenHash = sha3Hash(token);
  if (!bundle.finalizeTokenHash || tokenHash.length !== bundle.finalizeTokenHash.length || !timingSafeEqual(tokenHash, bundle.finalizeTokenHash)) {
    throw new ForbiddenError("Invalid finalize token.");
  }

  bundlesRepo.update(bundleId, { $set: { status: "complete", finalizeTokenHash: null } });

  // Return refreshed bundle
  return bundlesRepo.findById(bundleId);
}

module.exports = { initBundle, checkStorageQuota, finalizeBundle };
