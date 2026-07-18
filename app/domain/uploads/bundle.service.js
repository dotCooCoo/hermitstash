/**
 * Bundle Service — business logic for upload bundles.
 * Handles bundle initialization, finalization, and validation.
 */
var b = require("../../../lib/vendor/blamejs");
var bundlesRepo = require("../../data/repositories/bundles.repo");
var { TIME, UPLOAD } = require("../../../lib/constants");
var { getTotalStorageUsed } = require("../../../lib/db");
var { ValidationError, NotFoundError, ForbiddenError } = require("../../shared/errors");
var { sanitizeRename } = require("../../shared/sanitize-filename");
var { validateEmail } = require("../../shared/validate");

/**
 * Initialize a new upload bundle.
 * Returns { bundleId, shareId, finalizeToken }.
 */
async function initBundle(opts) {
  var shareId = b.crypto.generateToken(32);
  var finalizeToken = b.crypto.generateToken(32);
  var bundlePassword = opts.password ? String(opts.password) : null;
  if (bundlePassword && bundlePassword.length < 4) throw new ValidationError("Password must be at least 4 characters.");
  // Validate uploader email format if provided
  var uploaderEmail = opts.uploaderEmail || null;
  if (uploaderEmail) {
    uploaderEmail = String(uploaderEmail).slice(0, 254);
    // Comma-separated recipients: validate each
    var parts = uploaderEmail.split(",").map(function (e) { return e.trim(); }).filter(Boolean);
    var validParts = parts.filter(function (e) { return validateEmail(e).valid; });
    uploaderEmail = validParts.length > 0 ? validParts.join(",") : null;
  }
  var message = opts.message ? String(opts.message).slice(0, 2000) : null;
  // Bundle expiry is server-authoritative. A client (including an anonymous
  // /drop uploader) may request a retention window via expiryDays, but the
  // operator's configured FILE_EXPIRY_DAYS is the CEILING — a request can only
  // shorten retention, never extend it past what the operator allows. When the
  // operator sets no expiry (0 = keep indefinitely) there is no per-operator
  // ceiling, so a client-chosen finite window is honored up to the absolute
  // MAX_EXPIRY_DAYS bound (which also keeps the date math from overflowing).
  var requestedDays = parseInt(opts.expiryDays, 10);
  requestedDays = (Number.isFinite(requestedDays) && requestedDays > 0) ? requestedDays : 0;
  var defaultExpiry = opts.defaultExpiryDays || 0;
  var ceilingDays = defaultExpiry > 0 ? defaultExpiry : UPLOAD.MAX_EXPIRY_DAYS;
  var effectiveDays = requestedDays > 0 ? Math.min(requestedDays, ceilingDays) : defaultExpiry;
  var expiresAt = effectiveDays > 0 ? new Date(Date.now() + effectiveDays * TIME.days(1)).toISOString() : null;

  // Email-gated access: clean and validate allowed emails through the same
  // canonical validator used for uploaderEmail above. validateEmail lowercases,
  // trims, caps length, and rejects control bytes / consecutive-dot locals —
  // so a stored entry always matches the validateEmail-normalized submission the
  // gate compares against (routes/bundles.js), closing the silent-lockout gap.
  var allowedEmails = null;
  if (opts.allowedEmails) {
    var cleaned = String(opts.allowedEmails).split(",")
      .map(function (e) { var v = validateEmail(e); return v.valid ? v.email : null; })
      .filter(Boolean);
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
    finalizeTokenHash: b.crypto.sha3Hash(finalizeToken),
    passwordHash: bundlePassword ? await b.auth.password.hash(bundlePassword) : null,
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
  var tokenHash = b.crypto.sha3Hash(token);
  if (!bundle.finalizeTokenHash || tokenHash.length !== bundle.finalizeTokenHash.length || !b.crypto.timingSafeEqual(tokenHash, bundle.finalizeTokenHash)) {
    throw new ForbiddenError("Invalid finalize token.");
  }

  bundlesRepo.update(bundleId, { $set: { status: "complete", finalizeTokenHash: null } });

  // Return refreshed bundle
  return bundlesRepo.findById(bundleId);
}

module.exports = { initBundle, checkStorageQuota, finalizeBundle };
