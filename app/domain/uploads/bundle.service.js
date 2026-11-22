/**
 * Bundle Service — business logic for upload bundles.
 * Handles bundle initialization, finalization, and validation.
 */
var b = require("../../../lib/vendor/blamejs");
var bundlesRepo = require("../../data/repositories/bundles.repo");
var filesRepo = require("../../data/repositories/files.repo");
var { TIME, UPLOAD } = require("../../../lib/constants");
var { getTotalStorageUsed } = require("../../../lib/db");
var passwordGate = require("../../../lib/password-gate");
var { ValidationError, NotFoundError, ForbiddenError } = require("../../shared/errors");
var { sanitizeRename } = require("../../shared/sanitize-filename");
var { validateEmail } = require("../../shared/validate");

// Codepoint policies for the two free-text fields an anonymous uploader can set.
// Both were length-sliced and otherwise unscreened, then rendered to every
// visitor of the bundle page and into the admin notification — whose SUBJECT
// line carries them with no escaping at all. HTML escaping neutralises markup;
// it does nothing about a right-to-left override that reverses how a filename
// reads, or zero-width and Tag-block characters that are invisible entirely.
//
// The policies are named EXPLICITLY because sanitize() does nothing otherwise —
// a profile alone leaves it a no-op, so passing one and assuming it strips is a
// silent way to have no protection. Homoglyphs are deliberately allowed, as they
// are for filenames: a name written in a non-Latin script is not an attack, and
// refusing one would refuse legitimate users.
var TEXT_OPTS = {
  bidiPolicy: "strip", controlPolicy: "strip", nullBytePolicy: "strip",
  zeroWidthPolicy: "strip", tagsPolicy: "strip", confusablePolicy: "allow",
};

function _safeText(value) {
  if (value === null || value === undefined) return value;
  var text = String(value);
  if (!text) return text;
  var cleaned = b.guardText.sanitize(text, TEXT_OPTS);
  return typeof cleaned === "string" ? cleaned : (cleaned && cleaned.value) || text;
}

/**
 * The read limit a sender asked for: 0 for an ordinary bundle, or 1..max for a
 * burn-after-read bundle, where max is the operator's maxBurnReads clamped to
 * UPLOAD.MAX_BURN_READS_CEILING. Only snapshot bundles take one.
 */
function resolveReadLimit(raw, bundleType, maxBurnReads) {
  if (raw === undefined || raw === null || raw === "") return 0;
  var n = typeof raw === "number" ? raw : (/^\d{1,4}$/.test(String(raw).trim()) ? Number(String(raw).trim()) : NaN);
  if (!Number.isInteger(n) || n < 0) throw new ValidationError("readLimit must be a whole number.");
  if (n === 0) return 0;
  if (bundleType === "sync") throw new ValidationError("A sync bundle cannot have a download limit.");
  var max = effectiveMaxBurnReads(maxBurnReads);
  if (n > max) throw new ValidationError("readLimit may not exceed " + max + ".");
  return n;
}

/** The operator's maxBurnReads, defaulted and clamped to the ceiling. */
function effectiveMaxBurnReads(maxBurnReads) {
  var max = parseInt(maxBurnReads, 10);
  if (!Number.isInteger(max) || max < 1) max = UPLOAD.MAX_BURN_READS_DEFAULT;
  return Math.min(max, UPLOAD.MAX_BURN_READS_CEILING);
}

/** The download-limit choices the upload form offers, up to the operator's maximum. */
function readLimitChoices(maxBurnReads) {
  var max = effectiveMaxBurnReads(maxBurnReads);
  var out = [1, 2, 3, 5, 10, 25, 50, 100].filter(function (n) { return n <= max; }); // allow:raw-byte-literal — download counts, not bytes
  if (out.indexOf(max) === -1) out.push(max);
  return out;
}

/**
 * Initialize a new upload bundle.
 * Returns { bundleId, shareId, finalizeToken }.
 * The init routes pass fileCount, skippedCount and skippedFiles as
 * uploadValidator.validateInitInput returned them, and allowedEmails as
 * uploadValidator.validateAllowedEmails returned it.
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
  var message = opts.message ? _safeText(String(opts.message).slice(0, 2000)) : null;
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

  var readLimit = resolveReadLimit(opts.readLimit, opts.bundleType, opts.maxBurnReads);
  if (readLimit > 0 && !expiresAt) {
    throw new ValidationError("A limited-download bundle needs an expiry. Choose how many days the link stays valid.");
  }

  // opts.allowedEmails is null or the comma-joined list that
  // uploadValidator.validateAllowedEmails returned: at most
  // UPLOAD.ALLOWED_EMAILS_MAX addresses, each normalized by validateEmail, which
  // is the normalization the gate in routes/bundles.js applies to a submission.
  var allowedEmails = opts.allowedEmails || null;

  // Compute access mode
  var hasPassword = !!bundlePassword;
  var hasEmailGate = !!allowedEmails;
  var accessMode = hasPassword && hasEmailGate ? "both"
    : hasPassword ? "password"
    : hasEmailGate ? "email"
    : "open";

  var bundle = bundlesRepo.create({
    shareId: shareId,
    uploaderName: _safeText(opts.uploaderName) || "Anonymous",
    uploaderEmail: uploaderEmail,
    ownerId: opts.ownerId || null,
    finalizeTokenHash: b.crypto.sha3Hash(finalizeToken),
    passwordHash: bundlePassword ? await passwordGate.hash(bundlePassword) : null,
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
    readLimit: readLimit,
    createdAt: new Date().toISOString(),
  });

  return { bundleId: bundle._id, shareId: shareId, finalizeToken: finalizeToken, readLimit: readLimit };
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
 * Whether token is the finalize token issued for bundle. The comparison is
 * timing-safe.
 */
function verifyFinalizeToken(bundle, token) {
  if (!bundle || !bundle.finalizeTokenHash) return false;
  var tokenHash = b.crypto.sha3Hash(String(token || ""));
  return tokenHash.length === bundle.finalizeTokenHash.length && b.crypto.timingSafeEqual(tokenHash, bundle.finalizeTokenHash);
}

/**
 * Finalize a bundle: check its finalize token and mark it complete. The token
 * hash stays on the bundle, and handleFinalize checks a repeated finalize
 * against it.
 */
function finalizeBundle(bundleId, token) {
  var bundle = bundlesRepo.findById(bundleId);
  // A burned bundle stays burned: finalizing it again would make its share
  // link serve files again.
  if (!bundle || bundle.status === "burned") throw new NotFoundError("Bundle not found.");
  if (bundle.status === "complete" && bundle.bundleType !== "sync") throw new ValidationError("Already finalized.");

  if (!verifyFinalizeToken(bundle, token)) {
    throw new ForbiddenError("Invalid finalize token.");
  }

  bundlesRepo.update(bundleId, { $set: { status: "complete" } });

  // Return refreshed bundle
  return bundlesRepo.findById(bundleId);
}

/**
 * Mark a burn-after-read bundle "burned" once it has no files left. The row
 * stays until its expiry, so its share link answers 410 like an expired one;
 * the expiry job removes it then.
 */
function markBurnedIfEmpty(bundleShareId) {
  if (filesRepo.findByBundleShareId(bundleShareId).length > 0) return false;
  var bundle = bundlesRepo.findByShareId(bundleShareId);
  if (!bundle || bundleReadLimit(bundle) === 0 || bundle.status === "burned") return false;
  bundlesRepo.update(bundle._id, { $set: { status: "burned" } });
  return true;
}

/**
 * The read budget a stored bundle row carries: 0 for an ordinary bundle.
 */
function bundleReadLimit(bundle) {
  var n = bundle ? Number(bundle.readLimit) : 0;
  return Number.isInteger(n) && n > 0 ? n : 0;
}

module.exports = { initBundle, checkStorageQuota, finalizeBundle, verifyFinalizeToken, resolveReadLimit, readLimitChoices, bundleReadLimit, markBurnedIfEmpty };
