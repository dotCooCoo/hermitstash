/**
 * Shared email access-code request / verify logic for bundles and stash pages.
 */
var crypto = require("crypto");
var { sha3Hash, timingSafeEqual } = require("../../lib/crypto");
var { HASH_PREFIX, TIME } = require("../../lib/constants");
var accessCodesRepo = require("../data/repositories/bundleAccessCodes.repo");
var emailService = require("../../lib/email");

/**
 * Request an email access code for a bundle or stash.
 * @param {object} opts
 * @param {string} opts.shareId     — scope key (bundle shareId or "stash:" + stashId)
 * @param {string} opts.email       — plaintext email (already validated + lowercased)
 * @param {string} opts.bundleName  — display name for the email template
 * @param {string} opts.senderName  — who sent it (for the email template)
 * @returns {Promise<{ sent: boolean }>}
 */
async function requestCode(opts) {
  var shareId = opts.shareId;
  var email = opts.email;

  var emailHash = sha3Hash(HASH_PREFIX.EMAIL + email);
  var tenMinAgo = new Date(Date.now() - TIME.TEN_MIN).toISOString();
  var recentCount = accessCodesRepo.countRecentCodes(shareId, emailHash, tenMinAgo);
  if (recentCount >= 3) {
    return { sent: false };
  }

  accessCodesRepo.invalidatePending(shareId, emailHash);

  var codeNum = crypto.randomInt(0, 1000000);
  var code = String(codeNum).padStart(6, "0");

  accessCodesRepo.create({
    bundleShareId: shareId,
    email: email,
    code: code,
    attempts: 0,
    status: "pending",
    expiresAt: new Date(Date.now() + TIME.TEN_MIN).toISOString(),
    createdAt: new Date().toISOString(),
  });

  await emailService.sendBundleAccessCode({
    to: email,
    code: code,
    bundleName: opts.bundleName || null,
    senderName: opts.senderName || null,
    expiresMinutes: 10,
  });

  return { sent: true };
}

/**
 * Verify a submitted access code.
 * @param {object} opts
 * @param {string} opts.shareId — same scope key used in requestCode
 * @param {string} opts.email   — plaintext email
 * @param {string} opts.code    — submitted 6-digit code
 * @returns {{ success: boolean, error?: string, status?: number, attempts?: number }}
 */
function verifyCode(opts) {
  var shareId = opts.shareId;
  var email = opts.email;
  var code = opts.code;

  var emailHash = sha3Hash(HASH_PREFIX.EMAIL + email);
  var codeRecord = accessCodesRepo.findPendingCode(shareId, emailHash);
  if (!codeRecord) {
    return { success: false, error: "Invalid or expired code.", status: 401 };
  }

  if (codeRecord.attempts >= 5) {
    return { success: false, error: "Too many attempts. Request a new code.", status: 429 };
  }

  var submittedHash = sha3Hash(HASH_PREFIX.ACCESS_CODE + code);
  if (!timingSafeEqual(submittedHash, codeRecord.codeHash)) {
    accessCodesRepo.update(codeRecord._id, { $set: { attempts: codeRecord.attempts + 1 } });
    return { success: false, error: "Incorrect code.", status: 401, attempts: codeRecord.attempts + 1 };
  }

  accessCodesRepo.update(codeRecord._id, { $set: { status: "used" } });
  return { success: true };
}

module.exports = { requestCode, verifyCode };
