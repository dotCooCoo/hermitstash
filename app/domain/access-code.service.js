/**
 * Shared email access-code request / verify logic for bundles and stash pages.
 */
var b = require("../../lib/vendor/blamejs");
var { HASH_PREFIX, TIME } = require("../../lib/constants");
var fieldCrypto = require("../../lib/field-crypto");
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

  // Must match exactly how field-crypto seals bundle_access_codes.emailHash — the
  // keyed MAC (lower:true), NOT the legacy unkeyed namespaceHash. Computing the
  // unkeyed digest here would never match the stored keyed digest, silently
  // killing the whole email-access-code gate (the v1.12.0 keyed-index drift).
  var emailHash = fieldCrypto.derivedKeyed(HASH_PREFIX.EMAIL, email, true);
  var tenMinAgo = new Date(Date.now() - TIME.minutes(10)).toISOString();
  var recentCount = accessCodesRepo.countRecentCodes(shareId, emailHash, tenMinAgo);
  if (recentCount >= 3) {
    return { sent: false };
  }

  accessCodesRepo.invalidatePending(shareId, emailHash);

  var codeNum = b.crypto.randomInt(0, 1000000);
  var code = String(codeNum).padStart(6, "0");

  accessCodesRepo.create({
    bundleShareId: shareId,
    email: email,
    code: code,
    attempts: 0,
    status: "pending",
    expiresAt: new Date(Date.now() + TIME.minutes(10)).toISOString(),
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

  // Must match exactly how field-crypto seals bundle_access_codes.emailHash — the
  // keyed MAC (lower:true), NOT the legacy unkeyed namespaceHash. Computing the
  // unkeyed digest here would never match the stored keyed digest, silently
  // killing the whole email-access-code gate (the v1.12.0 keyed-index drift).
  var emailHash = fieldCrypto.derivedKeyed(HASH_PREFIX.EMAIL, email, true);
  // Compute the submitted-code hash unconditionally so the no-pending-code path
  // and the wrong-code path pay the same derive cost (no timing oracle for which
  // emails have a code outstanding).
  var submittedHash = fieldCrypto.derivedKeyed(HASH_PREFIX.ACCESS_CODE, code, false);
  var codeRecord = accessCodesRepo.findPendingCode(shareId, emailHash);
  // Identical message + status for "no pending code" and "wrong code": a distinct
  // message/shape would let an attacker probe which emails have a code in flight.
  if (!codeRecord) {
    return { success: false, error: "Invalid or expired code.", status: 401 };
  }

  if (codeRecord.attempts >= 5) {
    // Surface the current attempt count so the lockout itself becomes auditable
    // (callers gate the BUNDLE_ACCESS_CODE_FAILED audit on a truthy `attempts`).
    return { success: false, error: "Too many attempts. Request a new code.", status: 429, attempts: codeRecord.attempts };
  }

  if (!b.crypto.timingSafeEqual(submittedHash, codeRecord.codeHash)) {
    accessCodesRepo.update(codeRecord._id, { $set: { attempts: codeRecord.attempts + 1 } });
    // Return the post-increment count (matching what was just written) so the
    // caller's `if (result.attempts)` brute-force audit gate fires.
    return { success: false, error: "Invalid or expired code.", status: 401, attempts: codeRecord.attempts + 1 };
  }

  // Consume the code with an ATOMIC compare-and-set (pending→used) so two
  // simultaneous redemptions of the same valid code cannot both succeed — the
  // loser changes 0 rows and is refused with the same generic message.
  if (!accessCodesRepo.claimPending(codeRecord._id)) {
    return { success: false, error: "Invalid or expired code.", status: 401 };
  }
  return { success: true };
}

module.exports = { requestCode, verifyCode };
