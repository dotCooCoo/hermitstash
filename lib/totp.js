/**
 * TOTP — thin wrapper over b.auth.totp.
 *
 * blamejs's b.auth.totp covers the SHA-512 path (the default for every
 * new enrollment since v1.9.11). HS keeps a legacy SHA-1 verify path
 * (routed through b.auth.totp.verify's verify-only SHA-1 mode) so users
 * enrolled before v1.9.11 can complete one final login and be force-migrated
 * through the re-enrollment flow. When the SHA-1 backlog reaches zero across
 * all operator deployments, drop the legacy branch and have callers use
 * b.auth.totp directly.
 */
var b = require("./vendor/blamejs");

var DEFAULT_ALGORITHM = "SHA512";

function generateSecret(algorithm) {
  // SHA-1 is verify-only legacy. New enrollments always go through
  // blamejs's defaults (SHA-512, 128-byte secret, 8 digits).
  if (algorithm && algorithm.toUpperCase() === "SHA1") {
    throw new Error("SHA-1 is verify-only — new TOTP enrollments must use SHA-512");
  }
  return b.auth.totp.generateSecret();
}

function computeCode(secret, timeStep) {
  return b.auth.totp.compute(secret, timeStep);
}

function verify(secret, code, lastUsedStep, algorithm) {
  // Legacy SHA-1 enrollments (pre-v1.9.11) verify through blamejs's verify-only
  // SHA-1 path. digits:6 reproduces HS's historical 6-digit code; verifyOnly
  // gates SHA-1 to verification (it can never reach generation). Returns the
  // matched step on success or false — the same contract as the SHA-512 path.
  var opts = (algorithm && algorithm.toUpperCase() === "SHA1")
    ? { lastUsedStep: lastUsedStep, algorithm: "sha1", verifyOnly: true, digits: 6 }
    : { lastUsedStep: lastUsedStep };
  var result = b.auth.totp.verify(secret, code, opts);
  if (result === false || result == null) return false;
  // b.auth.totp.verify returns the matched step number on success
  return result;
}

function getUri(secret, email, issuer, algorithm) {
  if (algorithm && algorithm.toUpperCase() === "SHA1") {
    var iss = encodeURIComponent(issuer || "HermitStash");
    return "otpauth://totp/" + iss + ":" + encodeURIComponent(email) +
      "?secret=" + secret + "&issuer=" + iss + "&algorithm=SHA1&digits=6&period=30";
  }
  return b.auth.totp.uri(secret, email, { issuer: issuer || "HermitStash" });
}

function generateBackupCodes() {
  return b.auth.totp.generateBackupCodes();
}

module.exports = {
  generateSecret: generateSecret,
  computeCode: computeCode,
  verify: verify,
  getUri: getUri,
  generateBackupCodes: generateBackupCodes,
  DEFAULT_ALGORITHM: DEFAULT_ALGORITHM,
};
