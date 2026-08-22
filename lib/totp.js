/**
 * TOTP, over the framework's own implementation.
 *
 * Every new enrolment is SHA-512. The SHA-1 branch exists so a user holding an
 * older secret can complete one final sign-in and be sent through re-enrolment;
 * it verifies and can never generate. Drop it, and have callers reach the
 * framework directly, once no deployment has a SHA-1 secret left.
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
  // digits:6 reproduces the shorter code those older secrets were enrolled
  // with. Returns the matched step or false, as the SHA-512 path does.
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
