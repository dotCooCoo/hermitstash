/**
 * TOTP — thin wrapper over b.auth.totp.
 *
 * blamejs's b.auth.totp covers the SHA-512 path (the default for every
 * new enrollment since v1.9.11). HS retains a short legacy SHA-1
 * verify branch so users enrolled before v1.9.11 can complete one
 * final login and be force-migrated through the re-enrollment flow
 * (see Phase 5 in memory/project_roadmap_1_9_series.md). When the
 * SHA-1 backlog reaches zero across all operator deployments, drop
 * the legacy branch and have callers use b.auth.totp directly.
 */
var b = require("./vendor/blamejs");
var crypto = require("node:crypto");

var DEFAULT_ALGORITHM = "SHA512";

// Legacy SHA-1 path — RFC 6238 with 20-byte secret, 6-digit code.
// Authenticator-app interop relic. Only invoked when user.totpAlgorithm
// === "SHA1" on the verify path.
var BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function _base32Decode(str) {
  var bits = "";
  for (var i = 0; i < str.length; i++) {
    var idx = BASE32.indexOf(str[i].toUpperCase());
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  var bytes = [];
  for (var j = 0; j + 8 <= bits.length; j += 8) bytes.push(parseInt(bits.substring(j, j + 8), 2));
  return Buffer.from(bytes);
}
function _legacySha1Compute(secret, timeStep) {
  var key = _base32Decode(secret);
  var time = Buffer.alloc(8);
  time.writeUInt32BE(0, 0);
  time.writeUInt32BE(timeStep, 4);
  var hmac = crypto.createHmac("sha1", key).update(time).digest();
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1000000).padStart(6, "0");
}

function generateSecret(algorithm) {
  // SHA-1 is verify-only legacy. New enrollments always go through
  // blamejs's defaults (SHA-512, 128-byte secret, 8 digits).
  if (algorithm && algorithm.toUpperCase() === "SHA1") {
    throw new Error("SHA-1 is verify-only — new TOTP enrollments must use SHA-512");
  }
  return b.auth.totp.generateSecret();
}

function computeCode(secret, timeStep, algorithm) {
  if (algorithm && algorithm.toUpperCase() === "SHA1") {
    return _legacySha1Compute(secret, timeStep);
  }
  return b.auth.totp.compute(secret, timeStep);
}

function verify(secret, code, lastUsedStep, algorithm) {
  if (algorithm && algorithm.toUpperCase() === "SHA1") {
    var timeStep = Math.floor(Date.now() / 30000);
    var userCode = Buffer.from(String(code).padStart(6, "0"));
    for (var i = -1; i <= 1; i++) {
      var step = timeStep + i;
      var expected = Buffer.from(_legacySha1Compute(secret, step));
      if (userCode.length === expected.length && b.crypto.timingSafeEqual(expected, userCode)) {
        if (lastUsedStep && step <= lastUsedStep) return false;
        return step;
      }
    }
    return false;
  }
  // SHA-512 path delegates to blamejs. Returns the matched step on
  // success (for replay prevention) or false otherwise.
  var result = b.auth.totp.verify(secret, code, { lastUsedStep: lastUsedStep });
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
