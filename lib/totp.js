/**
 * TOTP (Time-based One-Time Password) — RFC 6238.
 * Zero dependencies: uses Node.js crypto for HMAC-SHA1.
 * Backup codes: 10 single-use random codes generated on 2FA setup.
 */
var crypto = require("crypto"); // HMAC-SHA1 required by TOTP RFC 6238
var { generateBytes, generateToken: genToken, timingSafeEqual } = require("./crypto");

// Base32 encoding/decoding for TOTP secrets
var BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  var bits = "";
  for (var i = 0; i < buffer.length; i++) {
    bits += buffer[i].toString(2).padStart(8, "0");
  }
  var out = "";
  for (var j = 0; j < bits.length; j += 5) {
    var chunk = bits.substring(j, j + 5).padEnd(5, "0");
    out += BASE32[parseInt(chunk, 2)];
  }
  return out;
}

function base32Decode(str) {
  var bits = "";
  for (var i = 0; i < str.length; i++) {
    var idx = BASE32.indexOf(str[i].toUpperCase());
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  var bytes = [];
  for (var j = 0; j + 8 <= bits.length; j += 8) {
    bytes.push(parseInt(bits.substring(j, j + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * Generate a random TOTP secret (20 bytes, base32 encoded).
 */
function generateSecret() {
  return base32Encode(generateBytes(20));
}

/**
 * Compute TOTP code for a given time step.
 */
function computeCode(secret, timeStep) {
  var key = base32Decode(secret);
  var time = Buffer.alloc(8);
  time.writeUInt32BE(0, 0);
  time.writeUInt32BE(timeStep, 4);
  var hmac = crypto.createHmac("sha1", key).update(time).digest();
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1000000).padStart(6, "0");
}

/**
 * Verify a TOTP code (allows 1 step drift in each direction).
 * Returns the matched time step for replay prevention, or false.
 */
function verify(secret, code, lastUsedStep) {
  var timeStep = Math.floor(Date.now() / 30000);
  var userCode = Buffer.from(String(code).padStart(6, "0"));
  for (var i = -1; i <= 1; i++) {
    var step = timeStep + i;
    var expected = Buffer.from(computeCode(secret, step));
    if (userCode.length === expected.length && timingSafeEqual(expected, userCode)) {
      // Prevent replay: reject if this step was already used
      if (lastUsedStep && step <= lastUsedStep) return false;
      return step;
    }
  }
  return false;
}

/**
 * Generate otpauth:// URI for QR code scanning.
 */
function getUri(secret, email, issuer) {
  return "otpauth://totp/" + encodeURIComponent(issuer || "HermitStash") + ":" + encodeURIComponent(email) + "?secret=" + secret + "&issuer=" + encodeURIComponent(issuer || "HermitStash") + "&algorithm=SHA1&digits=6&period=30";
}

/**
 * Generate 10 single-use backup codes (8 chars each).
 */
function generateBackupCodes() {
  var codes = [];
  for (var i = 0; i < 10; i++) {
    codes.push(genToken(4));
  }
  return codes;
}

module.exports = { generateSecret, verify, getUri, generateBackupCodes };
