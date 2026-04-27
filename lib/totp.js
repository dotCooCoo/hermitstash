/**
 * TOTP (Time-based One-Time Password) — RFC 6238.
 *
 * Default for new enrollments: HMAC-SHA-512, 128-byte secret, 8-digit codes,
 * 30 s step, ±1 step drift window. The 128-byte size sits exactly at the
 * HMAC-SHA-512 block size B — every byte contributes to the inner/outer pads
 * without HMAC pre-hashing them down to L=64 bytes.
 *
 * RFC 6238 §1.2 explicitly defines SHA-256 and SHA-512 variants alongside
 * SHA-1; the legacy default in many implementations is SHA-1 only because of
 * authenticator-app interop history, not because the spec requires it.
 *
 * Legacy SHA-1 (20-byte secret, 6-digit code) remains verifiable so that
 * users enrolled before v1.9.11 can complete one final login and be forced
 * through the re-enrollment flow that upgrades them to SHA-512. Pass
 * algorithm="SHA1" explicitly to verify() for those secrets — never silently
 * dispatch to SHA-1 by default.
 *
 * Backup codes: 10 single-use random codes generated on enrollment, stored
 * SHA3-512-hashed, algorithm-independent.
 */
var crypto = require("crypto");
var { generateBytes, generateToken: genToken, timingSafeEqual } = require("./crypto");

var BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Per-algorithm parameters — secret length matches HMAC block size where
// possible (SHA-512 B=128) and HMAC output length otherwise (SHA-1 L=20).
var ALG_PARAMS = {
  SHA512: { secretBytes: 128, digits: 8, modulo: 100000000 },
  SHA1: { secretBytes: 20, digits: 6, modulo: 1000000 },
};

var DEFAULT_ALGORITHM = "SHA512";

function paramsFor(algorithm) {
  var p = ALG_PARAMS[algorithm];
  if (!p) throw new Error("Unsupported TOTP algorithm: " + algorithm);
  return p;
}

function nodeAlgName(algorithm) {
  if (algorithm === "SHA512") return "sha512";
  if (algorithm === "SHA1") return "sha1";
  throw new Error("Unsupported TOTP algorithm: " + algorithm);
}

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
 * Generate a random TOTP secret sized for the given algorithm (base32).
 */
function generateSecret(algorithm) {
  var alg = algorithm || DEFAULT_ALGORITHM;
  return base32Encode(generateBytes(paramsFor(alg).secretBytes));
}

/**
 * Compute the TOTP code for a given time step under the given algorithm.
 */
function computeCode(secret, timeStep, algorithm) {
  var alg = algorithm || DEFAULT_ALGORITHM;
  var params = paramsFor(alg);
  var key = base32Decode(secret);
  var time = Buffer.alloc(8);
  time.writeUInt32BE(0, 0);
  time.writeUInt32BE(timeStep, 4);
  var hmac = crypto.createHmac(nodeAlgName(alg), key).update(time).digest();
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % params.modulo).padStart(params.digits, "0");
}

/**
 * Verify a TOTP code (allows ±1 step drift). Returns the matched time step
 * for replay prevention, or false. Algorithm defaults to SHA-512; pass "SHA1"
 * explicitly to verify legacy enrollments.
 */
function verify(secret, code, lastUsedStep, algorithm) {
  var alg = algorithm || DEFAULT_ALGORITHM;
  var params = paramsFor(alg);
  var timeStep = Math.floor(Date.now() / 30000);
  var userCode = Buffer.from(String(code).padStart(params.digits, "0"));
  for (var i = -1; i <= 1; i++) {
    var step = timeStep + i;
    var expected = Buffer.from(computeCode(secret, step, alg));
    if (userCode.length === expected.length && timingSafeEqual(expected, userCode)) {
      if (lastUsedStep && step <= lastUsedStep) return false;
      return step;
    }
  }
  return false;
}

/**
 * Generate otpauth:// URI for QR code scanning or manual entry.
 */
function getUri(secret, email, issuer, algorithm) {
  var alg = algorithm || DEFAULT_ALGORITHM;
  var params = paramsFor(alg);
  var iss = encodeURIComponent(issuer || "HermitStash");
  return "otpauth://totp/" + iss + ":" + encodeURIComponent(email)
    + "?secret=" + secret
    + "&issuer=" + iss
    + "&algorithm=" + alg
    + "&digits=" + params.digits
    + "&period=30";
}

/**
 * Generate 10 single-use backup codes (8 chars each, hex). Algorithm-
 * independent; stored SHA3-512-hashed by the caller.
 */
function generateBackupCodes() {
  var codes = [];
  for (var i = 0; i < 10; i++) {
    codes.push(genToken(4));
  }
  return codes;
}

module.exports = {
  generateSecret,
  computeCode,
  verify,
  getUri,
  generateBackupCodes,
  DEFAULT_ALGORITHM,
};
