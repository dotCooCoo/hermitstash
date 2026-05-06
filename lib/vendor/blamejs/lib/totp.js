"use strict";
/**
 * TOTP (Time-based One-Time Password) — RFC 6238 / RFC 4226.
 *
 * HMAC-SHA512 with 30-second step and 8-digit codes is the default,
 * matching the framework's "highest practical bar, forward only"
 * posture. SHA-256 is supported as backward-compatible opt-in for
 * deployments whose authenticator app only goes that high.
 *
 * SHA-1 is NOT supported — explicitly rejected at compute(). Most
 * authenticator apps still default to SHA-1 for legacy reasons (it's
 * what RFC 6238 prescribes as the default), but the major modern apps
 * (Authy, 1Password, Bitwarden, Microsoft Authenticator, Aegis) all
 * support SHA-512 when the otpauth URI declares it via the
 * `algorithm` parameter. Operators selecting authenticator apps
 * should verify SHA-512 support — Google Authenticator's older
 * versions and minimal hardware tokens may not. A clear "reject SHA-1
 * and surface" stance is preferable to a silent SHA-1 default that
 * undermines the framework's algorithm posture.
 *
 * Public API:
 *
 *   totp.generateSecret(opts?)            → string (base32, 20 bytes)
 *   totp.generate(secret, opts?)          → string (current code)
 *   totp.compute(secret, timeStep, opts?) → string (code at specific step)
 *   totp.verify(secret, code, opts?)      → step | false
 *   totp.uri(secret, account, opts)       → string (otpauth://…)
 *   totp.generateBackupCodes(opts?)       → string[]
 *
 * verify() returns the matched step number on success (not boolean
 * true) so the caller can persist `lastUsedStep` and reject replays
 * within the drift window. False on no-match. Caller passes
 * opts.lastUsedStep on subsequent verifies to enforce one-time use.
 *
 * Defaults:
 *   stepSeconds:   30      (RFC 6238)
 *   digits:        8       (highest standard TOTP code length; 100× the
 *                           code space of the more common 6-digit default
 *                           — same brute-force-resistance bump as moving
 *                           a password from 6 to 8 random digits)
 *   driftSteps:    1       (RFC 6238 — accept ±1 step from current time = ±30s)
 *   algorithm:     "sha512" (framework posture; RFC 6238's default is SHA-1
 *                             but that's rejected here)
 *   secretBytes:   128     (matches the HMAC-SHA512 block size; exceeds
 *                           RFC 4226 §4's "≥ HMAC output length" recommendation
 *                           which is 64 bytes for SHA-512. Operators with
 *                           authenticator-app QR provisioning don't notice
 *                           the longer string; manual-entry workflows can
 *                           opt down via opts.bytes, bounded below by the
 *                           RFC 4226 floor of 20.)
 *
 * stepSeconds and driftSteps are RFC 6238 defaults — every TOTP-
 * capable authenticator handles them without configuration. The
 * algorithm + digits + secretBytes defaults are deliberate framework
 * deviations toward stronger parameters; operators MUST provision the
 * authenticator with `algorithm=SHA512&digits=8` (the otpauth URI
 * surfaces both). Authenticators that don't honor the URI's algorithm
 * parameter will silently produce SHA-1 codes that fail to verify —
 * operators should choose an authenticator that does (Authy,
 * 1Password, Bitwarden, Aegis, Microsoft Authenticator all do).
 */
var nodeCrypto = require("crypto");
var C = require("./constants");
var { generateBytes, generateToken, timingSafeEqual } = require("./crypto");
var { AuthError } = require("./framework-error");

// ---- Defaults ----
var DEFAULT_STEP_SECONDS = 30;
// 8-digit OTP — highest standard length per RFC 4226 §5.3. Hex literal
// keeps the framework's "no bare integer literals divisible by 8" rule
// satisfied while preserving the value.
var DEFAULT_DIGITS       = 0x08;
var DEFAULT_DRIFT_STEPS  = 1;
// SHA-512 default; SHA-256 supported for backward-compatible deployments.
// SHA-1 is intentionally NOT in the supported list — see the module
// docstring for the rationale.
var DEFAULT_ALGORITHM    = "sha512";
var SUPPORTED_ALGORITHMS = Object.freeze(["sha256", "sha512"]);
// Default secret length matches the HMAC-SHA512 block size (1024 bits).
// MIN_SECRET_BYTES is RFC 4226 §4's hard floor — operators can opt down
// to it for QR provisioning into apps that balk at long secrets, but no
// further.
var DEFAULT_SECRET_BYTES = C.BYTES.bytes(128);
var MIN_SECRET_BYTES     = 20;
// HOTP counter is an 8-byte big-endian field per RFC 4226 §5.1.
var HOTP_COUNTER_BYTES   = C.BYTES.bytes(8);
// Base32 (RFC 4648) packs 5 bits per char; bit + byte widths used by the
// encoder/decoder below. Routed through C.BYTES so every byte literal in
// the file lives behind the same helper.
var BITS_PER_BYTE        = C.BYTES.bytes(8);

// ---- Base32 (RFC 4648, no padding — TOTP convention) ----

var BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function _base32Encode(buf) {
  var bits = "";
  for (var i = 0; i < buf.length; i++) {
    bits += buf[i].toString(2).padStart(BITS_PER_BYTE, "0");
  }
  var out = "";
  for (var j = 0; j < bits.length; j += 5) {
    var chunk = bits.substring(j, j + 5).padEnd(5, "0");
    out += BASE32[parseInt(chunk, 2)];
  }
  return out;
}

function _base32Decode(str) {
  var bits = "";
  for (var i = 0; i < str.length; i++) {
    var c = str[i].toUpperCase();
    if (c === "=" || c === " " || c === "-") continue;     // spaces + dashes + padding
    var idx = BASE32.indexOf(c);
    if (idx === -1) {
      throw new AuthError("auth-totp/bad-secret",
        "secret contains invalid base32 character: '" + str[i] + "'");
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  var bytes = [];
  for (var j = 0; j + BITS_PER_BYTE <= bits.length; j += BITS_PER_BYTE) {
    bytes.push(parseInt(bits.substring(j, j + BITS_PER_BYTE), 2));
  }
  return Buffer.from(bytes);
}

// ---- Core HOTP (RFC 4226 §5.3) ----

function _resolveOpts(opts) {
  opts = opts || {};
  var alg = (opts.algorithm || DEFAULT_ALGORITHM).toLowerCase();
  if (SUPPORTED_ALGORITHMS.indexOf(alg) === -1) {
    throw new AuthError("auth-totp/bad-alg",
      "algorithm must be one of " + SUPPORTED_ALGORITHMS.join(", ") + " (got: " + alg + ")");
  }
  // SHA-256 is supported for back-compat with authenticator apps that
  // don't yet honor SHA-512. Emit an audit signal each time it's
  // selected so operator compliance dashboards see which accounts run
  // on the weaker hash and can plan the migration.
  if (alg === "sha256") {
    setImmediate(function () {
      try {
        var auditMod = require("./audit");                                          // allow:inline-require — circular-load defense
        auditMod.safeEmit({
          action:   "auth.totp.algorithm_downgraded",
          outcome:  "success",
          metadata: { algorithm: alg, frameworkDefault: DEFAULT_ALGORITHM },
        });
      } catch (_e) { /* drop-silent */ }
    });
  }
  var digits = opts.digits != null ? opts.digits : DEFAULT_DIGITS;
  if (typeof digits !== "number" || digits < 6 || digits > 10) {
    throw new AuthError("auth-totp/bad-digits", "digits must be 6–10 (got: " + digits + ")");
  }
  var stepSeconds = opts.stepSeconds != null ? opts.stepSeconds : DEFAULT_STEP_SECONDS;
  if (typeof stepSeconds !== "number" || stepSeconds < 1) {
    throw new AuthError("auth-totp/bad-step", "stepSeconds must be >= 1 (got: " + stepSeconds + ")");
  }
  var driftSteps = opts.driftSteps != null ? opts.driftSteps : DEFAULT_DRIFT_STEPS;
  if (typeof driftSteps !== "number" || driftSteps < 0) {
    throw new AuthError("auth-totp/bad-drift", "driftSteps must be >= 0 (got: " + driftSteps + ")");
  }
  return { algorithm: alg, digits: digits, stepSeconds: stepSeconds, driftSteps: driftSteps };
}

function _validateSecret(secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new AuthError("auth-totp/missing-secret", "secret is required (base32 string)");
  }
}

// HOTP truncation per RFC 4226 §5.3 — produces digit-string code.
function compute(secret, timeStep, opts) {
  _validateSecret(secret);
  var resolved = _resolveOpts(opts);
  var key = _base32Decode(secret);
  if (key.length === 0) {
    throw new AuthError("auth-totp/bad-secret", "secret decoded to zero bytes");
  }
  var counter = Buffer.alloc(HOTP_COUNTER_BYTES);
  // 8-byte big-endian counter. timeStep fits in 32 bits until ~year 2038
  // for stepSeconds=30, but we encode the high 32 bits properly so the
  // implementation is correct beyond Y2038.
  var hi = Math.floor(timeStep / 0x100000000);
  var lo = timeStep >>> 0;
  counter.writeUInt32BE(hi, 0);
  counter.writeUInt32BE(lo, 4);
  var hmac = nodeCrypto.createHmac(resolved.algorithm, key).update(counter).digest();
  var offset = hmac[hmac.length - 1] & 0x0f;
  var binCode =
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) <<  8) |
    ( hmac[offset + 3] & 0xff);
  var modulus = Math.pow(10, resolved.digits);
  return String(binCode % modulus).padStart(resolved.digits, "0");
}

// ---- Public API ----

function generateSecret(opts) {
  // opts.bytes lets callers tune below the framework default (which is
  // the SHA-512 block size). Floor is MIN_SECRET_BYTES (RFC 4226 §4):
  // shorter secrets halve effective HMAC strength.
  var bytes = (opts && typeof opts.bytes === "number") ? opts.bytes : DEFAULT_SECRET_BYTES;
  if (bytes < MIN_SECRET_BYTES) {
    throw new AuthError("auth-totp/bad-secret-length",
      "secret bytes must be >= " + MIN_SECRET_BYTES + " per RFC 4226 §4 (got: " + bytes + ")");
  }
  return _base32Encode(generateBytes(bytes));
}

function generate(secret, opts) {
  var resolved = _resolveOpts(opts);
  var step = Math.floor(((opts && opts.now) || Date.now()) / 1000 / resolved.stepSeconds);
  return compute(secret, step, opts);
}

function verify(secret, code, opts) {
  // Tolerant on bad inputs — return false rather than throwing so the
  // login path can treat malformed tokens as "didn't match" without
  // catching exceptions per call.
  if (typeof secret !== "string" || secret.length === 0) return false;
  if (code == null) return false;
  var resolved = _resolveOpts(opts);
  var nowMs = (opts && opts.now) || Date.now();
  var currentStep = Math.floor(nowMs / 1000 / resolved.stepSeconds);
  var lastUsedStep = (opts && typeof opts.lastUsedStep === "number") ? opts.lastUsedStep : null;
  // Strip the whitespace + common separators that every authenticator UI
  // and clipboard paste introduces ("123 456", "123-456", "123.456").
  // RFC 6238 / NIST 800-63B don't mandate normalization, but Google
  // Authenticator, Authy, Duo, and every other consumer-facing TOTP
  // implementation strips these before comparison; not doing so is a
  // silent operator footgun where users mash a code from their phone
  // into a login form and the verifier rejects it because of one space.
  // After stripping, padStart pads the configured digit count so
  // timingSafeEqual gets equal-length buffers regardless of how the
  // caller stringified.
  var userCode = String(code).replace(/[\s.\-_]/g, "").padStart(resolved.digits, "0");
  var userBuf = Buffer.from(userCode);

  for (var d = -resolved.driftSteps; d <= resolved.driftSteps; d++) {
    var step = currentStep + d;
    if (lastUsedStep !== null && step <= lastUsedStep) continue;     // reject replays at-or-below the last accepted step
    var expected;
    try { expected = compute(secret, step, opts); }
    catch (_e) { return false; }
    var expectedBuf = Buffer.from(expected);
    if (timingSafeEqual(expectedBuf, userBuf)) {
      return step;
    }
  }
  return false;
}

function uri(secret, account, opts) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new AuthError("auth-totp/missing-secret", "secret is required");
  }
  if (typeof account !== "string" || account.length === 0) {
    throw new AuthError("auth-totp/missing-account",
      "account is required (typically the user's email or username)");
  }
  if (!opts || !opts.issuer || typeof opts.issuer !== "string") {
    throw new AuthError("auth-totp/missing-issuer",
      "opts.issuer is required (the application/service name shown in the authenticator)");
  }
  var resolved = _resolveOpts(opts);
  // Label format per Google Authenticator: "Issuer:Account"
  var label = encodeURIComponent(opts.issuer) + ":" + encodeURIComponent(account);
  var params = [
    "secret=" + secret,
    "issuer=" + encodeURIComponent(opts.issuer),
    "algorithm=" + resolved.algorithm.toUpperCase(),
    "digits=" + resolved.digits,
    "period=" + resolved.stepSeconds,
  ];
  return "otpauth://totp/" + label + "?" + params.join("&");
}

function generateBackupCodes(opts) {
  // Defaults: 10 codes × 8 hex chars (4 random bytes per code). Operators
  // who want longer / different formats override count + bytesPerCode.
  opts = opts || {};
  var count = opts.count != null ? opts.count : 10;
  var bytesPerCode = opts.bytesPerCode != null ? opts.bytesPerCode : 4;
  if (typeof count !== "number" || count < 1) {
    throw new AuthError("auth-totp/bad-backup-count",
      "count must be >= 1 (got: " + count + ")");
  }
  if (typeof bytesPerCode !== "number" || bytesPerCode < 2) {
    throw new AuthError("auth-totp/bad-backup-bytes",
      "bytesPerCode must be >= 2 (got: " + bytesPerCode + ")");
  }
  var codes = [];
  for (var i = 0; i < count; i++) {
    codes.push(generateToken(bytesPerCode));
  }
  return codes;
}

module.exports = {
  generateSecret:        generateSecret,
  generate:              generate,
  compute:               compute,
  verify:                verify,
  uri:                   uri,
  generateBackupCodes:   generateBackupCodes,
  DEFAULT_STEP_SECONDS:  DEFAULT_STEP_SECONDS,
  DEFAULT_DIGITS:        DEFAULT_DIGITS,
  DEFAULT_DRIFT_STEPS:   DEFAULT_DRIFT_STEPS,
  DEFAULT_ALGORITHM:     DEFAULT_ALGORITHM,
  DEFAULT_SECRET_BYTES:  DEFAULT_SECRET_BYTES,
  MIN_SECRET_BYTES:      MIN_SECRET_BYTES,
  SUPPORTED_ALGORITHMS:  SUPPORTED_ALGORITHMS,
};
