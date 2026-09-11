// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var C = require("./constants");
var base32 = require("./base32");
var { generateBytes, generateToken, timingSafeEqual } = require("./crypto");
var { AuthError } = require("./framework-error");

var DEFAULT_STEP_SECONDS = 30;
var DEFAULT_DIGITS       = 0x08;
var DEFAULT_DRIFT_STEPS  = 1;
var DEFAULT_ALGORITHM    = "sha512";
var SUPPORTED_ALGORITHMS = Object.freeze(["sha256", "sha512"]);
var VERIFY_ONLY_ALGORITHMS = Object.freeze(["sha1"]);
var DEFAULT_SECRET_BYTES = C.BYTES.bytes(128);
var MIN_SECRET_BYTES     = 20;
var HOTP_COUNTER_BYTES   = C.BYTES.bytes(8);

function _base32Encode(buf) {
  return base32.encode(buf, { padding: false });
}

function _base32Decode(str) {
  try {
    return base32.decode(str, { loose: true });
  } catch (e) {
    throw new AuthError("auth-totp/bad-secret",
      "secret contains invalid base32 character" + (e && e.message ? ": " + e.message : ""));
  }
}

function _emitTotpAudit(action, alg) {
  setImmediate(function () {
    try {
      var auditMod = require("./audit");                                            // allow:inline-require — circular-load defense
      auditMod.safeEmit({
        action:   action,
        outcome:  "success",
        metadata: { algorithm: alg, frameworkDefault: DEFAULT_ALGORITHM },
      });
    } catch (_e) { /* drop-silent */ }
  });
}

function _resolveOpts(opts, ctx) {
  opts = opts || {};
  var allowVerifyOnly = !!(ctx && ctx.allowVerifyOnly);
  var alg = (opts.algorithm || DEFAULT_ALGORITHM).toLowerCase();
  var verifyOnly = false;
  if (SUPPORTED_ALGORITHMS.indexOf(alg) === -1) {
    if (allowVerifyOnly && opts.verifyOnly === true && VERIFY_ONLY_ALGORITHMS.indexOf(alg) !== -1) {
      verifyOnly = true;
    } else {
      throw new AuthError("auth-totp/bad-alg",
        "algorithm must be one of " + SUPPORTED_ALGORITHMS.join(", ") + " (got: " + alg + ")" +
        (VERIFY_ONLY_ALGORITHMS.indexOf(alg) !== -1
          ? "; " + alg + " is accepted only by verify() with { verifyOnly: true }"
          : ""));
    }
  }
  if (alg === "sha256") {
    _emitTotpAudit("auth.totp.algorithm_downgraded", alg);
  } else if (verifyOnly) {
    _emitTotpAudit("auth.totp.legacy_sha1_verify", alg);
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
  return {
    algorithm: alg, digits: digits, stepSeconds: stepSeconds,
    driftSteps: driftSteps, verifyOnly: verifyOnly,
  };
}

function _validateSecret(secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new AuthError("auth-totp/missing-secret", "secret is required (base32 string)");
  }
}

function _hotp(secret, timeStep, resolved) {
  var key = _base32Decode(secret);
  if (key.length === 0) {
    throw new AuthError("auth-totp/bad-secret", "secret decoded to zero bytes");
  }
  var counter = Buffer.alloc(HOTP_COUNTER_BYTES);
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

function compute(secret, timeStep, opts) {
  _validateSecret(secret);
  var resolved = _resolveOpts(opts);
  return _hotp(secret, timeStep, resolved);
}

function generateSecret(opts) {
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
  if (typeof secret !== "string" || secret.length === 0) return false;
  if (code == null) return false;
  var resolved = _resolveOpts(opts, { allowVerifyOnly: true });
  var nowMs = (opts && opts.now) || Date.now();
  var currentStep = Math.floor(nowMs / 1000 / resolved.stepSeconds);
  var lastUsedStep = (opts && typeof opts.lastUsedStep === "number") ? opts.lastUsedStep : null;
  var userCode = String(code).replace(/[\s.\-_]/g, "").padStart(resolved.digits, "0");
  var userBuf = Buffer.from(userCode);

  var matchedStep = null;
  for (var d = -resolved.driftSteps; d <= resolved.driftSteps; d++) {
    var step = currentStep + d;
    if (lastUsedStep !== null && step <= lastUsedStep) continue;
    var expected;
    try { expected = _hotp(secret, step, resolved); }
    catch (_e) { return false; }
    var expectedBuf = Buffer.from(expected);
    if (timingSafeEqual(expectedBuf, userBuf)) {
      if (matchedStep === null) matchedStep = step;
    }
  }
  return matchedStep === null ? false : matchedStep;
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
  VERIFY_ONLY_ALGORITHMS: VERIFY_ONLY_ALGORITHMS,
};
