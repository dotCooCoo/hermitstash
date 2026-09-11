// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var argon2 = require("../argon2-builtin");
var C = require("../constants");
var httpClient = require("../http-client");
var hibpSha1 = require("../framework-sha1-hibp");
var safeUrl = require("../safe-url");
var timingSafeEqual = require("../crypto").timingSafeEqual;
var { AuthError } = require("../framework-error");

var DEFAULT_PARAMS = Object.freeze({
  memoryCost:  C.BYTES.kib(64),
  timeCost:    3,
  parallelism: 4,
});

var MAX_PLAINTEXT_BYTES = C.BYTES.kib(4);

var DEFAULT_POLICY = Object.freeze({
  minLength:              0x08,
  maxLength:              MAX_PLAINTEXT_BYTES,
  forbidCommon:           [],
  useBundledCommon:       true,
  denyContextSubstrings:  true,
  breachCheck:            null,
  breachThreshold:        1,
  failClosed:             false,
  hibpEndpoint:           "https://api.pwnedpasswords.com",
  hibpTimeoutMs:          C.TIME.seconds(1.5),
  mustRotateAfterMs:      null,
  historyMinDistance:     0,
  complexity:             null,
  dictionary:             [],
});

var COMPLEXITY_DEFAULT = Object.freeze({
  minCategories:     0,
  categories:        ["lower", "upper", "digit", "special"],
  minRunRepeat:      0,
  minSequenceLength: 0,
});

var POLICY_PROFILES = Object.freeze({
  "nist-aal2": Object.freeze({
    minLength:    C.BYTES.bytes(8),
    breachCheck:  "haveibeenpwned",
  }),
  "pci-4.0": Object.freeze({
    minLength:           12,
    breachCheck:         "haveibeenpwned",
    mustRotateAfterMs:   C.TIME.days(90),
    historyMinDistance:  4,
  }),
  "hipaa-aal2": Object.freeze({
    minLength:           12,
    breachCheck:         "haveibeenpwned",
    mustRotateAfterMs:   C.TIME.days(180),
    historyMinDistance:  4,
    complexity: {
      minCategories: 3,
      minRunRepeat:  3,
      minSequenceLength: 3,
    },
  }),
});

var vendorData = require("../vendor-data");
var _bundledCommonPasswords = null;
function _loadBundledCommon() {
  if (_bundledCommonPasswords) return _bundledCommonPasswords;
  var text = vendorData.getAsString("common-passwords-top-10000");
  var set = new Set();
  var lines = text.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line.length > 0) set.add(line.toLowerCase());
  }
  _bundledCommonPasswords = set;
  return _bundledCommonPasswords;
}
function _ok(extra) { return Object.assign({ ok: true }, extra || {}); }
function _fail(code, message) {
  return { ok: false, code: "policy/" + code, message: message };
}

async function _argon2Verify(stored, plaintext) {
  if (typeof stored !== "string" || stored.indexOf("$argon2id$") !== 0) return false;
  try { return await argon2.verify(stored, plaintext); }
  catch (_e) { return false; }
}

function _hasCategory(plaintext, category) {
  if (category === "lower")   return /[a-z]/.test(plaintext);
  if (category === "upper")   return /[A-Z]/.test(plaintext);
  if (category === "digit")   return /[0-9]/.test(plaintext);
  if (category === "special") return /[^A-Za-z0-9]/.test(plaintext);
  return false;
}

function _hasRunOfLength(plaintext, n) {
  if (n < 2) return false;
  for (var i = 0; i + n <= plaintext.length; i++) {
    var c = plaintext.charCodeAt(i);
    var allSame = true;
    for (var j = 1; j < n; j++) {
      if (plaintext.charCodeAt(i + j) !== c) { allSame = false; break; }
    }
    if (allSame) return true;
  }
  return false;
}

function _hasSequenceOfLength(plaintext, n) {
  if (n < 3) return false;
  for (var i = 0; i + n <= plaintext.length; i++) {
    var ascending = true, descending = true;
    for (var j = 1; j < n; j++) {
      var diff = plaintext.charCodeAt(i + j) - plaintext.charCodeAt(i + j - 1);
      if (diff !== 1)  ascending  = false;
      if (diff !== -1) descending = false;
    }
    if (ascending || descending) return true;
  }
  return false;
}

function policy(opts) {
  opts = opts || {};
  if (typeof opts.profile === "string" && opts.profile.length > 0) {
    if (!Object.prototype.hasOwnProperty.call(POLICY_PROFILES, opts.profile)) {
      throw new AuthError("auth-password/bad-policy",
        "policy.profile must be one of " + Object.keys(POLICY_PROFILES).join("/") +
        ", got " + JSON.stringify(opts.profile));
    }
    opts = Object.assign({}, POLICY_PROFILES[opts.profile], opts);
    delete opts.profile;
  }
  var p = Object.assign({}, DEFAULT_POLICY, opts);
  if (typeof p.minLength !== "number" || p.minLength < 1 || p.minLength > MAX_PLAINTEXT_BYTES) {
    throw new AuthError("auth-password/bad-policy",
      "policy.minLength must be in [1, " + MAX_PLAINTEXT_BYTES + "]");
  }
  if (typeof p.maxLength !== "number" || p.maxLength < p.minLength || p.maxLength > MAX_PLAINTEXT_BYTES) {
    throw new AuthError("auth-password/bad-policy",
      "policy.maxLength must be in [minLength, " + MAX_PLAINTEXT_BYTES + "]");
  }
  if (p.breachCheck !== null && p.breachCheck !== "haveibeenpwned") {
    throw new AuthError("auth-password/bad-policy",
      "policy.breachCheck must be null or 'haveibeenpwned', got " + JSON.stringify(p.breachCheck));
  }
  if (p.hibpEndpoint) {
    safeUrl.parse(p.hibpEndpoint, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS, errorClass: AuthError });
  }
  if (p.mustRotateAfterMs !== null &&
      (typeof p.mustRotateAfterMs !== "number" || !isFinite(p.mustRotateAfterMs) || p.mustRotateAfterMs <= 0)) {
    throw new AuthError("auth-password/bad-policy",
      "policy.mustRotateAfterMs must be a positive finite number or null");
  }
  if (typeof p.historyMinDistance !== "number" || !isFinite(p.historyMinDistance) ||
      p.historyMinDistance < 0 || Math.floor(p.historyMinDistance) !== p.historyMinDistance) {
    throw new AuthError("auth-password/bad-policy",
      "policy.historyMinDistance must be a non-negative integer");
  }
  if (p.complexity !== null && typeof p.complexity !== "object") {
    throw new AuthError("auth-password/bad-policy",
      "policy.complexity must be null or an object");
  }
  var complexity = p.complexity ? Object.assign({}, COMPLEXITY_DEFAULT, p.complexity) : null;
  if (complexity) {
    if (typeof complexity.minCategories !== "number" || complexity.minCategories < 0 ||
        complexity.minCategories > complexity.categories.length) {
      throw new AuthError("auth-password/bad-policy",
        "policy.complexity.minCategories must be in [0, " + complexity.categories.length + "]");
    }
    for (var ci = 0; ci < complexity.categories.length; ci++) {
      if (["lower", "upper", "digit", "special"].indexOf(complexity.categories[ci]) === -1) {
        throw new AuthError("auth-password/bad-policy",
          "policy.complexity.categories[" + ci + "] must be lower / upper / digit / special, got " +
          JSON.stringify(complexity.categories[ci]));
      }
    }
  }
  var forbidLower = (Array.isArray(p.forbidCommon) ? p.forbidCommon : [])
    .map(function (s) { return String(s).toLowerCase(); });
  var bundledSet = p.useBundledCommon === false ? null : _loadBundledCommon();
  var dictionaryLower = (Array.isArray(p.dictionary) ? p.dictionary : [])
    .filter(function (s) { return typeof s === "string" && s.length >= 3; })
    .map(function (s) { return s.toLowerCase(); });

  async function check(plaintext, context) {
    if (typeof plaintext !== "string") {
      return _fail("bad-input", "plaintext must be a string");
    }
    var byteLen = Buffer.byteLength(plaintext, "utf8");
    if (byteLen < p.minLength) {
      return _fail("too-short", "plaintext is shorter than " + p.minLength + " bytes");
    }
    if (byteLen > p.maxLength) {
      return _fail("too-long", "plaintext exceeds " + p.maxLength + " bytes");
    }
    var lower = plaintext.toLowerCase();
    if (bundledSet && bundledSet.has(lower)) {
      return _fail("forbidden-common", "plaintext matches a known breached / common password (bundled top-10000)");
    }
    for (var i = 0; i < forbidLower.length; i++) {
      if (lower === forbidLower[i]) {
        return _fail("forbidden-common", "plaintext matches a known weak / common password");
      }
    }
    for (var di2 = 0; di2 < dictionaryLower.length; di2++) {
      if (lower.indexOf(dictionaryLower[di2]) !== -1) {
        return _fail("forbidden-dictionary",
          "plaintext contains a forbidden dictionary term");
      }
    }
    if (p.denyContextSubstrings && context) {
      var deny = [];
      if (typeof context.email === "string" && context.email.length > 0) {
        deny.push(context.email.toLowerCase());
        var at = context.email.indexOf("@");
        if (at > 0) deny.push(context.email.slice(0, at).toLowerCase());
      }
      if (typeof context.username === "string" && context.username.length > 0) {
        deny.push(context.username.toLowerCase());
      }
      if (Array.isArray(context.deny)) {
        for (var di = 0; di < context.deny.length; di++) {
          if (typeof context.deny[di] === "string" && context.deny[di].length >= 3) {
            deny.push(context.deny[di].toLowerCase());
          }
        }
      }
      for (var dj = 0; dj < deny.length; dj++) {
        if (deny[dj].length >= 3 && lower.indexOf(deny[dj]) !== -1) {
          return _fail("contains-context",
            "plaintext contains a forbidden context substring (account identifier or operator-supplied deny string)");
        }
      }
    }
    if (complexity) {
      if (complexity.minCategories > 0) {
        var hits = 0;
        for (var cc = 0; cc < complexity.categories.length; cc++) {
          if (_hasCategory(plaintext, complexity.categories[cc])) hits++;
        }
        if (hits < complexity.minCategories) {
          return _fail("complexity-categories",
            "plaintext uses " + hits + " character categories; policy requires at least " +
            complexity.minCategories + " of [" + complexity.categories.join(", ") + "]");
        }
      }
      if (complexity.minRunRepeat >= 2 && _hasRunOfLength(plaintext, complexity.minRunRepeat)) {
        return _fail("complexity-run",
          "plaintext contains " + complexity.minRunRepeat + "+ identical consecutive characters");
      }
      if (complexity.minSequenceLength >= 3 && _hasSequenceOfLength(plaintext, complexity.minSequenceLength)) {
        return _fail("complexity-sequence",
          "plaintext contains a " + complexity.minSequenceLength + "+-char ascending or descending sequence");
      }
    }
    if (p.breachCheck === "haveibeenpwned") {
      var sha1Full = hibpSha1.sha1Hex(plaintext).toUpperCase();
      var prefix = sha1Full.slice(0, 5);
      var suffix = sha1Full.slice(5);
      var endEp = p.hibpEndpoint.length;
      while (endEp > 0 && p.hibpEndpoint.charCodeAt(endEp - 1) === 0x2f) { endEp -= 1; }
      var url = p.hibpEndpoint.slice(0, endEp) + "/range/" + prefix;
      var resp;
      try {
        resp = await httpClient.request({
          method:        "GET",
          url:           url,
          headers:       { "User-Agent": "blamejs-password-policy/1" },
          timeoutMs:     p.hibpTimeoutMs,
          idleTimeoutMs: p.hibpTimeoutMs,
          errorClass:    AuthError,
        });
      } catch (e) {
        if (p.failClosed) {
          return _fail("breach-check-failed",
            "HIBP lookup failed and policy is fail-closed: " + ((e && e.message) || String(e)));
        }
        return _ok({ breachCheckSkipped: true,
          breachCheckSkipReason: (e && e.message) || String(e) });
      }
      if (resp.statusCode !== C.HTTP.STATUS.OK || !resp.body) {
        if (p.failClosed) {
          return _fail("breach-check-failed",
            "HIBP returned status " + resp.statusCode + " with no body");
        }
        return _ok({ breachCheckSkipped: true,
          breachCheckSkipReason: "hibp-status-" + resp.statusCode });
      }
      var bodyText = Buffer.isBuffer(resp.body) ? resp.body.toString("utf8") : String(resp.body);
      var lines = bodyText.split(/\r?\n/);
      var goodLines = 0;
      var badLines = 0;
      var breachedCount = null;
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li].trim();
        if (line.length === 0) continue;
        var colon = line.indexOf(":");
        if (colon < 0) { badLines += 1; continue; }
        var hashSuffix = line.slice(0, colon).toUpperCase();
        var count = parseInt(line.slice(colon + 1), 10);
        if (!isFinite(count)) { badLines += 1; continue; }
        goodLines += 1;
        if (timingSafeEqual(Buffer.from(hashSuffix, "utf8"), Buffer.from(suffix, "utf8"))) {
          if (count >= p.breachThreshold && breachedCount === null) breachedCount = count;
        }
      }
      if (breachedCount !== null) {
        return _fail("breached",
          "plaintext appears in HaveIBeenPwned with count " + breachedCount +
          " (threshold " + p.breachThreshold + ")");
      }
      if (goodLines + badLines > 0 && badLines * 2 > goodLines) {
        if (p.failClosed) {
          return _fail("breach-check-failed",
            "HIBP response was mostly-unparseable (good=" + goodLines +
            ", bad=" + badLines + ") — possible poisoned mirror");
        }
        return _ok({ breachCheckSkipped: true,
          breachCheckSkipReason: "hibp-response-mostly-unparseable" });
      }
      return _ok({ breachCheckCount: 0 });
    }
    return _ok();
  }

  function shouldRotate(passwordSetAt, now) {
    if (p.mustRotateAfterMs === null) return false;
    if (typeof passwordSetAt !== "number" || !isFinite(passwordSetAt)) {
      throw new AuthError("auth-password/bad-input",
        "shouldRotate: passwordSetAt must be a numeric ms-epoch timestamp");
    }
    var nowMs = typeof now === "number" ? now : Date.now();
    return (nowMs - passwordSetAt) >= p.mustRotateAfterMs;
  }

  async function reuseProhibited(plaintext, history) {
    if (typeof plaintext !== "string" || plaintext.length === 0) return false;
    if (p.historyMinDistance <= 0) return false;
    if (!Array.isArray(history) || history.length === 0) return false;
    var checkCount = Math.min(history.length, p.historyMinDistance);
    for (var i = 0; i < checkCount; i++) {
      if (await _argon2Verify(history[i], plaintext)) return true;
    }
    return false;
  }

  return {
    check:            check,
    shouldRotate:     shouldRotate,
    reuseProhibited:  reuseProhibited,
    describe: function () {
      return {
        minLength:           p.minLength,
        maxLength:           p.maxLength,
        breachCheck:         p.breachCheck,
        mustRotateAfterMs:   p.mustRotateAfterMs,
        historyMinDistance:  p.historyMinDistance,
        complexity:          complexity ? Object.assign({}, complexity) : null,
        dictionaryCount:     dictionaryLower.length,
        forbidCommonCount:   forbidLower.length,
        bundledCommonCount:  bundledSet ? bundledSet.size : 0,
      };
    },
  };
}

function _validatePlain(plain) {
  if (typeof plain !== "string" || plain.length === 0) {
    throw new AuthError("auth-password/invalid-plain",
      "auth.password.hash requires a non-empty string");
  }
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) {
    throw new AuthError("auth-password/plain-too-large",
      "plaintext exceeds " + MAX_PLAINTEXT_BYTES + " bytes (UTF-8)");
  }
}

function _resolveParams(opts) {
  var p = Object.assign({}, DEFAULT_PARAMS, opts || {});
  if (typeof p.memoryCost !== "number" || p.memoryCost < C.BYTES.kib(1)) {
    throw new AuthError("auth-password/bad-params",
      "memoryCost must be >= 1024 KiB (1 MiB)");
  }
  if (typeof p.timeCost !== "number" || p.timeCost < 1) {
    throw new AuthError("auth-password/bad-params", "timeCost must be >= 1");
  }
  if (typeof p.parallelism !== "number" || p.parallelism < 1) {
    throw new AuthError("auth-password/bad-params", "parallelism must be >= 1");
  }
  return p;
}

var _concurrencyLimit = (function () { return 4 + 4; })();
var _activeCount = 0;
var _waiters = [];

function _acquire() {
  return new Promise(function (resolve) {
    if (_activeCount < _concurrencyLimit) {
      _activeCount += 1;
      resolve();
      return;
    }
    _waiters.push(resolve);
  });
}

function _release() {
  if (_waiters.length > 0) {
    var next = _waiters.shift();
    next();
    return;
  }
  _activeCount -= 1;
}

function gate(n) {
  if (typeof n !== "number" || !isFinite(n) || n < 1 || (n | 0) !== n) {
    throw new AuthError("auth-password/bad-gate",
      "auth.password.gate(n): n must be a positive integer");
  }
  _concurrencyLimit = n;
}

async function hash(plain, opts) {
  _validatePlain(plain);
  var p = _resolveParams(opts);
  await _acquire();
  try {
    return await argon2.hash(plain, {
      type:        argon2.argon2id,
      memoryCost:  p.memoryCost,
      timeCost:    p.timeCost,
      parallelism: p.parallelism,
    });
  } finally { _release(); }
}

async function verify(stored, plain) {
  if (typeof stored !== "string" || stored.length === 0) return false;
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (!stored.indexOf || stored.indexOf("$argon2id$") !== 0) return false;
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) return false;
  await _acquire();
  try {
    return await argon2.verify(stored, plain);
  } catch (_e) {
    return false;
  } finally { _release(); }
}

function needsRehash(stored, opts) {
  if (typeof stored !== "string" || stored.indexOf("$argon2id$") !== 0) {
    return true;
  }
  var p = _resolveParams(opts);
  try {
    return argon2.needsRehash(stored, {
      memoryCost:  p.memoryCost,
      timeCost:    p.timeCost,
      parallelism: p.parallelism,
    });
  } catch (_e) {
    return true;
  }
}

var OWASP_FLOOR_2026 = Object.freeze({
  memoryCostKib: C.BYTES.kib(19),
  timeCost:      2,
  parallelism:   1,
});

function params() {
  var active = {
    memoryCostKib: DEFAULT_PARAMS.memoryCost,
    timeCost:      DEFAULT_PARAMS.timeCost,
    parallelism:   DEFAULT_PARAMS.parallelism,
  };
  return {
    algorithm:     "argon2id",
    active:        active,
    owaspFloor:    OWASP_FLOOR_2026,
    meetsFloor:    active.memoryCostKib >= OWASP_FLOOR_2026.memoryCostKib &&
                   active.timeCost      >= OWASP_FLOOR_2026.timeCost &&
                   active.parallelism   >= OWASP_FLOOR_2026.parallelism,
  };
}

module.exports = {
  hash:             hash,
  verify:           verify,
  needsRehash:      needsRehash,
  policy:           policy,
  params:           params,
  gate:             gate,
  DEFAULT_PARAMS:   DEFAULT_PARAMS,
  DEFAULT_POLICY:   DEFAULT_POLICY,
  POLICY_PROFILES:  POLICY_PROFILES,
  OWASP_FLOOR_2026: OWASP_FLOOR_2026,
};
