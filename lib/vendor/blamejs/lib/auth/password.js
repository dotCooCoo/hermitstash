// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.auth.password
 * @nav        Identity
 * @title      Passwords
 * @order      110
 *
 * @intro
 *   Argon2id password hashing, verification and rehash detection, with a
 *   policy checker that screens a candidate password before it is hashed.
 *
 *   `hash` writes a PHC string carrying the algorithm, the Argon2 version and
 *   the cost parameters. `verify` reads those parameters back out of the
 *   stored string, so `costCeiling` bounds how much memory and time a stored
 *   hash may ask a login attempt to spend.
 *
 *   `gate` bounds how many Argon2id derivations run at once across every
 *   caller in the process. The three callers are this namespace, the
 *   passphrase wrapping in `b.vault` and the backup passphrase derivation in
 *   `b.backup`. A queued derivation can be bounded in depth and in waiting
 *   time, and `stats` reports both counts.
 *
 *   `policy` builds a checker from the operator's rules or from one of the
 *   `nist-aal2`, `pci-4.0` and `hipaa-aal2` profiles. It screens length, the
 *   bundled top-10000 breached list, an operator dictionary, account
 *   identifiers, character-class complexity, and HaveIBeenPwned through a
 *   k-anonymity range lookup.
 *
 * @card
 *   Argon2id hashing and verification with a ceiling on the cost a stored
 *   hash can ask a login attempt to spend, a process-wide concurrency gate,
 *   and a policy checker with NIST, PCI and HIPAA profiles.
 */
var argon2 = require("../argon2-builtin");
var validateOpts = require("../validate-opts");
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
  catch (e) {
    if (argon2.isGateRefusal(e)) throw e;
    return false;
  }
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

/**
 * @primitive  b.auth.password.policy
 * @signature  b.auth.password.policy(opts?)
 * @since      0.6.14
 * @status     stable
 * @compliance pci-dss, hipaa, soc2
 * @related    b.auth.password.hash, b.auth.password.params
 *
 * Build a checker that screens a candidate password before it is hashed.
 * Returns an object with four methods.
 *
 * `check(plaintext, context?)` resolves to `{ ok: true }` or to
 * `{ ok: false, code, message }`. The refusal codes are `policy/bad-input`,
 * `policy/too-short`, `policy/too-long`, `policy/forbidden-common`,
 * `policy/forbidden-dictionary`, `policy/contains-context`,
 * `policy/complexity-categories`, `policy/complexity-run`,
 * `policy/complexity-sequence`, `policy/breached` and
 * `policy/breach-check-failed`. The `context` argument screens the password
 * against the account's own identifiers: `email` (whole address and local
 * part), `username`, and a `deny` array of further strings. Terms shorter
 * than three characters are ignored.
 *
 * `shouldRotate(passwordSetAt, now?)` compares a ms-epoch timestamp against
 * `mustRotateAfterMs` and returns a boolean. It raises
 * `auth-password/bad-input` when `passwordSetAt` is not a finite number.
 *
 * `reuseProhibited(plaintext, history)` verifies the candidate against the
 * most recent `historyMinDistance` stored hashes and resolves to `true` when
 * one of them matches. It returns `false` when `historyMinDistance` is 0. Each
 * comparison waits on the Argon2id gate `b.auth.password.gate` holds, so it
 * raises `argon2/busy` or `argon2/queue-timeout` rather than reporting no
 * reuse, which would approve a password this check exists to refuse. For the
 * same reason it raises `auth-password/history-over-ceiling` for an entry
 * hashed above the current cost ceiling: `verify` answers `false` for such a
 * hash rather than spending the work the ceiling refuses, and on a login that
 * is a failed sign-in, but here it would read as no reuse and approve the old
 * password. Rehash that entry or raise the ceiling with
 * `b.auth.password.costCeiling`.
 *
 * `describe()` returns the resolved policy with the three list sizes rather
 * than the lists themselves, which makes it safe to log.
 *
 * A `breachCheck` of `haveibeenpwned` sends the first five hex characters of
 * the candidate's SHA-1 to `hibpEndpoint` and compares the remaining 35 in
 * constant time against the returned range. With `failClosed` false a lookup
 * that fails, times out, answers with a non-200 status, or returns a response
 * where more than a third of the lines do not parse resolves to
 * `{ ok: true, breachCheckSkipped: true, breachCheckSkipReason }`. With
 * `failClosed` true each of those four cases becomes
 * `policy/breach-check-failed`.
 *
 * The builder raises `auth-password/bad-policy` for an unknown `profile`, a
 * `minLength` outside [1, 4096], a `maxLength` outside [minLength, 4096], a
 * `breachCheck` other than null or `haveibeenpwned`, a non-positive
 * `mustRotateAfterMs`, a negative or fractional `historyMinDistance`, a
 * `complexity` that is neither null nor an object, a `minCategories` above
 * the number of categories, and a category name other than `lower`, `upper`,
 * `digit` or `special`. A `hibpEndpoint` that is not an https URL is refused by
 * the same error class with the URL parser's own code, so a cleartext mirror is
 * not accepted.
 *
 * @opts
 *   profile:               string,         // nist-aal2 | pci-4.0 | hipaa-aal2
 *   minLength:             number,         // bytes; default 8
 *   maxLength:             number,         // bytes; default 4096
 *   forbidCommon:          Array<string>,  // default: []
 *   useBundledCommon:      boolean,        // default: true (top-10000 list)
 *   denyContextSubstrings: boolean,        // default: true
 *   breachCheck:           string|null,    // default: null
 *   breachThreshold:       number,         // default: 1 sighting
 *   failClosed:            boolean,        // default: false
 *   hibpEndpoint:          string,         // default: the HIBP range API
 *   hibpTimeoutMs:         number,         // default: 1500
 *   mustRotateAfterMs:     number|null,    // default: null (no rotation)
 *   historyMinDistance:    number,         // default: 0 (no reuse check)
 *   complexity:            object|null,    // default: null
 *   dictionary:            Array<string>,  // default: []
 *
 * @example
 *   var pol = b.auth.password.policy({ minLength: 12, useBundledCommon: false });
 *
 *   await pol.check("tr0ub4dor-and-three-horses", {
 *     email:    "ada@example.com",
 *     username: "ada",
 *   });
 *   // → { ok: true }
 *
 *   (await pol.check("ada-rules-the-whole-world", { username: "ada" })).code;
 *   // → "policy/contains-context"
 *
 *   b.auth.password.policy({ profile: "pci-4.0" }).describe().minLength;
 *   // → 12
 */
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
      if (argon2.exceedsCostCeiling(history[i])) {
        throw new AuthError("auth-password/history-over-ceiling",
          "policy.reuseProhibited: history entry " + i + " was hashed above the " +
          "current cost ceiling, so it cannot be checked without spending the " +
          "work the ceiling refuses; rehash that entry or raise the ceiling");
      }
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

function _wholeCount(n, min) {
  return typeof n === "number" && isFinite(n) && Math.floor(n) === n && n >= min;
}

function _resolveParams(opts) {
  var p = Object.assign({}, DEFAULT_PARAMS, opts || {});
  if (!_wholeCount(p.memoryCost, C.BYTES.kib(1))) {
    throw new AuthError("auth-password/bad-params",
      "memoryCost must be a whole number of KiB >= 1024 (1 MiB); got " + p.memoryCost);
  }
  if (!_wholeCount(p.timeCost, 1)) {
    throw new AuthError("auth-password/bad-params",
      "timeCost must be a whole number >= 1; got " + p.timeCost);
  }
  if (!_wholeCount(p.parallelism, 1)) {
    throw new AuthError("auth-password/bad-params",
      "parallelism must be a whole number >= 1; got " + p.parallelism);
  }
  return p;
}

/**
 * @primitive  b.auth.password.gate
 * @signature  b.auth.password.gate(n?, opts?)
 * @since      0.8.41
 * @status     stable
 * @related    b.auth.password.stats, b.auth.password.verify
 *
 * Set how many Argon2id derivations may run at once in this process, and how
 * a derivation past that limit is queued. Returns the counts `stats` returns.
 * Calling it with no arguments reports the current state without changing it.
 *
 * The limit covers every Argon2id derivation in the process, not only the
 * ones this namespace starts: `hash`, `verify`, the reuse check a `policy`
 * runs over stored history, the passphrase wrapping in `b.vault` and the
 * backup passphrase derivation in `b.backup` all wait on it. Lowering `n`
 * below the number already running takes effect as those finish, and no
 * waiter starts while the running count is at or above the new limit.
 *
 * `maxQueued` bounds the waiter list. A derivation that arrives with the
 * queue full raises `argon2/busy` instead of waiting, which is what turns a
 * flood of login attempts into refusals rather than unbounded memory.
 * `waitTimeoutMs` bounds how long one waiter may sit in the queue before it
 * raises `argon2/queue-timeout`. Both default to no bound, so a queued
 * derivation waits for as long as it takes.
 *
 * `n` must be a positive integer or the call raises
 * `auth-password/bad-gate`. A `maxQueued` that is neither a non-negative
 * integer nor `Infinity`, and a `waitTimeoutMs` that is neither 0 nor a
 * positive integer, each raise `argon2/bad-gate`. A call that raises changes
 * none of the three, so a caller that catches the error is still running under
 * the limits it had.
 *
 * @opts
 *   maxQueued:     number,   // default: Infinity (unbounded queue)
 *   waitTimeoutMs: number,   // default: 0 (no timeout)
 *
 * @example
 *   b.auth.password.gate(4, { maxQueued: 64, waitTimeoutMs: 2000 });
 *   // → { running: 0, waiting: 0, limit: 4, maxQueued: 64, waitTimeoutMs: 2000 }
 */
function gate(n, opts) {
  if (n !== undefined && n !== null &&
      (typeof n !== "number" || !isFinite(n) || n < 1 || (n | 0) !== n)) {
    throw new AuthError("auth-password/bad-gate",
      "auth.password.gate(n): n must be a positive integer");
  }
  if (opts !== undefined && opts !== null) {
    validateOpts.checkOrThrow(opts, ["maxQueued", "waitTimeoutMs"],
      "auth.password.gate", AuthError, "auth-password/bad-gate");
  }
  return argon2.gate(n, opts);
}

/**
 * @primitive  b.auth.password.stats
 * @signature  b.auth.password.stats()
 * @since      0.20.38
 * @status     stable
 * @related    b.auth.password.gate
 *
 * Report the Argon2id concurrency gate's current counts. `running` is the
 * number of derivations in flight, `waiting` the length of the queue behind
 * them, and the other three fields are the limits `gate` holds.
 *
 * The counts cover the whole process, so a `waiting` that stays near
 * `maxQueued` under load is the signal to raise `n`, add capacity, or shed
 * login attempts earlier in the request lifecycle.
 *
 * @example
 *   b.auth.password.gate(2, { maxQueued: 64, waitTimeoutMs: 2000 });
 *   b.auth.password.stats();
 *   // → { running: 0, waiting: 0, limit: 2, maxQueued: 64, waitTimeoutMs: 2000 }
 */
function stats() {
  return argon2.stats();
}

/**
 * @primitive  b.auth.password.hash
 * @signature  b.auth.password.hash(plain, opts?)
 * @since      0.1.53
 * @status     stable
 * @related    b.auth.password.verify, b.auth.password.needsRehash
 *
 * Derive an Argon2id hash of `plain` and return it as a PHC string, which
 * carries the algorithm, the Argon2 version, the three cost parameters, the
 * random 16-byte salt and the 32-byte tag. Store the whole string; `verify`
 * reads everything it needs back out of it.
 *
 * The derivation waits on the concurrency gate `gate` holds, so it can raise
 * `argon2/busy` when the queue is full and `argon2/queue-timeout` when a
 * waiter exceeds `waitTimeoutMs`.
 *
 * A `plain` that is not a non-empty string raises
 * `auth-password/invalid-plain`, and one longer than 4096 UTF-8 bytes raises
 * `auth-password/plain-too-large`. A `memoryCost` under 1024 KiB, a
 * `timeCost` under 1 and a `parallelism` under 1 each raise
 * `auth-password/bad-params`. Parameters above the ceiling `costCeiling`
 * holds raise `argon2/cost-over-ceiling`.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 65536 (64 MiB)
 *   timeCost:    number,   // default: 3 passes
 *   parallelism: number,   // default: 4 lanes
 *
 * @example
 *   var stored = await b.auth.password.hash("correct horse battery staple");
 *   // → "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<tag>"
 */
async function hash(plain, opts) {
  _validatePlain(plain);
  var p = _resolveParams(opts);
  return await argon2.hash(plain, {
    type:        argon2.argon2id,
    memoryCost:  p.memoryCost,
    timeCost:    p.timeCost,
    parallelism: p.parallelism,
  });
}

/**
 * @primitive  b.auth.password.verify
 * @signature  b.auth.password.verify(stored, plain)
 * @since      0.1.53
 * @status     stable
 * @related    b.auth.password.hash, b.auth.password.costCeiling
 *
 * Compare `plain` against a PHC string written by `hash` and resolve to a
 * boolean. The tag comparison is constant-time.
 *
 * Everything that is not a match answers `false` rather than raising: a
 * `stored` that is not a string or does not start with `$argon2id$`, an empty
 * or over-length `plain`, a PHC string this module cannot decode, a hash
 * whose cost parameters exceed the ceiling `costCeiling` holds, and a failed
 * derivation. The two exceptions are the concurrency gate's own refusals,
 * `argon2/busy` and `argon2/queue-timeout`, which are rethrown so a loaded
 * process can answer 503 instead of reporting the password wrong.
 *
 * @example
 *   var ok = await b.auth.password.verify(row.passwordHash, submitted);
 *   if (!ok) {
 *     res.statusCode = 401;
 *     return res.end();
 *   }
 *   if (b.auth.password.needsRehash(row.passwordHash)) {
 *     var fresh = await b.auth.password.hash(submitted);
 *     db.from("users").where({ _id: row._id }).update({ passwordHash: fresh });
 *   }
 */
async function verify(stored, plain) {
  if (typeof stored !== "string" || stored.length === 0) return false;
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (!stored.indexOf || stored.indexOf("$argon2id$") !== 0) return false;
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) return false;
  try {
    return await argon2.verify(stored, plain);
  } catch (e) {
    if (argon2.isGateRefusal(e)) throw e;
    return false;
  }
}

/**
 * @primitive b.auth.password.costCeiling
 * @signature b.auth.password.costCeiling(opts?)
 * @since     0.20.38
 * @status    stable
 * @related   b.auth.password.verify, b.auth.password.needsRehash
 *
 * Read or set the ceiling on the Argon2id cost a stored hash may ask `verify`
 * to spend. Returns the ceiling in force. Passing `null` restores the default,
 * which is eight times the hash defaults for memory and time and a parallelism
 * of 16.
 *
 * `verify` reads `m`, `t` and `p` out of the stored string, so a row that did
 * not come from this module's own `hash` decides how much memory and time a
 * login attempt costs. A stored `m=4194304` asked for 4 GiB and took about
 * three seconds.
 *
 * Three primitives read the ceiling. `verify` answers `false` for a hash above
 * it and reports `auth.password.cost_over_ceiling` through observability with
 * the three parameters, rather than raising, because `verify` must stay safe to
 * call without a `try`. `needsRehash` reports such a hash as needing
 * re-derivation. `hash` refuses parameters above it with
 * `argon2/cost-over-ceiling` rather than writing a credential this process
 * would then refuse to verify.
 *
 * Raise it when the deployment deliberately runs more expensive parameters than
 * the default allows. Lowering it below rows that are already stored makes
 * those rows unverifiable, and re-deriving one needs a successful `verify`
 * first, so the remedy for a row above the new ceiling is to raise the ceiling
 * again or to require a password reset.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 524288 (8x the 64 MiB hash default)
 *   timeCost:    number,   // default 24
 *   parallelism: number,   // default 16
 *
 * A value below what `hash` writes by default raises
 * `auth-password/bad-ceiling`, since it would leave this module refusing every
 * credential it produces. So does an unknown key, an array, and a value that is
 * not a whole number of KiB, passes or lanes.
 *
 * @example
 *   // memoryCost is a KiB count, so this is a 1 GiB bound, not 1 MiB.
 *   b.auth.password.costCeiling({ memoryCost: 1048576 });
 *   // → { memoryCost: 1048576, timeCost: 24, parallelism: 16 }
 */
function costCeiling(opts) {
  if (opts !== undefined && opts !== null) {
    if (typeof opts !== "object" || Array.isArray(opts)) {
      throw new AuthError("auth-password/bad-ceiling",
        "auth.password.costCeiling: opts must be an object of memoryCost / " +
        "timeCost / parallelism, or null to restore the default");
    }
    validateOpts.checkOrThrow(opts, ["memoryCost", "timeCost", "parallelism"],
      "auth.password.costCeiling", AuthError, "auth-password/bad-ceiling");
    ["memoryCost", "timeCost", "parallelism"].forEach(function (k) {
      if (opts[k] === undefined) return;
      if (!_wholeCount(opts[k], 1)) {
        throw new AuthError("auth-password/bad-ceiling",
          "auth.password.costCeiling: " + k +
          " must be a whole number >= 1; got " + opts[k]);
      }
      if (opts[k] < DEFAULT_PARAMS[k]) {
        throw new AuthError("auth-password/bad-ceiling",
          "auth.password.costCeiling: " + k + " of " + opts[k] +
          " is below the " + k + " hash() uses by default (" + DEFAULT_PARAMS[k] +
          "), which would refuse every hash this module writes");
      }
    });
  }
  return argon2.costCeiling(opts);
}

/**
 * @primitive  b.auth.password.needsRehash
 * @signature  b.auth.password.needsRehash(stored, opts?)
 * @since      0.1.53
 * @status     stable
 * @related    b.auth.password.hash, b.auth.password.verify
 *
 * Report whether a stored hash should be re-derived at the next successful
 * login. Returns `true` for a string that is not an Argon2id PHC string, one
 * this module cannot decode, one written under a different Argon2 version,
 * one whose cost parameters exceed the ceiling `costCeiling` holds, and one
 * cheaper in memory, time or lanes than the parameters asked for here.
 *
 * Call it after `verify` answers true, while the plaintext is still in hand.
 *
 * A `memoryCost` under 1024 KiB, a `timeCost` under 1 and a `parallelism`
 * under 1 each raise `auth-password/bad-params`.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 65536 (64 MiB)
 *   timeCost:    number,   // default: 3 passes
 *   parallelism: number,   // default: 4 lanes
 *
 * @example
 *   b.auth.password.needsRehash("$argon2id$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$dGFn");
 *   // → true (cheaper than the current defaults)
 */
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

/**
 * @primitive  b.auth.password.params
 * @signature  b.auth.password.params()
 * @since      0.7.19
 * @status     stable
 * @related    b.auth.password.hash, b.auth.password.costCeiling
 *
 * Report the Argon2id parameters `hash` uses when the caller passes none,
 * alongside the OWASP minimum for Argon2id and whether the active parameters
 * meet it. `active.memoryCostKib` is counted in KiB, matching the `m` field
 * of the PHC strings `hash` writes.
 *
 * The comparison is an inequality on all three parameters at once, so
 * `meetsFloor` is false as soon as any one of them drops below the floor.
 *
 * @example
 *   b.auth.password.params();
 *   // → { algorithm: "argon2id",
 *   //     active:     { memoryCostKib: 65536, timeCost: 3, parallelism: 4 },
 *   //     owaspFloor: { memoryCostKib: 19456, timeCost: 2, parallelism: 1 },
 *   //     meetsFloor: true }
 */
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
  costCeiling:      costCeiling,
  policy:           policy,
  params:           params,
  gate:             gate,
  stats:            stats,
  DEFAULT_PARAMS:   DEFAULT_PARAMS,
  DEFAULT_POLICY:   DEFAULT_POLICY,
  POLICY_PROFILES:  POLICY_PROFILES,
  OWASP_FLOOR_2026: OWASP_FLOOR_2026,
};
