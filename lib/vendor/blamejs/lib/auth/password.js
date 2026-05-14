"use strict";
/**
 * Argon2id password hashing — public framework primitive.
 *
 * Different concern from lib/vault-wrap.js, which also uses Argon2id but
 * for KEK derivation (the output is a KEY used to AEAD-wrap the vault
 * file). This module is for application-layer password storage: the
 * output is a verifiable digest in PHC format, never decrypted, used
 * for "is this the password the user originally set?".
 *
 * Public API:
 *
 *   await auth.password.hash(plain, opts?)        → string (PHC format)
 *   await auth.password.verify(hash, plain)       → boolean
 *   auth.password.needsRehash(hash, opts?)        → boolean
 *
 * The PHC string captures the algorithm + parameters + salt + digest:
 *
 *   $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
 *
 * That string is what callers store in the database. verify() parses
 * it to recover the parameters, recomputes the digest with the
 * supplied plaintext, and timing-safe compares.
 *
 * Defaults (memoryCost=64 MiB, timeCost=3, parallelism=4) target
 * ~250–500ms on commodity 2026 hardware — painful for offline brute
 * force, tolerable inside a login latency budget. Operators with
 * tighter budgets (or beefier hardware) tune via opts; needsRehash
 * surfaces when stored hashes lag behind the current defaults so the
 * caller can transparently rehash on next successful login.
 *
 * Validation posture:
 *   - plain must be a non-empty string. Empty/whitespace passwords
 *     are operator bugs (UI should reject) — failing here surfaces
 *     them before they hit the DB.
 *   - plain length is capped at 4096 bytes (UTF-8). Same cap as the
 *     vault-wrap passphrase. A 5 GiB string fed to Argon2 would peg
 *     the box for minutes; the cap is sanity, not security.
 *   - hash must be a non-empty string starting with `$argon2id$`.
 *     Other Argon2 variants (`$argon2i$` / `$argon2d$`) are out of
 *     spec for this framework — verify() returns false rather than
 *     attempting to validate them. Callers using needsRehash on a
 *     non-id hash get true (forces rehash on next login).
 *
 * Errors are AuthError(code, message) with permanent=true. A failed
 * verify is NOT an error — it returns false. Errors are reserved for
 * "the call shape was wrong" (empty plain, oversize plain).
 */
var argon2 = require("../argon2-builtin");
var C = require("../constants");
var httpClient = require("../http-client");
var hibpSha1 = require("../framework-sha1-hibp");
var safeUrl = require("../safe-url");
var timingSafeEqual = require("../crypto").timingSafeEqual;
var { AuthError } = require("../framework-error");

// Tuning targets ~250–500ms on commodity 2026 hardware. memoryCost
// is in KiB per Argon2's parameter convention. 64 MiB expressed as
// KiB through C.BYTES.kib so the framework's byte math has a single
// source of truth.
var DEFAULT_PARAMS = Object.freeze({
  memoryCost:  C.BYTES.kib(64),    // 64 MiB
  timeCost:    3,
  parallelism: 4,
});

// Plaintext upper bound. NIST 800-63B requires >= 64 chars; 4 KiB is
// the framework's defense against amplification attacks (a hostile
// caller submitting a multi-megabyte "password" would otherwise burn
// Argon2 cycles for no security gain).
var MAX_PLAINTEXT_BYTES = C.BYTES.kib(4);

// ---- Policy primitive ----------------------------------------------
//
// Argon2id covers the OFFLINE attack model: even with the DB stolen,
// each guess costs ~250ms of CPU + 64 MiB of RAM. It does NOT cover:
//   - Online weak-credential attacks (operator phishes / reuses)
//   - Periodic rotation requirements (PCI 8.3, NYDFS, some HIPAA)
//   - History reuse (PCI 8.3 last-4 floor)
//   - Operator-tunable composition rules (HIPAA / industry-specific
//     where AAL2-equivalent posture is mandated)
//
// b.auth.password.policy(opts) returns:
//   - check(plaintext, context?)         → presentation-time gate
//   - shouldRotate(passwordSetAt)        → per-account rotation check
//   - reuseProhibited(plaintext, history)→ history-reuse check
//
// Standards mapped:
//   - NIST 800-63B §5.1.1.2: 8-char min floor, 64-char min max,
//     breach check, NO MANDATORY composition. (Default posture.)
//   - PCI-DSS 8.3.6 / 8.3.7: 12-char min, 90-day rotation, history
//     of 4. (Operator opts in via { profile: "pci-8.3" }.)
//   - HIPAA 164.308(a)(5)(ii)(D): "procedures for creating, changing,
//     and safeguarding passwords" — addressed via composition opts.
//   - GDPR Art. 32: storage shape (sealed via Argon2id); no
//     additional policy requirement here.
//   - NYDFS 23 NYCRR 500.12 / NIST AAL2: rotation + breach + length.
//
// The defaults follow NIST 800-63B (no mandatory composition,
// length-and-breach over rules). Every other regime layers on
// opt-in opts; the framework refuses to surprise an operator who
// followed the defaults.
//
//   var policy = b.auth.password.policy({
//     minLength:        12,
//     breachCheck:      "haveibeenpwned",
//     mustRotateAfterMs:    C.TIME.days(90),     // PCI 8.3.9
//     historyMinDistance:   4,                    // PCI 8.3.7
//     complexity: {
//       minCategories:      0,                    // NIST: don't enforce. opt in for HIPAA-flavoured.
//       categories:         ["lower", "upper", "digit", "special"],
//       minRunRepeat:       3,                    // reject "aaaa…"
//       minSequenceLength:  3,                    // reject "abcd"/"1234"
//     },
//     dictionary: ["companyName", "productName"],
//   });
//
//   await policy.check(plain, { email, username, deny: [...], passwordSetAt });
//   policy.shouldRotate(passwordSetAt);
//   await policy.reuseProhibited(plain, [oldHash1, oldHash2, oldHash3]);
//
// breachCheck:"haveibeenpwned" uses the HIBP k-anonymity API; the
// SHA-1 hash is computed in-process via lib/framework-sha1-hibp.js
// (NOT exported on b.crypto — see comment in lib/crypto.js). Only
// the first 5 hex chars cross the wire. Rate-limit and failure-mode
// are operator's call: an HIBP outage returns
// { ok: true, breachCheckSkipped: true } by default; failClosed:true
// rejects.
var DEFAULT_POLICY = Object.freeze({
  minLength:              0x08,               // NIST floor — hex literal form
  maxLength:              MAX_PLAINTEXT_BYTES,
  forbidCommon:           [],
  // The bundled top-10000 list ships in lib/vendor/common-passwords-top-10000.txt
  // (SecLists, CC-BY-3.0). Set false to skip — operators with a richer
  // breach-list (HIBP downloads, NCSC 100k) layered via forbidCommon
  // typically leave this on; it's additive.
  useBundledCommon:       true,
  denyContextSubstrings:  true,
  breachCheck:            null,               // null | "haveibeenpwned"
  breachThreshold:        1,
  failClosed:             false,
  hibpEndpoint:           "https://api.pwnedpasswords.com",
  hibpTimeoutMs:          C.TIME.seconds(1.5),
  // Rotation policy (PCI 8.3.9 / NYDFS / industry-specific). null = no rotation.
  mustRotateAfterMs:      null,
  // History reuse (PCI 8.3.7 floor: last-4). 0 = disabled.
  // Operator passes the actual stored hash list to reuseProhibited().
  historyMinDistance:     0,
  // Composition rules (NIST 800-63B explicitly says NOT to enforce
  // these; HIPAA / older standards still ask for them. Default is OFF
  // so the NIST-aligned posture is the default; operators opt in.)
  complexity:             null,
  // Dictionary terms forbidden as substrings (operator brand names,
  // product names, etc.). Substring match, case-insensitive. Empty
  // by default.
  dictionary:             [],
});

var COMPLEXITY_DEFAULT = Object.freeze({
  minCategories:     0,        // NIST default off; HIPAA-flavoured ops set 3 or 4
  categories:        ["lower", "upper", "digit", "special"],
  minRunRepeat:      0,        // reject N+ identical chars in a row; 0 = off
  minSequenceLength: 0,        // reject N+ ascending or descending chars; 0 = off
});

// Predefined profiles operators can opt into. Each spreads onto the
// policy opts so the operator can still override individual fields.
var POLICY_PROFILES = Object.freeze({
  // NIST 800-63B AAL2 baseline — length + breach, no composition.
  // §5.1.1.2 mandates an 8-character floor; routed through C.BYTES.bytes
  // so every length-shaped integer in the framework reads through the
  // same single source of truth.
  "nist-aal2": Object.freeze({
    minLength:    C.BYTES.bytes(8),
    breachCheck:  "haveibeenpwned",
  }),
  // PCI-DSS 4.0 §8.3 — 12-char min, 90-day rotation, history of 4.
  // Composition is NOT required by PCI 4.0 (it dropped the older
  // version's composition rule); breach check + length covers it.
  "pci-4.0": Object.freeze({
    minLength:           12,
    breachCheck:         "haveibeenpwned",
    mustRotateAfterMs:   C.TIME.days(90),
    historyMinDistance:  4,
  }),
  // HIPAA 164.308 — "procedures for creating, changing, and
  // safeguarding". The standard is intentionally vague; the
  // commonly-implemented profile pairs length + composition +
  // rotation + lockout (lockout is b.auth.lockout, separate
  // primitive).
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

// Top-10000 common-password set vendored from SecLists
// (CC-BY-3.0 by Daniel Miessler). Loaded lazily on first policy.check
// call — keeps boot fast for apps that never invoke the dictionary.
// Operators wanting deeper enforcement supply opts.forbidCommon (set
// of additional plaintexts) and/or opts.forbidCommonExtra (operator's
// own breach list); both layer additively on top of the bundled set.
var vendorData = require("../vendor-data");
var _bundledCommonPasswords = null;
function _loadBundledCommon() {
  if (_bundledCommonPasswords) return _bundledCommonPasswords;
  // b.vendorData verifies the dual-hash + SLH-DSA signature + in-payload
  // canary before returning the bytes. Packaging-mode-invariant — no
  // __dirname-relative file lookup that breaks under SEA / pkg / bundler.
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
function _commonPasswordsSize() {
  return _loadBundledCommon().size;
}

function _ok(extra) { return Object.assign({ ok: true }, extra || {}); }
function _fail(code, message) {
  return { ok: false, code: "policy/" + code, message: message };
}

// Argon2id verify with a known stored hash — used by reuseProhibited
// to compare a candidate plaintext against history entries without
// the operator having to wire verify() per row.
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
  // Apply named profile FIRST, then operator opts on top so the
  // operator can override profile defaults per-field.
  if (typeof opts.profile === "string" && opts.profile.length > 0) {
    if (!POLICY_PROFILES[opts.profile]) {
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
      // HIBP k-anonymity: send the first 5 hex chars of the SHA-1
      // hash, scan the returned suffix list. The framework's only
      // SHA-1 usage; HIBP requires it. (See lib/framework-sha1-hibp.js
      // for the restriction rationale.)
      var sha1Full = hibpSha1.sha1Hex(plaintext).toUpperCase();
      var prefix = sha1Full.slice(0, 5);
      var suffix = sha1Full.slice(5);
      var url = p.hibpEndpoint.replace(/\/+$/, "") + "/range/" + prefix;
      var resp;
      try {
        resp = await httpClient.request({
          method:        "GET",
          url:           url,
          headers:       { "User-Agent": "blamejs-password-policy/1" },
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
      if (resp.statusCode !== 200 || !resp.body) {
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
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li].trim();
        if (line.length === 0) continue;
        var colon = line.indexOf(":");
        if (colon < 0) { badLines += 1; continue; }
        var hashSuffix = line.slice(0, colon).toUpperCase();
        var count = parseInt(line.slice(colon + 1), 10);
        if (!isFinite(count)) { badLines += 1; continue; }
        goodLines += 1;
        if (timingSafeEqual(Buffer.from(hashSuffix, "utf8"), Buffer.from(suffix, "utf8")) &&
            count >= p.breachThreshold) {
          return _fail("breached",
            "plaintext appears in HaveIBeenPwned with count " + count +
            " (threshold " + p.breachThreshold + ")");
        }
      }
      // If a hostile / poisoned mirror returned a response shaped like
      // HIBP but with mostly-unparseable counts, the original loop
      // skipped them silently and reported breachCheckCount=0 — i.e.
      // the operator saw "looks fine" against a body that was never
      // actually verifiable. When more than half the lines fail to
      // parse, treat the response as unverifiable and apply the
      // operator's fail-closed posture.
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
    // Check the most-recent N entries (history-min-distance bound).
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
    // Operator introspection — handy when an admin tool wants to
    // surface "your policy requires X" to end users.
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

// Process-global concurrency gate. Argon2id at default params holds
// ~64 MiB peak per concurrent hash; 100 simultaneous logins would
// peg ~6.4 GiB and OOM the process. The gate caps concurrent hash +
// verify calls at `_concurrencyLimit` and queues the rest. Operators
// can override via b.auth.password.gate(n) at boot — typical sizing
// is `Math.floor(availableHeapBytes / memoryCost) - 2`. Default 8 is
// safe on a 1 GiB heap with 64 MiB memoryCost.
var _concurrencyLimit = (function () { return 4 + 4; })();   // semaphore size — concurrent Argon2id slots
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
  // verify intentionally tolerates malformed input by returning false
  // rather than throwing — login flows already treat false as "credentials
  // didn't match" and shouldn't have to wrap each call in try/catch.
  if (typeof stored !== "string" || stored.length === 0) return false;
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (!stored.indexOf || stored.indexOf("$argon2id$") !== 0) return false;
  if (Buffer.byteLength(plain, "utf8") > MAX_PLAINTEXT_BYTES) return false;
  await _acquire();
  try {
    return await argon2.verify(stored, plain);
  } catch (_e) {
    // PHC-string parse failures from the vendor surface as throws —
    // treat as "doesn't match" so a corrupted DB column can't break
    // login flows with an unexpected exception type.
    return false;
  } finally { _release(); }
}

function needsRehash(stored, opts) {
  if (typeof stored !== "string" || stored.indexOf("$argon2id$") !== 0) {
    // Non-id variant or malformed — force rehash on next successful login
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
    return true;     // unparseable → rehash
  }
}

// OWASP 2026 Argon2id minimum floor — operator audit visibility.
// Any deploy MUST satisfy m >= 19 MiB, t >= 2, p >= 1. params() exposes
// the active defaults so an operator audit (or compliance scan) can
// verify the floor without parsing PHC strings out of the database.
//
// Argon2 expresses memoryCost in KiB. C.BYTES.kib(19) returns 19456,
// which argon2 reads as 19456 KiB = 19 MiB — the same shape as the
// active DEFAULT_PARAMS.memoryCost (C.BYTES.kib(64) = 65536 KiB = 64
// MiB). timeCost + parallelism are unitless argon2 parameters.
var OWASP_FLOOR_2026 = Object.freeze({
  memoryCostKib: C.BYTES.kib(19),
  timeCost:      2,
  parallelism:   1,
});

function params() {
  // Active framework defaults plus the OWASP 2026 floor for comparison.
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
