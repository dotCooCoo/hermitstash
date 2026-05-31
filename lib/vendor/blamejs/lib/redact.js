"use strict";
/**
 * @module b.redact
 * @nav    Observability
 * @title  Redact
 *
 * @intro
 *   Operational-log redaction — regex-shape and field-name rules that
 *   strip PII / secrets out of every log payload before it reaches a
 *   file, debug sink, or external SIEM.
 *
 *   Two complementary signals run on every walk: a sensitive-field
 *   name set (case-insensitive substring match against keys like
 *   `password`, `api_key`, `authorization`, `dpop`, `client_secret`,
 *   `refresh_token`) and a value-shape detector chain (Luhn-validated
 *   credit-card numbers, JWS triplets, PEM / OpenSSH private-key
 *   blocks, AWS access-key prefixes, vault-sealed ciphertexts,
 *   connection-string credential leaks). Field-name hits replace the
 *   whole value with the configured marker; value-shape hits replace
 *   with a per-detector marker (`[REDACTED-CC]`, `[REDACTED-JWT]`).
 *
 *   The redactor never mutates the input — every call returns a fresh
 *   object. The same payload commonly lands in two paths simultaneously
 *   (audit-log seals via vault; operational log redacts here) so
 *   in-place mutation would corrupt the sealed-then-archived copy.
 *
 *   `classifyDefaults` and `installOutboundDlp` extend the same primitive
 *   set into outbound-DLP duty: the classifier produces a verdict
 *   ("clean" / "redact" / "refuse") for a request body + headers, and
 *   the installer wraps `httpClient` / `mail` / `webhook` instances so
 *   refused requests fail with `DlpError` and redacted ones proceed
 *   with sanitized payloads. Posture presets (`pci-dss` / `hipaa` /
 *   `fapi2` / `soc2` / `gdpr`) pick a sensible default classifier.
 *
 * @card
 *   Operational-log redaction — regex-shape and field-name rules that strip PII / secrets out of every log payload before it reaches a file, debug sink, or external SIEM.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { DlpError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var DEFAULT_MARKER = "[REDACTED]";

// Field names that are always redacted, regardless of value contents.
// Match is case-insensitive and includes substring (so 'userPassword' matches).
var SENSITIVE_FIELDS = [
  "password", "passwd", "secret", "token", "apikey", "api_key",
  "authorization", "auth", "ssn", "creditcard", "credit_card",
  "card_number", "cardnumber", "cvc", "cvv", "pin",
  "privatekey", "private_key", "passphrase", "session", "sid",
  "_authtoken", "auth_token", "bearer", "cookie",
  // Header-shaped variants of api-key — substring matching against a
  // lowercased field name treats hyphen + underscore + dot as
  // literal, so each header form needs its own entry.
  "x-api-key", "x_api_key", "x-apikey", "api-key",
  // DPoP / OAuth 2.1 / OIDC proof-of-possession + selective-disclosure
  // fields — operator-error metadata logging often carries these.
  "jwk", "dpop", "proof", "assertion", "client_assertion", "id_token_hint",
  "code_verifier", "client_secret", "refresh_token", "access_token",
  // Vault-sealed values (don't log even though they're encrypted —
  // operational logs aren't a place to leak ciphertext shape either)
  // matched separately by value detector below
];

// Value-shape detectors. Each takes a string, returns true if the value
// matches the pattern. Used as a fallback when field-name redaction misses.
function _luhnCheck(num) {
  var digits = num.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  var sum = 0;
  var alt = false;
  for (var i = digits.length - 1; i >= 0; i--) {
    var d = parseInt(digits.charAt(i), 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

var VALUE_DETECTORS = [
  {
    name:        "credit-card",
    test:        function (v) {
      if (typeof v !== "string") return false;
      var digits = v.replace(/\s|-/g, "");
      if (!/^\d{13,19}$/.test(digits)) return false;
      return _luhnCheck(digits);
    },
    replacement: "[REDACTED-CC]",
  },
  {
    name:        "jwt",
    test:        function (v) {
      return typeof v === "string" && /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
    },
    replacement: "[REDACTED-JWT]",
  },
  {
    // URL with bearer-shaped query parameter — the parent field is
    // typically `url` or `referer`, neither of which the field-name
    // pass redacts. Replace the whole querystring after the marker
    // so the path stays useful for log triage.
    name:        "url-bearer-query",
    test:        function (v) {
      return typeof v === "string" &&
        /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s]*[?&#](?:access_token|id_token|token|api_key|apikey)=/.test(v);
    },
    replacement: function (v) {
      return String(v).replace(/(access_token|id_token|token|api_key|apikey)=[^&#]*/g, "$1=[REDACTED]");
    },
  },
  {
    name:        "pem",
    test:        function (v) { return typeof v === "string" && /-----BEGIN [A-Z ]+-----/.test(v); },
    replacement: "[REDACTED-PEM]",
  },
  {
    name:        "ssh-private",
    test:        function (v) { return typeof v === "string" && /-----BEGIN OPENSSH PRIVATE KEY-----/.test(v); },
    replacement: "[REDACTED-SSH-KEY]",
  },
  {
    name:        "aws-access-key",
    test:        function (v) { return typeof v === "string" && /^(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}$/.test(v); },
    replacement: "[REDACTED-AWS-KEY]",
  },
  {
    name:        "vault-sealed",
    test:        function (v) { return typeof v === "string" && v.startsWith("vault:"); },
    replacement: "[REDACTED-SEALED]",
  },
  {
    name:        "ssn",
    test:        function (v) { return typeof v === "string" && /^\d{3}-?\d{2}-?\d{4}$/.test(v); },
    replacement: "[REDACTED-SSN]",
  },
  {
    // Connection-string credential leak — matches `protocol://user:pass@host`
    // shapes that surface in error messages / metadata.reason fields when
    // an external-DB driver drops its connect URL into an Error.message.
    // Replacement preserves the host part for operator triage but redacts
    // the credentials.
    name:        "connection-string",
    test:        function (v) {
      if (typeof v !== "string" || v.length < C.BYTES.bytes(8)) return false; // bound BEFORE regex test
      if (v.length > C.BYTES.kib(8)) return false;
      // user may be empty (e.g. redis://:password@host); password
      // segment is required to flag this as a credentialed URI.
      return /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/?#]*:[^\s@/?#]+@/.test(v);
    },
    replacement: "[REDACTED-CONN-STRING]",
  },
];

var sensitiveFieldsSet = new Set(SENSITIVE_FIELDS);
var customDetectors = [];

/**
 * @primitive b.redact.registerFieldRule
 * @signature b.redact.registerFieldRule(name, replacement?)
 * @since     0.1.0
 * @related   b.redact.redact, b.redact.registerValueDetector
 *
 * Add a field name to the always-redact set. Match is
 * case-insensitive substring, so registering `secret` also redacts
 * `appSecret` / `customer_secret`. The `replacement` argument is
 * accepted for symmetry with `registerValueDetector` but ignored —
 * field-name hits always use the redactor's configured marker.
 *
 * @example
 *   b.redact.registerFieldRule("internal_token");
 *   var out = b.redact.redact({ internal_token: "abc-123" });
 *   // → { internal_token: "[REDACTED]" }
 */
function registerFieldRule(name, replacement) {
  void replacement; // marker not used here; redact replaces with marker
  if (typeof name === "string") {
    sensitiveFieldsSet.add(name.toLowerCase());
    return;
  }
  throw new Error("registerFieldRule expects a string field name");
}

/**
 * @primitive b.redact.registerValueDetector
 * @signature b.redact.registerValueDetector(name, testFn, replacement)
 * @since     0.1.0
 * @related   b.redact.redact, b.redact.registerFieldRule
 *
 * Register a custom value-shape detector. `testFn(value)` runs against
 * every string value the redactor walks; truthy result substitutes the
 * `replacement` (string or function — function receives the matched
 * value and returns the substitution). Custom detectors run AFTER the
 * built-in chain.
 *
 * @example
 *   // Redact internal employee IDs (shape: EMP-NNNNNN).
 *   b.redact.registerValueDetector("employee-id",
 *     function (v) { return /^EMP-\d{6}$/.test(v); },
 *     "[REDACTED-EMPID]");
 *   var out = b.redact.redact({ note: "owner EMP-123456" });
 *   // → { note: "owner EMP-123456" } — value-shape detectors only fire
 *   //   on full-string match; in-string matches need a custom regex
 *   //   replacement function.
 */
function registerValueDetector(name, testFn, replacement) {
  if (typeof testFn !== "function") {
    throw new Error("registerValueDetector requires a test function");
  }
  customDetectors.push({ name: name, test: testFn, replacement: replacement || DEFAULT_MARKER });
}

function _isSensitiveFieldName(key) {
  if (typeof key !== "string") return false;
  var lk = key.toLowerCase();
  if (sensitiveFieldsSet.has(lk)) return true;
  // Substring match: 'userPassword' contains 'password'
  for (var s of sensitiveFieldsSet) {
    if (lk.indexOf(s) !== -1) return true;
  }
  return false;
}

function _redactValue(value) {
  if (typeof value !== "string") return value;
  var allDetectors = VALUE_DETECTORS.concat(customDetectors);
  for (var i = 0; i < allDetectors.length; i++) {
    if (allDetectors[i].test(value)) {
      var rep = allDetectors[i].replacement;
      return typeof rep === "function" ? rep(value) : rep;
    }
  }
  return value;
}

/**
 * @primitive b.redact.redact
 * @signature b.redact.redact(value, opts?)
 * @since     0.1.0
 * @related   b.redact.registerFieldRule, b.redact.registerValueDetector, b.redact.classifyDefaults
 *
 * Walk `value` and return a NEW value with sensitive fields and
 * sensitive-shaped strings replaced by the marker. Handles plain
 * objects, arrays, primitives, Buffers (always replaced — never log
 * raw binary). The original input is never mutated.
 *
 * @opts
 *   marker:     string,         // replacement marker; default "[REDACTED]"
 *   maxDepth:   number,         // recursion cap; default 50
 *   parentKey:  string | null,  // seed parent-key for top-level scalars
 *
 * @example
 *   var safe = b.redact.redact({
 *     email:    "alice@example.com",
 *     password: "hunter2",
 *     card:     "4111 1111 1111 1111",
 *     note:     "see eyJabcdefghijk.eyJxyz.signature for proof",
 *   });
 *   // → { email: "alice@example.com",
 *   //     password: "[REDACTED]",
 *   //     card: "[REDACTED-CC]",
 *   //     note: "see eyJabcdefghijk.eyJxyz.signature for proof" }
 */
function redact(value, opts) {
  opts = opts || {};
  var marker = opts.marker || DEFAULT_MARKER;
  var maxDepth = opts.maxDepth || 50;
  return _redact(value, 0, maxDepth, marker, opts.parentKey || null);
}

function _redact(value, depth, maxDepth, marker, parentKey) {
  if (depth > maxDepth) return marker;
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    if (parentKey && _isSensitiveFieldName(parentKey)) return marker;
    return _redactValue(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    if (parentKey && _isSensitiveFieldName(parentKey)) return marker;
    return value;
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return marker;  // never log raw binary
  }
  if (Array.isArray(value)) {
    return value.map(function (v) { return _redact(v, depth + 1, maxDepth, marker, null); });
  }
  if (typeof value === "object") {
    var out = {};
    for (var k in value) {
      if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
      if (_isSensitiveFieldName(k)) {
        out[k] = marker;
      } else {
        out[k] = _redact(value[k], depth + 1, maxDepth, marker, k);
      }
    }
    return out;
  }
  return value;
}

function _resetForTest() {
  sensitiveFieldsSet = new Set(SENSITIVE_FIELDS);
  customDetectors = [];
}

// ---- Classifier presets (for outbound DLP) ----
//
// Each pattern maps to a verdict-producing predicate. The default
// classifier walks the request body and headers, surfaces a verdict
// per-pattern, and returns either "clean", "redact" (if any pattern
// is sanitizable in-place by the redactor), or "refuse" (if any
// pattern is operator-flagged as refuse-only).
//
// Patterns:
//   pan, credit-card  — Luhn-validated card numbers
//   ssn               — US SSN shape
//   ein               — US EIN shape (NN-NNNNNNN)
//   iban              — IBAN shape + mod-97 checksum
//   api-key-shape     — generic high-entropy long token in known-key
//                       header / field names
//   pem, ssh-private  — private-key blocks
//   jwt               — JWS triplet
//   aws-access-key    — AWS access-key-id shape
//   phi-shape         — composite of US SSN + DOB-shape near a name field
//                       (used for HIPAA posture)
var CLASSIFIER_PATTERNS = Object.freeze({
  "pan": {
    detect: function (v) {
      if (typeof v !== "string") return false;
      // Two-stage match: full-field exact PAN OR embedded 13-19 digit
      // run anywhere in a longer string. Both pass through Luhn before
      // being flagged so high-digit-count IDs (timestamps, monotonic
      // sequence numbers) don't false-positive.
      var dExact = v.replace(/\s|-/g, "");
      if (/^\d{13,19}$/.test(dExact) && _luhnCheck(dExact)) return true;
      var m = v.match(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/);
      if (m) {
        var inner = m[0].replace(/\s|-/g, "");
        if (inner.length >= 13 && inner.length <= 19 && _luhnCheck(inner)) return true;
      }
      return false;
    },
    action: "refuse",
    label:  "pan",
  },
  "credit-card": {
    detect: function (v) {
      if (typeof v !== "string") return false;
      var dExact = v.replace(/\s|-/g, "");
      if (/^\d{13,19}$/.test(dExact) && _luhnCheck(dExact)) return true;
      var m = v.match(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/);
      if (m) {
        var inner = m[0].replace(/\s|-/g, "");
        if (inner.length >= 13 && inner.length <= 19 && _luhnCheck(inner)) return true;
      }
      return false;
    },
    action: "refuse",
    label:  "credit-card",
  },
  "ssn": {
    detect: function (v) { return typeof v === "string" && /\b\d{3}-\d{2}-\d{4}\b/.test(v); },
    action: "redact",
    label:  "ssn",
  },
  "ein": {
    detect: function (v) { return typeof v === "string" && /\b\d{2}-\d{7}\b/.test(v); },
    action: "redact",
    label:  "ein",
  },
  "iban": {
    detect: function (v) {
      if (typeof v !== "string") return false;
      var s = v.replace(/\s/g, "").toUpperCase();
      if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
      // mod-97 checksum
      var rearranged = s.slice(4) + s.slice(0, 4);
      var num = "";
      for (var i = 0; i < rearranged.length; i += 1) {
        var c = rearranged.charCodeAt(i);
        if (c >= 48 && c <= 57) num += rearranged.charAt(i); // ASCII '0'..'9' codepoint range
        else if (c >= 65 && c <= 90) num += String(c - 55);
        else return false;
      }
      // Long-integer mod 97 in chunks
      var rem = 0;
      for (var j = 0; j < num.length; j += 7) {
        rem = parseInt(String(rem) + num.slice(j, j + 7), 10) % 97;
      }
      return rem === 1;
    },
    action: "refuse",
    label:  "iban",
  },
  "api-key-shape": {
    detect: function (v) {
      if (typeof v !== "string") return false;
      // High-entropy string with at least one digit + one uppercase + length >= 24.
      if (v.length < 24) return false; // minimum entropy-bearing string length in chars, not bytes
      if (!/[A-Z]/.test(v)) return false;
      if (!/[0-9]/.test(v)) return false;
      if (!/^[A-Za-z0-9_-]+$/.test(v)) return false;
      return true;
    },
    action: "redact",
    label:  "api-key-shape",
  },
  "pem": {
    detect: function (v) { return typeof v === "string" && /-----BEGIN [A-Z ]+-----/.test(v); },
    action: "refuse",
    label:  "pem",
  },
  "ssh-private": {
    detect: function (v) { return typeof v === "string" && /-----BEGIN OPENSSH PRIVATE KEY-----/.test(v); },
    action: "refuse",
    label:  "ssh-private",
  },
  "jwt": {
    detect: function (v) {
      return typeof v === "string" &&
        /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
    },
    action: "redact",
    label:  "jwt",
  },
  "aws-access-key": {
    detect: function (v) {
      return typeof v === "string" &&
        /\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/.test(v);
    },
    action: "refuse",
    label:  "aws-access-key",
  },
  "phi-shape": {
    detect: function (v) {
      if (typeof v !== "string") return false;
      // SSN, DOB, MRN, ICD-10 shape — any one is enough to flag PHI
      // adjacency in a body fragment. Operators using HIPAA posture
      // get this composite by default.
      if (/\b\d{3}-\d{2}-\d{4}\b/.test(v)) return true;                 // SSN
      if (/\b(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}\b/.test(v)) return true; // DOB
      if (/\bMRN[:#]?\s*\d{4,12}\b/i.test(v)) return true;              // MRN
      if (/\b[A-TV-Z][0-9][0-9AB](\.[0-9A-TV-Z]{1,4})?\b/.test(v)) return true; // ICD-10
      return false;
    },
    action: "refuse",
    label:  "phi-shape",
  },
});

// classifyDefaults — build a classifier function from a list of pattern
// names. The returned classifier inspects body + headers and yields:
//
//   { verdict: "clean" | "redact" | "refuse",
//     hits:    [ { label, action, where } ],
//     redacted?: <body with matches replaced by marker> }
//
// "refuse" wins over "redact" wins over "clean". Operators choosing
// "redact" actions still get a redacted body so the request can proceed
// without leaking the matched value; "refuse" means the host primitive
// throws DlpError.
/**
 * @primitive b.redact.classifyDefaults
 * @signature b.redact.classifyDefaults(opts)
 * @since     0.7.46
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, fapi2
 * @related   b.redact.installOutboundDlp, b.redact.installForPosture
 *
 * Build a classifier function from a list of pattern names. The
 * returned `classify({ body, headers, url })` walks the body (object,
 * string, or Buffer), inspects every header value, and returns
 * `{ verdict, hits, redactedBody }`. Verdict precedence is
 * `refuse > redact > audit-only > clean`.
 *
 * @opts
 *   patterns:       string[],            // names from CLASSIFIER_PATTERNS
 *   extra:          object,              // additional { name: { detect, action, label } }
 *   overrideAction: "refuse" | "redact" | "audit-only",
 *   marker:         string,              // default "[REDACTED]"
 *
 * @example
 *   var classify = b.redact.classifyDefaults({
 *     patterns: ["pan", "ssn", "jwt", "aws-access-key"],
 *   });
 *   var v = classify({
 *     body:    { card: "4111111111111111", note: "ok" },
 *     headers: { authorization: "Bearer eyJabc.eyJdef.sig" },
 *   });
 *   // → v.verdict === "refuse"  (PAN match defaults to refuse)
 */
function classifyDefaults(opts) {
  opts = opts || {};
  validateOpts(opts, ["patterns", "extra", "overrideAction", "marker"], "redact.classifyDefaults");
  var patterns = Array.isArray(opts.patterns) ? opts.patterns : Object.keys(CLASSIFIER_PATTERNS);
  if (patterns.length === 0) {
    throw new DlpError("redact-dlp/no-patterns",
      "redact.classifyDefaults: opts.patterns must be a non-empty array");
  }
  for (var p = 0; p < patterns.length; p += 1) {
    if (typeof patterns[p] !== "string") {
      throw new DlpError("redact-dlp/bad-pattern",
        "redact.classifyDefaults: patterns[" + p + "] must be a string, got " +
        typeof patterns[p]);
    }
    if (!CLASSIFIER_PATTERNS[patterns[p]] &&
        !(opts.extra && opts.extra[patterns[p]])) {
      throw new DlpError("redact-dlp/unknown-pattern",
        "redact.classifyDefaults: unknown pattern '" + patterns[p] +
        "'. Known: " + Object.keys(CLASSIFIER_PATTERNS).join(", "));
    }
  }
  var marker = typeof opts.marker === "string" && opts.marker.length > 0
    ? opts.marker : DEFAULT_MARKER;
  var overrideAction = opts.overrideAction || null;
  if (overrideAction && overrideAction !== "refuse" && overrideAction !== "redact" && overrideAction !== "audit-only") {
    throw new DlpError("redact-dlp/bad-action",
      "redact.classifyDefaults: overrideAction must be refuse|redact|audit-only");
  }
  var extra = opts.extra || {};

  function _resolve(name) {
    var spec = CLASSIFIER_PATTERNS[name] || extra[name];
    return spec;
  }

  return function classify(input) {
    var hits = [];
    var bodyAccumulator = [];

    function _scanString(str, where) {
      if (typeof str !== "string" || str.length === 0) return str;
      var out = str;
      for (var i = 0; i < patterns.length; i += 1) {
        var spec = _resolve(patterns[i]);
        if (!spec) continue;
        if (spec.detect(out)) {
          var action = overrideAction || spec.action;
          hits.push({ label: spec.label || patterns[i], action: action, where: where });
          if (action === "redact") {
            // Best-effort scrub of the matched fragment. Field-name
            // redaction inside the body is handled by walking the
            // structure separately.
            out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker)
                     .replace(/\b\d{2}-\d{7}\b/g, marker);
            // For other shapes, replace the full string when matched.
            if (spec.label !== "ssn" && spec.label !== "ein") out = marker;
          }
        }
      }
      return out;
    }

    function _walk(value, where) {
      if (value === null || value === undefined) return value;
      if (typeof value === "string") {
        var scanned = _scanString(value, where);
        bodyAccumulator.push(scanned);
        return scanned;
      }
      if (typeof value === "number" || typeof value === "boolean") return value;
      if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        return value;  // raw bytes — scanned separately when input.body
      }
      if (Array.isArray(value)) {
        return value.map(function (item, idx) {
          return _walk(item, where + "[" + idx + "]");
        });
      }
      if (typeof value === "object") {
        var copy = {};
        for (var k in value) {
          if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
          copy[k] = _walk(value[k], where + "." + k);
        }
        return copy;
      }
      return value;
    }

    var redactedBody;
    var input2 = input || {};
    var bodyVal = input2.body;
    if (Buffer.isBuffer(bodyVal) || bodyVal instanceof Uint8Array) {
      var asText;
      try { asText = Buffer.from(bodyVal).toString("utf8"); }
      catch (_e) { asText = ""; }
      var scannedText = _scanString(asText, "body");
      redactedBody = scannedText === asText ? bodyVal : Buffer.from(scannedText, "utf8");
    } else if (typeof bodyVal === "string") {
      redactedBody = _scanString(bodyVal, "body");
    } else if (bodyVal && typeof bodyVal === "object") {
      redactedBody = _walk(bodyVal, "body");
    } else {
      redactedBody = bodyVal;
    }

    if (input2.headers && typeof input2.headers === "object") {
      for (var hk in input2.headers) {
        if (!Object.prototype.hasOwnProperty.call(input2.headers, hk)) continue;
        _scanString(String(input2.headers[hk]), "headers." + hk);
      }
    }

    // Verdict precedence: refuse > redact > audit-only > clean.
    var verdict = "clean";
    for (var hi = 0; hi < hits.length; hi += 1) {
      if (hits[hi].action === "refuse") { verdict = "refuse"; break; }
      if (hits[hi].action === "redact") verdict = "redact";
      else if (hits[hi].action === "audit-only" && verdict === "clean") verdict = "audit-only";
    }
    return { verdict: verdict, hits: hits, redactedBody: redactedBody };
  };
}

// ---- Outbound DLP installer ----

var OUTBOUND_INSTALL_REGISTRY = new WeakMap();

function _emitDlp(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent */ }
}

function _wrapClassifier(fn, where) {
  if (typeof fn !== "function") {
    throw new DlpError("redact-dlp/bad-classifier",
      where + ": classifier must be a function");
  }
  return function safeClassify(input) {
    var v;
    try { v = fn(input || {}); }
    catch (e) {
      // Classifier threw — treat as refuse (fail-closed, since the
      // classifier is the gate; an unknown verdict cannot be
      // sanitized as "clean").
      return { verdict: "refuse", hits: [{ label: "classifier-error", action: "refuse", where: "classifier" }],
        redactedBody: input && input.body, error: e && e.message };
    }
    if (!v || typeof v !== "object" || typeof v.verdict !== "string") {
      return { verdict: "refuse", hits: [{ label: "classifier-bad-verdict", action: "refuse", where: "classifier" }],
        redactedBody: input && input.body };
    }
    return v;
  };
}

// installOutboundDlp({ httpClient, mail, webhook, classifier?, posture?,
//                      onRefuse?, onRedact?, onScan? })
//
// Installs interceptors on each of the operator-supplied primitive
// instances. The installer is idempotent per primitive — a second
// install with the same instance no-ops on that instance. Each
// interceptor wraps the request-emit boundary; the original instance
// keeps its surface unchanged and any callers see DlpError on refuse
// or a sanitized payload on redact.
//
// Returns { uninstall(), installed: { httpClient, mail, webhook } }.
/**
 * @primitive b.redact.installOutboundDlp
 * @signature b.redact.installOutboundDlp(opts)
 * @since     0.7.46
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, fapi2
 * @related   b.redact.classifyDefaults, b.redact.installForPosture
 *
 * Install request-time interceptors on `httpClient` / `mail` /
 * `webhook` instances so every outbound payload runs through a DLP
 * classifier first. Refused requests reject with `DlpError`; redacted
 * requests proceed with a sanitized body. Idempotent per primitive
 * instance — installing twice on the same client no-ops.
 *
 * @opts
 *   httpClient: object,             // instance with .request(opts)
 *   mail:       object,             // instance with .send(message)
 *   webhook:    object,             // signer instance with .send(input)
 *   classifier: function,           // override the default classifier
 *   posture:    string,             // "pci-dss" | "hipaa" | "fapi2" | "soc2" | "gdpr"
 *   onRefuse:   function,           // hook fired on refuse verdict
 *   onRedact:   function,           // hook fired on redact verdict
 *   onScan:     function,           // hook fired on every classify call
 *
 * @example
 *   var http  = b.httpClient.create({ baseUrl: "https://api.example.com" });
 *   var mail  = b.mail.create({ host: "smtp.example.com", port: 587 });
 *   var dlp = b.redact.installOutboundDlp({
 *     httpClient: http,
 *     mail:       mail,
 *     posture:    "pci-dss",
 *     onRefuse:   function (info) { console.warn("DLP refused", info.verdict.hits); },
 *   });
 *   // dlp.installed → { httpClient: true, mail: true, webhook: false }
 *   // dlp.uninstall() restores the original .request / .send methods.
 */
function installOutboundDlp(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "httpClient", "mail", "webhook", "classifier", "posture",
    "onRefuse", "onRedact", "onScan",
  ], "redact.installOutboundDlp");

  // Posture default-on. When posture is given but no classifier, we
  // build a posture-derived default. PCI-DSS → pan + credit-card +
  // pem + aws-access-key. HIPAA → phi-shape + ssn + ein + pem.
  var classifier = opts.classifier;
  var posturePatterns = null;
  if (typeof opts.posture === "string" && opts.posture.length > 0) {
    posturePatterns = _resolvePosturePatterns(opts.posture);
  }
  if (!classifier) {
    classifier = classifyDefaults({
      patterns: posturePatterns ||
        ["pan", "ssn", "ein", "iban", "credit-card", "api-key-shape", "pem", "ssh-private", "aws-access-key"],
    });
  }
  classifier = _wrapClassifier(classifier, "redact.installOutboundDlp");

  validateOpts.optionalFunction(opts.onRefuse, "redact.installOutboundDlp: onRefuse",
    DlpError, "redact-dlp/bad-hook");
  validateOpts.optionalFunction(opts.onRedact, "redact.installOutboundDlp: onRedact",
    DlpError, "redact-dlp/bad-hook");
  validateOpts.optionalFunction(opts.onScan, "redact.installOutboundDlp: onScan",
    DlpError, "redact-dlp/bad-hook");

  var uninstallers = [];
  var installed = { httpClient: false, mail: false, webhook: false };

  if (opts.httpClient) {
    var u1 = _installHttpClient(opts.httpClient, classifier, opts);
    if (u1) { uninstallers.push(u1); installed.httpClient = true; }
  }
  if (opts.mail) {
    var u2 = _installMail(opts.mail, classifier, opts);
    if (u2) { uninstallers.push(u2); installed.mail = true; }
  }
  if (opts.webhook) {
    var u3 = _installWebhook(opts.webhook, classifier, opts);
    if (u3) { uninstallers.push(u3); installed.webhook = true; }
  }

  _emitDlp("dlp.outbound.installed", "success", {
    posture:   opts.posture || null,
    primitives: Object.keys(installed).filter(function (k) { return installed[k]; }),
  });

  return {
    installed:  installed,
    uninstall:  function () {
      while (uninstallers.length > 0) {
        var fn = uninstallers.pop();
        try { fn(); } catch (_e) { /* best-effort */ }
      }
    },
  };
}

function _resolvePosturePatterns(name) {
  var n = String(name).toLowerCase();
  if (n === "pci-dss" || n === "pci") {
    return ["pan", "credit-card", "pem", "aws-access-key", "api-key-shape"];
  }
  if (n === "hipaa") {
    return ["phi-shape", "ssn", "ein", "pem", "aws-access-key", "api-key-shape"];
  }
  if (n === "fapi2") {
    return ["pan", "credit-card", "iban", "pem", "aws-access-key", "jwt", "api-key-shape"];
  }
  if (n === "soc2" || n === "gdpr") {
    return ["ssn", "ein", "pem", "ssh-private", "aws-access-key", "api-key-shape"];
  }
  throw new DlpError("redact-dlp/unknown-posture",
    "redact.installOutboundDlp: unknown posture '" + name +
    "'. Known: pci-dss | hipaa | fapi2 | soc2 | gdpr");
}

function _runHook(hook, payload) {
  if (typeof hook !== "function") return;
  try { hook(payload); } catch (_e) { /* drop-silent */ }
}

function _installHttpClient(client, classifier, opts) {
  if (OUTBOUND_INSTALL_REGISTRY.has(client)) return null;
  if (typeof client.request !== "function") {
    throw new DlpError("redact-dlp/bad-target",
      "redact.installOutboundDlp: httpClient must expose a request() function");
  }
  var original = client.request.bind(client);
  client.request = function dlpScannedRequest(reqOpts) {
    reqOpts = reqOpts || {};
    var verdict = classifier({ body: reqOpts.body, headers: reqOpts.headers, url: reqOpts.url });
    _runHook(opts.onScan, { primitive: "httpClient", verdict: verdict, opts: reqOpts });
    if (verdict.verdict === "refuse") {
      _emitDlp("dlp.outbound.refused", "denied", {
        primitive: "httpClient",
        url:       reqOpts.url || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRefuse, { primitive: "httpClient", verdict: verdict, opts: reqOpts });
      return Promise.reject(new DlpError("redact-dlp/refused",
        "outbound httpClient.request refused by DLP classifier — hits: " +
        verdict.hits.map(function (h) { return h.label; }).join(", ")));
    }
    if (verdict.verdict === "redact") {
      // Mutate the body field on a defensive shallow clone built via
      // explicit field copy, not Object.assign, so operator-shaped opts
      // can't smuggle keys past the existing httpClient.request opts
      // validator.
      var newOpts = {};
      for (var rk in reqOpts) {
        if (Object.prototype.hasOwnProperty.call(reqOpts, rk)) newOpts[rk] = reqOpts[rk];
      }
      newOpts.body = verdict.redactedBody;
      _emitDlp("dlp.outbound.redacted", "success", {
        primitive: "httpClient",
        url:       reqOpts.url || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRedact, { primitive: "httpClient", verdict: verdict, opts: newOpts });
      return original(newOpts);
    }
    return original(reqOpts);
  };
  OUTBOUND_INSTALL_REGISTRY.set(client, true);
  return function uninstall() {
    client.request = original;
    OUTBOUND_INSTALL_REGISTRY.delete(client);
  };
}

function _installMail(mailInstance, classifier, opts) {
  if (OUTBOUND_INSTALL_REGISTRY.has(mailInstance)) return null;
  if (typeof mailInstance.send !== "function") {
    throw new DlpError("redact-dlp/bad-target",
      "redact.installOutboundDlp: mail must expose a send() function");
  }
  var original = mailInstance.send.bind(mailInstance);
  mailInstance.send = function dlpScannedSend(message) {
    message = message || {};
    var bodyParts = {
      text:    message.text,
      html:    message.html,
      subject: message.subject,
    };
    var verdict = classifier({ body: bodyParts, headers: message.headers || {} });
    _runHook(opts.onScan, { primitive: "mail", verdict: verdict, message: message });
    if (verdict.verdict === "refuse") {
      _emitDlp("dlp.outbound.refused", "denied", {
        primitive: "mail",
        to:        message.to || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRefuse, { primitive: "mail", verdict: verdict, message: message });
      return Promise.reject(new DlpError("redact-dlp/refused",
        "outbound mail.send refused by DLP classifier — hits: " +
        verdict.hits.map(function (h) { return h.label; }).join(", ")));
    }
    if (verdict.verdict === "redact") {
      var newMessage = {};
      for (var mk in message) {
        if (Object.prototype.hasOwnProperty.call(message, mk)) newMessage[mk] = message[mk];
      }
      newMessage.text    = verdict.redactedBody && verdict.redactedBody.text;
      newMessage.html    = verdict.redactedBody && verdict.redactedBody.html;
      newMessage.subject = verdict.redactedBody && verdict.redactedBody.subject;
      _emitDlp("dlp.outbound.redacted", "success", {
        primitive: "mail",
        to:        message.to || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRedact, { primitive: "mail", verdict: verdict, message: newMessage });
      return original(newMessage);
    }
    return original(message);
  };
  OUTBOUND_INSTALL_REGISTRY.set(mailInstance, true);
  return function uninstall() {
    mailInstance.send = original;
    OUTBOUND_INSTALL_REGISTRY.delete(mailInstance);
  };
}

function _installWebhook(signerInstance, classifier, opts) {
  if (OUTBOUND_INSTALL_REGISTRY.has(signerInstance)) return null;
  if (typeof signerInstance.send !== "function") {
    throw new DlpError("redact-dlp/bad-target",
      "redact.installOutboundDlp: webhook must expose a send() function (signer instance)");
  }
  var original = signerInstance.send.bind(signerInstance);
  signerInstance.send = function dlpScannedWebhookSend(input) {
    input = input || {};
    var bodyForScan = input.body;
    // body may be a JSON string — try parsing for a richer scan.
    var parsedBody = null;
    if (typeof bodyForScan === "string") {
      try { parsedBody = safeJson.parse(bodyForScan); }
      catch (_e) { parsedBody = null; }
    }
    var verdict = classifier({
      body:    parsedBody !== null ? parsedBody : bodyForScan,
      headers: input.headers || {},
      url:     input.url,
    });
    _runHook(opts.onScan, { primitive: "webhook", verdict: verdict, input: input });
    if (verdict.verdict === "refuse") {
      _emitDlp("dlp.outbound.refused", "denied", {
        primitive: "webhook",
        url:       input.url || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRefuse, { primitive: "webhook", verdict: verdict, input: input });
      return Promise.reject(new DlpError("redact-dlp/refused",
        "outbound webhook.send refused by DLP classifier — hits: " +
        verdict.hits.map(function (h) { return h.label; }).join(", ")));
    }
    if (verdict.verdict === "redact") {
      var newBody = parsedBody !== null
        ? JSON.stringify(verdict.redactedBody)
        : verdict.redactedBody;
      // Build the rebuilt input from a fixed allowlist of fields rather
      // than a spread, so an operator-shaped input object cannot smuggle
      // unexpected keys into the downstream signer-send call.
      var newInput = {
        url:     input.url,
        body:    newBody,
        kid:     input.kid,
        headers: input.headers,
      };
      _emitDlp("dlp.outbound.redacted", "success", {
        primitive: "webhook",
        url:       input.url || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRedact, { primitive: "webhook", verdict: verdict, input: newInput });
      return original(newInput);
    }
    return original(input);
  };
  OUTBOUND_INSTALL_REGISTRY.set(signerInstance, true);
  return function uninstall() {
    signerInstance.send = original;
    OUTBOUND_INSTALL_REGISTRY.delete(signerInstance);
  };
}

function _summarizeHit(h) {
  return { label: h.label, action: h.action, where: h.where };
}

// Posture-coordinated install — a thin wrapper used by b.compliance.set
// to wire DLP automatically when the posture is set. Operators using
// b.compliance can rely on this; direct callers use installOutboundDlp.
/**
 * @primitive b.redact.installForPosture
 * @signature b.redact.installForPosture(posture, primitives)
 * @since     0.7.46
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, fapi2
 * @related   b.redact.installOutboundDlp, b.redact.classifyDefaults
 *
 * Posture-coordinated install — a thin wrapper used by
 * `b.compliance.set` so picking a posture also wires outbound DLP
 * automatically. Direct callers usually want `installOutboundDlp`
 * because it accepts the full hook surface.
 *
 * @example
 *   var dlp = b.redact.installForPosture("hipaa", {
 *     httpClient: myHttp,
 *     mail:       myMail,
 *     webhook:    myWebhook,
 *   });
 *   // → dlp.installed.httpClient === true
 */
function installForPosture(posture, primitives) {
  return installOutboundDlp({
    httpClient: primitives && primitives.httpClient,
    mail:       primitives && primitives.mail,
    webhook:    primitives && primitives.webhook,
    posture:    posture,
  });
}

module.exports = {
  redact:                redact,
  registerFieldRule:     registerFieldRule,
  registerValueDetector: registerValueDetector,
  classifyDefaults:      classifyDefaults,
  installOutboundDlp:    installOutboundDlp,
  installForPosture:     installForPosture,
  CLASSIFIER_PATTERNS:   CLASSIFIER_PATTERNS,
  MARKER:                DEFAULT_MARKER,
  SENSITIVE_FIELDS:      SENSITIVE_FIELDS,
  DlpError:              DlpError,
  _resetForTest:         _resetForTest,
};
