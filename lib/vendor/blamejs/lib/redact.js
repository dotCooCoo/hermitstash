// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   with a per-detector marker (`[REDACTED-CC]`, `[REDACTED-JWT]`). The
 *   value-shape detectors check member names too, and a matching name is
 *   replaced by the marker (`[REDACTED]`, then `[REDACTED:2]` for the
 *   second in the same object).
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

var nodePath = require("node:path");
var nodeTypes = require("node:util").types;
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var pick = require("./pick");
var safeBuffer = require("./safe-buffer");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var structuredFields = require("./structured-fields");
var validateOpts = require("./validate-opts");
var { DlpError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var DEFAULT_MARKER = "[REDACTED]";

var AUTH_ORDINARY_REMAINDER_RE =
  /(?:entic|enticate|enticated|enticatedas|enticates|enticating|entication|enticationresults|enticator|enticators|enticity|or|ors|ored|oring|ority|orities|oritative|serv|servid)$/y;

var SHORT_SENSITIVE_FIELDS = [
  { name: "auth", ordinary: AUTH_ORDINARY_REMAINDER_RE },
  { name: "pin",  ordinary: /(?:(?:g(?:fn|ms|s)?|ip|set)$|ned|ning|dex|terval|tegrit|stalle|verifi)/y },
  { name: "sid",  ordinary: /(?:(?:e|es)$|ecar|ency|entifier|entkey|ual)/y },
  { name: "ssn",  ordinary: /ames?$/y },
  { name: "cvc",  ordinary: null },
  { name: "cvv",  ordinary: null },
];

function _hasShortSensitiveOccurrence(lk) {
  for (var e = 0; e < SHORT_SENSITIVE_FIELDS.length; e += 1) {
    var entry = SHORT_SENSITIVE_FIELDS[e];
    var i = lk.indexOf(entry.name);
    while (i !== -1) {
      if (!entry.ordinary) return true;
      entry.ordinary.lastIndex = i + entry.name.length;
      if (!entry.ordinary.test(lk)) return true;                                                        // allow:regex-no-length-cap — every pattern is a fixed alternation with no quantifier, matched at one sticky offset, so each test is O(1) in the name length and the scan is linear overall
      i = lk.indexOf(entry.name, i + 1);
    }
  }
  return false;
}

var SENSITIVE_FIELDS = [
  "password", "passwd", "secret", "token", "apikey", "api_key",
  "authorization", "creditcard", "credit_card",
  "card_number", "cardnumber",
  "privatekey", "private_key", "passphrase", "session",
  "_authtoken", "auth_token", "authtoken", "auth-token", "bearer", "cookie",
  "pincode", "pin_code", "pin-code", "sessionpin", "session_pin",
  "x-api-key", "x_api_key", "x-apikey", "api-key",
  "jwk", "dpop", "proof", "assertion", "client_assertion", "id_token_hint",
  "code_verifier", "client_secret", "refresh_token", "access_token",
];

function _luhnCheck(num) {
  var digits = num.replace(/\D/g, "");
  /* c8 ignore next */
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

function _numberCardDigits(value) {
  if (typeof value === "number" && (!isFinite(value) || Math.floor(value) !== value)) return null;
  if (typeof value !== "number" && typeof value !== "bigint") return null;
  var digits = String(value < 0 ? -value : value);
  if (digits.length < 13 || digits.length > 19) return null;
  var lead = digits.charCodeAt(0);
  if (lead < 0x32 || lead > 0x39) return null;
  for (var i = 1; i < digits.length; i += 1) {
    var c = digits.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return null;
  }
  return digits;
}

function _defineOwn(target, key, value) {
  if (key !== "__proto__") { target[key] = value; return; }
  Object.defineProperty(target, key, { value: value, writable: true, enumerable: true, configurable: true });
}

var VALUE_DETECTORS = [
  {
    name:        "credit-card",
    test:        function (v) {
      /* c8 ignore next */
      if (typeof v !== "string" || v.length < 13) return false;
      var first = v.charCodeAt(0);
      if (!_isDigitCode(first) && first !== 0x2d && !/\s/.test(v.charAt(0))) return false;
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
    name:        "connection-string",
    test:        function (v) {
      if (typeof v !== "string" || v.length < C.BYTES.bytes(8) || v.indexOf("://") === -1) return false;
      if (safeBuffer.byteLengthOf(v) > C.BYTES.kib(8)) return false;
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
  void replacement;
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
 * built-in chain, on member names as well as values.
 *
 * A `testFn` that throws counts as a match, and a replacement function
 * that throws gives `[REDACTED]`, so `b.redact.redact` does not throw and
 * does not return the value or name it was checking.
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
  if (_hasShortSensitiveOccurrence(lk)) return true;
  for (var s of sensitiveFieldsSet) {
    if (lk.indexOf(s) !== -1) return true;
  }
  return false;
}

function _firstDetector(value) {
  for (var i = 0; i < VALUE_DETECTORS.length; i++) {
    if (VALUE_DETECTORS[i].test(value)) return VALUE_DETECTORS[i];
  }
  for (var j = 0; j < customDetectors.length; j++) {
    var matched;
    try { matched = customDetectors[j].test(value); }
    catch (_e) { matched = true; }
    if (matched) return customDetectors[j];
  }
  return null;
}

function _redactValue(value) {
  /* c8 ignore next */
  if (typeof value !== "string") return value;
  var detector = _firstDetector(value);
  if (detector === null) return value;
  var rep = detector.replacement;
  if (typeof rep !== "function") return rep;
  try { return rep(value); }
  catch (_e) { return DEFAULT_MARKER; }
}

function _numberedMarker(marker, n) {
  if (n === 1) return marker;
  return marker.charCodeAt(marker.length - 1) === 0x5d
    ? marker.slice(0, -1) + ":" + n + "]"
    : marker + ":" + n;
}

function _outputNames(keys, marker) {
  var names = null;
  for (var i = 0; i < keys.length; i += 1) {
    if (_firstDetector(keys[i]) === null) continue;
    if (names === null) names = keys.slice();
    names[i] = null;
  }
  if (names === null) return keys;
  var taken = new Set();
  for (var t = 0; t < names.length; t += 1) {
    if (names[t] !== null) taken.add(names[t]);
  }
  var n = 0;
  for (var j = 0; j < names.length; j += 1) {
    if (names[j] !== null) continue;
    var candidate;
    do { n += 1; candidate = _numberedMarker(marker, n); } while (taken.has(candidate));
    taken.add(candidate);
    names[j] = candidate;
  }
  return names;
}

/**
 * @primitive b.redact.redact
 * @signature b.redact.redact(value, opts?)
 * @since     0.1.0
 * @related   b.redact.registerFieldRule, b.redact.registerValueDetector, b.redact.classifyDefaults
 *
 * Walk `value` and return a NEW value with sensitive fields and
 * sensitive-shaped strings replaced by the marker. Handles plain
 * objects, arrays, primitives and Buffers; a Buffer or Uint8Array is
 * always replaced by the marker. An integer number or bigint whose digits have the shape
 * of a payment card number (13-19 digits, first digit 2-9) is checked
 * by its digits and replaced by the same string the digits would get;
 * a numeric Unix timestamp starts with 1 and is kept. The original input
 * is never mutated.
 *
 * Every member name is checked with the same value detectors, including
 * the ones added with `registerValueDetector`. A name that a detector
 * matches is written as the marker. When one object has more than one
 * such name, the second is written `[REDACTED:2]`, the third
 * `[REDACTED:3]`, and so on in the order of the object's keys; a marker
 * that does not end in `]` takes the number after a colon (`***:2`). A
 * numbered marker that is already the name of a kept member in the same
 * object is skipped, so no member is overwritten. The value under a renamed member is
 * redacted as it would be under its original name, and the members keep
 * their order. A name is checked as a string value is, so a 9-digit name
 * and a Luhn-valid 13-19 digit name, a millisecond timestamp among them,
 * are renamed too.
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
  var maxDepth = numericBounds.isNonNegativeFiniteInt(opts.maxDepth) ? opts.maxDepth : 50;
  return _redact(value, 0, maxDepth, marker, opts.parentKey || null);
}

function _redact(value, depth, maxDepth, marker, parentKey) {
  if (depth > maxDepth) return marker;
  if (value === null || value === undefined) return value;
  if (parentKey && _isSensitiveFieldName(parentKey)) return marker;
  if (typeof value === "string") {
    return _redactValue(value);
  }
  if (typeof value === "number" || typeof value === "bigint") {
    var digits = _numberCardDigits(value);
    if (digits === null) return value;
    var redactedDigits = _redactValue(digits);
    return redactedDigits === digits ? value : redactedDigits;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (nodeTypes.isUint8Array(value)) {
    return marker;
  }
  if (Array.isArray(value)) {
    return value.map(function (v) { return _redact(v, depth + 1, maxDepth, marker, null); });
  }
  if (typeof value === "object") {
    var keys = [];
    for (var k in value) {
      if (Object.prototype.hasOwnProperty.call(value, k)) keys.push(k);
    }
    var names = _outputNames(keys, marker);
    var out = {};
    for (var i = 0; i < keys.length; i += 1) {
      var key = keys[i];
      _defineOwn(out, names[i],
        _isSensitiveFieldName(key) ? marker : _redact(value[key], depth + 1, maxDepth, marker, key));
    }
    return out;
  }
  return value;
}

function _resetForTest() {
  sensitiveFieldsSet = new Set(SENSITIVE_FIELDS);
  customDetectors = [];
  outboundInstallCount = 0;
}

var CARD_CANDIDATE_RE = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g;

function _cardSpans(v, firstOnly) {
  var spans = [];
  CARD_CANDIDATE_RE.lastIndex = 0;
  var m;
  while ((m = CARD_CANDIDATE_RE.exec(v)) !== null) {
    var inner = m[0].replace(/\s|-/g, "");
    if (inner.length >= 13 && inner.length <= 19 && _luhnCheck(inner)) {
      spans.push(m.index, m.index + m[0].length);
      if (firstOnly) break;
    } else {
      CARD_CANDIDATE_RE.lastIndex = m.index + 1;
    }
  }
  CARD_CANDIDATE_RE.lastIndex = 0;
  return spans;
}

function _hasLuhnCard(v) {
  if (typeof v !== "string") return false;
  var dExact = v.replace(/\s|-/g, "");
  if (/^\d{13,19}$/.test(dExact) && _luhnCheck(dExact)) return true;
  return _cardSpans(v, true).length > 0;
}

function _replaceCards(str, marker) {
  var spans = _cardSpans(str, false);
  if (spans.length === 0) return str;
  var out = "";
  var at = 0;
  for (var i = 0; i < spans.length; i += 2) {
    out += str.slice(at, spans[i]) + marker;
    at = spans[i + 1];
  }
  return out + str.slice(at);
}

var CLASSIFIER_PATTERNS = Object.freeze({
  "pan": {
    detect: _hasLuhnCard,
    action: "refuse",
    label:  "pan",
  },
  "credit-card": {
    detect: _hasLuhnCard,
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
      var rearranged = s.slice(4) + s.slice(0, 4);
      var num = "";
      for (var i = 0; i < rearranged.length; i += 1) {
        var c = rearranged.charCodeAt(i);
        if (c >= 48 && c <= 57) num += rearranged.charAt(i);
        else if (c >= 65 && c <= 90) num += String(c - 55);
        /* c8 ignore start */
        else return false;
        /* c8 ignore stop */
      }
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
      if (v.length < 24) return false;
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
      if (/\b\d{3}-\d{2}-\d{4}\b/.test(v)) return true;
      if (/\b(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}\b/.test(v)) return true;
      if (/\bMRN[:#]?\s*\d{4,12}\b/i.test(v)) return true;
      if (/\b[A-TV-Z][0-9][0-9AB](\.[0-9A-TV-Z]{1,4})?\b/.test(v)) return true;
      return false;
    },
    action: "refuse",
    label:  "phi-shape",
  },
});

function _nameMayHoldCard(name) {
  for (var i = 0; i < name.length; i += 1) {
    if (!_isDigitCode(name.charCodeAt(i))) return true;
  }
  return _numberCardDigits(BigInt(name)) !== null;
}

function _decodedComponent(text) {
  try { return decodeURIComponent(text); }
  catch (_e) { return text; }
}

function _urlComponents(url) {
  if (url === undefined || url === null) return [];
  var text = String(url);
  var parsed;
  var relative = false;
  try { parsed = new URL(text); }                                  // allow:raw-new-url-parse-only: the URL is split into components to classify, never dialed
  catch (_e) {
    try { parsed = new URL(text, "http://relative.invalid"); relative = true; }   // allow:raw-new-url-parse-only: a relative URL is split the same way
    catch (_e2) { return [{ text: text, where: "url" }]; }
  }
  var parts = [];
  if (!relative) {
    var labels = parsed.hostname.split(".");
    for (var h = 0; h < labels.length; h += 1) parts.push({ text: labels[h], where: "url.host[" + h + "]" });
    if (parsed.username) parts.push({ text: _decodedComponent(parsed.username), where: "url.username" });
    if (parsed.password) parts.push({ text: _decodedComponent(parsed.password), where: "url.password" });
  }
  var segments = parsed.pathname.split("/");
  var at = 0;
  for (var s = 0; s < segments.length; s += 1) {
    if (segments[s].length === 0) continue;
    parts.push({ text: _decodedComponent(segments[s]), where: "url.path[" + at + "]" });
    at += 1;
  }
  var q = 0;
  parsed.searchParams.forEach(function (value, name) {
    parts.push({ text: name, where: "url.query@key:" + q });
    parts.push({ text: value, where: "url.query[" + q + "]" });
    q += 1;
  });
  if (parsed.hash.length > 1) parts.push({ text: _decodedComponent(parsed.hash.slice(1)), where: "url.fragment" });
  return parts;
}

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
 * string, or Buffer), inspects every header name and value and the URL,
 * and returns `{ verdict, hits, redactedBody }`. Verdict precedence is
 * `refuse > redact > audit-only > clean`.
 *
 * Every leaf of the body is scanned: strings, Buffer / Uint8Array values
 * at any depth, and integer numbers and bigints whose digits have the
 * shape of a payment card number (13-19 digits, first digit 2-9). A
 * numeric Unix timestamp starts with 1 and is not scanned. Bytes are read
 * as UTF-8. Bytes that start with a UTF-16 byte-order mark (`FF FE` or
 * `FE FF`) are also read as UTF-16LE or UTF-16BE, and every redact hit in
 * either reading of them is reported as `refuse`, because the bytes are
 * not re-encoded. Bytes that start with a UTF-32 byte-order mark
 * (`FF FE 00 00` or `00 00 FE FF`) are refused with an `undecodable-bytes`
 * hit. In
 * `redactedBody` a redacted number or bigint is replaced by the redacted
 * string, and redacted UTF-8 bytes by a re-encoded Buffer. Booleans are
 * not scanned.
 *
 * Every member name of an object in the body is scanned too, at any
 * depth, and so is every header name. A name is never renamed: a hit
 * whose action would be `redact` is reported as `refuse`, and an
 * `audit-only` hit stays `audit-only`. The hit names the member by its
 * position among the object's own keys, as `<path>@key:<n>`
 * (`body.user@key:2`, `headers@key:0`). The path of a value inside that
 * member, or of that header's value, starts from the same label, so the
 * name does not appear in any hit.
 *
 * The URL is split into its host labels, user name, password, path
 * segments, query names, query values and fragment, each percent-decoded,
 * and each part is scanned as a name is: the URL is never rewritten. The
 * hits are labeled `url.host[<n>]`, `url.username`, `url.password`,
 * `url.path[<n>]`, `url.query@key:<n>`, `url.query[<n>]` and
 * `url.fragment`, or `url` for a URL that does not parse.
 *
 * Names and URL parts are not checked with `api-key-shape`. A name or URL
 * part made only of digits is checked for a card number only when,
 * without its leading zeros, it has 13-19 digits and starts with 2-9, as
 * a number in the body is. A millisecond timestamp starts with 1 and is
 * not checked.
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
    if (!Object.prototype.hasOwnProperty.call(CLASSIFIER_PATTERNS, patterns[p]) &&
        !(opts.extra && Object.prototype.hasOwnProperty.call(opts.extra, patterns[p]))) {
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
    if (Object.prototype.hasOwnProperty.call(CLASSIFIER_PATTERNS, name)) return CLASSIFIER_PATTERNS[name];
    if (Object.prototype.hasOwnProperty.call(extra, name)) return extra[name];
    return undefined;
  }

  return function classify(input) {
    var hits = [];

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
            out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker)
                     .replace(/\b\d{2}-\d{7}\b/g, marker);
            if (spec.label !== "ssn" && spec.label !== "ein") out = marker;
          }
        }
      }
      return out;
    }

    function _scanName(name, where) {
      if (typeof name !== "string" || name.length === 0) return false;
      var cardShaped = _nameMayHoldCard(name);
      var flagged = false;
      for (var i = 0; i < patterns.length; i += 1) {
        var spec = _resolve(patterns[i]);
        if (!spec || spec === CLASSIFIER_PATTERNS["api-key-shape"]) continue;
        if (!cardShaped && (spec === CLASSIFIER_PATTERNS.pan || spec === CLASSIFIER_PATTERNS["credit-card"])) continue;
        if (!spec.detect(name)) continue;
        var action = overrideAction || spec.action;
        hits.push({ label: spec.label || patterns[i], action: action === "redact" ? "refuse" : action, where: where });
        flagged = true;
      }
      return flagged;
    }

    function _scanBytes(bytes, where) {
      var bom = _bomEncoding(bytes);
      if (bom === null) {
        hits.push({ label: "undecodable-bytes", action: "refuse", where: where });
        return bytes;
      }
      var asText;
      try { asText = Buffer.from(bytes).toString("utf8"); }
      // unreachable drop-silent: Buffer.toString only throws on >512MiB payloads
      /* c8 ignore next */
      catch (_e) { asText = ""; }
      if (bom !== "utf-16le" && bom !== "utf-16be") {
        var scannedText = _scanString(asText, where);
        return scannedText === asText ? bytes : Buffer.from(scannedText, "utf8");
      }
      var from = hits.length;
      _scanString(new TextDecoder(bom).decode(bytes), where);
      _scanString(asText, where);
      var found = hits.splice(from);
      var seen = new Set();
      for (var h = 0; h < found.length; h += 1) {
        if (found[h].action === "redact") found[h].action = "refuse";
        var id = JSON.stringify([found[h].label, found[h].action]);
        if (seen.has(id)) continue;
        seen.add(id);
        hits.push(found[h]);
      }
      return bytes;
    }

    function _walk(value, where) {
      if (value === null || value === undefined) return value;
      if (typeof value === "string") return _scanString(value, where);
      if (typeof value === "number" || typeof value === "bigint") {
        var digits = _numberCardDigits(value);
        if (digits === null) return value;
        var scannedDigits = _scanString(digits, where);
        return scannedDigits === digits ? value : scannedDigits;
      }
      if (typeof value === "boolean") return value;
      if (nodeTypes.isUint8Array(value)) return _scanBytes(value, where);
      if (Array.isArray(value)) {
        return value.map(function (item, idx) {
          return _walk(item, where + "[" + idx + "]");
        });
      }
      if (typeof value === "object") {
        var copy = {};
        var index = 0;
        for (var k in value) {
          if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
          var keyWhere = where + "@key:" + index;
          index += 1;
          _defineOwn(copy, k, _walk(value[k], _scanName(k, keyWhere) ? keyWhere : where + "." + k));
        }
        return copy;
      }
      return value;
    }

    var input2 = input || {};
    var redactedBody = _walk(input2.body, "body");

    if (input2.headers && typeof input2.headers === "object") {
      var headerIndex = 0;
      for (var hk in input2.headers) {
        if (!Object.prototype.hasOwnProperty.call(input2.headers, hk)) continue;
        var nameWhere = "headers@key:" + headerIndex;
        headerIndex += 1;
        _scanString(String(input2.headers[hk]), _scanName(hk, nameWhere) ? nameWhere : "headers." + hk);
      }
    }

    var urlParts = _urlComponents(input2.url);
    for (var ui = 0; ui < urlParts.length; ui += 1) _scanName(urlParts[ui].text, urlParts[ui].where);

    var verdict = "clean";
    for (var hi = 0; hi < hits.length; hi += 1) {
      if (hits[hi].action === "refuse") { verdict = "refuse"; break; }
      if (hits[hi].action === "redact") verdict = "redact";
      else if (hits[hi].action === "audit-only" && verdict === "clean") verdict = "audit-only";
    }
    return { verdict: verdict, hits: hits, redactedBody: redactedBody };
  };
}

var OUTBOUND_INSTALL_REGISTRY = new WeakMap();

var outboundInstallCount = 0;

function _emitDlp(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      /* c8 ignore next */
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
    /* c8 ignore next */
    try { v = fn(input || {}); }
    catch (e) {
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
 * classifier first. A refused request rejects with a `DlpError` whose
 * code is `redact-dlp/refused`, or `redact-dlp/undecodable-body` when
 * the body or multipart content cannot be decoded for the scan (described
 * below); redacted
 * requests proceed with a sanitized body. Installing twice on the same
 * instance does nothing the second time.
 *
 * At install it throws `redact-dlp/unknown-posture` for a `posture` it
 * does not know, `redact-dlp/bad-classifier` when `classifier` is not a
 * function, `redact-dlp/bad-hook` when a hook is not a function, and
 * `redact-dlp/bad-target` when an instance has no `request()` or `send()`
 * function. The default classifier is built by `b.redact.classifyDefaults`
 * from a fixed list of patterns, so that function's
 * `redact-dlp/no-patterns`, `redact-dlp/bad-pattern`,
 * `redact-dlp/unknown-pattern` and `redact-dlp/bad-action` do not occur
 * here.
 *
 * An httpClient or webhook body given as a string or as bytes is scanned
 * in every encoding a receiver may read it in. It is always classified as
 * UTF-8, as described below; a string body is sent as UTF-8. It is also
 * decoded and classified as UTF-16LE or UTF-16BE when its bytes start with
 * that byte-order mark (`FF FE` or `FE FF`), and in the encoding the
 * `charset` parameter of its Content-Type header names when that is not
 * UTF-8 (`utf-16le`, `windows-1252`, `shift_jis`; TextDecoder reads
 * `us-ascii` and `iso-8859-1` as `windows-1252`). The decoded text is
 * passed to the classifier as a string body. The hits of every reading are
 * reported together and the strictest verdict applies. A body with such a
 * second reading is sent as the same string or bytes when it is clean.
 * When the classifier would redact it, the request is refused instead and
 * its redact hits are reported as `refuse`, because the body is not
 * re-encoded. The request is refused with `redact-dlp/undecodable-body`
 * and an `undecodable-body` hit when the bytes start with a UTF-32
 * byte-order mark (`FF FE 00 00` or `00 00 FE FF`), when the charset is
 * one TextDecoder cannot decode (`utf-32`, an unknown name), when the
 * charset is `utf-16` or another UTF-16 name that does not give the byte
 * order and the bytes have no UTF-16 byte-order mark, or when the
 * Content-Type headers name different charsets. No option sends such a
 * body unscanned. A UTF-16 body with neither a byte-order mark nor a
 * charset is read as UTF-8 only, and a card number in it is not found. An
 * empty body is not decoded.
 *
 * A webhook body given as a JSON string, and an httpClient body given as
 * a string or as bytes, that safeJson.parse accepts at its default limits
 * (at most 1 MiB, nested at most 100 deep, at most 10,000 members in one
 * object) is classified parsed, so a value written behind a JSON escape
 * (`"4111..."`) is seen as the receiver reads it. The classifier is
 * then called a second time with `body` set to an array of
 * strings: the values on the wire that the parsed object does not hold
 * exactly. These are number literals that JSON.parse rounds and whose
 * value is an integer with the shape of a card number, however the
 * literal is written (`4111111111111111110`, `4111111111111111110.0`,
 * `4.11111111111111111e18`), passed as their exact digits; and every
 * string, card-shaped integer and member name inside a member that a
 * later member of the same name replaces, or inside a `__proto__`,
 * `constructor` or `prototype` member, which the parse drops. The hits
 * of both calls are reported together and the stricter verdict applies.
 * A hit from the second call names the field path of its value, or
 * `body@offset:<n>` (the value's character offset in the body) when the
 * parsed object does not hold it or when a member name in the body was
 * flagged. A member name from the second call that the classifier would
 * redact is refused instead. A redacted JSON body is serialized
 * again from the parsed object: a repeated member name keeps only its
 * last value, and a number literal that JSON.parse does not hold exactly
 * (an integer beyond 2^53, `1e400`, `0.10000000000000000000001`) keeps
 * its literal text unless it was redacted.
 *
 * A body that starts with `{`, `[` or `"` and that safeJson.parse refuses
 * for its size, its nesting or its member count is read token by token
 * instead, whether or not it is valid JSON. The classifier is called with
 * arrays of up to 4096 values: every non-empty string literal and member
 * name with its escapes decoded, and the exact digits of every number
 * literal whose value is a card-shaped integer. A hit from these calls
 * names `body@offset:<n>`, and at most the first 1000 of them are listed.
 * A member name the classifier would redact is refused. A redacted value
 * is replaced in the text by the redacted string in JSON quotes, and every
 * other character is sent as given. Scanning stops at the first refusal.
 *
 * Every httpClient string or bytes body, and a webhook string that is not
 * classified parsed, is also scanned as text, and the stricter verdict
 * applies. The classifier is first called with an array of the exact
 * digits of every number in the text that is written with a fraction or
 * an exponent and whose value is a card-shaped integer
 * (`4.11111111111111111e18`). A hit from that call names
 * `body@offset:<n>`. A redacted number is replaced in the text by the
 * redacted string in JSON quotes before the text is classified. When the
 * parsed or token-by-token classification redacts the body, the text scan
 * runs again on the result before it is sent. A redacted body given as
 * bytes is sent as a Buffer.
 *
 * When the classifier reports a redact hit on one of these values and
 * returns it unchanged, the value is sent as `[REDACTED]`.
 *
 * The httpClient interceptor classifies the request `url` and headers, and
 * for a `multipart` request it classifies a view of the spec with `body`
 * set to `{ fields, files }`: `fields` is the spec's `fields` object, and
 * `files` holds one `{ field, filename, content }` per file, where
 * `filename` is the name the client writes (the given `filename`, or the
 * base name of `filePath`) and `content` is the in-memory `content`. The
 * hits of that call are labeled from `multipart` (`multipart.fields.note`).
 * A redacted field value or in-memory content is sent redacted, and a
 * field name or file name the classifier would change refuses the request.
 * In-memory content is also read by its byte-order mark and by the charset
 * of the file's `contentType` (or `mimeType`) under the rule above for a
 * body: the classifier is called again with `{ fields: {}, files }`,
 * where each file whose content has another reading carries it as a
 * string and every other file carries no `content`. When content has
 * another reading, a redaction the classifier would make in it in any
 * reading refuses the request. Content whose encoding cannot be read
 * refuses the request with `redact-dlp/undecodable-body` and an
 * `undecodable-body` hit at `multipart.files[<n>].content`.
 * The contents of a file given as `filePath` or `stream`, a body given as
 * a stream, and the bytes an `uploadTransform` produces are not scanned.
 *
 * When an httpClient request carries `before` hooks, the request the last
 * hook returns, or the value its promise resolves to, is classified again
 * before it is sent, and `onScan`, `onRedact` and `onRefuse` fire for that
 * classification too. A refusal there rejects with the same `DlpError`.
 *
 * The `verdict` that `onScan`, `onRedact` and `onRefuse` receive for an
 * httpClient request carries the body that is sent as `redactedBody`. A
 * redact verdict that gives no body that can be sent in place of a string
 * or bytes body (no `redactedBody`, or one that does not serialize as
 * JSON) refuses the request with a `classifier-bad-verdict` hit. A failure
 * while classifying an httpClient request or a webhook rejects the
 * returned promise.
 *
 * The default classifier scans member names, header names and the URL as
 * well as values, and refuses a request whose name or URL part would need
 * redacting rather than renaming it (see `b.redact.classifyDefaults`).
 *
 * A number in a body is checked by its digits when they have the shape
 * of a payment card number: 13-19 digits whose first digit is 2-9. A
 * numeric Unix timestamp starts with 1 and is not checked.
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
 *   var http  = b.httpClient.pinnedClient(
 *     { request: function (opts) { return b.httpClient.request(opts); } },
 *     ["api.example.com"]);
 *   var mail  = b.mail.create({ defaults: { from: "noreply@example.com" } });
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
    if (u1) { uninstallers.push(u1); installed.httpClient = true; outboundInstallCount += 1; }
  }
  if (opts.mail) {
    var u2 = _installMail(opts.mail, classifier, opts);
    if (u2) { uninstallers.push(u2); installed.mail = true; outboundInstallCount += 1; }
  }
  if (opts.webhook) {
    var u3 = _installWebhook(opts.webhook, classifier, opts);
    if (u3) { uninstallers.push(u3); installed.webhook = true; outboundInstallCount += 1; }
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
        try { fn(); if (outboundInstallCount > 0) outboundInstallCount -= 1; }
        catch (_e) { /* best-effort */ }
      }
    },
  };
}

/**
 * @primitive b.redact.isOutboundDlpInstalled
 * @signature b.redact.isOutboundDlpInstalled()
 * @since     0.14.27
 * @compliance hipaa, pci-dss, gdpr, soc2, fapi2
 * @related   b.redact.installForPosture, b.redact.installOutboundDlp
 *
 * Returns `true` when at least one primitive instance (httpClient /
 * mail / webhook) currently carries an outbound-DLP interceptor.
 * `b.compliance.set` reads this to decide whether to emit the one-time
 * `compliance.posture.outbound_dlp_unwired` warning when a posture whose
 * floor implies outbound DLP is pinned without any wiring. Read-only.
 *
 * @example
 *   b.redact.isOutboundDlpInstalled();   // → false
 *   var dlp = b.redact.installForPosture("hipaa", { httpClient: myHttp });
 *   b.redact.isOutboundDlpInstalled();   // → true
 *   dlp.uninstall();
 *   b.redact.isOutboundDlpInstalled();   // → false
 */
function isOutboundDlpInstalled() {
  return outboundInstallCount > 0;
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

function _ownCopy(source) {
  var copy = {};
  for (var k in source) {
    if (Object.prototype.hasOwnProperty.call(source, k)) copy[k] = source[k];
  }
  return copy;
}

function _decideHttpRequest(classifier, hooks, reqOpts) {
  var classified = _classifyHttpRequest(classifier, reqOpts);
  var verdict = classified.verdict;
  _runHook(hooks.onScan, { primitive: "httpClient", verdict: verdict, opts: reqOpts });
  if (verdict.verdict === "refuse") {
    _emitDlp("dlp.outbound.refused", "denied", {
      primitive: "httpClient",
      url:       reqOpts.url || null,
      hits:      verdict.hits.map(_summarizeHit),
    });
    _runHook(hooks.onRefuse, { primitive: "httpClient", verdict: verdict, opts: reqOpts });
    if (classified.undecodable !== undefined) {
      return { error: new DlpError("redact-dlp/undecodable-body",
        "outbound httpClient.request refused: the DLP scan cannot decode " + classified.undecodable) };
    }
    return { error: new DlpError("redact-dlp/refused",
      "outbound httpClient.request refused by DLP classifier; hits: " +
      verdict.hits.map(function (h) { return h.label; }).join(", ")) };
  }
  if (verdict.verdict !== "redact") return { opts: reqOpts };
  var newOpts = _ownCopy(reqOpts);
  newOpts.body = classified.body;
  if (classified.multipart !== undefined) newOpts.multipart = classified.multipart;
  _emitDlp("dlp.outbound.redacted", "success", {
    primitive: "httpClient",
    url:       reqOpts.url || null,
    hits:      verdict.hits.map(_summarizeHit),
  });
  _runHook(hooks.onRedact, { primitive: "httpClient", verdict: verdict, opts: newOpts });
  return { opts: newOpts };
}

function _withFinalScan(reqOpts, scan) {
  if (!Array.isArray(reqOpts.before) || reqOpts.before.length === 0) return reqOpts;
  var copy = _ownCopy(reqOpts);
  copy.before = reqOpts.before.concat([scan]);
  return copy;
}

function _installHttpClient(client, classifier, opts) {
  if (OUTBOUND_INSTALL_REGISTRY.has(client)) return null;
  if (typeof client.request !== "function") {
    throw new DlpError("redact-dlp/bad-target",
      "redact.installOutboundDlp: httpClient must expose a request() function");
  }
  var original = client.request.bind(client);
  client.request = function dlpScannedRequest(reqOpts) {
    var refusal = null;
    var outOpts;
    try {
      var decided = _decideHttpRequest(classifier, opts, reqOpts || {});
      if (decided.error) return Promise.reject(decided.error);
      var scanAgain = function (working) {
        var again = _decideHttpRequest(classifier, opts, working || {});
        if (again.error) { refusal = again.error; throw again.error; }
        return again.opts;
      };
      outOpts = _withFinalScan(decided.opts, function dlpScanAfterBeforeHooks(working) {
        return working && typeof working.then === "function" ? working.then(scanAgain) : scanAgain(working);
      });
    } catch (e) {
      return Promise.reject(e);
    }
    var pending = original(outOpts);
    if (outOpts === decided.opts || !pending || typeof pending.then !== "function") return pending;
    return pending.then(function (res) { return res; }, function (e) { throw refusal !== null ? refusal : e; });
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
        "outbound mail.send refused by DLP classifier; hits: " +
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

var _VERDICT_RANK = Object.freeze({ "clean": 0, "audit-only": 1, "redact": 2, "refuse": 3 });

var MAX_CARD_DIGITS = 19;
var MAX_EXPONENT_MAGNITUDE = 1e15;

function _isDigitCode(c) { return c >= 0x30 && c <= 0x39; }

function _decimalOf(text) {
  var n = text.length;
  var neg = text.charCodeAt(0) === 0x2d;
  var i = neg ? 1 : 0;
  var intStart = i;
  while (i < n && _isDigitCode(text.charCodeAt(i))) i += 1;
  var intEnd = i;
  if (intEnd === intStart) return null;
  var fracStart = i;
  var fracEnd = i;
  if (text.charCodeAt(i) === 0x2e) {
    i += 1;
    fracStart = i;
    while (i < n && _isDigitCode(text.charCodeAt(i))) i += 1;
    fracEnd = i;
  }
  var exp = 0;
  if (i < n && (text.charCodeAt(i) | 0x20) === 0x65) {
    i += 1;
    var sign = text.charCodeAt(i);
    if (sign === 0x2b || sign === 0x2d) i += 1;
    while (i < n && text.charCodeAt(i) === 0x30) i += 1;
    var expStart = i;
    while (i < n && _isDigitCode(text.charCodeAt(i))) i += 1;
    exp = i - expStart > 15 ? MAX_EXPONENT_MAGNITUDE : Number(text.slice(expStart, i));
    if (sign === 0x2d) exp = -exp;
  }
  if (i !== n) return null;
  var digits = text.slice(intStart, intEnd) + text.slice(fracStart, fracEnd);
  var lead = 0;
  while (lead < digits.length && digits.charCodeAt(lead) === 0x30) lead += 1;
  var tail = digits.length;
  while (tail > lead && digits.charCodeAt(tail - 1) === 0x30) tail -= 1;
  if (lead === tail) return { neg: false, sig: "", point: 0 };
  return { neg: neg, sig: digits.slice(lead, tail), point: (intEnd - intStart) + exp - lead };
}

function _wireNumber(literal) {
  var exact = _decimalOf(literal);
  if (exact === null) return { value: null, lossy: false };
  var held = _decimalOf(String(Number(literal)));
  var lossy = held === null || held.sig !== exact.sig ||
    (exact.sig !== "" && (held.neg !== exact.neg || held.point !== exact.point));
  var value = null;
  if (exact.sig !== "" && exact.point >= exact.sig.length && exact.point <= MAX_CARD_DIGITS) {
    value = _numberCardDigits(BigInt(exact.sig + "0".repeat(exact.point - exact.sig.length)));
  }
  return { value: value, lossy: lossy };
}

function _wirePath(node) {
  var keys = [];
  for (var at = node; at.up !== null; at = at.up) keys.push(at.key);
  return keys.reverse();
}

function _wireOnlyValues(text) {
  var leaves = [];
  var n = text.length;
  var pos = text.charCodeAt(0) === 0xfeff ? 1 : 0;

  function _ws() {
    while (pos < n) {
      var c = text.charCodeAt(pos);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
      pos += 1;
    }
  }

  function _skipString() {
    pos += 1;
    while (pos < n) {
      var c = text.charCodeAt(pos);
      if (c === 0x5c) { pos += 2; continue; }
      pos += 1;
      if (c === 0x22) return;
    }
  }

  function _readNumber(up, key) {
    var start = pos;
    if (text.charCodeAt(pos) === 0x2d) pos += 1;
    while (pos < n) {
      var c = text.charCodeAt(pos);
      if (!_isDigitCode(c) && c !== 0x2e && c !== 0x65 && c !== 0x45 && c !== 0x2b && c !== 0x2d) break;
      pos += 1;
    }
    var literal = text.slice(start, pos);
    var num = _wireNumber(literal);
    if (num.value === null && !num.lossy) return;
    leaves.push({ up: up, key: key, start: start, end: pos, str: false, value: num.value,
      literal: literal, lossy: num.lossy, dropped: false, scanIndex: -1 });
  }

  function _readObject(up, key) {
    pos += 1;
    _ws();
    if (text.charCodeAt(pos) === 0x7d) { pos += 1; return; }
    var node = { up: up, key: key, label: undefined };
    var members = [];
    while (pos < n) {
      _ws();
      var keyStart = pos;
      _skipString();
      var name = safeJson.parse(text.slice(keyStart, pos));
      if (up !== null) {
        leaves.push({ up: null, key: null, start: keyStart, end: pos, str: true, value: null,
          literal: null, lossy: false, dropped: false, scanIndex: -1, name: true });
      }
      _ws();
      pos += 1;
      var from = leaves.length;
      _readValue(node, name);
      members.push({ key: name, from: from, to: leaves.length });
      _ws();
      pos += 1;
      if (text.charCodeAt(pos - 1) === 0x7d) break;
    }
    var lastIndex = new Map();
    for (var m = 0; m < members.length; m += 1) lastIndex.set(members[m].key, m);
    for (var d = 0; d < members.length; d += 1) {
      if (lastIndex.get(members[d].key) === d && !pick.isPoisonedKey(members[d].key)) continue;
      for (var li = members[d].from; li < members[d].to; li += 1) leaves[li].dropped = true;
    }
  }

  function _readArray(up, key) {
    pos += 1;
    _ws();
    if (text.charCodeAt(pos) === 0x5d) { pos += 1; return; }
    var node = { up: up, key: key, label: undefined };
    for (var idx = 0; pos < n; idx += 1) {
      _readValue(node, idx);
      _ws();
      pos += 1;
      if (text.charCodeAt(pos - 1) === 0x5d) break;
    }
  }

  function _readValue(up, key) {
    _ws();
    var c = text.charCodeAt(pos);
    if (c === 0x7b) { _readObject(up, key); return; }
    if (c === 0x5b) { _readArray(up, key); return; }
    if (c === 0x22) {
      var start = pos;
      _skipString();
      leaves.push({ up: up, key: key, start: start, end: pos, str: true, value: null,
        literal: null, lossy: false, dropped: false, scanIndex: -1 });
      return;
    }
    if (c === 0x2d || _isDigitCode(c)) { _readNumber(up, key); return; }
    while (pos < n && text.charCodeAt(pos) >= 0x61 && text.charCodeAt(pos) <= 0x7a) pos += 1;
  }

  _readValue(null, null);
  var scan = [];
  var exact = [];
  for (var i = 0; i < leaves.length; i += 1) {
    var leaf = leaves[i];
    if (leaf.str) {
      if (!leaf.dropped) continue;
      leaf.value = safeJson.parse(text.slice(leaf.start, leaf.end));
    }
    if (typeof leaf.value === "string" && (leaf.dropped || leaf.lossy)) {
      leaf.scanIndex = scan.length;
      scan.push(leaf);
    }
    if (leaf.lossy && !leaf.dropped) exact.push(leaf);
  }
  return { scan: scan, exact: exact };
}

function _leafValue(leaf) { return leaf.value; }

function _segment(key) {
  return typeof key === "number" ? "[" + key + "]" : "." + key;
}

function _containerLabel(node) {
  var chain = [];
  for (var at = node; at.label === undefined; at = at.up) {
    chain.push(at);
    if (at.up === null) break;
  }
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    chain[i].label = chain[i].up === null ? "body" : chain[i].up.label + _segment(chain[i].key);
  }
  return node.label;
}

function _wireLabel(leaf) {
  return leaf.up === null ? "body" : _containerLabel(leaf.up) + _segment(leaf.key);
}

function _hitsOf(verdict) {
  return Array.isArray(verdict.hits) ? verdict.hits : [];
}

var WIRE_HIT_INDEX_RE = /^body\[(\d+)\]/;

function _flagsMemberName(verdict) {
  var hits = _hitsOf(verdict);
  for (var i = 0; i < hits.length; i += 1) {
    if (hits[i] && typeof hits[i].where === "string" && hits[i].where.indexOf("@key:") !== -1) return true;
  }
  return false;
}

function _wireHitLabeler(scan, refusedNames, byOffset) {
  return function (hit) {
    if (!hit || typeof hit.where !== "string") return hit;
    var m = WIRE_HIT_INDEX_RE.exec(hit.where);
    var leaf = m ? scan[Number(m[1])] : undefined;
    if (!leaf) return hit;
    var where = (!leaf.dropped && !byOffset ? _wireLabel(leaf) : "body@offset:" + leaf.start) +
      hit.where.slice(m[0].length);
    var relabeled = Object.assign({}, hit, { where: where });
    if (refusedNames.has(Number(m[1])) && hit.action !== "audit-only") relabeled.action = "refuse";
    return relabeled;
  };
}

function _redactedIndexes(verdict) {
  var out = new Set();
  if (!verdict || verdict.verdict !== "redact") return out;
  var hits = _hitsOf(verdict);
  for (var i = 0; i < hits.length; i += 1) {
    var h = hits[i];
    if (!h || typeof h.where !== "string" || h.action === "audit-only") continue;
    var m = WIRE_HIT_INDEX_RE.exec(h.where);
    if (m) out.add(Number(m[1]));
  }
  return out;
}

function _wireReplacement(leaf, wireVerdict, redacted) {
  if (leaf.scanIndex < 0 || !wireVerdict || wireVerdict.verdict !== "redact") return null;
  var scanned = Array.isArray(wireVerdict.redactedBody) ? wireVerdict.redactedBody : null;
  var r = scanned !== null ? scanned[leaf.scanIndex] : undefined;
  if (typeof r === "string" && r !== leaf.value) return r;
  return redacted.has(leaf.scanIndex) ? DEFAULT_MARKER : null;
}

function _stricterVerdict(a, b) {
  return (_VERDICT_RANK[b] || 0) > (_VERDICT_RANK[a] || 0) ? b : a;
}

function _mergeWireVerdict(parsedVerdict, wireVerdict, scan) {
  var verdict = _stricterVerdict(parsedVerdict.verdict, wireVerdict.verdict);
  var names = new Set();
  if (wireVerdict.verdict === "redact") {
    var redacted = _redactedIndexes(wireVerdict);
    for (var i = 0; i < scan.length; i += 1) {
      if (scan[i].name === true && _wireReplacement(scan[i], wireVerdict, redacted) !== null) names.add(i);
    }
    if (names.size > 0) verdict = "refuse";
  }
  return {
    verdict:      verdict,
    hits:         _uniqueHits(_hitsOf(parsedVerdict).concat(_hitsOf(wireVerdict).map(
      _wireHitLabeler(scan, names, _flagsMemberName(parsedVerdict))))),
    redactedBody: parsedVerdict.redactedBody,
  };
}

function _uniqueHits(all) {
  var seen = new Set();
  var hits = [];
  for (var i = 0; i < all.length; i += 1) {
    var h = all[i];
    var id = h && typeof h === "object" ? JSON.stringify([h.label, h.action, h.where]) : null;
    if (id !== null && seen.has(id)) continue;
    if (id !== null) seen.add(id);
    hits.push(h);
  }
  return hits;
}

function _shallowCopy(container) {
  if (Array.isArray(container)) return container.slice();
  var copy = {};
  var keys = Object.keys(container);
  for (var i = 0; i < keys.length; i += 1) {
    Object.defineProperty(copy, keys[i], {
      value: container[keys[i]], writable: true, enumerable: true, configurable: true,
    });
  }
  return copy;
}

function _copyOnWrite() {
  var copies = new Map();
  return function writable(container) {
    var copy = copies.get(container);
    if (copy !== undefined) return copy;
    copy = _shallowCopy(container);
    copies.set(container, copy);
    copies.set(copy, copy);
    return copy;
  };
}

function _setNumberAt(root, path, replacement, parsed, writable) {
  if (path.length === 0) return root === parsed ? replacement : root;
  if (root === null || typeof root !== "object") return root;
  var node = root;
  for (var i = 0; i < path.length - 1; i += 1) {
    if (!Object.prototype.hasOwnProperty.call(node, path[i])) return root;
    var child = node[path[i]];
    if (child === null || typeof child !== "object") return root;
    node = child;
  }
  var last = path[path.length - 1];
  if (!Object.prototype.hasOwnProperty.call(node, last) || node[last] !== parsed) return root;
  var top = writable(root);
  var cur = top;
  for (var d = 0; d < path.length - 1; d += 1) {
    var next = writable(cur[path[d]]);
    cur[path[d]] = next;
    cur = next;
  }
  cur[last] = replacement;
  return top;
}

function _redactedJsonText(parsedBody, parsedVerdict, wire, wireVerdict) {
  var base = parsedVerdict.verdict === "redact" ? parsedVerdict.redactedBody : parsedBody;
  var redacted = _redactedIndexes(wireVerdict);
  var writable = _copyOnWrite();
  for (var i = 0; i < wire.exact.length; i += 1) {
    var leaf = wire.exact[i];
    var replacement = _wireReplacement(leaf, wireVerdict, redacted);
    if (replacement === null) replacement = JSON.rawJSON(leaf.literal);
    base = _setNumberAt(base, _wirePath(leaf), replacement, Number(leaf.literal), writable);
  }
  return JSON.stringify(base);
}

function _isWordCode(c) {
  return _isDigitCode(c) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
}

function _digitsFrom(text, i) {
  while (i < text.length && _isDigitCode(text.charCodeAt(i))) i += 1;
  return i;
}

function _rawNumberValues(text) {
  var leaves = [];
  var n = text.length;
  var i = 0;
  var quoted = false;
  while (i < n) {
    var c = text.charCodeAt(i);
    if (c === 0x5c && quoted) { i += 2; continue; }
    if (c === 0x22) { quoted = !quoted; i += 1; continue; }
    var prev = i > 0 ? text.charCodeAt(i - 1) : 0x20;
    var signed = c === 0x2d && i + 1 < n && _isDigitCode(text.charCodeAt(i + 1));
    if ((!_isDigitCode(c) && !signed) || _isWordCode(prev) || prev === 0x2e) { i += 1; continue; }
    var start = i;
    i = _digitsFrom(text, signed ? i + 1 : i);
    var shaped = false;
    if (i + 1 < n && text.charCodeAt(i) === 0x2e && _isDigitCode(text.charCodeAt(i + 1))) {
      i = _digitsFrom(text, i + 1);
      shaped = true;
    }
    if (i < n && (text.charCodeAt(i) | 0x20) === 0x65) {
      var e = i + 1;
      if (e < n && (text.charCodeAt(e) === 0x2b || text.charCodeAt(e) === 0x2d)) e += 1;
      if (e < n && _isDigitCode(text.charCodeAt(e))) {
        i = _digitsFrom(text, e);
        shaped = true;
      }
    }
    if (!shaped || (i < n && _isWordCode(text.charCodeAt(i))) ||
        (i + 1 < n && text.charCodeAt(i) === 0x2e && _isDigitCode(text.charCodeAt(i + 1)))) {
      continue;
    }
    var value = _wireNumber(text.slice(start, i)).value;
    if (value === null) continue;
    leaves.push({ up: null, key: null, start: start, end: i, str: false, value: value,
      literal: null, lossy: false, dropped: true, scanIndex: leaves.length, quoted: quoted });
  }
  return leaves;
}

function _bomEncoding(bytes) {
  var n = bytes.length;
  if (n >= 4 && bytes[0] === 0xff && bytes[1] === 0xfe && bytes[2] === 0x00 && bytes[3] === 0x00) return null;
  if (n >= 4 && bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0xfe && bytes[3] === 0xff) return null;
  if (n >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return "utf-8";
  if (n >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return "utf-16le";
  if (n >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return "utf-16be";
  return undefined;
}

function _charsetParam(contentType) {
  if (structuredFields.endsInsideQuotedString(contentType)) return null;
  var params = structuredFields.splitTopLevel(contentType, ";");
  var charset;
  for (var i = 1; i < params.length; i += 1) {
    var piece = structuredFields.parseKeyValuePiece(params[i]);
    if (piece.key !== "charset" || piece.value === null) continue;
    var value = structuredFields.unquoteSfString(piece.value);
    if (value === null) return null;
    value = value.trim().toLowerCase();
    if (charset !== undefined && charset !== value) return null;
    charset = value;
  }
  return charset;
}

function _contentTypeCharset(headers) {
  if (!headers || typeof headers !== "object") return undefined;
  var seen = [];
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name) || name.toLowerCase() !== "content-type") continue;
    var values = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
    for (var v = 0; v < values.length; v += 1) {
      if (values[v] === undefined || values[v] === null) continue;
      var charset = _charsetParam(String(values[v]));
      if (charset === null) return null;
      if (seen.length > 0 && seen[0] !== charset) return null;
      seen.push(charset);
    }
  }
  return seen.length > 0 ? seen[0] : undefined;
}

function _isUtf16(encoding) {
  return encoding === "utf-16le" || encoding === "utf-16be";
}

function _otherReadings(body, headers) {
  var bom = nodeTypes.isUint8Array(body) ? _bomEncoding(body) : undefined;
  if (bom === null) return { error: "it starts with a UTF-32 byte-order mark" };
  var label = _contentTypeCharset(headers);
  if (label === null) return { error: "its Content-Type names different charsets" };
  var encodings = _isUtf16(bom) ? [bom] : [];
  if (label === undefined) return { encodings: encodings };
  var encoding;
  try { encoding = new TextDecoder(label).encoding; }
  catch (_e) { return { error: "its charset is not one the runtime can decode" }; }
  if (_isUtf16(encoding) && label !== encoding) {
    if (encodings.length > 0) return { encodings: encodings };
    return { error: "its charset does not name the UTF-16 byte order and it has no UTF-16 byte-order mark" };
  }
  if (encoding !== "utf-8" && encodings.indexOf(encoding) === -1) encodings.push(encoding);
  return { encodings: encodings };
}

function _decodedReadings(body, encodings) {
  var bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return encodings.map(function (encoding) { return new TextDecoder(encoding).decode(bytes); });
}

function _refusedRedactions(verdict) {
  return {
    verdict:      verdict.verdict === "redact" ? "refuse" : verdict.verdict,
    hits:         _uniqueHits(_hitsOf(verdict).map(function (h) {
      return h && h.action === "redact" ? Object.assign({}, h, { action: "refuse" }) : h;
    })),
    redactedBody: undefined,
  };
}

function _classifyEncodedBody(classifyBody, body, headers) {
  if ((!nodeTypes.isUint8Array(body) && typeof body !== "string") || body.length === 0) return classifyBody(body);
  var readings = _otherReadings(body, headers);
  if (readings.error !== undefined) {
    return { verdict: _refusalVerdict("undecodable-body", "body"), body: body,
      undecodable: "the body because " + readings.error };
  }
  var classified = classifyBody(body);
  if (readings.encodings.length === 0) return classified;
  var verdict = classified.verdict;
  var decoded = _decodedReadings(body, readings.encodings);
  for (var i = 0; i < decoded.length; i += 1) verdict = _mergeVerdicts(verdict, classifyBody(decoded[i]).verdict);
  verdict = _refusedRedactions(verdict);
  return { verdict: Object.assign({}, verdict, { redactedBody: body }), body: body };
}

function _bodyText(body) {
  if (typeof body === "string") return body;
  if (nodeTypes.isUint8Array(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString("utf8");
  return null;
}

function _classifyText(classifier, body, headers, url) {
  var text = _bodyText(body);
  var raw = text !== null ? _rawNumberValues(text) : [];
  var scanned = body;
  var rawVerdict = null;
  if (raw.length > 0) {
    rawVerdict = classifier({ body: raw.map(_leafValue), headers: {}, url: url });
    var redacted = _redactedIndexes(rawVerdict);
    var parts = [];
    var at = 0;
    for (var i = 0; i < raw.length; i += 1) {
      var replacement = _wireReplacement(raw[i], rawVerdict, redacted);
      if (replacement === null) continue;
      var quotedText = JSON.stringify(replacement);
      parts.push(text.slice(at, raw[i].start), raw[i].quoted ? quotedText.slice(1, -1) : quotedText);
      at = raw[i].end;
    }
    if (parts.length > 0) {
      parts.push(text.slice(at));
      scanned = typeof body === "string" ? parts.join("") : Buffer.from(parts.join(""), "utf8");
    }
  }
  var mainVerdict = classifier({ body: scanned, headers: headers, url: url });
  return {
    verdict: rawVerdict !== null ? _mergeWireVerdict(mainVerdict, rawVerdict, raw) : mainVerdict,
    body:    mainVerdict.verdict === "redact" ? mainVerdict.redactedBody : scanned,
  };
}

var TOKEN_BATCH = 4096;
var TOKEN_HIT_LIMIT = 1000;

var JSON_SIMPLE_ESCAPES = Object.freeze({
  0x22: "\"", 0x5c: "\\", 0x2f: "/", 0x62: "\b", 0x66: "\f", 0x6e: "\n", 0x72: "\r", 0x74: "\t",
});

function _isJsonSpace(c) {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function _startsAsJson(text) {
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charCodeAt(i);
    if (_isJsonSpace(c) || c === 0xfeff) continue;
    return c === 0x7b || c === 0x5b || c === 0x22;
  }
  return false;
}

function _parseJsonText(text) {
  try { return { value: safeJson.parse(text), tokens: false }; }
  catch (e) {
    if (e && e.code === "json/syntax") return null;
    return _startsAsJson(text) ? { value: undefined, tokens: true } : null;
  }
}

function _isHexCode(c) {
  return _isDigitCode(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

function _jsonStringValue(text, from, to) {
  var parts = [];
  var at = from;
  for (var i = from; i < to; i += 1) {
    if (text.charCodeAt(i) !== 0x5c || i + 1 >= to) continue;
    var e = text.charCodeAt(i + 1);
    if (e === 0x75 && i + 5 < to && _isHexCode(text.charCodeAt(i + 2)) && _isHexCode(text.charCodeAt(i + 3)) &&
        _isHexCode(text.charCodeAt(i + 4)) && _isHexCode(text.charCodeAt(i + 5))) {
      parts.push(text.slice(at, i), String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)));
      i += 5;
      at = i + 1;
    } else if (Object.prototype.hasOwnProperty.call(JSON_SIMPLE_ESCAPES, e)) {
      parts.push(text.slice(at, i), JSON_SIMPLE_ESCAPES[e]);
      i += 1;
      at = i + 1;
    }
  }
  parts.push(text.slice(at, to));
  return parts.join("");
}

function _jsonTokens(text, onLeaf) {
  var n = text.length;
  var pos = 0;
  while (pos < n) {
    var c = text.charCodeAt(pos);
    if (c === 0x22) {
      var start = pos;
      var escaped = false;
      var terminated = false;
      pos += 1;
      while (pos < n) {
        var d = text.charCodeAt(pos);
        if (d === 0x5c) { escaped = true; pos += 2; continue; }
        pos += 1;
        if (d === 0x22) { terminated = true; break; }
      }
      var end = Math.min(pos, n);
      var close = terminated ? end - 1 : end;
      var after = end;
      while (after < n && _isJsonSpace(text.charCodeAt(after))) after += 1;
      if (close > start + 1 && onLeaf({ start: start, end: end, str: true, lossy: false, dropped: true, scanIndex: -1,
        name: after < n && text.charCodeAt(after) === 0x3a,
        value: escaped ? _jsonStringValue(text, start + 1, close) : text.slice(start + 1, close) }) === false) return;
      continue;
    }
    var prev = pos > 0 ? text.charCodeAt(pos - 1) : 0x20;
    if ((c === 0x2d || _isDigitCode(c)) && !_isWordCode(prev) && prev !== 0x2e) {
      var numStart = pos;
      pos += 1;
      while (pos < n) {
        var k = text.charCodeAt(pos);
        if (!_isDigitCode(k) && k !== 0x2e && k !== 0x65 && k !== 0x45 && k !== 0x2b && k !== 0x2d) break;
        pos += 1;
      }
      var value = _wireNumber(text.slice(numStart, pos)).value;
      if (value !== null && onLeaf({ start: numStart, end: pos, str: false, lossy: false, dropped: true, scanIndex: -1,
        name: false, value: value }) === false) return;
      continue;
    }
    pos += 1;
  }
}

var CLEAN_VERDICT = Object.freeze({ verdict: "clean", hits: Object.freeze([]), redactedBody: undefined });

function _classifyJsonTokens(classifier, text, url) {
  var verdict = "clean";
  var hits = [];
  var seen = new Set();
  var spliceStart = [];
  var spliceEnd = [];
  var spliceText = [];
  var lastReplacement = null;
  var lastText = null;
  var batch = [];

  function _flush() {
    if (batch.length === 0) return;
    var v = classifier({ body: batch.map(_leafValue), headers: {}, url: url });
    var merged = _mergeWireVerdict(CLEAN_VERDICT, v, batch);
    verdict = _stricterVerdict(verdict, merged.verdict);
    for (var i = 0; i < merged.hits.length && hits.length < TOKEN_HIT_LIMIT; i += 1) {
      var h = merged.hits[i];
      var id = h && typeof h === "object" ? JSON.stringify([h.label, h.action, h.where]) : null;
      if (id !== null && seen.has(id)) continue;
      if (id !== null) seen.add(id);
      hits.push(h);
    }
    if (v.verdict === "redact") {
      var redacted = _redactedIndexes(v);
      for (var j = 0; j < batch.length; j += 1) {
        var replacement = _wireReplacement(batch[j], v, redacted);
        if (replacement === null || batch[j].name) continue;
        if (replacement !== lastReplacement) {
          lastReplacement = replacement;
          lastText = JSON.stringify(replacement);
        }
        spliceStart.push(batch[j].start);
        spliceEnd.push(batch[j].end);
        spliceText.push(lastText);
      }
    }
    batch = [];
  }

  _jsonTokens(text, function (leaf) {
    leaf.scanIndex = batch.length;
    batch.push(leaf);
    if (batch.length < TOKEN_BATCH) return true;
    _flush();
    return verdict !== "refuse";
  });
  if (verdict !== "refuse") _flush();

  return {
    verdict:      { verdict: verdict, hits: hits, redactedBody: undefined },
    redactedText: function () {
      var pieces = [];
      var parts = [];
      var at = 0;
      for (var s = 0; s < spliceStart.length; s += 1) {
        parts.push(text.slice(at, spliceStart[s]), spliceText[s]);
        at = spliceEnd[s];
        if (parts.length >= TOKEN_BATCH) { pieces.push(parts.join("")); parts = []; }
      }
      parts.push(text.slice(at));
      pieces.push(parts.join(""));
      return pieces.join("");
    },
  };
}

function _refusalVerdict(label, where) {
  return { verdict: "refuse", hits: [{ label: label, action: "refuse", where: where }], redactedBody: undefined };
}

function _isTextBody(value) {
  return typeof value === "string" || nodeTypes.isUint8Array(value);
}

function _settledBody(classified, body) {
  if (classified.verdict.verdict !== "redact") return classified;
  if (_isTextBody(body) && !_isTextBody(classified.body)) {
    return { verdict: _mergeVerdicts(classified.verdict, _refusalVerdict("classifier-bad-verdict", "classifier")),
      body: body };
  }
  return { verdict: Object.assign({}, classified.verdict, { redactedBody: classified.body }), body: classified.body };
}

function _jsonRedactedText(json) {
  try { return json.redactedText(); }
  catch (_e) { return undefined; }
}

function _classifyJsonText(classifier, text, parsedBody, headers, url) {
  var parsedVerdict = classifier({ body: parsedBody, headers: headers, url: url });
  var verdict = parsedVerdict;
  var wire = _wireOnlyValues(text);
  var wireVerdict = null;
  if (wire.scan.length > 0) {
    wireVerdict = classifier({ body: wire.scan.map(_leafValue), headers: {}, url: url });
    verdict = _mergeWireVerdict(parsedVerdict, wireVerdict, wire.scan);
  }
  return {
    verdict:      verdict,
    redactedText: function () { return _redactedJsonText(parsedBody, parsedVerdict, wire, wireVerdict); },
  };
}

function _mergeVerdicts(a, b) {
  return {
    verdict:      _stricterVerdict(a.verdict, b.verdict),
    hits:         _uniqueHits(_hitsOf(a).concat(_hitsOf(b))),
    redactedBody: a.redactedBody,
  };
}

function _asBodyOf(body, text) {
  return typeof body === "string" ? text : Buffer.from(text, "utf8");
}

function _classifyJsonAndText(classifier, body, json, asText, headers, url) {
  var verdict = _mergeVerdicts(json.verdict, asText.verdict);
  if (verdict.verdict !== "redact") return { verdict: verdict, body: body };
  if (json.verdict.verdict !== "redact") return { verdict: verdict, body: asText.body };
  var redactedText = _jsonRedactedText(json);
  if (typeof redactedText !== "string") return { verdict: verdict, body: undefined };
  var redacted = _asBodyOf(body, redactedText);
  var again = _classifyText(classifier, redacted, headers, url);
  if (again.verdict.verdict === "refuse") return { verdict: _mergeVerdicts(verdict, again.verdict), body: body };
  return { verdict: verdict, body: again.verdict.verdict === "redact" ? again.body : redacted };
}

function _classifyHttpBody(classifier, body, headers, url) {
  var asText = _classifyText(classifier, body, headers, url);
  var text = _bodyText(body);
  var parsed = text !== null ? _parseJsonText(text) : null;
  if (parsed === null) return _settledBody(asText, body);
  var json = parsed.tokens
    ? _classifyJsonTokens(classifier, text, url)
    : _classifyJsonText(classifier, text, parsed.value, headers, url);
  return _settledBody(_classifyJsonAndText(classifier, body, json, asText, headers, url), body);
}

function _multipartFileName(file) {
  if (typeof file.filename === "string" && file.filename.length > 0) return file.filename;
  if (typeof file.filePath === "string" && file.filePath.length > 0) return nodePath.basename(file.filePath);
  return undefined;
}

function _multipartView(spec) {
  var files = Array.isArray(spec.files) ? spec.files : [];
  var view = { fields: spec.fields && typeof spec.fields === "object" ? spec.fields : {}, files: [] };
  for (var i = 0; i < files.length; i += 1) {
    var file = files[i] && typeof files[i] === "object" ? files[i] : {};
    view.files.push({ field: file.field, filename: _multipartFileName(file), content: file.content });
  }
  return view;
}

function _asMultipartHit(hit) {
  if (!hit || typeof hit.where !== "string" || hit.where.indexOf("body") !== 0) return hit;
  return Object.assign({}, hit, { where: "multipart" + hit.where.slice(4) });
}

function _sameKeys(a, b) {
  var ka = Object.keys(a);
  var kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  for (var i = 0; i < ka.length; i += 1) {
    if (ka[i] !== kb[i]) return false;
  }
  return true;
}

function _redactedMultipart(spec, view, redacted) {
  if (!redacted || typeof redacted !== "object" || !redacted.fields || typeof redacted.fields !== "object" ||
      !Array.isArray(redacted.files) || redacted.files.length !== view.files.length ||
      !_sameKeys(view.fields, redacted.fields)) {
    return null;
  }
  var renamed = [];
  var files = [];
  for (var i = 0; i < view.files.length; i += 1) {
    var r = redacted.files[i];
    if (!r || typeof r !== "object") return null;
    if (r.field !== view.files[i].field) renamed.push("multipart.files[" + i + "].field");
    if (r.filename !== view.files[i].filename) renamed.push("multipart.files[" + i + "].filename");
    var original = spec.files[i];
    var copy = original && typeof original === "object" ? Object.assign({}, original) : original;
    if (view.files[i].content !== undefined && view.files[i].content !== null) {
      if (!_isTextBody(r.content)) return null;
      copy.content = r.content;
    }
    files.push(copy);
  }
  if (renamed.length > 0) return { renamed: renamed };
  var out = Object.assign({}, spec);
  if (spec.fields && typeof spec.fields === "object") out.fields = redacted.fields;
  if (Array.isArray(spec.files)) out.files = files;
  return { spec: out };
}

function _multipartReadings(classifier, spec, view, url) {
  var rounds = [];
  var decodedFiles = [];
  var refusal = null;
  var undecodable;
  for (var i = 0; i < view.files.length; i += 1) {
    var content = view.files[i].content;
    if ((!nodeTypes.isUint8Array(content) && typeof content !== "string") || content.length === 0) continue;
    var file = spec.files[i] && typeof spec.files[i] === "object" ? spec.files[i] : {};
    var type = file.contentType || file.mimeType;
    var readings = _otherReadings(content, typeof type === "string" ? { "content-type": type } : {});
    if (readings.error !== undefined) {
      var refused = _refusalVerdict("undecodable-body", "multipart.files[" + i + "].content");
      refusal = refusal === null ? refused : _mergeVerdicts(refusal, refused);
      if (undecodable === undefined) undecodable = "the content of multipart file " + i + " because " + readings.error;
      continue;
    }
    var decoded = _decodedReadings(content, readings.encodings);
    if (decoded.length > 0) decodedFiles.push(i);
    for (var r = 0; r < decoded.length; r += 1) {
      if (rounds.length <= r) {
        rounds.push(view.files.map(function (f) { return { field: f.field, filename: f.filename, content: undefined }; }));
      }
      rounds[r][i].content = decoded[r];
    }
  }
  if (refusal !== null) return { verdict: refusal, decodedFiles: decodedFiles, undecodable: undecodable };
  var verdict = null;
  for (var n = 0; n < rounds.length; n += 1) {
    var raw = classifier({ body: { fields: {}, files: rounds[n] }, headers: {}, url: url });
    var mapped = { verdict: raw.verdict, hits: _hitsOf(raw).map(_asMultipartHit), redactedBody: undefined };
    verdict = verdict === null ? mapped : _mergeVerdicts(verdict, mapped);
  }
  return { verdict: verdict === null ? null : _refusedRedactions(verdict), decodedFiles: decodedFiles };
}

function _sameText(a, b) {
  if (typeof a === "string" || typeof b === "string") return a === b;
  return Buffer.from(a.buffer, a.byteOffset, a.byteLength).equals(Buffer.from(b.buffer, b.byteOffset, b.byteLength));
}

function _classifyMultipart(classifier, spec, url) {
  var view = _multipartView(spec);
  var other = _multipartReadings(classifier, spec, view, url);
  if (other.undecodable !== undefined) return { verdict: other.verdict, spec: spec, undecodable: other.undecodable };
  var raw = classifier({ body: view, headers: {}, url: url });
  var verdict = { verdict: raw.verdict, hits: _hitsOf(raw).map(_asMultipartHit), redactedBody: undefined };
  if (other.verdict !== null) verdict = _mergeVerdicts(verdict, other.verdict);
  if (verdict.verdict !== "redact") return { verdict: verdict, spec: spec };
  var applied = _redactedMultipart(spec, view, raw.redactedBody);
  if (applied === null) {
    return { verdict: _mergeVerdicts(verdict, _refusalVerdict("classifier-bad-verdict", "classifier")), spec: spec };
  }
  if (applied.renamed) {
    var hits = verdict.hits.map(function (h) {
      if (!h || applied.renamed.indexOf(h.where) === -1 || h.action === "audit-only") return h;
      return Object.assign({}, h, { action: "refuse" });
    });
    return { verdict: { verdict: "refuse", hits: hits, redactedBody: undefined }, spec: spec };
  }
  for (var d = 0; d < other.decodedFiles.length; d += 1) {
    var at = other.decodedFiles[d];
    if (!_sameText(applied.spec.files[at].content, view.files[at].content)) {
      return { verdict: _refusedRedactions(verdict), spec: spec };
    }
  }
  return { verdict: verdict, spec: applied.spec };
}

function _classifyHttpRequest(classifier, reqOpts) {
  var main = _classifyEncodedBody(function (body) {
    return _classifyHttpBody(classifier, body, reqOpts.headers, reqOpts.url);
  }, reqOpts.body, reqOpts.headers);
  if (!reqOpts.multipart || typeof reqOpts.multipart !== "object") {
    return { verdict: main.verdict, body: main.body, multipart: undefined, undecodable: main.undecodable };
  }
  var mp = _classifyMultipart(classifier, reqOpts.multipart, reqOpts.url);
  return { verdict: _mergeVerdicts(main.verdict, mp.verdict), body: main.body, multipart: mp.spec,
    undecodable: main.undecodable !== undefined ? main.undecodable : mp.undecodable };
}

function _classifyWebhookBody(classifier, body, headers, url) {
  var parsed = typeof body === "string" ? _parseJsonText(body) : null;
  if (parsed === null) return _settledBody(_classifyText(classifier, body, headers, url), body);
  if (parsed.tokens) {
    return _settledBody(_classifyJsonAndText(classifier, body, _classifyJsonTokens(classifier, body, url),
      _classifyText(classifier, body, headers, url), headers, url), body);
  }
  var json = _classifyJsonText(classifier, body, parsed.value, headers, url);
  if (json.verdict.verdict !== "redact") return { verdict: json.verdict, body: body };
  var text = _jsonRedactedText(json);
  if (typeof text !== "string") {
    return { verdict: _mergeVerdicts(json.verdict, _refusalVerdict("classifier-bad-verdict", "classifier")), body: body };
  }
  return { verdict: json.verdict, body: text };
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
    var classified;
    try {
      classified = _classifyEncodedBody(function (body) {
        return _classifyWebhookBody(classifier, body, input.headers || {}, input.url);
      }, input.body, input.headers);
    } catch (e) { return Promise.reject(e); }
    var verdict = classified.verdict;
    _runHook(opts.onScan, { primitive: "webhook", verdict: verdict, input: input });
    if (verdict.verdict === "refuse") {
      _emitDlp("dlp.outbound.refused", "denied", {
        primitive: "webhook",
        url:       input.url || null,
        hits:      verdict.hits.map(_summarizeHit),
      });
      _runHook(opts.onRefuse, { primitive: "webhook", verdict: verdict, input: input });
      if (classified.undecodable !== undefined) {
        return Promise.reject(new DlpError("redact-dlp/undecodable-body",
          "outbound webhook.send refused: the DLP scan cannot decode " + classified.undecodable));
      }
      return Promise.reject(new DlpError("redact-dlp/refused",
        "outbound webhook.send refused by DLP classifier; hits: " +
        verdict.hits.map(function (h) { return h.label; }).join(", ")));
    }
    if (verdict.verdict === "redact") {
      var newInput = {
        url:     input.url,
        body:    classified.body,
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

/**
 * @primitive b.redact.installForPosture
 * @signature b.redact.installForPosture(posture, primitives)
 * @since     0.7.46
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, fapi2
 * @related   b.redact.installOutboundDlp, b.redact.classifyDefaults
 *
 * Posture-coordinated install — picks the default classifier for
 * `posture` and wraps the operator-supplied `primitives.httpClient` /
 * `.mail` / `.webhook` so every outbound payload runs through it. A
 * thin convenience over `installOutboundDlp`; direct callers usually
 * want `installOutboundDlp` because it accepts the full hook surface.
 *
 * The operator MUST call this with the primitive instances — pinning a
 * posture via `b.compliance.set` does NOT auto-install outbound DLP,
 * because the compliance coordinator holds no httpClient / mail /
 * webhook handles. When a posture whose floor implies outbound DLP
 * (hipaa / pci-dss / gdpr / soc2 / fapi-2.0) is pinned without this
 * call, `b.compliance.set` emits a one-time
 * `compliance.posture.outbound_dlp_unwired` audit warning so the gap is
 * grep-able in the audit chain.
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

var TEXT_REDACT_MARKER = "[redacted]";

/**
 * @primitive b.redact.redactText
 * @signature b.redact.redactText(str)
 * @since     0.17.13
 * @status    stable
 * @related   b.redact.redact
 *
 * Scrub credentials EMBEDDED in a free-text string in place, keeping the
 * surrounding prose — for log messages and other operator-facing text where a
 * secret may be interpolated mid-sentence. Unlike `redact` (structured,
 * whole-value, anchored), this uses word-boundary fragment replacement so
 * "login failed: &lt;jwt&gt; for bob" keeps everything but the jwt. Detects PEM
 * blocks, JWTs, AWS access keys, vault-sealed ciphertext, URL-userinfo passwords
 * (including empty-username forms), bearer tokens, `key=secret` assignments,
 * SSN/EIN, and Luhn-valid PANs. The high-entropy
 * api-key-shape detector is deliberately excluded (on free text it eats
 * ordinary IDs / hashes / base64). Drop-safe: never throws (it runs on the
 * hot-path log-emit sink); on any error it returns a fully-masked marker rather
 * than the raw input. Every quantifier is length-capped (ReDoS backstop).
 *
 * @example
 *   b.redact.redactText("token=AKIAIOSFODNN7EXAMPLE ok");  // → "token=[redacted] ok"
 */
function redactText(str) {
  if (typeof str !== "string" || str.length === 0) return str;
  try {
    return _replaceCards(str
      .replace(/-----BEGIN [A-Z0-9 ]{1,40}-----[\s\S]{0,8192}?-----END [A-Z0-9 ]{1,40}-----/g, TEXT_REDACT_MARKER)
      .replace(/\beyJ[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,4096}\b/g, TEXT_REDACT_MARKER)
      .replace(/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g, TEXT_REDACT_MARKER)
      .replace(/\bvault:[A-Za-z0-9+/=_.:-]{3,8192}/g, TEXT_REDACT_MARKER)
      .replace(/([a-z][a-z0-9+.-]{0,32}:\/\/[^\s:@/]{0,256}:)[^\s@/]{1,256}(@)/gi, "$1" + TEXT_REDACT_MARKER + "$2")
      .replace(/\b([Bb]earer\s{1,4})[A-Za-z0-9._~+/-]{8,4096}=*/g, "$1" + TEXT_REDACT_MARKER)
      .replace(/\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|password|passwd|pwd|token)["']?\s{0,4}[=:]\s{0,4}["']?)[^\s&;"']{6,4096}/gi, "$1" + TEXT_REDACT_MARKER)
      .replace(/\b\d{3}-\d{2}-\d{4}\b/g, TEXT_REDACT_MARKER)
      .replace(/\b\d{2}-\d{7}\b/g, TEXT_REDACT_MARKER), TEXT_REDACT_MARKER);
  // unreachable drop-silent: the replace chain runs on a guaranteed string with static regexes
  /* c8 ignore next 3 */
  } catch (_e) {
    return TEXT_REDACT_MARKER;
  }
}

module.exports = {
  redact:                redact,
  redactText:            redactText,
  registerFieldRule:     registerFieldRule,
  registerValueDetector: registerValueDetector,
  classifyDefaults:      classifyDefaults,
  installOutboundDlp:    installOutboundDlp,
  installForPosture:     installForPosture,
  isOutboundDlpInstalled: isOutboundDlpInstalled,
  CLASSIFIER_PATTERNS:   CLASSIFIER_PATTERNS,
  MARKER:                DEFAULT_MARKER,
  SENSITIVE_FIELDS:      SENSITIVE_FIELDS,
  DlpError:              DlpError,
  _resetForTest:         _resetForTest,
};
