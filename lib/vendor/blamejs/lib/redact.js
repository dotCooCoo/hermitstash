"use strict";
/**
 * Operational-log redaction layer.
 *
 * Wraps every operational log emit so PHI / PCI / personal data never
 * reaches a debug sink, file, or external SIEM. Two complementary signals:
 *
 *   1. Field-name allow/deny: known sensitive fields are scrubbed by name
 *      regardless of the value's contents.
 *   2. Pattern detection: even if a field name slips past, common-shape
 *      detectors (credit-card via Luhn, JWT, PEM blocks, AWS-key-shape)
 *      catch the value and replace with a marker.
 *
 * The redactor returns a NEW object — the original log payload is never
 * mutated. This matters because the same object may be passed to the
 * audit-log path (which DOES seal sensitive content via vault) AND the
 * operational path (which redacts) in the same call.
 *
 * Public API:
 *   redact.redact(value, opts?)              → redacted value
 *   redact.registerFieldRule(pattern, replacement)
 *   redact.registerValueDetector(name, fn, replacement)
 *   redact.MARKER                            → '[REDACTED]'
 */

var C = require("./constants");

var DEFAULT_MARKER = "[REDACTED]";

// Field names that are always redacted, regardless of value contents.
// Match is case-insensitive and includes substring (so 'userPassword' matches).
var SENSITIVE_FIELDS = [
  "password", "passwd", "secret", "token", "apikey", "api_key",
  "authorization", "auth", "ssn", "creditcard", "credit_card",
  "card_number", "cardnumber", "cvc", "cvv", "pin",
  "privatekey", "private_key", "passphrase", "session", "sid",
  "_authtoken", "auth_token", "bearer", "cookie",
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

function registerFieldRule(name, replacement) {
  void replacement; // marker not used here; redact replaces with marker
  if (typeof name === "string") {
    sensitiveFieldsSet.add(name.toLowerCase());
    return;
  }
  throw new Error("registerFieldRule expects a string field name");
}

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
    if (allDetectors[i].test(value)) return allDetectors[i].replacement;
  }
  return value;
}

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

module.exports = {
  redact:                redact,
  registerFieldRule:     registerFieldRule,
  registerValueDetector: registerValueDetector,
  MARKER:                DEFAULT_MARKER,
  SENSITIVE_FIELDS:      SENSITIVE_FIELDS,
  _resetForTest:         _resetForTest,
};
