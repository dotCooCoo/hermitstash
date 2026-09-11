// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardUuid
 * @nav    Guards
 * @title  Guard Uuid
 *
 * @intro
 *   UUID identifier-safety guard. Validates user-supplied UUID
 *   strings per RFC 9562 (May 2024 — obsoletes RFC 4122) and
 *   refuses non-RFC shapes that downstream parsers routinely
 *   misinterpret. KIND="identifier" — the gate consumes
 *   `ctx.identifier` (or `ctx.uuid`).
 *
 *   Threat catalog: wrong length / shape (canonical 36-char
 *   hyphenated, 32-char hyphenless, 38-char braced, or
 *   `urn:uuid:` prefixed — anything else is malformed); wrong
 *   character class (non-hex anywhere); invalid version field
 *   (RFC 9562 §4.2 defines 1-8; 0 and 9-F are reserved /
 *   unassigned and indicate hand-rolled or attacker-shaped IDs);
 *   variant bits (RFC 9562 §4.1 — only 10xx is the canonical
 *   variant; NCS-reserved 0xxx, Microsoft 110x, future 111x often
 *   indicate non-UUID payloads coerced into the slot); nil UUID
 *   (§5.9 all zeros — usually "no UUID set", masks missing-key
 *   bugs when passed through); max UUID (§5.10 all FF — sentinel
 *   with the same semantic risk as nil); `urn:uuid:` prefix
 *   smuggling; Microsoft GUID braces `{...}` smuggling;
 *   BIDI / zero-width / C0-control / null-byte universal-refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   UUID identifier-safety guard.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { GuardUuidError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var UUID_GROUP_LENGTHS = [8, 4, 4, 4, 12];
var UUID_HEX_LENGTH = 32;
var URN_PREFIX = "urn:uuid:";

var NIL_HEX = "00000000000000000000000000000000";
var MAX_HEX = "ffffffffffffffffffffffffffffffff";

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "hyphenated-only",
    versionPolicy:     "reject-unassigned",
    variantPolicy:     "reject-non-rfc",
    nilPolicy:         "reject",
    maxPolicy:         "reject",
    urnPolicy:         "reject",
    bracedPolicy:      "reject",
    allowedVersions:   [1, 2, 3, 4, 5, 6, 7, 8],
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "any",
    versionPolicy:     "reject-unassigned",
    variantPolicy:     "audit",
    nilPolicy:         "audit",
    maxPolicy:         "audit",
    urnPolicy:         "audit",
    bracedPolicy:      "audit",
    allowedVersions:   [1, 2, 3, 4, 5, 6, 7, 8],
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "any",
    versionPolicy:     "audit",
    variantPolicy:     "allow",
    nilPolicy:         "allow",
    maxPolicy:         "allow",
    urnPolicy:         "allow",
    bracedPolicy:      "allow",
    allowedVersions:   null,
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 128 });

function _isHexDigit(cc) {
  return codepointClass.isAsciiDigit(cc) ||
         (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}

function _isHexRun(s, at, n) {
  if (at + n > s.length) return false;
  for (var i = at; i < at + n; i += 1) {
    if (!_isHexDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

function _isHyphenatedAt(s, at, end) {
  var i = at;
  for (var g = 0; g < UUID_GROUP_LENGTHS.length; g += 1) {
    if (!_isHexRun(s, i, UUID_GROUP_LENGTHS[g])) return false;
    i += UUID_GROUP_LENGTHS[g];
    if (g < UUID_GROUP_LENGTHS.length - 1) {
      if (s.charAt(i) !== "-") return false;
      i += 1;
    }
  }
  return i === end;
}

function _isHyphenless(s) {
  return s.length === UUID_HEX_LENGTH && _isHexRun(s, 0, UUID_HEX_LENGTH);
}

function _classifyForm(input) {
  if (codepointClass.containsFolded(input.slice(0, URN_PREFIX.length), URN_PREFIX) &&
      _isHyphenatedAt(input, URN_PREFIX.length, input.length)) return "urn";
  if (input.charAt(0) === "{" && input.charAt(input.length - 1) === "}" &&
      _isHyphenatedAt(input, 1, input.length - 1)) return "braced";
  if (_isHyphenatedAt(input, 0, input.length)) return "hyphenated";
  if (_isHyphenless(input)) return "hyphenless";
  return null;
}

function _toCanonicalHex(input, form) {
  var s = input.toLowerCase();
  if (form === "urn")     s = s.slice(URN_PREFIX.length);
  if (form === "braced")  s = s.slice(1, -1);
  return codepointClass.replaceAny(s, "-", "");
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "uuid", cap: { bytes: opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var form = _classifyForm(input);
  if (form === null) {
    issues.push({
      kind: "uuid-shape", severity: "high",
      ruleId: "uuid.uuid-shape",
      snippet: "input does not match any RFC 9562 UUID form " +
               "(hyphenated / hyphenless / braced / urn:uuid:)",
    });
    return issues;
  }

  var formatPolicy = opts.formatPolicy;
  var formAllowed = (
    formatPolicy === "any" ||
    formatPolicy === form ||
    (formatPolicy === "hyphenated-only" && form === "hyphenated")
  );
  if (!formAllowed) {
    issues.push({
      kind: "uuid-form-disallowed",
      severity: "high",
      ruleId: "uuid.uuid-form-disallowed",
      snippet: "uuid form `" + form + "` not permitted by formatPolicy `" +
               formatPolicy + "`",
    });
  }
  if (form === "urn" && opts.urnPolicy !== "allow") {
    issues.push({
      kind: "urn-prefix",
      severity: opts.urnPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.urn-prefix",
      snippet: "uuid carries `urn:uuid:` prefix — would be processed " +
               "by URN-shape parsers downstream",
    });
  }
  if (form === "braced" && opts.bracedPolicy !== "allow") {
    issues.push({
      kind: "braced",
      severity: opts.bracedPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.braced",
      snippet: "uuid uses Microsoft GUID braces `{...}` — non-canonical",
    });
  }

  var hex = _toCanonicalHex(input, form);

  if (hex === NIL_HEX && opts.nilPolicy !== "allow") {
    issues.push({
      kind: "nil-uuid",
      severity: opts.nilPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.nil-uuid",
      snippet: "uuid is the nil UUID (RFC 9562 §5.9) — sentinel often " +
               "indicates missing-key bug",
    });
  }
  if (hex === MAX_HEX && opts.maxPolicy !== "allow") {
    issues.push({
      kind: "max-uuid",
      severity: opts.maxPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.max-uuid",
      snippet: "uuid is the max UUID (RFC 9562 §5.10) — sentinel often " +
               "indicates missing-key bug",
    });
  }

  if (hex !== NIL_HEX && hex !== MAX_HEX) {
    var versionDigit = parseInt(hex.charAt(12), 16);
    var variantNibble = parseInt(hex.charAt(16), 16);

    if (opts.versionPolicy !== "allow") {
      var allowed = opts.allowedVersions;
      var versionOk = !allowed || allowed.indexOf(versionDigit) !== -1;
      if (!versionOk) {
        issues.push({
          kind: "version-unassigned",
          severity: opts.versionPolicy === "reject-unassigned" ? "high" : "warn",
          ruleId: "uuid.version-unassigned",
          snippet: "uuid version digit " + versionDigit + " not in " +
                   "allowedVersions " + JSON.stringify(allowed) +
                   " (RFC 9562 §4.2 defines 1-8)",
        });
      }
    }

    if (opts.variantPolicy !== "allow") {
      var isRfcVariant = (variantNibble & 0xC) === 0x8;
      if (!isRfcVariant) {
        issues.push({
          kind: "variant-non-rfc",
          severity: opts.variantPolicy === "reject-non-rfc" ? "high" : "warn",
          ruleId: "uuid.variant-non-rfc",
          snippet: "uuid variant nibble `" + hex.charAt(16) + "` is not " +
                   "the RFC 9562 §4.1 variant (10xx — nibble 8-b)",
        });
      }
    }
  }

  return issues;
}

/**
 * @primitive  b.guardUuid.validate
 * @signature  b.guardUuid.validate(input, opts?)
 * @since      0.7.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardUuid.sanitize, b.guardUuid.gate, b.uuid.v4, b.uuid.v7
 *
 * Inspect a UUID string against the resolved profile and return
 * `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `uuid.bad-input` issue rather
 * than throwing — callers that prefer an exception use
 * `b.guardUuid.sanitize`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"audit"|"allow",
 *   formatPolicy:           "hyphenated"|"hyphenless"|"braced"|"urn"|"hyphenated-only"|"any",
 *   versionPolicy:          "reject-unassigned"|"audit"|"allow",
 *   variantPolicy:          "reject-non-rfc"|"audit"|"allow",
 *   nilPolicy:              "reject"|"audit"|"allow",
 *   maxPolicy:              "reject"|"audit"|"allow",
 *   urnPolicy:              "reject"|"audit"|"allow",
 *   maxBytes:               number,
 *
 * @example
 *   var rv = b.guardUuid.validate("550e8400-e29b-41d4-a716-446655440000",
 *                                 { profile: "strict" });
 *   rv.ok;                                             // → true
 *
 *   var bad = b.guardUuid.validate("00000000-0000-0000-0000-000000000000",
 *                                  { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].ruleId;                              // → "uuid.nil-uuid"
 */

/**
 * @primitive  b.guardUuid.sanitize
 * @signature  b.guardUuid.sanitize(input, opts?)
 * @since      0.7.44
 * @status     stable
 * @related    b.guardUuid.validate, b.guardUuid.gate
 *
 * Normalize a UUID to canonical hyphenated lowercase form. Strips
 * Microsoft GUID braces `{...}` and the `urn:uuid:` prefix. Throws
 * `GuardUuidError` when any `critical` or `high` issue fires
 * (nil / max sentinel under reject, unassigned version, non-RFC
 * variant). Use `validate` to inspect issues without throwing.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardUuid.validate opts,
 *
 * @example
 *   var safe = b.guardUuid.sanitize("urn:uuid:550E8400-E29B-41D4-A716-446655440000",
 *                                   { profile: "balanced" });
 *   safe;                                              // → "550e8400-e29b-41d4-a716-446655440000"
 *
 *   try {
 *     b.guardUuid.sanitize("ffffffff-ffff-ffff-ffff-ffffffffffff",
 *                          { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "uuid.max-uuid"
 *   }
 */
function _sanitizeTransform(input) {
  var form = _classifyForm(input);
  if (!form) return input;
  var hex = _toCanonicalHex(input, form);
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" +
         hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" +
         hex.slice(20);
}

var INTEGRATION_FIXTURES = gateContract.identifierFixtures("550e8400-e29b-41d4-a716-446655440000", "00000000-0000-0000-0000-000000000000");

var POLICY_ENUM = gateContract.policyVocabulary([
  "nilPolicy", "maxPolicy", "urnPolicy", "bracedPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  formatPolicy:  ["hyphenated", "hyphenless", "braced", "urn", "hyphenated-only", "any"],
  versionPolicy: ["reject-unassigned", "audit", "audit-only", "allow"],
  variantPolicy: ["reject-non-rfc", "audit", "audit-only", "allow"],
});

module.exports = gateContract.defineGuard({
  name:        "uuid",
  kind:        "identifier",
  errorClass:  GuardUuidError,
  enumOpts:    POLICY_ENUM,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes"],
  ctxFields:   ["identifier", "uuid"],
  extra: {
    _classifyFormForTest: _classifyForm,
  },
});
