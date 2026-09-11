// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardCountry
 * @nav    Guards
 * @title  Guard Country
 *
 * @intro
 *   ISO 3166-1 alpha-2 country-code guard. Accepts the 249
 *   officially assigned codes and refuses everything else, from a
 *   bundled table. KIND="identifier" - the gate consumes
 *   `ctx.identifier` (or `ctx.country` / `ctx.countryCode`).
 *
 *   The framework already routes on these codes: compliance
 *   postures are keyed by jurisdiction, and data-residency, tax
 *   nexus, geo-restriction and DSR-jurisdiction decisions all turn
 *   on one. A two-letter string that looks like a country but is
 *   not one produces a wrong answer at every one of those, wearing
 *   the shape of a right one.
 *
 *   Threat catalog: not-a-code (`UK` - the United Kingdom is `GB`);
 *   user-assigned codes (`AA`, `QM`-`QZ`, `XA`-`XZ`, `ZZ`, which
 *   includes CLDR's unknown-region sentinel and `XK` for Kosovo);
 *   exceptionally reserved codes (`EU`, `EZ`, `UN`, `AC`, `CP`,
 *   `CQ`, `DG`, `EA`, `IC`, `TA`) that name unions, organizations
 *   and territories rather than countries; formerly used codes
 *   (`AN`, `BU`, `CS`, `DD`, `FX`, `NT`, `SU`, `TP`, `YD`, `YU`,
 *   `ZR`) that a legacy dataset still carries; BIDI / zero-width /
 *   C0-control / null-byte universal-refuse; and homoglyph or
 *   fullwidth spellings that render as a valid code.
 *
 *   The answer comes from the bundled table and never from `Intl`.
 *   A `small-icu` or `no-icu` Node build has no
 *   `Intl.DisplayNames`, so the widespread hand-rolled version -
 *   which asks `DisplayNames` whether a code echoes back and
 *   returns true from its `catch` - accepts every two-letter string
 *   on those runtimes. That is a deployment-shaped behavior change
 *   with no signal.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   ISO 3166-1 alpha-2 country-code guard, answered from a bundled table.
 */

var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { GuardCountryError } = require("./framework-error");

void GuardCountryError;

var ASSIGNED_CODES = Object.freeze([
  "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT",
  "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
  "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
  "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
  "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
  "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK",
  "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
  "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
  "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR",
  "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
  "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
  "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
  "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
  "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
  "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
  "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
  "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
  "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF",
  "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW",
  "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
  "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
]);

var ASSIGNED = new Set(ASSIGNED_CODES);

var EXCEPTIONALLY_RESERVED = Object.freeze({
  AC: "Ascension Island",
  CP: "Clipperton Island",
  CQ: "Sark",
  DG: "Diego Garcia",
  EA: "Ceuta and Melilla",
  EU: "European Union",
  EZ: "Eurozone",
  IC: "Canary Islands",
  TA: "Tristan da Cunha",
  UN: "United Nations",
});

var FORMERLY_USED = Object.freeze({
  AN: null,
  BU: "MM",
  CS: null,
  DD: "DE",
  FX: "FR",
  NT: null,
  SU: null,
  TP: "TL",
  YD: "YE",
  YU: null,
  ZR: "CD",
});

var COMMON_MISTAKES = Object.freeze({ UK: "GB" });

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    reservedPolicy:     "reject",
    userAssignedPolicy: "reject",
    formerlyUsedPolicy: "reject",
    maxBytes:           C.BYTES.bytes(16),
    maxRuntimeMs:       C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    reservedPolicy:     "reject",
    userAssignedPolicy: "reject",
    formerlyUsedPolicy: "audit",
    maxBytes:           C.BYTES.bytes(16),
    maxRuntimeMs:       C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    reservedPolicy:     "audit",
    userAssignedPolicy: "audit",
    formerlyUsedPolicy: "audit",
    maxBytes:           C.BYTES.bytes(16),
    maxRuntimeMs:       C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 32 });

function _isUserAssigned(code) {
  if (code === "AA" || code === "ZZ") return true;
  var first = code.charCodeAt(0);
  var second = code.charCodeAt(1);
  if (first === 0x51 && second >= 0x4D && second <= 0x5A) return true;
  if (first === 0x58) return true;
  return false;
}

function _isTwoAsciiLetters(input) {
  if (input.length !== 2) return false;
  for (var i = 0; i < 2; i += 1) {
    if (!codepointClass.isAsciiLetter(input.charCodeAt(i))) return false;
  }
  return true;
}

function _upper(input) {
  var out = "";
  for (var i = 0; i < input.length; i += 1) {
    var cc = input.charCodeAt(i);
    out += (cc >= 0x61 && cc <= 0x7A) ? String.fromCharCode(cc - 32) : input.charAt(i);
  }
  return out;
}

var POLICY_VALUES = ["reject", "audit", "allow"];

var POLICY_ENUM = {
  reservedPolicy:     POLICY_VALUES,
  userAssignedPolicy: POLICY_VALUES,
  formerlyUsedPolicy: POLICY_VALUES,
};

function _severity(policy) { return policy === "reject" ? "high" : "warn"; }

function _allowed(policy) { return policy === "allow"; }

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, {
    name: "country", cap: { bytes: opts.maxBytes },
  });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  if (!_isTwoAsciiLetters(input)) {
    issues.push({
      kind: "country-shape", severity: "high",
      ruleId: "country.country-shape",
      snippet: "input is not two ASCII letters, so it cannot be an " +
               "ISO 3166-1 alpha-2 code",
    });
    return issues;
  }

  var code = _upper(input);
  if (ASSIGNED.has(code)) return issues;

  if (Object.prototype.hasOwnProperty.call(COMMON_MISTAKES, code)) {
    issues.push({
      kind: "country-not-assigned", severity: "high",
      ruleId: "country.country-not-assigned",
      snippet: "`" + code + "` is not an ISO 3166-1 alpha-2 code; the code " +
               "for that country is `" + COMMON_MISTAKES[code] + "`",
    });
    return issues;
  }

  if (_isUserAssigned(code)) {
    if (_allowed(opts.userAssignedPolicy)) return issues;
    issues.push({
      kind: "country-user-assigned", severity: _severity(opts.userAssignedPolicy),
      ruleId: "country.country-user-assigned",
      snippet: "`" + code + "` is in an ISO 3166-1 user-assigned range " +
               "(AA, QM-QZ, XA-XZ, ZZ) - reserved for private use, so it " +
               "means whatever the system that wrote it decided",
    });
    return issues;
  }

  if (Object.prototype.hasOwnProperty.call(EXCEPTIONALLY_RESERVED, code)) {
    if (_allowed(opts.reservedPolicy)) return issues;
    issues.push({
      kind: "country-exceptionally-reserved", severity: _severity(opts.reservedPolicy),
      ruleId: "country.country-exceptionally-reserved",
      snippet: "`" + code + "` is exceptionally reserved for " +
               EXCEPTIONALLY_RESERVED[code] + ", which is not a country",
    });
    return issues;
  }

  if (Object.prototype.hasOwnProperty.call(FORMERLY_USED, code)) {
    if (_allowed(opts.formerlyUsedPolicy)) return issues;
    var successor = FORMERLY_USED[code];
    issues.push({
      kind: "country-formerly-used", severity: _severity(opts.formerlyUsedPolicy),
      ruleId: "country.country-formerly-used",
      snippet: "`" + code + "` is a formerly used code, withdrawn from " +
               "ISO 3166-1" + (successor
                 ? "; the registry records it as replaced by `" + successor + "`"
                 : "; no single successor is recorded"),
    });
    return issues;
  }

  issues.push({
    kind: "country-not-assigned", severity: "high",
    ruleId: "country.country-not-assigned",
    snippet: "`" + code + "` is not an officially assigned ISO 3166-1 " +
             "alpha-2 code",
  });
  return issues;
}

/**
 * @primitive  b.guardCountry.validate
 * @signature  b.guardCountry.validate(input, opts?)
 * @since      0.18.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCountry.sanitize, b.guardCountry.isValid, b.guardCountry.gate
 *
 * Inspect a country code against the resolved profile and return
 * `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `country.bad-input` issue
 * rather than throwing - callers that prefer an exception use
 * `b.guardCountry.sanitize`.
 *
 * Issue kinds name only what a record can be pointed at:
 * `country-user-assigned`, `country-exceptionally-reserved`,
 * `country-formerly-used`, and `country-not-assigned` for anything
 * else well-formed. There is deliberately no "unassigned" kind -
 * ISO reserves codes this table has no source for, so the stronger
 * claim would be unsupported.
 *
 * @opts
 *   profile:            "strict"|"balanced"|"permissive",
 *   compliancePosture:  "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:         "reject"|"audit"|"allow",
 *   controlPolicy:      "reject"|"audit"|"allow",
 *   nullBytePolicy:     "reject"|"audit"|"allow",
 *   zeroWidthPolicy:    "reject"|"audit"|"allow",
 *   reservedPolicy:     "reject"|"audit"|"allow",
 *   userAssignedPolicy: "reject"|"audit"|"allow",
 *   formerlyUsedPolicy: "reject"|"audit"|"allow",
 *   maxBytes:           number,
 *
 * @example
 *   b.guardCountry.validate("GB", { profile: "strict" }).ok;   // -> true
 *
 *   var uk = b.guardCountry.validate("UK", { profile: "strict" });
 *   uk.ok;                    // -> false
 *   uk.issues[0].ruleId;      // -> "country.country-not-assigned"
 */

/**
 * @primitive  b.guardCountry.sanitize
 * @signature  b.guardCountry.sanitize(input, opts?)
 * @since      0.18.44
 * @status     stable
 * @related    b.guardCountry.validate, b.guardCountry.isValid
 *
 * Normalize a country code to its canonical uppercase form and
 * return it. Throws `GuardCountryError` when any `critical` or
 * `high` issue fires - a malformed shape, or a code the resolved
 * profile refuses. Use `validate` to inspect issues without
 * throwing.
 *
 * @opts
 *   profile:            "strict"|"balanced"|"permissive",
 *   compliancePosture:  "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                same shape as b.guardCountry.validate opts,
 *
 * @example
 *   b.guardCountry.sanitize("gb", { profile: "strict" });   // -> "GB"
 *
 *   try {
 *     b.guardCountry.sanitize("ZZ", { profile: "strict" });
 *   } catch (e) {
 *     e.code;   // -> "country.country-user-assigned"
 *   }
 */
function _sanitizeTransform(input) {
  return _upper(input);
}

/**
 * @primitive  b.guardCountry.isValid
 * @signature  b.guardCountry.isValid(input)
 * @since      0.18.44
 * @status     stable
 * @related    b.guardCountry.validate, b.guardCountry.sanitize
 *
 * Whether `input` is an officially assigned ISO 3166-1 alpha-2
 * code, as a boolean. Case-insensitive; never throws, so a
 * non-string is `false` rather than an exception.
 *
 * Takes NO profile, deliberately. The profiles differ in how they
 * DISPOSE of a non-assigned code — `strict` refuses it, `balanced`
 * and `permissive` downgrade some findings to a warning — and none
 * of them changes whether ISO assigned the code. A predicate that
 * accepted a profile would answer `true` for `EU`, `ZZ` or `SU`
 * under `permissive`, which is exactly the reserved-and-sentinel
 * value a residency or jurisdiction decision must never act on.
 *
 * Reach for `validate(input, { profile })` when the
 * profile-dependent disposition is what you want, and for the
 * reason a code was refused.
 *
 * @example
 *   b.guardCountry.isValid("gb");   // -> true
 *   b.guardCountry.isValid("UK");   // -> false
 *   b.guardCountry.isValid("ZZ");   // -> false
 *   b.guardCountry.isValid(null);   // -> false
 */
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("GB", "ZZ");

module.exports = gateContract.defineGuard({
  name:        "country",
  kind:        "identifier",
  errorClass:  GuardCountryError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes"],
  enumOpts:          POLICY_ENUM,
  ctxFields:   ["identifier", "country", "countryCode"],
  extra: {
    ASSIGNED_CODES: ASSIGNED_CODES,
    isValid: function isValid(input) {
      if (typeof input !== "string" || !_isTwoAsciiLetters(input)) return false;
      return ASSIGNED.has(_upper(input));
    },
  },
});
