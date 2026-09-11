// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardTime
 * @nav    Guards
 * @title  Guard Time
 *
 * @intro
 *   ISO 8601 / RFC 3339 datetime identifier-safety guard. Validates
 *   user-supplied datetime strings destined for audit timestamps,
 *   scheduling, retention windows, query ranges, and cross-system
 *   event correlation. KIND="identifier" — the gate consumes
 *   `ctx.identifier` / `ctx.timestamp` / `ctx.time`.
 *
 *   Threat catalog: shape malformation (not RFC 3339 datetime
 *   grammar); pre-epoch / far-future (year before 1970 or after
 *   the operator's ceiling, default 9999 — often a parsing bug or
 *   sentinel-leak shape); naive datetime with no offset (strict
 *   refuses — downstream interpretation depends on local timezone,
 *   breaks cross-region equality); non-UTC offset (strict accepts
 *   only `Z` / `+00:00`; balanced accepts any offset; permissive
 *   allows naive too); leap-second `60` in seconds field (RFC 3339
 *   §5.6 explicitly valid, most parsers panic — flagged-by-default
 *   with operator policy); excessive fractional precision (cap at
 *   9 digits = nanosecond floor); date-only / time-only refused for
 *   full-datetime contexts; BIDI / zero-width / C0-control /
 *   null-byte universal-refuse.
 *
 *   Far-future / pre-epoch refusal is critical-severity by default:
 *   year-2038 wrap shapes, Y10K sentinels, and `0000-01-01` poison
 *   pills routinely leak through downstream parsers as silent
 *   `NaN` / `0` rows; the guard refuses at the boundary instead.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   ISO 8601 / RFC 3339 datetime identifier-safety guard.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var time = require("./time");
var C = require("./constants");
var { GuardTimeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var DEFAULT_MIN_YEAR = 1970;
var DEFAULT_MAX_YEAR = 9999;
var MAX_FRACTIONAL_DIGITS = 9;

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    naiveDatetimePolicy:       "reject",
    nonUtcOffsetPolicy:        "reject",
    leapSecondPolicy:          "reject",
    fractionalDigitsPolicy:    "reject",
    dateOnlyPolicy:            "reject",
    timeOnlyPolicy:            "reject",
    minYear:                   DEFAULT_MIN_YEAR,
    maxYear:                   DEFAULT_MAX_YEAR,
    maxFractionalDigits:       MAX_FRACTIONAL_DIGITS,
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    naiveDatetimePolicy:       "reject",
    nonUtcOffsetPolicy:        "audit",
    leapSecondPolicy:          "audit",
    fractionalDigitsPolicy:    "audit",
    dateOnlyPolicy:            "audit",
    timeOnlyPolicy:            "audit",
    minYear:                   DEFAULT_MIN_YEAR,
    maxYear:                   DEFAULT_MAX_YEAR,
    maxFractionalDigits:       MAX_FRACTIONAL_DIGITS,
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    naiveDatetimePolicy:       "audit",
    nonUtcOffsetPolicy:        "allow",
    leapSecondPolicy:          "allow",
    fractionalDigitsPolicy:    "allow",
    dateOnlyPolicy:            "allow",
    timeOnlyPolicy:            "allow",
    minYear:                   DEFAULT_MIN_YEAR,
    maxYear:                   DEFAULT_MAX_YEAR,
    maxFractionalDigits:       MAX_FRACTIONAL_DIGITS,
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 128 });

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "time", cap: { bytes: opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var dateOnly = time.readDate(input, 0);
  if (dateOnly !== null && dateOnly.end === input.length) {
    if (opts.dateOnlyPolicy !== "allow") {
      issues.push({
        kind: "date-only",
        severity: opts.dateOnlyPolicy === "reject" ? "high" : "warn",
        ruleId: "time.date-only",
        snippet: "input is RFC 3339 full-date only — full datetime " +
                 "(date + time + offset) required",
      });
      return issues;
    }
  }
  var timeOnly = time.readTime(input, 0);
  if (timeOnly !== null && timeOnly.end === input.length) {
    if (opts.timeOnlyPolicy !== "allow") {
      issues.push({
        kind: "time-only",
        severity: opts.timeOnlyPolicy === "reject" ? "high" : "warn",
        ruleId: "time.time-only",
        snippet: "input is RFC 3339 partial-time only — full datetime " +
                 "(date + time + offset) required",
      });
      return issues;
    }
  }

  var match = time.readDateTime(input);
  if (match === null) {
    issues.push({
      kind: "datetime-shape", severity: "high",
      ruleId: "time.datetime-shape",
      snippet: "input does not match RFC 3339 §5.6 date-time grammar",
    });
    return issues;
  }

  var year = parseInt(match.year, 10);
  var month = parseInt(match.month, 10);
  var day = parseInt(match.day, 10);
  var hour = parseInt(match.hour, 10);
  var minute = parseInt(match.minute, 10);
  var second = parseInt(match.second, 10);
  var fractional = match.fraction;
  var offset = match.offset === "" ? undefined : match.offset;

  if (year < opts.minYear || year > opts.maxYear) {
    issues.push({
      kind: "year-window", severity: "high",
      ruleId: "time.year-window",
      snippet: "year " + year + " outside operator window [" +
               opts.minYear + ", " + opts.maxYear + "]",
    });
  }

  if (month < 1 || month > 12) {
    issues.push({
      kind: "month-range", severity: "high",
      ruleId: "time.month-range",
      snippet: "month " + month + " outside [1, 12]",
    });
  }
  if (day < 1 || day > 31) {
    issues.push({
      kind: "day-range", severity: "high",
      ruleId: "time.day-range",
      snippet: "day " + day + " outside [1, 31]",
    });
  }
  if (hour > 23) {
    issues.push({
      kind: "hour-range", severity: "high",
      ruleId: "time.hour-range",
      snippet: "hour " + hour + " > 23",
    });
  }
  if (minute > 59) {
    issues.push({
      kind: "minute-range", severity: "high",
      ruleId: "time.minute-range",
      snippet: "minute " + minute + " > 59",
    });
  }
  if (second > 60) {                                                             // allow:raw-time-literal — leap-second ceiling literal 60 (RFC 3339 5.6); coincidental multiple-of-60, not a duration, C.TIME N/A
    issues.push({
      kind: "second-range", severity: "high",
      ruleId: "time.second-range",
      snippet: "second " + second + " > 60 (RFC 3339 §5.6 ceiling " +
               "including leap)",
    });
  }

  if (second === 60 && opts.leapSecondPolicy !== "allow") {                      // allow:raw-time-literal — leap-second sentinel, RFC 3339 §5.6
    issues.push({
      kind: "leap-second",
      severity: opts.leapSecondPolicy === "reject" ? "high" : "warn",
      ruleId: "time.leap-second",
      snippet: "second field is 60 (leap second; RFC 3339 §5.6 valid " +
               "but most parsers panic)",
    });
  }

  var daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month >= 1 && month <= 12 && day > daysInMonth[month - 1]) {
    issues.push({
      kind: "day-in-month", severity: "high",
      ruleId: "time.day-in-month",
      snippet: "day " + day + " not valid in month " + month,
    });
  }

  var fracLen = fractional.length > 0 ? fractional.length - 1 : 0;
  if (fracLen > opts.maxFractionalDigits &&
      opts.fractionalDigitsPolicy !== "allow") {
    issues.push({
      kind: "fractional-digits",
      severity: opts.fractionalDigitsPolicy === "reject" ? "high" : "warn",
      ruleId: "time.fractional-digits",
      snippet: "fractional precision " + fracLen + " exceeds " +
               opts.maxFractionalDigits + " digits — downstream " +
               "consumers may truncate or reject",
    });
  }

  if (!offset) {
    if (opts.naiveDatetimePolicy !== "allow") {
      issues.push({
        kind: "naive-datetime",
        severity: opts.naiveDatetimePolicy === "reject" ? "high" : "warn",
        ruleId: "time.naive-datetime",
        snippet: "datetime has no offset (`Z` or `+HH:MM`) — naive " +
                 "datetimes break cross-region equality",
      });
    }
  } else {
    var isUtc = offset === "Z" || offset === "z" ||
                offset === "+00:00" || offset === "-00:00";
    if (!isUtc && opts.nonUtcOffsetPolicy !== "allow") {
      issues.push({
        kind: "non-utc-offset",
        severity: opts.nonUtcOffsetPolicy === "reject" ? "high" : "warn",
        ruleId: "time.non-utc-offset",
        snippet: "datetime offset `" + offset + "` is not UTC — " +
                 "strict requires `Z` or `+00:00` for unambiguous " +
                 "cross-system comparison",
      });
    }
  }

  return issues;
}

/**
 * @primitive  b.guardTime.validate
 * @signature  b.guardTime.validate(input, opts?)
 * @since      0.7.46
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardTime.sanitize, b.guardTime.gate
 *
 * Inspect a datetime string against the resolved profile and return
 * `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `time.bad-input` issue rather
 * than throwing — callers that prefer an exception use
 * `b.guardTime.sanitize`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"audit"|"allow",
 *   naiveDatetimePolicy:    "reject"|"audit"|"allow",
 *   nonUtcOffsetPolicy:     "reject"|"audit"|"allow",
 *   leapSecondPolicy:       "reject"|"audit"|"allow",
 *   fractionalDigitsPolicy: "reject"|"truncate"|"audit"|"allow",
 *   dateOnlyPolicy:         "reject"|"audit"|"allow",
 *   timeOnlyPolicy:         "reject"|"audit"|"allow",
 *   minYear:                number,    // default 1970
 *   maxYear:                number,    // default 9999
 *   maxFractionalDigits:    number,    // default 9 (nanosecond)
 *   maxBytes:               number,    // default 64
 *
 * @example
 *   var rv = b.guardTime.validate("2026-05-05T12:34:56Z", { profile: "strict" });
 *   rv.ok;                                             // → true
 *
 *   var bad = b.guardTime.validate("1969-12-31T23:59:59Z", { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].ruleId;                              // → "time.year-window"
 */

/**
 * @primitive  b.guardTime.sanitize
 * @signature  b.guardTime.sanitize(input, opts?)
 * @since      0.7.46
 * @status     stable
 * @related    b.guardTime.validate, b.guardTime.gate
 *
 * Normalize a datetime string in-place: replace the legacy
 * space-separator with `T`, upper-case the trailing `Z` UTC
 * marker. Throws `GuardTimeError` when any `critical` or `high`
 * issue fires (year out of range, leap-second under reject,
 * naive datetime under reject). Use `validate` to inspect issues
 * without throwing.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardTime.validate opts,
 *
 * @example
 *   var safe = b.guardTime.sanitize("2026-05-05 12:34:56z",
 *                                   { profile: "balanced" });
 *   safe;                                              // → "2026-05-05T12:34:56Z"
 *
 *   try {
 *     b.guardTime.sanitize("9999-12-31T23:59:60Z", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "time.leap-second"
 *   }
 */
function _sanitizeTransform(input) {
  var out = input;
  for (var i = 1; i < out.length; i += 1) {
    if (out.charAt(i) === " " && codepointClass.isAsciiDigit(out.charCodeAt(i - 1))) {
      out = out.slice(0, i) + "T" + out.slice(i + 1);
      break;
    }
  }
  if (out.charAt(out.length - 1) === "z") out = out.slice(0, -1) + "Z";
  return out;
}

var INTEGRATION_FIXTURES = gateContract.identifierFixtures("2026-05-05T12:34:56Z", "2026-05-05 12:34:56");

var POLICY_ENUM = gateContract.policyVocabulary([
  "naiveDatetimePolicy", "nonUtcOffsetPolicy", "leapSecondPolicy",
  "dateOnlyPolicy", "timeOnlyPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  fractionalDigitsPolicy: ["reject", "truncate", "audit", "audit-only", "allow"],
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "time",
  kind:        "identifier",
  errorClass:  GuardTimeError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:           _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:          ["maxBytes", "minYear", "maxYear", "maxFractionalDigits"],
  ctxFields:   ["identifier", "timestamp", "time"],
});
