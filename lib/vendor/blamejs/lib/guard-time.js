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

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardTimeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardTimeError.factory;

// RFC 3339 §5.6 full-date + full-time grammar — anchored.
//
// Capture groups:
//   1: year (4 digits)         2: month (2)         3: day (2)
//   4: hour (2)                5: minute (2)        6: second (2; allows 60 for leap-second)
//   7: fractional incl. dot (optional)              8: offset (Z or +HH:MM/-HH:MM)
var RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$/;

var DEFAULT_MIN_YEAR = 1970;                                                     // Unix epoch year
var DEFAULT_MAX_YEAR = 9999;                                                     // RFC 3339 4-digit year ceiling
var MAX_FRACTIONAL_DIGITS = 9;                                                   // nanosecond precision cap

// ---- Profile presets ----

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

// ---- Detection ----

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "time", cap: { bytes: opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // Date-only / time-only quick checks BEFORE the full RFC 3339 regex
  // so the operator gets a more actionable diagnosis.
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) {                                       // allow:regex-no-length-cap — input bounded by maxBytes; allow:duplicate-regex — same RFC 3339 full-date shape used by safe-json + safe-schema; not consolidatable across module boundaries
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
  if (/^\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.test(input)) {           // allow:regex-no-length-cap — input bounded by maxBytes
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

  var match = input.match(RFC3339_RE);                                           // allow:regex-no-length-cap — input bounded by maxBytes
  if (!match) {
    issues.push({
      kind: "datetime-shape", severity: "high",
      ruleId: "time.datetime-shape",
      snippet: "input does not match RFC 3339 §5.6 date-time grammar",
    });
    return issues;
  }

  var year = parseInt(match[1], 10);                                             // base-10 radix
  var month = parseInt(match[2], 10);                                            // base-10 radix
  var day = parseInt(match[3], 10);                                              // base-10 radix
  var hour = parseInt(match[4], 10);                                             // base-10 radix
  var minute = parseInt(match[5], 10);                                           // base-10 radix
  var second = parseInt(match[6], 10);                                           // base-10 radix
  var fractional = match[7] || "";
  var offset = match[8];

  // Year window.
  if (year < opts.minYear || year > opts.maxYear) {
    issues.push({
      kind: "year-window", severity: "high",
      ruleId: "time.year-window",
      snippet: "year " + year + " outside operator window [" +
               opts.minYear + ", " + opts.maxYear + "]",
    });
  }

  // Month / day / hour / minute structural ranges.
  if (month < 1 || month > 12) {                                                 // month range
    issues.push({
      kind: "month-range", severity: "high",
      ruleId: "time.month-range",
      snippet: "month " + month + " outside [1, 12]",
    });
  }
  if (day < 1 || day > 31) {                                                     // day-of-month upper bound
    issues.push({
      kind: "day-range", severity: "high",
      ruleId: "time.day-range",
      snippet: "day " + day + " outside [1, 31]",
    });
  }
  if (hour > 23) {                                                               // hour ceiling
    issues.push({
      kind: "hour-range", severity: "high",
      ruleId: "time.hour-range",
      snippet: "hour " + hour + " > 23",
    });
  }
  if (minute > 59) {                                                             // minute ceiling
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

  // Leap-second flag.
  if (second === 60 && opts.leapSecondPolicy !== "allow") {                      // allow:raw-time-literal — leap-second sentinel, RFC 3339 §5.6
    issues.push({
      kind: "leap-second",
      severity: opts.leapSecondPolicy === "reject" ? "high" : "warn",
      ruleId: "time.leap-second",
      snippet: "second field is 60 (leap second; RFC 3339 §5.6 valid " +
               "but most parsers panic)",
    });
  }

  // Day-in-month structural sanity (light — not full Gregorian
  // rollover; the framework refuses obviously-out-of-bounds dates
  // like Feb 30 / Apr 31).
  var daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];            // Gregorian month-day table
  if (month >= 1 && month <= 12 && day > daysInMonth[month - 1]) {               // month range
    issues.push({
      kind: "day-in-month", severity: "high",
      ruleId: "time.day-in-month",
      snippet: "day " + day + " not valid in month " + month,
    });
  }

  // Fractional digits cap.
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

  // Naive datetime (no offset).
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
    // Non-UTC offset.
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
 *   bidiPolicy:             "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:          "reject"|"strip"|"allow",
 *   nullBytePolicy:         "reject"|"strip"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"allow",
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
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with maxBytes / minYear / maxYear /
// maxFractionalDigits declared via `intOpts`. _detectIssues returns the
// `time.bad-input` issue for a non-string, so validate reports
// `{ ok: false }` there without a bespoke early-return. The @primitive
// block above documents the resulting public ABI.

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
// _sanitizeTransform — the guard-specific normalize applied by defineGuard's
// generated sanitize AFTER resolve → detect → throw-on-refusal. Input is an
// already-validated string at this point (a non-string refuses upstream).
function _sanitizeTransform(input) {
  // Normalize: replace the legacy space separator with `T`, uppercase the
  // trailing `z` UTC marker.
  return input.replace(/(\d) /, "$1T").replace(/z$/, "Z");
}

// gate / buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate (defineGuard) blocks in gate-contract.js,
// instantiated per guard by the page generator.

// Hostile: naive datetime (space separator + no offset) — refused at
// strict (cross-region ambiguity class).
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("2026-05-05T12:34:56Z", "2026-05-05 12:34:56");

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize). The gate is the factory default — the
// standard serve -> audit-only -> refuse chain — reading
// ctx.identifier / ctx.timestamp / ctx.time via ctxFields.
module.exports = gateContract.defineGuard({
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
