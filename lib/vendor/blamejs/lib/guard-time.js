"use strict";
/**
 * guard-time — RFC 3339 / ISO 8601 datetime identifier-safety primitive
 * (b.guardTime).
 *
 * Validates user-supplied datetime strings destined for audit
 * timestamps, scheduling, retention windows, query ranges, and
 * cross-system event correlation. KIND="identifier" — consumes
 * ctx.identifier (or ctx.timestamp).
 *
 * Threat catalog:
 *   - Shape malformation — not RFC 3339 / ISO 8601 datetime.
 *   - Pre-epoch / far-future — year before 1970 or after the
 *     operator's far-future ceiling (default 9999); often a parsing
 *     bug or sentinel-leak shape.
 *   - Naive datetime (no offset) — strict refuses; downstream
 *     interpretation depends on local timezone, breaks
 *     cross-region equality.
 *   - Non-UTC offset — strict accepts only `Z` / `+00:00`; balanced
 *     accepts any offset; permissive allows naive too.
 *   - Leap-second `60` in seconds field — RFC 3339 §5.6 explicitly
 *     valid (`23:59:60Z` is a real wall-clock time); most parsers
 *     panic. Flagged-by-default with operator policy.
 *   - Excessive fractional precision — RFC 3339 allows any digits
 *     after the dot but every consuming system has a cap; flag > 9
 *     fractional digits.
 *   - Date-only / time-only — refused for full-datetime contexts.
 *   - Whitespace / control / null-byte / BIDI universal refuse.
 *
 *   var rv = b.guardTime.validate("2026-05-05T12:34:56Z",
 *                                 { profile: "strict" });
 *   var safe = b.guardTime.sanitize("2026-05-05T12:34:56.123+05:30",
 *                                   { profile: "balanced" });
 *   var g = b.guardTime.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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

var DEFAULT_MIN_YEAR = 1970;                                                     // allow:raw-byte-literal — Unix epoch year
var DEFAULT_MAX_YEAR = 9999;                                                     // allow:raw-byte-literal — RFC 3339 4-digit year ceiling
var MAX_FRACTIONAL_DIGITS = 9;                                                   // allow:raw-byte-literal — nanosecond precision cap

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
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
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
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
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
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

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(64),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardTimeError,
    errCodePrefix:      "time",
  });
}

// ---- Detection ----

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "time.bad-input",
              snippet: "time is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "time.empty",
              snippet: "time is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "time-cap", severity: "high",
              ruleId: "time.time-cap",
              snippet: "time input exceeds maxBytes " + opts.maxBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "time");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

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

  var year = parseInt(match[1], 10);                                             // allow:raw-byte-literal — base-10 radix
  var month = parseInt(match[2], 10);                                            // allow:raw-byte-literal — base-10 radix
  var day = parseInt(match[3], 10);                                              // allow:raw-byte-literal — base-10 radix
  var hour = parseInt(match[4], 10);                                             // allow:raw-byte-literal — base-10 radix
  var minute = parseInt(match[5], 10);                                           // allow:raw-byte-literal — base-10 radix
  var second = parseInt(match[6], 10);                                           // allow:raw-byte-literal — base-10 radix
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
  if (month < 1 || month > 12) {                                                 // allow:raw-byte-literal — month range
    issues.push({
      kind: "month-range", severity: "high",
      ruleId: "time.month-range",
      snippet: "month " + month + " outside [1, 12]",
    });
  }
  if (day < 1 || day > 31) {                                                     // allow:raw-byte-literal — day-of-month upper bound
    issues.push({
      kind: "day-range", severity: "high",
      ruleId: "time.day-range",
      snippet: "day " + day + " outside [1, 31]",
    });
  }
  if (hour > 23) {                                                               // allow:raw-byte-literal — hour ceiling
    issues.push({
      kind: "hour-range", severity: "high",
      ruleId: "time.hour-range",
      snippet: "hour " + hour + " > 23",
    });
  }
  if (minute > 59) {                                                             // allow:raw-byte-literal — minute ceiling
    issues.push({
      kind: "minute-range", severity: "high",
      ruleId: "time.minute-range",
      snippet: "minute " + minute + " > 59",
    });
  }
  if (second > 60) {                                                             // allow:raw-time-literal — leap-second ceiling, RFC 3339 §5.6 (not seconds-of-time)
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
  var daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];            // allow:raw-byte-literal — Gregorian month-day table
  if (month >= 1 && month <= 12 && day > daysInMonth[month - 1]) {               // allow:raw-byte-literal — month range
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "minYear", "maxYear", "maxFractionalDigits"],
    "guardTime.validate", GuardTimeError, "time.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 ruleId: "time.bad-input",
                 snippet: "time is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("time.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "time.refused",
        "guardTime.sanitize: " + issues[i].snippet);
    }
  }
  // Normalize: lowercase the trailing `T` separator, uppercase the
  // `Z` UTC marker.
  return input.replace(/(\d) /, "$1T").replace(/z$/, "Z");
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardTime:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var identifier = ctx && (ctx.identifier || ctx.timestamp || ctx.time || "");
      if (!identifier) return { ok: true, action: "serve" };
      var rv = validate(identifier, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "time");
}

var _timeRulePacks = gateContract.makeRulePackLoader(GuardTimeError, "time");
var loadRulePack = _timeRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "time",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("2026-05-05T12:34:56Z", "utf8"),
    hostileBytes:      Buffer.from("2026-05-05 12:34:56", "utf8"),
    benignIdentifier:  "2026-05-05T12:34:56Z",
    // Hostile: naive datetime (space separator + no offset) — refused
    // at strict (cross-region ambiguity class).
    hostileIdentifier: "2026-05-05 12:34:56",
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardTimeError:      GuardTimeError,
};
