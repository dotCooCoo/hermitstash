// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.time
 * @featured true
 * @nav    Tools
 * @title  Time
 *
 * @intro
 *   Timezone-aware datetime helpers built on top of native
 *   `Intl.DateTimeFormat`. No TZ-database vendor; operators get the
 *   IANA names Node's ICU build supports (full set on every mainstream
 *   platform).
 *
 *   The module covers four concerns: parsing ISO 8601 strings into
 *   `Date`, decomposing an instant into calendar parts in a named
 *   timezone, formatting an instant for human display, and DST-safe
 *   calendar arithmetic (addDays / addMonths / startOfDay / endOfDay /
 *   diffDays).
 *
 *   Every operation accepts a `Date`, a millisecond-epoch number, or
 *   an ISO 8601 string interchangeably. The `timezone` opt defaults
 *   to `"UTC"` and the `locale` opt defaults to `"en-US"`.
 *
 *   Calendar arithmetic anchors on parts in the requested timezone,
 *   not on UTC milliseconds — so `addDays(d, 1, { timezone:
 *   "America/New_York" })` always lands on the same wall-clock time
 *   the next civil day, even across the spring-forward / fall-back
 *   transitions.
 *
 * @card
 *   Timezone-aware datetime helpers built on top of native `Intl.DateTimeFormat`.
 */
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var { defineClass } = require("./framework-error");

var TimeError = defineClass("TimeError", { alwaysPermanent: true });

var DEFAULT_TIMEZONE = "UTC";
var DEFAULT_LOCALE   = "en-US";

var _dtfCache = new Map();
function _dtf(opts) {
  var key = JSON.stringify(opts);
  if (_dtfCache.has(key)) return _dtfCache.get(key);
  var dtf;
  try { dtf = new Intl.DateTimeFormat(opts.locale || DEFAULT_LOCALE, opts); }
  catch (e) {
    throw new TimeError("time/bad-timezone-or-locale",
      "Intl rejected the timezone/locale: " + ((e && e.message) || String(e)));
  }
  _dtfCache.set(key, dtf);
  return dtf;
}

function _toDate(v) {
  if (v instanceof Date) {
    if (isNaN(v.getTime())) {
      throw new TimeError("time/invalid-date", "input Date is invalid (NaN)");
    }
    return v;
  }
  if (typeof v === "number") {
    if (!isFinite(v)) {
      throw new TimeError("time/invalid-ms", "input must be a finite number of milliseconds");
    }
    return new Date(v);
  }
  if (typeof v === "string") return parseISO(v);
  throw new TimeError("time/bad-input",
    "expected Date | number | ISO string, got " + typeof v);
}

var WEEKDAY_TO_NUM = {
  "Mon": 1, "Tue": 2, "Wed": 3, "Thu": 4, "Fri": 5, "Sat": 6, "Sun": 7,
};

/**
 * @primitive b.time.toParts
 * @signature b.time.toParts(input, opts)
 * @since     0.1.0
 * @related   b.time.format, b.time.parseISO
 *
 * Decompose an instant into calendar parts as observed in a named
 * timezone. Returns `{ year, month, day, hour, minute, second,
 * millisecond, weekday: 1..7, weekdayName: "Mon".."Sun", dayOfYear }`.
 * Weekday numbering follows ISO 8601 (Monday = 1, Sunday = 7).
 *
 * Accepts a `Date`, ms-epoch number, or ISO 8601 string. `timezone`
 * defaults to `"UTC"`.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var parts = b.time.toParts("2026-05-09T14:30:00Z", {
 *     timezone: "America/New_York",
 *   });
 *   parts.year;         // → 2026
 *   parts.month;        // → 5
 *   parts.day;          // → 9
 *   parts.hour;         // → 10
 *   parts.weekdayName;  // → "Sat"
 *   parts.weekday;      // → 6
 *   parts.dayOfYear;    // → 129
 */
function toParts(input, opts) {
  opts = opts || {};
  var date = _toDate(input);
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var dtf = _dtf({
    timeZone: tz,
    year:    "numeric", month: "2-digit", day: "2-digit",
    hour:    "2-digit", minute: "2-digit", second: "2-digit",
    weekday: "short",
    hour12:  false,
  });
  var parts = dtf.formatToParts(date);
  var out = { millisecond: date.getUTCMilliseconds() };
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    if (p.type === "year")    out.year    = parseInt(p.value, 10);
    if (p.type === "month")   out.month   = parseInt(p.value, 10);
    if (p.type === "day")     out.day     = parseInt(p.value, 10);
    if (p.type === "hour")    out.hour    = (p.value === "24" ? 0 : parseInt(p.value, 10));
    if (p.type === "minute")  out.minute  = parseInt(p.value, 10);
    if (p.type === "second")  out.second  = parseInt(p.value, 10);
    if (p.type === "weekday") {
      out.weekdayName = p.value;
      out.weekday = WEEKDAY_TO_NUM[p.value] || null;
    }
  }
  // dayOfYear: computed from out.year + out.month + out.day directly,
  // no recursion through toParts. Days-in-month table for non-leap;
  // Feb gets +1 in leap years (Gregorian rule: divisible by 4, not 100,
  // unless 400).
  // Cumulative days-before-each-month-start in a non-leap Gregorian year.
  // Built from the days-in-month sequence so the source literals are
  // calendar lengths (31 / 28 / 31 / …), not their running total.
  var DAYS_IN_MONTH_NONLEAP = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  var DAYS_BEFORE_MONTH = [0];
  for (var _dm = 0; _dm < DAYS_IN_MONTH_NONLEAP.length - 1; _dm++) {
    DAYS_BEFORE_MONTH.push(DAYS_BEFORE_MONTH[_dm] + DAYS_IN_MONTH_NONLEAP[_dm]);
  }
  var leap = (out.year % 4 === 0 && out.year % 100 !== 0) || (out.year % 400 === 0);
  out.dayOfYear = DAYS_BEFORE_MONTH[out.month - 1] + out.day + (leap && out.month > 2 ? 1 : 0);
  return out;
}

/**
 * @primitive b.time.format
 * @signature b.time.format(input, opts)
 * @since     0.1.0
 * @related   b.time.toParts, b.time.parseISO
 *
 * Render an instant as an operator-readable string in a named
 * timezone and locale. Accepts the same `Date | number | string`
 * input as the rest of the module. When neither `dateStyle` /
 * `timeStyle` nor any per-field opt is supplied, defaults to
 * `dateStyle: "medium"` + `timeStyle: "short"`.
 *
 * Per-field opts (`year` / `month` / `day` / `hour` / `minute` /
 * `second` / `weekday` / `era` / `hour12` / `fractionalSecondDigits` /
 * `timeZoneName`) pass through to `Intl.DateTimeFormat` unchanged.
 *
 * @opts
 *   timezone: string,            // IANA name; defaults to "UTC"
 *   locale:   string,            // BCP 47; defaults to "en-US"
 *   dateStyle: string,           // "full" | "long" | "medium" | "short"
 *   timeStyle: string,           // "full" | "long" | "medium" | "short"
 *   year:     string,            // "numeric" | "2-digit"
 *   month:    string,            // "numeric" | "2-digit" | "long" | "short" | "narrow"
 *   day:      string,
 *   hour:     string,
 *   minute:   string,
 *   second:   string,
 *   weekday:  string,
 *   era:      string,
 *   hour12:   boolean,
 *   fractionalSecondDigits: number,
 *   timeZoneName: string,        // "long" | "short" | "shortOffset" | etc.
 *
 * @example
 *   var when = "2026-05-09T14:30:00Z";
 *   b.time.format(when, { timezone: "America/New_York" });
 *   // → "May 9, 2026, 10:30 AM"
 *
 *   b.time.format(when, {
 *     timezone: "Asia/Tokyo",
 *     dateStyle: "full",
 *     timeStyle: "long",
 *   });
 *   // → operator-readable Japanese-locale-style string
 */
function format(input, opts) {
  opts = opts || {};
  var date = _toDate(input);
  var fmtOpts = {
    timeZone: opts.timezone || DEFAULT_TIMEZONE,
    locale:   opts.locale   || DEFAULT_LOCALE,
  };
  if (opts.dateStyle) fmtOpts.dateStyle = opts.dateStyle;
  if (opts.timeStyle) fmtOpts.timeStyle = opts.timeStyle;
  var passthroughKeys = [
    "year", "month", "day", "hour", "minute", "second",
    "weekday", "era", "hour12", "fractionalSecondDigits",
    "timeZoneName",
  ];
  for (var i = 0; i < passthroughKeys.length; i++) {
    var k = passthroughKeys[i];
    if (opts[k] !== undefined) fmtOpts[k] = opts[k];
  }
  if (!opts.dateStyle && !opts.timeStyle && !passthroughKeys.some(function (k) { return opts[k] !== undefined; })) {
    fmtOpts.dateStyle = "medium";
    fmtOpts.timeStyle = "short";
  }
  return _dtf(fmtOpts).format(date);
}

/**
 * @primitive b.time.tzOffsetMs
 * @signature b.time.tzOffsetMs(input, timezone)
 * @since     0.1.0
 * @related   b.time.toParts, b.time.startOfDay
 *
 * Compute the offset in milliseconds between the named timezone's
 * local wall-clock and UTC at the given instant. Positive east of
 * UTC, negative west. The value depends on the instant — DST
 * transitions are honoured automatically.
 *
 * Throws `TimeError` when `timezone` is missing, non-string, or not
 * an IANA name supported by Node's ICU build.
 *
 * @example
 *   var offset = b.time.tzOffsetMs("2026-05-09T12:00:00Z", "America/New_York");
 *   // → -14400000   (UTC-4 during DST; 4h * 60m * 60s * 1000ms)
 *
 *   var winter = b.time.tzOffsetMs("2026-01-15T12:00:00Z", "America/New_York");
 *   // → -18000000   (UTC-5 in standard time)
 */
function tzOffsetMs(input, timezone) {
  var date = _toDate(input);
  if (!timezone || typeof timezone !== "string") {
    throw new TimeError("time/bad-timezone",
      "tzOffsetMs: timezone must be a non-empty IANA name");
  }
  var dtf = _dtf({
    timeZone: timezone,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });
  var parts = {};
  dtf.formatToParts(date).forEach(function (p) { parts[p.type] = p.value; });
  var hour = parts.hour === "24" ? "00" : parts.hour;
  var asUtcMs = Date.UTC(
    parseInt(parts.year, 10),
    parseInt(parts.month, 10) - 1,
    parseInt(parts.day, 10),
    parseInt(hour, 10),
    parseInt(parts.minute, 10),
    parseInt(parts.second, 10)
  );
  var instantSec = C.TIME.seconds(Math.floor(date.getTime() / 1000));
  return asUtcMs - instantSec;
}

function _fromPartsAtTz(p, timezone) {
  var candidate = Date.UTC(
    p.year,
    (p.month - 1),
    p.day,
    p.hour    || 0,
    p.minute  || 0,
    p.second  || 0,
    p.millisecond || 0
  );
  var offset1 = tzOffsetMs(candidate, timezone);
  var step1   = candidate - offset1;
  var offset2 = tzOffsetMs(step1, timezone);
  return new Date(step1 - (offset2 - offset1));
}

/**
 * @primitive b.time.startOfDay
 * @signature b.time.startOfDay(input, opts)
 * @since     0.1.0
 * @related   b.time.endOfDay, b.time.diffDays
 *
 * Return a `Date` pointing at midnight (00:00:00.000) of the input's
 * civil day in the named timezone. DST-safe — the spring-forward day
 * still resolves to the first valid wall-clock instant. Useful for
 * day-bucketed audit queries and "is this still today?" comparisons.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var dayStart = b.time.startOfDay("2026-05-09T14:30:00Z", {
 *     timezone: "America/New_York",
 *   });
 *   dayStart.toISOString();
 *   // → "2026-05-09T04:00:00.000Z"   (midnight NY = 04:00 UTC during DST)
 */
function startOfDay(input, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  return _fromPartsAtTz({
    year: p.year, month: p.month, day: p.day,
    hour: 0, minute: 0, second: 0, millisecond: 0,
  }, tz);
}

/**
 * @primitive b.time.endOfDay
 * @signature b.time.endOfDay(input, opts)
 * @since     0.1.0
 * @related   b.time.startOfDay, b.time.diffDays
 *
 * Return a `Date` pointing at the last representable millisecond
 * (23:59:59.999) of the input's civil day in the named timezone.
 * DST-safe. Pair with `startOfDay` to bracket "all events on day X
 * in timezone Y" range queries.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var dayEnd = b.time.endOfDay("2026-05-09T14:30:00Z", {
 *     timezone: "America/New_York",
 *   });
 *   dayEnd.toISOString();
 *   // → "2026-05-10T03:59:59.999Z"   (23:59:59.999 NY = 03:59 next-day UTC)
 */
function endOfDay(input, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  return _fromPartsAtTz({
    year: p.year, month: p.month, day: p.day,
    hour: 23, minute: 59, second: 59, millisecond: 999,
  }, tz);
}

/**
 * @primitive b.time.addDays
 * @signature b.time.addDays(input, n, opts)
 * @since     0.1.0
 * @related   b.time.addMonths, b.time.diffDays
 *
 * Add `n` calendar days to the input, anchored on the named
 * timezone's wall clock. Negative `n` subtracts. Calendar-day
 * arithmetic — the wall-clock hour / minute / second / millisecond
 * stay the same across DST transitions, even though the resulting
 * UTC offset between the two instants will differ by an hour around
 * the transition.
 *
 * Throws `TimeError` when `n` is not a finite number.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var due = b.time.addDays("2026-05-09T14:30:00Z", 7, {
 *     timezone: "America/New_York",
 *   });
 *   due.toISOString();
 *   // → "2026-05-16T14:30:00.000Z"
 *
 *   // Subtract: "yesterday at this time"
 *   var yesterday = b.time.addDays(Date.now(), -1, { timezone: "UTC" });
 */
function addDays(input, n, opts) {
  opts = opts || {};
  if (typeof n !== "number" || !isFinite(n)) {
    throw new TimeError("time/bad-arg", "addDays: n must be a finite number");
  }
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  var asUtc = new Date(Date.UTC(p.year, p.month - 1, p.day + Math.trunc(n),
    p.hour, p.minute, p.second, p.millisecond));
  return _fromPartsAtTz({
    year:        asUtc.getUTCFullYear(),
    month:       asUtc.getUTCMonth() + 1,
    day:         asUtc.getUTCDate(),
    hour:        p.hour, minute: p.minute, second: p.second, millisecond: p.millisecond,
  }, tz);
}

/**
 * @primitive b.time.addMonths
 * @signature b.time.addMonths(input, n, opts)
 * @since     0.1.0
 * @related   b.time.addDays, b.time.diffDays
 *
 * Add `n` calendar months to the input, anchored on the named
 * timezone's wall clock. Negative `n` subtracts. End-of-month days
 * clamp to the target month's last day — Jan 31 + 1 month is
 * Feb 28/29, not "March 3". Wall-clock hour / minute / second /
 * millisecond are preserved.
 *
 * Throws `TimeError` when `n` is not a finite number.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var renewal = b.time.addMonths("2026-01-31T09:00:00Z", 1, {
 *     timezone: "UTC",
 *   });
 *   renewal.toISOString();
 *   // → "2026-02-28T09:00:00.000Z"   (clamped: Feb has no day 31)
 *
 *   var nextQuarter = b.time.addMonths(Date.now(), 3, { timezone: "UTC" });
 */
function addMonths(input, n, opts) {
  opts = opts || {};
  if (typeof n !== "number" || !isFinite(n)) {
    throw new TimeError("time/bad-arg", "addMonths: n must be a finite number");
  }
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  var newMonth0 = (p.month - 1) + Math.trunc(n);
  var newYear   = p.year + Math.floor(newMonth0 / 12);
  newMonth0     = ((newMonth0 % 12) + 12) % 12;
  var daysInNew = new Date(Date.UTC(newYear, newMonth0 + 1, 0)).getUTCDate();
  var newDay    = Math.min(p.day, daysInNew);
  return _fromPartsAtTz({
    year: newYear, month: newMonth0 + 1, day: newDay,
    hour: p.hour, minute: p.minute, second: p.second, millisecond: p.millisecond,
  }, tz);
}

/**
 * @primitive b.time.diffDays
 * @signature b.time.diffDays(a, b, opts)
 * @since     0.1.0
 * @related   b.time.addDays, b.time.startOfDay
 *
 * Calendar days between two instants in the named timezone, computed
 * as `startOfDay(b) - startOfDay(a)` rounded to whole days. Positive
 * when `b` is after `a`; negative otherwise. Foundation for
 * "X days ago" / "Y days until" relative formatting.
 *
 * @opts
 *   timezone: string,   // IANA name; defaults to "UTC"
 *
 * @example
 *   var posted = "2026-05-02T08:00:00Z";
 *   var now    = "2026-05-09T14:30:00Z";
 *   var ago    = b.time.diffDays(posted, now, { timezone: "UTC" });
 *   // → 7
 *
 *   // "X days ago" relative formatting:
 *   var label = ago === 0 ? "today"
 *             : ago === 1 ? "yesterday"
 *             : ago + " days ago";
 *   // → "7 days ago"
 */
function diffDays(a, b, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var aMid = startOfDay(a, { timezone: tz });
  var bMid = startOfDay(b, { timezone: tz });
  return Math.round((bMid.getTime() - aMid.getTime()) / C.TIME.days(1));
}

// ---- the ISO 8601 / RFC 3339 grammar, read once ----
//
// Five places in the framework used to spell this grammar as a pattern of
// their own: this module, the time guard, the event-bus payload guard, the
// schema builder and the JSON format table. They agreed on the easy cases and
// diverged on the ones that matter — whether the offset may drop its colon,
// whether a fraction with no digits parses, whether a lone date counts. These
// three readers are the grammar; the callers supply the POLICY.
//
// Each returns the text of each field (not a number: a caller that reports on
// the input needs the characters it was given) plus `end`, the index just past
// what was read, or null when the text at that position is not the production.

var DATE_LENGTH = 10;                                                            // YYYY-MM-DD
var HOUR_MINUTE_LENGTH = 5;                                                      // HH:MM
var OFFSET_LENGTH_WITH_COLON = 6;                                                // +HH:MM
var OFFSET_LENGTH_BARE = 5;                                                      // +HHMM
var DEFAULT_DATE_TIME_SEPARATORS = "Tt ";                                        // RFC 3339 §5.6 + its NOTE

function _digitsAt(text, at, count) {
  if (at + count > text.length) return false;
  for (var i = at; i < at + count; i += 1) {
    if (!codepointClass.isAsciiDigit(text.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * @primitive b.time.readDate
 * @signature b.time.readDate(text, at?)
 * @since     0.18.31
 * @status    stable
 * @related   b.time.readTime, b.time.readDateTime
 *
 * Read `YYYY-MM-DD` at index `at` (default 0), returning
 * `{ year, month, day, end }` as TEXT plus the index just past it, or `null`.
 * Shape only — a month of `13` reads fine here and is rejected by whoever
 * cares about the calendar.
 *
 * @example
 *   b.time.readDate("2026-08-16T00:00:00Z").day;                     // → "16"
 */
function readDate(text, at) {
  if (typeof text !== "string") return null;
  var from = at > 0 ? Math.floor(at) : 0;
  if (!_digitsAt(text, from, 4) || text.charAt(from + 4) !== "-") return null;
  if (!_digitsAt(text, from + 5, 2) || text.charAt(from + 7) !== "-") return null;
  if (!_digitsAt(text, from + 8, 2)) return null;
  return {
    year:  text.slice(from, from + 4),
    month: text.slice(from + 5, from + 7),
    day:   text.slice(from + 8, from + 10),
    end:   from + DATE_LENGTH,
  };
}

/**
 * @primitive b.time.readTime
 * @signature b.time.readTime(text, at?, opts?)
 * @since     0.18.31
 * @status    stable
 * @related   b.time.readDate, b.time.readDateTime
 *
 * Read `HH:MM:SS` with an optional fraction and an optional offset at index
 * `at` (default 0), returning `{ hour, minute, second, fraction, offset, end }`
 * or `null`. `fraction` carries its leading dot and `offset` its sign, both
 * empty when absent, so a caller can tell "no offset" from `+00:00` — which
 * matters, because one says the time is UTC and the other says nobody
 * recorded a zone.
 *
 * A fraction with no digits after the dot is not a time.
 *
 * `requireSeconds: false` accepts `HH:MM` — the shape ISO 8601 permits and
 * RFC 3339 §5.6 does not. A time with no seconds is one two systems will round
 * differently, so it is off by default; the option exists because narrowing
 * what an EXISTING parser accepts is a change to every caller below it.
 * Without seconds there is no fraction either, which is where they hang.
 *
 * `offsetCase: "upper"` refuses a lower-case `z`. RFC 3339 §5.6 permits it, so
 * the default takes it — but a caller that will branch on the returned offset
 * has to say which spellings it handles, and several in this framework only
 * ever handled `Z`.
 *
 * @opts
 *   offsetColon:    "require"|"optional",  // default: "require" (RFC 3339 §5.6)
 *   offsetCase:     "either"|"upper",      // default: "either" (RFC 3339 §5.6)
 *   requireSeconds: boolean,               // default: true
 *
 * @example
 *   b.time.readTime("12:34:56.5+01:00").offset;                      // → "+01:00"
 *   b.time.readTime("12:34:56Z", 0).fraction;                        // → ""
 *   b.time.readTime("12:34Z", 0, { requireSeconds: false }).second;  // → ""
 *   b.time.readTime("12:34:56z", 0, { offsetCase: "upper" });        // → null
 */
function readTime(text, at, opts) {
  if (typeof text !== "string") return null;
  var colonOptional = !!(opts && opts.offsetColon === "optional");
  var upperOffsetOnly = !!(opts && opts.offsetCase === "upper");
  var requireSeconds = !opts || opts.requireSeconds !== false;
  var from = at > 0 ? Math.floor(at) : 0;
  if (!_digitsAt(text, from, 2) || text.charAt(from + 2) !== ":") return null;
  if (!_digitsAt(text, from + 3, 2)) return null;

  var p = from + HOUR_MINUTE_LENGTH;
  var second = "";
  var fraction = "";
  var hasSeconds = text.charAt(p) === ":";
  if (!hasSeconds && requireSeconds) return null;
  if (hasSeconds) {
    if (!_digitsAt(text, p + 1, 2)) return null;
    second = text.slice(p + 1, p + 3);
    p += 3;
    if (text.charAt(p) === ".") {
      var digits = p + 1;
      while (digits < text.length && codepointClass.isAsciiDigit(text.charCodeAt(digits))) digits += 1;
      if (digits === p + 1) return null;                                         // a dot with no digits
      fraction = text.slice(p, digits);
      p = digits;
    }
  }

  var offset = "";
  var here = text.charAt(p);
  if (here === "Z" || (here === "z" && !upperOffsetOnly)) {
    offset = here;
    p += 1;
  } else if (here === "z") {
    return null;                                                                 // lower case refused by this caller
  } else if (here === "+" || here === "-") {
    if (!_digitsAt(text, p + 1, 2)) return null;
    if (text.charAt(p + 3) === ":") {
      if (!_digitsAt(text, p + 4, 2)) return null;
      offset = text.slice(p, p + OFFSET_LENGTH_WITH_COLON);
      p += OFFSET_LENGTH_WITH_COLON;
    } else if (colonOptional && _digitsAt(text, p + 3, 2)) {
      offset = text.slice(p, p + OFFSET_LENGTH_BARE);
      p += OFFSET_LENGTH_BARE;
    } else {
      return null;
    }
  }

  return {
    hour:     text.slice(from, from + 2),
    minute:   text.slice(from + 3, from + 5),
    second:   second,
    fraction: fraction,
    offset:   offset,
    end:      p,
  };
}

/**
 * @primitive b.time.readDateTime
 * @signature b.time.readDateTime(text, opts?)
 * @since     0.18.31
 * @status    stable
 * @related   b.time.readDate, b.time.readTime
 *
 * Read a whole ISO 8601 / RFC 3339 date-time — the ENTIRE string, so trailing
 * text is a refusal rather than an ignored tail. Returns the date fields and,
 * when a time is present, the time fields too; `null` otherwise.
 *
 * @opts
 *   separators:    string,   // default: "Tt " — what may sit between the halves
 *   requireTime:   boolean,  // default: true — is a bare date a date-time?
 *   requireOffset: boolean,  // default: false — must the zone be stated?
 *   offsetColon:   "require"|"optional",  // default: "require"
 *
 * @example
 *   b.time.readDateTime("2026-08-16T12:34:56Z").hour;                // → "12"
 *   b.time.readDateTime("2026-08-16T12:34:56");                      // → the fields, offset ""
 *   b.time.readDateTime("2026-08-16T12:34:56", { requireOffset: true });  // → null
 */
function readDateTime(text, opts) {
  if (typeof text !== "string") return null;
  var separators = (opts && typeof opts.separators === "string")
    ? opts.separators : DEFAULT_DATE_TIME_SEPARATORS;
  var requireTime = !opts || opts.requireTime !== false;
  var requireOffset = !!(opts && opts.requireOffset);

  var date = readDate(text, 0);
  if (date === null) return null;
  if (date.end === text.length) {
    if (requireTime) return null;
    return {
      year: date.year, month: date.month, day: date.day,
      hour: "", minute: "", second: "", fraction: "", offset: "",
    };
  }

  if (separators.indexOf(text.charAt(date.end)) === -1) return null;
  var time = readTime(text, date.end + 1, opts);
  if (time === null || time.end !== text.length) return null;
  if (requireOffset && time.offset === "") return null;

  return {
    year: date.year, month: date.month, day: date.day,
    hour: time.hour, minute: time.minute, second: time.second,
    fraction: time.fraction, offset: time.offset,
  };
}

/**
 * @primitive b.time.parseISO
 * @signature b.time.parseISO(s)
 * @since     0.1.0
 * @related   b.time.toIso8601NoMs, b.time.toParts
 *
 * Parse an ISO 8601 / RFC 3339 datetime string into a `Date`.
 * Accepts `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, `YYYY-MM-DDTHH:MM:SS`,
 * optional `.sss` fractional seconds, and an optional trailing
 * `Z` / `+HH:MM` / `-HH:MM` zone designator. A space separator
 * between date and time is also accepted. Strings without a zone
 * designator are interpreted as UTC.
 *
 * Throws `TimeError` for non-strings, malformed input, or
 * out-of-range component values (month > 12, day > 31, hour > 23,
 * etc.).
 *
 * @example
 *   var d = b.time.parseISO("2026-05-09T14:30:00Z");
 *   d.toISOString();        // → "2026-05-09T14:30:00.000Z"
 *
 *   // Offset zone:
 *   var withOffset = b.time.parseISO("2026-05-09T10:30:00-04:00");
 *   withOffset.toISOString();   // → "2026-05-09T14:30:00.000Z"
 *
 *   // Date-only (interpreted as UTC midnight):
 *   var date = b.time.parseISO("2026-05-09");
 *   date.toISOString();     // → "2026-05-09T00:00:00.000Z"
 */
function parseISO(s) {
  if (typeof s !== "string" || s.length === 0) {
    throw new TimeError("time/bad-iso", "parseISO: input must be a non-empty string");
  }
  // Every option here pins this function to the shapes it has always taken,
  // rather than to the defaults a new caller gets. RFC 3339 §5.6 permits a
  // lower-case `t` and `z` and requires seconds; this accepted neither letter
  // and did not require the seconds. Changing what an EXISTING parser accepts
  // — in either direction — is a change to every caller downstream of it.
  var m = readDateTime(s, {
    separators:     "T ",
    requireTime:    false,
    requireSeconds: false,
    offsetColon:    "optional",
    offsetCase:     "upper",
  });
  if (m === null) {
    throw new TimeError("time/bad-iso",
      "parseISO: not an ISO 8601 datetime: " + JSON.stringify(s));
  }
  var year   = parseInt(m.year, 10);
  var month  = parseInt(m.month, 10);
  var day    = parseInt(m.day, 10);
  var hour   = m.hour ? parseInt(m.hour, 10) : 0;
  var minute = m.minute ? parseInt(m.minute, 10) : 0;
  var second = m.second ? parseInt(m.second, 10) : 0;
  // The fraction arrives with its leading dot; pad or truncate to
  // milliseconds, which is the resolution a Date carries.
  var msStr  = m.fraction ? m.fraction.slice(1) : "";
  var ms     = msStr ? parseInt((msStr + "000").slice(0, 3), 10) : 0;
  var tz     = m.offset === "" ? undefined : m.offset;

  if (month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59 || second > 59) {
    throw new TimeError("time/bad-iso",
      "parseISO: out-of-range component in " + JSON.stringify(s));
  }
  var utcMs;
  if (!tz || tz === "Z") {
    utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  } else if (tz.charAt(0) === "+" || tz.charAt(0) === "-") {
    var sign = tz.charAt(0) === "-" ? -1 : 1;
    var hh   = parseInt(tz.slice(1, 3), 10);
    var mm   = parseInt(tz.slice(tz.length - 2), 10);
    var offsetMs = sign * (C.TIME.hours(hh) + C.TIME.minutes(mm));
    utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms) - offsetMs;
  } else {
    // An offset spelling the reader returned and this branch does not handle.
    // Reaching here means the two have drifted apart; refuse rather than fall
    // through to a NaN that becomes an Invalid Date the caller has to notice.
    throw new TimeError("time/bad-iso",
      "parseISO: unsupported timezone offset " + JSON.stringify(tz) +
      " in " + JSON.stringify(s));
  }
  var parsed = new Date(utcMs);
  // Fail closed. A parser at a trust boundary must not hand back an Invalid
  // Date, which reads as an object and fails much later at whatever first
  // formats or compares it.
  if (isNaN(parsed.getTime())) {
    throw new TimeError("time/bad-iso",
      "parseISO: not a representable date: " + JSON.stringify(s));
  }
  return parsed;
}

var ISO_MS_LENGTH = 5;                                                             // ".sssZ"

/**
 * @primitive b.time.toIso8601NoMs
 * @signature b.time.toIso8601NoMs(input)
 * @since     0.1.0
 * @related   b.time.parseISO
 *
 * Emit an ISO 8601 string with the trailing `.sssZ` milliseconds
 * dropped — produces `2026-05-09T14:30:00Z` instead of
 * `2026-05-09T14:30:00.000Z`. Used by SAS / SigV4 / log-filename
 * builders that need a one-second-resolution timestamp string. The strip lives
 * in one place so every caller agrees on the shape.
 *
 * @example
 *   b.time.toIso8601NoMs("2026-05-09T14:30:00.789Z");
 *   // → "2026-05-09T14:30:00Z"
 *
 *   b.time.toIso8601NoMs(new Date(Date.UTC(2026, 4, 9, 14, 30, 0)));
 *   // → "2026-05-09T14:30:00Z"
 */
function toIso8601NoMs(input) {
  var d = _toDate(input);
  return stripIsoMilliseconds(d.toISOString());
}

/**
 * @primitive b.time.stripIsoMilliseconds
 * @signature b.time.stripIsoMilliseconds(text)
 * @since     0.18.31
 * @status    stable
 * @related   b.time.toIso8601NoMs
 *
 * Drop a trailing `.sssZ` down to `Z`, leaving anything else alone. The half
 * of `toIso8601NoMs` that works on a STRING, so a caller comparing two
 * timestamps at one-second resolution can normalize both without going through
 * a `Date` — and without running a pattern over a value that arrived on the
 * wire.
 *
 * @example
 *   b.time.stripIsoMilliseconds("2026-05-09T14:30:00.789Z");
 *   // → "2026-05-09T14:30:00Z"
 *
 *   b.time.stripIsoMilliseconds("2026-05-09T14:30:00Z");
 *   // → "2026-05-09T14:30:00Z"
 */
function stripIsoMilliseconds(text) {
  if (typeof text !== "string" || text.length < ISO_MS_LENGTH) return text;
  var at = text.length - ISO_MS_LENGTH;
  if (text.charAt(at) !== "." || text.charAt(text.length - 1) !== "Z") return text;
  for (var i = at + 1; i < text.length - 1; i += 1) {
    if (!codepointClass.isAsciiDigit(text.charCodeAt(i))) return text;
  }
  return text.slice(0, at) + "Z";
}

module.exports = {
  toParts:      toParts,
  format:       format,
  tzOffsetMs:   tzOffsetMs,
  startOfDay:   startOfDay,
  endOfDay:     endOfDay,
  addDays:      addDays,
  addMonths:    addMonths,
  diffDays:     diffDays,
  parseISO:     parseISO,
  readDate:     readDate,
  readTime:     readTime,
  readDateTime: readDateTime,
  toIso8601NoMs: toIso8601NoMs,
  stripIsoMilliseconds: stripIsoMilliseconds,
  TimeError:    TimeError,
};
