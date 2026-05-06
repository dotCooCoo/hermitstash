"use strict";
/**
 * time — timezone-aware datetime arithmetic + formatting on top of
 * native `Intl.DateTimeFormat`. No TZ-database vendor; operators get
 * the IANA names Node's ICU build supports (full set on every
 * mainstream platform).
 *
 *   b.time.toParts(d, { timezone: "America/New_York" })
 *     → { year, month, day, hour, minute, second, millisecond,
 *         weekday: 1..7, weekdayName: "Mon"..."Sun", dayOfYear }
 *
 *   b.time.format(d, { timezone, locale, dateStyle, timeStyle })
 *     → operator-readable string
 *
 *   b.time.startOfDay(d, { timezone })   → midnight in TZ
 *   b.time.endOfDay(d, { timezone })     → 23:59:59.999 in TZ
 *   b.time.addDays(d, n, { timezone })   → calendar-day add (DST-safe)
 *   b.time.addMonths(d, n, { timezone }) → calendar-month add
 *   b.time.diffDays(a, b, { timezone })  → calendar days between
 *
 *   b.time.parseISO(s)                   → Date | throws TimeError
 *   b.time.tzOffsetMs(d, timezone)       → ms offset (= local - utc)
 *
 * All ops accept Date, ms-epoch number, or ISO 8601 string. `timezone`
 * defaults to UTC. `locale` defaults to "en-US".
 */
var C = require("./constants");
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

function startOfDay(input, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  return _fromPartsAtTz({
    year: p.year, month: p.month, day: p.day,
    hour: 0, minute: 0, second: 0, millisecond: 0,
  }, tz);
}

function endOfDay(input, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var p = toParts(input, { timezone: tz });
  return _fromPartsAtTz({
    year: p.year, month: p.month, day: p.day,
    hour: 23, minute: 59, second: 59, millisecond: 999,
  }, tz);
}

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

function diffDays(a, b, opts) {
  opts = opts || {};
  var tz = opts.timezone || DEFAULT_TIMEZONE;
  var aMid = startOfDay(a, { timezone: tz });
  var bMid = startOfDay(b, { timezone: tz });
  return Math.round((bMid.getTime() - aMid.getTime()) / C.TIME.days(1));
}

var ISO_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[T\s](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?)?$/;

function parseISO(s) {
  if (typeof s !== "string" || s.length === 0) {
    throw new TimeError("time/bad-iso", "parseISO: input must be a non-empty string");
  }
  var m = ISO_RE.exec(s);
  if (!m) {
    throw new TimeError("time/bad-iso",
      "parseISO: not an ISO 8601 datetime: " + JSON.stringify(s));
  }
  var year   = parseInt(m[1], 10);
  var month  = parseInt(m[2], 10);
  var day    = parseInt(m[3], 10);
  var hour   = m[4] ? parseInt(m[4], 10) : 0;
  var minute = m[5] ? parseInt(m[5], 10) : 0;
  var second = m[6] ? parseInt(m[6], 10) : 0;
  var msStr  = m[7] || "";
  var ms     = msStr ? parseInt((msStr + "000").slice(0, 3), 10) : 0;
  var tz     = m[0x8];

  if (month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59 || second > 59) {
    throw new TimeError("time/bad-iso",
      "parseISO: out-of-range component in " + JSON.stringify(s));
  }
  var utcMs;
  if (!tz) {
    utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  } else if (tz === "Z") {
    utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  } else {
    var sign = tz.charAt(0) === "-" ? -1 : 1;
    var hh   = parseInt(tz.slice(1, 3), 10);
    var mm   = parseInt(tz.slice(tz.length - 2), 10);
    var offsetMs = sign * C.TIME.seconds(hh * 3600 + mm * 60);
    utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms) - offsetMs;
  }
  return new Date(utcMs);
}

// toIso8601NoMs — emit ISO 8601 with the trailing `.\d{3}Z`
// milliseconds dropped (`2026-05-03T12:34:56Z` instead of
// `…:56.789Z`). Used by SAS / SigV4 / log filename builders that need
// a one-second-resolution timestamp string. Single source of truth so
// the strip pattern lives in one place.
var ISO_MS_RE = /\.\d{3}Z$/;
function toIso8601NoMs(input) {
  var d = _toDate(input);
  return d.toISOString().replace(ISO_MS_RE, "Z");
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
  toIso8601NoMs: toIso8601NoMs,
  ISO_MS_RE:    ISO_MS_RE,
  TimeError:    TimeError,
};
