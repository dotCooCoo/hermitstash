"use strict";
/**
 * b.time — timezone-aware datetime arithmetic + formatting.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("b.time namespace present",        typeof b.time === "object");
  check("b.time.toParts is fn",            typeof b.time.toParts === "function");
  check("b.time.format is fn",             typeof b.time.format === "function");
  check("b.time.startOfDay is fn",         typeof b.time.startOfDay === "function");
  check("b.time.endOfDay is fn",           typeof b.time.endOfDay === "function");
  check("b.time.addDays is fn",            typeof b.time.addDays === "function");
  check("b.time.addMonths is fn",          typeof b.time.addMonths === "function");
  check("b.time.diffDays is fn",           typeof b.time.diffDays === "function");
  check("b.time.parseISO is fn",           typeof b.time.parseISO === "function");
  check("b.time.tzOffsetMs is fn",         typeof b.time.tzOffsetMs === "function");

  // ---- toParts ----
  // Anchor: 2026-04-30T14:32:00Z (a Thursday).
  var anchor = new Date(Date.UTC(2026, 3, 30, 14, 32, 0));
  var pUtc = b.time.toParts(anchor);
  check("toParts UTC: year",                pUtc.year === 2026);
  check("toParts UTC: month",               pUtc.month === 4);
  check("toParts UTC: day",                 pUtc.day === 30);
  check("toParts UTC: hour",                pUtc.hour === 14);
  check("toParts UTC: minute",              pUtc.minute === 32);
  check("toParts UTC: weekday is Thursday", pUtc.weekday === 4);
  check("toParts UTC: weekdayName Thu",     pUtc.weekdayName === "Thu");

  // Same instant in America/New_York → 14:32 UTC = 10:32 EDT (DST in April)
  var pNyc = b.time.toParts(anchor, { timezone: "America/New_York" });
  check("toParts NYC: hour shifted to 10",  pNyc.hour === 10);
  check("toParts NYC: same day (April)",    pNyc.day === 30);

  // ---- format (default + dateStyle) ----
  var fDefault = b.time.format(anchor, { timezone: "UTC" });
  check("format: returns a string",          typeof fDefault === "string" && fDefault.length > 0);
  var fLong = b.time.format(anchor, { timezone: "UTC", dateStyle: "full" });
  check("format dateStyle:full mentions year",  /2026/.test(fLong));

  // ---- tzOffsetMs ----
  var offUtc = b.time.tzOffsetMs(anchor, "UTC");
  check("tzOffsetMs UTC = 0",                offUtc === 0);
  var offNyc = b.time.tzOffsetMs(anchor, "America/New_York");
  // April 30 = EDT = UTC-4 = -14400000 ms
  check("tzOffsetMs NYC EDT = -4h",          offNyc === -14400000);
  // January 30 = EST = UTC-5
  var winter = new Date(Date.UTC(2026, 0, 30, 14, 32, 0));
  var offNycWinter = b.time.tzOffsetMs(winter, "America/New_York");
  check("tzOffsetMs NYC EST = -5h",          offNycWinter === -18000000);

  // ---- startOfDay / endOfDay ----
  var sodUtc = b.time.startOfDay(anchor, { timezone: "UTC" });
  check("startOfDay UTC: midnight",         sodUtc.getUTCHours() === 0 && sodUtc.getUTCMinutes() === 0);
  check("startOfDay UTC: same calendar day",sodUtc.getUTCDate() === 30);

  var eodUtc = b.time.endOfDay(anchor, { timezone: "UTC" });
  check("endOfDay UTC: 23:59:59.999",
        eodUtc.getUTCHours() === 23 && eodUtc.getUTCMinutes() === 59 &&
        eodUtc.getUTCSeconds() === 59 && eodUtc.getUTCMilliseconds() === 999);

  var sodNyc = b.time.startOfDay(anchor, { timezone: "America/New_York" });
  // 14:32 UTC on Apr 30 → 10:32 EDT Apr 30. Start of NYC day = 04:00 UTC Apr 30.
  check("startOfDay NYC: 04:00 UTC (DST)",
        sodNyc.getUTCHours() === 4 && sodNyc.getUTCDate() === 30);

  // ---- addDays ----
  var plus1 = b.time.addDays(anchor, 1, { timezone: "UTC" });
  check("addDays +1: day+1",                 plus1.getUTCDate() === 1 && plus1.getUTCMonth() === 4);
  var minus1 = b.time.addDays(anchor, -1, { timezone: "UTC" });
  check("addDays -1: day-1",                 minus1.getUTCDate() === 29);

  // DST-safe: adding 1 day across an EDT-EST boundary preserves
  // the local wall-clock hour. America/New_York: 2026-11-01 02:00
  // EDT → EST (fall back). Pick a date around the boundary.
  var preFallBack = new Date(Date.UTC(2026, 10, 1, 2, 0, 0));   // Nov 1 02:00 UTC
  var nextDayNyc  = b.time.addDays(preFallBack, 1, { timezone: "America/New_York" });
  var pPlus = b.time.toParts(preFallBack, { timezone: "America/New_York" });
  var pNext = b.time.toParts(nextDayNyc,  { timezone: "America/New_York" });
  check("addDays DST: same wall-clock hour preserved",
        pPlus.hour === pNext.hour && pPlus.minute === pNext.minute);

  // ---- addMonths ----
  // Jan 31 + 1 month = Feb 28 (or 29 in leap year). 2026 not a leap year.
  var jan31 = new Date(Date.UTC(2026, 0, 31, 12, 0, 0));
  var feb = b.time.addMonths(jan31, 1, { timezone: "UTC" });
  check("addMonths Jan31 + 1mo = Feb 28 (clamped)",
        feb.getUTCMonth() === 1 && feb.getUTCDate() === 28);

  // ---- diffDays ----
  var d1 = new Date(Date.UTC(2026, 3, 1, 0, 0, 0));
  var d2 = new Date(Date.UTC(2026, 3, 30, 0, 0, 0));
  check("diffDays: 29 calendar days",        b.time.diffDays(d1, d2, { timezone: "UTC" }) === 29);

  // ---- parseISO ----
  var iso1 = b.time.parseISO("2026-04-30T14:32:00Z");
  check("parseISO: Z timezone parsed",       iso1.getTime() === anchor.getTime());

  var iso2 = b.time.parseISO("2026-04-30T10:32:00-04:00");
  check("parseISO: -04:00 offset parsed",    iso2.getTime() === anchor.getTime());

  var iso3 = b.time.parseISO("2026-04-30");
  check("parseISO: date-only → UTC midnight",
        iso3.getUTCFullYear() === 2026 && iso3.getUTCMonth() === 3 && iso3.getUTCDate() === 30);

  // Fractional seconds
  var iso4 = b.time.parseISO("2026-04-30T14:32:00.123Z");
  check("parseISO: fractional seconds",      iso4.getUTCMilliseconds() === 123);

  // ---- parseISO: rejects ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parseISO reject: " + label, threw && codeRe.test(threw.code || ""));
  }
  rejects("non-string",     function () { b.time.parseISO(42); }, /time\/bad-iso/);
  rejects("malformed",      function () { b.time.parseISO("not-a-date"); }, /time\/bad-iso/);
  rejects("bad month (13)", function () { b.time.parseISO("2026-13-01"); }, /time\/bad-iso/);
  rejects("bad day (32)",   function () { b.time.parseISO("2026-04-32"); }, /time\/bad-iso/);

  // ---- _toDate variants ----
  rejects("invalid Date",  function () { b.time.toParts(new Date("nope")); }, /time\/invalid-date/);
  rejects("non-finite ms", function () { b.time.toParts(Infinity); }, /time\/invalid-ms/);

  // String input flows through parseISO
  var pStr = b.time.toParts("2026-04-30T14:32:00Z", { timezone: "UTC" });
  check("toParts: ISO string input",        pStr.year === 2026 && pStr.hour === 14);

  // Number (ms) input
  var pNum = b.time.toParts(anchor.getTime(), { timezone: "UTC" });
  check("toParts: ms-epoch input",          pNum.year === 2026);

  // ---- Bad timezone ----
  rejects("bad timezone", function () {
    b.time.toParts(anchor, { timezone: "Not/A_Real_TZ" });
  }, /time\/bad-timezone-or-locale/);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
