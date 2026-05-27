"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("b.calendar namespace",            typeof b.calendar === "object");
  check("validate is fn",                  typeof b.calendar.validate === "function");
  check("fromIcal is fn",                  typeof b.calendar.fromIcal === "function");
  check("toIcal is fn",                    typeof b.calendar.toIcal === "function");
  check("expandRecurrence is fn",          typeof b.calendar.expandRecurrence === "function");
  check("CalendarError is class",          typeof b.calendar.CalendarError === "function");
  check("JSCAL_TYPES.Event",               b.calendar.JSCAL_TYPES.Event === "Event");
  check("JSCAL_FREQUENCIES.daily",         b.calendar.JSCAL_FREQUENCIES.daily === 1);
}

function testValidateHappyPath() {
  var ev = {
    "@type":  "Event",
    uid:      "0e612e8b-1c4f-4e30-8e6a-4adc4e8b1c4f",
    updated:  "2026-05-21T10:00:00Z",
    title:    "Sprint planning",
    start:    "2026-05-22T09:00:00",
    duration: "PT1H",
    timeZone: "America/Los_Angeles",
  };
  var rv = b.calendar.validate(ev);
  check("validate returns input on success", rv === ev);
}

function testValidateRefusalCases() {
  function expectCode(label, jsCal, codeFragment) {
    var threw = null;
    try { b.calendar.validate(jsCal); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFragment) !== -1);
  }
  expectCode("non-object refused",             null,                                    "calendar/bad-input");
  expectCode("bad @type refused",              { "@type": "Foo", uid: "x", updated: "2026-05-21T10:00:00Z" }, "calendar/bad-type");
  expectCode("missing uid refused",
    { "@type": "Event", updated: "2026-05-21T10:00:00Z" },                              "calendar/no-uid");
  expectCode("missing updated refused",
    { "@type": "Event", uid: "x" },                                                      "calendar/bad-updated");
  expectCode("non-UTC updated refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21 10:00:00" },                     "calendar/bad-updated");
  expectCode("non-RecurrenceRule @type refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", recurrenceRules: [{ "@type": "X" }] }, "calendar/bad-recurrence");
  expectCode("unknown frequency refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z",
      recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "fortnightly" }] },     "calendar/bad-recurrence");
  expectCode("bad duration refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", duration: "1h30m" }, "calendar/bad-duration");
  expectCode("alerts as array refused",
    { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z", alerts: [] },        "calendar/bad-alerts");
}

function testFromIcalRoundTrip() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:abc@example.com\r\n" +
    "DTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\n" +
    "DURATION:PT1H\r\n" +
    "SUMMARY:Sprint planning\r\n" +
    "DESCRIPTION:Review last week + plan next\r\n" +
    "LOCATION:Meeting Room A\r\n" +
    "END:VEVENT\r\n" +
    "END:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("fromIcal Event @type",            ev["@type"] === "Event");
  check("fromIcal uid preserved",          ev.uid === "abc@example.com");
  check("fromIcal updated → UTCDateTime",  ev.updated === "2026-05-21T10:00:00Z");
  check("fromIcal start → LocalDateTime",  ev.start === "2026-05-22T09:00:00");
  check("fromIcal title from SUMMARY",     ev.title === "Sprint planning");
  check("fromIcal description preserved",  ev.description === "Review last week + plan next");
  check("fromIcal location → locations[]", ev.locations && ev.locations.L1 &&
                                            ev.locations.L1.name === "Meeting Room A");
  // Round-trip back.
  var back = b.calendar.toIcal(ev);
  check("toIcal produces VCALENDAR envelope", /BEGIN:VCALENDAR/.test(back) && /END:VCALENDAR/.test(back));
  check("toIcal preserves UID",            /UID:abc@example\.com/.test(back));
  check("toIcal preserves SUMMARY",        /SUMMARY:Sprint planning/.test(back));
  check("toIcal preserves DTSTART",        /DTSTART:20260522T090000/.test(back));
}

function testFromIcalSafeIcalOptsForwarded() {
  // @opts documents safeIcalOpts as forwarded to b.safeIcal.parse.
  // Proof it actually reaches the parser: an unknown profile inside
  // safeIcalOpts must surface safeIcal's bad-opt refusal. If the opts
  // were dropped (or the whole outer opts passed instead), safeIcal
  // would default to "strict" and never throw.
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:a@b\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\nDURATION:PT1H\r\nSUMMARY:x\r\n" +
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
  var threw = null;
  try { b.calendar.fromIcal(ical, { safeIcalOpts: { profile: "bogus" } }); }
  catch (e) { threw = e; }
  check("fromIcal forwards safeIcalOpts to safeIcal.parse (bad profile refused)",
        threw && (threw.code || "").indexOf("safe-ical/bad-opt") !== -1);
  // And a VALID nested profile parses cleanly (no accidental refusal).
  var ev = b.calendar.fromIcal(ical, { safeIcalOpts: { profile: "balanced" } });
  check("fromIcal honors a valid nested safeIcalOpts profile", ev && ev["@type"] === "Event");
  // Backward-compat: the historically-working TOP-LEVEL parser-options
  // form must keep working (no patch-release regression).
  var threwTop = null;
  try { b.calendar.fromIcal(ical, { profile: "bogus" }); }
  catch (e) { threwTop = e; }
  check("fromIcal still honors a top-level profile (no regression)",
        threwTop && (threwTop.code || "").indexOf("safe-ical/bad-opt") !== -1);
  var evTop = b.calendar.fromIcal(ical, { profile: "balanced" });
  check("fromIcal parses with a valid top-level profile", evTop && evTop["@type"] === "Event");
}

function testFromIcalNoVevent() {
  var threw = null;
  try { b.calendar.fromIcal("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nEND:VCALENDAR\r\n"); }
  catch (e) { threw = e; }
  check("fromIcal with zero components throws", threw && (threw.code || "").indexOf("calendar/no-component") !== -1);
}

function testRrulePreserved() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:r@x\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\n" +
    "RRULE:FREQ=WEEKLY;COUNT=5;BYDAY=MO,WE,FR\r\n" +
    "SUMMARY:Standup\r\n" +
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("RRULE → recurrenceRules[0]",       Array.isArray(ev.recurrenceRules) && ev.recurrenceRules.length === 1);
  check("frequency mapped to lower-case",   ev.recurrenceRules[0].frequency === "weekly");
  check("COUNT mapped",                     ev.recurrenceRules[0].count === 5);
  check("BYDAY mapped to NDay[]",           Array.isArray(ev.recurrenceRules[0].byDay) &&
                                             ev.recurrenceRules[0].byDay[0].day === "mo");
}

function testExpandRecurrenceDaily() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-daily",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 5 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
  check("daily expand emits 5 instances",   instances.length === 5);
  check("first instance at start",          instances[0] === "2026-05-22T09:00:00Z");
  check("fifth instance at start+4 days",   instances[4] === "2026-05-26T09:00:00Z");
}

function testExpandRecurrenceWeeklyInterval() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-weekly",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "weekly", interval: 2, count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-07-31T00:00:00Z" });
  check("weekly interval=2 emits 3",        instances.length === 3);
  check("second instance +14 days",         instances[1] === "2026-06-05T09:00:00Z");
  check("third instance +28 days",          instances[2] === "2026-06-19T09:00:00Z");
}

function testExpandRecurrenceUntil() {
  var ev = {
    "@type":  "Event",
    uid:      "expand-until",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", until: "2026-05-25T00:00:00Z" }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
  // Days 22, 23, 24 fire (the UNTIL stamp is inclusive of the start time but 25T00 cuts off the 25-09-00 instance).
  check("UNTIL bounds the expansion",       instances.length === 3);
  check("last instance is 2026-05-24",      instances[instances.length - 1] === "2026-05-24T09:00:00Z");
}

function testExpandRecurrenceCapEnforced() {
  var ev = {
    "@type":  "Event",
    uid:      "bomb",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T09:00:00",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 99999 }],                // allow:raw-byte-literal — recurrence-bomb attempt
  };
  var threw = null;
  try { b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2200-01-01T00:00:00Z" }); }
  catch (e) { threw = e; }
  check("oversize expansion span refused",  threw && (threw.code || "").indexOf("calendar/oversize-expansion-span") !== -1);

  // With a tight window the expansion completes but is capped by
  // MAX_EXPAND_INSTANCES.
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2030-05-22T00:00:00Z", max: 50 });
  check("instance count cap honoured",      instances.length <= 50);
}

function testUtcDtstartRoundTripPreserved() {
  // Codex P1 — DTSTART:...Z must produce a JSCalendar Event with
  // timeZone="Etc/UTC" so the round-trip back to iCalendar preserves
  // the `Z` suffix instead of emitting floating local time.
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:u@x\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000Z\r\nDURATION:PT1H\r\nSUMMARY:UTC test\r\n" +
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
  var ev = b.calendar.fromIcal(ical);
  check("UTC DTSTART → timeZone Etc/UTC",   ev.timeZone === "Etc/UTC");
  var back = b.calendar.toIcal(ev);
  check("toIcal preserves Z suffix",        /DTSTART:20260522T090000Z/.test(back));
  check("toIcal does NOT emit floating DTSTART", !/DTSTART:20260522T090000\r\n/.test(back));
  check("toIcal does NOT emit TZID for Etc/UTC", !/TZID=Etc\/UTC/.test(back));
}

function testFractionalSecondsStrippedInToIcal() {
  // Codex P2 — validate accepts fractional-second UTCDateTime but
  // toIcal MUST emit RFC 5545 form (no fractional seconds).
  var ev = {
    "@type":  "Event",
    uid:      "frac",
    updated:  "2026-05-21T10:00:00.123Z",
    title:    "frac",
    start:    "2026-05-22T09:00:00.456",
    duration: "PT1H",
    timeZone: "Etc/UTC",
  };
  var ical = b.calendar.toIcal(ev);
  check("fractional updated stripped in DTSTAMP", /DTSTAMP:20260521T100000Z/.test(ical));
  check("DTSTAMP does NOT carry fractional",     !/DTSTAMP:[^\r\n]*\.\d/.test(ical));
  check("fractional start stripped in DTSTART",   /DTSTART:20260522T090000Z/.test(ical));
  check("DTSTART does NOT carry fractional",     !/DTSTART:[^\r\n]*\.\d/.test(ical));
}

function testExpandRecurrenceByDayFilter() {
  // Codex P1 — FREQ=DAILY;BYDAY=MO must only emit Mondays.
  var ev = {
    "@type":  "Event",
    uid:      "mondays-only",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-18T09:00:00",                                                                   // 2026-05-18 is a Monday
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily",
                        byDay: [{ "@type": "NDay", day: "mo" }], count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-18T00:00:00Z", to: "2026-07-01T00:00:00Z" });
  check("BYDAY=MO emits 3 instances",      instances.length === 3);
  // 2026-05-18 (Mon), 2026-05-25 (Mon), 2026-06-01 (Mon).
  check("first Monday",                     instances[0] === "2026-05-18T09:00:00Z");
  check("second Monday is +7 days",         instances[1] === "2026-05-25T09:00:00Z");
  check("third Monday is +14 days",         instances[2] === "2026-06-01T09:00:00Z");
}

function testExpandRecurrenceByMonthFilter() {
  // FREQ=YEARLY;BYMONTH=1 — January-only birthday-class.
  var ev = {
    "@type":  "Event",
    uid:      "yearly-jan",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-01-15T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "yearly",
                        byMonth: ["1"], count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-01-01T00:00:00Z", to: "2030-01-01T00:00:00Z" });
  check("BYMONTH=1 yearly emits 3 Januaries", instances.length === 3);
  check("first January 2026",               instances[0] === "2026-01-15T09:00:00Z");
  check("third January 2028",               instances[2] === "2028-01-15T09:00:00Z");
}

// ---- v0.11.35 — VTODO → JSCalendar Task ----

function testVtodoToTaskRoundTrip() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
    "BEGIN:VTODO\r\nUID:task-1@x\r\n" +
    "DTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260522T090000\r\n" +
    "DUE:20260522T170000\r\n" +
    "DURATION:PT8H\r\n" +
    "STATUS:IN-PROCESS\r\n" +
    "PERCENT-COMPLETE:25\r\n" +
    "SUMMARY:Write docs\r\n" +
    "DESCRIPTION:JSCalendar Task release notes\r\n" +
    "END:VTODO\r\n" +
    "END:VCALENDAR\r\n";
  var task = b.calendar.fromIcal(ical);
  check("VTODO → Task @type",                  task["@type"] === "Task");
  check("VTODO uid",                            task.uid === "task-1@x");
  check("VTODO start mapped",                   task.start === "2026-05-22T09:00:00");
  check("VTODO due mapped",                     task.due === "2026-05-22T17:00:00");
  check("DURATION → estimatedDuration",         task.estimatedDuration === "PT8H");
  check("STATUS IN-PROCESS → progress in-process", task.progress === "in-process");
  check("PERCENT-COMPLETE 25 mapped",           task.percentComplete === 25);
  check("title from SUMMARY",                   task.title === "Write docs");

  // Round-trip back to iCalendar.
  var back = b.calendar.toIcal(task);
  check("toIcal emits BEGIN:VTODO",             /BEGIN:VTODO/.test(back));
  check("toIcal emits END:VTODO",               /END:VTODO/.test(back));
  check("toIcal does NOT emit VEVENT",          !/BEGIN:VEVENT/.test(back));
  check("toIcal preserves UID",                 /UID:task-1@x/.test(back));
  check("toIcal preserves DTSTART",             /DTSTART:20260522T090000/.test(back));
  check("toIcal preserves DUE",                 /DUE:20260522T170000/.test(back));
  check("toIcal preserves DURATION",            /DURATION:PT8H/.test(back));
  check("toIcal preserves STATUS",              /STATUS:IN-PROCESS/.test(back));
  check("toIcal preserves PERCENT-COMPLETE",    /PERCENT-COMPLETE:25/.test(back));
}

function testTaskValidateRefusals() {
  function expectCode(label, jsCal, codeFragment) {
    var threw = null;
    try { b.calendar.validate(jsCal); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFragment) !== -1);
  }
  expectCode("Task with bad progress refused",
    { "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z", progress: "started" }, "calendar/bad-progress");
  expectCode("Task with bad percent refused",
    { "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z", percentComplete: 150 }, "calendar/bad-percent");
  expectCode("Task with bad due refused",
    { "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z", due: "not-a-datetime" }, "calendar/bad-due");
  expectCode("Task with bad estimatedDuration refused",
    { "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z", estimatedDuration: "8h" }, "calendar/bad-duration");
  // Happy path.
  var rv = b.calendar.validate({
    "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z",
    progress: "needs-action", percentComplete: 0, due: "2026-05-22T17:00:00",
  });
  check("valid Task accepted",                  rv && rv["@type"] === "Task");
}

function testCompletedTaskWithProgressUpdated() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VTODO\r\nUID:done@x\r\n" +
    "DTSTAMP:20260521T100000Z\r\n" +
    "STATUS:COMPLETED\r\n" +
    "PERCENT-COMPLETE:100\r\n" +
    "COMPLETED:20260521T093000Z\r\n" +
    "SUMMARY:Reticulate splines\r\n" +
    "END:VTODO\r\nEND:VCALENDAR\r\n";
  var task = b.calendar.fromIcal(ical);
  check("progress completed mapped",            task.progress === "completed");
  check("percentComplete 100",                  task.percentComplete === 100);
  check("COMPLETED → progressUpdated UTC",      task.progressUpdated === "2026-05-21T09:30:00Z");
  var back = b.calendar.toIcal(task);
  check("toIcal preserves COMPLETED",           /COMPLETED:20260521T093000Z/.test(back));
}

function testTaskProgressFailedRefused() {
  // Codex P1 — `progress: "failed"` cannot round-trip through RFC 5545
  // STATUS (no FAILED value defined). Catalogue refuses.
  var threw = null;
  try {
    b.calendar.validate({
      "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z",
      progress: "failed",
    });
  } catch (e) { threw = e; }
  check("progress=failed refused (no RFC 5545 STATUS)",
        threw && (threw.code || "").indexOf("calendar/bad-progress") !== -1);
}

function testTaskPercentCompleteIntegerRequired() {
  // Codex P2 — JSCalendar UnsignedInt + iCal PERCENT-COMPLETE both
  // require integer. 12.5 must refuse.
  var threw = null;
  try {
    b.calendar.validate({
      "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z",
      percentComplete: 12.5,
    });
  } catch (e) { threw = e; }
  check("percentComplete float refused",
        threw && (threw.code || "").indexOf("calendar/bad-percent") !== -1);
  // 12 still accepted.
  var rv = b.calendar.validate({
    "@type": "Task", uid: "x", updated: "2026-05-21T10:00:00Z",
    percentComplete: 12,
  });
  check("integer percentComplete accepted", rv && rv["@type"] === "Task");
}

function testExpandRecurrenceByYearDay() {
  // FREQ=DAILY;BYYEARDAY=1 — daily step, filtered to Jan 1.
  // (RFC 5545 §3.3.10 BY* filters narrow the stepped candidates;
  // expanding within a yearly step is the BYSETPOS-class restructure
  // that's deferred. With daily stepping, BYYEARDAY=1 fires Jan 1 of
  // each year.)
  var ev = {
    "@type":  "Event",
    uid:      "yearday",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2024-01-01T12:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily",
                        byYearDay: [1], count: 3 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2024-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z" });
  check("BYYEARDAY=1 with daily step emits Jan 1 of each year",
        instances.length === 3 &&
        instances[0] === "2024-01-01T12:00:00Z" &&
        instances[1] === "2025-01-01T12:00:00Z" &&
        instances[2] === "2026-01-01T12:00:00Z");
}

function testExpandRecurrenceByYearDayNegative() {
  // BYYEARDAY=-1 — last day of year. Daily step + filter — last day
  // of each year fires.
  var ev = {
    "@type":  "Event",
    uid:      "yearday-neg",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2025-01-01T12:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily",
                        byYearDay: [-1], count: 2 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2025-01-01T00:00:00Z", to: "2028-01-01T00:00:00Z" });
  check("BYYEARDAY=-1 emits Dec 31 of each year",
        instances.length === 2 &&
        instances[0] === "2025-12-31T12:00:00Z" &&
        instances[1] === "2026-12-31T12:00:00Z");
}

function testExpandRecurrenceByWeekNo() {
  // FREQ=YEARLY;BYWEEKNO=1 — first ISO week of the year.
  // ISO 8601 week 1 is the week containing the first Thursday.
  var ev = {
    "@type":  "Event",
    uid:      "weekno",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-01-05T12:00:00",                                                                   // 2026-01-05 is a Monday in ISO week 2 (week 1 = Dec 29 2025 - Jan 4 2026)
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "weekly",
                        byWeekNo: [1], count: 2 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-01-01T00:00:00Z", to: "2028-01-01T00:00:00Z" });
  // Weekly stepping starting Jan 5 — most weeks don't match BYWEEKNO=1.
  // The cap-bounded loop walks through; at most 2 ISO-week-1 instances
  // within the 2-year span fire (2027 week 1, 2028 week 1 roughly).
  check("BYWEEKNO filter produces a bounded set",  instances.length <= 2);
}

function testExpandRecurrenceByHour() {
  // FREQ=DAILY;BYHOUR=9,17 — twice-daily at 9am and 5pm.
  // expandRecurrence steps daily, so each day produces ONE instance
  // (at the start's hour); BYHOUR can only match if the start hour
  // is in the set OR if the rule advances hour. Step the start at
  // 09:00, daily — instances stay at 09:00. So BYHOUR=9,17 still
  // matches the 09:00 one. To exercise BYHOUR fully an HOURLY rule
  // is needed.
  var ev = {
    "@type":  "Event",
    uid:      "hourly",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-22T08:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "hourly",
                        byHour: [9, 17], count: 6 }],
  };
  var instances = b.calendar.expandRecurrence(ev, { from: "2026-05-22T00:00:00Z", to: "2026-05-25T00:00:00Z" });
  check("BYHOUR emits up to 6 instances",   instances.length === 6);
  // First emission is the first hour at/after start where hour ∈ {9,17}.
  check("first emission is hour 9",          /T09:00:00Z$/.test(instances[0]));
  // Pattern alternates 9,17,9,17,9,17 — hours 9 or 17 only.
  check("every instance is hour 9 or 17",    instances.every(function (s) { return /T(09|17):00:00Z$/.test(s); }));
}

function testByWeekNoIsoWeekYearGuard() {
  // 2021-01-01 is ISO week 53 of WEEK-YEAR 2020 (2021 has only 52 ISO
  // weeks). A 2021-anchored BYWEEKNO=53 rule must NOT match Jan 1
  // 2021 — the candidate's ISO week-year differs from its Gregorian
  // year, so the rule rejects it.
  var ev = {
    "@type":  "Event",
    uid:      "isoweekyear",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2021-01-01T00:00:00",
    timeZone: "Etc/UTC",
    duration: "PT1H",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "yearly", byWeekNo: [53] }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2021-01-01T00:00:00Z", to: "2021-12-31T23:59:59Z" });
  check("BYWEEKNO=53 rejects Jan 1 2021 (week 53 of 2020)", insts.length === 0);

  // Boundary positive: Dec 28 2020 IS ISO week 53 of week-year 2020,
  // and its Gregorian year matches — must emit.
  var ev2 = {
    "@type":  "Event",
    uid:      "isoweekyear-positive",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2020-12-28T00:00:00",
    timeZone: "Etc/UTC",
    duration: "PT1H",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "yearly", byWeekNo: [53] }],
  };
  var insts2 = b.calendar.expandRecurrence(ev2, { from: "2020-12-28T00:00:00Z", to: "2020-12-31T23:59:59Z" });
  check("BYWEEKNO=53 accepts Dec 28 2020 (week 53 of week-year 2020)", insts2.length >= 1);
}

function testByTimeAllInvalidIsNoop() {
  // byHour:[99] — every value is out of range. Must drop to no-op
  // (rule continues unfiltered) rather than match-nothing.
  var ev = {
    "@type":  "Event",
    uid:      "byhour-noop",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-21T10:00:00",
    timeZone: "Etc/UTC",
    duration: "PT1H",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", byHour: [99] }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-21T00:00:00Z", to: "2026-05-25T23:59:59Z" });
  check("byHour:[99] all-invalid drops to no-op (5 daily instances)", insts.length === 5);

  // Mixed valid + invalid — valid ones still filter
  var ev2 = {
    "@type":  "Event",
    uid:      "byhour-mixed",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-21T00:00:00",
    timeZone: "Etc/UTC",
    duration: "PT1H",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "hourly", byHour: [9, 99, 17] }],
  };
  var insts2 = b.calendar.expandRecurrence(ev2, { from: "2026-05-21T00:00:00Z", to: "2026-05-21T23:59:59Z" });
  check("byHour:[9,99,17] mixed keeps valid (9 + 17 = 2 hours / day)", insts2.length === 2);
}

function testVjournalToJsCalNote() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VJOURNAL\r\nUID:j1@example.com\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DTSTART:20260521T120000Z\r\nSUMMARY:Sprint standup\r\n" +
    "DESCRIPTION:Day 1 of the sprint.\r\nSTATUS:FINAL\r\n" +
    "END:VJOURNAL\r\nEND:VCALENDAR\r\n";
  var note = b.calendar.fromIcal(ical);
  check("VJOURNAL maps to Note @type",       note["@type"] === "Note");
  check("Note carries uid",                  note.uid === "j1@example.com");
  check("Note carries title",                note.title === "Sprint standup");
  check("Note carries description",          note.description === "Day 1 of the sprint.");
  check("Note carries lower-cased status",   note.status === "final");
  check("Note maps UTC DTSTART to Etc/UTC",  note.timeZone === "Etc/UTC");
  check("Note carries start LocalDateTime",  note.start === "2026-05-21T12:00:00");
}

function testVjournalMultipleDescriptionJoined() {
  // RFC 5545 §3.6.3 — VJOURNAL is the only component that may carry
  // multiple DESCRIPTION properties. Confirm join with blank-line.
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VJOURNAL\r\nUID:j2\r\nDTSTAMP:20260521T100000Z\r\n" +
    "DESCRIPTION:Entry one.\r\nDESCRIPTION:Entry two.\r\n" +
    "END:VJOURNAL\r\nEND:VCALENDAR\r\n";
  var note = b.calendar.fromIcal(ical);
  check("multi-DESCRIPTION joined with blank line", note.description === "Entry one.\n\nEntry two.");
}

function testNoteToIcalRoundTrip() {
  var note = {
    "@type":   "Note",
    uid:       "j1@example.com",
    updated:   "2026-05-21T10:00:00Z",
    title:     "Sprint standup",
    start:     "2026-05-21T12:00:00",
    timeZone:  "Etc/UTC",
    status:    "final",
    description: "Day 1 of the sprint.",
  };
  check("Note validates",                    b.calendar.validate(note) === note);
  var ical = b.calendar.toIcal(note);
  check("toIcal emits BEGIN:VJOURNAL",       ical.indexOf("BEGIN:VJOURNAL") !== -1);
  check("toIcal emits STATUS:FINAL",         ical.indexOf("STATUS:FINAL") !== -1);
  check("toIcal emits UTC DTSTART",          ical.indexOf("DTSTART:20260521T120000Z") !== -1);
  check("toIcal does NOT emit DURATION",     ical.indexOf("DURATION:") === -1);
  check("toIcal does NOT emit DUE",          ical.indexOf("DUE:") === -1);
}

function testNoteRefusalCases() {
  function expectCode(label, jsCal, codeFragment) {
    var threw = null;
    try { b.calendar.validate(jsCal); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFragment) !== -1);
  }
  expectCode("Note with due refused",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", due: "2026-05-22T00:00:00" },
    "calendar/bad-due");
  expectCode("Note with progress refused",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", progress: "completed" },
    "calendar/bad-progress");
  expectCode("Note with duration refused",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", duration: "PT1H" },
    "calendar/bad-duration");
  expectCode("Note with percentComplete refused",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", percentComplete: 50 },
    "calendar/bad-percent");
  expectCode("Note with progressUpdated refused",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", progressUpdated: "2026-05-21T10:00:00Z" },
    "calendar/bad-progress-updated");
  expectCode("Note with non-VJOURNAL status refused (in-process is VTODO-only)",
    { "@type": "Note", uid: "x", updated: "2026-05-21T10:00:00Z", status: "in-process" },
    "calendar/bad-note-status");
}

function testMultipleRecurrenceRulesUnion() {
  // RFC 8984 §4.3.2 — multiple RecurrenceRule objects expand
  // independently and union; per-rule count applies per rule.
  var ev = {
    "@type":  "Event",
    uid:      "multi-rule",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-19T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [
      { "@type": "RecurrenceRule", frequency: "daily",   count: 3 },
      { "@type": "RecurrenceRule", frequency: "monthly", count: 3 },
    ],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-18T00:00:00Z", to: "2026-08-01T00:00:00Z" });
  // Day 1 of the daily rule == first instance of the monthly rule — dedup.
  check("union: dedup leaves 5 instances (3 daily + 3 monthly - 1 overlap)", insts.length === 5);
  check("union: sorted ascending", insts[0] === "2026-05-19T09:00:00Z" &&
                                    insts[4] === "2026-07-19T09:00:00Z");
}

function testRecurrenceRulesDedupSameRule() {
  var ev = {
    "@type":  "Event",
    uid:      "dup-rule",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-19T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [
      { "@type": "RecurrenceRule", frequency: "daily", count: 3 },
      { "@type": "RecurrenceRule", frequency: "daily", count: 3 },
    ],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-18T00:00:00Z", to: "2026-06-01T00:00:00Z" });
  check("duplicate rules dedupe", insts.length === 3);
}

function testMultipleRecurrenceRulesBoundedByMax() {
  var ev = {
    "@type":  "Event",
    uid:      "bounded-rule",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-19T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [
      { "@type": "RecurrenceRule", frequency: "daily", count: 10 },
      { "@type": "RecurrenceRule", frequency: "daily", count: 10, interval: 2 },
    ],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-18T00:00:00Z", to: "2026-07-01T00:00:00Z", max: 5 });
  check("global maxCount applies to unioned set", insts.length === 5);
}

function testGroupValidateHappyPath() {
  var group = {
    "@type": "Group",
    uid:     "g1",
    updated: "2026-05-21T10:00:00Z",
    name:    "Sprint cadence",
    description: "Recurring rituals for the team",
    categories: { sprint: true, ops: true },
    entries: [
      { "@type": "Event", uid: "e1", updated: "2026-05-21T10:00:00Z",
        start: "2026-05-22T09:00:00", timeZone: "Etc/UTC", duration: "PT1H", title: "Standup" },
      { "@type": "Task",  uid: "t1", updated: "2026-05-21T10:00:00Z",
        title: "Retro prep", progress: "needs-action" },
      { "@type": "Note",  uid: "n1", updated: "2026-05-21T10:00:00Z",
        title: "Postmortem outline", status: "draft" },
    ],
  };
  check("Group validate returns input on success", b.calendar.validate(group) === group);
}

function testGroupRefusalCases() {
  function expectCode(label, obj, codeFrag) {
    var threw = null;
    try { b.calendar.validate(obj); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFrag) !== -1);
  }
  expectCode("empty entries refused",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z", entries: [] },
    "calendar/bad-entries");
  expectCode("Group with entry-specific field refused",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z",
      entries: [{ "@type": "Event", uid: "a", updated: "2026-05-21T10:00:00Z" }],
      start: "2026-05-22T09:00:00" },
    "calendar/bad-group");
  expectCode("Group nesting refused",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z",
      entries: [{ "@type": "Group", uid: "nested", updated: "2026-05-21T10:00:00Z",
                  entries: [{ "@type": "Event", uid: "a", updated: "2026-05-21T10:00:00Z" }] }] },
    "calendar/bad-entries");
  expectCode("non-true category value refused",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z",
      entries: [{ "@type": "Event", uid: "a", updated: "2026-05-21T10:00:00Z" }],
      categories: { sprint: "yes" } },
    "calendar/bad-categories");
  // Codex P1 — `typeof null === "object"` would let `categories: null`
  // skip the type check + cause Object.keys(null) to throw a raw
  // TypeError instead of a structured `calendar/bad-categories`.
  expectCode("null categories refused with structured error",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z",
      entries: [{ "@type": "Event", uid: "a", updated: "2026-05-21T10:00:00Z" }],
      categories: null },
    "calendar/bad-categories");
  expectCode("non-string source refused",
    { "@type": "Group", uid: "x", updated: "2026-05-21T10:00:00Z",
      entries: [{ "@type": "Event", uid: "a", updated: "2026-05-21T10:00:00Z" }],
      source: 42 },
    "calendar/bad-source");
}

function testGroupToIcalSingleEnvelope() {
  var group = {
    "@type": "Group",
    uid:     "g2",
    updated: "2026-05-21T10:00:00Z",
    name:    "Multi",
    entries: [
      { "@type": "Event", uid: "e1", updated: "2026-05-21T10:00:00Z",
        start: "2026-05-22T09:00:00", timeZone: "Etc/UTC", title: "Standup" },
      { "@type": "Task",  uid: "t1", updated: "2026-05-21T10:00:00Z",
        title: "Retro prep" },
      { "@type": "Note",  uid: "n1", updated: "2026-05-21T10:00:00Z",
        title: "Notes" },
    ],
  };
  var ical = b.calendar.toIcal(group);
  check("Group emits single VCALENDAR wrap",     (ical.match(/BEGIN:VCALENDAR/g) || []).length === 1);
  check("Group emits VEVENT for Event entry",    ical.indexOf("BEGIN:VEVENT") !== -1);
  check("Group emits VTODO for Task entry",      ical.indexOf("BEGIN:VTODO") !== -1);
  check("Group emits VJOURNAL for Note entry",   ical.indexOf("BEGIN:VJOURNAL") !== -1);
  check("Group emits only one PRODID",           (ical.match(/PRODID:/g) || []).length === 1);
}

function testBysetposLastFridayOfMonth() {
  var ev = {
    "@type":  "Event",
    uid:      "lastfri",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-01T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "monthly",
                        byDay: ["FR"], bySetPos: [-1], count: 3 }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-01T00:00:00Z", to: "2026-09-01T00:00:00Z" });
  check("BYSETPOS=-1: 3 last-Friday instances", insts.length === 3);
  check("May 2026 last Friday = May 29",        insts[0] === "2026-05-29T09:00:00Z");
  check("Jun 2026 last Friday = Jun 26",        insts[1] === "2026-06-26T09:00:00Z");
}

function testBysetposSecondTuesdayOfMonth() {
  var ev = {
    "@type":  "Event",
    uid:      "secondtue",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-01T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "monthly",
                        byDay: ["TU"], bySetPos: [2], count: 2 }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-01T00:00:00Z", to: "2026-08-01T00:00:00Z" });
  check("BYSETPOS=2: second Tuesday count = 2", insts.length === 2);
  check("May 2026 2nd Tuesday = May 12",        insts[0] === "2026-05-12T09:00:00Z");
}

function testBysetposYearlyFirstSundayOfOctober() {
  // DST-end pattern — "first Sunday of October each year".
  var ev = {
    "@type":  "Event",
    uid:      "dstend",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-10-01T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "yearly",
                        byMonth: [10], byDay: ["SU"], bySetPos: [1], count: 3 }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-10-01T00:00:00Z", to: "2030-01-01T00:00:00Z" });
  check("YEARLY BYSETPOS=1 emits 3 instances", insts.length === 3);
  check("2026 first Sunday of Oct = Oct 4",    insts[0] === "2026-10-04T09:00:00Z");
}

function testBysetposCombinedPositions() {
  var ev = {
    "@type":  "Event",
    uid:      "firstlast",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-01T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "monthly",
                        byDay: ["MO", "TU", "WE", "TH", "FR"],
                        bySetPos: [1, -1], count: 4 }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-05-01T00:00:00Z", to: "2026-08-01T00:00:00Z" });
  check("BYSETPOS=[1,-1]: first+last weekday of month, 4 total", insts.length === 4);
}

function testBysetposNeverEmitsBeforeStart() {
  // Codex P1 — BYSETPOS path enumerates from the period boundary
  // (month/year/week start), so without a DTSTART floor it could
  // emit instances from BEFORE the rule's start. Start = May 20
  // Friday; BYDAY=FR;BYSETPOS=1 — the candidate set for May would
  // normally include May 1 (first Friday). The detector confirms
  // pre-start instances are refused.
  var ev = {
    "@type":  "Event",
    uid:      "pre-start",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-20T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "monthly",
                        byDay: ["FR"], bySetPos: [1], count: 3 }],
  };
  var insts = b.calendar.expandRecurrence(ev, { from: "2026-01-01T00:00:00Z", to: "2026-12-01T00:00:00Z" });
  check("BYSETPOS=1 + start mid-month: no instances before start",
    insts.every(function (iso) { return iso >= "2026-05-20T00:00:00Z"; }));
  // First emission must be the first BY*-matching candidate that is
  // AT OR AFTER start — for FR;BYSETPOS=1 starting May 20 the first
  // satisfying entry IS the May-period first-Friday = May 1 (dropped)
  // → June first-Friday = June 5.
  check("first emission is first Friday of June (May's was pre-start)",
    insts[0] === "2026-06-05T09:00:00Z");
}

function testBysetposRefusesDailyFrequency() {
  var ev = {
    "@type":  "Event",
    uid:      "baddaily",
    updated:  "2026-05-21T10:00:00Z",
    start:    "2026-05-01T09:00:00",
    timeZone: "Etc/UTC",
    recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", bySetPos: [1] }],
  };
  var threw = null;
  try { b.calendar.expandRecurrence(ev, { from: "2026-05-01T00:00:00Z", to: "2026-08-01T00:00:00Z" }); }
  catch (e) { threw = e; }
  check("BYSETPOS+DAILY refused", threw && (threw.code || "").indexOf("calendar/bad-recurrence") !== -1);
}

function testMixedVcalendarReturnsArray() {
  var ical =
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n" +
    "BEGIN:VEVENT\r\nUID:e1\r\nDTSTAMP:20260521T100000Z\r\nSUMMARY:Event\r\nEND:VEVENT\r\n" +
    "BEGIN:VTODO\r\nUID:t1\r\nDTSTAMP:20260521T100000Z\r\nSUMMARY:Task\r\nEND:VTODO\r\n" +
    "END:VCALENDAR\r\n";
  var rv = b.calendar.fromIcal(ical);
  check("mixed VCALENDAR returns array",        Array.isArray(rv) && rv.length === 2);
  check("first element is Event",               rv[0]["@type"] === "Event");
  check("second element is Task",               rv[1]["@type"] === "Task");
}

function testJmapCatalogueCarriesCalendarMethods() {
  var reg = b.mail.serverRegistry.create({
    protocol:  "jmap",
    defaults:  {
      "CalendarEvent/get": { fn: function () {}, maxHandlerBytes: 1024, maxHandlerMs: 100 },          // allow:raw-byte-literal
    },
  });
  check("CalendarEvent/get accepted in JMAP catalogue", reg && typeof reg.dispatch === "function");
}

function run() {
  testSurface();
  testValidateHappyPath();
  testValidateRefusalCases();
  testFromIcalRoundTrip();
  testFromIcalSafeIcalOptsForwarded();
  testFromIcalNoVevent();
  testRrulePreserved();
  testExpandRecurrenceDaily();
  testExpandRecurrenceWeeklyInterval();
  testExpandRecurrenceUntil();
  testExpandRecurrenceCapEnforced();
  testUtcDtstartRoundTripPreserved();
  testFractionalSecondsStrippedInToIcal();
  testExpandRecurrenceByDayFilter();
  testExpandRecurrenceByMonthFilter();
  // v0.11.35 — VTODO → JSCalendar Task
  testVtodoToTaskRoundTrip();
  testTaskValidateRefusals();
  testCompletedTaskWithProgressUpdated();
  testTaskProgressFailedRefused();
  testTaskPercentCompleteIntegerRequired();
  // v0.11.36 — BYYEARDAY / BYWEEKNO / BYHOUR filters
  testExpandRecurrenceByYearDay();
  testExpandRecurrenceByYearDayNegative();
  testExpandRecurrenceByWeekNo();
  testExpandRecurrenceByHour();
  testByWeekNoIsoWeekYearGuard();
  testByTimeAllInvalidIsNoop();
  testVjournalToJsCalNote();
  testVjournalMultipleDescriptionJoined();
  testNoteToIcalRoundTrip();
  testNoteRefusalCases();
  testMultipleRecurrenceRulesUnion();
  testRecurrenceRulesDedupSameRule();
  testMultipleRecurrenceRulesBoundedByMax();
  testGroupValidateHappyPath();
  testGroupRefusalCases();
  testGroupToIcalSingleEnvelope();
  testBysetposLastFridayOfMonth();
  testBysetposSecondTuesdayOfMonth();
  testBysetposYearlyFirstSundayOfOctober();
  testBysetposCombinedPositions();
  testBysetposNeverEmitsBeforeStart();
  testBysetposRefusesDailyFrequency();
  testMixedVcalendarReturnsArray();
  testJmapCatalogueCarriesCalendarMethods();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[calendar] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
