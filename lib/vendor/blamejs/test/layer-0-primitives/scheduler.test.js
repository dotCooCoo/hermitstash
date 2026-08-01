// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scheduler.nextBaselineFire — earliest UTC ms strictly after `after`
 * whose wall-clock in a timezone matches an HH:MM baseline.
 *
 * Pure function: known-answer vectors (UTC + a non-UTC zone + local
 * clock), the strictly-after / next-day rollover semantics, and the
 * malformed-input throws.
 *
 * Run standalone: `node test/layer-0-primitives/scheduler.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _iso(ms) { return new Date(ms).toISOString(); }

function testNextBaselineFireKnownAnswerUtc() {
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T01:00:00Z"));
  check("nextBaselineFire UTC known-answer",
        _iso(when) === "2026-05-09T02:30:00.000Z");
}

function testNextBaselineFireStrictlyAfter() {
  // `after` sitting exactly on the target minute must roll to the NEXT day.
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T02:30:00.000Z"));
  check("nextBaselineFire is strictly-after (rolls a day when at target)",
        _iso(when) === "2026-05-10T02:30:00.000Z");
}

function testNextBaselineFireRollsWhenPast() {
  var when = b.scheduler.nextBaselineFire("02:30", "UTC", new Date("2026-05-09T05:00:00Z"));
  check("nextBaselineFire rolls to next day when time already passed today",
        _iso(when) === "2026-05-10T02:30:00.000Z");
}

function testNextBaselineFireNonUtcZone() {
  // America/New_York on 2026-05-09 is EDT (UTC-4): 02:30 local = 06:30 UTC.
  var when = b.scheduler.nextBaselineFire("02:30", "America/New_York", new Date("2026-05-09T00:00:00Z"));
  check("nextBaselineFire honors a non-UTC timeZone",
        _iso(when) === "2026-05-09T06:30:00.000Z");
}

function testNextBaselineFireLocalClock() {
  // null timeZone follows the server's local clock — assert the local
  // wall-clock of the result matches the requested HH:MM (TZ-independent).
  var after = new Date("2026-05-09T00:00:00Z");
  var when  = b.scheduler.nextBaselineFire("13:45", null, after);
  var d     = new Date(when);
  check("nextBaselineFire local-clock matches requested HH:MM",
        d.getHours() === 13 && d.getMinutes() === 45);
  check("nextBaselineFire local-clock result is strictly after `after`",
        when > after.getTime());
}

function testNextBaselineFireRejectsBadInput() {
  var t1 = null;
  try { b.scheduler.nextBaselineFire("2:3", "UTC", new Date()); } catch (e) { t1 = e; }
  check("nextBaselineFire rejects malformed HH:MM",
        t1 && t1.code === "scheduler/invalid-baseline");
  var t2 = null;
  try { b.scheduler.nextBaselineFire("25:00", "UTC", new Date()); } catch (e) { t2 = e; }
  check("nextBaselineFire rejects out-of-range hour",
        t2 && t2.code === "scheduler/invalid-baseline");
  var t3 = null;
  try { b.scheduler.nextBaselineFire("12:60", "UTC", new Date()); } catch (e) { t3 = e; }
  check("nextBaselineFire rejects out-of-range minute",
        t3 && t3.code === "scheduler/invalid-baseline");
}

function _sortedSet(s) { return Array.from(s).sort(function (a, b) { return a - b; }); }
function _eq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

// A bare number followed by a step (`N/step`) is the Vixie-cron / crontab.guru
// shorthand for `N-max/step` — it fires at N and every `step` thereafter up to
// the field maximum, NOT just at the single value N. `5/15` in the minute
// field is 5,20,35,50 (the same way `*/15` is 0,15,30,45); before the fix it
// silently collapsed to {5}, so a task the operator meant to run every 15
// minutes ran once an hour. That silent under-firing is exactly the class the
// framework already rejects for over-range steps (v0.6.65).
function testCronBareNumberStep() {
  var m = b.scheduler.parseCron("5/15 * * * *");
  check("cron 5/15 minute expands to 5,20,35,50 (N/step == N-max/step)",
        _eq(_sortedSet(m.minute), [5, 20, 35, 50]));

  var m2 = b.scheduler.parseCron("10/20 * * * *");
  check("cron 10/20 minute expands to 10,30,50",
        _eq(_sortedSet(m2.minute), [10, 30, 50]));

  // `0/15` must be identical to `*/15` — both start at 0 and step by 15.
  var m3 = b.scheduler.parseCron("0/15 * * * *");
  check("cron 0/15 minute equals */15 (0,15,30,45)",
        _eq(_sortedSet(m3.minute), [0, 15, 30, 45]));

  var h = b.scheduler.parseCron("* 1/6 * * *");
  check("cron 1/6 hour expands to 1,7,13,19",
        _eq(_sortedSet(h.hour), [1, 7, 13, 19]));

  // dom starts at 1: `2/10` day-of-month = 2,12,22 (max 31).
  var d = b.scheduler.parseCron("0 0 2/10 * *");
  check("cron 2/10 dom expands to 2,12,22",
        _eq(_sortedSet(d.dom), [2, 12, 22]));

  // Regressions: forms that must be UNCHANGED by the fix.
  var star = b.scheduler.parseCron("*/15 * * * *");
  check("cron */15 unchanged (0,15,30,45)",
        _eq(_sortedSet(star.minute), [0, 15, 30, 45]));
  var bare = b.scheduler.parseCron("5 * * * *");
  check("cron bare 5 (no step) is the single value {5}",
        _eq(_sortedSet(bare.minute), [5]));
  var list = b.scheduler.parseCron("0,30 * * * *");
  check("cron list 0,30 unchanged",
        _eq(_sortedSet(list.minute), [0, 30]));
  var range = b.scheduler.parseCron("10-20/5 * * * *");
  check("cron explicit range 10-20/5 unchanged (10,15,20)",
        _eq(_sortedSet(range.minute), [10, 15, 20]));
}

// nextCronFire must actually fire at every step position of an `N/step`
// schedule — the real consumer path a queue cron-repeat / scheduler task
// drives. `5/15` fires at :05, :20, :35, :50, then :05 the next hour.
function testCronBareNumberStepNextFire() {
  var cron = b.scheduler.parseCron("5/15 * * * *");
  var t = new Date("2026-05-09T00:00:00Z");
  var fires = [];
  for (var i = 0; i < 5; i++) {
    var next = b.scheduler.nextCronFire(cron, t, "UTC");
    fires.push(new Date(next).toISOString().slice(11, 16));
    t = new Date(next);
  }
  check("nextCronFire 5/15 fires at every 15-min step, not once an hour",
        _eq(fires, ["00:05", "00:20", "00:35", "00:50", "01:05"]));
}

async function run() {
  testNextBaselineFireKnownAnswerUtc();
  testNextBaselineFireStrictlyAfter();
  testNextBaselineFireRollsWhenPast();
  testNextBaselineFireNonUtcZone();
  testNextBaselineFireLocalClock();
  testNextBaselineFireRejectsBadInput();
  testCronBareNumberStep();
  testCronBareNumberStepNextFire();
  await testSchedulerRegisterValidation();
  await testSchedulerStartStopStatusAndAfterStart();
  await testSchedulerTaskFireAndFailure();
}

// ---- Lifecycle: register/schedule validation, start/stop/status, fire + failure ----
// (audit:false keeps the emitter gated so no b.db is required; real short
// timers + helpers.waitUntil, every scheduler stop()'d in a finally.)
async function testSchedulerRegisterValidation() {
  var s = b.scheduler.create({ audit: false });
  function code(fn) { try { fn(); return "OK"; } catch (e) { return e.code; } }
  check("register: empty name -> INVALID_NAME", code(function () { s.register("", 1000, function () {}); }) === "INVALID_NAME");
  check("register: sub-second interval -> INVALID_SPEC", code(function () { s.register("a", 500, function () {}); }) === "INVALID_SPEC");
  check("register: non-function fn -> INVALID_SPEC", code(function () { s.register("a", 1000, "nope"); }) === "INVALID_SPEC");
  check("schedule: no spec object -> INVALID_SPEC", code(function () { s.schedule(null); }) === "INVALID_SPEC");
  check("schedule: missing name -> INVALID_NAME", code(function () { s.schedule({ every: 1000, run: function () {} }); }) === "INVALID_NAME");
  check("schedule: both cron+every -> INVALID_SPEC", code(function () { s.schedule({ name: "b", cron: "* * * * *", every: 1000, run: function () {} }); }) === "INVALID_SPEC");
  check("schedule: neither cron nor every -> INVALID_SPEC", code(function () { s.schedule({ name: "c", run: function () {} }); }) === "INVALID_SPEC");
  check("schedule: sub-second every -> INVALID_SPEC", code(function () { s.schedule({ name: "d", every: 500, run: function () {} }); }) === "INVALID_SPEC");
  s.register("dup", 1000, function () {});
  check("schedule: duplicate name -> DUPLICATE_NAME", code(function () { s.register("dup", 1000, function () {}); }) === "DUPLICATE_NAME");
}

async function testSchedulerStartStopStatusAndAfterStart() {
  var s = b.scheduler.create({ audit: false });
  s.register("noop", 1000, function () {});
  var st0 = s.getStatus();
  check("getStatus: not started, 1 task, aggregate.total=1",
        st0.started === false && st0.aggregate.total === 1 && st0.tasks.length === 1);
  await s.start();
  try {
    check("getStatus: started=true after start()", s.getStatus().started === true);
    var threw = null;
    try { s.schedule({ name: "late", every: 1000, run: function () {} }); } catch (e) { threw = e; }
    check("schedule after start -> ALREADY_STARTED", threw && threw.code === "ALREADY_STARTED");
  } finally {
    await s.stop();
  }
  check("getStatus: started=false after stop()", s.getStatus().started === false);
  await s.stop();
  check("stop() when already stopped is a no-op", s.getStatus().started === false);
}

async function testSchedulerTaskFireAndFailure() {
  var s = b.scheduler.create({ audit: false });
  var okRuns = 0;
  s.register("ok-task", 1000, function () { okRuns += 1; });
  s.register("bad-task", 1000, function () { throw new Error("task boom"); });
  await s.start();
  try {
    await helpers.waitUntil(function () {
      var agg = s.getStatus().aggregate;
      return agg.totalFires >= 1 && agg.withErrors >= 1;
    }, { timeoutMs: 8000, label: "scheduler: ok task fired + bad task failed" });
    var agg = s.getStatus().aggregate;
    check("task success path fired (totalFires>=1 + run body ran)", agg.totalFires >= 1 && okRuns >= 1);
    check("task failure path recorded (aggregate.withErrors>=1)", agg.withErrors >= 1);
    var bad = s.getStatus().tasks.filter(function (t) { return t.name === "bad-task"; })[0];
    check("failing task carries its lastError", bad && /boom/.test(bad.lastError || ""));
  } finally {
    await s.stop();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[scheduler] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
