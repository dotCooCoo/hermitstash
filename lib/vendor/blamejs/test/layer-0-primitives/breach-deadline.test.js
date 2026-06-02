"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

(async function run() {
  var now = Date.now();
  var d = b.breach.deadline.forStates(["CA", "TX"], now);
  check("forStates returns 2", d.length === 2);
  var ca = d.filter(function (e) { return e.state === "CA"; })[0];
  var tx = d.filter(function (e) { return e.state === "TX"; })[0];
  check("CA is asap kind", ca.kind === "as-soon-as-possible");
  check("TX is hard-deadline kind", tx.kind === "hard-deadline");
  check("TX 60-day deadline", tx.dueBy === now + 60 * 24 * 60 * 60 * 1000);

  var threwUnknown = false;
  try { b.breach.deadline.forStates(["XX"], now); }
  catch (e) { threwUnknown = e.code === "breach/unknown-state"; }
  check("forStates refuses unknown state", threwUnknown);

  var reporter = b.breach.report.create({ audit: false });
  var rec = reporter.open({
    detectedAt: now,
    affectedStates: ["CA", "NY"],
    impact: { individualsAffected: 5000 },
  });
  check("report.open returns id", typeof rec.id === "string");
  check("report tracks two states", rec.affectedStates.length === 2);

  await reporter.fileNotice(rec.id, "CA", { method: "email" });
  check("after one filing, one pending", reporter.pending(rec.id).length === 1);

  await reporter.fileNotice(rec.id, "NY", { method: "email" });
  check("after both filings, none pending", reporter.pending(rec.id).length === 0);
  check("breach closed after all filed",   reporter.get(rec.id).closedAt !== null);

  // ---- running clock (composes incident.report.createDeadlineClock) ----
  // Injected clock so escalation timing is deterministic, no wall-clock sleep.
  var detectedAt = 0;
  var clockNow = detectedAt;
  var events = [];

  var clockReporter = b.breach.report.create({ audit: false, now: function () { return clockNow; } });
  var clockRec = clockReporter.open({
    detectedAt: detectedAt,
    affectedStates: ["CA", "TX"],   // CA = asap-ceiling 60d, TX = hard 60d
    impact: { individualsAffected: 9000 },
  });

  var clock = b.breach.deadline.createClock({
    audit:    false,
    autoStart: false,
    approachThresholds: [0.5, 0.9],
    notify:   { send: function (p) { events.push(p); } },
    now:      function () { return clockNow; },
  });

  var trackedId = clock.trackReport(clockRec);
  check("trackReport returns the breach id", trackedId === clockRec.id);
  check("clock tracks both states", clock.status().tracked === 2);
  check("clock counts one breach",  clock.status().breaches === 1);

  // Day 0: nothing has elapsed, no escalation.
  clock.tick();
  check("no escalation at detection time", events.length === 0);

  // Advance past the 50% threshold of the 60-day window (31 days).
  clockNow = detectedAt + 31 * 24 * 60 * 60 * 1000;
  clock.tick();
  var approaching = events.filter(function (e) { return e.kind === "deadline_approaching"; });
  check("approaching fired for both states at 50%", approaching.length === 2);

  // Re-ticking at the same proportion must NOT re-fire (once per phase).
  var beforeReTick = events.length;
  clock.tick();
  check("approaching does not re-fire on repeat tick", events.length === beforeReTick);

  // Acknowledge CA's filing — CA must go silent even past its deadline.
  clock.acknowledgeSubmission(clockRec.id, "ca");

  // Advance past the deadline (61 days). TX should fire "passed"; CA must not.
  clockNow = detectedAt + 61 * 24 * 60 * 60 * 1000;
  clock.tick();
  var passed = events.filter(function (e) { return e.kind === "deadline_passed"; });
  check("exactly one state fired passed (TX, not acked CA)", passed.length === 1);
  check("passed carries the statute regime", typeof passed[0].regime === "string" && passed[0].regime.length > 0);

  var ackUnknownThrew = false;
  try { clock.acknowledgeSubmission(clockRec.id, "NY"); }
  catch (e) { ackUnknownThrew = e.code === "breach-clock/unknown-tracked-state"; }
  check("acknowledgeSubmission refuses an untracked state", ackUnknownThrew);

  var badReportThrew = false;
  try { clock.trackReport({ id: 42 }); }
  catch (e) { badReportThrew = e.code === "breach-clock/bad-report"; }
  check("trackReport refuses a non-record", badReportThrew);

  check("untrack removes the breach", clock.untrack(clockRec.id) === true);
  check("clock empty after untrack", clock.status().tracked === 0);

  // Auto-start timer path: poll the notify sink (no fixed-budget sleep).
  var autoEvents = [];
  var autoNow = 0;
  var autoReporter = b.breach.report.create({ audit: false, now: function () { return autoNow; } });
  var autoRec = autoReporter.open({ detectedAt: 0, affectedStates: ["TX"], impact: {} });
  autoNow = 61 * 24 * 60 * 60 * 1000;   // already past TX's 60-day wall
  var autoClock = b.breach.deadline.createClock({
    audit:    false,
    autoStart: true,
    intervalMs: 10,
    notify:   { send: function (p) { autoEvents.push(p); } },
    now:      function () { return autoNow; },
  });
  autoClock.trackReport(autoRec);
  await helpers.waitUntil(function () {
    return autoEvents.some(function (e) { return e.kind === "deadline_passed"; });
  }, { timeoutMs: 5000, label: "breach-clock: auto-tick fires deadline_passed" });
  check("auto-tick timer fired the passed alert", true);
  autoClock.stop();
  check("clock stops cleanly", autoClock.status().running === false);

  console.log("OK — breach-deadline tests");
})().catch(function (e) { console.error(e); process.exit(1); });
