"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

(async function run() {
  var ir = b.incident.report.create({ audit: false });
  var rec = await ir.open({ regime: "gdpr", detectedAt: Date.now() });
  check("incident.open returns id", typeof rec.id === "string");
  check("incident.open sets dueBy",  typeof rec.dueBy.initial === "number");
  check("incident.open uses regime deadlines", rec.dueBy.intermediate === rec.detectedAt + 72 * 60 * 60 * 1000);
  await ir.recordInitial(rec.id, { foo: "bar" });
  await ir.recordIntermediate(rec.id, { foo: "bar" });
  await ir.recordFinal(rec.id, { foo: "bar" });
  check("incident.list returns one", ir.list().length === 1);
  check("incident.status reports closed", ir.status().closed === 1);

  var threwBadStage = false;
  try { await ir.recordInitial(rec.id, {}); }
  catch (e) { threwBadStage = e.code === "incident-report/stage-already-filed"; }
  check("incident refuses double-file", threwBadStage);

  var ir2 = b.incident.report.create({ audit: false });
  var threwBadSpec = false;
  try { await ir2.open({}); } catch (e) { threwBadSpec = e.code === "incident-report/bad-regime"; }
  check("incident.open refuses bad spec", threwBadSpec);

  // ---- createDeadlineClock — running-clock approaching/passed alerts ----
  // Manual-tick mode (autoStart:false) keeps the test deterministic and
  // sleep-free; thresholds fire as the injected "now" crosses fractions
  // of each stage deadline.
  check("createDeadlineClock is fn", typeof b.incident.report.createDeadlineClock === "function");

  var sent = [];
  var clk = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sent.push(m); } },
    autoStart: false,
    approachThresholds: [0.5, 0.9],
  });
  // detectedAt=0; stage deadlines initial=100, intermediate=200, final=300.
  clk.track({ id: "inc-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 100, intermediate: 200, final: 300 } });
  check("deadline clock: tracked=1", clk.status().tracked === 1);

  clk.tick(50);   // 50% of initial → approaching@0.5
  check("tick@50: one approaching@0.5 (initial)",
    sent.length === 1 && sent[0].kind === "deadline_approaching" &&
    sent[0].stage === "initial" && sent[0].threshold === 0.5);

  clk.tick(55);   // still <0.9 of initial → dedupe, no new alert
  check("tick@55: dedupe (no new alert)", sent.length === 1);

  clk.tick(95);   // 95% of initial → approaching@0.9
  check("tick@95: approaching@0.9 fires", sent.length === 2 && sent[1].threshold === 0.9);

  clk.tick(150);  // initial(100) passed
  check("tick@150: initial passed fires once",
    sent.filter(function (m) { return m.kind === "deadline_passed" && m.stage === "initial"; }).length === 1);

  clk.tick(160);  // no duplicate passed for initial
  check("tick@160: no duplicate passed",
    sent.filter(function (m) { return m.kind === "deadline_passed" && m.stage === "initial"; }).length === 1);

  // Acknowledging a stage suppresses its further alerts.
  clk.acknowledgeSubmission("inc-1", "intermediate");
  clk.tick(250);  // intermediate(200) would be passed, but acked → suppressed
  check("acknowledged stage: no passed alert",
    sent.filter(function (m) { return m.stage === "intermediate" && m.kind === "deadline_passed"; }).length === 0);

  // Construction-time + track-time input validation.
  var badThresh = false;
  try { b.incident.report.createDeadlineClock({ approachThresholds: [1.5] }); }
  catch (e) { badThresh = /between 0 and 1/.test(e.message); }
  check("createDeadlineClock rejects threshold > 1", badThresh);

  var badTrack = false;
  try { clk.track({ id: "x" }); } catch (e) { badTrack = /dueBy/.test(e.message); }
  check("deadline clock: track without dueBy rejected", badTrack);

  // Faster regime crosses before slower one on the same tick
  // (registry windows differ — DORA vs GDPR here).
  var sent2 = [];
  var clk2 = b.incident.report.createDeadlineClock({
    notify: { send: function (m) { sent2.push(m); } }, autoStart: false,
  });
  clk2.track({ id: "dora-1", detectedAt: 0, regime: "dora", dueBy: { initial: 4, intermediate: 8, final: 12 } });
  clk2.track({ id: "gdpr-1", detectedAt: 0, regime: "gdpr", dueBy: { initial: 72, intermediate: 100, final: 200 } });
  clk2.tick(5);  // DORA initial(4) passed; GDPR initial(72) only ~7% → nothing
  check("deadline clock: faster regime crosses first",
    sent2.filter(function (m) { return m.incidentId === "dora-1" && m.kind === "deadline_passed"; }).length === 1 &&
    sent2.filter(function (m) { return m.incidentId === "gdpr-1"; }).length === 0);
  clk2.stop();

  console.log("OK — incident.report tests");
})().catch(function (e) { console.error(e); process.exit(1); });
