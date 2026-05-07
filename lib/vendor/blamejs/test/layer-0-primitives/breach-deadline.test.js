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

  console.log("OK — breach-deadline tests");
})().catch(function (e) { console.error(e); process.exit(1); });
