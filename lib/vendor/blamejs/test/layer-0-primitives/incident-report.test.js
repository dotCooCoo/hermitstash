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

  console.log("OK — incident.report tests");
})().catch(function (e) { console.error(e); process.exit(1); });
