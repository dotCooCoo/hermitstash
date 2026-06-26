"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var n = b.nis2.report.create({
    audit: false,
    entityId: "acme-1", entityType: "essential", sectorAnnex: "I.6",
  });
  var rec = await n.open({ detectedAt: Date.now() });
  check("nis2.open returns id", typeof rec.id === "string");
  check("nis2 uses 30d final", rec.dueBy.final === rec.detectedAt + 30 * 24 * 60 * 60 * 1000);

  var threwBadType = false;
  try { b.nis2.report.create({ entityId: "x", entityType: "huge", sectorAnnex: "I.1" }); }
  catch (e) { threwBadType = e.code === "nis2-report/bad-entity-type"; }
  check("nis2 refuses bad entityType", threwBadType);

  console.log("OK — nis2.report tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
