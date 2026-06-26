"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function run() {
  var cra = b.cra.report.create({
    audit: false,
    productId: "blamejs-1.x",
    manufacturer: { name: "Acme", contact: "sec@acme.example" },
  });
  var rec = await cra.open({ detectedAt: Date.now(), scope: "vuln-actively-exploited" });
  check("cra.open returns id",                        typeof rec.id === "string");
  check("cra.open uses CRA 24h initial deadline",     rec.dueBy.initial === rec.detectedAt + 24 * 60 * 60 * 1000);
  check("cra.open uses CRA 14d final deadline",       rec.dueBy.final === rec.detectedAt + 14 * 24 * 60 * 60 * 1000);

  var ew = await cra.earlyWarning(rec.id, { summary: "..." });
  check("cra.earlyWarning records initial", ew.record.stages.initial !== undefined);

  var threwNoProduct = false;
  try { b.cra.report.create({ manufacturer: { name: "x" } }); }
  catch (e) { threwNoProduct = e.code === "cra-report/bad-product-id"; }
  check("cra refuses missing productId", threwNoProduct);

  var threwNoMfg = false;
  try { b.cra.report.create({ productId: "x" }); }
  catch (e) { threwNoMfg = e.code === "cra-report/bad-manufacturer"; }
  check("cra refuses missing manufacturer", threwNoMfg);

  console.log("OK — cra.report tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
