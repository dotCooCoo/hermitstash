"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

(function run() {
  var eaa = b.compliance.eaa.create({
    audit: false,
    productName: "Acme Portal",
    productScope: "https://portal.acme.example",
    standards: ["WCAG 2.2 AA"],
  });
  eaa.declareCriterion("1.1.1", { conformance: "supports", note: "alt text on every image" });
  eaa.declareCriterion("1.4.3", { conformance: "supports", note: "ratio >= 4.5:1" });
  eaa.declareNonConformance({ criterion: "2.5.5", reason: "legacy desktop interaction" });

  var json = eaa["export"]({ format: "json" });
  check("eaa.export json regulation",       json.directive === "(EU) 2019/882");
  check("eaa.export json criteria count",   json.criteria.length === 3);
  check("eaa.export json non-conformances", json.nonConformances.length === 1);

  var md = eaa["export"]({ format: "markdown" });
  check("eaa.export markdown contains product name", md.indexOf("Acme Portal") !== -1);

  var threwBadProduct = false;
  try { b.compliance.eaa.create({ standards: ["WCAG 2.2 AA"] }); }
  catch (e) { threwBadProduct = e.code === "compliance-eaa/bad-product"; }
  check("eaa refuses missing productName", threwBadProduct);

  var threwBadConformance = false;
  try { eaa.declareCriterion("1.4.4", { conformance: "kinda-works" }); }
  catch (e) { threwBadConformance = e.code === "compliance-eaa/bad-conformance"; }
  check("eaa refuses bad conformance", threwBadConformance);

  console.log("OK — compliance.eaa tests");
})();
