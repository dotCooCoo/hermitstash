"use strict";
// b.nistCrosswalk — NIST 800-53 / CSF 2.0 / 800-171 / 800-218 control crosswalk.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function run() {
  check("NistCrosswalkError exposed",                        typeof b.nistCrosswalk.NistCrosswalkError === "function");


  var cats = b.nistCrosswalk.listCatalogs();
  check("listCatalogs: returns array",                       Array.isArray(cats) && cats.length === 4);
  check("listCatalogs: 800-53r5 present",                    cats.some(function (c) { return c.id === "800-53r5"; }));
  check("listCatalogs: csf-2.0 present",                     cats.some(function (c) { return c.id === "csf-2.0"; }));
  check("listCatalogs: count > 0 per catalog",               cats.every(function (c) { return c.count > 0; }));

  var sp80053 = b.nistCrosswalk.controls("800-53r5");
  check("controls(800-53r5): AC-3 present",                  Array.isArray(sp80053["AC-3"].primitives));
  check("controls(800-53r5): AC-3 maps to b.permissions",    sp80053["AC-3"].primitives.indexOf("b.permissions") !== -1);

  var threw = false;
  try { b.nistCrosswalk.controls("bogus"); }
  catch (e) { threw = /unknown-catalog/.test(e.code || ""); }
  check("controls: unknown catalog throws",                  threw);

  var cov = b.nistCrosswalk.coverage({
    catalog:    "800-53r5",
    controlIds: ["AC-2", "AC-3", "ZZ-99"],
  });
  check("coverage: AC-2 + AC-3 covered",                     cov.covered.length === 2);
  check("coverage: ZZ-99 uncovered",                         cov.uncovered.indexOf("ZZ-99") !== -1);
  check("coverage: primitives deduplicated",                 cov.primitives.indexOf("b.permissions") !== -1);
  check("coverage: primitives sorted",                       cov.primitives.slice().sort().join() === cov.primitives.join());
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
