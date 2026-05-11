"use strict";
// b.dsr.stateRules + b.dsr.listStateRules — US state DSR drift registry.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function run() {
  var rules = b.dsr.listStateRules();
  check("listStateRules: returns array",                    Array.isArray(rules));
  check("listStateRules: covers >= 20 states",              rules.length >= 20);
  check("listStateRules: each has responseDays",            rules.every(function (r) { return typeof r.responseDays === "number"; }));
  check("listStateRules: each has profilingOptOut bool",    rules.every(function (r) { return typeof r.profilingOptOut === "boolean"; }));

  var va = b.dsr.stateRules("vcdpa");
  check("stateRules(vcdpa): present",                       va !== null);
  check("stateRules(vcdpa): VA",                            va.state === "VA");
  check("stateRules(vcdpa): 45 day response",               va.responseDays === 45);
  check("stateRules(vcdpa): profiling opt-out enabled",     va.profilingOptOut === true);

  // Case-insensitive 2-letter abbreviation lookup
  var co = b.dsr.stateRules("co");
  check("stateRules(co): case-insensitive abbreviation",    co !== null && co.posture === "co-cpa");

  var ia = b.dsr.stateRules("IA");
  check("stateRules(IA): weakest framework — 90 days",      ia.responseDays === 90);
  check("stateRules(IA): no profiling opt-out",             ia.profilingOptOut === false);

  var nj = b.dsr.stateRules("nj-njdpa");
  check("stateRules(NJ): minorOptIn 17",                    nj.minorOptIn === 17);

  var ca = b.dsr.stateRules("ca-aadc");
  check("stateRules(ca-aadc): minorOptIn 18",               ca.minorOptIn === 18);

  check("stateRules(bogus): null",                          b.dsr.stateRules("xxx-fake") === null);
  check("stateRules(empty): null",                          b.dsr.stateRules("") === null);
  check("stateRules(not-string): null",                     b.dsr.stateRules(null) === null);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
