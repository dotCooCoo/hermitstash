"use strict";
/**
 * b.dataAct — EU Data Act (Regulation 2023/2854) connected-product
 * data-access workflow.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function run() {
  check("dataAct.DataActError is fn", typeof b.dataAct.DataActError === "function");
  b.dataAct._resetForTest();
  b.dataAct.declareProduct({
    productId:   "thermo-v3",
    dataHolder:  "Acme",
    productKind: "connected-product",
  });
  b.dataAct.recordUserAccess({ productId: "thermo-v3", userId: "user-1" });
  check("dataAct.recordUserAccess: succeeds for declared product",   true);

  var threw = false;
  try { b.dataAct.recordUserAccess({ productId: "phantom", userId: "x" }); }
  catch (e) { threw = /unknown-product/.test(e.code); }
  check("dataAct: unknown product refused",                          threw);

  // Art 5 — non-gatekeeper share accepted.
  b.dataAct.shareWithThirdParty({
    productId: "thermo-v3", userId: "user-1",
    recipient: "Beta Repair Co", scope: "temperature-readings",
  });
  check("dataAct.shareWithThirdParty: non-gatekeeper accepted",      true);

  // Art 32 §1 — designated gatekeeper share refused without override.
  threw = false;
  try {
    b.dataAct.shareWithThirdParty({
      productId: "thermo-v3", userId: "user-1",
      recipient: "Google", scope: "x",
    });
  } catch (e) { threw = /gatekeeper-refused/.test(e.code); }
  check("dataAct: designated gatekeeper share refused (Art 32 §1)",  threw);

  // Override accepted with audited reason.
  b.dataAct.shareWithThirdParty({
    productId: "thermo-v3", userId: "user-1",
    recipient: "Google", scope: "x",
    acceptGatekeeper: { reason: "explicit user request via DSR ticket #4321" },
  });
  check("dataAct: gatekeeper override with reason accepted",         true);

  // Art 28 §3 — 30-day notice cap enforced.
  threw = false;
  try {
    b.dataAct.recordSwitchRequest({
      customerId: "c1", targetProvider: "OtherCloud",
      dataSlices: ["app-state"], noticePeriodDays: 60,
    });
  } catch (e) { threw = /notice-period-too-long/.test(e.code); }
  check("dataAct.recordSwitchRequest: refuses >30-day notice",       threw);

  var rv = b.dataAct.recordSwitchRequest({
    customerId: "c1", targetProvider: "OtherCloud",
    dataSlices: ["app-state"],
  });
  check("dataAct.recordSwitchRequest: returns acceptedAt + period",  rv && rv.noticePeriodDays === 30);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
