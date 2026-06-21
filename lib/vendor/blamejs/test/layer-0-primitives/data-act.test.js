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

  // B10: a gatekeeper as the FINAL domain label must still be refused. The old
  // substring `indexOf(g + ".")` test missed "blog.google" / "data.amazon" (the
  // gatekeeper token is the last label, e.g. the real ".google" TLD), letting an
  // Art 32 §1 share through. Label matching closes the bypass.
  ["blog.google", "drive.google", "data.amazon", "play.google.com",
   "https://meta.com/share", "user@booking.com"].forEach(function (recip) {
    var bypassed = false, refused = false;
    try {
      b.dataAct.shareWithThirdParty({
        productId: "thermo-v3", userId: "user-1", recipient: recip, scope: "x",
      });
      bypassed = true;   // no throw → the gate let a gatekeeper through
    } catch (e) { refused = /gatekeeper-refused/.test(e.code); }
    check("B10: gatekeeper recipient '" + recip + "' refused (no final-label bypass)",
          refused && !bypassed);
  });

  // B10: a NON-gatekeeper whose name merely CONTAINS a gatekeeper token must NOT
  // be over-refused (the substring test false-flagged "notgoogle.com").
  ["notgoogle.com", "evilgoogle.com", "google-partners.example.com"].forEach(function (recip) {
    var ok = false;
    try {
      b.dataAct.shareWithThirdParty({
        productId: "thermo-v3", userId: "user-1", recipient: recip, scope: "x",
      });
      ok = true;
    } catch (_e) { ok = false; }
    check("B10: non-gatekeeper '" + recip + "' is NOT over-refused", ok);
  });

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
