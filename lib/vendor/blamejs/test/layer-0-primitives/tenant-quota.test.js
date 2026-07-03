// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.tenantQuota — per-tenant DB storage caps + query budget +
 * isolation breach detection.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("tenantQuota.create is fn",          typeof b.tenantQuota.create === "function");
  check("tenantQuota.budget is fn",          typeof b.tenantQuota.budget === "function");
  check("tenantQuota.instrumentQuery is fn", typeof b.tenantQuota.instrumentQuery === "function");
  check("TenantQuotaError is fn",            typeof b.tenantQuota.TenantQuotaError === "function");

  // ---- budget — sliding-window sentry ----
  var budget = b.tenantQuota.budget({
    tenantField:            "tenantId",
    perTenantQpsCap:        2,
    perTenantTotalRowsRead: 100,
    window:                 b.constants.TIME.seconds(1),
    audit:                  false,
  });
  check("budget.observe is fn", typeof budget.observe === "function");

  var snap0 = budget.snapshot("tenant-acme");
  check("snapshot empty starts at zero", snap0.calls === 0 && snap0.rowsRead === 0);

  var ob1 = budget.observe("tenant-acme", { rowsRead: 5 });
  check("observe increments calls/rowsRead", ob1.calls === 1 && ob1.rowsRead === 5);

  // Force a budget breach by reading too many rows in one observe.
  var threwBudget = null;
  try { budget.observe("tenant-acme", { rowsRead: 200 }); }
  catch (e) { threwBudget = e; }
  check("observe throws when rowsRead exceeds cap",
    threwBudget && threwBudget.code === "tenant-quota/budget-exceeded");

  budget.reset("tenant-acme");
  var snapReset = budget.snapshot("tenant-acme");
  check("reset clears counters", snapReset.calls === 0);

  // ---- budget — TRUE sliding window (no fixed-window boundary doubling) ----
  // maxCalls = floor(qpsCap * window/1s) = 5. Fill 5 near the window's tail,
  // then 1 more just past the nominal reset: a fixed window would admit it
  // (~2x burst), a sliding window refuses (trailing window still covers them).
  var sw = b.tenantQuota.budget({ tenantField: "tenantId", perTenantQpsCap: 5, window: 1000, audit: false });
  for (var i = 0; i < 5; i++) sw.observe("t-burst", { now: 900 });
  var threwBoundary = null;
  try { sw.observe("t-burst", { now: 1001 }); } catch (e) { threwBoundary = e; }
  check("sliding window refuses the boundary-straddling burst (not a fixed window)",
        threwBoundary && threwBoundary.code === "tenant-quota/budget-exceeded");
  // After a full window has elapsed, the old calls scroll out → admitted again.
  var allowedAfterGap = true;
  try { sw.observe("t-burst", { now: 2600 }); } catch (_e) { allowedAfterGap = false; }
  check("sliding window admits again once the prior calls age out", allowedAfterGap === true);

  // ---- instrumentQuery — tenant-isolation breach ----
  var goodCheck = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-a", value: 2 },
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    audit:       false,
  });
  check("instrumentQuery clean rows → ok",       goodCheck.ok === true);
  check("instrumentQuery clean rows → empty cross", goodCheck.crossover.length === 0);

  var badCheck = b.tenantQuota.instrumentQuery({
    rows: [
      { tenantId: "tenant-a", value: 1 },
      { tenantId: "tenant-b", value: 2 }, // crossover
    ],
    tenantField: "tenantId",
    tenantId:    "tenant-a",
    audit:       false,
  });
  check("instrumentQuery crossover detected",     badCheck.ok === false);
  check("instrumentQuery crossover index recorded", badCheck.crossover[0].index === 1);
  check("instrumentQuery crossover actual recorded",
    badCheck.crossover[0].actualTenantId === "tenant-b");

  // ---- create — opts validation ----
  var threwBadDb = null;
  try {
    b.tenantQuota.create({
      db: { foo: 1 }, tenantField: "tenantId", audit: false,
    });
  } catch (e) { threwBadDb = e; }
  check("create rejects non-b.db handle",
    threwBadDb && threwBadDb.code === "tenant-quota/bad-db");

  var threwBadField = null;
  try {
    b.tenantQuota.create({ db: b.db, tenantField: "", audit: false });
  } catch (e) { threwBadField = e; }
  check("create rejects empty tenantField",
    threwBadField && threwBadField.code === "tenant-quota/bad-field");
}

module.exports = { run: run };
