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
    threwBudget && threwBudget.code === "tenantQuota/budget-exceeded");

  budget.reset("tenant-acme");
  var snapReset = budget.snapshot("tenant-acme");
  check("reset clears counters", snapReset.calls === 0);

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
    threwBadDb && threwBadDb.code === "tenantQuota/bad-db");

  var threwBadField = null;
  try {
    b.tenantQuota.create({ db: b.db, tenantField: "", audit: false });
  } catch (e) { threwBadField = e; }
  check("create rejects empty tenantField",
    threwBadField && threwBadField.code === "tenantQuota/bad-field");
}

module.exports = { run: run };
