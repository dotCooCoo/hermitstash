"use strict";
/**
 * b.ddlChangeControl — formal DDL approval / change-control workflow.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAudit() {
  var emitted = [];
  return {
    safeEmit: function (event) { emitted.push(event); },
    _emitted: emitted,
  };
}

function testSurface() {
  check("ddlChangeControl.create is a function",
        typeof b.ddlChangeControl.create === "function");
  check("STATES.PROPOSED",  b.ddlChangeControl.STATES.PROPOSED  === "proposed");
  check("STATES.APPROVED",  b.ddlChangeControl.STATES.APPROVED  === "approved");
  check("frameworkError.DdlChangeControlError exposed",
        typeof b.frameworkError.DdlChangeControlError === "function");
  check("ddlChangeControl.DdlChangeControlError is fn",
        typeof b.ddlChangeControl.DdlChangeControlError === "function");
}

async function testProposeApproveApply() {
  var fakeAudit = _fakeAudit();
  var ddl = b.ddlChangeControl.create({
    audit:     fakeAudit,
    approvers: 2,
  });
  var prop = await ddl.propose("ALTER TABLE x ADD COLUMN y TEXT", {
    proposer: "alice",
    reason:   "feature-A",
  });
  check("propose returns changeId + sqlHash",
        typeof prop.changeId === "string" && typeof prop.sqlHash === "string");
  check("ddl.change.proposed audit emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "ddl.change.proposed"; }));

  var rv1 = await ddl.approve(prop.changeId, "bob");
  check("first approval count = 1, threshold not met",
        rv1.signaturesCount === 1 && rv1.thresholdMet === false);
  var rv2 = await ddl.approve(prop.changeId, "carol");
  check("second approval count = 2, threshold met",
        rv2.signaturesCount === 2 && rv2.thresholdMet === true);

  var ranSql = null;
  var apply = await ddl.applyApproved(prop.changeId, async function (sql) {
    ranSql = sql; return { ok: true };
  });
  check("applyApproved ran the SQL",
        ranSql === "ALTER TABLE x ADD COLUMN y TEXT");
  check("applyApproved returns result",
        apply.result && apply.result.ok === true);
  check("ddl.change.applied audit emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "ddl.change.applied"; }));
}

async function testInsufficientApprovals() {
  var ddl = b.ddlChangeControl.create({
    audit:     _fakeAudit(),
    approvers: 2,
  });
  var prop = await ddl.propose("ALTER TABLE x ADD COLUMN y TEXT", {
    proposer: "alice",
  });
  await ddl.approve(prop.changeId, "bob");
  var threw = null;
  try {
    await ddl.applyApproved(prop.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("insufficient approvals refuse apply",
        threw && /insufficient-approvals/.test(threw.code || ""));
}

async function testSelfApprovalUnderPosture() {
  var ddl = b.ddlChangeControl.create({
    audit:     _fakeAudit(),
    approvers: 2,
    posture:   "sox-404",
  });
  var prop = await ddl.propose("ALTER TABLE x ADD y TEXT", { proposer: "alice" });
  var threw = null;
  try { await ddl.approve(prop.changeId, "alice"); } catch (e) { threw = e; }
  check("self-approval denied under sox-404",
        threw && /self-approval-denied/.test(threw.code || ""));
}

async function testDuplicateApproval() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 2 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.approve(prop.changeId, "bob");
  var threw = null;
  try { await ddl.approve(prop.changeId, "bob"); } catch (e) { threw = e; }
  check("duplicate approval refused",
        threw && /duplicate-approval/.test(threw.code || ""));
}

async function testRejectThenApply() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.reject(prop.changeId, "reviewer", "not safe");
  var threw = null;
  try {
    await ddl.applyApproved(prop.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("apply after reject refused",
        threw && /already-rejected/.test(threw.code || ""));
}

function testWindowSpecParsing() {
  var fakeAudit = _fakeAudit();
  // Should parse:
  var ddl1 = b.ddlChangeControl.create({
    audit: fakeAudit, approvers: 1, windowSpec: "always",
  });
  check("always window OK", ddl1.windowSpec === "always");
  var ddl2 = b.ddlChangeControl.create({
    audit: fakeAudit, approvers: 1, windowSpec: "Mon-Fri 09:00-17:00 UTC",
  });
  check("Mon-Fri 09-17 window OK", ddl2.windowSpec === "Mon-Fri 09:00-17:00 UTC");

  // Bad input throws
  var threw = null;
  try {
    b.ddlChangeControl.create({
      audit: fakeAudit, approvers: 1, windowSpec: "Mon 09:00-17:00 EST",
    });
  } catch (e) { threw = e; }
  check("non-UTC window refused",
        threw && /bad-window/.test(threw.code || ""));
}

async function testSqlTamperRefused() {
  var ddl = b.ddlChangeControl.create({ audit: _fakeAudit(), approvers: 1 });
  var prop = await ddl.propose("ALTER", { proposer: "p" });
  await ddl.approve(prop.changeId, "bob");
  // Tamper the stored SQL via b.ddlChangeControl get + manual edit:
  // Without an exposed mutator, simulate by creating a second instance
  // sharing a custom store and tampering directly.
  var byId = new Map();
  var customStore = {
    get: function (id) { return byId.get(id) || null; },
    put: function (id, c) { byId.set(id, c); },
    list: function () { return Array.from(byId.values()); },
  };
  var ddl2 = b.ddlChangeControl.create({
    audit: _fakeAudit(), approvers: 1, store: customStore,
  });
  var prop2 = await ddl2.propose("ORIGINAL", { proposer: "p" });
  await ddl2.approve(prop2.changeId, "bob");
  // Tamper:
  var raw = customStore.get(prop2.changeId);
  raw.sql = "EVIL";
  customStore.put(prop2.changeId, raw);
  var threw = null;
  try {
    await ddl2.applyApproved(prop2.changeId, async function () { return null; });
  } catch (e) { threw = e; }
  check("sql tamper refused",
        threw && /sql-tampered/.test(threw.code || ""));
}

async function run() {
  testSurface();
  await testProposeApproveApply();
  await testInsufficientApprovals();
  await testSelfApprovalUnderPosture();
  await testDuplicateApproval();
  await testRejectThenApply();
  testWindowSpecParsing();
  await testSqlTamperRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
