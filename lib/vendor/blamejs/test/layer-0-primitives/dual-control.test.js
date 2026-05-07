"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  check("dualControl namespace present",  typeof b.dualControl === "object");
  check("dualControl.create is fn",       typeof b.dualControl.create === "function");

  // Use a memory-backend cache so this test is hermetic.
  var cache = b.cache.create({ namespace: "dual-test" });
  var approvals = b.dualControl.create({
    namespace: "test.destructive",
    cache:     cache,
    audit:     b.audit,
    ttlMs:     60 * 1000,
  });

  // Step 1 — request
  var req1 = await approvals.request({
    action:      "<test>.purge",
    requestedBy: { id: "alice" },
    reason:      "test request",
  });
  check("request: returns pending",          req1.status === "pending");
  check("request: needs minApprovers (2)",   req1.needs === 2);
  check("request: empty approvedBy",         Array.isArray(req1.approvedBy) && req1.approvedBy.length === 0);

  // Self-approve forbidden
  var selfApprove = await approvals.approve({
    grantId:  req1.grantId,
    approver: { id: "alice" },
  });
  check("approve: self-approval rejected",   selfApprove.error === "self-approval-forbidden");

  // First valid approver
  var ap1 = await approvals.approve({
    grantId:  req1.grantId,
    approver: { id: "bob" },
  });
  check("approve: 1/2 still pending",        ap1.status === "pending" && ap1.approvedBy.length === 1);

  // Second different approver — quorum reached
  var ap2 = await approvals.approve({
    grantId:  req1.grantId,
    approver: { id: "carol" },
  });
  check("approve: 2/2 approved",             ap2.status === "approved");

  // Same approver twice — rejected
  var dupAp = await approvals.approve({
    grantId:  req1.grantId,
    approver: { id: "carol" },
  });
  check("approve: duplicate approver rejected", dupAp.error === "already-approved-by-this-actor");

  // Status check
  var st = await approvals.status(req1.grantId);
  check("status: 'approved' state",          st && st.status === "approved");

  // Consume — single use, then gone
  var c1 = await approvals.consume(req1.grantId);
  check("consume: ready",                    c1.ready === true);
  check("consume: returns action",           c1.action === "<test>.purge");

  var c2 = await approvals.consume(req1.grantId);
  check("consume: second call grant-not-found",  c2.ready === false && c2.reason === "grant-not-found");

  // Revoke flow
  var req2 = await approvals.request({
    action:      "<test>.purge2",
    requestedBy: { id: "alice" },
  });
  await approvals.revoke({ grantId: req2.grantId, revokedBy: { id: "admin" }, reason: "rolled back" });
  var revokedConsume = await approvals.consume(req2.grantId);
  check("consume: revoked → not-ready",      revokedConsume.ready === false && revokedConsume.reason === "revoked");

  // Approve attempt against a revoked grant
  var revokedApprove = await approvals.approve({
    grantId:  req2.grantId,
    approver: { id: "bob" },
  });
  check("approve: revoked grant rejected",   revokedApprove.error === "grant-revoked");

  // ---- Validation ----
  var threwBadCache = null;
  try { b.dualControl.create({ namespace: "x", cache: {} }); }
  catch (e) { threwBadCache = e; }
  check("create: rejects non-cache opts.cache", threwBadCache && /BAD_OPT/.test(threwBadCache.code || ""));

  var threwBadMin = null;
  try { b.dualControl.create({ namespace: "x", cache: cache, minApprovers: 1 }); }
  catch (e) { threwBadMin = e; }
  check("create: rejects minApprovers < 2",   threwBadMin && /BAD_OPT/.test(threwBadMin.code || ""));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dual-control] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
