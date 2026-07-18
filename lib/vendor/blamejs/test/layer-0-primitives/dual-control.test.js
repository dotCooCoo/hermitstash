// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

  // ---- Concurrency: the quorum-bypass + double-consume races ----
  // The get/set version read a snapshot, mutated, and wrote back with an
  // await in between, so two concurrent operations could each act on stale
  // state. cache.update makes the read-modify-write atomic. These pin the
  // invariants that broke before.
  var reqC = await approvals.request({ action: "<test>.concurrent", requestedBy: { id: "alice" } });

  // (a) The SAME approver firing two approvals in parallel must count ONCE.
  // A stale-snapshot double-append would reach the 2-of-2 quorum with one
  // human — the dual-control bypass.
  var dupResults = await Promise.all([
    approvals.approve({ grantId: reqC.grantId, approver: { id: "bob" } }),
    approvals.approve({ grantId: reqC.grantId, approver: { id: "bob" } }),
  ]);
  var stC = await approvals.status(reqC.grantId);
  check("concurrent same-approver: counted once (no quorum bypass)",
        stC.approvedBy.length === 1 && stC.status === "pending");
  var okN  = dupResults.filter(function (r) { return !r.error; }).length;
  var dupN = dupResults.filter(function (r) { return r.error === "already-approved-by-this-actor"; }).length;
  check("concurrent same-approver: exactly one succeeds, one rejected duplicate",
        okN === 1 && dupN === 1);

  // (b) Two parallel consumes of a quorum-reached grant: exactly ONE wins
  // ready:true — never two (single-use).
  await approvals.approve({ grantId: reqC.grantId, approver: { id: "carol" } });   // 2/2 → approved
  var consumeResults = await Promise.all([
    approvals.consume(reqC.grantId),
    approvals.consume(reqC.grantId),
  ]);
  var readyN = consumeResults.filter(function (r) { return r.ready === true; }).length;
  check("concurrent consume: exactly one ready (no double-consume)", readyN === 1);

  // ---- Approver-role gate: wildcard match is segment-aware ----
  var roleApprovals = b.dualControl.create({
    namespace:     "test.rolewild",
    cache:         b.cache.create({ namespace: "dual-role-wild" }),
    audit:         b.audit,
    approverRoles: ["security:officer"],
  });
  // "security:o*" is a partial-segment wildcard — NOT the segment wildcard
  // "security:*" — so it must not authorize approval of a flow requiring
  // "security:officer" (segment-aware match via b.permissions.match, not a raw
  // string prefix where "security:officer".indexOf("security:o") === 0).
  var rwReq = await roleApprovals.request({ action: "<test>.rolewild", requestedBy: { id: "alice" } });
  var rwPartial = await roleApprovals.approve({
    grantId: rwReq.grantId, approver: { id: "bob", roles: ["security:o*"] },
  });
  check("dual-control: partial-segment role 'security:o*' is NOT authorized for 'security:officer'",
        rwPartial.error === "approver-role-required");

  // A proper segment wildcard "security:*" DOES authorize (legit wildcard kept).
  var rwReq2 = await roleApprovals.request({ action: "<test>.rolewild2", requestedBy: { id: "alice" } });
  var rwWild = await roleApprovals.approve({
    grantId: rwReq2.grantId, approver: { id: "carol", roles: ["security:*"] },
  });
  check("dual-control: segment wildcard 'security:*' authorizes approval",
        !rwWild.error && rwWild.approvedBy && rwWild.approvedBy.length === 1);

  // ---- Validation ----
  var threwBadCache = null;
  try { b.dualControl.create({ namespace: "x", cache: {} }); }
  catch (e) { threwBadCache = e; }
  check("create: rejects non-cache opts.cache", threwBadCache && /BAD_OPT/.test(threwBadCache.code || ""));

  var threwBadMin = null;
  try { b.dualControl.create({ namespace: "x", cache: cache, minApprovers: 1 }); }
  catch (e) { threwBadMin = e; }
  check("create: rejects minApprovers < 2",   threwBadMin && /BAD_OPT/.test(threwBadMin.code || ""));

  // ---------------------------------------------------------------------------
  // Adversarial / error-branch coverage — every path must FAIL CLOSED.
  // ---------------------------------------------------------------------------

  // ---- request(): argument validation (typed refusal, never a crash) ----
  var reqThrewNoArgs = null;
  try { await approvals.request(); } catch (e) { reqThrewNoArgs = e; }
  check("request: no args → typed BAD_ARG", reqThrewNoArgs && /BAD_ARG/.test(reqThrewNoArgs.code || ""));

  var reqThrewNoAction = null;
  try { await approvals.request({ requestedBy: { id: "alice" } }); } catch (e) { reqThrewNoAction = e; }
  check("request: missing action → typed BAD_ARG", reqThrewNoAction && /BAD_ARG/.test(reqThrewNoAction.code || ""));

  var reqThrewNoActor = null;
  try { await approvals.request({ action: "x", requestedBy: {} }); } catch (e) { reqThrewNoActor = e; }
  check("request: requestedBy without stable id → typed BAD_ARG",
        reqThrewNoActor && /BAD_ARG/.test(reqThrewNoActor.code || ""));

  var reqThrewNullActor = null;
  try { await approvals.request({ action: "x", requestedBy: null }); } catch (e) { reqThrewNullActor = e; }
  check("request: null requestedBy → typed BAD_ARG",
        reqThrewNullActor && /BAD_ARG/.test(reqThrewNullActor.code || ""));

  // ---- _actorIdOf(): every id-resolution fallback drives a real request ----
  var reqUnderId = await approvals.request({ action: "<test>.uid", requestedBy: { _id: "svc-1" } });
  check("actorId: resolves from _id", reqUnderId.status === "pending");
  var stUnderId = await approvals.status(reqUnderId.grantId);
  check("actorId: _id recorded as requestedBy", stUnderId.requestedBy === "svc-1");

  var reqUserId = await approvals.request({ action: "<test>.uid2", requestedBy: { userId: "u-9" } });
  var stUserId = await approvals.status(reqUserId.grantId);
  check("actorId: resolves from userId", stUserId.requestedBy === "u-9");

  var reqEmail = await approvals.request({ action: "<test>.uid3", requestedBy: { email: "eve@example.test" } });
  var stEmail = await approvals.status(reqEmail.grantId);
  check("actorId: email actor prefixed 'email:'", stEmail.requestedBy === "email:eve@example.test");

  // ---- approve(): argument validation ----
  var apThrewNoArgs = null;
  try { await approvals.approve(); } catch (e) { apThrewNoArgs = e; }
  check("approve: no args → typed BAD_ARG", apThrewNoArgs && /BAD_ARG/.test(apThrewNoArgs.code || ""));

  var apThrewNoApprover = null;
  try { await approvals.approve({ grantId: reqUserId.grantId, approver: {} }); }
  catch (e) { apThrewNoApprover = e; }
  check("approve: approver without stable id → typed BAD_ARG",
        apThrewNoApprover && /BAD_ARG/.test(apThrewNoApprover.code || ""));

  // ---- approve() on a grant that does not exist → fail closed ----
  var apMissing = await approvals.approve({ grantId: "dc-doesnotexist", approver: { id: "bob" } });
  check("approve: unknown grant → grant-not-found (no fabricated approval)",
        apMissing.error === "grant-not-found");

  // ---- revoke(): argument validation + edge branches ----
  var rvThrewNoArgs = null;
  try { await approvals.revoke(); } catch (e) { rvThrewNoArgs = e; }
  check("revoke: no args → typed BAD_ARG", rvThrewNoArgs && /BAD_ARG/.test(rvThrewNoArgs.code || ""));

  var rvMissing = await approvals.revoke({ grantId: "dc-nope", revokedBy: { id: "admin" } });
  check("revoke: unknown grant → grant-not-found", rvMissing.error === "grant-not-found");

  // revoke with no revokedBy actor still succeeds (admin-deny path; revokedById null)
  var reqRvNull = await approvals.request({ action: "<test>.rvnull", requestedBy: { id: "alice" } });
  var rvNull = await approvals.revoke({ grantId: reqRvNull.grantId });
  check("revoke: succeeds even without a named revoker", rvNull.status === "revoked");

  // revoke of an already-consumed grant → grant-already-consumed
  var reqRvConsumed = await approvals.request({ action: "<test>.rvcon", requestedBy: { id: "alice" } });
  await approvals.approve({ grantId: reqRvConsumed.grantId, approver: { id: "bob" } });
  await approvals.approve({ grantId: reqRvConsumed.grantId, approver: { id: "carol" } });
  await approvals.consume(reqRvConsumed.grantId);
  // consume() single-uses AND deletes the grant, so a later revoke sees no
  // record → grant-not-found (still fail closed; the destructive op already ran
  // exactly once and can never run again through this grant).
  var rvConsumed = await approvals.revoke({ grantId: reqRvConsumed.grantId, revokedBy: { id: "admin" } });
  check("revoke: consumed grant is gone → grant-not-found", rvConsumed.error === "grant-not-found");

  // ---- SECURITY-CRITICAL: consume() refuses UNDER-QUORUM (fail closed) ----
  var reqUnder = await approvals.request({ action: "<test>.underquorum", requestedBy: { id: "alice" } });
  await approvals.approve({ grantId: reqUnder.grantId, approver: { id: "bob" } });   // 1 of 2 only
  var consumeUnder = await approvals.consume(reqUnder.grantId);
  check("consume: UNDER-QUORUM refused (fail closed)",
        consumeUnder.ready === false && consumeUnder.reason === "not-enough-approvers");
  check("consume: under-quorum reports needs + current approvers",
        consumeUnder.needs === 2 && consumeUnder.approvedBy.length === 1);
  // The under-quorum grant is NOT consumed — a later legitimate second approval
  // still reaches quorum (refusal did not corrupt the grant).
  var underSecond = await approvals.approve({ grantId: reqUnder.grantId, approver: { id: "carol" } });
  check("consume: refusal left grant intact for legit quorum", underSecond.status === "approved");
  var consumeAfter = await approvals.consume(reqUnder.grantId);
  check("consume: proceeds once quorum truly reached", consumeAfter.ready === true);

  // ---- cancel(): full lifecycle (was entirely untested) ----
  var cxThrewNoArgs = null;
  try { await approvals.cancel(); } catch (e) { cxThrewNoArgs = e; }
  check("cancel: no args → typed BAD_ARG", cxThrewNoArgs && /BAD_ARG/.test(cxThrewNoArgs.code || ""));

  var cxMissing = await approvals.cancel({ grantId: "dc-none", cancelledBy: { id: "alice" } });
  check("cancel: unknown grant → grant-not-found", cxMissing.error === "grant-not-found");

  // only the requester may cancel — a stranger is refused
  var reqCancel = await approvals.request({ action: "<test>.cancel", requestedBy: { id: "alice" } });
  var cxStranger = await approvals.cancel({ grantId: reqCancel.grantId, cancelledBy: { id: "mallory" } });
  check("cancel: non-requester refused (only-requester-can-cancel)",
        cxStranger.error === "only-requester-can-cancel");
  // a missing cancelledBy actor is likewise not the requester → refused
  var cxNoActor = await approvals.cancel({ grantId: reqCancel.grantId });
  check("cancel: absent actor is not the requester → refused",
        cxNoActor.error === "only-requester-can-cancel");

  // the requester cancels successfully
  var cxOk = await approvals.cancel({ grantId: reqCancel.grantId, cancelledBy: { id: "alice" }, reason: "withdrawn" });
  check("cancel: requester cancels → cancelled", cxOk.status === "cancelled");
  // double cancel → grant-already-cancelled
  var cxAgain = await approvals.cancel({ grantId: reqCancel.grantId, cancelledBy: { id: "alice" } });
  check("cancel: second cancel → grant-already-cancelled", cxAgain.error === "grant-already-cancelled");
  // approve / consume a cancelled grant → fail closed
  var apCancelled = await approvals.approve({ grantId: reqCancel.grantId, approver: { id: "bob" } });
  check("approve: cancelled grant rejected", apCancelled.error === "grant-cancelled");
  var consumeCancelled = await approvals.consume(reqCancel.grantId);
  check("consume: cancelled grant → not-ready", consumeCancelled.ready === false && consumeCancelled.reason === "cancelled");

  // cancel a consumed grant → grant-already-consumed
  var reqCxCon = await approvals.request({ action: "<test>.cxcon", requestedBy: { id: "alice" } });
  await approvals.approve({ grantId: reqCxCon.grantId, approver: { id: "bob" } });
  await approvals.approve({ grantId: reqCxCon.grantId, approver: { id: "carol" } });
  await approvals.consume(reqCxCon.grantId);
  // As with revoke: the consumed grant was deleted, so cancel → grant-not-found.
  var cxConsumed = await approvals.cancel({ grantId: reqCxCon.grantId, cancelledBy: { id: "alice" } });
  check("cancel: consumed grant is gone → grant-not-found", cxConsumed.error === "grant-not-found");

  // cancel a revoked grant → grant-revoked
  var reqCxRev = await approvals.request({ action: "<test>.cxrev", requestedBy: { id: "alice" } });
  await approvals.revoke({ grantId: reqCxRev.grantId, revokedBy: { id: "admin" } });
  var cxRevoked = await approvals.cancel({ grantId: reqCxRev.grantId, cancelledBy: { id: "alice" } });
  check("cancel: revoked grant → grant-revoked", cxRevoked.error === "grant-revoked");

  // ---- status(): missing grant + every terminal state ----
  var stMissing = await approvals.status("dc-absent");
  check("status: unknown grant → null", stMissing === null);

  var stThrew = null;
  try { await approvals.status(""); } catch (e) { stThrew = e; }
  check("status: empty grantId → typed BAD_ARG", stThrew && /BAD_ARG/.test(stThrew.code || ""));

  var stRevoked = await approvals.status(reqCxRev.grantId);
  check("status: revoked state", stRevoked.status === "revoked");
  var stCancelled = await approvals.status(reqCancel.grantId);
  check("status: cancelled state", stCancelled.status === "cancelled");
  var stConsumedGone = await approvals.status(reqCxCon.grantId);
  check("status: consumed+single-use grant is gone → null", stConsumedGone === null);

  // ---- minReasonLength gate on request() AND approve() ----
  var reasonApprovals = b.dualControl.create({
    namespace:       "test.reason",
    cache:           b.cache.create({ namespace: "dual-reason" }),
    audit:           b.audit,
    minReasonLength: 12,
  });
  var rShort = await reasonApprovals.request({ action: "<test>.r", requestedBy: { id: "alice" }, reason: "too short" });
  check("request: reason below minReasonLength refused", rShort.error === "reason-too-short" && rShort.grantId === null);
  var rMissingReason = await reasonApprovals.request({ action: "<test>.r", requestedBy: { id: "alice" } });
  check("request: absent reason refused when minReasonLength set", rMissingReason.error === "reason-too-short");
  var rOk = await reasonApprovals.request({
    action: "<test>.r", requestedBy: { id: "alice" }, reason: "a properly long compliance reason",
  });
  check("request: adequate reason accepted", rOk.status === "pending");
  var rApShort = await reasonApprovals.approve({ grantId: rOk.grantId, approver: { id: "bob" }, reason: "nope" });
  check("approve: reason below minReasonLength refused", rApShort.error === "reason-too-short");

  // ---- approverRoles: an approver with NO qualifying role fails CLOSED ----
  var rNoRole = await roleApprovals.request({ action: "<test>.norole", requestedBy: { id: "alice" } });
  var apNoRole = await roleApprovals.approve({ grantId: rNoRole.grantId, approver: { id: "dave" } });
  check("approve: approver lacking required role → fail closed",
        apNoRole.error === "approver-role-required");
  var apEmptyRoles = await roleApprovals.approve({ grantId: rNoRole.grantId, approver: { id: "dave", roles: [] } });
  check("approve: approver with empty roles list → fail closed",
        apEmptyRoles.error === "approver-role-required");

  // ---- consumeLockMs cooling-off: quorum-reached grant blocks immediate consume ----
  var lockApprovals = b.dualControl.create({
    namespace:     "test.lock",
    cache:         b.cache.create({ namespace: "dual-lock" }),
    audit:         b.audit,
    consumeLockMs: 120,
  });
  var lReq = await lockApprovals.request({ action: "<test>.lock", requestedBy: { id: "alice" } });
  await lockApprovals.approve({ grantId: lReq.grantId, approver: { id: "bob" } });
  var lQuorum = await lockApprovals.approve({ grantId: lReq.grantId, approver: { id: "carol" } });
  check("consume-lock: approve reports a consumeUnlockAt", typeof lQuorum.consumeUnlockAt === "number");
  var lLocked = await lockApprovals.consume(lReq.grantId);
  check("consume-lock: immediate consume blocked (fail closed)",
        lLocked.ready === false && lLocked.reason === "consume-locked" && lLocked.waitMs > 0);
  // Poll (never sleep) until the cooling-off window elapses; each locked
  // attempt returns without consuming, so re-polling consume is safe.
  var lUnlocked = null;
  await helpers.waitUntil(async function () {
    var r = await lockApprovals.consume(lReq.grantId);
    if (r.ready) { lUnlocked = r; return true; }
    return false;
  }, { timeoutMs: 5000, label: "dual-control: consume unlocks after cooling-off" });
  check("consume-lock: consume proceeds once cooling-off elapses", lUnlocked && lUnlocked.ready === true);

  // ---- Expired grant: fail closed on approve AND consume ----
  // The lib couples the cache-entry TTL to the grant's logical expiry, so a
  // naturally-expired grant is evicted (grant-not-found) rather than surfacing
  // the grant-expired branch. That branch only fires under clock skew / a
  // sliding cache TTL where the entry outlives the grant's expiresAt — reproduce
  // that here by driving the real cache to push expiresAt into the past while
  // keeping the entry alive. Both outcomes fail closed.
  var expCache = b.cache.create({ namespace: "dual-exp" });
  var expApprovals = b.dualControl.create({ namespace: "test.exp", cache: expCache, audit: b.audit });
  function _stale(grantId) {
    return expCache.update("test.exp:" + grantId, function (rec) {
      rec.expiresAt = Date.now() - 1000;
      return { value: rec, ttlMs: 60 * 1000 };
    });
  }
  var expReq = await expApprovals.request({ action: "<test>.exp", requestedBy: { id: "alice" } });
  await _stale(expReq.grantId);
  var expApprove = await expApprovals.approve({ grantId: expReq.grantId, approver: { id: "bob" } });
  check("approve: expired grant refused (fail closed)", expApprove.error === "grant-expired");
  var expStatus = await expApprovals.status(expReq.grantId);
  check("status: expired grant reports 'expired'", expStatus.status === "expired");

  var expReq2 = await expApprovals.request({ action: "<test>.exp2", requestedBy: { id: "alice" } });
  await expApprovals.approve({ grantId: expReq2.grantId, approver: { id: "bob" } });
  await expApprovals.approve({ grantId: expReq2.grantId, approver: { id: "carol" } });
  await _stale(expReq2.grantId);
  var expConsume = await expApprovals.consume(expReq2.grantId);
  check("consume: expired (even quorum-reached) grant refused (fail closed)",
        expConsume.ready === false && expConsume.reason === "expired");

  // ---- notify hook fires on every transition; a throwing hook is swallowed ----
  var events = [];
  var notifyApprovals = b.dualControl.create({
    namespace: "test.notify",
    cache:     b.cache.create({ namespace: "dual-notify" }),
    notify:    function (e) { events.push(e.action); throw new Error("notify boom (must be swallowed)"); },
  });
  var nReq = await notifyApprovals.request({ action: "<test>.notify", requestedBy: { id: "alice" } });
  check("notify: request transition delivered", events.indexOf("dual.grant.requested") !== -1);
  await notifyApprovals.approve({ grantId: nReq.grantId, approver: { id: "bob" } });
  await notifyApprovals.approve({ grantId: nReq.grantId, approver: { id: "carol" } });
  check("notify: approve transition delivered", events.indexOf("dual.grant.approved") !== -1);
  var nConsume = await notifyApprovals.consume(nReq.grantId);
  check("notify: consume proceeds despite throwing hook (best-effort)", nConsume.ready === true);
  check("notify: consume transition delivered", events.indexOf("dual.grant.consumed") !== -1);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dual-control] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
