// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for b.dsr — Data Subject Rights workflow primitive (v0.7.104).
 *
 * Covers ticket lifecycle (submit/process/cancel/reject), per-source
 * orchestration (query/erase), audit emission, posture-aware deadline
 * computation, expireOverdue sweep, portability bundle build, and
 * the in-memory store reference implementation.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var C = b.constants;
var fs = helpers.fs;
var os = helpers.os;
var path = helpers.path;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dsr-")); }

function _makeDsr(extraOpts) {
  var sources = [
    {
      name: "users",
      query: async function (subj) {
        if (subj.email === "alice@example.com") {
          return [{ id: 1, name: "Alice", email: "alice@example.com" }];
        }
        return [];
      },
      erase: async function (subj) {
        if (subj.email === "alice@example.com") {
          return { deletedIds: [1] };
        }
        return { deletedIds: [] };
      },
    },
    {
      name: "orders",
      query: async function (subj) {
        if (subj.email === "alice@example.com") {
          return [
            { id: 100, total: 42.00 },
            { id: 101, total: 99.99 },
          ];
        }
        return [];
      },
      erase: async function (subj) {
        if (subj.email === "alice@example.com") {
          return { deletedIds: [100, 101] };
        }
        return { deletedIds: [] };
      },
    },
  ];
  var dsrOpts = Object.assign({
    ticketStore: b.dsr.memoryTicketStore(),
    posture:     "gdpr",
    identityResolver: async function (input) {
      // simple resolver — looks up by email
      if (input.email === "alice@example.com") {
        return { subjectId: "u-1", email: "alice@example.com", phone: null };
      }
      if (input.email === "bob@example.com") {
        return { subjectId: "u-2", email: "bob@example.com", phone: null };
      }
      return null;
    },
    sources: sources,
  }, extraOpts || {});
  return b.dsr.create(dsrOpts);
}

// ---- Ticket submit ----

async function testSubmitAccess() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "access",
    subject: { email: "alice@example.com" },
    reason:  "user-initiated",
  });
  check("dsr.submit access: ticket created", typeof ticket.id === "string" && ticket.id.indexOf("DSR-") === 0);
  check("dsr.submit access: status pending", ticket.status === "pending");
  check("dsr.submit access: subject resolved", ticket.subject.subjectId === "u-1");
  check("dsr.submit access: posture stamped", ticket.posture === "gdpr");
  check("dsr.submit access: deadline = +30d (gdpr)",
        ticket.deadlineAt > ticket.submittedAt &&
        ticket.deadlineAt - ticket.submittedAt === C.TIME.days(30));
}

async function testSubmitErasure() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "erasure",
    subject: { email: "bob@example.com" },
  });
  check("dsr.submit erasure: subject u-2", ticket.subject.subjectId === "u-2");
  check("dsr.submit erasure: type erasure", ticket.type === "erasure");
}

async function testSubmitInvalidType() {
  var dsr = _makeDsr();
  var threw = false;
  try { await dsr.submit({ type: "INVALID", subject: { email: "x" } }); }
  catch (_e) { threw = true; }
  check("dsr.submit: invalid type throws", threw);
}

async function testSubmitNoSubject() {
  var dsr = _makeDsr();
  var threw = false;
  try { await dsr.submit({ type: "access" }); }
  catch (_e) { threw = true; }
  check("dsr.submit: missing subject throws", threw);
}

async function testSubmitIdentityResolverFails() {
  var dsr = _makeDsr();
  var threw = false;
  try {
    await dsr.submit({
      type: "access",
      subject: { email: "ghost@example.com" },
    });
  } catch (_e) { threw = true; }
  check("dsr.submit: unresolved identity throws", threw);
}

async function testSubmitCustomDeadline() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:       "access",
    subject:    { email: "alice@example.com" },
    deadlineMs: C.TIME.days(7),
  });
  check("dsr.submit: custom deadline honored",
        ticket.deadlineAt - ticket.submittedAt === C.TIME.days(7));
}

// ---- Ticket process ----

async function testProcessAccess() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "access",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id, { actor: "compliance@example.com" });
  check("dsr.process access: status completed",
        result.status === "completed");
  check("dsr.process access: 2 sources queried",
        result.sourceResults.length === 2);
  check("dsr.process access: users source returned 1 row",
        result.sourceResults[0].rows === 1);
  check("dsr.process access: orders source returned 2 rows",
        result.sourceResults[1].rows === 2);
  check("dsr.process access: result.totalRowsFound = 3",
        result.result.totalRowsFound === 3);
}

async function testProcessErasure() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "erasure",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",   // erasure requires secondary
  });
  var result = await dsr.process(ticket.id, { actor: "admin@" });
  check("dsr.process erasure: status completed",
        result.status === "completed");
  check("dsr.process erasure: users source erased 1",
        result.sourceResults[0].deleted === 1);
  check("dsr.process erasure: orders source erased 2",
        result.sourceResults[1].deleted === 2);
  check("dsr.process erasure: totalDeleted = 3",
        result.result.totalDeleted === 3);
}

async function testProcessRestriction() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "restriction",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id);
  check("dsr.process restriction: marked-restricted",
        result.sourceResults[0].outcome === "marked-restricted");
  check("dsr.process restriction: status completed",
        result.status === "completed");
}

async function testProcessObject() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "object",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id);
  check("dsr.process object: marked-objection",
        result.sourceResults[0].outcome === "marked-objection");
}

async function testProcessAutomatedDecision() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type:    "automated-decision",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id);
  check("dsr.process automated-decision: marked review",
        result.sourceResults[0].outcome === "marked-automated-decision-review");
}

async function testProcessSourceFailure() {
  var failingSources = [
    {
      name: "broken",
      query: async function () { throw new Error("DB unreachable"); },
    },
    {
      name: "ok",
      query: async function () { return [{ id: 1 }]; },
    },
  ];
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(),
    posture: "gdpr",
    identityResolver: async function () { return { subjectId: "u" }; },
    sources: failingSources,
  });
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "x" },
  });
  var result = await dsr.process(ticket.id);
  check("dsr.process: source failure → partially_completed",
        result.status === "partially_completed");
  check("dsr.process: failed source recorded",
        result.sourceResults[0].outcome === "failed");
  check("dsr.process: failed source has error message",
        typeof result.sourceResults[0].error === "string" &&
        result.sourceResults[0].error.indexOf("DB unreachable") !== -1);
  check("dsr.process: ok source still completed",
        result.sourceResults[1].outcome === "queried");
}

async function testProcessNotFound() {
  var dsr = _makeDsr();
  var threw = false;
  try { await dsr.process("DSR-NONEXISTENT"); }
  catch (_e) { threw = true; }
  check("dsr.process: unknown ticket throws", threw);
}

async function testProcessTerminalState() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var threw = false;
  try { await dsr.process(ticket.id); }
  catch (_e) { threw = true; }
  check("dsr.process: re-processing completed ticket throws", threw);
}

// ---- Cancel + reject ----

async function testCancel() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var cancelled = await dsr.cancel(ticket.id, {
    actor:  "admin@",
    reason: "subject withdrew on phone",
  });
  check("dsr.cancel: status cancelled", cancelled.status === "cancelled");
  check("dsr.cancel: reason captured",
        cancelled.cancelReason === "subject withdrew on phone");
}

async function testCancelTerminal() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var threw = false;
  try { await dsr.cancel(ticket.id); }
  catch (_e) { threw = true; }
  check("dsr.cancel: terminal-state ticket throws", threw);
}

async function testReject() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
  });
  var rejected = await dsr.reject(ticket.id, {
    actor:  "compliance@",
    reason: "manifestly unfounded under GDPR Art. 12(5)(b)",
  });
  check("dsr.reject: status rejected", rejected.status === "rejected");
  check("dsr.reject: reason captured",
        rejected.rejectReason.indexOf("manifestly unfounded") !== -1);
}

async function testRejectRequiresReason() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var threw = false;
  try { await dsr.reject(ticket.id); }
  catch (_e) { threw = true; }
  check("dsr.reject: missing reason throws", threw);
}

// ---- List / get ----

async function testListBySubject() {
  var dsr = _makeDsr();
  var t1 = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var t2 = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
  });
  await dsr.submit({
    type: "access",
    subject: { email: "bob@example.com" },
  });
  var alice = await dsr.listBySubject({ email: "alice@example.com" });
  check("dsr.listBySubject: 2 alice tickets", alice.length === 2);
  check("dsr.listBySubject: not bob's",
        alice.every(function (t) { return t.subject.email === "alice@example.com"; }));
  void t1; void t2;
}

async function testListByStatus() {
  var dsr = _makeDsr();
  var t1 = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.submit({
    type: "access",
    subject: { email: "bob@example.com" },
  });
  await dsr.process(t1.id);
  var pending = await dsr.listByStatus("pending");
  check("dsr.listByStatus pending: 1 ticket", pending.length === 1);
  var completed = await dsr.listByStatus("completed");
  check("dsr.listByStatus completed: 1 ticket", completed.length === 1);
}

// ---- expireOverdue ----

async function testExpireOverdue() {
  var dsr = _makeDsr({ deadlineMs: 50 });   // 50ms — for testing
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  // Wait past the 50ms deadline, then poll expireOverdue() until it
  // collects the ticket.
  var expired = await helpers.waitUntil(async function () {
    var rv = await dsr.expireOverdue();
    return rv.length >= 1 ? rv : false;
  }, { label: "dsr.expireOverdue: 50ms-deadline ticket collected" });
  check("dsr.expireOverdue: 1 expired", expired.length === 1);
  check("dsr.expireOverdue: ticket marked expired",
        expired[0].id === ticket.id && expired[0].status === "expired");
}

async function testExpireOverdueSkipsCompleted() {
  var dsr = _makeDsr({ deadlineMs: 50 });
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  // Wait past the 50ms deadline. Even though the ticket is completed,
  // verify expireOverdue() does NOT collect it; pass real time then
  // call expireOverdue once.
  await helpers.passiveObserve(80, "dsr.expireOverdue: deadline elapsed for completed ticket");
  var expired = await dsr.expireOverdue();
  check("dsr.expireOverdue: completed tickets not re-expired",
        expired.length === 0);
}

// ---- Portability bundle ----

async function testPortabilityBundle() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "portability",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  var processed = await dsr.process(ticket.id);
  var bundle = dsr.buildPortabilityBundle(processed);
  check("buildPortabilityBundle: schema version",
        bundle.schema === "blamejs.dsr.portability/1");
  check("buildPortabilityBundle: ticketId echoed",
        bundle.ticketId === ticket.id);
  check("buildPortabilityBundle: data has users",
        Array.isArray(bundle.data.users) && bundle.data.users[0].email === "alice@example.com");
  check("buildPortabilityBundle: data has orders",
        Array.isArray(bundle.data.orders) && bundle.data.orders.length === 2);
}

async function testPortabilityWrongType() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  var processed = await dsr.process(ticket.id);
  var threw = false;
  try { dsr.buildPortabilityBundle(processed); }
  catch (_e) { threw = true; }
  check("buildPortabilityBundle: erasure type throws", threw);
}

async function testPortabilityNotCompleted() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "portability",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  // Don't process — still pending
  var threw = false;
  try { dsr.buildPortabilityBundle(ticket); }
  catch (_e) { threw = true; }
  check("buildPortabilityBundle: pending ticket throws", threw);
}

// ---- Posture deadlines ----

function testPostureDeadlines() {
  var dsrMod = require("../../lib/dsr");
  // gdpr → 30 days
  check("posture gdpr deadline = 30d",
        dsrMod.POSTURE_DEADLINE_MS["gdpr"] === C.TIME.days(30));
  // ccpa → 45 days
  check("posture ccpa deadline = 45d",
        dsrMod.POSTURE_DEADLINE_MS["ccpa"] === C.TIME.days(45));
  // lgpd-br → 15 days
  check("posture lgpd-br deadline = 15d",
        dsrMod.POSTURE_DEADLINE_MS["lgpd-br"] === C.TIME.days(15));
  // pipl-cn → 15 days
  check("posture pipl-cn deadline = 15d",
        dsrMod.POSTURE_DEADLINE_MS["pipl-cn"] === C.TIME.days(15));
}

async function testPosturePicksDifferentDeadlines() {
  var ccpaDsr = _makeDsr({ posture: "ccpa" });
  var t1 = await ccpaDsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  check("posture ccpa: deadline = +45d",
        t1.deadlineAt - t1.submittedAt === C.TIME.days(45));

  var brDsr = _makeDsr({ posture: "lgpd-br" });
  var t2 = await brDsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  check("posture lgpd-br: deadline = +15d",
        t2.deadlineAt - t2.submittedAt === C.TIME.days(15));
}

async function testPostureUnknownFallsBackToDefault() {
  var dsr = _makeDsr({ posture: "made-up-posture" });
  var t = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  check("posture unknown: deadline falls back to default 30d",
        t.deadlineAt - t.submittedAt === C.TIME.days(30));
}

// ---- create() validation ----

function testCreateValidation() {
  var threwBadStore = false;
  try { b.dsr.create({ ticketStore: { insert: function () {} } }); }
  catch (_e) { threwBadStore = true; }
  check("dsr.create: invalid store throws", threwBadStore);

  var threwNoSources = false;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () {},
      sources: [],
    });
  } catch (_e) { threwNoSources = true; }
  check("dsr.create: empty sources throws", threwNoSources);

  var threwNoIdentity = false;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      sources: [{ name: "x", query: async function () {} }],
    });
  } catch (_e) { threwNoIdentity = true; }
  check("dsr.create: missing identityResolver throws", threwNoIdentity);

  // De-advertised create-time keys: `observability` was never read at
  // create (the counter always fires through the module sink) and
  // `verifyContext` is a per-call process() opt, not a create() opt.
  // Both removed from the create allowlist → unknown-option throw.
  function _validBase() {
    return {
      ticketStore:      b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources:          [{ name: "x", query: async function () { return []; } }],
    };
  }
  var threwObs = false;
  try {
    var oObs = _validBase(); oObs.observability = true;
    b.dsr.create(oObs);
  } catch (e) { threwObs = /unknown option 'observability'/.test(e.message || ""); }
  check("dsr.create: unknown 'observability' opt rejected", threwObs);

  var threwVc = false;
  try {
    var oVc = _validBase(); oVc.verifyContext = { mfaVerified: true };
    b.dsr.create(oVc);
  } catch (e) { threwVc = /unknown option 'verifyContext'/.test(e.message || ""); }
  check("dsr.create: unknown create-time 'verifyContext' opt rejected", threwVc);

  // Sanity: the valid base still constructs.
  check("dsr.create: valid base opts construct",
        typeof b.dsr.create(_validBase()).submit === "function");
}

// ---- Memory store ----

async function testMemoryStore() {
  var store = b.dsr.memoryTicketStore();
  await store.insert({ id: "T1", subject: { email: "a" }, status: "pending" });
  await store.insert({ id: "T2", subject: { email: "b" }, status: "pending" });
  await store.insert({ id: "T3", subject: { email: "a" }, status: "completed" });

  var t1 = await store.get("T1");
  check("memoryStore.get: returns ticket", t1 && t1.id === "T1");

  var byA = await store.list({ subject: { email: "a" } });
  check("memoryStore.list: filter by subject", byA.length === 2);

  var pending = await store.list({ status: "pending" });
  check("memoryStore.list: filter by status", pending.length === 2);

  var threwDup = false;
  try { await store.insert({ id: "T1", subject: {}, status: "pending" }); }
  catch (_e) { threwDup = true; }
  check("memoryStore.insert: duplicate id throws", threwDup);

  // update preserves shape
  await store.update("T1", { id: "T1", subject: { email: "a" }, status: "completed" });
  var t1Updated = await store.get("T1");
  check("memoryStore.update: status updated", t1Updated.status === "completed");
}

// ---- Verification ladder ----

async function testVerificationDefault() {
  var dsr = _makeDsr();
  // Default verificationLevel is "minimal"; access requires "minimal"
  // → should pass
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id);
  check("verification: access at minimal level processes",
        result.status === "completed");
  check("verification: ticket stamped with level",
        result.verificationLevel === "minimal");
}

async function testVerificationErasureRequiresSecondary() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
  });
  // Erasure requires "secondary"; default is "minimal" → should fail
  var threw = false;
  try { await dsr.process(ticket.id); }
  catch (_e) { threw = true; }
  check("verification: erasure refuses minimal level", threw);

  // Provide secondary level → should now process
  var result = await dsr.process(ticket.id, { verificationLevel: "secondary" });
  check("verification: erasure accepts secondary level",
        result.status === "completed");
}

async function testVerificationStrong() {
  var dsr = _makeDsr({
    minVerificationByType: { "access": "strong" },
  });
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var threw = false;
  try { await dsr.process(ticket.id, { verificationLevel: "secondary" }); }
  catch (_e) { threw = true; }
  check("verification: operator-override 'strong' refuses secondary",
        threw);
  var result = await dsr.process(ticket.id, { verificationLevel: "strong" });
  check("verification: 'strong' accepts strong level",
        result.status === "completed");
}

async function testVerificationContext() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id, {
    verifyContext: { mfaVerified: true, attestation: "abc" },
  });
  check("verification: verifyContext captured",
        result.verifyContext &&
        result.verifyContext.mfaVerified === true);
}

async function testVerificationLevelOnSubmit() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  // Ticket stamped with secondary at submit time; process() can use
  // it without passing again
  var result = await dsr.process(ticket.id);
  check("verification: submit-time level used at process",
        result.status === "completed");
}

// ---- Receipt ----

async function testBuildReceipt() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("receipt: schema version",
        receipt.schema === "blamejs.dsr.receipt/1");
  check("receipt: ticketId",          receipt.ticketId === ticket.id);
  check("receipt: type",              receipt.type === "access");
  check("receipt: status completed",  receipt.status === "completed");
  check("receipt: subject email",     receipt.subject.email === "alice@example.com");
  check("receipt: posture stamped",   receipt.posture === "gdpr");
  check("receipt: summary has rows",  receipt.summary.totalRowsFound === 3);
  check("receipt: summary has sources",
        Array.isArray(receipt.summary.sources) && receipt.summary.sources.length === 2);
  check("receipt: issuedAt is recent",
        typeof receipt.issuedAt === "number" && receipt.issuedAt > Date.now() - 5000);
}

async function testReceiptForCancelled() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.cancel(ticket.id, { actor: "admin", reason: "withdrew" });
  var receipt = await dsr.buildReceipt(ticket.id);
  check("receipt: cancelled status",   receipt.status === "cancelled");
  check("receipt: cancelReason captured",
        receipt.summary.cancelReason === "withdrew");
}

async function testReceiptForRejected() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "erasure",
    subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  await dsr.reject(ticket.id, { reason: "manifestly unfounded" });
  var receipt = await dsr.buildReceipt(ticket.id);
  check("receipt: rejected status",    receipt.status === "rejected");
  check("receipt: rejectReason captured",
        receipt.summary.rejectReason === "manifestly unfounded");
}

async function testReceiptNotTerminal() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  var threw = false;
  try { await dsr.buildReceipt(ticket.id); }
  catch (_e) { threw = true; }
  check("receipt: pending ticket throws", threw);
}

async function testReceiptWithSigner() {
  var signCalled = 0;
  var dsr = _makeDsr({
    receiptSigner: async function (receipt) {
      signCalled += 1;
      return {
        issuer:    "compliance@example.com",
        algorithm: "ed25519",
        signature: "FAKE_SIG_" + receipt.ticketId,
      };
    },
  });
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("receipt: signer called once", signCalled === 1);
  check("receipt: issuer captured",     receipt.issuer === "compliance@example.com");
  check("receipt: signature captured",
        receipt.signature && receipt.signature.indexOf("FAKE_SIG") === 0);
  check("receipt: algorithm captured",  receipt.algorithm === "ed25519");
}

async function testReceiptSignerError() {
  var dsr = _makeDsr({
    receiptSigner: async function () {
      throw new Error("HSM unavailable");
    },
  });
  var ticket = await dsr.submit({
    type: "access",
    subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("receipt: signer error captured",
        typeof receipt.signatureError === "string" &&
        receipt.signatureError.indexOf("HSM unavailable") !== -1);
  check("receipt: still issued without signature",
        receipt.signature === undefined);
}

// ---- dbTicketStore: at-rest sealing + erasure purge + upgrade path ----

function _dbDsr(extraOpts) {
  var store = b.dsr.dbTicketStore({ db: b.db });
  return {
    store: store,
    dsr: b.dsr.create(Object.assign({
      ticketStore: store,
      posture:     "gdpr",
      identityResolver: async function (input) {
        if (input.email === "alice@example.com") {
          return { subjectId: "u-1", email: "alice@example.com", phone: "+15550001111" };
        }
        return null;
      },
      sources: [{
        name:  "users",
        query: async function () { return [{ id: 1 }]; },
        erase: async function () { return { deletedIds: [1] }; },
      }],
    }, extraOpts || {})),
  };
}

async function testDbStoreSealsAtRest() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var h = _dbDsr();
    var ticket = await h.dsr.submit({
      type:    "access",
      subject: { email: "alice@example.com" },
      reason:  "sealing-at-rest verification",
    });
    // Read the RAW row directly (bypassing the store's unseal) and assert
    // the PII columns + payload are NOT stored in plaintext.
    var raw = b.db.prepare(
      "SELECT subject_email, subject_phone, subject_id, subject_email_hash, payload " +
      "FROM dsr_tickets WHERE id = $id").all({ $id: ticket.id })[0];
    check("dbStore: raw row exists", !!raw);
    check("dbStore: subject_email sealed at rest (not plaintext)",
          typeof raw.subject_email === "string" &&
          raw.subject_email.indexOf("alice@example.com") === -1);
    check("dbStore: subject_phone sealed at rest (not plaintext)",
          typeof raw.subject_phone === "string" &&
          raw.subject_phone.indexOf("+15550001111") === -1);
    check("dbStore: payload sealed at rest (no plaintext email leak)",
          typeof raw.payload === "string" &&
          raw.payload.indexOf("alice@example.com") === -1);
    check("dbStore: derived email hash populated for lookup",
          typeof raw.subject_email_hash === "string" && raw.subject_email_hash.length > 0);

    // The store still round-trips the cleartext ticket via get().
    var got = await h.store.get(ticket.id);
    check("dbStore: get() unseals payload back to cleartext",
          got && got.subject.email === "alice@example.com");

    // list-by-subject matches via the derived hash (sealed columns can't
    // be matched on plaintext).
    var listed = await h.store.list({ subject: { email: "alice@example.com" } });
    check("dbStore: list-by-subject matches via derived hash",
          listed.length === 1 && listed[0].id === ticket.id);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreLargePayloadRoundTrips() {
  // A completed access/portability ticket can carry a data export larger
  // than safeJson's 1 MiB parse default. The store reads its payload column
  // back with the store-matched ceiling, so a multi-MiB ticket round-trips
  // through get() and list() rather than failing json/too-large.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var h = _dbDsr();
    var bigExport = "x".repeat(C.BYTES.mib(2)); // ~2 MiB > the 1 MiB read default
    var ticket = {
      id:                "dsr-big-1",
      type:              "access",
      status:            "completed",
      subject:           { subjectId: "u-1", email: "alice@example.com", phone: "+15550001111" },
      submittedAt:       Date.now(),
      deadlineAt:        Date.now() + C.TIME.minutes(1),
      processedAt:       Date.now(),
      verificationLevel: "primary",
      posture:           "gdpr",
      export:            bigExport,
    };
    await h.store.insert(ticket);

    var got = await h.store.get("dsr-big-1");
    check("dbStore: >1 MiB ticket round-trips through get()",
          got && got.export === bigExport && got.status === "completed");

    var listed = await h.store.list({ subject: { email: "alice@example.com" } });
    check("dbStore: >1 MiB ticket round-trips through list()",
          listed.length === 1 && listed[0].export === bigExport);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreErasurePurgesPriorTickets() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var h = _dbDsr();
    // Two prior access tickets for alice + a final erasure.
    var t1 = await h.dsr.submit({ type: "access", subject: { email: "alice@example.com" }, reason: "prior access one" });
    var t2 = await h.dsr.submit({ type: "access", subject: { email: "alice@example.com" }, reason: "prior access two" });
    var erasure = await h.dsr.submit({
      type: "erasure", subject: { email: "alice@example.com" },
      reason: "right to erasure", verificationLevel: "secondary",
    });
    var before = await h.store.list({ subject: { email: "alice@example.com" } });
    check("dbStore erasure: 3 tickets before completion", before.length === 3);

    var processed = await h.dsr.process(erasure.id, { actor: "compliance@", verificationLevel: "secondary" });
    check("dbStore erasure: erasure completed", processed.status === "completed");

    // After completion, the subject's prior tickets are purged; the
    // erasure ticket itself survives (audit/receipt trail).
    var after = await h.store.list({ subject: { email: "alice@example.com" } });
    check("dbStore erasure: only the erasure ticket remains", after.length === 1 && after[0].id === erasure.id);
    check("dbStore erasure: prior ticket t1 gone", (await h.store.get(t1.id)) === null);
    check("dbStore erasure: prior ticket t2 gone", (await h.store.get(t2.id)) === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreUpgradePath() {
  // Build an OLD-shape (v0.8.0) dsr_tickets table by hand — no
  // subject_*_hash columns — then construct the store. ensureSchema must
  // ALTER TABLE ADD COLUMN the missing columns so the first insert
  // succeeds rather than throwing "no such column".
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.db.runSql("CREATE TABLE dsr_tickets (" +
      "id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, " +
      "subject_id TEXT, subject_email TEXT, subject_phone TEXT, " +
      "submitted_at INTEGER NOT NULL, deadline_at INTEGER NOT NULL, " +
      "processed_at INTEGER, verification_level TEXT, posture TEXT, " +
      "payload TEXT NOT NULL)");
    // Seed a legacy plaintext row to prove the ALTER survives existing data.
    b.db.prepare("INSERT INTO dsr_tickets (id, type, status, subject_email, submitted_at, deadline_at, payload) " +
      "VALUES ($id, $type, $status, $email, $sa, $da, $p)").run({
        $id: "DSR-LEGACY-1", $type: "access", $status: "pending",
        $email: "legacy@example.com", $sa: Date.now(), $da: Date.now() + 1000,
        $p: JSON.stringify({ id: "DSR-LEGACY-1", status: "pending", subject: { email: "legacy@example.com" } }),
      });

    // Also seed an OVERSIZED legacy plaintext row: its payload cannot be
    // re-sealed into the vaulted store (the sealed form exceeds b.sql's
    // per-value ceiling). The backfill must SKIP it — leaving it un-migrated —
    // rather than crash provisioning with a SqlBuilderError.
    var bigLegacy = "x".repeat(C.BYTES.mib(50));
    b.db.prepare("INSERT INTO dsr_tickets (id, type, status, subject_email, submitted_at, deadline_at, payload) " +
      "VALUES ($id, $type, $status, $email, $sa, $da, $p)").run({
        $id: "DSR-LEGACY-BIG", $type: "access", $status: "pending",
        $email: "big@example.com", $sa: Date.now(), $da: Date.now() + 1000, $p: bigLegacy,
      });
    bigLegacy = null;   // release the big string promptly

    // Constructing the store runs ensureSchema → reconciles the columns AND
    // runs the legacy backfill (which must not crash on the oversized row).
    var h = _dbDsr();
    var cols = b.db.prepare("PRAGMA table_info(dsr_tickets)").all({});
    var names = cols.map(function (c) { return c.name; });
    check("dbStore upgrade: subject_email_hash column added",
          names.indexOf("subject_email_hash") !== -1);
    check("dbStore upgrade: subject_id_hash column added",
          names.indexOf("subject_id_hash") !== -1);

    // A fresh insert against the upgraded table succeeds (the bug under
    // test threw "no such column: subject_email_hash" here).
    var ticket = await h.dsr.submit({
      type: "access", subject: { email: "alice@example.com" }, reason: "post-upgrade insert",
    });
    check("dbStore upgrade: insert succeeds after schema reconcile",
          typeof ticket.id === "string");
    var got = await h.store.get(ticket.id);
    check("dbStore upgrade: round-trips the new ticket", got && got.subject.email === "alice@example.com");

    // The legacy row was seeded with a plaintext subject and NULL hash. Once a
    // vault is present, list({ subject }) matches on the hash column, so the
    // upgrade MUST have backfilled the legacy row's hash — otherwise it is
    // invisible to a subject lookup and the erasure-completion purge skips it.
    var legacyFound = await h.store.list({ subject: { email: "legacy@example.com" } });
    check("dbStore upgrade: legacy plaintext row backfilled + found by subject",
          legacyFound.some(function (t) { return t.id === "DSR-LEGACY-1"; }));
    var rawLegacy = b.db.prepare(
      "SELECT subject_email, subject_email_hash FROM dsr_tickets WHERE id = $id")
      .all({ $id: "DSR-LEGACY-1" })[0];
    check("dbStore upgrade: legacy subject_email_hash populated by backfill",
          rawLegacy && typeof rawLegacy.subject_email_hash === "string" &&
          rawLegacy.subject_email_hash.length > 0);
    check("dbStore upgrade: legacy subject_email sealed at rest by backfill (now erasable)",
          rawLegacy && rawLegacy.subject_email !== "legacy@example.com");

    // The oversized legacy row was migrated for FINDABILITY without crashing:
    // its subject columns are sealed and its derived hash is populated (so
    // list({ subject }) and the erasure purge see it — no un-erasable PII),
    // while its over-cap payload is left plaintext (it cannot be sealed, but
    // it is DB-encrypted at rest and removed when the row is erased).
    var rawBig = b.db.prepare(
      "SELECT subject_email, subject_email_hash, payload FROM dsr_tickets WHERE id = $id")
      .all({ $id: "DSR-LEGACY-BIG" })[0];
    check("dbStore upgrade: oversized legacy row hash populated (findable by subject lookup, erasable)",
          rawBig && typeof rawBig.subject_email_hash === "string" && rawBig.subject_email_hash.length > 0);
    check("dbStore upgrade: oversized legacy row subject sealed at rest",
          rawBig && rawBig.subject_email !== "big@example.com");
    check("dbStore upgrade: over-cap payload left plaintext (not sealed, but erasable via row delete)",
          rawBig && typeof rawBig.payload === "string" && rawBig.payload.indexOf("vault:") !== 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreFindsLegacyKeyedMacRows() {
  // A ticket written BEFORE the keyed-MAC default flip stored the LEGACY
  // salted-sha3 digest in subject_email_hash (non-NULL, so the NULL-only
  // backfill never migrates it). list-by-subject must still FIND it via the
  // dual-read (keyed-MAC + legacy candidates) — otherwise an Art.17 erasure
  // purge (list → delete) skips the subject's prior PII-bearing tickets.
  var cryptoField = require("../../lib/crypto-field");
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var h = _dbDsr();
    var t = await h.dsr.submit({
      type: "access", subject: { email: "alice@example.com" }, reason: "pre-flip ticket",
    });
    // Simulate a pre-flip row: overwrite the keyed-MAC hash with the legacy
    // salted-sha3 digest the old default would have stored.
    var d = cryptoField.computeDerived("dsr_tickets", "subject_email", "alice@example.com");
    check("dsr legacy: a legacy digest distinct from the keyed-MAC exists",
          d && d.legacyValue && d.legacyValue !== d.value);
    b.db.prepare("UPDATE dsr_tickets SET subject_email_hash = $h WHERE id = $id")
      .run({ $h: d.legacyValue, $id: t.id });
    // RED before the dual-read fix: the keyed-MAC single-value equality never
    // matches the legacy digest, so this returns 0 rows.
    var found = await h.store.list({ subject: { email: "alice@example.com" } });
    check("dsr legacy: list-by-subject finds the pre-flip legacy-hashed ticket",
          found.some(function (x) { return x.id === t.id; }));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- AAD_ROTATION descriptor + reseal ----

function testAadRotationDescriptor() {
  var d = b.dsr.AAD_ROTATION;
  check("AAD_ROTATION: exported", d && typeof d === "object");
  check("AAD_ROTATION: table is dsr_tickets", d.table === "dsr_tickets");
  check("AAD_ROTATION: rowIdField is id", d.rowIdField === "id");
  check("AAD_ROTATION: backend external", d.backend === "external");
  check("AAD_ROTATION: reseal is the fn", d.reseal === b.dsr.reseal && typeof d.reseal === "function");
}

async function testResealValidationAndStore() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Missing roots are rejected at entry.
    var threw = null;
    try { await b.dsr.reseal({ store: { listAll: function () { return []; }, putResealed: function () {} } }); }
    catch (e) { threw = e; }
    check("reseal: missing root snapshots refused",
          threw && /dsr\/bad-root/.test(threw.code));

    // Bad store shape is rejected.
    var threw2 = null;
    try { await b.dsr.reseal({ oldRootJson: "{}", newRootJson: "{}", store: {} }); }
    catch (e) { threw2 = e; }
    check("reseal: store missing listAll/putResealed refused",
          threw2 && /dsr\/bad-reseal-store/.test(threw2.code));

    // A store whose rows carry no AAD-sealed cells re-seals nothing
    // (plaintext rows pass through) — exercises the row-walk + putResealed
    // contract without needing a full keypair rotation.
    var keys = b.vault.getKeysJson();
    var puts = [];
    var plainStore = {
      listAll:     function () { return [{ id: "T1", payload: "plain-json" }]; },
      putResealed: function (row) { puts.push(row.id); },
    };
    var rv = await b.dsr.reseal({ oldRootJson: keys, newRootJson: keys, store: plainStore });
    check("reseal: returns table + resealed count", rv.table === "dsr_tickets" && rv.resealed === 0);
    check("reseal: plaintext rows not re-persisted", puts.length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- create() adversarial validation ----

async function testCreateBadSource() {
  var threw = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      // second source has neither query nor erase → invalid
      sources: [{ name: "ok", query: async function () { return []; } }, { name: "bad" }],
    });
  } catch (e) { threw = e; }
  check("dsr.create: source missing query/erase → dsr/bad-source",
        threw && threw.code === "dsr/bad-source");
}

function testCreateBadPosture() {
  var threw = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [{ name: "x", query: async function () { return []; } }],
      posture: 123,   // non-string posture
    });
  } catch (e) { threw = e; }
  check("dsr.create: non-string posture → dsr/bad-posture",
        threw && threw.code === "dsr/bad-posture");
}

function testCreateBadDefaultVerificationLevel() {
  var threw = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [{ name: "x", query: async function () { return []; } }],
      verificationLevel: "bogus",
    });
  } catch (e) { threw = e; }
  check("dsr.create: invalid verificationLevel → dsr/bad-verification-level",
        threw && threw.code === "dsr/bad-verification-level");
}

function testCreateBadMinVerificationByType() {
  var threw = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [{ name: "x", query: async function () { return []; } }],
      minVerificationByType: { erasure: "bogus-level" },
    });
  } catch (e) { threw = e; }
  check("dsr.create: invalid minVerificationByType value → dsr/bad-min-verification",
        threw && threw.code === "dsr/bad-min-verification");
}

// ---- submit() adversarial ----

async function testSubmitBadInput() {
  var dsr = _makeDsr();
  var threwNull = null;
  try { await dsr.submit(null); } catch (e) { threwNull = e; }
  check("dsr.submit: null input → dsr/bad-submit",
        threwNull && threwNull.code === "dsr/bad-submit");
  var threwStr = null;
  try { await dsr.submit("not-an-object"); } catch (e) { threwStr = e; }
  check("dsr.submit: non-object input → dsr/bad-submit",
        threwStr && threwStr.code === "dsr/bad-submit");
}

async function testSubmitIdentityResolverThrows() {
  // Distinct from testSubmitIdentityResolverFails (resolver RETURNS null):
  // here the resolver THROWS, exercising the reject-audit + wrap path.
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(),
    posture: "gdpr",
    identityResolver: async function () { throw new Error("resolver backend down"); },
    sources: [{ name: "x", query: async function () { return []; } }],
  });
  var threw = null;
  try { await dsr.submit({ type: "access", subject: { email: "a@b.com" } }); }
  catch (e) { threw = e; }
  check("dsr.submit: identityResolver throw → dsr/identity-resolver-failed",
        threw && threw.code === "dsr/identity-resolver-failed");
  check("dsr.submit: identity-resolver error surfaced in message",
        threw && /resolver backend down/.test(threw.message || ""));
}

async function testSubmitBadVerificationLevel() {
  var dsr = _makeDsr();
  var threw = null;
  try {
    await dsr.submit({
      type: "access",
      subject: { email: "alice@example.com" },
      verificationLevel: "ultra",
    });
  } catch (e) { threw = e; }
  check("dsr.submit: invalid verificationLevel → dsr/bad-verification-level",
        threw && threw.code === "dsr/bad-verification-level");
}

// ---- process() adversarial / wrong-state ----

async function testProcessAlreadyInProgress() {
  // Drive a ticket into "in_progress" (the concurrent-processor guard state)
  // via the store, then re-process → dsr/already-in-progress.
  var store = b.dsr.memoryTicketStore();
  var dsr = _makeDsr({ ticketStore: store });
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var t = await store.get(ticket.id);
  t.status = "in_progress";
  await store.update(ticket.id, t);
  var threw = null;
  try { await dsr.process(ticket.id); } catch (e) { threw = e; }
  check("dsr.process: in_progress ticket → dsr/already-in-progress",
        threw && threw.code === "dsr/already-in-progress");
}

async function testProcessBadVerificationLevel() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var threw = null;
  try { await dsr.process(ticket.id, { verificationLevel: "not-a-level" }); }
  catch (e) { threw = e; }
  check("dsr.process: invalid verificationLevel → dsr/bad-verification-level",
        threw && threw.code === "dsr/bad-verification-level");
}

async function testProcessErasurePurgeFailure() {
  // The erasure-completion purge is best-effort: a store.delete() failure
  // must NOT unwind the completed erasure. Wrap the memory store so delete
  // throws; the erasure still completes and the prior ticket survives.
  var real = b.dsr.memoryTicketStore();
  var store = {
    insert: real.insert,
    get:    real.get,
    list:   real.list,
    update: real.update,
    delete: async function () { throw new Error("delete backend unreachable"); },
  };
  var dsr = _makeDsr({ ticketStore: store });
  var prior = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var erasure = await dsr.submit({
    type: "erasure", subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  var result = await dsr.process(erasure.id, { verificationLevel: "secondary" });
  check("dsr.process erasure: completes despite purge delete() failure",
        result.status === "completed");
  var priorStill = await store.get(prior.id);
  check("dsr.process erasure: purge delete() failure leaves prior ticket intact",
        priorStill && priorStill.id === prior.id);
}

async function testAuditDisabled() {
  // audit:false disables emission — the _emitAudit early-return path. The
  // workflow must still function end-to-end with the audit sink off.
  var dsr = _makeDsr({ audit: false });
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var result = await dsr.process(ticket.id);
  check("dsr audit:false: submit + process still complete",
        result.status === "completed" && ticket.status === "pending");
}

async function testProcessQueryNonArrayRows() {
  // rows = Array.isArray(rows) ? len : (rows ? 1 : 0). A source returning a
  // truthy non-array counts as 1; a falsy return counts as 0.
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(),
    posture: "gdpr",
    identityResolver: async function () { return { subjectId: "u" }; },
    sources: [
      { name: "objsrc",  query: async function () { return { single: true }; } },
      { name: "nullsrc", query: async function () { return null; } },
    ],
  });
  var ticket = await dsr.submit({ type: "access", subject: { email: "x" } });
  var result = await dsr.process(ticket.id);
  check("dsr.process: non-array truthy query counts as 1 row",
        result.sourceResults[0].rows === 1);
  check("dsr.process: falsy query counts as 0 rows",
        result.sourceResults[1].rows === 0);
}

async function testProcessEraseResultShapes() {
  // Erase-result normalization: { deleted: n } numeric count, {} → 0 with
  // null deletedIds, and eraseExclusions falling back from the source spec.
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(),
    posture: "gdpr",
    identityResolver: async function () { return { subjectId: "u" }; },
    minVerificationByType: { erasure: "minimal" },
    sources: [
      { name: "countsrc", erase: async function () { return { deleted: 3 }; } },
      { name: "emptysrc", erase: async function () { return {}; } },
      { name: "exclsrc",  eraseExclusions: ["legal-hold"],
        erase: async function () { return { deletedIds: [1] }; } },
    ],
  });
  var ticket = await dsr.submit({ type: "erasure", subject: { email: "x" } });
  var result = await dsr.process(ticket.id);
  check("dsr.process erase: numeric { deleted } count honored",
        result.sourceResults[0].deleted === 3);
  check("dsr.process erase: empty erase result → 0 deleted, null deletedIds",
        result.sourceResults[1].deleted === 0 && result.sourceResults[1].deletedIds === null);
  check("dsr.process erase: exclusions fall back to source eraseExclusions",
        Array.isArray(result.sourceResults[2].exclusions) &&
        result.sourceResults[2].exclusions[0] === "legal-hold");
  check("dsr.process erase: totalDeleted sums numeric + id-array counts",
        result.result.totalDeleted === 4);
}

// ---- cancel / reject / get not-found + defaults ----

async function testCancelNotFound() {
  var dsr = _makeDsr();
  var threw = null;
  try { await dsr.cancel("DSR-DOES-NOT-EXIST"); } catch (e) { threw = e; }
  check("dsr.cancel: unknown ticket → dsr/not-found",
        threw && threw.code === "dsr/not-found");
}

async function testCancelWithoutActorReason() {
  // cancel() with no opts → cancelledBy / cancelReason default to null; the
  // subsequent receipt's cancelReason is null too.
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var cancelled = await dsr.cancel(ticket.id);
  check("dsr.cancel: no actor → cancelledBy null", cancelled.cancelledBy === null);
  check("dsr.cancel: no reason → cancelReason null", cancelled.cancelReason === null);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("dsr.buildReceipt: cancelled without reason → summary.cancelReason null",
        receipt.status === "cancelled" && receipt.summary.cancelReason === null);
}

async function testRejectNotFound() {
  var dsr = _makeDsr();
  var threw = null;
  try { await dsr.reject("DSR-DOES-NOT-EXIST", { reason: "no such ticket" }); }
  catch (e) { threw = e; }
  check("dsr.reject: unknown ticket → dsr/not-found",
        threw && threw.code === "dsr/not-found");
}

async function testRejectTerminal() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);   // → completed (terminal)
  var threw = null;
  try { await dsr.reject(ticket.id, { reason: "too late" }); }
  catch (e) { threw = e; }
  check("dsr.reject: terminal-state ticket → dsr/terminal-state",
        threw && threw.code === "dsr/terminal-state");
}

async function testGetViaCoordinator() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var got = await dsr.get(ticket.id);
  check("dsr.get: coordinator returns the stored ticket",
        got && got.id === ticket.id && got.status === "pending");
  var missing = await dsr.get("DSR-NOPE");
  check("dsr.get: unknown id → null", missing === null);
}

async function testListByStatusBadStatus() {
  var dsr = _makeDsr();
  var threw = null;
  try { await dsr.listByStatus("made-up-status"); } catch (e) { threw = e; }
  check("dsr.listByStatus: invalid status → dsr/bad-status",
        threw && threw.code === "dsr/bad-status");
}

// ---- buildReceipt / buildPortabilityBundle adversarial ----

async function testBuildReceiptNotFound() {
  var dsr = _makeDsr();
  var threw = null;
  try { await dsr.buildReceipt("DSR-NOPE"); } catch (e) { threw = e; }
  check("dsr.buildReceipt: unknown ticket → dsr/not-found",
        threw && threw.code === "dsr/not-found");
}

async function testBuildReceiptExpired() {
  var dsr = _makeDsr({ deadlineMs: 50 });
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  var expired = await helpers.waitUntil(async function () {
    var rv = await dsr.expireOverdue();
    return rv.length >= 1 ? rv : false;
  }, { label: "dsr.buildReceipt: expired-ticket sweep" });
  check("dsr.buildReceipt expired: ticket collected", expired.length === 1);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("dsr.buildReceipt: expired status echoed", receipt.status === "expired");
  check("dsr.buildReceipt: expired summary carries deadlineAt",
        receipt.summary.deadlineAt === ticket.deadlineAt);
}

function testPortabilityBadTicket() {
  var dsr = _makeDsr();
  var threwNull = null;
  try { dsr.buildPortabilityBundle(null); } catch (e) { threwNull = e; }
  check("dsr.buildPortabilityBundle: null ticket → dsr/bad-ticket",
        threwNull && threwNull.code === "dsr/bad-ticket");
  var threwNoType = null;
  try { dsr.buildPortabilityBundle({ id: "x" }); } catch (e) { threwNoType = e; }
  check("dsr.buildPortabilityBundle: ticket without type → dsr/bad-ticket",
        threwNoType && threwNoType.code === "dsr/bad-ticket");
}

// ---- memoryTicketStore update-not-found + delete ----

async function testMemoryStoreUpdateNotFoundAndDelete() {
  var store = b.dsr.memoryTicketStore();
  await store.insert({ id: "M1", subject: { email: "a" }, status: "pending" });
  var threw = null;
  try { await store.update("M-MISSING", { id: "M-MISSING", subject: {}, status: "pending" }); }
  catch (e) { threw = e; }
  check("memoryStore.update: missing id → dsr/ticket-not-found",
        threw && threw.code === "dsr/ticket-not-found");

  var removed = await store.delete("M1");
  check("memoryStore.delete: existing id returns true", removed === true);
  check("memoryStore.delete: row is gone", (await store.get("M1")) === null);
  var removedMissing = await store.delete("M1");
  check("memoryStore.delete: absent id returns false", removedMissing === false);
}

// ---- dbTicketStore adversarial + purge + status list + update-not-found ----

async function testDbStoreBadTable() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var threw = null;
    try { b.dsr.dbTicketStore({ db: b.db, table: "evil; DROP TABLE users" }); }
    catch (e) { threw = e; }
    check("dbTicketStore: non-identifier table → dsr/bad-table",
          threw && threw.code === "dsr/bad-table");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreListByStatus() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var h = _dbDsr();
    var t1 = await h.dsr.submit({ type: "access", subject: { email: "alice@example.com" } });
    await h.dsr.process(t1.id);
    await h.dsr.submit({ type: "access", subject: { email: "alice@example.com" } });
    var pending = await h.store.list({ status: "pending" });
    check("dbStore.list({status:pending}): 1 pending ticket",
          pending.length === 1 && pending[0].status === "pending");
    var completed = await h.store.list({ status: "completed" });
    check("dbStore.list({status:completed}): 1 completed ticket",
          completed.length === 1 && completed[0].status === "completed");
    var all = await h.store.list();   // no filter → filter || {}
    check("dbStore.list(): no filter returns every ticket", all.length === 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreUpdateNotFound() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var store = b.dsr.dbTicketStore({ db: b.db });
    var ghost = {
      id: "DSR-GHOST", type: "access", status: "pending",
      subject: { subjectId: "u-x", email: "ghost@example.com", phone: null },
      submittedAt: Date.now(), deadlineAt: Date.now() + C.TIME.minutes(1),
      posture: "gdpr", verificationLevel: "minimal",
    };
    var threw = null;
    try { await store.update("DSR-GHOST", ghost); } catch (e) { threw = e; }
    check("dbStore.update: id absent (0 changes) → dsr/ticket-not-found",
          threw && threw.code === "dsr/ticket-not-found");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStorePurgeExpired() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var store = b.dsr.dbTicketStore({ db: b.db });
    var now = Date.now();
    function _mk(id, status, retentionUntil) {
      return {
        id: id, type: "access", status: status,
        subject: { subjectId: "u-" + id, email: id + "@example.com", phone: null },
        submittedAt: now, deadlineAt: now, retentionUntil: retentionUntil,
        posture: "gdpr", verificationLevel: "minimal",
      };
    }
    // Terminal + retention already lapsed → purged.
    await store.insert(_mk("PAST", "completed", now - C.TIME.days(1)));
    // Terminal but retention still in the future → retained.
    await store.insert(_mk("FUTURE", "cancelled", now + C.TIME.days(30)));
    // Non-terminal (pending) with lapsed retention → not selected at all.
    await store.insert(_mk("PENDING", "pending", now - C.TIME.days(1)));

    var purged = await store.purgeExpired();   // default asOf = now
    check("dbStore.purgeExpired(): removes only the lapsed terminal ticket",
          purged === 1);
    check("dbStore.purgeExpired(): lapsed terminal row gone",
          (await store.get("PAST")) === null);
    check("dbStore.purgeExpired(): future-retention terminal row survives",
          (await store.get("FUTURE")) !== null);
    check("dbStore.purgeExpired(): non-terminal pending row survives",
          (await store.get("PENDING")) !== null);

    // Explicit asOfMs far in the future now lapses the FUTURE ticket too.
    var purged2 = await store.purgeExpired(now + C.TIME.days(60));
    check("dbStore.purgeExpired(asOfMs): explicit cutoff lapses the future ticket",
          purged2 === 1 && (await store.get("FUTURE")) === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDbStoreTicketTooLarge() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var store = b.dsr.dbTicketStore({ db: b.db });
    // A serialized ticket above safeJson.ABSOLUTE_MAX_BYTES (64 MiB) is
    // refused at write, so the store never holds a payload it could not read
    // back through safeJson.parse's hard ceiling (write cap == read cap).
    var oversized = "x".repeat(C.BYTES.mib(64));   // JSON wrapping pushes it over 64 MiB
    var ticket = {
      id: "DSR-TOO-BIG", type: "access", status: "pending",
      subject: { subjectId: "u-1", email: "a@b.com", phone: null },
      submittedAt: Date.now(), deadlineAt: Date.now() + C.TIME.minutes(1),
      posture: "gdpr", verificationLevel: "minimal",
      blob: oversized,
    };
    var threw = null;
    try { await store.insert(ticket); } catch (e) { threw = e; }
    oversized = null; ticket.blob = null;   // release the big string promptly
    check("dbStore.insert: oversized ticket payload → dsr/ticket-too-large",
          threw && threw.code === "dsr/ticket-too-large");

    // A vaulted store AEAD-seals + base64-expands (~4/3) the payload before
    // binding it, so a plaintext between the expansion-safe cap (~48 MiB) and
    // the 64 MiB read ceiling would seal PAST b.sql's 64 MiB per-value cap. It
    // must be refused here with the store's own dsr/ticket-too-large error,
    // not surface as a SqlBuilderError (sql-builder/param-too-large) from the
    // insert's b.sql path.
    var nearMax = "x".repeat(C.BYTES.mib(50));   // > the ~48 MiB vaulted cap, < 64 MiB
    var ticket2 = {
      id: "DSR-SEAL-EXPAND", type: "access", status: "pending",
      subject: { subjectId: "u-2", email: "b@c.com", phone: null },
      submittedAt: Date.now(), deadlineAt: Date.now() + C.TIME.minutes(1),
      posture: "gdpr", verificationLevel: "minimal",
      blob: nearMax,
    };
    var threw2 = null;
    try { await store.insert(ticket2); } catch (e) { threw2 = e; }
    nearMax = null; ticket2.blob = null;   // release promptly
    check("dbStore.insert: vaulted payload that seals past 64 MiB → dsr/ticket-too-large (not SqlBuilderError)",
          threw2 && threw2.code === "dsr/ticket-too-large");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- reseal: real AAD-cell rotation + non-array store guard ----

async function testResealRotatesAadCell() {
  var cryptoField = require("../../lib/crypto-field");
  var vaultAad = require("../../lib/vault-aad");
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Constructing the store registers the dsr_tickets sealed-column schema
    // with cryptoField (vault is initialized), so sealRow can AAD-seal a cell.
    b.dsr.dbTicketStore({ db: b.db });
    var sealed = cryptoField.sealRow("dsr_tickets", {
      id: "RESEAL-1", subject_email: "rotate@example.com",
    });
    check("reseal fixture: subject_email is AAD-sealed",
          vaultAad.isAadSealed(sealed.subject_email));
    var origCell = sealed.subject_email;

    var keys = b.vault.getKeysJson();
    var puts = [];
    var store = {
      listAll:     function () { return [sealed]; },
      putResealed: function (row) { puts.push(row); },
    };
    var rv = await b.dsr.reseal({ store: store, oldRootJson: keys, newRootJson: keys });
    check("reseal: one AAD cell rotated + persisted",
          rv.table === "dsr_tickets" && rv.resealed === 1 && puts.length === 1);
    check("reseal: rotated cell re-encrypted (ciphertext changed)",
          sealed.subject_email !== origCell && vaultAad.isAadSealed(sealed.subject_email));
    var unsealed = cryptoField.unsealRow("dsr_tickets", {
      id: "RESEAL-1", subject_email: sealed.subject_email,
    });
    check("reseal: rotated cell still unseals to the original plaintext",
          unsealed.subject_email === "rotate@example.com");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testResealListAllNonArray() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var keys = b.vault.getKeysJson();
    var threw = null;
    try {
      await b.dsr.reseal({
        oldRootJson: keys, newRootJson: keys,
        store: { listAll: function () { return "not-an-array"; }, putResealed: function () {} },
      });
    } catch (e) { threw = e; }
    check("reseal: store.listAll() returning a non-array → dsr/bad-reseal-store",
          threw && threw.code === "dsr/bad-reseal-store");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- state-law DSR registry ----

function testStateRules() {
  var vcdpa = b.dsr.stateRules("vcdpa");
  check("stateRules(vcdpa): responseDays 45", vcdpa && vcdpa.responseDays === 45);
  check("stateRules(vcdpa): cureDays 30", vcdpa.cureDays === 30);
  check("stateRules(vcdpa): profilingOptOut true", vcdpa.profilingOptOut === true);

  var byAbbr = b.dsr.stateRules("va");   // 2-letter, case-insensitive
  check("stateRules(VA abbrev): resolves to VA rule",
        byAbbr && byAbbr.state === "VA" && byAbbr.posture === "vcdpa");

  check("stateRules(unknown): null", b.dsr.stateRules("zz") === null);
  check("stateRules(non-string): null", b.dsr.stateRules(123) === null);
  check("stateRules(empty string): null", b.dsr.stateRules("") === null);
}

function testListStateRules() {
  var all = b.dsr.listStateRules();
  check("listStateRules: returns a non-empty array",
        Array.isArray(all) && all.length > 0);
  check("listStateRules: each entry carries posture + state + responseDays",
        all.every(function (r) {
          return typeof r.posture === "string" &&
                 typeof r.state === "string" &&
                 typeof r.responseDays === "number";
        }));
}

// ---- additional default-branch / guard coverage ----

function testCreateMoreValidation() {
  var t1 = null;
  try {
    b.dsr.create({
      ticketStore: null,   // !store side of _validateTicketStore
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [{ name: "x", query: async function () { return []; } }],
    });
  } catch (e) { t1 = e; }
  check("dsr.create: null ticketStore → dsr/bad-store", t1 && t1.code === "dsr/bad-store");

  var t2 = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [null],   // !s side of _validateSource
    });
  } catch (e) { t2 = e; }
  check("dsr.create: null source → dsr/bad-source", t2 && t2.code === "dsr/bad-source");

  var t3 = null;
  try {
    b.dsr.create({
      ticketStore: b.dsr.memoryTicketStore(),
      identityResolver: async function () { return { subjectId: "u" }; },
      sources: [{ name: "", query: async function () { return []; } }],   // empty name
    });
  } catch (e) { t3 = e; }
  check("dsr.create: empty source name → dsr/bad-source", t3 && t3.code === "dsr/bad-source");
}

async function testSubmitResolverThrowsEmptyMessage() {
  // Resolver throws an Error with an empty message → (e && e.message) is
  // falsy, so the audit metadata + wrapped-message path takes the String(e)
  // fallback rather than the message branch.
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(), posture: "gdpr",
    identityResolver: async function () { throw new Error(""); },
    sources: [{ name: "x", query: async function () { return []; } }],
  });
  var threw = null;
  try { await dsr.submit({ type: "access", subject: { email: "a@b.com" } }); }
  catch (e) { threw = e; }
  check("dsr.submit: empty-message resolver throw → dsr/identity-resolver-failed",
        threw && threw.code === "dsr/identity-resolver-failed");
}

async function testProcessSourceThrowsEmptyMessage() {
  var dsr = b.dsr.create({
    ticketStore: b.dsr.memoryTicketStore(), posture: "gdpr",
    identityResolver: async function () { return { subjectId: "u" }; },
    sources: [{ name: "boom", query: async function () { throw new Error(""); } }],
  });
  var ticket = await dsr.submit({ type: "access", subject: { email: "x" } });
  var result = await dsr.process(ticket.id);
  check("dsr.process: empty-message source throw recorded via String(e) fallback",
        result.status === "partially_completed" &&
        result.sourceResults[0].error === "Error");
}

async function testListBySubjectBadInput() {
  var dsr = _makeDsr();
  var r1 = await dsr.listBySubject(null);
  var r2 = await dsr.listBySubject("not-an-object");
  check("dsr.listBySubject: non-object subject → []",
        Array.isArray(r1) && r1.length === 0 && Array.isArray(r2) && r2.length === 0);
}

async function testExpireOverdueNotPast() {
  var dsr = _makeDsr({ deadlineMs: C.TIME.days(30) });
  await dsr.submit({ type: "access", subject: { email: "alice@example.com" } });
  var expired = await dsr.expireOverdue();
  check("dsr.expireOverdue: pending ticket within deadline not swept",
        expired.length === 0);
}

async function testReceiptSignerPartialResult() {
  // Signer returns an object with none of issuer/algorithm/signature → each
  // falls back to null.
  var dsr = _makeDsr({ receiptSigner: async function () { return {}; } });
  var ticket = await dsr.submit({
    type: "access", subject: { email: "alice@example.com" },
  });
  await dsr.process(ticket.id);
  var receipt = await dsr.buildReceipt(ticket.id);
  check("dsr.buildReceipt: empty signer result → issuer/algorithm/signature null",
        receipt.issuer === null && receipt.algorithm === null && receipt.signature === null);
}

async function testPortabilityCancelled() {
  var dsr = _makeDsr();
  var ticket = await dsr.submit({
    type: "portability", subject: { email: "alice@example.com" },
    verificationLevel: "secondary",
  });
  await dsr.cancel(ticket.id, { actor: "admin", reason: "withdrew" });
  var cancelled = await dsr.get(ticket.id);
  var threw = null;
  try { dsr.buildPortabilityBundle(cancelled); } catch (e) { threw = e; }
  check("dsr.buildPortabilityBundle: cancelled portability ticket → dsr/not-completed",
        threw && threw.code === "dsr/not-completed");
}

async function testMemoryStoreListBySubjectId() {
  var store = b.dsr.memoryTicketStore();
  await store.insert({ id: "S1", subject: { subjectId: "u-1", email: "a@b.com" }, status: "pending" });
  await store.insert({ id: "S2", subject: { subjectId: "u-2", email: "c@d.com" }, status: "pending" });
  var byId = await store.list({ subject: { subjectId: "u-1" } });
  check("memoryStore.list: filter by subjectId matches one row",
        byId.length === 1 && byId[0].id === "S1");
}

// A subject filter that carries none of the store's indexable keys (email /
// subjectId) — a phone-only subject, an empty subject, or one keyed only on
// an alias — must match NOTHING, never every ticket. Fail-open here makes
// listBySubject leak every subject's tickets (GDPR Art. 15 cross-subject
// disclosure) and lets the erasure-completion purge delete them
// (cross-subject destruction). Both ticket stores must fail closed.
async function testMemoryStoreSubjectFilterFailClosed() {
  var store = b.dsr.memoryTicketStore();
  await store.insert({ id: "P1", subject: { phone: "+15550000001" }, status: "pending" });
  await store.insert({ id: "P2", subject: { phone: "+15550000002" }, status: "pending" });

  var phoneOnly = await store.list({ subject: { phone: "+15550000001" } });
  check("memoryStore.list: phone-only subject filter matches nothing (fail-closed)",
        phoneOnly.length === 0);

  var emptySubj = await store.list({ subject: {} });
  check("memoryStore.list: empty subject filter matches nothing (fail-closed)",
        emptySubj.length === 0);

  // Regression guard: an indexable key still matches, and the AND across
  // both keys still holds.
  await store.insert({ id: "P3", subject: { subjectId: "u-9", email: "e9@x.com" }, status: "pending" });
  var byId = await store.list({ subject: { subjectId: "u-9" } });
  check("memoryStore.list: indexable subjectId still matches after fail-closed guard",
        byId.length === 1 && byId[0].id === "P3");
}

async function testMemoryStoreErasurePurgeScopedToSubject() {
  // Two DIFFERENT phone-only subjects. Subject A's erasure-completion purge
  // lists the store by A's subject and deletes the "other" tickets it finds.
  // Because a phone-only subject is unindexable, the fail-open list returned
  // EVERY ticket — so the purge wiped Subject B's data. B's ticket must
  // survive A's erasure.
  var store = b.dsr.memoryTicketStore();
  var dsr = b.dsr.create({
    ticketStore: store,
    posture: "ccpa",
    identityResolver: async function (input) { return { phone: input.phone }; },
    sources: [{
      name:  "users",
      query: async function () { return []; },
      erase: async function () { return { deletedIds: [] }; },
    }],
  });
  var tB = await dsr.submit({ type: "access", subject: { phone: "+15550000002" } });
  var tAerase = await dsr.submit({
    type: "erasure", subject: { phone: "+15550000001" }, verificationLevel: "secondary",
  });
  await dsr.process(tAerase.id, { actor: "compliance@", verificationLevel: "secondary" });
  var bStill = await store.get(tB.id);
  check("dsr erasure purge: subject B's ticket survives subject A's erasure (no cross-subject delete)",
        bStill !== null);
}

async function testDbStoreSubjectFilterFailClosed() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var store = b.dsr.dbTicketStore({ db: b.db });
    var now = Date.now();
    await store.insert({ id: "DB-P1", type: "access", status: "pending",
      subject: { phone: "+15550000001" }, submittedAt: now, deadlineAt: now + 1000,
      retentionUntil: now + 1000 });
    await store.insert({ id: "DB-P2", type: "access", status: "pending",
      subject: { phone: "+15550000002" }, submittedAt: now, deadlineAt: now + 1000,
      retentionUntil: now + 1000 });

    var phoneOnly = await store.list({ subject: { phone: "+15550000001" } });
    check("dbStore.list: phone-only subject filter matches nothing (fail-closed)",
          phoneOnly.length === 0);

    var emptySubj = await store.list({ subject: {} });
    check("dbStore.list: empty subject filter matches nothing (fail-closed)",
          emptySubj.length === 0);

    // Regression guard: an indexable subject still round-trips.
    await store.insert({ id: "DB-U1", type: "access", status: "pending",
      subject: { subjectId: "u-9", email: "e9@x.com" }, submittedAt: now,
      deadlineAt: now + 1000, retentionUntil: now + 1000 });
    var byEmail = await store.list({ subject: { email: "e9@x.com" } });
    check("dbStore.list: indexable email still matches after fail-closed guard",
          byEmail.length === 1 && byEmail[0].id === "DB-U1");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testDbStoreNoArgs() {
  // dbTicketStore() with no opts → opts || {} → requireMethods refuses the
  // absent db handle.
  var threw = null;
  try { b.dsr.dbTicketStore(); } catch (e) { threw = e; }
  check("dbTicketStore: no opts → dsr/bad-db", threw && threw.code === "dsr/bad-db");
}

async function testResealNoArgsAndNonSealedRows() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var t1 = null;
    try { await b.dsr.reseal(); } catch (e) { t1 = e; }
    check("dsr.reseal: no args → dsr/bad-root", t1 && t1.code === "dsr/bad-root");

    var keys = b.vault.getKeysJson();
    var puts = [];
    var rv = await b.dsr.reseal({
      oldRootJson: keys, newRootJson: keys,
      store: {
        listAll:     function () { return [null, "str", { plain: 1 }]; },
        putResealed: function (r) { puts.push(r); },
      },
    });
    check("dsr.reseal: non-object / plaintext rows rotate nothing",
          rv.resealed === 0 && puts.length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Run all ----

async function run() {
  await testSubmitAccess();
  await testSubmitErasure();
  await testSubmitInvalidType();
  await testSubmitNoSubject();
  await testSubmitIdentityResolverFails();
  await testSubmitCustomDeadline();

  await testProcessAccess();
  await testProcessErasure();
  await testProcessRestriction();
  await testProcessObject();
  await testProcessAutomatedDecision();
  await testProcessSourceFailure();
  await testProcessNotFound();
  await testProcessTerminalState();

  await testCancel();
  await testCancelTerminal();
  await testReject();
  await testRejectRequiresReason();

  await testListBySubject();
  await testListByStatus();

  await testExpireOverdue();
  await testExpireOverdueSkipsCompleted();

  await testPortabilityBundle();
  await testPortabilityWrongType();
  await testPortabilityNotCompleted();

  testPostureDeadlines();
  await testPosturePicksDifferentDeadlines();
  await testPostureUnknownFallsBackToDefault();

  testCreateValidation();
  await testMemoryStore();

  await testVerificationDefault();
  await testVerificationErasureRequiresSecondary();
  await testVerificationStrong();
  await testVerificationContext();
  await testVerificationLevelOnSubmit();

  await testBuildReceipt();
  await testReceiptForCancelled();
  await testReceiptForRejected();
  await testReceiptNotTerminal();
  await testReceiptWithSigner();
  await testReceiptSignerError();

  // create() adversarial validation
  await testCreateBadSource();
  testCreateBadPosture();
  testCreateBadDefaultVerificationLevel();
  testCreateBadMinVerificationByType();

  // submit() adversarial
  await testSubmitBadInput();
  await testSubmitIdentityResolverThrows();
  await testSubmitBadVerificationLevel();

  // process() adversarial / wrong-state
  await testProcessAlreadyInProgress();
  await testProcessBadVerificationLevel();
  await testProcessErasurePurgeFailure();
  await testAuditDisabled();
  await testProcessQueryNonArrayRows();
  await testProcessEraseResultShapes();

  // cancel / reject / get not-found + defaults
  await testCancelNotFound();
  await testCancelWithoutActorReason();
  await testRejectNotFound();
  await testRejectTerminal();
  await testGetViaCoordinator();
  await testListByStatusBadStatus();

  // buildReceipt / buildPortabilityBundle adversarial
  await testBuildReceiptNotFound();
  await testBuildReceiptExpired();
  testPortabilityBadTicket();

  // memoryTicketStore update-not-found + delete
  await testMemoryStoreUpdateNotFoundAndDelete();

  // dbTicketStore at-rest sealing + erasure purge + upgrade path
  await testDbStoreSealsAtRest();
  await testDbStoreLargePayloadRoundTrips();
  await testDbStoreErasurePurgesPriorTickets();
  await testDbStoreUpgradePath();
  await testDbStoreFindsLegacyKeyedMacRows();
  // dbTicketStore adversarial + purge + status list + update-not-found
  await testDbStoreBadTable();
  await testDbStoreListByStatus();
  await testDbStoreUpdateNotFound();
  await testDbStorePurgeExpired();
  await testDbStoreTicketTooLarge();
  // AAD_ROTATION descriptor + reseal
  testAadRotationDescriptor();
  await testResealValidationAndStore();
  await testResealRotatesAadCell();
  await testResealListAllNonArray();

  // additional default-branch / guard coverage
  testCreateMoreValidation();
  await testSubmitResolverThrowsEmptyMessage();
  await testProcessSourceThrowsEmptyMessage();
  await testListBySubjectBadInput();
  await testExpireOverdueNotPast();
  await testReceiptSignerPartialResult();
  await testPortabilityCancelled();
  await testMemoryStoreListBySubjectId();
  await testMemoryStoreSubjectFilterFailClosed();
  await testMemoryStoreErasurePurgeScopedToSubject();
  await testDbStoreSubjectFilterFailClosed();
  testDbStoreNoArgs();
  await testResealNoArgsAndNonSealedRows();

  // state-law DSR registry
  testStateRules();
  testListStateRules();
}

module.exports = { run: run };

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}
