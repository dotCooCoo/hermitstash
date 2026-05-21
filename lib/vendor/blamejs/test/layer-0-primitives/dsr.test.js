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

// ---- Run all ----

(async function run() {
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
})().catch(function (e) { console.error(e); process.exit(1); });
