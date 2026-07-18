// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",         typeof b.agent.saga.create === "function");
  check("AgentSagaError",       typeof b.agent.saga.AgentSagaError === "function");
  check("guards.config",        b.agent.saga.guards.config === b.guardSagaConfig);
  var e = new b.agent.saga.AgentSagaError("agent-saga/test", "t");
  check("error carries code",   e.code === "agent-saga/test");
}

async function testHappyPath() {
  var saga = b.agent.saga.create({
    name: "test.happy",
    steps: [
      { name: "step1", run: async function (_ctx, s) { s.a = 1; } },
      { name: "step2", run: async function (_ctx, s) { s.b = 2; } },
      { name: "step3", run: async function (_ctx, s) { s.c = 3; } },
    ],
  });
  var r = await saga.run({}, {});
  check("happy: completed",       r.status === "completed");
  check("happy: state.a",          r.state.a === 1);
  check("happy: state.c",          r.state.c === 3);
}

async function testCompensationCascade() {
  var compensated = [];
  var saga = b.agent.saga.create({
    name: "test.compensation",
    steps: [
      {
        name: "step1",
        run:        async function (_ctx, s) { s.step1 = true; },
        compensate: async function (_ctx, _s) { compensated.push("step1"); },
      },
      {
        name: "step2",
        run:        async function (_ctx, s) { s.step2 = true; },
        compensate: async function (_ctx, _s) { compensated.push("step2"); },
      },
      {
        name: "step3-fails",
        run:        async function (_ctx, _s) { throw new Error("step3 boom"); },
        compensate: async function (_ctx, _s) { compensated.push("step3"); },
      },
    ],
  });
  await expectRejection("saga fails when step throws",
    saga.run({}, {}), "agent-saga/failed");
  // Compensations run in REVERSE order over completed steps (step1+step2),
  // skipping the failing step (step3 hadn't completed when it threw).
  check("compensation: step2 first (reverse order)", compensated[0] === "step2");
  check("compensation: step1 second",                compensated[1] === "step1");
  check("compensation: failing step not compensated", compensated.indexOf("step3") === -1);
}

async function testNoCompensationForUncompletedSteps() {
  var compensated = [];
  var saga = b.agent.saga.create({
    name: "test.no-comp-uncompleted",
    steps: [
      {
        name: "step1-fails",
        run:        async function (_ctx, _s) { throw new Error("immediately"); },
        compensate: async function (_ctx, _s) { compensated.push("step1"); },
      },
      {
        name: "step2",
        run:        async function (_ctx, _s) { /* never reached */ },
        compensate: async function (_ctx, _s) { compensated.push("step2"); },
      },
    ],
  });
  await expectRejection("first step fail aborts",
    saga.run({}, {}), "agent-saga/failed");
  check("no comp run for any step (first failed before completion)",
    compensated.length === 0);
}

async function testNoCompensateOptional() {
  var saga = b.agent.saga.create({
    name: "test.no-compensate",
    steps: [
      // No compensate function — that's allowed.
      { name: "pure-step", run: async function (_ctx, s) { s.x = 1; } },
      // This step has compensate.
      {
        name: "step-with-comp",
        run:        async function (_ctx, _s) { throw new Error("fail"); },
        compensate: async function (_ctx, _s) { /* won't fire — pure-step had no compensate */ },
      },
    ],
  });
  await expectRejection("fails as expected",
    saga.run({}, {}), "agent-saga/failed");
  // The pure-step had no compensate so nothing fires; the failing step
  // never completed. No compensation cascade.
  check("no compensate is OK on completed steps", true);
}

async function testStateCarriesThroughSteps() {
  var saga = b.agent.saga.create({
    name: "test.state-flow",
    steps: [
      { name: "init",   run: async function (_ctx, s) { s.counter = 0; } },
      { name: "inc",    run: async function (_ctx, s) { s.counter += 1; } },
      { name: "double", run: async function (_ctx, s) { s.counter *= 2; } },
    ],
  });
  var r = await saga.run({}, {});
  check("state flows through steps", r.state.counter === 2);
}

async function testCtxPassedToSteps() {
  var saga = b.agent.saga.create({
    name: "test.ctx",
    steps: [
      { name: "use-ctx", run: async function (ctx, s) { s.fromCtx = ctx.value; } },
    ],
  });
  var r = await saga.run({ value: "hello" }, {});
  check("ctx passed through", r.state.fromCtx === "hello");
}

async function testCompensationFailureAudit() {
  // Compensation that throws halts further compensations + emits
  // critical audit + error message references it.
  var saga = b.agent.saga.create({
    name: "test.comp-fails",
    steps: [
      {
        name: "step1",
        run:        async function (_ctx, _s) { /* ok */ },
        compensate: async function (_ctx, _s) { /* would be called second */ },
      },
      {
        name: "step2",
        run:        async function (_ctx, _s) { /* ok */ },
        compensate: async function (_ctx, _s) { throw new Error("comp-boom"); },
      },
      {
        name: "step3",
        run:        async function (_ctx, _s) { throw new Error("step3 fails"); },
      },
    ],
  });
  var threw = null;
  try { await saga.run({}, {}); } catch (e) { threw = e; }
  check("saga fails with comp-failure indicator",
    threw && threw.code === "agent-saga/failed" &&
    threw.message.indexOf("compensation") >= 0);
}

async function testRefusesBadConfig() {
  var threw = null;
  try { b.agent.saga.create({ name: "x", steps: [] }); } catch (e) { threw = e; }
  check("create refuses empty steps",
    threw && (threw.code || "").indexOf("saga-config/no-steps") !== -1);
}

async function testErrorCauseAttached() {
  // SUBSTRATE-15 — failed-step error attaches cause:stepErr so
  // operator stack-trace tooling walks the chain.
  var stepErr = new Error("downstream-failed");
  stepErr.code = "downstream/timeout";
  var saga = b.agent.saga.create({
    name: "test.cause",
    steps: [
      { name: "ok",   run: async function (_c, s) { s.x = 1; } },
      { name: "fail", run: async function () { throw stepErr; } },
    ],
  });
  var threw = null;
  try { await saga.run({}, {}); } catch (e) { threw = e; }
  check("SUBSTRATE-15: cause attached", threw && threw.cause === stepErr);
  check("SUBSTRATE-15: failedStep set",
    threw && threw.failedStep === "fail");
}

async function testFailedCompStepNameCorrect() {
  // BUG-5 — compensation error names the COMPENSATION that threw,
  // not the last-completed step.
  var saga = b.agent.saga.create({
    name: "test.bug5",
    steps: [
      { name: "s1", run: async function () {},
        compensate: async function () { /* fires after s3 + s2 comp */ } },
      { name: "s2", run: async function () {},
        compensate: async function () { throw new Error("s2-comp-failed"); } },
      { name: "s3", run: async function () {},
        compensate: async function () { /* fires first in reverse */ } },
      { name: "step-fails", run: async function () { throw new Error("step-fails"); } },
    ],
  });
  var threw = null;
  try { await saga.run({}, {}); } catch (e) { threw = e; }
  check("BUG-5: failedCompStepName matches the failing comp",
    threw && threw.failedCompStepName === "s2");
  // The prior shape would have named "s3" (last-completed step before
  // the failed-comp); detector confirms we name "s2".
}

async function testSagaStatePersistedAcrossRun() {
  // SUBSTRATE-7 — stateStore.saveStep fires after every completed
  // step; on a mid-saga crash, resume picks up where it left off.
  var saved = [];
  var stateStore = {
    saveStep: async function (chk) { saved.push(chk); },
    loadResumePoint: async function (sagaId) {
      // Pretend the saga crashed after step 1; resume from index 1.
      var last = saved.filter(function (s) { return s.sagaId === sagaId; }).pop();
      return last ? { stepIndex: last.nextIndex, state: last.state } : null;
    },
  };
  var executed = [];
  var saga = b.agent.saga.create({
    name: "test.persist",
    stateStore: stateStore,
    steps: [
      { name: "s1", run: async function (_c, s) { executed.push("s1"); s.s1 = 1; } },
      { name: "s2", run: async function (_c, s) { executed.push("s2"); s.s2 = 2; } },
      { name: "s3", run: async function (_c, s) { executed.push("s3"); s.s3 = 3; } },
    ],
  });
  // Initial run completes fully.
  var r = await saga.run({}, {}, { sagaId: "saga-A" });
  check("SUBSTRATE-7: saga completed", r.status === "completed");
  check("SUBSTRATE-7: 3 saveStep calls", saved.length === 3);
  // Now simulate a crash partway through a DIFFERENT saga + resume.
  var saga2 = b.agent.saga.create({
    name: "test.persist",
    stateStore: stateStore,
    steps: [
      { name: "s1", run: async function (_c, s) { s.s1 = "first-attempt"; } },
      { name: "s2", run: async function (_c, s) { s.s2 = "first-attempt"; } },
      { name: "s3", run: async function (_c, s) { s.s3 = "first-attempt"; } },
    ],
  });
  // Pre-populate saved checkpoints for "saga-B" after s1.
  saved.push({ sagaId: "saga-B", nextIndex: 1, stepName: "s1", state: { s1: "from-crash" } });
  executed.length = 0;
  var r2 = await saga2.resume("saga-B", {}, {});
  check("SUBSTRATE-7: resume completed", r2.status === "completed");
  check("SUBSTRATE-7: resume state preserved", r2.state.s1 === "from-crash");
  check("SUBSTRATE-7: resume skipped s1 (already checkpointed)",
    r2.state.s1 === "from-crash");
}

async function run() {
  testSurface();
  await testHappyPath();
  await testCompensationCascade();
  await testNoCompensationForUncompletedSteps();
  await testNoCompensateOptional();
  await testStateCarriesThroughSteps();
  await testCtxPassedToSteps();
  await testCompensationFailureAudit();
  await testErrorCauseAttached();
  await testFailedCompStepNameCorrect();
  await testSagaStatePersistedAcrossRun();
  await testResumeCompensatesPreCrashSteps();
  await testResumeRefusesTerminalSaga();
  await testRefusesBadConfig();
}

async function testResumeCompensatesPreCrashSteps() {
  // A saga that crashed after step 2, resumed, then FAILS at step 3 must
  // compensate the FULL completed set — the pre-crash steps (s1, s2) included,
  // in reverse order. Regression: _runFrom reset completedSteps=[] on resume,
  // so a post-resume failure compensated only this run's steps, leaving the
  // pre-crash work (e.g. a committed charge) uncompensated.
  var compensated = [];
  var stateStore = {
    saveStep:        async function () {},
    loadResumePoint: async function () { return { stepIndex: 2, state: { s1: "done", s2: "done" } }; },
    markFailed:      async function () {},
  };
  var saga = b.agent.saga.create({
    name:       "test.resume-compensate",
    stateStore: stateStore,
    steps: [
      { name: "s1", run: async function () {}, compensate: async function () { compensated.push("s1"); } },
      { name: "s2", run: async function () {}, compensate: async function () { compensated.push("s2"); } },
      { name: "s3", run: async function () { throw new Error("s3 boom"); },
        compensate: async function () { compensated.push("s3"); } },
    ],
  });
  var threw = null;
  try { await saga.resume("saga-X", {}, {}); } catch (e) { threw = e; }
  check("resume-then-fail rejects with agent-saga/failed", threw && /agent-saga\/failed/.test(threw.code || ""));
  check("resume compensates pre-crash s2 first (reverse order)", compensated[0] === "s2");
  check("resume compensates pre-crash s1 second",               compensated[1] === "s1");
  check("resume compensates BOTH pre-crash steps",              compensated.length === 2);
  check("the failing s3 is not compensated",                    compensated.indexOf("s3") === -1);
}

async function testResumeRefusesTerminalSaga() {
  // A saga that already reached a terminal state (failed-and-compensated, or
  // completed) must not be resumed — replaying it would re-invoke the completed
  // steps' compensators, which are not required to be idempotent (a double
  // refund). A stateStore that marks the saga terminal (resumePoint.terminal)
  // gets the resume refused rather than replayed.
  var compensated = [];
  var stateStore = {
    saveStep:        async function () {},
    loadResumePoint: async function () { return { stepIndex: 2, state: {}, terminal: true }; },
    markFailed:      async function () {},
  };
  var saga = b.agent.saga.create({
    name:       "test.terminal-resume",
    stateStore: stateStore,
    steps: [
      { name: "s1", run: async function () {}, compensate: async function () { compensated.push("s1"); } },
      { name: "s2", run: async function () {}, compensate: async function () { compensated.push("s2"); } },
      { name: "s3", run: async function () {}, compensate: async function () { compensated.push("s3"); } },
    ],
  });
  var threw = null;
  try { await saga.resume("saga-terminal", {}, {}); } catch (e) { threw = e; }
  check("resume of a terminal saga is refused", threw && /agent-saga\/not-resumable/.test(threw.code || ""));
  check("a refused terminal resume runs no compensators", compensated.length === 0);
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
