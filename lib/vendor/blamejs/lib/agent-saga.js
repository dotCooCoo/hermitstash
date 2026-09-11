// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.agent.saga
 * @nav        Agent
 * @title      Agent Saga
 * @order      75
 *
 * @intro
 *   Multi-step coordination with compensation cascade. When a saga's
 *   step fails mid-way, the framework fires every previously-completed
 *   step's `compensate` in reverse order so the operator-side state
 *   doesn't end up half-written.
 *
 *   Substrate for v0.9.34 submission (DKIM-sign → ARC-sign → outbox-
 *   enqueue → SMTP-deliver → store-move-to-Sent), regulated export,
 *   journal compaction, every future multi-step write.
 *
 *   ```js
 *   var sendSaga = b.agent.saga.create({
 *     name:  "mail.send",
 *     audit: b.audit,
 *     steps: [
 *       {
 *         name: "dkim-sign",
 *         run:        async function (ctx, state) { state.signed = sign(state.message); },
 *         compensate: async function (ctx, state) { /* sign is pure, nothing to undo *\/ },
 *       },
 *       {
 *         name: "store-draft",
 *         run:        async function (ctx, state) { state.draftId = store.append("Drafts", state.signed); },
 *         compensate: async function (ctx, state) { if (state.draftId) store.delete(state.draftId); },
 *       },
 *       {
 *         name: "smtp-deliver",
 *         run:        async function (ctx, state) { await smtp.deliver(state.signed); },
 *         compensate: async function (ctx, state) { /* idempotent: SMTP delivery doesn't have a recall *\/ },
 *       },
 *     ],
 *   });
 *
 *   var result = await sendSaga.run({ store, smtp }, { message: bytes });
 *   ```
 *
 *   ## Compensation order
 *
 *   If step `i` throws, the framework calls `step[i-1].compensate`,
 *   `step[i-2].compensate`, ..., `step[0].compensate` in reverse
 *   order. Each compensate receives the SAME `state` object that
 *   the corresponding `run` mutated — operator inspects what got
 *   written and undoes it.
 *
 *   Compensations that throw emit `agent.saga.compensation_failed`
 *   audit at CRITICAL severity and halt further compensations
 *   (operator alert; manual intervention needed). On step failure the
 *   saga REJECTS (throws) rather than resolving — the thrown error
 *   carries `failedStep`, `cause` (the originating step error),
 *   `compensationCause`, and `failedCompStepName`.
 *
 *   ## No saga-level retry
 *
 *   Saga's value-add is compensation, not retry. If a
 *   step needs retry-with-backoff, the operator wraps `step.run`
 *   with `b.retry` inside the step body. With v0.9.22 idempotency
 *   available, internal retry inside step.run is side-effect-safe.
 *
 * @card
 *   Multi-step coordination with compensation cascade. Reverse-order
 *   compensations on step failure. No saga-level retry — step.run
 *   owns its own retry semantics via b.retry + v0.9.22 idempotency.
 */

var lazyRequire        = require("./lazy-require");
var { defineClass }    = require("./framework-error");
var validateOpts       = require("./validate-opts");
var guardSagaConfig    = require("./guard-saga-config");
var bCrypto            = require("./crypto");
var agentAudit         = require("./agent-audit");

var audit              = lazyRequire(function () { return require("./audit"); });

var AgentSagaError = defineClass("AgentSagaError", { alwaysPermanent: true });

var SAGA_ID_RAND_BYTES = 8;

/**
 * @primitive b.agent.saga.create
 * @signature b.agent.saga.create(config)
 * @since     0.9.27
 * @status    stable
 * @related   b.agent.idempotency.create, b.outbox.enqueue
 *
 * Create a saga definition. Returns an instance whose `run(ctx,
 * initialState, opts)` resolves to `{ status: "completed", sagaId,
 * state }` on success and rejects (throws) on step failure with an
 * error carrying the failed-step + compensation detail (see the intro).
 *
 * @opts
 *   name:    string,                       // required (audit label)
 *   steps:   Array<{ name, run, compensate? }>,   // required, non-empty
 *   audit:   b.audit namespace,            // optional
 *
 * @example
 *   var saga = b.agent.saga.create({
 *     name: "my.workflow",
 *     steps: [{ name: "step1", run: async (ctx, s) => { s.x = 1; } }],
 *   });
 *   var final = await saga.run({}, {});
 */
function create(config) {
  guardSagaConfig.validate(config);
  var auditImpl = config.audit || audit();
  var stateStore = config.stateStore || null;
  if (stateStore !== null) {
    validateOpts.requireMethods(stateStore, ["saveStep", "loadResumePoint"],
      "create: stateStore", AgentSagaError, "agent-saga/bad-state-store");
  }
  return {
    run:                    function (ctx, initialState, opts) { return _run(config, auditImpl, stateStore, ctx, initialState, opts || {}); },
    resume:                 function (sagaId, ctx, opts) { return _resume(config, auditImpl, stateStore, sagaId, ctx, opts || {}); },
    name:                   config.name,
    stepCount:              config.steps.length,
    AgentSagaError:         AgentSagaError,
  };
}

async function _resume(config, auditImpl, stateStore, sagaId, ctx, opts) {
  if (!stateStore) {
    throw new AgentSagaError("agent-saga/no-state-store",
      "resume: stateStore not wired at create(); cannot resume without persisted state");
  }
  if (typeof sagaId !== "string" || sagaId.length === 0) {
    throw new AgentSagaError("agent-saga/bad-saga-id",
      "resume: sagaId required");
  }
  var resumePoint = await stateStore.loadResumePoint(sagaId);
  if (!resumePoint || typeof resumePoint.stepIndex !== "number") {
    throw new AgentSagaError("agent-saga/not-found",
      "resume: no resume point for saga '" + sagaId + "'");
  }
  if (resumePoint.terminal === true) {
    throw new AgentSagaError("agent-saga/not-resumable",
      "resume: saga '" + sagaId + "' is terminal and cannot be resumed — " +
      "replaying a failed/completed saga would re-invoke its compensators");
  }
  return _runFrom(config, auditImpl, stateStore, ctx,
    resumePoint.state || {}, opts, sagaId, resumePoint.stepIndex);
}

async function _run(config, auditImpl, stateStore, ctx, initialState, opts) {
  var sagaId = opts.sagaId || "saga-" + bCrypto.generateToken(SAGA_ID_RAND_BYTES);
  return _runFrom(config, auditImpl, stateStore, ctx,
    Object.assign({}, initialState || {}), opts, sagaId, 0);
}

async function _runFrom(config, auditImpl, stateStore, ctx, state, opts, sagaId, startIndex) {
  var completedSteps = [];
  for (var pre = 0; pre < startIndex; pre += 1) {
    completedSteps.push({ step: config.steps[pre], index: pre });
  }

  if (startIndex === 0) {
    agentAudit.safeAudit(auditImpl, "agent.saga.started", opts.actor, {
      sagaId: sagaId, name: config.name, stepCount: config.steps.length,
    });
    if (!stateStore) {
      agentAudit.safeAudit(auditImpl, "agent.saga.no_state_store", opts.actor, {
        sagaId: sagaId, name: config.name,
        warning: "no stateStore wired; mid-saga crash will lose progress",
      });
    }
  } else {
    agentAudit.safeAudit(auditImpl, "agent.saga.resumed", opts.actor, {
      sagaId: sagaId, name: config.name, fromIndex: startIndex,
    });
  }

  for (var i = startIndex; i < config.steps.length; i += 1) {
    var step = config.steps[i];
    try {
      agentAudit.safeAudit(auditImpl, "agent.saga.step_started", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
      });
      await step.run(ctx, state);
      completedSteps.push({ step: step, index: i });
      if (stateStore) {
        try {
          await stateStore.saveStep({
            sagaId:    sagaId,
            sagaName:  config.name,
            stepIndex: i,
            stepName:  step.name,
            state:     state,
            status:    "completed",
            nextIndex: i + 1,
            checkpointedAt: Date.now(),
          });
        } catch (storeErr) {
          agentAudit.safeAudit(auditImpl, "agent.saga.checkpoint_failed", opts.actor, {
            sagaId: sagaId, name: config.name, stepName: step.name,
            stepIndex: i, reason: (storeErr && storeErr.message) || String(storeErr),
          });
          var ckptErr = new AgentSagaError("agent-saga/checkpoint-failed",
            "saga '" + config.name + "' checkpoint after step '" + step.name +
            "' failed: " + ((storeErr && storeErr.message) || String(storeErr)));
          ckptErr.cause = storeErr;
          throw ckptErr;
        }
      }
      agentAudit.safeAudit(auditImpl, "agent.saga.step_completed", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
      });
    } catch (stepErr) {
      agentAudit.safeAudit(auditImpl, "agent.saga.step_failed", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
        message: (stepErr && stepErr.message) || String(stepErr),
      });
      var compensationError = null;
      var failedCompStepName = null;
      for (var c = completedSteps.length - 1; c >= 0; c -= 1) {
        var compEntry = completedSteps[c];
        var compStep = compEntry.step;
        if (typeof compStep.compensate !== "function") continue;
        try {
          agentAudit.safeAudit(auditImpl, "agent.saga.compensation_started", opts.actor, {
            sagaId: sagaId, name: config.name, stepName: compStep.name,
          });
          await compStep.compensate(ctx, state);
          agentAudit.safeAudit(auditImpl, "agent.saga.compensation_completed", opts.actor, {
            sagaId: sagaId, name: config.name, stepName: compStep.name,
          });
        } catch (compErr) {
          compensationError = compErr;
          failedCompStepName = compStep.name;
          agentAudit.safeAudit(auditImpl, "agent.saga.compensation_failed", opts.actor, {
            sagaId: sagaId, name: config.name, stepName: compStep.name,
            message: (compErr && compErr.message) || String(compErr),
          });
          break;
        }
      }
      agentAudit.safeAudit(auditImpl, "agent.saga.failed", opts.actor, {
        sagaId: sagaId, name: config.name, failedStep: step.name,
        compensationFailed: compensationError !== null,
        compensationFailedAt: failedCompStepName,
      });
      if (stateStore && typeof stateStore.markFailed === "function") {
        try {
          await stateStore.markFailed({
            sagaId: sagaId, sagaName: config.name,
            failedStep: step.name, stepIndex: i,
            compensationFailedAt: failedCompStepName,
            state: state,
          });
        } catch (_e) { /* drop-silent — audit already records */ }
      }
      var detailMsg = "saga '" + config.name + "' failed at step '" + step.name + "': " +
        ((stepErr && stepErr.message) || String(stepErr));
      if (compensationError && failedCompStepName) {
        detailMsg += " — and compensation of step '" + failedCompStepName +
                     "' subsequently failed: " +
                     ((compensationError.message) || String(compensationError));
      }
      var sagaErr = new AgentSagaError("agent-saga/failed", detailMsg);
      sagaErr.cause                = stepErr;
      sagaErr.compensationCause    = compensationError || null;
      sagaErr.failedStep           = step.name;
      sagaErr.failedCompStepName   = failedCompStepName;
      throw sagaErr;
    }
  }
  if (stateStore && typeof stateStore.markCompleted === "function") {
    try {
      await stateStore.markCompleted({
        sagaId: sagaId, sagaName: config.name,
        stepCount: config.steps.length, state: state,
      });
    } catch (_e) { /* drop-silent — audit records */ }
  }
  agentAudit.safeAudit(auditImpl, "agent.saga.completed", opts.actor, {
    sagaId: sagaId, name: config.name, stepCount: config.steps.length,
  });
  return { status: "completed", sagaId: sagaId, state: state };
}

module.exports = {
  create:            create,
  AgentSagaError:    AgentSagaError,
  guards: {
    config: guardSagaConfig,
  },
};
