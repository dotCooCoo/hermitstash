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
 *   (operator alert; manual intervention needed). The saga returns
 *   `{ status: "failed", failedStep, lastCompensationError }`.
 *
 *   ## No saga-level retry
 *
 *   Per the substrate playbook decision (operator-confirmed
 *   2026-05-14): saga's value-add is compensation, not retry. If a
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
var guardSagaConfig    = require("./guard-saga-config");
var bCrypto            = require("./crypto");
var agentAudit         = require("./agent-audit");

var audit              = lazyRequire(function () { return require("./audit"); });

var AgentSagaError = defineClass("AgentSagaError", { alwaysPermanent: true });

var SAGA_ID_RAND_BYTES = 8;                                                                           // allow:raw-byte-literal — saga-id random-suffix byte length

/**
 * @primitive b.agent.saga.create
 * @signature b.agent.saga.create(config)
 * @since     0.9.27
 * @status    stable
 * @related   b.agent.idempotency.create, b.outbox.enqueue
 *
 * Create a saga definition. Returns an instance with `run(ctx,
 * initialState, opts) → Promise<finalState>`.
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
  return {
    run:                    function (ctx, initialState, opts) { return _run(config, auditImpl, ctx, initialState, opts || {}); },
    name:                   config.name,
    stepCount:              config.steps.length,
    AgentSagaError:         AgentSagaError,
  };
}

async function _run(config, auditImpl, ctx, initialState, opts) {
  var sagaId = opts.sagaId || "saga-" + bCrypto.generateToken(SAGA_ID_RAND_BYTES);
  var state  = Object.assign({}, initialState || {});
  var completedSteps = [];

  agentAudit.safeAudit(auditImpl, "agent.saga.started", opts.actor, {
    sagaId: sagaId, name: config.name, stepCount: config.steps.length,
  });

  for (var i = 0; i < config.steps.length; i += 1) {
    var step = config.steps[i];
    try {
      agentAudit.safeAudit(auditImpl, "agent.saga.step_started", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
      });
      await step.run(ctx, state);
      completedSteps.push(step);
      agentAudit.safeAudit(auditImpl, "agent.saga.step_completed", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
      });
    } catch (stepErr) {
      // Step failed — compensate in reverse over already-completed steps.
      agentAudit.safeAudit(auditImpl, "agent.saga.step_failed", opts.actor, {
        sagaId: sagaId, name: config.name, stepName: step.name, stepIndex: i,
        message: (stepErr && stepErr.message) || String(stepErr),
      });
      var compensationError = null;
      for (var c = completedSteps.length - 1; c >= 0; c -= 1) {
        var compStep = completedSteps[c];
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
          // CRITICAL: compensation failed — operator intervention needed.
          // Halt further compensations; record what failed so audit
          // pipeline can alert.
          compensationError = compErr;
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
      });
      throw new AgentSagaError("agent-saga/failed",
        "saga '" + config.name + "' failed at step '" + step.name + "': " +
        ((stepErr && stepErr.message) || String(stepErr)) +
        (compensationError ? " — and compensation '" + completedSteps[completedSteps.length - 1].name +
                              "' subsequently failed: " +
                              (compensationError.message || String(compensationError))
                            : ""));
    }
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
