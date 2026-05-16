"use strict";
/**
 * b.agent._audit — internal shared audit-emit helper for the agent
 * substrate (`b.agent.orchestrator` / `b.agent.idempotency` /
 * `b.agent.stream` / `b.agent.eventBus` / future substrate slices).
 *
 * Each agent primitive emits audit events at lifecycle boundaries
 * (registered / opened / closed / replay / denied / drop / etc). The
 * emit logic is identical: actor shape → audit.safeEmit() → swallow
 * any audit-side failures. Extracted here so the 4+ agent substrate
 * modules don't re-implement the same wrapper.
 *
 * Internal — operator-facing surface is each primitive's `.audit`
 * opt; this is the implementation detail.
 */

function safeAudit(auditImpl, action, actor, metadata) {
  try {
    auditImpl.safeEmit({
      action: action,
      actor:  actor ? { id: actor.id, roles: actor.roles || [] } : { id: "<system>" },
      outcome: _outcomeFor(action),
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit failures don't crash the call */ }
}

// "denied" / "drop" / "threw" / "different_args" / "miss" / "not_implemented"
// all imply failure outcome; anything else is success. Per-primitive
// classification can override by passing a metadata.outcome — that's
// merged in by the caller, not here.
function _outcomeFor(action) {
  if (typeof action !== "string") return "success";
  if (action.indexOf("denied")          >= 0) return "failure";
  if (action.indexOf("drop")            >= 0) return "failure";
  if (action.indexOf("threw")           >= 0) return "failure";
  if (action.indexOf("different_args")  >= 0) return "failure";
  if (action.indexOf("miss")            >= 0) return "failure";
  if (action.indexOf("not_implemented") >= 0) return "failure";
  return "success";
}

module.exports = {
  safeAudit: safeAudit,
};
