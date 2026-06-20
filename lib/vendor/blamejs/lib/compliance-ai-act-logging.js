"use strict";
/**
 * EU AI Act Article 12 — automatic logging requirements for high-risk
 * AI systems.
 *
 * Per Regulation (EU) 2024/1689 Art. 12, providers of high-risk AI
 * systems MUST design the system to automatically record events
 * ("logs") over its lifetime, sufficient to:
 *
 *   (a) identify situations that may result in the AI system
 *       presenting a risk under Art. 79(1) (post-market monitoring);
 *   (b) facilitate post-market monitoring per Art. 72;
 *   (c) monitor the operation of the high-risk AI systems referred
 *       to in Art. 26(5) (deployer obligations).
 *
 * For Annex III §1(a) (remote biometric identification systems), the
 * minimum required logged fields are explicitly enumerated in
 * Art. 12(3):
 *
 *   - period of each use (start time, end time)
 *   - reference database against which input data was checked
 *   - input data for which the search led to a match
 *   - identification of natural persons involved in result verification
 *
 * The framework provides a typed event-builder that produces records
 * conforming to these requirements, plus a serialiser that funnels the
 * records into the framework's audit-chain (b.audit) so they ride the
 * tamper-evident PQC-signed chain.
 *
 * Logs are operator-retained per Art. 19 (provider must keep them at
 * least 6 months unless local law requires longer; for high-risk
 * systems used in financial services + employment + law enforcement
 * the retention floor is 1 year). The retention floor cross-walks
 * into b.retention.complianceFloor.
 */

var validateOpts        = require("./validate-opts");
var lazyRequire         = require("./lazy-require");
var C                   = require("./constants");
var { ComplianceError }  = require("./framework-error");

var audit               = lazyRequire(function () { return require("./audit"); });

// Retention floors per Art. 19. Operator's b.retention.complianceFloor
// applies the more-stringent of: AI Act floor, sectoral law, internal
// retention policy.
var RETENTION_FLOORS = Object.freeze({
  default:                    C.TIME.days(180),
  "high-risk-financial":      C.TIME.days(365),
  "high-risk-employment":     C.TIME.days(365),
  "high-risk-law-enforcement": C.TIME.days(365),
});

var MIN_BIOMETRIC_FIELDS = Object.freeze([
  "periodStart", "periodEnd", "referenceDatabase",
  "matchedInputRef", "verifiers",
]);

function buildEvent(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "systemId", "kind", "actor", "timestamp",
    "periodStart", "periodEnd", "referenceDatabase",
    "matchedInputRef", "verifiers",
    "outcome", "metadata", "annexIII",
  ], "compliance.aiAct.logging.buildEvent");

  validateOpts.requireNonEmptyString(opts.systemId,
    "buildEvent: systemId", ComplianceError, "compliance-ai-act/bad-event");
  validateOpts.requireNonEmptyString(opts.kind,
    "buildEvent: kind", ComplianceError, "compliance-ai-act/bad-event");

  var nowMs = (typeof opts.timestamp === "number" && isFinite(opts.timestamp))
    ? opts.timestamp : Date.now();

  var record = {
    aiActArticle:    "Art. 12",
    systemId:        opts.systemId,
    kind:            opts.kind,
    timestamp:       new Date(nowMs).toISOString(),
    actor:           opts.actor || null,
    annexIII:        opts.annexIII || null,
    outcome:         opts.outcome || "ok",
  };

  // Annex III §1(a) biometric-id systems require specific fields.
  if (opts.annexIII === "biometric-id-categorisation") {
    var missing = [];
    for (var i = 0; i < MIN_BIOMETRIC_FIELDS.length; i += 1) {
      var field = MIN_BIOMETRIC_FIELDS[i];
      if (opts[field] == null) missing.push(field);
    }
    if (missing.length > 0) {
      throw new ComplianceError("compliance-ai-act/missing-biometric-fields",
        "buildEvent: biometric-id event missing required fields per Art. 12(3): " +
        missing.join(", "));
    }
    record.periodStart       = _toIsoString(opts.periodStart);
    record.periodEnd         = _toIsoString(opts.periodEnd);
    record.referenceDatabase = opts.referenceDatabase;
    record.matchedInputRef   = opts.matchedInputRef;
    record.verifiers         = Array.isArray(opts.verifiers)
      ? opts.verifiers.slice() : [opts.verifiers];
  }

  if (opts.metadata && typeof opts.metadata === "object") {
    record.metadata = opts.metadata;
  }
  return record;
}

function _toIsoString(value) {
  if (value == null) return null;
  if (typeof value === "string") return value;
  if (typeof value === "number" && isFinite(value)) {
    return new Date(value).toISOString();
  }
  if (value instanceof Date) return value.toISOString();
  return null;
}

function emit(event) {
  if (!event || typeof event !== "object") {
    throw new ComplianceError("compliance-ai-act/bad-event",
      "compliance.aiAct.logging.emit: event must be an object");
  }
  // Funnel into the framework audit chain so the record rides the
  // tamper-evident PQC-signed chain. The operator-facing kind vocabulary
  // (from RFC-style slug identifiers in the AI-Act-Notice header — e.g.
  // "biometric-id-categorisation") carries hyphens; the audit action
  // namespace uses underscores, so the kind is rewritten before emit.
  try {
    var kindCanonical = String(event.kind || "log").replace(/-/g, "_");
    audit().namespaced("compliance.aiact")(kindCanonical, event.outcome || "success", event, { actor: event.actor || null });
  } catch (_e) { /* drop-silent */ }
  return event;
}

function logEvent(opts) {
  var record = buildEvent(opts);
  return emit(record);
}

function retentionFloorMs(opts) {
  opts = opts || {};
  validateOpts(opts, ["domain"], "compliance.aiAct.logging.retentionFloorMs");
  var key = opts.domain || "default";
  if (Object.prototype.hasOwnProperty.call(RETENTION_FLOORS, key)) {
    return RETENTION_FLOORS[key];
  }
  return RETENTION_FLOORS.default;
}

// Build a request-attached logger pre-bound to a system context. The
// returned function accepts a partial event and merges it with the
// preset (systemId, annexIII, deployer).
function loggerFor(systemContext) {
  if (!systemContext || typeof systemContext !== "object") {
    throw new ComplianceError("compliance-ai-act/bad-system-context",
      "loggerFor: systemContext must be an object");
  }
  validateOpts.requireNonEmptyString(systemContext.systemId,
    "loggerFor: systemContext.systemId", ComplianceError, "compliance-ai-act/bad-system-context");
  return function (eventPartial) {
    var merged = Object.assign({}, eventPartial || {});
    merged.systemId = systemContext.systemId;
    if (systemContext.annexIII && !merged.annexIII) {
      merged.annexIII = systemContext.annexIII;
    }
    if (systemContext.deployer && !merged.actor) {
      merged.actor = { deployer: systemContext.deployer };
    }
    return logEvent(merged);
  };
}

module.exports = {
  buildEvent:        buildEvent,
  emit:              emit,
  logEvent:          logEvent,
  retentionFloorMs:  retentionFloorMs,
  loggerFor:         loggerFor,
  RETENTION_FLOORS:  RETENTION_FLOORS,
  MIN_BIOMETRIC_FIELDS: MIN_BIOMETRIC_FIELDS,
};
