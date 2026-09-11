// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts        = require("./validate-opts");
var lazyRequire         = require("./lazy-require");
var C                   = require("./constants");
var { ComplianceError }  = require("./framework-error");

var audit               = lazyRequire(function () { return require("./audit"); });

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
