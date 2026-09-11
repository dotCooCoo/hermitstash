// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.dora
 * @nav    Compliance
 * @title  DORA
 *
 * @intro
 *   DORA Article 17 ICT-related incident-reporting workflow. The
 *   Digital Operational Resilience Act (Regulation (EU) 2022/2554)
 *   Article 17 requires every "financial entity" subject to DORA to
 *   classify, document, and report ICT-related incidents according to
 *   the harmonized RTS template (Commission Delegated Regulation
 *   2024/1772). The framework owns the classification rubric, the
 *   three-stage report shape (initial / intermediate / final), and
 *   the audit-chain integration; operators wire the produced
 *   RTS-template-shaped records into their submission code (channel
 *   + ESA / national-supervisor credentials are operator-specific —
 *   the framework does NOT submit on the operator's behalf).
 *
 *   Adjacent regimes (NIS2 Art. 23, CRA Art. 14, HIPAA breach
 *   notification) share the deadline-tracking shape; reference
 *   constants live on the module so operators don't pin literal hour
 *   counts in their reporters.
 *
 * @card
 *   DORA Article 17 ICT-related incident-reporting workflow.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { DoraError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var MAJOR_INCIDENT_THRESHOLDS = Object.freeze({
  affectedClientsAbsolute:      100000,
  affectedClientsPercentile:    0.10,
  economicImpactEur:            100000,
  geographicMemberStates:       2,
  durationCriticalProcessMs:    C.TIME.hours(8),
});

var SIGNIFICANT_INCIDENT_THRESHOLDS = Object.freeze({
  affectedClientsAbsolute:      10000,
  affectedClientsPercentile:    0.01,
  economicImpactEur:            10000,
  durationCriticalProcessMs:    C.TIME.hours(2),
});

var INITIAL_REPORT_DEADLINE_MS       = C.TIME.hours(4);
var INITIAL_REPORT_OUTER_DEADLINE_MS = C.TIME.hours(24);
var INTERMEDIATE_REPORT_DEADLINE_MS  = C.TIME.hours(72);
var FINAL_REPORT_DEADLINE_MS         = C.TIME.days(30);

var DEADLINES_NIS2 = Object.freeze({
  earlyWarningMs:   C.TIME.hours(24),
  initialReportMs:  C.TIME.hours(72),
  finalReportMs:    C.TIME.days(30),
});
var DEADLINES_CRA = Object.freeze({
  earlyWarningMs:   C.TIME.hours(24),
  initialReportMs:  C.TIME.hours(72),
  finalReportMs:    C.TIME.days(14),
});
var DEADLINES_HIPAA_BREACH = Object.freeze({
  individualNoticeMs:  C.TIME.days(60),
  secretaryNoticeMs:   C.TIME.days(60),
  annualAggregateMs:   null,
});

var VALID_DATA_AFFECTED = ["phi", "financial", "personal", "operational", "none"];
var VALID_SEVERITY      = ["critical", "high", "medium", "low"];
var VALID_REPUTATIONAL  = ["media", "internal", "none"];
var VALID_STAGES        = ["initial", "intermediate", "final"];
var VALID_CLASSIFICATIONS = ["major", "significant", "minor"];

function _classifyImpl(input) {
  var reasons = [];
  var hitsMajor = 0;
  var hitsSignificant = 0;

  if (input.severityIndicator === "critical") {
    hitsMajor += 1;
    reasons.push("severity-critical");
  } else if (input.severityIndicator === "high") {
    hitsSignificant += 1;
    reasons.push("severity-high");
  }

  if (typeof input.affectedClients === "number" && input.affectedClients > 0) {
    var clientBase = (typeof input.clientBase === "number" && input.clientBase > 0) ? input.clientBase : null;
    var clientPct = clientBase ? (input.affectedClients / clientBase) : 0;
    var majorByClients = input.affectedClients >= MAJOR_INCIDENT_THRESHOLDS.affectedClientsAbsolute ||
      (clientBase !== null && clientPct >= MAJOR_INCIDENT_THRESHOLDS.affectedClientsPercentile);
    var significantByClients = input.affectedClients >= SIGNIFICANT_INCIDENT_THRESHOLDS.affectedClientsAbsolute ||
      (clientBase !== null && clientPct >= SIGNIFICANT_INCIDENT_THRESHOLDS.affectedClientsPercentile);
    if (majorByClients) {
      hitsMajor += 1;
      reasons.push("clients-major");
    } else if (significantByClients) {
      hitsSignificant += 1;
      reasons.push("clients-significant");
    }
  }

  if (input.economicImpact && typeof input.economicImpact.eur === "number") {
    if (input.economicImpact.eur >= MAJOR_INCIDENT_THRESHOLDS.economicImpactEur) {
      hitsMajor += 1;
      reasons.push("economic-major");
    } else if (input.economicImpact.eur >= SIGNIFICANT_INCIDENT_THRESHOLDS.economicImpactEur) {
      hitsSignificant += 1;
      reasons.push("economic-significant");
    }
  }

  if (Array.isArray(input.geographicScope) &&
      input.geographicScope.length >= MAJOR_INCIDENT_THRESHOLDS.geographicMemberStates) {
    hitsMajor += 1;
    reasons.push("geographic-cross-border");
  }

  if (typeof input.durationMs === "number" && input.durationMs > 0) {
    if (input.durationMs >= MAJOR_INCIDENT_THRESHOLDS.durationCriticalProcessMs) {
      hitsMajor += 1;
      reasons.push("duration-major");
    } else if (input.durationMs >= SIGNIFICANT_INCIDENT_THRESHOLDS.durationCriticalProcessMs) {
      hitsSignificant += 1;
      reasons.push("duration-significant");
    }
  }

  if (input.reputationalImpact === "media") {
    hitsMajor += 1;
    reasons.push("reputational-media");
  }

  if (input.dataAffected === "phi" || input.dataAffected === "financial") {
    hitsSignificant += 1;
    reasons.push("data-sensitive-" + input.dataAffected);
  }

  var classification;
  if (hitsMajor >= 1) {
    classification = "major";
  } else if (hitsSignificant >= 1) {
    classification = "significant";
  } else {
    classification = "minor";
  }
  var mustReport = classification !== "minor";
  return {
    classification:        classification,
    mustReport:            mustReport,
    mustReportInitialByMs: mustReport ? INITIAL_REPORT_DEADLINE_MS : null,
    mustReportInitialOuterByMs: mustReport ? INITIAL_REPORT_OUTER_DEADLINE_MS : null,
    reasons:               reasons,
  };
}

function _validateReportInput(input) {
  if (!input || typeof input !== "object") {
    throw new DoraError("dora/bad-report",
      "report: input must be an object");
  }
  if (typeof input.incidentId !== "string" || input.incidentId.length === 0) {
    throw new DoraError("dora/missing-incident-id",
      "report: incidentId is required (non-empty string)");
  }
  if (VALID_CLASSIFICATIONS.indexOf(input.classification) === -1) {
    throw new DoraError("dora/bad-classification",
      "report: classification must be one of " +
      VALID_CLASSIFICATIONS.join(", ") + ", got " + JSON.stringify(input.classification));
  }
  if (VALID_STAGES.indexOf(input.stage) === -1) {
    throw new DoraError("dora/bad-stage",
      "report: stage must be one of " + VALID_STAGES.join(", ") +
      ", got " + JSON.stringify(input.stage));
  }
  if (typeof input.detectedAt !== "number" || !isFinite(input.detectedAt) || input.detectedAt <= 0) {
    throw new DoraError("dora/bad-detected-at",
      "report: detectedAt must be a positive ms-since-epoch number");
  }
  if (typeof input.description !== "string" || input.description.length === 0) {
    throw new DoraError("dora/missing-description",
      "report: description is required");
  }
}

/**
 * @primitive b.dora.create
 * @signature b.dora.create(opts)
 * @since     0.7.25
 * @status    stable
 * @compliance dora, nis2, cra, hipaa
 * @related   b.audit.safeEmit
 *
 * Build a DORA reporter handle exposing `classify`, `report`, and
 * `draftFinalReport`. `classify` runs the RTS 2024/1772 Articles
 * 1-12 thresholds (severity / affected clients / economic impact /
 * geographic scope / duration / reputational / sensitive-data
 * classes) and returns the regulatory tier (`"major"` / `"significant"`
 * / `"minor"`) plus a deadline hint. `report` validates and shapes
 * the operator's payload into an RTS-template record carrying the
 * `nextStageDueAt` deadline (Art. 19 — 24h initial / 72h intermediate
 * / 30-day final). `draftFinalReport` clones a prior record into a
 * Stage-final skeleton with the operator-fillable fields zeroed.
 * Each call emits an audit row in the `dora.*` namespace.
 *
 * @opts
 *   audit:          boolean (default true; set false to skip audit emits),
 *   observability:  boolean (default true; set false to skip the
 *                  best-effort observability counter on report),
 *
 * @example
 *   var dora = b.dora.create({ audit: true });
 *   var rv = dora.classify({
 *     dataAffected:       "financial",
 *     severityIndicator:  "critical",
 *     affectedClients:    1200,
 *     economicImpact:     { eur: 50000 },
 *     durationMs:         4 * 60 * 60 * 1000,
 *   });
 *   rv.classification;     // → "major"
 *   rv.mustReport;         // → true
 *
 *   var initial = dora.report({
 *     incidentId:    "INC-2026-0042",
 *     classification: rv.classification,
 *     stage:         "initial",
 *     detectedAt:    Date.now(),
 *     description:   "Payment-gateway outage — 2h customer-facing impact",
 *   });
 *   initial.stage;         // → "initial"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["audit", "observability"], "dora.create");
  var auditOn = opts.audit !== false;
  var obsOn   = opts.observability !== false;

  function _emit(action, info) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  info.outcome || "success",
        metadata: info.metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function classify(input) {
    if (!input || typeof input !== "object") {
      throw new DoraError("dora/bad-classify-input",
        "classify: input must be an object");
    }
    if (input.dataAffected !== undefined &&
        VALID_DATA_AFFECTED.indexOf(input.dataAffected) === -1) {
      throw new DoraError("dora/bad-data-affected",
        "classify: dataAffected must be one of " +
        VALID_DATA_AFFECTED.join(", "));
    }
    if (input.severityIndicator !== undefined &&
        VALID_SEVERITY.indexOf(input.severityIndicator) === -1) {
      throw new DoraError("dora/bad-severity",
        "classify: severityIndicator must be one of " + VALID_SEVERITY.join(", "));
    }
    if (input.reputationalImpact !== undefined &&
        VALID_REPUTATIONAL.indexOf(input.reputationalImpact) === -1) {
      throw new DoraError("dora/bad-reputational",
        "classify: reputationalImpact must be one of " + VALID_REPUTATIONAL.join(", "));
    }
    var rv = _classifyImpl(input);
    _emit("dora.incident.classified", {
      metadata: {
        classification: rv.classification,
        mustReport:     rv.mustReport,
        reasons:        rv.reasons,
      },
    });
    return rv;
  }

  function report(input) {
    _validateReportInput(input);
    var record = {
      incidentId:     input.incidentId,
      classification: input.classification,
      stage:          input.stage,
      detectedAt:     input.detectedAt,
      reportedAt:     Date.now(),
      description:    input.description,
      causeKnown:     input.causeKnown !== undefined ? !!input.causeKnown : null,
      rootCause:      input.rootCause || null,
      mitigationStarted: input.mitigationStarted !== undefined ? !!input.mitigationStarted : null,
      systemsAffected:   input.systemsAffected || [],
      affectedClients:   input.affectedClients || null,
      economicImpact:    input.economicImpact || null,
      geographicScope:   input.geographicScope || [],
      durationMs:        input.durationMs || null,
      reputationalImpact: input.reputationalImpact || null,
      contactPoint:      input.contactPoint || null,
      nextStageDueAt:    null,
    };
    if (input.stage === "initial") {
      record.nextStageDueAt = record.reportedAt + INTERMEDIATE_REPORT_DEADLINE_MS;
    } else if (input.stage === "intermediate") {
      record.nextStageDueAt = record.reportedAt + FINAL_REPORT_DEADLINE_MS;
    }
    _emit("dora.incident.reported", {
      metadata: {
        incidentId:     record.incidentId,
        classification: record.classification,
        stage:          record.stage,
      },
    });
    if (obsOn) {
      observability().safeEvent("dora.incident.reported", 1, {
        classification: record.classification, stage: record.stage,
      });
    }
    return record;
  }

  function draftFinalReport(initialOrIntermediate) {
    if (!initialOrIntermediate || typeof initialOrIntermediate !== "object") {
      throw new DoraError("dora/bad-draft-input",
        "draftFinalReport: input must be a prior report record");
    }
    var draft = Object.assign({}, initialOrIntermediate, {
      stage:        "final",
      reportedAt:   Date.now(),
      rootCause:           initialOrIntermediate.rootCause || null,
      remediationActions:  [],
      lessonsLearned:      "",
      preventiveMeasures:  [],
    });
    _emit("dora.incident.draftFinal", {
      metadata: { incidentId: draft.incidentId },
    });
    return draft;
  }

  return {
    classify:          classify,
    report:            report,
    draftFinalReport:  draftFinalReport,
  };
}

module.exports = {
  create:                              create,
  MAJOR_INCIDENT_THRESHOLDS:           MAJOR_INCIDENT_THRESHOLDS,
  SIGNIFICANT_INCIDENT_THRESHOLDS:     SIGNIFICANT_INCIDENT_THRESHOLDS,
  INITIAL_REPORT_DEADLINE_MS:          INITIAL_REPORT_DEADLINE_MS,
  INITIAL_REPORT_OUTER_DEADLINE_MS:    INITIAL_REPORT_OUTER_DEADLINE_MS,
  INTERMEDIATE_REPORT_DEADLINE_MS:     INTERMEDIATE_REPORT_DEADLINE_MS,
  FINAL_REPORT_DEADLINE_MS:            FINAL_REPORT_DEADLINE_MS,
  DEADLINES_NIS2:                      DEADLINES_NIS2,
  DEADLINES_CRA:                       DEADLINES_CRA,
  DEADLINES_HIPAA_BREACH:              DEADLINES_HIPAA_BREACH,
  DoraError:                           DoraError,
};
