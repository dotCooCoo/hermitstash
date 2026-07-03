// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.dora — DORA Article 17 incident-reporting workflow.
 *
 * Covers: surface; classification thresholds (major / significant /
 * minor) per RTS 2024/1772; report-shape validation (initial /
 * intermediate / final); deadline computation per Article 19; final-
 * report draft generation; bad-input rejection.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("dora.create is a function", typeof b.dora.create === "function");
  check("dora.MAJOR_INCIDENT_THRESHOLDS exposed",
        typeof b.dora.MAJOR_INCIDENT_THRESHOLDS === "object");
  // RTS (EU) 2024/1772 Art. 5: initial notification within 4h of classifying
  // the incident as major; the 24h-from-awareness outer bound is exposed
  // separately. (Was asserted as 24h, contradicting the framework's own
  // incident-report DORA regime which correctly uses 4h.)
  check("dora.INITIAL_REPORT_DEADLINE_MS = 4h (operative from classification)",
        b.dora.INITIAL_REPORT_DEADLINE_MS === b.constants.TIME.hours(4));
  check("dora.INITIAL_REPORT_OUTER_DEADLINE_MS = 24h (outer, from awareness)",
        b.dora.INITIAL_REPORT_OUTER_DEADLINE_MS === b.constants.TIME.hours(24));
  check("dora agrees with incident-report REGIME_DEADLINES.dora",
        b.dora.INITIAL_REPORT_DEADLINE_MS === require("../../lib/incident-report").REGIME_DEADLINES.dora.initial &&
        b.dora.INTERMEDIATE_REPORT_DEADLINE_MS === require("../../lib/incident-report").REGIME_DEADLINES.dora.intermediate);
  check("frameworkError.DoraError exposed",
        typeof b.frameworkError.DoraError === "function");
}

function testClassifyMajor() {
  var dora = b.dora.create({ audit: false });
  var rv = dora.classify({
    severityIndicator: "critical",
    affectedClients:   200000,
    durationMs:        b.constants.TIME.hours(10),
    economicImpact:    { eur: 500000 },
  });
  check("classify with critical severity → major",
        rv.classification === "major" && rv.mustReport === true);
  check("major incident → 4h initial-report deadline (from classification)",
        rv.mustReportInitialByMs === b.constants.TIME.hours(4));
  check("major incident → 24h outer initial deadline (from awareness)",
        rv.mustReportInitialOuterByMs === b.constants.TIME.hours(24));
}

function testClassifySignificant() {
  var dora = b.dora.create({ audit: false });
  var rv = dora.classify({
    severityIndicator: "high",
    affectedClients:   15000,
    durationMs:        b.constants.TIME.hours(3),
  });
  check("classify with high severity + 15k clients → significant",
        rv.classification === "significant" && rv.mustReport === true);
}

function testClassifyMinor() {
  var dora = b.dora.create({ audit: false });
  var rv = dora.classify({
    severityIndicator: "low",
    affectedClients:   50,
    durationMs:        b.constants.TIME.minutes(10),
  });
  check("classify low-severity-tiny-impact → minor + no report required",
        rv.classification === "minor" && rv.mustReport === false);
}

function testClassifyDataSensitive() {
  var dora = b.dora.create({ audit: false });
  var rv = dora.classify({
    severityIndicator: "low",
    dataAffected:      "phi",
    affectedClients:   50,
  });
  check("classify with phi data → at minimum significant",
        rv.classification !== "minor");
}

function testClassifyBadInput() {
  var dora = b.dora.create({ audit: false });
  var threw = null;
  try { dora.classify({ dataAffected: "not-real" }); } catch (e) { threw = e; }
  check("classify: bad dataAffected throws",
        threw && /bad-data-affected/.test(threw.code || ""));
}

function testReportInitial() {
  var dora = b.dora.create({ audit: false });
  var detectedAt = Date.now() - b.constants.TIME.minutes(30);
  var record = dora.report({
    incidentId:    "INC-2026-0001",
    classification: "major",
    stage:          "initial",
    detectedAt:     detectedAt,
    description:    "Payment-gateway outage — 30-min impact",
    causeKnown:     false,
  });
  check("report initial: returns RTS-shaped record with reportedAt set",
        record && record.incidentId === "INC-2026-0001" &&
        typeof record.reportedAt === "number");
  // The intermediate deadline anchors on the INITIAL report's SUBMISSION time
  // (record.reportedAt), not detectedAt — a report filed late must not get a
  // deadline measured from detection (RTS 2024/1772 reporting timeline).
  check("report initial: nextStageDueAt = reportedAt + 72h (submission-anchored)",
        record.nextStageDueAt === record.reportedAt + b.constants.TIME.hours(72));
}

function testReportFinal() {
  var dora = b.dora.create({ audit: false });
  var record = dora.report({
    incidentId:    "INC-2026-0001",
    classification: "major",
    stage:          "final",
    detectedAt:     Date.now() - b.constants.TIME.days(7),
    description:    "Closed",
  });
  check("report final: nextStageDueAt = null (no further reports due)",
        record.nextStageDueAt === null);
}

function testReportBadInput() {
  var dora = b.dora.create({ audit: false });
  var threw = null;
  try {
    dora.report({
      incidentId:    "INC-x",
      classification: "not-real",
      stage:          "initial",
      detectedAt:     Date.now(),
      description:    "x",
    });
  } catch (e) { threw = e; }
  check("report: bad classification throws",
        threw && /bad-classification/.test(threw.code || ""));
}

function testDraftFinalReport() {
  var dora = b.dora.create({ audit: false });
  var initial = dora.report({
    incidentId:    "INC-final-test",
    classification: "major",
    stage:          "initial",
    detectedAt:     Date.now() - b.constants.TIME.days(3),
    description:    "Initial",
  });
  var draft = dora.draftFinalReport(initial);
  check("draftFinalReport: stage = 'final'",
        draft.stage === "final");
  check("draftFinalReport: incidentId preserved",
        draft.incidentId === initial.incidentId);
  check("draftFinalReport: includes RTS final-report fields",
        Array.isArray(draft.remediationActions) &&
        Array.isArray(draft.preventiveMeasures) &&
        typeof draft.lessonsLearned === "string");
}

function testReportObservabilityKnob() {
  // The `observability` opt gates the best-effort report counter.
  // Default (omitted) emits the dora.incident.reported event; setting
  // observability:false suppresses it. We tap the observability sink to
  // observe the emission.
  var events = [];
  b.observability.setTap(function (name) {
    if (name === "dora.incident.reported") events.push(name);
  });
  try {
    var doraDefault = b.dora.create({ audit: false });
    doraDefault.report({
      incidentId:     "INC-obs-default",
      classification: "major",
      stage:          "initial",
      detectedAt:     Date.now(),
      description:    "obs default path",
    });
    check("dora.observability default: counter emitted",
      events.indexOf("dora.incident.reported") !== -1);

    events.length = 0;
    var doraSilent = b.dora.create({ audit: false, observability: false });
    doraSilent.report({
      incidentId:     "INC-obs-silent",
      classification: "major",
      stage:          "initial",
      detectedAt:     Date.now(),
      description:    "obs suppressed path",
    });
    check("dora.observability false: no counter emitted",
      events.length === 0);
  } finally {
    b.observability.setTap(null);
  }
}

async function run() {
  testSurface();
  testClassifyMajor();
  testClassifySignificant();
  testClassifyMinor();
  testClassifyDataSensitive();
  testClassifyBadInput();
  testReportInitial();
  testReportFinal();
  testReportBadInput();
  testDraftFinalReport();
  testReportObservabilityKnob();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
