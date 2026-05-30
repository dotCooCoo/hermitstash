"use strict";
/**
 * b.secCyber — SEC Cybersecurity Disclosure Item 1.05 (Form 8-K)
 * artifact generator.
 *
 * Required by 17 CFR §229.106 / Form 8-K Item 1.05 (final rule
 * effective 2023-12-18). When a registrant determines that a
 * cybersecurity incident is material, it MUST file a Form 8-K within
 * 4 business days of the materiality determination, describing:
 *
 *   - The material aspects of the nature, scope, and timing
 *   - The material impact or reasonably likely material impact on
 *     the registrant (financial condition + results of operations)
 *
 * Materiality determination MUST be made "without unreasonable
 * delay." The Attorney General can authorize a delay (when public
 * disclosure would pose substantial risk to national security or
 * public safety) — registrant requests the delay before the 4-day
 * window elapses.
 *
 * The framework can't decide materiality (that's a fact-and-circum-
 * stances judgment). What it CAN do:
 *
 *   - Structure the operator's materiality finding into a
 *     tamper-evident audit-chain row (the regulator-facing record).
 *   - Generate the 8-K Item 1.05 narrative skeleton with the
 *     operator's content slotted in.
 *   - Compute the 4-business-day deadline so the operator's
 *     filing-system gate refuses to slip past it.
 *   - Emit an AG-delay-request artifact when the operator asserts
 *     national-security / public-safety risk.
 *
 * Public API:
 *
 *   b.secCyber.eightKArtifact(opts) -> { artifact, deadline, deadlineBusinessDays }
 *     opts:
 *       incidentId:        operator-supplied incident reference (string).
 *       registrant:        { name, cik, filer }
 *       detectedAt:        Unix-ms when the incident was detected.
 *       materialityDeterminedAt: Unix-ms when materiality was determined.
 *       materialityFinding:      "material" | "not-material" | "pending".
 *       materialityReasoning:    operator-provided narrative
 *                                explaining the materiality call.
 *       nature:            string describing the incident's nature.
 *       scope:             string describing the scope.
 *       timing:            string describing the timing.
 *       impact:            string describing material/likely-material
 *                          impact on financial condition + operations.
 *       agDelayRequested:  bool. When true, the artifact includes the
 *                          AG-delay-request template and the 4-day
 *                          deadline is suspended pending DOJ response.
 *       agDelayJustification: string explaining the national-security
 *                          / public-safety risk that justifies delay
 *                          (REQUIRED when agDelayRequested = true).
 *       audit:             bool, default true.
 *
 *   Returns:
 *       artifact:          structured 8-K Item 1.05 content (markdown
 *                          + JSON for downstream EDGAR filing).
 *       deadline:          Unix-ms 4-business-day deadline (null when
 *                          AG-delay-requested).
 *       deadlineBusinessDays: business-day count (4 by default; spec
 *                          gives no exception).
 *
 * The framework does NOT submit to EDGAR — operators wire the
 * artifact into their existing filer-attorney workflow.
 */

var audit = require("./audit");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var SecCyberError = defineClass("SecCyberError", { alwaysPermanent: true });

var FINDINGS = ["material", "not-material", "pending"];

function _addBusinessDays(startMs, days) {
  // Walk forward N business days (Mon-Fri). Doesn't honor US federal
  // holidays — operators with a calendar-aware filing system override
  // by reading deadlineBusinessDays and computing themselves.
  var t = new Date(startMs);
  var added = 0;
  while (added < days) {
    t = new Date(t.getTime() + C.TIME.days(1));
    var dow = t.getUTCDay();
    if (dow !== 0 && dow !== 6) added += 1;
  }
  return t.getTime();
}

function eightKArtifact(opts) {
  if (!opts || typeof opts !== "object") {
    throw SecCyberError.factory("BAD_OPTS",
      "secCyber.eightKArtifact: opts required");
  }
  validateOpts.requireNonEmptyString(opts.incidentId,
    "secCyber.eightKArtifact: incidentId", SecCyberError, "BAD_INCIDENT_ID");
  if (!opts.registrant || typeof opts.registrant !== "object") {
    throw SecCyberError.factory("BAD_REGISTRANT",
      "secCyber.eightKArtifact: registrant object required");
  }
  validateOpts.requireNonEmptyString(opts.registrant.name,
    "secCyber.eightKArtifact: registrant.name", SecCyberError, "BAD_REGISTRANT_NAME");
  validateOpts.requireNonEmptyString(opts.registrant.cik,
    "secCyber.eightKArtifact: registrant.cik", SecCyberError, "BAD_CIK");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.detectedAt,
    "secCyber.eightKArtifact: detectedAt", SecCyberError, "BAD_DETECTED_AT");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.materialityDeterminedAt,
    "secCyber.eightKArtifact: materialityDeterminedAt", SecCyberError, "BAD_MAT_AT");

  if (FINDINGS.indexOf(opts.materialityFinding) === -1) {
    throw SecCyberError.factory("BAD_FINDING",
      "secCyber.eightKArtifact: materialityFinding must be one of " + FINDINGS.join(", "));
  }
  validateOpts.requireNonEmptyString(opts.materialityReasoning,
    "secCyber.eightKArtifact: materialityReasoning", SecCyberError, "BAD_REASONING");

  if (opts.materialityFinding === "material") {
    validateOpts.requireNonEmptyString(opts.nature,
      "secCyber.eightKArtifact: nature", SecCyberError, "BAD_NATURE");
    validateOpts.requireNonEmptyString(opts.scope,
      "secCyber.eightKArtifact: scope", SecCyberError, "BAD_SCOPE");
    validateOpts.requireNonEmptyString(opts.timing,
      "secCyber.eightKArtifact: timing", SecCyberError, "BAD_TIMING");
    validateOpts.requireNonEmptyString(opts.impact,
      "secCyber.eightKArtifact: impact", SecCyberError, "BAD_IMPACT");
  }

  var agDelayRequested = opts.agDelayRequested === true;
  if (agDelayRequested) {
    validateOpts.requireNonEmptyString(opts.agDelayJustification,
      "secCyber.eightKArtifact: agDelayJustification (required when agDelayRequested=true)",
      SecCyberError, "BAD_AG_JUSTIFICATION");
  }

  var matAt = opts.materialityDeterminedAt || Date.now();
  var deadline = agDelayRequested ? null : _addBusinessDays(matAt, 4);

  var markdown = "# Form 8-K — Item 1.05 Material Cybersecurity Incident\n\n" +
    "**Registrant:** " + opts.registrant.name + " (CIK: " + opts.registrant.cik + ")\n\n" +
    "**Incident ID:** " + opts.incidentId + "\n\n" +
    "**Materiality determination date:** " + new Date(matAt).toISOString() + "\n\n" +
    "**Materiality finding:** " + opts.materialityFinding + "\n\n" +
    "**Reasoning:**\n\n" + opts.materialityReasoning + "\n\n";

  if (opts.materialityFinding === "material") {
    markdown +=
      "## Item 1.05(a) — Material aspects\n\n" +
      "**Nature.** " + opts.nature + "\n\n" +
      "**Scope.** " + opts.scope + "\n\n" +
      "**Timing.** " + opts.timing + "\n\n" +
      "## Item 1.05(b) — Material impact\n\n" + opts.impact + "\n\n";
  }

  if (agDelayRequested) {
    markdown += "## AG-delay request (17 CFR §229.106(c)(1)(ii))\n\n" +
      "Registrant asserts that disclosure of this incident would pose a substantial " +
      "risk to national security or public safety. Pursuant to the rule, registrant " +
      "requests that the Attorney General authorize a delay of disclosure.\n\n" +
      "**Justification:** " + opts.agDelayJustification + "\n\n";
  }

  markdown += "**Filing deadline:** " +
    (deadline ? new Date(deadline).toISOString() + " (4 business days from materiality determination)" :
                "suspended pending DOJ response to AG-delay request") + "\n";

  var artifactJson = {
    form:         "8-K",
    item:         "1.05",
    incidentId:   opts.incidentId,
    registrant:   { name: opts.registrant.name, cik: opts.registrant.cik },
    detectedAt:   opts.detectedAt || null,
    materialityDeterminedAt: matAt,
    materialityFinding: opts.materialityFinding,
    materialityReasoning: opts.materialityReasoning,
    items: opts.materialityFinding === "material" ? {
      "1.05(a)": {
        nature: opts.nature, scope: opts.scope, timing: opts.timing,
      },
      "1.05(b)": { impact: opts.impact },
    } : null,
    agDelayRequested:     agDelayRequested,
    agDelayJustification: agDelayRequested ? opts.agDelayJustification : null,
    deadlineMs:           deadline,
  };

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "seccyber.eight_k_artifact",
      outcome:  "success",
      metadata: {
        incidentId:           opts.incidentId,
        registrant:           opts.registrant.name,
        cik:                  opts.registrant.cik,
        materialityFinding:   opts.materialityFinding,
        deadlineMs:           deadline,
        agDelayRequested:     agDelayRequested,
      },
    });
  }

  return {
    artifact: { markdown: markdown, json: artifactJson },
    deadline: deadline,
    deadlineBusinessDays: agDelayRequested ? null : 4,                                       // allow:raw-byte-literal — SEC Item 1.05 4-business-day deadline (17 CFR §229.106(c)(1))
  };
}

module.exports = {
  eightKArtifact: eightKArtifact,
  FINDINGS:       FINDINGS.slice(),
  SecCyberError:  SecCyberError,
};
