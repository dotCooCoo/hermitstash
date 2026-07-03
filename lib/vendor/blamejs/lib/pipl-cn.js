// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.pipl
 * @nav    Compliance
 * @title  PIPL (China)
 *
 * @intro
 *   China PIPL (Personal Information Protection Law) cross-border
 *   transfer record-builders. PIPL Art. 38 sets three lawful bases for
 *   transferring personal information outside the PRC: a CAC security
 *   assessment (Art. 40), the CAC standard contract (SCC), or
 *   certification by a CAC-accredited body. The CAC security assessment
 *   is MANDATORY — the operator may not self-select the standard
 *   contract — when the exporter is a critical-information-infrastructure
 *   operator (CIIO), handles "important data", or crosses the volume /
 *   sensitive-PI thresholds in the Measures for Security Assessment of
 *   Outbound Data Transfers.
 *
 *   These primitives follow the operator-feeds-metadata pattern: the
 *   operator supplies the transfer's facts and the builder returns a
 *   frozen, dated record (plus a best-effort audit event) that composes
 *   into the operator's own retention / export sink. They perform NO
 *   network I/O and do NOT file anything with the CAC — they document
 *   the legal basis the operator must be able to produce on inspection.
 *
 * @card
 *   China PIPL cross-border transfer records — Art. 38/40/55 SCC + CAC security-assessment basis (sccFilingAssessment, securityAssessmentCertificate).
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { PiplError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// PIPL Art. 38(1) lawful cross-border mechanisms. A standard contract or
// certification is a self-selectable basis; a security assessment is the
// mechanism the CAC Measures impose when a mandatory trigger is present.
var LEGAL_BASES = Object.freeze(["standard-contract", "security-assessment", "certification"]);

// Mandatory-security-assessment thresholds from the CAC 2024 Provisions on
// Promoting and Regulating Cross-Border Data Flows (Art. 7/8), which relaxed
// the original 2022 Measures. Crossing ANY of these forces the
// security-assessment mechanism — the operator cannot fall back to the
// standard contract or certification.
//   - CIIO exporter, or "important data" in scope: always mandatory.
//   - cumulative outbound NON-sensitive PI of MORE THAN 1,000,000 individuals
//     since 1 January of the current year (the 100,000–1,000,000 band is the
//     standard-contract / certification tier, NOT a security-assessment
//     trigger).
//   - cumulative outbound SENSITIVE PI of MORE THAN 10,000 individuals in that
//     window.
// The thresholds are CUMULATIVE since 1 January and THIS transfer counts toward
// them — the transfer's own `volume` is sorted into the sensitive or
// non-sensitive bucket by `sensitivePI` and added to the running cumulative
// before the comparison.
var SECURITY_ASSESSMENT_NONSENSITIVE_PI_THRESHOLD = 1000000;
var SECURITY_ASSESSMENT_SENSITIVE_PI_THRESHOLD = 10000;

// Re-assessment / re-filing cadence. The CAC security assessment result
// is valid for 3 years (Measures Art. 14); the standard-contract +
// certification bases carry a PIPIA (Art. 55) that should be refreshed
// at least annually or on any material change. We stamp the longer 3-year
// clock for a mandated security assessment and a 1-year clock otherwise.
var SECURITY_ASSESSMENT_VALIDITY_DAYS = 365 * 3;
var STANDARD_REVIEW_DAYS = 365;

var SCC_ASSESSMENT_ALLOWED_KEYS = [
  "assessmentId", "transferType", "recipientJurisdiction", "dataCategories",
  "legalBasis", "volume", "sensitivePI", "ciio", "importantData",
  "cumulativePI", "cumulativeSensitivePI", "recordedAt", "audit",
];

var RISK_RATINGS = Object.freeze(["low", "medium", "high"]);

var SECURITY_CERT_ALLOWED_KEYS = [
  "certId", "assessmentScope", "dataExporter", "overseasRecipient",
  "riskRating", "safeguards", "filingRef", "recordedAt", "audit",
];

// Resolve the audit sink: an operator-supplied b.audit-shaped object wins
// (so the call is captured even without a DB-backed global handler);
// otherwise fall back to the framework's global audit. Validated for shape
// at the call site so a malformed sink throws rather than silently no-ops.
function _resolveAudit(optsAudit, label) {
  if (optsAudit === undefined || optsAudit === null) return audit();
  return validateOpts.auditShape(optsAudit, label, PiplError, "pipl/bad-audit");
}

function _requireRecordedAt(value, label) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new PiplError("pipl/bad-recorded-at",
      label + " must be a positive epoch-ms number");
  }
  return value;
}

/**
 * @primitive  b.pipl.sccFilingAssessment
 * @signature  b.pipl.sccFilingAssessment(opts)
 * @since      0.15.8
 * @status     stable
 * @compliance pipl-cn
 * @related    b.pipl.securityAssessmentCertificate, b.compliance.isCrossBorderRegulated, b.privacy.vendorReview
 *
 * Build a dated PIPL Art. 38 / Art. 55 cross-border transfer assessment
 * and determine the lawful mechanism the transfer requires. PIPL Art. 38(1)
 * permits three bases for moving personal information out of the PRC — the
 * CAC standard contract (SCC), a CAC security assessment (Art. 40), or
 * certification by a CAC-accredited body. Under the CAC Provisions on
 * Promoting and Regulating Cross-Border Data Flows (effective 2024, which
 * relaxed the 2022 thresholds) the security assessment is MANDATORY (the
 * operator may NOT self-select the standard contract or certification) when
 * the exporter is a critical-information-infrastructure operator (CIIO),
 * exports "important data", or — counting cumulatively since 1 January of
 * the current year — transfers the personal information of more than
 * 1,000,000 individuals (non-sensitive) or the sensitive personal
 * information of more than 10,000 individuals. The 100,000–1,000,000
 * non-sensitive band is the standard-contract / certification tier, NOT a
 * security-assessment trigger.
 *
 * The builder validates the operator-supplied facts, computes
 * `securityAssessmentRequired` against those thresholds, resolves the
 * `mechanismRequired` (forcing `security-assessment` when any trigger is
 * present, otherwise honoring the operator's declared `legalBasis`), and
 * stamps `recordedAt` plus a `nextReviewDueBy` re-assessment clock (3 years
 * for a mandated security assessment per Measures Art. 14, otherwise the
 * annual PIPIA refresh under Art. 55). The returned record is frozen and
 * is NOT framework-persisted — compose it into your retention / audit /
 * export sink. A best-effort `pipl.transfer.assessed` audit event fires.
 *
 * @opts
 *   assessmentId:          string,    // required — operator's identifier for this assessment
 *   transferType:          string,    // required — e.g. "intra-group", "processor", "controller-to-controller"
 *   recipientJurisdiction: string,    // required — destination jurisdiction (e.g. "US", "EU", "SG")
 *   dataCategories:        string[],  // required — non-empty list of PI categories transferred
 *   legalBasis:            string,    // required — "standard-contract" | "security-assessment" | "certification"
 *   volume:                number,    // required — count of data subjects in this transfer (>= 0)
 *   sensitivePI:           boolean,   // required — whether the transfer includes sensitive PI (Art. 28)
 *   ciio:                  boolean,   // optional — exporter is a CIIO (forces security assessment); default false
 *   importantData:         boolean,   // optional — transfer includes "important data" (forces it); default false
 *   cumulativePI:          number,    // optional — cumulative PI subjects exported since 1 Jan prior year; default 0
 *   cumulativeSensitivePI: number,    // optional — cumulative sensitive-PI subjects exported in that window; default 0
 *   recordedAt:            number,    // required — epoch ms of this assessment
 *   audit:                 object,    // optional — b.audit-shaped sink; default global b.audit
 *
 * @example
 *   var rec = b.pipl.sccFilingAssessment({
 *     assessmentId:          "xfer-2026-001",
 *     transferType:          "processor",
 *     recipientJurisdiction: "US",
 *     dataCategories:        ["contact", "billing"],
 *     legalBasis:            "standard-contract",
 *     volume:                5000,
 *     sensitivePI:           false,
 *     recordedAt:            Date.now(),
 *   });
 *   // → { assessmentId, mechanismRequired: "standard-contract",
 *   //     securityAssessmentRequired: false, recordedAt, nextReviewDueBy, ... }
 */
function sccFilingAssessment(opts) {
  validateOpts.requireObject(opts, "b.pipl.sccFilingAssessment: opts", PiplError, "pipl/bad-opts");
  validateOpts(opts, SCC_ASSESSMENT_ALLOWED_KEYS, "b.pipl.sccFilingAssessment");
  validateOpts.shape(opts, {
    assessmentId:          { rule: "required-string", code: "pipl/bad-assessment-id", label: "b.pipl.sccFilingAssessment: opts.assessmentId" },
    transferType:          { rule: "required-string", code: "pipl/bad-transfer-type", label: "b.pipl.sccFilingAssessment: opts.transferType" },
    recipientJurisdiction: { rule: "required-string", code: "pipl/bad-recipient", label: "b.pipl.sccFilingAssessment: opts.recipientJurisdiction" },
    dataCategories: function (value) {
      if (!Array.isArray(value) || value.length === 0) {
        throw new PiplError("pipl/bad-data-categories",
          "b.pipl.sccFilingAssessment: opts.dataCategories must be a non-empty array of strings");
      }
      validateOpts.optionalNonEmptyStringArray(value,
        "b.pipl.sccFilingAssessment: opts.dataCategories", PiplError, "pipl/bad-data-categories");
    },
    legalBasis: function (value) {
      if (LEGAL_BASES.indexOf(value) === -1) {
        throw new PiplError("pipl/bad-legal-basis",
          "b.pipl.sccFilingAssessment: opts.legalBasis must be one of " +
          LEGAL_BASES.join(" | ") + " (PIPL Art. 38(1)) — got " + JSON.stringify(value));
      }
    },
    volume: function (value) {
      if (typeof value !== "number" || !isFinite(value) || value < 0) {
        throw new PiplError("pipl/bad-volume",
          "b.pipl.sccFilingAssessment: opts.volume must be a non-negative finite number (data-subject count)");
      }
    },
    sensitivePI: function (value) {
      if (typeof value !== "boolean") {
        throw new PiplError("pipl/bad-sensitive-pi",
          "b.pipl.sccFilingAssessment: opts.sensitivePI must be a boolean");
      }
    },
    ciio:                  { rule: "optional-boolean", code: "pipl/bad-ciio", label: "b.pipl.sccFilingAssessment: opts.ciio" },
    importantData:         { rule: "optional-boolean", code: "pipl/bad-important-data", label: "b.pipl.sccFilingAssessment: opts.importantData" },
    cumulativePI:          { rule: "optional-non-negative", code: "pipl/bad-cumulative-pi", label: "b.pipl.sccFilingAssessment: opts.cumulativePI" },
    cumulativeSensitivePI: { rule: "optional-non-negative", code: "pipl/bad-cumulative-sensitive-pi", label: "b.pipl.sccFilingAssessment: opts.cumulativeSensitivePI" },
    recordedAt: function (value) {
      _requireRecordedAt(value, "b.pipl.sccFilingAssessment: opts.recordedAt");
    },
  }, "b.pipl.sccFilingAssessment: opts", PiplError, "pipl/bad-opts", { allow: ["audit"] });

  var ciio = opts.ciio === undefined ? false : opts.ciio;
  var importantData = opts.importantData === undefined ? false : opts.importantData;
  var cumulativePI = opts.cumulativePI === undefined ? 0 : opts.cumulativePI;
  var cumulativeSensitivePI = opts.cumulativeSensitivePI === undefined ? 0 : opts.cumulativeSensitivePI;

  var recordedAt = _requireRecordedAt(opts.recordedAt, "b.pipl.sccFilingAssessment: opts.recordedAt");
  // Resolve + shape-validate the audit sink at the entry-point tier (THROWS
  // on a malformed sink) — NOT inside the drop-silent emission try/catch
  // below, which would swallow the config error.
  var auditSink = _resolveAudit(opts.audit, "b.pipl.sccFilingAssessment: opts.audit");

  // Mandatory-security-assessment determination (CAC 2024 Provisions, Art. 7/8).
  // Crossing ANY trigger forces the security-assessment mechanism regardless of
  // the operator's declared legalBasis — the operator cannot self-downgrade to
  // the standard contract or certification once a trigger is present. The
  // thresholds are cumulative since 1 January and THIS transfer counts: sort its
  // own volume into the sensitive or non-sensitive bucket and add it to the
  // running cumulative before comparing, so a first/planned transfer that alone
  // crosses a threshold is classified correctly without the caller having to
  // pre-add it to the cumulative field.
  var effectiveSensitivePI    = cumulativeSensitivePI + (opts.sensitivePI ? opts.volume : 0);
  var effectiveNonSensitivePI = cumulativePI          + (opts.sensitivePI ? 0 : opts.volume);
  var triggers = [];
  if (ciio) triggers.push("ciio");
  if (importantData) triggers.push("important-data");
  if (effectiveNonSensitivePI > SECURITY_ASSESSMENT_NONSENSITIVE_PI_THRESHOLD) triggers.push("non-sensitive-pi-volume");
  if (effectiveSensitivePI > SECURITY_ASSESSMENT_SENSITIVE_PI_THRESHOLD) triggers.push("sensitive-pi-volume");

  var securityAssessmentRequired = triggers.length > 0;
  var mechanismRequired = securityAssessmentRequired ? "security-assessment" : opts.legalBasis;
  var nextReviewDays = securityAssessmentRequired ? SECURITY_ASSESSMENT_VALIDITY_DAYS : STANDARD_REVIEW_DAYS;

  var record = Object.freeze({
    assessmentId:               opts.assessmentId,
    transferType:               opts.transferType,
    recipientJurisdiction:      opts.recipientJurisdiction,
    dataCategories:             Object.freeze(opts.dataCategories.slice()),
    legalBasis:                 opts.legalBasis,
    volume:                     opts.volume,
    sensitivePI:                opts.sensitivePI,
    mechanismRequired:          mechanismRequired,
    securityAssessmentRequired: securityAssessmentRequired,
    securityAssessmentTriggers: Object.freeze(triggers),
    legalReference:             "PIPL Art. 38 / Art. 40 / Art. 55",
    recordedAt:                 recordedAt,
    nextReviewDueBy:            recordedAt + C.TIME.days(nextReviewDays),
  });

  try {
    auditSink.safeEmit({
      action:   "pipl.transfer.assessed",
      outcome:  "success",
      resource: { kind: "pipl-cross-border-transfer", id: opts.assessmentId },
      metadata: {
        transferType:               opts.transferType,
        recipientJurisdiction:      opts.recipientJurisdiction,
        mechanismRequired:          mechanismRequired,
        securityAssessmentRequired: securityAssessmentRequired,
        triggers:                   triggers,
        recordedAt:                 recordedAt,
      },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }

  return record;
}

/**
 * @primitive  b.pipl.securityAssessmentCertificate
 * @signature  b.pipl.securityAssessmentCertificate(opts)
 * @since      0.15.8
 * @status     stable
 * @compliance pipl-cn
 * @related    b.pipl.sccFilingAssessment, b.compliance.isCrossBorderRegulated
 *
 * Record a dated PIPL Art. 40 / CAC security-assessment self-declaration
 * for an outbound data transfer. PIPL Art. 40 and the Measures for
 * Security Assessment of Outbound Data Transfers require an operator who
 * must pass (or has passed) the CAC security assessment to document the
 * assessment scope, the data exporter, the overseas recipient, a risk
 * rating, and the safeguards relied on — the evidence the operator must be
 * able to produce on CAC inspection. This builder validates the supplied
 * facts and returns a frozen, dated certificate record stamped with a
 * 3-year `validUntil` clock (the CAC security-assessment result validity
 * period, Measures Art. 14). It performs NO network I/O and files nothing
 * with the CAC — it documents the assessment the operator conducted. A
 * best-effort `pipl.security_assessment.recorded` audit event fires.
 *
 * @opts
 *   certId:            string,    // required — operator's identifier for this certificate
 *   assessmentScope:   string,    // required — scope of the security assessment (systems / data flows covered)
 *   dataExporter:      string,    // required — the PRC data exporter (controller / processor)
 *   overseasRecipient: string,    // required — the overseas recipient receiving the PI
 *   riskRating:        string,    // required — "low" | "medium" | "high"
 *   safeguards:        string[],  // required — non-empty list of safeguards relied on (encryption, DPA, etc.)
 *   filingRef:         string,    // optional — CAC filing / acceptance reference number
 *   recordedAt:        number,    // required — epoch ms of this declaration
 *   audit:             object,    // optional — b.audit-shaped sink; default global b.audit
 *
 * @example
 *   var cert = b.pipl.securityAssessmentCertificate({
 *     certId:            "sa-2026-014",
 *     assessmentScope:   "CRM outbound replication to US region",
 *     dataExporter:      "Acme (Shanghai) Co., Ltd.",
 *     overseasRecipient: "Acme Inc. (Delaware)",
 *     riskRating:        "medium",
 *     safeguards:        ["XChaCha20 at rest", "standard contractual clauses", "data minimization"],
 *     recordedAt:        Date.now(),
 *   });
 *   // → { certId, assessmentScope, riskRating, recordedAt, validUntil }
 */
function securityAssessmentCertificate(opts) {
  validateOpts.requireObject(opts, "b.pipl.securityAssessmentCertificate: opts", PiplError, "pipl/bad-opts");
  validateOpts(opts, SECURITY_CERT_ALLOWED_KEYS, "b.pipl.securityAssessmentCertificate");
  validateOpts.shape(opts, {
    certId:            { rule: "required-string", code: "pipl/bad-cert-id", label: "b.pipl.securityAssessmentCertificate: opts.certId" },
    assessmentScope:   { rule: "required-string", code: "pipl/bad-scope", label: "b.pipl.securityAssessmentCertificate: opts.assessmentScope" },
    dataExporter:      { rule: "required-string", code: "pipl/bad-exporter", label: "b.pipl.securityAssessmentCertificate: opts.dataExporter" },
    overseasRecipient: { rule: "required-string", code: "pipl/bad-recipient", label: "b.pipl.securityAssessmentCertificate: opts.overseasRecipient" },
    riskRating: function (value) {
      if (RISK_RATINGS.indexOf(value) === -1) {
        throw new PiplError("pipl/bad-risk-rating",
          "b.pipl.securityAssessmentCertificate: opts.riskRating must be one of " +
          RISK_RATINGS.join(" | ") + " — got " + JSON.stringify(value));
      }
    },
    safeguards: function (value) {
      if (!Array.isArray(value) || value.length === 0) {
        throw new PiplError("pipl/bad-safeguards",
          "b.pipl.securityAssessmentCertificate: opts.safeguards must be a non-empty array of strings");
      }
      validateOpts.optionalNonEmptyStringArray(value,
        "b.pipl.securityAssessmentCertificate: opts.safeguards", PiplError, "pipl/bad-safeguards");
    },
    filingRef:         { rule: "optional-string", code: "pipl/bad-filing-ref", label: "b.pipl.securityAssessmentCertificate: opts.filingRef" },
    recordedAt: function (value) {
      _requireRecordedAt(value, "b.pipl.securityAssessmentCertificate: opts.recordedAt");
    },
  }, "b.pipl.securityAssessmentCertificate: opts", PiplError, "pipl/bad-opts", { allow: ["audit"] });

  var filingRef = opts.filingRef;

  var recordedAt = _requireRecordedAt(opts.recordedAt, "b.pipl.securityAssessmentCertificate: opts.recordedAt");
  // Entry-point shape-validate the audit sink (THROWS) before the drop-silent
  // emission try/catch below.
  var auditSink = _resolveAudit(opts.audit, "b.pipl.securityAssessmentCertificate: opts.audit");

  var record = Object.freeze({
    certId:            opts.certId,
    assessmentScope:   opts.assessmentScope,
    dataExporter:      opts.dataExporter,
    overseasRecipient: opts.overseasRecipient,
    riskRating:        opts.riskRating,
    safeguards:        Object.freeze(opts.safeguards.slice()),
    filingRef:         filingRef || null,
    legalReference:    "PIPL Art. 40 / CAC Measures for Security Assessment of Outbound Data Transfers",
    recordedAt:        recordedAt,
    validUntil:        recordedAt + C.TIME.days(SECURITY_ASSESSMENT_VALIDITY_DAYS),
  });

  try {
    auditSink.safeEmit({
      action:   "pipl.security_assessment.recorded",
      outcome:  "success",
      resource: { kind: "pipl-security-assessment", id: opts.certId },
      metadata: {
        assessmentScope:   opts.assessmentScope,
        dataExporter:      opts.dataExporter,
        overseasRecipient: opts.overseasRecipient,
        riskRating:        opts.riskRating,
        filingRef:         filingRef || null,
        recordedAt:        recordedAt,
      },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }

  return record;
}

module.exports = {
  sccFilingAssessment:           sccFilingAssessment,
  securityAssessmentCertificate: securityAssessmentCertificate,
  LEGAL_BASES:                   LEGAL_BASES,
  RISK_RATINGS:                  RISK_RATINGS,
  PiplError:                     PiplError,
};
