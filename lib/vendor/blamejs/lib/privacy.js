"use strict";
/**
 * @module b.privacy
 * @nav    Compliance
 * @title  Privacy
 *
 * @intro
 *   Privacy-program operational helpers. The first primitive,
 *   `vendorReview`, builds the annual third-party / EdTech vendor-review
 *   attestation that FERPA's school-official exception and California's
 *   SOPIPA expect a school or district to keep on file for every
 *   processor that touches student data: a dated, clause-by-clause
 *   record that the vendor uses the data only for the authorized
 *   educational purpose, runs no targeted advertising or commercial
 *   profiling, sells nothing, keeps reasonable security safeguards,
 *   deletes on request, and so on.
 *
 *   The builder follows the operator-feeds-metadata pattern: the
 *   operator supplies the vendor's attested answers and `vendorReview`
 *   returns a frozen report — `{ attested, gaps, reviewedAt,
 *   nextReviewDueAt, ... }` — that composes into the operator's own
 *   retention / audit / export sink. It is not framework-persisted.
 *
 * @card
 *   Privacy-program helpers — annual FERPA / SOPIPA EdTech vendor-review attestation reports (`vendorReview`).
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { PrivacyError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// The clause set a FERPA school-official / SOPIPA vendor review attests.
// Each entry: { id, required, citation, description }. Every `required`
// clause must be attested true for the review to pass (attested:true).
var VENDOR_REVIEW_CLAUSES = Object.freeze([
  Object.freeze({ id: "educationalPurposeOnly",       required: true,  citation: "FERPA 34 CFR 99.31(a)(1)(i)(B)", description: "Vendor uses student data only for the authorized educational purpose under direct school control; no redisclosure." }),
  Object.freeze({ id: "noTargetedAdvertising",        required: true,  citation: "SOPIPA Cal. B&P 22584(b)(1)",    description: "No targeted advertising to students based on covered information." }),
  Object.freeze({ id: "noCommercialProfiling",        required: true,  citation: "SOPIPA Cal. B&P 22584(b)(2)",    description: "No amassing of a student profile except in furtherance of K-12 purposes." }),
  Object.freeze({ id: "noSaleOfStudentData",          required: true,  citation: "SOPIPA Cal. B&P 22584(b)(3)",    description: "No sale or rental of student information." }),
  Object.freeze({ id: "securitySafeguards",           required: true,  citation: "SOPIPA Cal. B&P 22584(d)(1)",    description: "Reasonable security procedures and practices appropriate to the data's sensitivity." }),
  Object.freeze({ id: "deletionOnRequest",            required: true,  citation: "SOPIPA Cal. B&P 22584(d)(2)",    description: "Deletes student PII within a reasonable time at the school's or district's request." }),
  Object.freeze({ id: "subProcessorsCurrent",         required: true,  citation: "FERPA 34 CFR 99.33 (redisclosure)", description: "Sub-processor list is current and each is bound to the same restrictions." }),
  Object.freeze({ id: "breachNotification",           required: true,  citation: "FERPA 34 CFR 99.31(a)(1) control + state breach law", description: "Notifies the school / district of any security breach without undue delay." }),
  Object.freeze({ id: "schoolOfficialDesignation",    required: true,  citation: "FERPA 34 CFR 99.31(a)(1)(i)(B)", description: "Vendor is designated a school official with a legitimate educational interest." }),
  Object.freeze({ id: "directoryInformationHandling", required: false, citation: "FERPA 34 CFR 99.37",             description: "Handles directory information per the school's opt-out notice (only when applicable)." }),
]);

var CLAUSE_IDS = VENDOR_REVIEW_CLAUSES.map(function (c) { return c.id; });

/**
 * @primitive  b.privacy.vendorReview
 * @signature  b.privacy.vendorReview(opts)
 * @since      0.14.14
 * @status     stable
 * @compliance ferpa, ca-sopipa, coppa
 * @related    b.consent.recognizedPurpose, b.compliance.describe, b.retention
 *
 * Build a dated annual third-party / EdTech vendor-review attestation —
 * the record a FERPA school-official arrangement and California SOPIPA
 * expect a school or district to keep for every processor of student
 * data. The operator supplies the vendor's attested answer (a boolean)
 * per clause; `vendorReview` validates the shape, computes whether every
 * REQUIRED clause is attested (`attested`) and which are not (`gaps`),
 * and stamps the review date plus a 365-day `nextReviewDueAt` re-review
 * clock. Operator-feeds-metadata: the returned report is frozen and is
 * NOT framework-persisted — compose it into your retention / audit /
 * export sink. A best-effort `privacy.vendor_review.recorded` audit event
 * fires when an audit sink is wired.
 *
 * @opts
 *   vendorName:   string,                    // required — the processor under review
 *   reviewedAt:   number,                    // required — epoch ms of this review
 *   clauses:      { <clauseId>: boolean },   // attested answer per clause (see listVendorReviewClauses)
 *   reviewer:     string,                    // optional — who performed the review
 *   notes:        string,                    // optional — free-text reviewer notes
 *
 * @example
 *   var report = b.privacy.vendorReview({
 *     vendorName: "Acme LMS",
 *     reviewedAt: Date.now(),
 *     clauses: {
 *       educationalPurposeOnly: true, noTargetedAdvertising: true,
 *       noCommercialProfiling: true, noSaleOfStudentData: true,
 *       securitySafeguards: true, deletionOnRequest: true,
 *       subProcessorsCurrent: true, breachNotification: true,
 *       schoolOfficialDesignation: true,
 *     },
 *   });
 *   // → { vendorName, reviewedAt, nextReviewDueAt, attested: true, gaps: [], clauses: {...} }
 */
function vendorReview(opts) {
  validateOpts.requireObject(opts, "b.privacy.vendorReview: opts", PrivacyError, "privacy/bad-opts");
  validateOpts.requireNonEmptyString(opts.vendorName, "b.privacy.vendorReview: opts.vendorName", PrivacyError, "privacy/bad-vendor");
  if (typeof opts.reviewedAt !== "number" || !isFinite(opts.reviewedAt) || opts.reviewedAt <= 0) {
    throw new PrivacyError("privacy/bad-reviewed-at",
      "b.privacy.vendorReview: opts.reviewedAt must be a positive epoch-ms number");
  }
  var clauses = opts.clauses || {};
  validateOpts.requireObject(clauses, "b.privacy.vendorReview: opts.clauses", PrivacyError, "privacy/bad-clauses");
  // Reject unknown clause keys — a misspelled clause would otherwise
  // silently never gate.
  Object.keys(clauses).forEach(function (k) {
    if (CLAUSE_IDS.indexOf(k) === -1) {
      throw new PrivacyError("privacy/unknown-clause",
        "b.privacy.vendorReview: unknown clause '" + k + "' (see b.privacy.listVendorReviewClauses())");
    }
  });
  var resolved = {};
  var gaps = [];
  VENDOR_REVIEW_CLAUSES.forEach(function (clause) {
    var v = clauses[clause.id];
    // A supplied clause answer must be a boolean (config-time THROW); an
    // omitted one defaults to not-attested.
    validateOpts.optionalBoolean(v, "b.privacy.vendorReview: clauses." + clause.id, PrivacyError, "privacy/bad-clause-value");
    var attestedTrue = v === true;
    resolved[clause.id] = attestedTrue;
    if (clause.required && !attestedTrue) gaps.push(clause.id);
  });
  var attested = gaps.length === 0;
  var report = Object.freeze({
    vendorName:      opts.vendorName,
    reviewedAt:      opts.reviewedAt,
    nextReviewDueAt: opts.reviewedAt + C.TIME.days(365),
    coversPeriod:    Object.freeze({ from: opts.reviewedAt - C.TIME.days(365), to: opts.reviewedAt }),
    reviewer:        opts.reviewer || null,
    notes:           opts.notes || null,
    attested:        attested,
    gaps:            Object.freeze(gaps),
    clauses:         Object.freeze(resolved),
  });
  try {
    audit().safeEmit({
      action:   "privacy.vendor_review.recorded",
      outcome:  attested ? "success" : "denied",
      metadata: { vendorName: opts.vendorName, attested: attested, gaps: gaps, reviewedAt: opts.reviewedAt },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }
  return report;
}

/**
 * @primitive  b.privacy.listVendorReviewClauses
 * @signature  b.privacy.listVendorReviewClauses()
 * @since      0.14.14
 * @status     stable
 * @related    b.privacy.vendorReview
 *
 * Return the frozen FERPA / SOPIPA vendor-review clause set — each entry
 * is `{ id, required, citation, description }`. Use it to render a review
 * form or to enumerate the clauses `vendorReview` evaluates.
 *
 * @example
 *   b.privacy.listVendorReviewClauses().map(function (c) { return c.id; });
 *   // → ["educationalPurposeOnly", "noTargetedAdvertising", ...]
 */
function listVendorReviewClauses() {
  return VENDOR_REVIEW_CLAUSES;
}

module.exports = {
  vendorReview:            vendorReview,
  listVendorReviewClauses: listVendorReviewClauses,
  VENDOR_REVIEW_CLAUSES:   VENDOR_REVIEW_CLAUSES,
  PrivacyError:            PrivacyError,
};
