"use strict";
/**
 * @module b.dsa
 * @nav    Compliance
 * @title  Digital Services Act
 *
 * @intro
 *   Record-builders for the operator workflows the EU Digital Services
 *   Act (Regulation (EU) 2022/2065) requires an online intermediary or
 *   platform to keep on file. Three dated, frozen attestation records
 *   cover the regulation's core content-governance loop:
 *
 *     - `noticeAndAction` (Art. 16) records a notice a third party
 *       submits against a piece of content and computes the window
 *       inside which the provider must act on it.
 *     - `statementOfReasons` (Art. 17) records the moderation decision
 *       taken on a piece of content, its legal or contractual ground,
 *       the facts relied on, whether it was automated, and the redress
 *       routes offered to the affected recipient.
 *     - `transparencyReport` (Art. 15 / Art. 24(3)) aggregates the
 *       period counts a provider must publish — notices received,
 *       actions taken, automated decisions, appeals — into a report
 *       record with the next due date.
 *
 *   The builders follow the operator-feeds-metadata pattern: the
 *   operator supplies the facts and each function returns a frozen,
 *   timestamped record that composes into the operator's own retention /
 *   audit / export sink. None of them persist to the framework or touch
 *   the network. A best-effort `dsa.*` audit event fires when an audit
 *   sink is wired. They map to the `dsa` compliance posture, which
 *   cascades ML-DSA-87 audit-chain signing and a TLS 1.3 floor.
 *
 * @card
 *   EU Digital Services Act (Reg 2022/2065) record-builders — Art. 16 notice-and-action, Art. 17 statement of reasons, Art. 15/24(3) transparency report.
 */

var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var { DsaError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// ---- Art. 16 notice-and-action ----

// The notice categories Art. 16(2) expects a notice-and-action
// mechanism to distinguish. A notice that alleges illegal content
// (Art. 16(2)(a)-(d)) starts the diligent-and-timely action clock and
// MUST be answered with an Art. 17 statement of reasons when the
// provider acts on it; a terms-of-service notice need not be.
var NOTICE_TYPES = Object.freeze({
  "illegal-content":   { statementOfReasonsRequired: true,  description: "Notice alleges the content is illegal under Union or member-state law (Art. 16(2))." },
  "terms-violation":   { statementOfReasonsRequired: false, description: "Notice alleges the content breaches the provider's terms and conditions." },
  "ip-infringement":   { statementOfReasonsRequired: true,  description: "Notice alleges intellectual-property infringement (a sub-case of illegal content)." },
  "other":             { statementOfReasonsRequired: false, description: "Any other notice category the provider's mechanism accepts." },
});
var NOTICE_TYPE_IDS = Object.keys(NOTICE_TYPES);

// Who submitted the notice. A trusted flagger (Art. 22) is processed
// with priority; the field is recorded so the provider can evidence
// the Art. 22(1) priority-handling obligation.
var SUBMITTER_TYPES = Object.freeze(["individual", "trusted-flagger", "authority", "rights-holder", "other"]);

// Default action window. Art. 16(6) requires action "in a timely,
// diligent, non-arbitrary and objective manner"; it sets no fixed
// hour count, so the framework default is a conservative 24h SLA that
// operators override per their own published policy via actionWindowMs.
var DEFAULT_ACTION_WINDOW_MS = C.TIME.hours(24);

/**
 * @primitive  b.dsa.noticeAndAction
 * @signature  b.dsa.noticeAndAction(opts)
 * @since      0.15.8
 * @status     stable
 * @compliance dsa
 * @related    b.dsa.statementOfReasons, b.dsa.transparencyReport, b.compliance.describe
 *
 * Record an Art. 16 notice-and-action notice and compute the window
 * inside which the provider must act on it. The operator supplies the
 * notice facts — the content it targets, the alleged category, the
 * substantiating reason, when it was submitted, and who submitted it —
 * and `noticeAndAction` validates the shape, stamps `recordedAt`,
 * derives `actionDueBy` from the submission time plus the action
 * window, and flags whether acting on the notice will require an
 * Art. 17 statement of reasons (true for illegal-content / IP notices).
 * The returned record is frozen and is NOT framework-persisted —
 * compose it into your retention / audit / export sink. A best-effort
 * `dsa.notice.recorded` audit event fires when an audit sink is wired.
 *
 * @opts
 *   contentId:       string,   // required — the content the notice targets
 *   noticeType:      string,   // required — illegal-content | terms-violation | ip-infringement | other
 *   reason:          string,   // required — the notice's substantiation (Art. 16(2)(a))
 *   submittedAt:     number,   // required — epoch ms the notice was submitted
 *   submitterType:   string,   // required — individual | trusted-flagger | authority | rights-holder | other
 *   noticeId:        string,   // optional — operator notice id; defaults to "dsa-notice-<submittedAt>"
 *   actionWindowMs:  number,   // optional — SLA window; default 24h (Art. 16(6) "timely")
 *
 * @example
 *   var n = b.dsa.noticeAndAction({
 *     contentId:     "post-9931",
 *     noticeType:    "illegal-content",
 *     reason:        "Depicts a sale prohibited under national law.",
 *     submittedAt:   Date.now(),
 *     submitterType: "trusted-flagger",
 *   });
 *   // → { noticeId, contentId, noticeType, status: "recorded",
 *   //     recordedAt, actionDueBy, statementOfReasonsRequired: true }
 */
function noticeAndAction(opts) {
  validateOpts.requireObject(opts, "b.dsa.noticeAndAction: opts", DsaError, "dsa/bad-opts");
  validateOpts(opts, [
    "contentId", "noticeType", "reason", "submittedAt", "submitterType",
    "noticeId", "actionWindowMs",
  ], "b.dsa.noticeAndAction");
  validateOpts.requireNonEmptyString(opts.contentId, "b.dsa.noticeAndAction: opts.contentId", DsaError, "dsa/bad-content-id");
  validateOpts.requireNonEmptyString(opts.noticeType, "b.dsa.noticeAndAction: opts.noticeType", DsaError, "dsa/bad-notice-type");
  if (NOTICE_TYPE_IDS.indexOf(opts.noticeType) === -1) {
    throw new DsaError("dsa/unknown-notice-type",
      "b.dsa.noticeAndAction: unknown noticeType '" + opts.noticeType +
      "' (allowed: " + NOTICE_TYPE_IDS.join(", ") + ")");
  }
  validateOpts.requireNonEmptyString(opts.reason, "b.dsa.noticeAndAction: opts.reason", DsaError, "dsa/bad-reason");
  if (typeof opts.submittedAt !== "number" || !isFinite(opts.submittedAt) || opts.submittedAt <= 0) {
    throw new DsaError("dsa/bad-submitted-at",
      "b.dsa.noticeAndAction: opts.submittedAt must be a positive epoch-ms number");
  }
  validateOpts.requireNonEmptyString(opts.submitterType, "b.dsa.noticeAndAction: opts.submitterType", DsaError, "dsa/bad-submitter-type");
  if (SUBMITTER_TYPES.indexOf(opts.submitterType) === -1) {
    throw new DsaError("dsa/unknown-submitter-type",
      "b.dsa.noticeAndAction: unknown submitterType '" + opts.submitterType +
      "' (allowed: " + SUBMITTER_TYPES.join(", ") + ")");
  }
  validateOpts.optionalNonEmptyString(opts.noticeId, "b.dsa.noticeAndAction: opts.noticeId", DsaError, "dsa/bad-notice-id");
  var actionWindowMs = opts.actionWindowMs === undefined
    ? DEFAULT_ACTION_WINDOW_MS
    : validateOpts.optionalPositiveFinite(opts.actionWindowMs, "b.dsa.noticeAndAction: opts.actionWindowMs", DsaError, "dsa/bad-action-window");

  var recordedAt = Date.now();
  var sorRequired = NOTICE_TYPES[opts.noticeType].statementOfReasonsRequired;
  var record = Object.freeze({
    noticeId:                    opts.noticeId || ("dsa-notice-" + opts.submittedAt),
    contentId:                   opts.contentId,
    noticeType:                  opts.noticeType,
    submitterType:               opts.submitterType,
    reason:                      opts.reason,
    submittedAt:                 opts.submittedAt,
    status:                      "recorded",
    recordedAt:                  recordedAt,
    actionDueBy:                 opts.submittedAt + actionWindowMs,
    statementOfReasonsRequired:  sorRequired,
  });
  try {
    audit().safeEmit({
      action:   "dsa.notice.recorded",
      outcome:  "success",
      metadata: {
        noticeId:                   record.noticeId,
        contentId:                  record.contentId,
        noticeType:                 record.noticeType,
        submitterType:              record.submitterType,
        actionDueBy:                record.actionDueBy,
        statementOfReasonsRequired: record.statementOfReasonsRequired,
      },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }
  return record;
}

// ---- Art. 17 statement of reasons ----

// The moderation decisions Art. 17(1) covers. Each restricts the
// content or the recipient's account; the statement of reasons must
// state which (Art. 17(3)(a)).
var DECISIONS = Object.freeze([
  "content-removed",
  "content-disabled",
  "content-demoted",
  "age-restricted",
  "monetisation-removed",
  "account-suspended",
  "account-terminated",
  "no-action",
]);

// The redress routes Art. 17(3)(f) requires the statement to point the
// recipient to. At least one must be offered for a restrictive
// decision.
var REDRESS_OPTIONS = Object.freeze([
  "internal-complaint",       // Art. 20 internal complaint-handling system
  "out-of-court-settlement",  // Art. 21 out-of-court dispute settlement
  "judicial-redress",         // Art. 17(3)(f) — judicial remedy
]);

/**
 * @primitive  b.dsa.statementOfReasons
 * @signature  b.dsa.statementOfReasons(opts)
 * @since      0.15.8
 * @status     stable
 * @compliance dsa
 * @related    b.dsa.noticeAndAction, b.dsa.transparencyReport, b.compliance.describe
 *
 * Record an Art. 17 statement of reasons for a content-moderation
 * decision. Whenever a provider restricts content (or a recipient's
 * account) it must give the affected recipient a clear, specific
 * statement of reasons; this builder records that statement as a frozen
 * dated record. The operator supplies the decision, the legal ground
 * (Art. 17(3)(d)) or the contractual ground (Art. 17(3)(e)) it rests
 * on, the facts relied on (Art. 17(3)(c)), whether the decision was
 * taken by automated means (Art. 17(3)(c)), and the redress routes
 * offered (Art. 17(3)(f)). Exactly one of `legalGround` /
 * `contractualGround` is required so the ground is never left implicit.
 * The returned record is frozen and is NOT framework-persisted — also
 * submit it to the Commission's DSA Transparency Database per Art. 24(5)
 * from your own pipeline. A best-effort `dsa.sor.recorded` audit event
 * fires when an audit sink is wired.
 *
 * @opts
 *   contentId:          string,    // required — the content the decision concerns
 *   decision:           string,    // required — content-removed | content-disabled | ... | no-action
 *   facts:              string,    // required — the facts and circumstances relied on (Art. 17(3)(c))
 *   automated:          boolean,   // required — was the decision taken by automated means (Art. 17(3)(c))
 *   redressOptions:     string[],  // required — internal-complaint | out-of-court-settlement | judicial-redress
 *   legalGround:        string,    // one-of-two — the legal ground when the decision rests on illegality (Art. 17(3)(d))
 *   contractualGround:  string,    // one-of-two — the T&C clause when the decision rests on the contract (Art. 17(3)(e))
 *   sorId:              string,    // optional — operator id; defaults to "dsa-sor-<recordedAt>"
 *   noticeId:           string,    // optional — the Art. 16 notice this answers, if any
 *   territorialScope:   string,    // optional — geographic scope of the restriction (Art. 17(3)(b))
 *
 * @example
 *   var s = b.dsa.statementOfReasons({
 *     contentId:      "post-9931",
 *     decision:       "content-removed",
 *     legalGround:    "National law prohibiting the depicted sale.",
 *     facts:          "Listing offered a prohibited item for sale.",
 *     automated:      false,
 *     redressOptions: ["internal-complaint", "judicial-redress"],
 *   });
 *   // → { sorId, contentId, decision, recordedAt, groundType, automated, ... }
 */
function statementOfReasons(opts) {
  validateOpts.requireObject(opts, "b.dsa.statementOfReasons: opts", DsaError, "dsa/bad-opts");
  validateOpts(opts, [
    "contentId", "decision", "facts", "automated", "redressOptions",
    "legalGround", "contractualGround", "sorId", "noticeId", "territorialScope",
  ], "b.dsa.statementOfReasons");
  validateOpts.requireNonEmptyString(opts.contentId, "b.dsa.statementOfReasons: opts.contentId", DsaError, "dsa/bad-content-id");
  validateOpts.requireNonEmptyString(opts.decision, "b.dsa.statementOfReasons: opts.decision", DsaError, "dsa/bad-decision");
  if (DECISIONS.indexOf(opts.decision) === -1) {
    throw new DsaError("dsa/unknown-decision",
      "b.dsa.statementOfReasons: unknown decision '" + opts.decision +
      "' (allowed: " + DECISIONS.join(", ") + ")");
  }
  validateOpts.requireNonEmptyString(opts.facts, "b.dsa.statementOfReasons: opts.facts", DsaError, "dsa/bad-facts");
  if (typeof opts.automated !== "boolean") {
    throw new DsaError("dsa/bad-automated",
      "b.dsa.statementOfReasons: opts.automated must be a boolean (Art. 17(3)(c) — was the decision automated)");
  }
  // Exactly one ground — never both, never neither. Art. 17(3)(d)/(e)
  // require the statement to state the specific ground; leaving it
  // implicit or asserting two grounds at once is the compliance-theater
  // shape this refuses.
  validateOpts.optionalNonEmptyString(opts.legalGround, "b.dsa.statementOfReasons: opts.legalGround", DsaError, "dsa/bad-legal-ground");
  validateOpts.optionalNonEmptyString(opts.contractualGround, "b.dsa.statementOfReasons: opts.contractualGround", DsaError, "dsa/bad-contractual-ground");
  var hasLegal = typeof opts.legalGround === "string" && opts.legalGround.length > 0;
  var hasContractual = typeof opts.contractualGround === "string" && opts.contractualGround.length > 0;
  if (hasLegal === hasContractual) {
    throw new DsaError("dsa/ground-required",
      "b.dsa.statementOfReasons: supply exactly one of legalGround (Art. 17(3)(d)) or " +
      "contractualGround (Art. 17(3)(e)) — got " + (hasLegal ? "both" : "neither"));
  }
  if (!Array.isArray(opts.redressOptions) || opts.redressOptions.length === 0) {
    throw new DsaError("dsa/redress-required",
      "b.dsa.statementOfReasons: opts.redressOptions must be a non-empty array (Art. 17(3)(f)) — " +
      "allowed: " + REDRESS_OPTIONS.join(", "));
  }
  opts.redressOptions.forEach(function (r, i) {
    if (typeof r !== "string" || REDRESS_OPTIONS.indexOf(r) === -1) {
      throw new DsaError("dsa/unknown-redress-option",
        "b.dsa.statementOfReasons: redressOptions[" + i + "] '" + r +
        "' is not a recognised redress route (allowed: " + REDRESS_OPTIONS.join(", ") + ")");
    }
  });
  validateOpts.optionalNonEmptyString(opts.sorId, "b.dsa.statementOfReasons: opts.sorId", DsaError, "dsa/bad-sor-id");
  validateOpts.optionalNonEmptyString(opts.noticeId, "b.dsa.statementOfReasons: opts.noticeId", DsaError, "dsa/bad-notice-id");
  validateOpts.optionalNonEmptyString(opts.territorialScope, "b.dsa.statementOfReasons: opts.territorialScope", DsaError, "dsa/bad-territorial-scope");

  var recordedAt = Date.now();
  var record = Object.freeze({
    sorId:             opts.sorId || ("dsa-sor-" + recordedAt),
    contentId:         opts.contentId,
    noticeId:          opts.noticeId || null,
    decision:          opts.decision,
    groundType:        hasLegal ? "legal" : "contractual",
    legalGround:       hasLegal ? opts.legalGround : null,
    contractualGround: hasContractual ? opts.contractualGround : null,
    facts:             opts.facts,
    automated:         opts.automated,
    redressOptions:    Object.freeze(opts.redressOptions.slice()),
    territorialScope:  opts.territorialScope || null,
    recordedAt:        recordedAt,
  });
  try {
    audit().safeEmit({
      action:   "dsa.sor.recorded",
      outcome:  "success",
      metadata: {
        sorId:      record.sorId,
        contentId:  record.contentId,
        decision:   record.decision,
        groundType: record.groundType,
        automated:  record.automated,
        noticeId:   record.noticeId,
      },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }
  return record;
}

// ---- Art. 15 / Art. 24(3) transparency report ----

// The metric fields Art. 15(1) + Art. 24 expect a transparency report
// to carry. Every metric is a non-negative integer count over the
// reporting period; an omitted metric defaults to 0 so a partial
// report still produces a complete, comparable shape.
var METRIC_FIELDS = Object.freeze([
  "noticesReceived",        // Art. 15(1)(b) — notices submitted under Art. 16
  "actionsTaken",           // Art. 15(1)(b) — actions taken on those notices
  "automatedDecisions",     // Art. 15(1)(e) — content moderation by automated means
  "ownInitiativeActions",   // Art. 15(1)(c) — own-initiative content moderation
  "statementsOfReasons",    // Art. 24(1) — statements of reasons issued
  "appeals",                // Art. 24(1)(a) — Art. 20 internal complaints received
  "appealsUpheld",          // Art. 24(1)(a) — complaints decided in the recipient's favour
  "outOfCourtDisputes",     // Art. 24(1)(b) — Art. 21 out-of-court settlements
  "accountSuspensions",     // Art. 23 — suspensions for misuse
]);

// The annual re-report clock. Art. 15(1) requires reporting "at least
// once a year"; the next-due default is one year after the period end.
var REPORT_PERIOD_MS = C.TIME.days(365);

/**
 * @primitive  b.dsa.transparencyReport
 * @signature  b.dsa.transparencyReport(opts)
 * @since      0.15.8
 * @status     stable
 * @compliance dsa
 * @related    b.dsa.noticeAndAction, b.dsa.statementOfReasons, b.compliance.describe
 *
 * Build an Art. 15 (all intermediary services) / Art. 24(3) (online
 * platforms) transparency report. The operator supplies the reporting
 * period and the period counts — notices received, actions taken,
 * automated decisions, appeals, and so on — and `transparencyReport`
 * validates the shape, normalises every metric to a non-negative
 * integer (omitted metrics default to 0 so a partial report still has a
 * complete, comparable shape), stamps `generatedAt`, and computes
 * `nextReportDueBy` one year after the period end (Art. 15(1) "at least
 * once a year"). The returned report is frozen and is NOT
 * framework-persisted — publish it from your own pipeline. A
 * best-effort `dsa.transparency_report.generated` audit event fires
 * when an audit sink is wired.
 *
 * @opts
 *   period:    object,   // required — { from: number, to: number } epoch-ms window (from < to)
 *   metrics:   object,   // optional — { <metric>: number } period counts; see b.dsa.listTransparencyMetrics()
 *   reportId:  string,   // optional — operator id; defaults to "dsa-transparency-<to>"
 *   service:   string,   // optional — the service the report covers
 *
 * @example
 *   var r = b.dsa.transparencyReport({
 *     period:  { from: Date.UTC(2025, 0, 1), to: Date.UTC(2025, 11, 31) },
 *     metrics: { noticesReceived: 1200, actionsTaken: 940, automatedDecisions: 610, appeals: 75 },
 *   });
 *   // → { reportId, period, metrics: {...all 9 normalised...}, generatedAt, nextReportDueBy }
 */
function transparencyReport(opts) {
  validateOpts.requireObject(opts, "b.dsa.transparencyReport: opts", DsaError, "dsa/bad-opts");
  validateOpts(opts, ["period", "metrics", "reportId", "service"], "b.dsa.transparencyReport");
  if (!opts.period || typeof opts.period !== "object" || Array.isArray(opts.period)) {
    throw new DsaError("dsa/bad-period",
      "b.dsa.transparencyReport: opts.period must be a { from, to } object of epoch-ms numbers");
  }
  var from = opts.period.from;
  var to = opts.period.to;
  if (typeof from !== "number" || !isFinite(from) || from <= 0 ||
      typeof to !== "number" || !isFinite(to) || to <= 0) {
    throw new DsaError("dsa/bad-period",
      "b.dsa.transparencyReport: opts.period.from and opts.period.to must be positive epoch-ms numbers");
  }
  if (from >= to) {
    throw new DsaError("dsa/bad-period-order",
      "b.dsa.transparencyReport: opts.period.from must be strictly before opts.period.to");
  }
  validateOpts.optionalNonEmptyString(opts.reportId, "b.dsa.transparencyReport: opts.reportId", DsaError, "dsa/bad-report-id");
  validateOpts.optionalNonEmptyString(opts.service, "b.dsa.transparencyReport: opts.service", DsaError, "dsa/bad-service");

  var supplied = opts.metrics;
  if (supplied !== undefined && supplied !== null &&
      (typeof supplied !== "object" || Array.isArray(supplied))) {
    throw new DsaError("dsa/bad-metrics",
      "b.dsa.transparencyReport: opts.metrics must be a plain object of metric counts");
  }
  supplied = supplied || {};
  // Reject unknown metric keys — a misspelled metric would otherwise
  // silently drop out of the published report.
  Object.keys(supplied).forEach(function (k) {
    if (METRIC_FIELDS.indexOf(k) === -1) {
      throw new DsaError("dsa/unknown-metric",
        "b.dsa.transparencyReport: unknown metric '" + k +
        "' (see b.dsa.listTransparencyMetrics())");
    }
  });
  var metrics = {};
  METRIC_FIELDS.forEach(function (field) {
    var v = supplied[field];
    if (v === undefined || v === null) { metrics[field] = 0; return; }
    if (!numericBounds.isNonNegativeFiniteInt(v)) {
      throw new DsaError("dsa/bad-metric-value",
        "b.dsa.transparencyReport: metrics." + field +
        " must be a non-negative integer, got " +
        (typeof v === "number" ? String(v) : typeof v));
    }
    metrics[field] = v;
  });

  var generatedAt = Date.now();
  var report = Object.freeze({
    reportId:        opts.reportId || ("dsa-transparency-" + to),
    service:         opts.service || null,
    period:          Object.freeze({ from: from, to: to }),
    metrics:         Object.freeze(metrics),
    generatedAt:     generatedAt,
    nextReportDueBy: to + REPORT_PERIOD_MS,
  });
  try {
    audit().safeEmit({
      action:   "dsa.transparency_report.generated",
      outcome:  "success",
      metadata: {
        reportId:        report.reportId,
        service:         report.service,
        periodFrom:      from,
        periodTo:        to,
        noticesReceived: metrics.noticesReceived,
        actionsTaken:    metrics.actionsTaken,
      },
    });
  } catch (_e) { /* drop-silent — audit is best-effort, never block the builder */ }
  return report;
}

/**
 * @primitive  b.dsa.listTransparencyMetrics
 * @signature  b.dsa.listTransparencyMetrics()
 * @since      0.15.8
 * @status     stable
 * @related    b.dsa.transparencyReport
 *
 * Return the frozen list of metric field names a `transparencyReport`
 * aggregates — each maps to an Art. 15 / Art. 24 reporting obligation.
 * Use it to render a data-entry form or to enumerate the counts the
 * report normalises.
 *
 * @example
 *   b.dsa.listTransparencyMetrics();
 *   // → ["noticesReceived", "actionsTaken", "automatedDecisions", ...]
 */
function listTransparencyMetrics() {
  return METRIC_FIELDS;
}

module.exports = {
  noticeAndAction:         noticeAndAction,
  statementOfReasons:      statementOfReasons,
  transparencyReport:      transparencyReport,
  listTransparencyMetrics: listTransparencyMetrics,
  NOTICE_TYPES:            NOTICE_TYPES,
  DECISIONS:               DECISIONS,
  REDRESS_OPTIONS:         REDRESS_OPTIONS,
  METRIC_FIELDS:           METRIC_FIELDS,
  DsaError:                DsaError,
};
