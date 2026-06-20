"use strict";
/**
 * b.ai.adverseDecision — adverse-decision wrapper for automated
 * decisions affecting consumer rights.
 *
 * GDPR Article 22, EU AI Act Article 86, Colorado AI Act, NYC Local
 * Law 144, and Equal Credit Opportunity Act §1002.9 all require some
 * form of consumer notice + explanation when an automated decision
 * adversely affects a person (denial of credit, denial of employment,
 * adverse insurance pricing, etc.).
 *
 * The primitive wraps an operator-supplied predicate and:
 *   - logs every decision with audit-chain attribution
 *   - emits a structured consumer-rights notice on adverse outcomes
 *   - pulls operator-supplied principal reasons (the "specific reasons
 *     for the action" that ECOA + similar regimes require)
 *
 *   var hireDecision = b.ai.adverseDecision.wrap({
 *     name:         "hire-screening",
 *     model:        "screening-v3.1",
 *     legalBasis:   "ecoa-1002.9",
 *     decide:       function (applicant) {
 *       var score = scoreModel(applicant);
 *       return {
 *         outcome:        score < 0.5 ? "adverse" : "favorable",
 *         score:          score,
 *         principalReasons: score < 0.5 ? ["insufficient-credit-history", "..."] : [],
 *       };
 *     },
 *     onAdverse:    async function (subject, decision) {
 *       await mailer.send({ to: subject.email, ... });
 *     },
 *   });
 *
 *   var decision = await hireDecision({ id: "applicant-1234", email: "..." });
 *   // decision = { outcome, score, principalReasons, adverseNotice? }
 *
 * adverseNotice (when outcome === "adverse"):
 *   {
 *     subjectId:     "applicant-1234",
 *     decisionAt:    1715040000000,
 *     model:         "screening-v3.1",
 *     legalBasis:    "ecoa-1002.9",
 *     principalReasons: [...],
 *     consumerRights: {
 *       requestExplanation: true,
 *       requestHumanReview: true,
 *       requestAppeal:      true,
 *       requestData:        true,
 *       statutoryDeadlines: { explanation: "30d", humanReview: null, appeal: null }
 *     }
 *   }
 */

var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var AdverseDecisionError = defineClass("AdverseDecisionError", { alwaysPermanent: true });

// Per-regime statutory deadlines for the consumer-rights surfaces.
// Operators select via opts.legalBasis; the framework attaches the
// right deadline shape to each adverseNotice.
var REGIME_DEADLINES = Object.freeze({
  "gdpr-22":           { explanation: "30d", humanReview: "30d", appeal: "30d", regulation: "GDPR Article 22" },
  "ai-act-86":         { explanation: "30d", humanReview: "30d", appeal: "30d", regulation: "EU AI Act Article 86" },
  "ecoa-1002.9":       { explanation: "30d", humanReview: null, appeal: null,   regulation: "ECOA 12 CFR §1002.9" },
  "colorado-ai-act":   { explanation: "60d", humanReview: "60d", appeal: "60d", regulation: "Colorado AI Act" },
  "nyc-ll-144":        { explanation: "10d", humanReview: null, appeal: null,   regulation: "NYC Local Law 144" },
  "fcra-615":          { explanation: "60d", humanReview: null, appeal: null,   regulation: "FCRA 15 USC §1681m" },
  "operator-defined":  { explanation: null,  humanReview: null, appeal: null,   regulation: "operator-supplied" },
});

function wrap(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "name", "model", "legalBasis", "decide", "onAdverse",
    "audit", "now",
  ], "ai.adverseDecision");

  validateOpts.requireNonEmptyString(opts.name,
    "ai.adverseDecision.wrap: opts.name is required",
    AdverseDecisionError, "ai-adverse/bad-name");
  validateOpts.requireNonEmptyString(opts.model,
    "ai.adverseDecision.wrap: opts.model is required (model id + version for audit attribution)",
    AdverseDecisionError, "ai-adverse/bad-model");
  validateOpts.requireNonEmptyString(opts.legalBasis,
    "ai.adverseDecision.wrap: opts.legalBasis is required (e.g. 'ecoa-1002.9' / 'gdpr-22' / 'colorado-ai-act')",
    AdverseDecisionError, "ai-adverse/bad-legal-basis");
  if (typeof opts.decide !== "function") {
    throw new AdverseDecisionError("ai-adverse/bad-decide",
      "ai.adverseDecision.wrap: opts.decide must be a function (subject) -> { outcome, principalReasons }");
  }
  var name = opts.name;
  var model = opts.model;
  var legalBasis = opts.legalBasis;
  var decide = opts.decide;
  var onAdverse = typeof opts.onAdverse === "function" ? opts.onAdverse : null;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  var deadlines = REGIME_DEADLINES[legalBasis] || REGIME_DEADLINES["operator-defined"];

  var _emitAudit = audit().namespaced("ai.adverse_decision", opts.audit);
  var _emitMetric = observability().namespaced("ai.adverse_decision");

  return async function adverseDecisionDecorated(subject) {
    if (!subject || typeof subject !== "object") {
      throw new AdverseDecisionError("ai-adverse/bad-subject",
        "ai.adverseDecision: subject must be an object with at least { id }");
    }
    var subjectId = subject.id || null;
    var decidedAt = now();
    var decision;
    try {
      decision = await decide(subject);
    } catch (e) {
      _emitAudit("decide_failed", "failure", { name: name, subjectId: subjectId, error: (e && e.message) || String(e) });
      throw e;
    }
    if (!decision || typeof decision !== "object") {
      throw new AdverseDecisionError("ai-adverse/bad-decision-shape",
        "ai.adverseDecision: opts.decide must return an object with { outcome, principalReasons }");
    }
    var outcome = decision.outcome;
    var isAdverse = outcome === "adverse" || outcome === "denied" || outcome === "rejected";

    _emitAudit("decided", isAdverse ? "denied" : "success", {
      name: name, model: model, legalBasis: legalBasis,
      subjectId: subjectId, outcome: outcome,
      principalReasons: Array.isArray(decision.principalReasons) ? decision.principalReasons : [],
    });
    _emitMetric("decided", 1, { name: name, outcome: outcome });

    if (isAdverse) {
      decision.adverseNotice = {
        subjectId:        subjectId,
        decisionAt:       decidedAt,
        model:            model,
        legalBasis:       legalBasis,
        regulation:       deadlines.regulation,
        principalReasons: Array.isArray(decision.principalReasons) ? decision.principalReasons : [],
        consumerRights: {
          requestExplanation: deadlines.explanation !== null,
          requestHumanReview: deadlines.humanReview !== null,
          requestAppeal:      deadlines.appeal !== null,
          requestData:        true,
          statutoryDeadlines: {
            explanation: deadlines.explanation,
            humanReview: deadlines.humanReview,
            appeal:      deadlines.appeal,
          },
        },
      };
      if (onAdverse) {
        try { await onAdverse(subject, decision); }
        catch (e) { _emitAudit("on_adverse_threw", "failure", { error: (e && e.message) || String(e) }); }
      }
    }
    return decision;
  };
}

module.exports = {
  wrap:                  wrap,
  REGIME_DEADLINES:      REGIME_DEADLINES,
  AdverseDecisionError:  AdverseDecisionError,
  VALID_REGIMES:         Object.keys(REGIME_DEADLINES),
};
