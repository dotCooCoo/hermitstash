"use strict";
/**
 * EU AI Act Article 6 + Annex III — high-risk AI system classification.
 *
 * Per Regulation (EU) 2024/1689 Art. 6, an AI system is "high-risk"
 * when:
 *
 *   (a) it is intended to be used as a safety component of a product
 *       covered by the Union harmonisation legislation listed in Annex I,
 *       OR the AI system is itself such a product, AND the product is
 *       required to undergo third-party conformity assessment; OR
 *
 *   (b) it falls into one of the eight Annex III use-case categories.
 *
 * The classifier returns the tier and the matched Annex-III row(s) so
 * operators can produce the Annex IV technical documentation required
 * by Art. 11 + 18.
 *
 * Tiers:
 *   "prohibited"      → falls under Article 5
 *   "high-risk"       → falls under Article 6 / Annex III
 *   "limited-risk"    → falls under Article 50 (transparency obligations only)
 *   "minimal-risk"    → no specific obligations beyond general principles
 *   "general-purpose" → general-purpose AI model (GPAI) — Article 53
 */

var ANNEX_III_USE_CASES = Object.freeze([
  Object.freeze({
    id:          "biometric-id-categorisation",
    annexRow:    "Annex III §1",
    title:       "Biometric identification and categorisation",
    description: "Remote biometric identification systems (excluding the prohibited real-time-public ones), biometric categorisation systems, emotion-recognition systems.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
  Object.freeze({
    id:          "critical-infrastructure",
    annexRow:    "Annex III §2",
    title:       "Critical infrastructure",
    description: "AI systems intended to be used as safety components in the management and operation of critical digital infrastructure, road traffic, or in the supply of water, gas, heating or electricity.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
  Object.freeze({
    id:          "education-vocational",
    annexRow:    "Annex III §3",
    title:       "Education and vocational training",
    description: "AI systems for determining access, admission or assignment to educational and vocational training institutions; for evaluating learning outcomes; for assessing the appropriate level of education; for monitoring and detecting prohibited behaviour during tests.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
  Object.freeze({
    id:          "employment-workers-mgmt",
    annexRow:    "Annex III §4",
    title:       "Employment, workers management, and access to self-employment",
    description: "AI systems for recruitment / selection, advertising vacancies, screening or filtering applications, evaluating candidates; for promotion / termination decisions, task allocation based on individual behaviour or personal traits, for monitoring and evaluating performance and behaviour.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
  Object.freeze({
    id:          "essential-services",
    annexRow:    "Annex III §5",
    title:       "Access to essential private and public services",
    description: "AI systems used by public authorities to evaluate eligibility for essential public assistance benefits and services; for credit-worthiness scoring of natural persons; for risk assessment and pricing of life and health insurance; for emergency-response triage.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
  Object.freeze({
    id:          "law-enforcement",
    annexRow:    "Annex III §6",
    title:       "Law enforcement",
    description: "AI systems used by law enforcement authorities for risk assessment of natural persons (excluding the prohibited profiling-only ones), polygraphs / similar tools, evaluating reliability of evidence, profiling for detection / investigation of criminal offences.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15", "fundamental-rights-impact-assessment-art-27"]),
  }),
  Object.freeze({
    id:          "migration-asylum-border",
    annexRow:    "Annex III §7",
    title:       "Migration, asylum and border control management",
    description: "AI systems used by competent public authorities for assessing risks (security, irregular migration, health) posed by a natural person intending to enter / having entered the EU; for examining applications for asylum / visa / residence permits; for detecting / recognising / identifying natural persons in the context of migration.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15", "fundamental-rights-impact-assessment-art-27"]),
  }),
  Object.freeze({
    id:          "judicial-democratic-process",
    annexRow:    "Annex III §8",
    title:       "Administration of justice and democratic processes",
    description: "AI systems intended to assist judicial authorities in researching / interpreting facts and the law and applying the law; AI systems used to influence the outcome of an election or referendum or voting behaviour.",
    obligations: Object.freeze(["risk-management-art-9", "data-governance-art-10",
                                "technical-documentation-art-11", "logging-art-12",
                                "transparency-art-13", "human-oversight-art-14",
                                "accuracy-robustness-art-15"]),
  }),
]);

function listAnnexIII() {
  return ANNEX_III_USE_CASES.slice();
}

function getAnnexIII(id) {
  for (var i = 0; i < ANNEX_III_USE_CASES.length; i += 1) {
    if (ANNEX_III_USE_CASES[i].id === id) return ANNEX_III_USE_CASES[i];
  }
  return null;
}

// Operator-side helper to determine the matching Annex III row from a
// purpose vocabulary the framework recognises.
function classifyAnnexIII(purpose) {
  if (typeof purpose !== "string") return [];
  var hits = [];
  // Per-row heuristics — operators with a private vocabulary use
  // .isHighRisk and pass annexId directly.
  if (purpose === "biometric-id" || purpose === "biometric-category" ||
      purpose === "emotion-recognition") {
    hits.push("biometric-id-categorisation");
  }
  if (purpose === "critical-infrastructure-control" ||
      purpose === "traffic-control" || purpose === "energy-grid") {
    hits.push("critical-infrastructure");
  }
  if (purpose === "school-admissions" || purpose === "exam-grading" ||
      purpose === "exam-proctoring") {
    hits.push("education-vocational");
  }
  if (purpose === "candidate-screening" || purpose === "performance-evaluation" ||
      purpose === "promotion-decision" || purpose === "termination-decision") {
    hits.push("employment-workers-mgmt");
  }
  if (purpose === "credit-scoring" || purpose === "insurance-pricing" ||
      purpose === "benefits-eligibility" || purpose === "emergency-triage") {
    hits.push("essential-services");
  }
  if (purpose === "evidence-evaluation" || purpose === "law-enforcement-risk-assessment" ||
      purpose === "polygraph") {
    hits.push("law-enforcement");
  }
  if (purpose === "asylum-application-screening" || purpose === "visa-screening" ||
      purpose === "border-biometric-id") {
    hits.push("migration-asylum-border");
  }
  if (purpose === "judicial-research-assistant" || purpose === "election-influence") {
    hits.push("judicial-democratic-process");
  }
  return hits;
}

function isHighRisk(opts) {
  if (!opts || typeof opts !== "object") return false;
  if (opts.tier === "high-risk") return true;
  if (opts.purpose) {
    var matches = classifyAnnexIII(opts.purpose);
    if (matches.length > 0) return true;
  }
  if (opts.safetyComponentForRegulatedProduct === true &&
      opts.requiresThirdPartyConformity === true) {
    return true;
  }
  return false;
}

function obligationsFor(annexId) {
  var row = getAnnexIII(annexId);
  if (!row) return [];
  return row.obligations.slice();
}

module.exports = {
  ANNEX_III_USE_CASES: ANNEX_III_USE_CASES,
  listAnnexIII:        listAnnexIII,
  getAnnexIII:         getAnnexIII,
  classifyAnnexIII:    classifyAnnexIII,
  isHighRisk:          isHighRisk,
  obligationsFor:      obligationsFor,
};
