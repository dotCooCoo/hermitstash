"use strict";
/**
 * EU AI Act Article 5 — prohibited AI practices.
 *
 * Per Regulation (EU) 2024/1689 Art. 5, certain AI practices are
 * unconditionally prohibited in the EU market. The practices fall
 * into eight categories listed below; each entry carries:
 *
 *   - id          — short canonical identifier (used by classify())
 *   - article     — the sub-article of Art. 5 (a-h)
 *   - title       — operator-readable title
 *   - description — paraphrase of the prohibited practice
 *   - examples    — non-exhaustive list of system shapes that fall in
 *
 * The catalog is operator-readable but NOT operator-extensible — Art. 5
 * is set by EU regulation; operators don't add private "prohibited
 * practices". For private "we don't allow this" rules see
 * b.compliance.aiAct.local-policy (separate primitive).
 *
 * Effective date: 2026-02-02 per Art. 113(a). Operators with EU users
 * MUST classify each AI system against this catalog before deployment.
 */

var PROHIBITED_PRACTICES = Object.freeze([
  Object.freeze({
    id:          "subliminal-manipulation",
    article:     "Art. 5(1)(a)",
    title:       "Subliminal techniques beyond a person's consciousness",
    description: "AI systems that deploy subliminal, purposefully manipulative, or deceptive techniques with the objective or effect of materially distorting a person's behaviour by appreciably impairing their ability to make an informed decision, thereby causing or likely to cause significant harm.",
    examples:    Object.freeze([
      "Hidden audio cues in marketing audio that bypass conscious perception",
      "UX patterns engineered with eye-tracking to push specific decisions",
      "Generative content that subliminally embeds product imagery",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "exploit-vulnerabilities",
    article:     "Art. 5(1)(b)",
    title:       "Exploiting vulnerabilities of specific groups",
    description: "AI systems that exploit vulnerabilities of a specific group of persons (due to age, disability, or specific social or economic situation) with the objective or effect of materially distorting their behaviour, thereby causing or likely to cause significant harm.",
    examples:    Object.freeze([
      "Recommender systems targeting children with addictive content patterns",
      "Predatory lending offers tuned to financial-distress signals",
      "Manipulative chatbots aimed at elderly users with dementia signals",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "social-scoring",
    article:     "Art. 5(1)(c)",
    title:       "Social scoring by public authorities",
    description: "AI systems for the evaluation or classification of natural persons over a certain period of time based on their social behaviour or known, inferred or predicted personal or personality characteristics, leading to detrimental or unfavourable treatment that is unjustified or disproportionate.",
    examples:    Object.freeze([
      "General-purpose social-credit ranking by a state agency",
      "Cross-context behavior scoring used to deny unrelated services",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "predictive-policing-individual",
    article:     "Art. 5(1)(d)",
    title:       "Predictive policing solely on profiling",
    description: "AI systems for making risk assessments of natural persons in order to assess or predict the risk of a natural person committing a criminal offence, based solely on the profiling of a natural person or on assessing their personality traits and characteristics.",
    examples:    Object.freeze([
      "Recidivism scoring using only demographic + arrest-history features",
      "Heatmap-driven 'pre-crime' targeting of named individuals",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "untargeted-facial-scraping",
    article:     "Art. 5(1)(e)",
    title:       "Untargeted scraping for facial-recognition databases",
    description: "AI systems that create or expand facial-recognition databases through the untargeted scraping of facial images from the internet or CCTV footage.",
    examples:    Object.freeze([
      "Bulk-collecting public profile photos to populate a face-search index",
      "CCTV-derived enrolment of unconsenting bystanders",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "emotion-inference-workplace-edu",
    article:     "Art. 5(1)(f)",
    title:       "Emotion inference in workplace and education",
    description: "AI systems to infer emotions of a natural person in the areas of workplace and education institutions, except where the use of the AI system is intended to be put in place or into the market for medical or safety reasons.",
    examples:    Object.freeze([
      "Camera-based 'engagement' scoring of students during remote class",
      "Sentiment analysis of employee video calls for performance review",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "biometric-categorisation-sensitive",
    article:     "Art. 5(1)(g)",
    title:       "Biometric categorisation by sensitive attributes",
    description: "AI systems of biometric categorisation that categorise individually natural persons based on their biometric data to deduce or infer their race, political opinions, trade union membership, religious or philosophical beliefs, sex life or sexual orientation.",
    examples:    Object.freeze([
      "Face-derived political-opinion or religion classifiers",
      "Voice-derived sexual-orientation inference",
    ]),
    effectiveDate: "2026-02-02",
  }),
  Object.freeze({
    id:          "real-time-remote-biometric-id",
    article:     "Art. 5(1)(h)",
    title:       "Real-time remote biometric identification in public",
    description: "AI systems for real-time remote biometric identification in publicly accessible spaces for law-enforcement purposes — except for narrowly-defined exceptions (search for missing persons, prevention of imminent threat, suspect of serious crime listed in Annex II).",
    examples:    Object.freeze([
      "Mass facial-recognition gates at festivals or stations",
      "Real-time crowd-scanning ID systems without imminent-threat trigger",
    ]),
    effectiveDate: "2026-02-02",
  }),
]);

function listPractices() {
  return PROHIBITED_PRACTICES.slice();
}

function getPractice(id) {
  for (var i = 0; i < PROHIBITED_PRACTICES.length; i += 1) {
    if (PROHIBITED_PRACTICES[i].id === id) return PROHIBITED_PRACTICES[i];
  }
  return null;
}

function listIds() {
  return PROHIBITED_PRACTICES.map(function (p) { return p.id; });
}

// Classify a system description against the catalog. Returns the array
// of practice IDs it appears to fall under, based on operator-supplied
// signals. The classifier is intentionally conservative — it errs on
// the side of flagging a system as potentially-prohibited; legal
// review is required before deployment regardless of the result.

function classify(systemDescription) {
  if (!systemDescription || typeof systemDescription !== "object") {
    return [];
  }
  var hits = [];
  // (a) subliminal manipulation
  if (systemDescription.usesSubliminalCues === true ||
      systemDescription.intent === "subliminal-influence") {
    hits.push("subliminal-manipulation");
  }
  // (b) exploit vulnerabilities
  if (systemDescription.targetsVulnerableGroup === true) {
    hits.push("exploit-vulnerabilities");
  }
  // (c) social scoring
  if (systemDescription.purpose === "social-scoring" &&
      systemDescription.deployerType === "public-authority") {
    hits.push("social-scoring");
  }
  // (d) predictive policing on profiling alone
  if (systemDescription.purpose === "predictive-policing" &&
      systemDescription.usesProfileOnly === true) {
    hits.push("predictive-policing-individual");
  }
  // (e) untargeted facial-recognition database build
  if (systemDescription.builds === "facial-recognition-db" &&
      systemDescription.scrapesUntargeted === true) {
    hits.push("untargeted-facial-scraping");
  }
  // (f) emotion inference in workplace / education
  if (systemDescription.infersEmotion === true &&
      (systemDescription.deployContext === "workplace" ||
       systemDescription.deployContext === "education")) {
    if (systemDescription.purpose !== "medical" &&
        systemDescription.purpose !== "safety") {
      hits.push("emotion-inference-workplace-edu");
    }
  }
  // (g) biometric categorisation of sensitive attributes
  if (systemDescription.biometricCategorisation === true &&
      Array.isArray(systemDescription.inferredAttributes)) {
    var sensitive = ["race", "political-opinion", "trade-union",
                     "religion", "philosophy", "sex-life", "sexual-orientation"];
    for (var i = 0; i < systemDescription.inferredAttributes.length; i += 1) {
      if (sensitive.indexOf(systemDescription.inferredAttributes[i]) !== -1) {
        hits.push("biometric-categorisation-sensitive");
        break;
      }
    }
  }
  // (h) real-time remote biometric ID for law enforcement
  if (systemDescription.remoteBiometricId === "real-time" &&
      systemDescription.deployContext === "law-enforcement-public-space" &&
      systemDescription.exemption !== "missing-person" &&
      systemDescription.exemption !== "imminent-threat" &&
      systemDescription.exemption !== "annex-ii-suspect") {
    hits.push("real-time-remote-biometric-id");
  }
  return hits;
}

module.exports = {
  PROHIBITED_PRACTICES: PROHIBITED_PRACTICES,
  listPractices:        listPractices,
  listIds:              listIds,
  getPractice:          getPractice,
  classify:             classify,
};
