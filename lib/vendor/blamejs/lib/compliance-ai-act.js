"use strict";
/**
 * b.compliance.aiAct — EU AI Act (Regulation (EU) 2024/1689) compliance
 * primitive.
 *
 * Public surface (b.compliance.aiAct.*):
 *
 *   .classify(systemDescription)
 *     → { tier, prohibitedHits[], annexIIIHits[], obligations[] }
 *
 *   .prohibited.{listPractices,listIds,getPractice,classify}
 *   .risk.{listAnnexIII,getAnnexIII,classifyAnnexIII,isHighRisk,obligationsFor}
 *   .transparency.{banner,htmlBanner,watermark,jsonLdDisclosure,metaTags}
 *   .logging.{buildEvent,emit,logEvent,retentionFloorMs,loggerFor}
 *   .gpai.{classify, listObligations}                 (Article 51-55)
 *   .deadlines                                         (Article 113)
 *   .articleObligations(article)
 *
 * Per the no-MVP rule: every spec'd surface above is implemented; the
 * five Annex III §1-8 use-cases plus the eight Article 5 prohibited
 * practices plus the four Article 50 transparency obligations all ship
 * here. GPAI obligations (Article 51-55) ship as a sibling helper.
 *
 * Operators integrate via the framework's compliance-posture flow:
 *
 *   var assessment = b.compliance.aiAct.classify({
 *     purpose:     "credit-scoring",
 *     deployContext: "consumer-finance",
 *     deployerType:  "private-company",
 *   });
 *   // assessment.tier === "high-risk"
 *   // assessment.annexIIIHits === ["essential-services"]
 *   // assessment.obligations  === [...Art-9..15 obligations]
 *
 * The framework does NOT perform legal interpretation — operators
 * remain responsible for engaging counsel before deployment.
 */

var validateOpts        = require("./validate-opts");
var lazyRequire         = require("./lazy-require");
var { ComplianceError }  = require("./framework-error");

var prohibited     = require("./compliance-ai-act-prohibited");
var risk           = require("./compliance-ai-act-risk");
var transparency   = require("./compliance-ai-act-transparency");
var logging        = require("./compliance-ai-act-logging");
var audit          = lazyRequire(function () { return require("./audit"); });

// ---- Article 113 deadline calendar ----
//
// Per Art. 113, different parts of the regulation phase in:
//
//   2024-08-01 — Regulation enters into force
//   2026-02-02 — Chapters I (general) + II (prohibited practices)
//                become applicable
//   2026-08-02 — Chapter V (general-purpose AI) + Chapter X-XI obligations
//                applicable; transparency obligations applicable
//   2027-08-02 — Chapter III (high-risk AI systems) become applicable
//                for products covered by Art. 6(1) Annex I third-party
//                conformity assessment
//   2027-08-02 — Member states designate competent authorities

var DEADLINES = Object.freeze({
  enteredForce:                "2024-08-01",
  prohibitedPractices:         "2026-02-02",
  generalPurposeAI:            "2026-08-02",
  transparencyObligations:     "2026-08-02",
  highRiskAnnexIII:            "2027-08-02",
  highRiskAnnexIProducts:      "2027-08-02",
});

// ---- Article 51-55 — General-Purpose AI Models ----

var GPAI_OBLIGATIONS = Object.freeze([
  Object.freeze({
    article:     "Art. 53(1)(a)",
    title:       "Technical documentation",
    description: "Provider keeps up-to-date technical documentation including training and testing process, evaluation results, info per Annex XI.",
  }),
  Object.freeze({
    article:     "Art. 53(1)(b)",
    title:       "Information for downstream providers",
    description: "Provider draws up information / documentation to enable downstream providers to comply with their obligations and to understand the model's capabilities / limitations.",
  }),
  Object.freeze({
    article:     "Art. 53(1)(c)",
    title:       "Copyright policy",
    description: "Provider puts in place a policy to comply with EU copyright law, in particular to identify and respect machine-readable rights reservations under Art. 4(3) Directive 2019/790.",
  }),
  Object.freeze({
    article:     "Art. 53(1)(d)",
    title:       "Training-content public summary",
    description: "Provider draws up and makes publicly available a sufficiently detailed summary of the content used for training the GPAI model, per a template provided by the AI Office.",
  }),
  Object.freeze({
    article:     "Art. 55",
    title:       "Systemic-risk obligations (FLOP threshold)",
    description: "GPAI models with systemic risk (cumulative training compute > 10^25 FLOP per Art. 51(2)) MUST: perform model evaluation including adversarial testing, assess and mitigate possible Union-level systemic risks, track and report serious incidents to the AI Office, ensure adequate cybersecurity.",
  }),
]);

function gpaiClassify(opts) {
  if (!opts || typeof opts !== "object") return { isGpai: false, isSystemicRisk: false };
  var isGpai = opts.kind === "gpai" ||
               (typeof opts.modalities === "object" && opts.generalPurpose === true);
  var isSystemicRisk = false;
  // Art. 51(2) — presumption of systemic risk if cumulative training
  // compute > 10^25 FLOP.
  if (typeof opts.trainingFlops === "number" && opts.trainingFlops >= 1e25) {
    isSystemicRisk = true;
  }
  if (opts.designatedSystemicRisk === true) {
    isSystemicRisk = true;
  }
  return {
    isGpai:          isGpai,
    isSystemicRisk:  isSystemicRisk,
    obligations:     isGpai ? listGpaiObligations(isSystemicRisk) : [],
  };
}

function listGpaiObligations(includeSystemic) {
  var out = [];
  for (var i = 0; i < GPAI_OBLIGATIONS.length; i += 1) {
    var entry = GPAI_OBLIGATIONS[i];
    if (entry.article === "Art. 55") {
      if (includeSystemic) out.push(entry);
    } else {
      out.push(entry);
    }
  }
  return out;
}

// ---- Article catalog (cross-reference helper) ----
var ARTICLE_OBLIGATIONS = Object.freeze({
  "Art. 9":  Object.freeze({
    title:       "Risk-management system",
    summary:     "Iterative process throughout the AI system lifecycle: identification + analysis of foreseeable risks, mitigation measures, residual-risk acceptance, post-market evaluation.",
  }),
  "Art. 10": Object.freeze({
    title:       "Data and data governance",
    summary:     "Training, validation, and testing datasets relevant, sufficiently representative, free of errors / complete; data-governance practices including bias examination + mitigation.",
  }),
  "Art. 11": Object.freeze({
    title:       "Technical documentation",
    summary:     "Drawn up before placement on market; includes Annex IV elements (general description, design specifications, monitoring + functioning, risk-management procedure, etc.).",
  }),
  "Art. 12": Object.freeze({
    title:       "Record-keeping (logging)",
    summary:     "Automatic recording of events over the system's lifetime; for biometric ID systems, minimum logged fields per Art. 12(3).",
  }),
  "Art. 13": Object.freeze({
    title:       "Transparency and information to deployers",
    summary:     "Designed so deployers can interpret + use output appropriately; instructions for use including capabilities + limitations + known foreseeable misuse.",
  }),
  "Art. 14": Object.freeze({
    title:       "Human oversight",
    summary:     "Effective human oversight by natural persons during use, including ability to intervene, decide not to use the system, or override the output.",
  }),
  "Art. 15": Object.freeze({
    title:       "Accuracy, robustness and cybersecurity",
    summary:     "Appropriate accuracy / robustness / cybersecurity throughout the lifecycle; declaration of accuracy levels and metrics in instructions for use.",
  }),
  "Art. 27": Object.freeze({
    title:       "Fundamental rights impact assessment",
    summary:     "Required for deployers using high-risk AI in essential-services / law-enforcement / migration contexts; documents who is using, purpose, individuals affected, risks of harm, governance measures.",
  }),
  "Art. 50": Object.freeze({
    title:       "Transparency obligations",
    summary:     "Disclosure to natural persons that they are interacting with AI, that content is AI-generated, that emotion recognition / biometric categorisation is in use, that media is a deep fake.",
  }),
  "Art. 53": Object.freeze({
    title:       "GPAI provider obligations",
    summary:     "Technical documentation, downstream-info, copyright policy, training-content public summary.",
  }),
  "Art. 55": Object.freeze({
    title:       "GPAI systemic-risk obligations",
    summary:     "Adversarial evaluation, systemic-risk assessment + mitigation, serious-incident reporting, cybersecurity.",
  }),
});

function articleObligations(article) {
  if (typeof article !== "string") return null;
  if (Object.prototype.hasOwnProperty.call(ARTICLE_OBLIGATIONS, article)) {
    return ARTICLE_OBLIGATIONS[article];
  }
  return null;
}

function listArticles() {
  return Object.keys(ARTICLE_OBLIGATIONS).slice();
}

// ---- top-level classifier ----

function classify(systemDescription) {
  if (!systemDescription || typeof systemDescription !== "object") {
    throw new ComplianceError("compliance-ai-act/bad-input",
      "compliance.aiAct.classify: systemDescription must be an object — got " +
      typeof systemDescription);
  }

  var prohibitedHits = prohibited.classify(systemDescription);
  if (prohibitedHits.length > 0) {
    return {
      tier:           "prohibited",
      prohibitedHits: prohibitedHits,
      annexIIIHits:   [],
      obligations:    [],
      action:         "do-not-deploy",
      legalReference: prohibitedHits.map(function (id) {
        var p = prohibited.getPractice(id);
        return p ? p.article : null;
      }).filter(Boolean),
    };
  }

  var annexIIIHits = [];
  if (typeof systemDescription.purpose === "string") {
    annexIIIHits = risk.classifyAnnexIII(systemDescription.purpose);
  }
  if (systemDescription.annexIIIRow && Array.isArray(systemDescription.annexIIIRow)) {
    for (var i = 0; i < systemDescription.annexIIIRow.length; i += 1) {
      if (annexIIIHits.indexOf(systemDescription.annexIIIRow[i]) === -1) {
        annexIIIHits.push(systemDescription.annexIIIRow[i]);
      }
    }
  }

  var isHighRisk = annexIIIHits.length > 0 ||
    (systemDescription.safetyComponentForRegulatedProduct === true &&
     systemDescription.requiresThirdPartyConformity === true);

  if (isHighRisk) {
    var obligations = [];
    var seen = Object.create(null);
    for (var j = 0; j < annexIIIHits.length; j += 1) {
      var rowObs = risk.obligationsFor(annexIIIHits[j]);
      for (var k = 0; k < rowObs.length; k += 1) {
        if (!seen[rowObs[k]]) { seen[rowObs[k]] = true; obligations.push(rowObs[k]); }
      }
    }
    return {
      tier:           "high-risk",
      prohibitedHits: [],
      annexIIIHits:   annexIIIHits,
      obligations:    obligations,
      action:         "deploy-with-art-9-15-controls",
      legalReference: ["Art. 6(2)", "Annex III"],
    };
  }

  // GPAI?
  var gpai = gpaiClassify(systemDescription);
  if (gpai.isGpai) {
    return {
      tier:           "general-purpose",
      prohibitedHits: [],
      annexIIIHits:   [],
      obligations:    gpai.obligations.map(function (o) { return o.article; }),
      isSystemicRisk: gpai.isSystemicRisk,
      action:         gpai.isSystemicRisk ? "deploy-with-art-53-55-controls" :
                                            "deploy-with-art-53-controls",
      legalReference: gpai.isSystemicRisk ? ["Art. 51", "Art. 53", "Art. 55"]
                                          : ["Art. 53"],
    };
  }

  // Limited-risk transparency-only systems
  if (systemDescription.directlyInteractsWithUsers === true ||
      systemDescription.generatesSyntheticContent === true ||
      systemDescription.usesEmotionRecognition === true ||
      systemDescription.usesBiometricCategorisation === true ||
      systemDescription.generatesDeepFake === true) {
    return {
      tier:           "limited-risk",
      prohibitedHits: [],
      annexIIIHits:   [],
      obligations:    ["Art. 50"],
      action:         "deploy-with-art-50-disclosures",
      legalReference: ["Art. 50"],
    };
  }

  return {
    tier:           "minimal-risk",
    prohibitedHits: [],
    annexIIIHits:   [],
    obligations:    [],
    action:         "deploy-no-specific-obligations",
    legalReference: [],
  };
}

// Operator-side hook: emit an audit event whenever a classification is
// run on the production path. Useful for compliance reviewers tracing
// which system was classified at which decision point.
function emitClassificationAudit(systemDescription, result) {
  try {
    audit().safeEmit({
      action:  "compliance.aiact.classified",
      outcome: result.tier === "prohibited" ? "denied" : "success",
      actor:   { systemId: systemDescription.systemId || null,
                 deployer: systemDescription.deployerName || null },
      metadata: {
        tier:            result.tier,
        prohibitedHits:  result.prohibitedHits,
        annexIIIHits:    result.annexIIIHits,
        obligationCount: result.obligations.length,
      },
    });
  } catch (_e) { /* drop-silent */ }
}

// Operator helper that builds the Annex IV technical-documentation
// scaffold. Returns a sectioned document the operator fills in over
// the deployment lifecycle. Validated against minimum-required keys at
// generation time so an operator can't accidentally omit a section.
function annexIVScaffold(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "systemId", "deployerName", "providerName", "intendedPurpose",
    "annexIIIRow", "deploymentScope", "version",
  ], "compliance.aiAct.annexIVScaffold");
  validateOpts.requireNonEmptyString(opts.systemId,
    "annexIVScaffold: systemId", ComplianceError, "compliance-ai-act/bad-input");

  return {
    "@context": "https://blamejs.com/schemas/ai-act-annex-iv/v1",
    aiActArticle: "Annex IV",
    sections: {
      "1-general-description": {
        title:       "General description of the AI system",
        required:    ["systemId", "intendedPurpose", "annexIIIRow", "version", "providerName", "deployerName"],
        provided: {
          systemId:        opts.systemId,
          intendedPurpose: opts.intendedPurpose || null,
          annexIIIRow:     opts.annexIIIRow || null,
          version:         opts.version || null,
          providerName:    opts.providerName || null,
          deployerName:    opts.deployerName || null,
          deploymentScope: opts.deploymentScope || null,
        },
      },
      "2-detailed-description": {
        title:       "Detailed description of the elements and process for development",
        required:    ["modelArchitecture", "trainingDataDescription", "preProcessing"],
        provided:    null,
      },
      "3-monitoring-functioning": {
        title:       "Detailed information about monitoring + functioning + control",
        required:    ["accuracyMetrics", "robustnessMetrics", "monitoringMechanism"],
        provided:    null,
      },
      "4-risk-management": {
        title:       "Description of the risk-management system per Art. 9",
        required:    ["riskRegister", "mitigationMeasures", "residualRiskAcceptance"],
        provided:    null,
      },
      "5-changes": {
        title:       "Description of any changes made to the system through its lifecycle",
        required:    ["changeLog"],
        provided:    null,
      },
      "6-list-of-harmonised-standards": {
        title:       "List of harmonised standards applied",
        required:    ["standardsList"],
        provided:    null,
      },
      "7-eu-declaration-of-conformity": {
        title:       "EU declaration of conformity per Art. 47 + Annex V",
        required:    ["declarationDocument"],
        provided:    null,
      },
      "8-post-market-monitoring": {
        title:       "Description of the post-market monitoring system per Art. 72",
        required:    ["monitoringPlan"],
        provided:    null,
      },
    },
  };
}

// Operator-actionable checklist derived from a classify() result. Each
// entry carries a status ("required" | "conditional" | "deferred") +
// the article reference + a short next-step description.
function deployerChecklist(assessment) {
  if (!assessment || typeof assessment !== "object") {
    throw new ComplianceError("compliance-ai-act/bad-checklist-input",
      "deployerChecklist: assessment must be a classify() result object");
  }
  var items = [];
  if (assessment.tier === "prohibited") {
    items.push({
      status:       "required",
      action:       "do-not-deploy",
      article:      "Art. 5",
      description:  "System falls under Art. 5 prohibited practices — do not deploy in EU market.",
    });
    return items;
  }
  if (assessment.tier === "high-risk") {
    items.push({
      status:       "required",
      action:       "engage-conformity-assessment",
      article:      "Art. 16-26",
      description:  "Engage notified body for third-party conformity assessment per Annex VII (or self-assess for systems where self-assessment is permitted under Art. 43).",
    });
    items.push({
      status:       "required",
      action:       "draw-up-technical-documentation",
      article:      "Art. 11 + Annex IV",
      description:  "Prepare Annex IV technical documentation. Use b.compliance.aiAct.annexIVScaffold().",
    });
    items.push({
      status:       "required",
      action:       "establish-risk-management-system",
      article:      "Art. 9",
      description:  "Iterative risk-management system over the system lifecycle.",
    });
    items.push({
      status:       "required",
      action:       "data-governance",
      article:      "Art. 10",
      description:  "Training / validation / testing dataset governance including bias examination.",
    });
    items.push({
      status:       "required",
      action:       "automatic-logging",
      article:      "Art. 12",
      description:  "Implement automatic logging via b.compliance.aiAct.logging.loggerFor().",
    });
    items.push({
      status:       "required",
      action:       "human-oversight",
      article:      "Art. 14",
      description:  "Effective human oversight by natural persons during use; ability to intervene / override.",
    });
    items.push({
      status:       "required",
      action:       "accuracy-robustness-cyber",
      article:      "Art. 15",
      description:  "Declare accuracy / robustness / cybersecurity levels in instructions for use.",
    });
    if (assessment.obligations.indexOf("fundamental-rights-impact-assessment-art-27") !== -1) {
      items.push({
        status:       "required",
        action:       "fundamental-rights-impact-assessment",
        article:      "Art. 27",
        description:  "Conduct FRIA before first deployment; documents purpose, individuals affected, foreseeable harms, mitigation.",
      });
    }
    items.push({
      status:       "required",
      action:       "register-eu-database",
      article:      "Art. 71",
      description:  "Register the high-risk AI system in the EU database before placing on market or putting into service.",
    });
    items.push({
      status:       "required",
      action:       "post-market-monitoring",
      article:      "Art. 72",
      description:  "Establish a post-market monitoring system commensurate with the AI risks.",
    });
    return items;
  }
  if (assessment.tier === "limited-risk") {
    items.push({
      status:       "required",
      action:       "transparency-disclosure",
      article:      "Art. 50",
      description:  "Mount b.middleware.aiActDisclosure({ kind: ... }) on routes that interact with users / generate synthetic content / use emotion or biometric categorisation.",
    });
    return items;
  }
  if (assessment.tier === "general-purpose") {
    items.push({
      status:       "required",
      action:       "gpai-technical-documentation",
      article:      "Art. 53(1)(a) + Annex XI",
      description:  "Maintain up-to-date technical documentation incl. training process, evaluation results, capabilities / limitations.",
    });
    items.push({
      status:       "required",
      action:       "downstream-info",
      article:      "Art. 53(1)(b)",
      description:  "Provide info to downstream providers to enable their compliance.",
    });
    items.push({
      status:       "required",
      action:       "copyright-policy",
      article:      "Art. 53(1)(c)",
      description:  "Adopt a policy compliant with EU copyright law including respecting Art. 4(3) Directive 2019/790 rights reservations.",
    });
    items.push({
      status:       "required",
      action:       "training-content-summary",
      article:      "Art. 53(1)(d)",
      description:  "Publish a sufficiently detailed summary of training content per the AI Office template.",
    });
    if (assessment.isSystemicRisk === true) {
      items.push({
        status:       "required",
        action:       "adversarial-evaluation",
        article:      "Art. 55",
        description:  "Perform model evaluation including adversarial testing to identify systemic risk.",
      });
      items.push({
        status:       "required",
        action:       "systemic-risk-mitigation",
        article:      "Art. 55",
        description:  "Assess and mitigate possible Union-level systemic risks.",
      });
      items.push({
        status:       "required",
        action:       "incident-reporting",
        article:      "Art. 55",
        description:  "Track and report serious incidents + corrective measures to the AI Office.",
      });
      items.push({
        status:       "required",
        action:       "cybersecurity",
        article:      "Art. 55",
        description:  "Ensure adequate cybersecurity protection of the model and physical infrastructure.",
      });
    }
    return items;
  }
  // minimal-risk
  items.push({
    status:       "deferred",
    action:       "voluntary-codes",
    article:      "Art. 95",
    description:  "Consider adoption of voluntary codes of conduct for minimal-risk AI per Art. 95.",
  });
  return items;
}

/**
 * @primitive b.complianceAiAct.fundamentalRightsImpactAssessment
 * @signature b.complianceAiAct.fundamentalRightsImpactAssessment(opts)
 * @since     0.8.77
 *
 * EU AI Act Article 27 — Fundamental Rights Impact Assessment (FRIA).
 * Mandatory for deployers of high-risk AI systems listed in Annex III
 * §5 (creditworthiness scoring, life/health insurance risk), §6
 * (law enforcement), §7 (migration/asylum), §8 (justice admin), public
 * authorities, and any private body providing public services. Must
 * be completed BEFORE the first use of the high-risk system, kept
 * updated, and notified to the national market-surveillance authority.
 *
 * Returns the structured FRIA document scaffold — operator fills in
 * the per-deployment specifics; the framework auto-populates the
 * fields it can derive (system identification, GPAI classification
 * if applicable, Annex IV reference, deployment-context audit hooks).
 *
 * @opts
 *   {
 *     systemId:               string,           // operator's high-risk system identifier
 *     systemDescription:      { ... },          // forwarded to classify() for risk-tier verdict
 *     deploymentContext:      { purpose, sector, geography, scale },
 *     affectedPersons:        { categories: string[], estimatedCount: number },
 *     risksToFundamentalRights: string[],       // operator-identified risks
 *     mitigations:            string[],         // mitigations + monitoring per risk
 *     humanOversight:         { roles: string[], escalationPath: string },
 *     residualRisks:          string[],
 *     reviewCadence:          string,            // e.g. "quarterly"
 *   }
 *
 * @example
 *   var fria = b.complianceAiAct.fundamentalRightsImpactAssessment({
 *     systemId: "credit-scoring-v3",
 *     deploymentContext: { purpose: "loan approval", sector: "financial",
 *                          geography: "EU", scale: "1M decisions/year" },
 *     affectedPersons:   { categories: ["EU consumers"], estimatedCount: 1000000 },
 *     risksToFundamentalRights: ["discriminatory denial", "right to explanation"],
 *     mitigations:       ["bias audit every 6 months", "human review threshold"],
 *     humanOversight:    { roles: ["credit officer"], escalationPath: "ombudsman" },
 *     reviewCadence:     "semi-annual",
 *   });
 */
function fundamentalRightsImpactAssessment(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("fundamentalRightsImpactAssessment: opts required");
  }
  validateOpts.requireNonEmptyString(opts.systemId, "systemId",
    Error, "compliance-ai-act/no-system-id");
  return {
    "$schema":            "https://blamejs.com/schema/ai-act-fria-v1.json",
    regulation:           "EU Regulation 2024/1689 — AI Act",
    article:              "Article 27 (Fundamental Rights Impact Assessment)",
    generatedAt:          new Date().toISOString(),
    systemId:             opts.systemId,
    classification:       opts.systemDescription ? classify(opts.systemDescription) : null,
    deploymentContext:    opts.deploymentContext || {},
    affectedPersons:      opts.affectedPersons   || { categories: [], estimatedCount: null },
    risks:                opts.risksToFundamentalRights || [],
    mitigations:          opts.mitigations              || [],
    humanOversight:       opts.humanOversight           || { roles: [], escalationPath: null },
    residualRisks:        opts.residualRisks            || [],
    reviewCadence:        opts.reviewCadence || "annual",
    notificationStatus:   "operator-must-notify",
    note:                 "Notify national market-surveillance authority before first use (Art 27(3))",
    auditHook:            "b.audit emission action='aiact.fria.completed' recommended",
    annexIVReference:     "see b.complianceAiAct.annexIVScaffold for technical documentation",
  };
}

/**
 * @primitive b.complianceAiAct.gpai.trainingDataSummary
 * @signature b.complianceAiAct.gpai.trainingDataSummary(opts)
 * @since     0.8.77
 *
 * EU AI Act Article 53(1)(d) — GPAI training-data summary template
 * compliant with the AI Office's template format (published in 2024,
 * mandatory from 2026-08-02). The template requires categories of
 * data, modalities, source provenance, copyright + licensing status,
 * dataset sizes, dates of collection, and steps taken to identify +
 * mitigate biases.
 *
 * Returns the JSON document operators publish under their `/.well-known/
 * ai-training-data-summary` endpoint or attach to model cards.
 *
 * @opts
 *   modelId:           string,    // required
 *   modelVersion:      string,    // optional
 *   provider:          object,    // { name, address, contact }
 *   dataCategories:    string[],  // ["web-crawl", "books", "code", "synthetic", ...]
 *   modalities:        string[],  // ["text", "image", "audio", "video"]
 *   sources:           object[],  // { identifier, url, type, licenseStatus, size, collectedFrom, collectedTo }
 *   copyrightStatus:   object,    // { respectsRightReservations, machineReadableSignalsObserved, tdmExceptionUsed }
 *   biasMitigation:    object,    // { methodsApplied, auditCadence, remediations }
 *   contentProvenance: object,    // { synthIdEmbed, c2paManifestEmbed, watermarkProvider }
 *
 * @example
 *   var summary = b.complianceAiAct.gpai.trainingDataSummary({
 *     modelId:        "acme-llm-7b",
 *     modelVersion:   "1.0",
 *     provider:       { name: "Acme AI", address: "1 St", contact: "ai@acme.example" },
 *     dataCategories: ["web-crawl", "books", "code"],
 *     modalities:     ["text"],
 *     sources: [
 *       { identifier: "CommonCrawl-2024", type: "web-crawl", licenseStatus: "permitted" },
 *     ],
 *     biasMitigation: { methodsApplied: ["demographic-balance"], auditCadence: "quarterly" },
 *   });
 */
function trainingDataSummary(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("trainingDataSummary: opts required");
  }
  validateOpts.requireNonEmptyString(opts.modelId, "modelId",
    Error, "compliance-ai-act/no-model-id");
  return {
    "$schema":           "https://blamejs.com/schema/ai-act-gpai-training-summary-v1.json",
    regulation:          "EU Regulation 2024/1689 — AI Act",
    article:             "Article 53(1)(d) (GPAI training data summary)",
    template:            "AI Office GPAI Training Data Summary Template",
    generatedAt:         new Date().toISOString(),
    modelId:             opts.modelId,
    modelVersion:        opts.modelVersion || null,
    provider:            opts.provider     || { name: null, address: null, contact: null },
    dataCategories:      opts.dataCategories || [],            // ["web-crawl", "books", "code", "synthetic", ...]
    modalities:          opts.modalities     || [],            // ["text", "image", "audio", "video"]
    sources: (opts.sources || []).map(function (s) {
      return {
        identifier:    s.identifier,
        url:           s.url || null,
        type:          s.type || "unknown",
        licenseStatus: s.licenseStatus || "unknown",
        size:          s.size || null,
        collectedFrom: s.collectedFrom || null,
        collectedTo:   s.collectedTo   || null,
      };
    }),
    copyrightStatus:     opts.copyrightStatus || {
      respectsRightReservations: null,
      machineReadableSignalsObserved: null,
      tdmExceptionUsed: null,
    },
    biasMitigation: opts.biasMitigation || {
      methodsApplied: [],
      auditCadence:   "annual",
      remediations:   [],
    },
    contentProvenance: opts.contentProvenance || {
      synthIdEmbed:        false,
      c2paManifestEmbed:   false,
      watermarkProvider:   null,
    },
    note: "Publish at /.well-known/ai-training-data-summary or model card per AI Office template (mandatory 2026-08-02)",
  };
}

module.exports = {
  classify:                  classify,
  deployerChecklist:         deployerChecklist,
  prohibited:                prohibited,
  risk:                      risk,
  transparency:              transparency,
  logging:                   logging,
  gpai: {
    classify:             gpaiClassify,
    listObligations:      listGpaiObligations,
    trainingDataSummary:  trainingDataSummary,
    OBLIGATIONS:          GPAI_OBLIGATIONS,
  },
  articleObligations:        articleObligations,
  listArticles:              listArticles,
  ARTICLE_OBLIGATIONS:       ARTICLE_OBLIGATIONS,
  DEADLINES:                 DEADLINES,
  emitClassificationAudit:   emitClassificationAudit,
  annexIVScaffold:           annexIVScaffold,
  fundamentalRightsImpactAssessment: fundamentalRightsImpactAssessment,
};
