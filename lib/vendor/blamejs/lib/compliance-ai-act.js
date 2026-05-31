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
var C                   = require("./constants");
var { ComplianceError }  = require("./framework-error");

var prohibited     = require("./compliance-ai-act-prohibited");
var risk           = require("./compliance-ai-act-risk");
var transparency   = require("./compliance-ai-act-transparency");
var logging        = require("./compliance-ai-act-logging");
var safeJson       = require("./safe-json");
var audit          = lazyRequire(function () { return require("./audit"); });
// modelManifest carries the CycloneDX 1.6 ML-BOM build/sign/verify
// envelope. lazyRequire'd to dodge the framework's documented
// circular-load chain (index.js → compliance-* → audit → db →
// framework-error → constants → package.json), the same reason
// ai-model-manifest reads package.json behind a call.
var modelManifest  = lazyRequire(function () { return require("./ai-model-manifest"); });

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
 * @primitive b.compliance.aiAct.fundamentalRightsImpactAssessment
 * @signature b.compliance.aiAct.fundamentalRightsImpactAssessment(opts)
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
 *   var fria = b.compliance.aiAct.fundamentalRightsImpactAssessment({
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
    annexIVReference:     "see b.compliance.aiAct.annexIVScaffold for technical documentation",
  };
}

/**
 * @primitive b.compliance.aiAct.gpai.trainingDataSummary
 * @signature b.compliance.aiAct.gpai.trainingDataSummary(opts)
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
 *   var summary = b.compliance.aiAct.gpai.trainingDataSummary({
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

// ---- ISO/IEC 42001:2023 + ISO/IEC 23894:2023 cross-walk ----
//
// Voluntary AI-management-system + AI-risk-management standards;
// audit conformance against EU AI Act Annex IV technical documentation
// overlaps ~70% with ISO 42001 Annex A controls. Operators chasing
// ISO certification while running under the AI Act use these tables
// to map each Annex IV / Article-9..15 requirement to the matching
// ISO control. Pure metadata — no behavior change at deploy time.

// AI Act → ISO/IEC 42001 Annex A control mapping. Each entry pairs
// an AI Act citation with the ISO control(s) that cover the same
// obligation.
var ISO_42001_CROSSWALK = Object.freeze([
  Object.freeze({ aiAct: "Art. 9 (Risk management system)",              iso42001: ["A.6.1.1 AI risk-management process", "A.6.1.2 AI risk assessment", "A.6.1.3 AI risk treatment"], iso23894: ["Clause 5 (Risk management process)", "Clause 6 (Risk assessment)"] }),
  Object.freeze({ aiAct: "Art. 10 (Data and data governance)",           iso42001: ["A.7.2 Data quality for AI systems", "A.7.3 Data provenance", "A.7.4 Data preparation"], iso23894: ["Clause 6.4.2 (Data-related risks)"] }),
  Object.freeze({ aiAct: "Art. 11 (Technical documentation)",            iso42001: ["A.4.5 AI system documentation", "A.6.2.5 AI system records"], iso23894: ["Clause 6.6 (Recording and reporting)"] }),
  Object.freeze({ aiAct: "Art. 12 (Record-keeping / logs)",              iso42001: ["A.6.2.5 AI system records", "A.9.4 Event logging"], iso23894: ["Clause 6.6 (Recording and reporting)"] }),
  Object.freeze({ aiAct: "Art. 13 (Transparency / instructions for use)", iso42001: ["A.4.5 AI system documentation", "A.8.2 User information"], iso23894: ["Clause 6.5.3 (Communication of risk)"] }),
  Object.freeze({ aiAct: "Art. 14 (Human oversight)",                     iso42001: ["A.4.2 AI system objectives", "A.6.2.6 Human oversight"], iso23894: ["Clause 6.4.6 (Human-AI interaction risks)"] }),
  Object.freeze({ aiAct: "Art. 15 (Accuracy, robustness, cybersecurity)", iso42001: ["A.6.2.3 AI verification + validation", "A.10.2 AI security controls"], iso23894: ["Clause 6.4.4 (Security risks)", "Clause 6.4.5 (Robustness risks)"] }),
  Object.freeze({ aiAct: "Art. 17 (Quality management system)",          iso42001: ["A.4 Leadership", "A.5 Planning", "A.6 Operation"], iso23894: ["Clause 4 (Context of the organization)"] }),
  Object.freeze({ aiAct: "Art. 18 (Logs retention 6 months min)",        iso42001: ["A.6.2.5 AI system records", "A.9.4 Event logging"], iso23894: ["Clause 6.6.3 (Records retention)"] }),
  Object.freeze({ aiAct: "Art. 23 (Conformity assessment)",              iso42001: ["A.6.2.4 AI conformity assessment"], iso23894: [] }),
  Object.freeze({ aiAct: "Art. 27 (Fundamental rights impact assessment)", iso42001: ["A.6.1.4 AI impact assessment", "A.10.3 Societal impact controls"], iso23894: ["Clause 6.4.7 (Ethical risks)", "Clause 6.4.8 (Fundamental rights risks)"] }),
  Object.freeze({ aiAct: "Art. 50 (Transparency obligations)",           iso42001: ["A.4.5 AI system documentation", "A.8.2 User information"], iso23894: ["Clause 6.5.3 (Risk communication)"] }),
  Object.freeze({ aiAct: "Art. 51-55 (GPAI obligations)",                iso42001: ["A.4.5 AI system documentation", "A.7.3 Data provenance", "A.10.3 Societal impact controls"], iso23894: ["Clause 6.4 (AI-specific risk categories)"] }),
  Object.freeze({ aiAct: "Art. 72 (Post-market monitoring)",             iso42001: ["A.9.2 Performance monitoring", "A.9.3 Improvement actions"], iso23894: ["Clause 7 (Monitoring and review)"] }),
  Object.freeze({ aiAct: "Art. 73 (Serious incident reporting)",          iso42001: ["A.9.4 Event logging", "A.10.4 Incident response"], iso23894: ["Clause 6.5.4 (Risk treatment plan — incidents)"] }),
]);

/**
 * @primitive b.compliance.aiAct.crossWalkIso42001
 * @signature b.compliance.aiAct.crossWalkIso42001(aiActCitation?)
 * @since     0.8.81
 * @status    stable
 * @related   b.compliance.aiAct.crossWalkIso23894, b.compliance.describe
 *
 * Map AI Act articles to ISO/IEC 42001:2023 Annex A controls (and the
 * matching ISO/IEC 23894:2023 risk-management clauses where they
 * overlap). Returns the full cross-walk table when called with no
 * arguments, or the entry for a specific AI Act citation when passed
 * a string. Returns `null` for unknown citations. Useful for
 * operators chasing ISO 42001 certification while running under the
 * AI Act — the table tracks the regulatory text and updates with
 * the framework rather than going stale in operator code.
 *
 * @example
 *   var rows = b.compliance.aiAct.crossWalkIso42001();
 *   rows[0].aiAct;        // → "Art. 9 (Risk management system)"
 *   rows[0].iso42001;     // → ["A.6.1.1 AI risk-management process", ...]
 *
 *   var art10 = b.compliance.aiAct.crossWalkIso42001("Art. 10 (Data and data governance)");
 *   art10.iso42001;       // → ["A.7.2 Data quality for AI systems", ...]
 *
 *   b.compliance.aiAct.crossWalkIso42001("not-a-real-citation");
 *   // → null
 */
function crossWalkIso42001(aiActCitation) {
  if (arguments.length === 0 || aiActCitation === undefined || aiActCitation === null) {
    return ISO_42001_CROSSWALK.map(function (r) {
      return { aiAct: r.aiAct, iso42001: r.iso42001.slice(), iso23894: r.iso23894.slice() };
    });
  }
  if (typeof aiActCitation !== "string") return null;
  for (var i = 0; i < ISO_42001_CROSSWALK.length; i += 1) {
    if (ISO_42001_CROSSWALK[i].aiAct === aiActCitation) {
      return {
        aiAct:    ISO_42001_CROSSWALK[i].aiAct,
        iso42001: ISO_42001_CROSSWALK[i].iso42001.slice(),
        iso23894: ISO_42001_CROSSWALK[i].iso23894.slice(),
      };
    }
  }
  return null;
}

/**
 * @primitive b.compliance.aiAct.crossWalkIso23894
 * @signature b.compliance.aiAct.crossWalkIso23894()
 * @since     0.8.81
 * @status    stable
 * @related   b.compliance.aiAct.crossWalkIso42001
 *
 * Same cross-walk shape filtered to entries that map to an ISO/IEC
 * 23894:2023 clause. Used by operators whose audit scope is the
 * AI-risk-management standard specifically (ISO 23894 is the
 * companion to ISO 42001 focused purely on risk).
 *
 * @example
 *   var rows = b.compliance.aiAct.crossWalkIso23894();
 *   rows.forEach(function (r) {
 *     console.log(r.aiAct, "→", r.iso23894);
 *   });
 */
function crossWalkIso23894() {
  return ISO_42001_CROSSWALK
    .filter(function (r) { return r.iso23894.length > 0; })
    .map(function (r) {
      return { aiAct: r.aiAct, iso42001: r.iso42001.slice(), iso23894: r.iso23894.slice() };
    });
}

// ---- GPAI Code-of-Practice adherence declaration (Art. 53/55) ----
//
// The General-Purpose AI Code of Practice (published 10 July 2025 by
// the AI Office) is the voluntary instrument by which a GPAI provider
// demonstrates compliance with Reg (EU) 2024/1689 Art. 53 (and Art. 55
// for systemic-risk models). Signing the Code is a public adherence
// declaration; this primitive emits a cryptographically-bound,
// tamper-evident version of that declaration so the obligation-set it
// covers cannot be silently downgraded and the per-commitment evidence
// cannot be replaced with a hollow claim.
//
// COP_VERSION_RE is shape-only — it pins the documented `YYYY-MM`
// release-label form of the Code (e.g. "2025-07") with a real month
// group; it is NOT a semantic validity check (the AI Office is the
// authority on which labels exist).
var COP_VERSION_RE = /^\d{4}-(0[1-9]|1[0-2])$/;                                                 // allow:regex-no-length-cap — fixed 7-char YYYY-MM Code-of-Practice release label, fully anchored
// SHA3-512 hex digest shape, matching b.crypto.sha3Hash output (64
// bytes → 128 lowercase-hex chars). An evidenceHash that does not match
// this shape is a hollow attestation — the compliance-theater shape
// this primitive exists to refuse.
var EVIDENCE_HASH_RE = /^[0-9a-f]{128}$/;                                                       // allow:regex-no-length-cap — fixed-length SHA3-512 hex (128 chars), fully anchored

// Default validity window for a phase-in adherence declaration. The
// Art. 53 obligations become applicable 2026-08-02 (DEADLINES
// .generalPurposeAI); a declaration that predates a material model
// change should not be relied on indefinitely. 90 days is the auditor-
// review default; operators override via opts.validityMs.
var DEFAULT_VALIDITY_MS = C.TIME.days(90);

var DECLARE_ALLOWED_KEYS = [
  "modelId", "modelVersion", "provider", "isSystemicRisk", "trainingFlops",
  "designatedSystemicRisk", "modalities", "copVersion", "commitments",
  "trainingDataSummary", "generatedAt", "validityMs", "privateKeyPem",
  "serialNumber", "audit",
];

// Derive the in-scope obligation set from the regulation, never from an
// operator-asserted list. declareAdherence is GPAI-specific, so kind is
// injected as "gpai" before gpaiClassify runs — otherwise a caller that
// omits kind/generalPurpose would classify as non-GPAI (isGpai:false →
// obligations:[]) and the scope-downgrade refusal below could never
// fire.
function _deriveGpaiObligations(opts) {
  var probe = {
    kind:                   "gpai",
    trainingFlops:          opts.trainingFlops,
    designatedSystemicRisk: opts.designatedSystemicRisk === true ||
                            opts.isSystemicRisk === true ? true : undefined,
  };
  var verdict = gpaiClassify(probe);
  return {
    isSystemicRisk: verdict.isSystemicRisk,
    obligations:    verdict.obligations,   // [{ article, title, description }, ...]
  };
}

/**
 * @primitive  b.compliance.aiAct.gpai.adherenceForm
 * @signature  b.compliance.aiAct.gpai.adherenceForm(opts)
 * @since      0.14.11
 * @status     stable
 * @compliance eu-ai-act-art-11
 * @related    b.compliance.aiAct.gpai.declareAdherence, b.ai.modelManifest.build
 *
 * Build the unsigned GPAI Code-of-Practice adherence document for a
 * general-purpose AI model. The obligation set is DERIVED from the
 * regulation via the GPAI classifier (Reg (EU) 2024/1689 Art. 53(1)(a-d)
 * always; Art. 55 when the model is a systemic-risk model under
 * Art. 51(2)), never taken from an operator-supplied list. Each
 * obligation is paired with the operator's commitment + evidence hash;
 * the evidence hash is validated against the SHA3-512 hex shape so a
 * hollow attestation (junk "hash") is refused at build time (CWE-345
 * insufficient verification of data authenticity).
 *
 * This is the document `declareAdherence` signs; most operators call
 * `declareAdherence` directly. The form is exposed for operators who
 * want to inspect or persist the derived obligation set before signing.
 *
 * @opts
 *   modelId:        string,     // required — provider's model identifier
 *   modelVersion:   string,     // required — model version
 *   provider:       object,     // { name, address, contact }
 *   trainingFlops:  number,     // cumulative training compute (Art. 51(2) presumption at >= 1e25)
 *   isSystemicRisk: boolean,    // operator-asserted systemic-risk designation (Art. 51(1)(b))
 *   designatedSystemicRisk: boolean,  // AI-Office-designated systemic risk
 *   copVersion:     string,     // GPAI Code of Practice release label, "YYYY-MM" (default "2025-07")
 *   commitments:    object[],   // [{ article, statement, evidenceHash }] — evidenceHash is SHA3-512 hex
 *   trainingDataSummary: object,// Art. 53(1)(d) public-summary pointer (b.compliance.aiAct.gpai.trainingDataSummary)
 *   generatedAt:    string,     // ISO 8601 UTC; defaults to now
 *   validityMs:     number,     // declaration validity window; default 90 days
 *
 * @example
 *   var hash = b.crypto.sha3Hash("eval-report-2026.pdf");
 *   var form = b.compliance.aiAct.gpai.adherenceForm({
 *     modelId:      "acme-llm-7b",
 *     modelVersion: "1.0",
 *     commitments:  [{ article: "Art. 53(1)(a)", statement: "Annex XI docs maintained", evidenceHash: hash }],
 *   });
 *   form.commitments.length;       // 4 — the four Art. 53 obligations (no systemic-risk chapter)
 *   form.commitments[0].evidenced; // true (Art. 53(1)(a) has a bound commitment)
 *   form.commitments[1].evidenced; // false (no commitment supplied yet)
 */
function adherenceForm(opts) {
  validateOpts.requireObject(opts, "compliance.aiAct.gpai.adherenceForm",
    ComplianceError, "compliance-ai-act/bad-input");
  validateOpts(opts, DECLARE_ALLOWED_KEYS, "compliance.aiAct.gpai.adherenceForm");
  validateOpts.requireNonEmptyString(opts.modelId, "adherenceForm: modelId",
    ComplianceError, "compliance-ai-act/no-model-id");
  validateOpts.requireNonEmptyString(opts.modelVersion, "adherenceForm: modelVersion",
    ComplianceError, "compliance-ai-act/no-model-version");

  var copVersion = opts.copVersion || "2025-07";
  if (typeof copVersion !== "string" || copVersion.length > 10 || !COP_VERSION_RE.test(copVersion)) {
    throw new ComplianceError("compliance-ai-act/cop-version-bad",
      "adherenceForm: copVersion must be a YYYY-MM Code-of-Practice release label — got " +
      JSON.stringify(copVersion));
  }

  var derived = _deriveGpaiObligations(opts);
  if (derived.obligations.length === 0) {
    // Defensive: kind is injected "gpai" so this is unreachable on the
    // happy path, but a future classifier change must not silently emit
    // an empty-obligation declaration that asserts nothing.
    throw new ComplianceError("compliance-ai-act/cop-no-obligations",
      "adherenceForm: derived GPAI obligation set is empty — refusing to sign a declaration that covers no Art. 53 obligation");
  }

  var requiredArticles = derived.obligations.map(function (o) { return o.article; });

  // Index operator commitments by article + validate each evidence hash.
  var byArticle = Object.create(null);
  var commitments = Array.isArray(opts.commitments) ? opts.commitments : [];
  for (var i = 0; i < commitments.length; i += 1) {
    var c = commitments[i];
    if (!c || typeof c !== "object" || typeof c.article !== "string") {
      throw new ComplianceError("compliance-ai-act/cop-commitment-shape",
        "adherenceForm: commitments[" + i + "] must be { article, statement, evidenceHash }");
    }
    if (typeof c.evidenceHash !== "string" || c.evidenceHash.length !== 128 || !EVIDENCE_HASH_RE.test(c.evidenceHash)) {
      throw new ComplianceError("compliance-ai-act/cop-evidence-bad-hash",
        "adherenceForm: commitments[" + i + "].evidenceHash must be a SHA3-512 hex digest " +
        "(128 lowercase-hex chars, b.crypto.sha3Hash output) — a 1-char junk hash is a hollow attestation");
    }
    byArticle[c.article] = {
      article:      c.article,
      statement:    typeof c.statement === "string" ? c.statement : null,
      evidenceHash: c.evidenceHash,
    };
  }

  // Build the per-obligation declaration. Every DERIVED obligation gets
  // an entry; if the operator supplied a matching commitment it binds,
  // otherwise the obligation is recorded as not-yet-evidenced (the
  // verify path surfaces it, the auditor decides).
  var declaredCommitments = derived.obligations.map(function (o) {
    var bound = byArticle[o.article];
    return {
      article:      o.article,
      title:        o.title,
      description:  o.description,
      statement:    bound ? bound.statement : null,
      evidenceHash: bound ? bound.evidenceHash : null,
      evidenced:    !!bound,
    };
  });

  var generatedAt = opts.generatedAt || new Date().toISOString();
  var validityMs = opts.validityMs === undefined ? DEFAULT_VALIDITY_MS
    : validateOpts.optionalPositiveFinite(opts.validityMs, "adherenceForm: validityMs",
        ComplianceError, "compliance-ai-act/bad-validity");

  return {
    "$schema":        "https://blamejs.com/schema/ai-act-gpai-cop-adherence-v1.json",
    regulation:       "EU Regulation 2024/1689 — AI Act",
    articles:         derived.isSystemicRisk ? ["Art. 53", "Art. 55"] : ["Art. 53"],
    instrument:       "GPAI Code of Practice (10 July 2025)",
    copVersion:       copVersion,
    modelId:          opts.modelId,
    modelVersion:     opts.modelVersion,
    provider:         opts.provider || { name: null, address: null, contact: null },
    isSystemicRisk:   derived.isSystemicRisk,
    requiredArticles: requiredArticles,
    commitments:      declaredCommitments,
    trainingDataSummary: opts.trainingDataSummary || null,
    // Art. 113 phase-in deadlines are bound INTO the signed payload so a
    // verifier can confirm the declaration was made against the correct
    // applicability calendar (not back-dated to a different regime).
    deadlines:        DEADLINES,
    generatedAt:      generatedAt,
    validityMs:       validityMs,
    note:             "Adherence to the GPAI Code of Practice per Reg (EU) 2024/1689 Art. 53" +
                      (derived.isSystemicRisk ? " + Art. 55 (systemic risk)." : "."),
  };
}

/**
 * @primitive  b.compliance.aiAct.gpai.declareAdherence
 * @signature  b.compliance.aiAct.gpai.declareAdherence(opts)
 * @since      0.14.11
 * @status     stable
 * @compliance eu-ai-act-art-11
 * @related    b.ai.modelManifest.sign, b.compliance.aiAct.gpai.adherenceForm
 *
 * Emit a SIGNED, tamper-evident GPAI Code-of-Practice adherence
 * declaration (Reg (EU) 2024/1689 Art. 53(1)(a-d); Art. 55 when the
 * model is a systemic-risk model under Art. 51(2)). The Code of
 * Practice (10 July 2025) is the AI Office's voluntary compliance
 * instrument; this primitive binds the adherence to the model + the
 * derived obligation set + the per-commitment evidence hashes inside a
 * CycloneDX 1.6 ML-BOM signed with ML-DSA-87 (FIPS 204) via
 * `b.ai.modelManifest.build` + `sign`. There is no unsigned return
 * path on the happy path: the declaration always ships inside the
 * signature envelope.
 *
 * Two compliance-theater shapes are refused structurally rather than
 * trusted:
 *
 *   - Obligation-set downgrade: the in-scope obligations are DERIVED
 *     from the classifier (kind injected as "gpai"), never accepted
 *     from the operator. A 10^25-FLOP+ model that omits the Art. 55
 *     systemic-risk chapter is refused — the classifier puts Art. 55
 *     in scope, the declaration must cover it.
 *   - Hollow attestation: every commitment's `evidenceHash` is checked
 *     against the SHA3-512 hex shape (128 hex chars, `b.crypto.sha3Hash`
 *     output). A junk "hash" cannot bind — CWE-345 (insufficient
 *     verification of data authenticity) / CWE-347 (improper
 *     verification of cryptographic signature).
 *
 * The signed envelope is verified with
 * `b.compliance.aiAct.gpai.verifyAdherence(envelope, publicKeyPem)`,
 * which re-canonicalizes before trusting any field (never trusts an
 * embedded signed-bytes value — the xml-crypto signature-substitution
 * class, CVE-2025-29774 / CVE-2025-29775) and rejects an expired
 * declaration (`generatedAt + validityMs < now`) so a stale adherence
 * cannot be replayed past its window.
 *
 * @opts
 *   modelId:        string,     // required
 *   modelVersion:   string,     // required
 *   provider:       object,     // { name, address, contact }
 *   trainingFlops:  number,     // cumulative training compute; Art. 51(2) presumption at >= 1e25 FLOP
 *   isSystemicRisk: boolean,    // operator-asserted systemic-risk designation (Art. 51(1)(b))
 *   designatedSystemicRisk: boolean,  // AI-Office-designated systemic risk
 *   copVersion:     string,     // Code of Practice release label "YYYY-MM" (default "2025-07")
 *   commitments:    object[],   // [{ article, statement, evidenceHash }]; evidenceHash is b.crypto.sha3Hash output
 *   trainingDataSummary: object,// Art. 53(1)(d) public-summary pointer (b.compliance.aiAct.gpai.trainingDataSummary)
 *   validityMs:     number,     // validity window; default 90 days
 *   privateKeyPem:  string,     // required — ML-DSA-87 signing key (b.crypto.generateSigningKeyPair)
 *   serialNumber:   string,     // urn:uuid:...; defaults to a fresh UUIDv4
 *   audit:          boolean,    // emit compliance.aiact.gpai.declareadherence audit event; default true
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var hash = b.crypto.sha3Hash("annex-xi-technical-documentation-v1");
 *   var env = b.compliance.aiAct.gpai.declareAdherence({
 *     modelId:       "acme-llm-7b",
 *     modelVersion:  "1.0",
 *     commitments:   [{ article: "Art. 53(1)(a)", statement: "Annex XI docs maintained", evidenceHash: hash }],
 *     privateKeyPem: pair.privateKey,
 *   });
 *   typeof env.signature;   // "string"
 */
function declareAdherence(opts) {
  validateOpts.requireObject(opts, "compliance.aiAct.gpai.declareAdherence",
    ComplianceError, "compliance-ai-act/bad-input");
  validateOpts(opts, DECLARE_ALLOWED_KEYS, "compliance.aiAct.gpai.declareAdherence");
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "declareAdherence: privateKeyPem", ComplianceError, "compliance-ai-act/no-signing-key");

  var form = adherenceForm(opts);

  // Scope-downgrade refusal: a SIGNED declaration must cover EVERY
  // derived obligation with bound evidence. The obligations are derived
  // from the classifier, not the operator, so a systemic-risk model
  // (>= 1e25 FLOP, Art. 51(2)) puts Art. 55 in scope — signing a
  // declaration that omits the Art. 55 chapter would be a silent scope
  // downgrade. adherenceForm() stays an inspection tool that surfaces
  // `evidenced: false`; the signing path refuses an unevidenced
  // obligation outright (CWE-345 insufficient verification).
  var unevidenced = form.commitments
    .filter(function (c) { return !c.evidenced; })
    .map(function (c) { return c.article; });
  if (unevidenced.length > 0) {
    throw new ComplianceError("compliance-ai-act/cop-obligation-unevidenced",
      "declareAdherence: cannot sign — required obligation(s) [" + unevidenced.join(", ") +
      "] have no bound commitment with a valid evidenceHash. A systemic-risk model must cover " +
      "the Art. 55 chapter; supply a commitment for every required article (" +
      form.requiredArticles.join(", ") + ").");
  }

  // Compose the AIBOM substrate: the adherence form rides as a
  // property-bag + Art. 53(1)(d) training-data summary on the model
  // component, signed as one canonical-JSON-1785 byte stream. We do NOT
  // hand-roll an envelope or call canonicalJson.stringify + crypto.sign
  // directly — modelManifest.build/sign already provide CycloneDX 1.6
  // conformance + the signature-substitution defense in verify.
  var bom = modelManifest().build({
    model: {
      name:    form.modelId,
      version: form.modelVersion,
      modelCard: {
        properties: [
          { name: "ai-act:gpai-cop-adherence", value: JSON.stringify(form) },
        ],
      },
    },
    serialNumber: opts.serialNumber,
    tool: { name: "@blamejs/core:compliance.aiAct.gpai.declareAdherence" },
  });

  var envelope = modelManifest().sign(bom, {
    privateKeyPem: opts.privateKeyPem,
    audit:         false,   // emit our own domain-specific event below
  });

  // Surface the adherence form alongside the signed envelope so callers
  // don't have to re-parse the BOM property to read what was declared.
  var out = {
    bom:           envelope.bom,
    signature:     envelope.signature,
    adherence:     form,
  };

  if (opts.audit !== false) {
    // Hot-path audit sink — drop-silent by design (rule 5). A throw
    // here would crash the caller that just produced a valid signed
    // declaration.
    try {
      audit().safeEmit({
        action:  "compliance.aiact.gpai.declareadherence",
        outcome: "success",
        metadata: {
          modelId:        form.modelId,
          modelVersion:   form.modelVersion,
          isSystemicRisk: form.isSystemicRisk,
          articles:       form.articles,
          serialNumber:   envelope.bom.serialNumber,
        },
      });
    } catch (_e) { /* drop-silent — by design */ }
  }

  return Object.freeze(out);
}

/**
 * @primitive  b.compliance.aiAct.gpai.verifyAdherence
 * @signature  b.compliance.aiAct.gpai.verifyAdherence(envelope, publicKeyPem, opts?)
 * @since      0.14.11
 * @status     stable
 * @compliance eu-ai-act-art-11
 * @related    b.compliance.aiAct.gpai.declareAdherence, b.ai.modelManifest.verify
 *
 * Verify a signed GPAI Code-of-Practice adherence declaration produced
 * by `declareAdherence`. Delegates the cryptographic check to
 * `b.ai.modelManifest.verify`, which re-canonicalizes the BOM with
 * canonical-JSON-1785 before trusting any field and NEVER trusts an
 * embedded signed-bytes value (the xml-crypto signature-substitution
 * class, CVE-2025-29774 / CVE-2025-29775). On a valid signature it
 * additionally enforces the validity window: a declaration whose
 * `generatedAt + validityMs` is in the past is rejected with
 * `reason: "expired"` so a stale adherence cannot be replayed past its
 * auditor-review window. Returns `{ valid, adherence, reason }`; never
 * throws (the documented contract mirrors b.ai.modelManifest.verify).
 *
 * @opts
 *   now:    number,     // override the comparison clock (ms epoch); default Date.now()
 *   audit:  boolean,    // emit compliance.aiact.gpai.verifyadherence audit event; default true
 *
 * @example
 *   var result = b.compliance.aiAct.gpai.verifyAdherence(env, pair.publicKey);
 *   if (result.valid) result.adherence.requiredArticles;   // ["Art. 53(1)(a)", ...]
 *   else              result.reason;                        // "signature-invalid" | "expired" | ...
 */
function verifyAdherence(envelope, publicKeyPem, opts) {
  opts = opts || {};
  var inner = modelManifest().verify(envelope, publicKeyPem, { audit: false });
  if (!inner.valid) {
    return { valid: false, adherence: null, reason: inner.reason };
  }

  // Re-read the adherence form from the (now signature-verified) BOM
  // property — never from a top-level field a caller could swap.
  var adherence = _extractAdherenceFromBom(inner.bom);
  if (!adherence) {
    return { valid: false, adherence: null, reason: "adherence-property-missing" };
  }

  // Anti-replay: reject an expired declaration.
  if (typeof adherence.generatedAt === "string" &&
      typeof adherence.validityMs === "number" && isFinite(adherence.validityMs)) {
    var issuedMs = Date.parse(adherence.generatedAt);
    if (isFinite(issuedMs)) {
      var now = typeof opts.now === "number" && isFinite(opts.now) ? opts.now : Date.now();
      if (issuedMs + adherence.validityMs < now) {
        return { valid: false, adherence: null, reason: "expired" };
      }
    }
  }

  if (opts.audit !== false) {
    try {
      audit().safeEmit({
        action:  "compliance.aiact.gpai.verifyadherence",
        outcome: "success",
        metadata: {
          modelId:        adherence.modelId,
          modelVersion:   adherence.modelVersion,
          isSystemicRisk: adherence.isSystemicRisk,
          serialNumber:   inner.bom && inner.bom.serialNumber,
        },
      });
    } catch (_e) { /* drop-silent — by design */ }
  }

  return { valid: true, adherence: adherence, reason: null };
}

// Pull the adherence form out of the signed BOM's model-card property
// bag. Returns null on any shape mismatch — the caller maps that to a
// structured verify reason rather than throwing.
function _extractAdherenceFromBom(bom) {
  try {
    var card = bom && bom.metadata && bom.metadata.component && bom.metadata.component.modelCard;
    var props = card && card.properties;
    if (!Array.isArray(props)) return null;
    for (var i = 0; i < props.length; i += 1) {
      if (props[i] && props[i].name === "ai-act:gpai-cop-adherence") {
        return safeJson.parse(props[i].value, { maxBytes: C.BYTES.mib(1) });
      }
    }
  } catch (_e) { return null; }
  return null;
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
    adherenceForm:        adherenceForm,
    declareAdherence:     declareAdherence,
    verifyAdherence:      verifyAdherence,
    OBLIGATIONS:          GPAI_OBLIGATIONS,
  },
  articleObligations:        articleObligations,
  listArticles:              listArticles,
  ARTICLE_OBLIGATIONS:       ARTICLE_OBLIGATIONS,
  DEADLINES:                 DEADLINES,
  emitClassificationAudit:   emitClassificationAudit,
  annexIVScaffold:           annexIVScaffold,
  fundamentalRightsImpactAssessment: fundamentalRightsImpactAssessment,
  crossWalkIso42001:         crossWalkIso42001,
  crossWalkIso23894:         crossWalkIso23894,
  ISO_42001_CROSSWALK:       ISO_42001_CROSSWALK,
};
