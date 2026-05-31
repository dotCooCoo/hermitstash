"use strict";
/**
 * b.compliance.aiAct — EU AI Act compliance primitive.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function run() {
  var aiAct = b.compliance.aiAct;

  // ---- module shape ----
  check("aiAct is object",                          typeof aiAct === "object");
  check("aiAct.classify is fn",                     typeof aiAct.classify === "function");
  check("aiAct.prohibited is object",               typeof aiAct.prohibited === "object");
  check("aiAct.risk is object",                     typeof aiAct.risk === "object");
  check("aiAct.transparency is object",             typeof aiAct.transparency === "object");
  check("aiAct.logging is object",                  typeof aiAct.logging === "object");
  check("aiAct.gpai is object",                     typeof aiAct.gpai === "object");
  check("aiAct.DEADLINES exists",                   typeof aiAct.DEADLINES === "object");
  check("aiAct.DEADLINES.prohibitedPractices",      aiAct.DEADLINES.prohibitedPractices === "2026-02-02");
  check("aiAct.DEADLINES.transparencyObligations",  aiAct.DEADLINES.transparencyObligations === "2026-08-02");

  // ---- prohibited practices catalog ----
  var practices = aiAct.prohibited.listPractices();
  check("prohibited: 8 practices",                  practices.length === 8);
  var ids = aiAct.prohibited.listIds();
  check("prohibited: ids include subliminal",       ids.indexOf("subliminal-manipulation") !== -1);
  check("prohibited: ids include social-scoring",   ids.indexOf("social-scoring") !== -1);
  check("prohibited: ids include real-time-rbi",    ids.indexOf("real-time-remote-biometric-id") !== -1);

  var subliminal = aiAct.prohibited.getPractice("subliminal-manipulation");
  check("prohibited: getPractice returns entry",    subliminal !== null && subliminal.article === "Art. 5(1)(a)");
  check("prohibited: getPractice unknown returns null", aiAct.prohibited.getPractice("nope") === null);

  // Catalog is frozen; can't mutate
  var first = practices[0];
  var threw = false;
  try { first.id = "tampered"; } catch (_e) { threw = true; }
  check("prohibited: practice frozen (mutation throws or noop)",
        threw || first.id === aiAct.prohibited.listIds()[0]);

  // ---- prohibited classifier ----
  var hits1 = aiAct.prohibited.classify({
    purpose: "social-scoring", deployerType: "public-authority",
  });
  check("prohibited.classify: social-scoring caught",  hits1.indexOf("social-scoring") !== -1);

  var hits2 = aiAct.prohibited.classify({
    builds: "facial-recognition-db", scrapesUntargeted: true,
  });
  check("prohibited.classify: facial scraping",        hits2.indexOf("untargeted-facial-scraping") !== -1);

  var hits3 = aiAct.prohibited.classify({
    biometricCategorisation: true,
    inferredAttributes: ["religion", "age"],
  });
  check("prohibited.classify: religion attr caught",   hits3.indexOf("biometric-categorisation-sensitive") !== -1);

  var hits4 = aiAct.prohibited.classify({
    infersEmotion: true, deployContext: "workplace",
  });
  check("prohibited.classify: workplace emotion",      hits4.indexOf("emotion-inference-workplace-edu") !== -1);

  // Medical exemption removes the workplace-emotion hit
  var hits5 = aiAct.prohibited.classify({
    infersEmotion: true, deployContext: "workplace", purpose: "medical",
  });
  check("prohibited.classify: medical exempts emotion", hits5.indexOf("emotion-inference-workplace-edu") === -1);

  // No hits
  var hits6 = aiAct.prohibited.classify({ purpose: "search-ranking" });
  check("prohibited.classify: nothing matches",         hits6.length === 0);

  check("prohibited.classify: null safe",               aiAct.prohibited.classify(null).length === 0);

  // ---- Annex III risk classifier ----
  var anx = aiAct.risk.listAnnexIII();
  check("risk: 8 Annex-III rows",                      anx.length === 8);
  check("risk: row has obligations",                   Array.isArray(anx[0].obligations) && anx[0].obligations.length > 0);

  var ann1 = aiAct.risk.classifyAnnexIII("credit-scoring");
  check("risk: credit-scoring → essential-services",   ann1.indexOf("essential-services") !== -1);

  var ann2 = aiAct.risk.classifyAnnexIII("candidate-screening");
  check("risk: hiring → employment-workers-mgmt",       ann2.indexOf("employment-workers-mgmt") !== -1);

  var ann3 = aiAct.risk.classifyAnnexIII("school-admissions");
  check("risk: school admissions → education",         ann3.indexOf("education-vocational") !== -1);

  var ann4 = aiAct.risk.classifyAnnexIII("law-enforcement-risk-assessment");
  check("risk: law enforcement",                       ann4.indexOf("law-enforcement") !== -1);

  check("risk.classifyAnnexIII: unknown empty",         aiAct.risk.classifyAnnexIII("not-a-purpose").length === 0);

  check("risk.isHighRisk: credit-scoring true",         aiAct.risk.isHighRisk({ purpose: "credit-scoring" }) === true);
  check("risk.isHighRisk: by tier",                     aiAct.risk.isHighRisk({ tier: "high-risk" }) === true);
  check("risk.isHighRisk: minimal false",               aiAct.risk.isHighRisk({ purpose: "search" }) === false);
  check("risk.isHighRisk: safety-component + 3p",       aiAct.risk.isHighRisk({
    safetyComponentForRegulatedProduct: true, requiresThirdPartyConformity: true,
  }) === true);

  var obs = aiAct.risk.obligationsFor("essential-services");
  check("risk.obligationsFor: returns Art. 9 etc",      obs.indexOf("risk-management-art-9") !== -1);
  check("risk.obligationsFor: includes Art. 14",        obs.indexOf("human-oversight-art-14") !== -1);
  check("risk.obligationsFor: includes Art. 15",        obs.indexOf("accuracy-robustness-art-15") !== -1);

  // Law enforcement / migration include the FRIA Art. 27 obligation
  var leObs = aiAct.risk.obligationsFor("law-enforcement");
  check("risk: law-enforcement includes FRIA",          leObs.indexOf("fundamental-rights-impact-assessment-art-27") !== -1);
  var migObs = aiAct.risk.obligationsFor("migration-asylum-border");
  check("risk: migration includes FRIA",                migObs.indexOf("fundamental-rights-impact-assessment-art-27") !== -1);

  // Other rows do NOT include FRIA
  var eduObs = aiAct.risk.obligationsFor("education-vocational");
  check("risk: education does NOT include FRIA",        eduObs.indexOf("fundamental-rights-impact-assessment-art-27") === -1);

  // ---- top-level classify ----
  var assess1 = aiAct.classify({
    purpose: "credit-scoring", deployerType: "private-company",
  });
  check("classify: credit-scoring → high-risk",         assess1.tier === "high-risk");
  check("classify: returns annexIIIHits",               assess1.annexIIIHits.indexOf("essential-services") !== -1);
  check("classify: action deploy-with-controls",        assess1.action.indexOf("deploy-with-art-9-15") !== -1);
  check("classify: legal reference includes Art. 6",    assess1.legalReference.indexOf("Art. 6(2)") !== -1);

  var assess2 = aiAct.classify({
    purpose: "social-scoring", deployerType: "public-authority",
  });
  check("classify: social-scoring → prohibited",        assess2.tier === "prohibited");
  check("classify: prohibited blocks deployment",        assess2.action === "do-not-deploy");
  check("classify: cites Art. 5",                        assess2.legalReference[0].indexOf("Art. 5") !== -1);

  var assess3 = aiAct.classify({
    purpose: "search-ranking", directlyInteractsWithUsers: true,
  });
  check("classify: chatbot → limited-risk",             assess3.tier === "limited-risk");
  check("classify: chatbot obligations include Art. 50", assess3.obligations.indexOf("Art. 50") !== -1);

  var assess4 = aiAct.classify({
    purpose: "search-ranking", generatesSyntheticContent: true,
  });
  check("classify: synthetic content → limited-risk",    assess4.tier === "limited-risk");

  var assess5 = aiAct.classify({ purpose: "spam-filter" });
  check("classify: spam-filter → minimal-risk",         assess5.tier === "minimal-risk");
  check("classify: minimal has no obligations",          assess5.obligations.length === 0);

  // GPAI
  var gpai1 = aiAct.classify({ kind: "gpai", generalPurpose: true, modalities: { text: true } });
  check("classify: gpai → general-purpose",             gpai1.tier === "general-purpose");
  check("classify: gpai non-systemic obligations",      gpai1.legalReference.indexOf("Art. 53") !== -1);

  var gpai2 = aiAct.classify({
    kind: "gpai", generalPurpose: true, modalities: { text: true },
    trainingFlops: 1e26,
  });
  check("classify: gpai >10^25 FLOP → systemic risk",   gpai2.isSystemicRisk === true);
  check("classify: systemic obligations include Art. 55",
        gpai2.legalReference.indexOf("Art. 55") !== -1);

  rejects("classify: bad input",
    function () { aiAct.classify(null); }, /must be an object/);

  // ---- transparency ----
  var t = aiAct.transparency;
  var b1 = t.banner({ kind: "ai-interaction", lang: "en" });
  check("transparency.banner: text",                    b1.text.indexOf("interacting") !== -1);
  check("transparency.banner: article",                 b1.article === "Art. 50(1)");
  rejects("transparency.banner: bad kind",
    function () { t.banner({ kind: "nope" }); }, /kind must/);

  var html = t.htmlBanner({ kind: "ai-generated-content" });
  check("transparency.htmlBanner: HTML element",        html.indexOf('<div ') === 0);
  check("transparency.htmlBanner: data attr",           html.indexOf('data-blamejs-aiAct="Art. 50(2)"') !== -1);

  var w = t.watermark({ mediaKind: "image", modelId: "myco/img-gen-3", modelVersion: "v3.1" });
  check("transparency.watermark: manifest",             w.aiActArticle === "Art. 50(2)");
  check("transparency.watermark: modelId",              w.modelId === "myco/img-gen-3");
  rejects("transparency.watermark: bad mediaKind",
    function () { t.watermark({ mediaKind: "nope", modelId: "x" }); }, /mediaKind/);
  rejects("transparency.watermark: missing modelId",
    function () { t.watermark({ mediaKind: "image" }); }, /modelId/);

  var jl = t.jsonLdDisclosure({ mediaKind: "audio", modelId: "myco/voice-gen-2" });
  check("transparency.jsonLdDisclosure: tag",            jl.indexOf('<script type="application/ld+json"') === 0);

  var meta = t.metaTags({ kind: "deep-fake", policyUri: "https://example.com/ai-policy" });
  check("transparency.metaTags: notice",                meta.indexOf('<meta name="ai-act-notice"') !== -1);
  check("transparency.metaTags: article",               meta.indexOf('<meta name="ai-act-article"') !== -1);
  check("transparency.metaTags: policy link",           meta.indexOf('<link rel="ai-act-policy"') !== -1);

  // BANNER_KINDS catalog
  check("transparency: BANNER_KINDS has 6 entries",     t.BANNER_KINDS.length === 6);

  // ---- logging ----
  var l = aiAct.logging;
  var ev = l.buildEvent({
    systemId: "myco/credit-score-v3",
    kind:     "inference",
    actor:    { userId: "anon-42" },
    outcome:  "ok",
    metadata: { confidence: 0.91 },
  });
  check("logging.buildEvent: aiActArticle",             ev.aiActArticle === "Art. 12");
  check("logging.buildEvent: systemId",                 ev.systemId === "myco/credit-score-v3");
  check("logging.buildEvent: timestamp ISO",            typeof ev.timestamp === "string" && ev.timestamp.indexOf("T") !== -1);

  // Biometric logging requires extra fields
  rejects("logging.buildEvent: biometric missing fields",
    function () {
      l.buildEvent({
        systemId: "myco/face-id-v1",
        kind:     "biometric-match",
        annexIII: "biometric-id-categorisation",
      });
    }, /missing required fields/);

  var bioEv = l.buildEvent({
    systemId:          "myco/face-id-v1",
    kind:              "biometric-match",
    annexIII:          "biometric-id-categorisation",
    periodStart:       "2026-05-06T10:00:00Z",
    periodEnd:         "2026-05-06T10:00:30Z",
    referenceDatabase: "missing-persons-2026",
    matchedInputRef:   "img-hash-abc",
    verifiers:         ["officer-42"],
  });
  check("logging.buildEvent: biometric ok",             bioEv.kind === "biometric-match");
  check("logging.buildEvent: verifiers retained",        bioEv.verifiers[0] === "officer-42");

  var emitted = l.emit(ev);
  check("logging.emit: returns event",                  emitted === ev);

  var floor = l.retentionFloorMs({ domain: "high-risk-financial" });
  check("logging.retentionFloorMs: financial 1 year",   floor === 365 * 24 * 60 * 60 * 1000);

  var defaultFloor = l.retentionFloorMs({ domain: "default" });
  check("logging.retentionFloorMs: default 180d",       defaultFloor === 180 * 24 * 60 * 60 * 1000);

  // loggerFor pre-binds context
  var sysLog = l.loggerFor({ systemId: "myco/x", annexIII: "essential-services", deployer: "myco-finance" });
  var rec = sysLog({ kind: "inference", outcome: "ok" });
  check("logging.loggerFor: binds systemId",            rec.systemId === "myco/x");
  check("logging.loggerFor: binds annexIII",            rec.annexIII === "essential-services");
  rejects("logging.loggerFor: missing systemId",
    function () { l.loggerFor({ deployer: "x" }); }, /systemId/);

  // ---- GPAI ----
  var g1 = aiAct.gpai.classify({ kind: "gpai", generalPurpose: true, modalities: { text: true } });
  check("gpai.classify: detected",                       g1.isGpai === true);
  check("gpai.classify: not systemic by default",        g1.isSystemicRisk === false);

  var g2 = aiAct.gpai.classify({
    kind: "gpai", generalPurpose: true, modalities: { text: true },
    trainingFlops: 1e26,
  });
  check("gpai.classify: systemic by FLOP threshold",     g2.isSystemicRisk === true);
  check("gpai.classify: systemic obligations 5",         g2.obligations.length === 5);

  var nonGpai = aiAct.gpai.classify({ kind: "narrow", generalPurpose: false });
  check("gpai.classify: non-gpai detected",              nonGpai.isGpai === false);
  check("gpai.classify: empty obligations",              nonGpai.obligations.length === 0);

  var nonSystemic = aiAct.gpai.listObligations(false);
  var systemic    = aiAct.gpai.listObligations(true);
  check("gpai.listObligations: non-systemic 4",          nonSystemic.length === 4);
  check("gpai.listObligations: systemic 5",              systemic.length === 5);

  // ---- article catalog ----
  check("articleObligations: Art. 9 known",              aiAct.articleObligations("Art. 9").title.indexOf("Risk") !== -1);
  check("articleObligations: Art. 14 oversight",         aiAct.articleObligations("Art. 14").title.indexOf("oversight") !== -1);
  check("articleObligations: Art. 50 transparency",      aiAct.articleObligations("Art. 50").title.indexOf("ransparency") !== -1);
  check("articleObligations: unknown null",              aiAct.articleObligations("Art. 999") === null);

  var arts = aiAct.listArticles();
  check("listArticles: includes Art. 9",                 arts.indexOf("Art. 9") !== -1);
  check("listArticles: includes Art. 50",                arts.indexOf("Art. 50") !== -1);

  // ---- annexIVScaffold ----
  var scaffold = aiAct.annexIVScaffold({
    systemId:        "myco/credit-score",
    deployerName:    "myco-finance",
    providerName:    "myco-ai",
    intendedPurpose: "credit-scoring for natural persons",
    annexIIIRow:     "essential-services",
    deploymentScope: "EU-DE+EU-FR",
    version:         "3.0.1",
  });
  check("annexIVScaffold: 8 sections",                   Object.keys(scaffold.sections).length === 8);
  check("annexIVScaffold: section 1 provided",           scaffold.sections["1-general-description"].provided.systemId === "myco/credit-score");
  check("annexIVScaffold: section 2 awaits content",     scaffold.sections["2-detailed-description"].provided === null);

  rejects("annexIVScaffold: missing systemId",
    function () { aiAct.annexIVScaffold({}); }, /systemId/);

  // ---- emitClassificationAudit (smoke — must not throw) ----
  var assessSmoke = aiAct.classify({ purpose: "spam-filter" });
  aiAct.emitClassificationAudit({ systemId: "myco/x", deployerName: "myco" }, assessSmoke);
  check("emitClassificationAudit: doesn't throw",        true);

  // ---- regime registry hookup ----
  check("compliance.REGIME_MAP: ai-act present",         b.compliance.REGIME_MAP &&
                                                          typeof b.compliance.REGIME_MAP["ai-act"] === "object");

  // ---- aiActDisclosure middleware ----
  check("middleware.aiActDisclosure is fn",              typeof b.middleware.aiActDisclosure === "function");

  rejects("middleware.aiActDisclosure: bad kind",
    function () { b.middleware.aiActDisclosure({ kind: "nope" }); }, /kind must/);

  // Header-mode test
  var mw = b.middleware.aiActDisclosure({
    kind:         "ai-interaction",
    deployerName: "myco",
    policyUri:    "https://myco.example.com/ai-policy",
    audit:        false,
  });
  check("middleware: factory returns fn",                typeof mw === "function");

  function _mockRes() {
    var headers = {};
    var listeners = {};
    return {
      _headers: headers,
      headersSent: false,
      writeHead: function (status, h) {
        if (typeof h === "object") for (var k in h) headers[k] = h[k];
        this.headersSent = true;
      },
      setHeader: function (name, value) { headers[name] = value; },
      getHeader: function (name) { return headers[name]; },
      end:    function () {},
      on:     function (event, fn) { listeners[event] = fn; },
      _close: function () { if (listeners.close) listeners.close(); },
    };
  }

  var req1 = { headers: {}, url: "/foo" };
  var res1 = _mockRes();
  var nextCalls = 0;
  mw(req1, res1, function () { nextCalls += 1; });
  check("middleware: calls next",                        nextCalls === 1);
  res1.writeHead(200, {});
  check("middleware: AI-Act-Notice set",                 res1._headers["AI-Act-Notice"] === "ai-interaction");
  check("middleware: AI-Act-Article set",                res1._headers["AI-Act-Article"] === "Art. 50(1)");
  check("middleware: AI-Act-Policy set",                 res1._headers["AI-Act-Policy"] === "https://myco.example.com/ai-policy");

  // Skip on x-skip-ai-act header
  var req2 = { headers: { "x-skip-ai-act": "1" }, url: "/skip" };
  var res2 = _mockRes();
  mw(req2, res2, function () { /* next2 — drop-silent */ });
  res2.writeHead(200, {});
  check("middleware: skip on x-skip-ai-act header",      res2._headers["AI-Act-Notice"] == null);

  // Skip on res.locals.aiActSkip
  var req3 = { headers: {}, url: "/locals-skip" };
  var res3 = _mockRes();
  res3.locals = { aiActSkip: true };
  mw(req3, res3, function () {});
  res3.writeHead(200, {});
  check("middleware: skip on res.locals.aiActSkip",      res3._headers["AI-Act-Notice"] == null);

  // Don't inject on 4xx
  var req4 = { headers: {}, url: "/err" };
  var res4 = _mockRes();
  mw(req4, res4, function () {});
  res4.writeHead(404, {});
  check("middleware: no inject on 4xx",                  res4._headers["AI-Act-Notice"] == null);

  // headerPrefix override — the disclosure headers carry a custom prefix
  var mwPfx = b.middleware.aiActDisclosure({
    kind:         "ai-interaction",
    policyUri:    "https://myco.example.com/ai-policy",
    headerPrefix: "X-AI-",
    audit:        false,
  });
  var req5 = { headers: {}, url: "/pfx" };
  var res5 = _mockRes();
  mwPfx(req5, res5, function () {});
  res5.writeHead(200, {});
  check("middleware: custom headerPrefix on Notice",     res5._headers["X-AI-Notice"] === "ai-interaction");
  check("middleware: custom headerPrefix on Article",    res5._headers["X-AI-Article"] === "Art. 50(1)");
  check("middleware: custom headerPrefix replaces default", res5._headers["AI-Act-Notice"] == null);

  // ---- expanded prohibited classifier ----
  var hits7 = aiAct.prohibited.classify({
    purpose: "predictive-policing", usesProfileOnly: true,
  });
  check("prohibited.classify: profile-only policing",    hits7.indexOf("predictive-policing-individual") !== -1);

  var hits8 = aiAct.prohibited.classify({
    remoteBiometricId: "real-time", deployContext: "law-enforcement-public-space",
    exemption: "missing-person",
  });
  check("prohibited.classify: missing-person exempt",    hits8.indexOf("real-time-remote-biometric-id") === -1);

  var hits9 = aiAct.prohibited.classify({
    remoteBiometricId: "real-time", deployContext: "law-enforcement-public-space",
  });
  check("prohibited.classify: real-time RBI no exempt",  hits9.indexOf("real-time-remote-biometric-id") !== -1);

  // ---- expanded annexIII classifier ----
  var ann5 = aiAct.risk.classifyAnnexIII("traffic-control");
  check("risk.classifyAnnexIII: traffic-control",        ann5.indexOf("critical-infrastructure") !== -1);
  var ann6 = aiAct.risk.classifyAnnexIII("election-influence");
  check("risk.classifyAnnexIII: election influence",     ann6.indexOf("judicial-democratic-process") !== -1);
  var ann7 = aiAct.risk.classifyAnnexIII("border-biometric-id");
  check("risk.classifyAnnexIII: border biometric",       ann7.indexOf("migration-asylum-border") !== -1);

  // ---- richer annex-III lookup ----
  check("risk.getAnnexIII: known",                       aiAct.risk.getAnnexIII("essential-services") !== null);
  check("risk.getAnnexIII: unknown null",                aiAct.risk.getAnnexIII("nope") === null);

  // ---- top-level: explicit annexIIIRow opt-in ----
  var assess6 = aiAct.classify({
    purpose: "search-ranking",
    annexIIIRow: ["essential-services"],
  });
  check("classify: explicit annexIIIRow",                assess6.tier === "high-risk");
  check("classify: explicit annex obligations",          assess6.obligations.length > 0);

  // ---- safety-component path ----
  var assess7 = aiAct.classify({
    purpose: "search-ranking",
    safetyComponentForRegulatedProduct: true,
    requiresThirdPartyConformity: true,
  });
  check("classify: safety-component → high-risk",        assess7.tier === "high-risk");

  // ---- annex-IV scaffold sections complete ----
  var sc = aiAct.annexIVScaffold({
    systemId: "sys-1", deployerName: "d", providerName: "p",
    intendedPurpose: "x", annexIIIRow: "essential-services",
    deploymentScope: "EU-DE", version: "1.0",
  });
  check("annexIVScaffold: section 1 required",           sc.sections["1-general-description"].required.indexOf("systemId") !== -1);
  check("annexIVScaffold: section 4 risk-mgmt",          sc.sections["4-risk-management"].title.indexOf("risk") !== -1);
  check("annexIVScaffold: section 7 declaration",        sc.sections["7-eu-declaration-of-conformity"].title.indexOf("conformity") !== -1);
  check("annexIVScaffold: section 8 post-market",        sc.sections["8-post-market-monitoring"].title.indexOf("post-market") !== -1);

  // ---- transparency: kinds catalog completeness ----
  for (var i = 0; i < t.BANNER_KINDS.length; i += 1) {
    var bk = t.banner({ kind: t.BANNER_KINDS[i] });
    check("transparency.banner: " + t.BANNER_KINDS[i] + " has text",
          typeof bk.text === "string" && bk.text.length > 0);
    check("transparency.banner: " + t.BANNER_KINDS[i] + " has article",
          typeof bk.article === "string" && bk.article.indexOf("Art. 50") === 0);
  }

  // ---- watermark with all opts ----
  var wAll = t.watermark({
    mediaKind:    "video",
    modelId:      "myco/v3",
    modelVersion: "3.2",
    createdAt:    "2026-05-06T10:00:00Z",
    promptHash:   "sha3-256:abc123",
    manipulation: true,
    deployerName: "myco-studio",
    encoding:     "c2pa",
  });
  check("watermark: all opts retained",                  wAll.modelVersion === "3.2");
  check("watermark: manipulation true",                  wAll.manipulation === true);
  check("watermark: encoding",                           wAll.encoding === "c2pa");

  // ---- transparency.banner: extra opts ----
  var bExtra = t.banner({
    kind: "ai-interaction",
    deployerName: "myco-bot",
    controllerContact: "privacy@myco.example.com",
    linkPolicy: "https://myco.example.com/policy",
    linkContact: "https://myco.example.com/contact",
  });
  check("banner: deployerName retained",                 bExtra.deployerName === "myco-bot");
  check("banner: controllerContact retained",            bExtra.controllerContact === "privacy@myco.example.com");
  check("banner: linkPolicy retained",                   bExtra.linkPolicy === "https://myco.example.com/policy");

  // ---- logging: full event with all context ----
  var rich = l.buildEvent({
    systemId:    "myco/credit-v3",
    kind:        "training-update",
    actor:       { userId: "ml-engineer-1", deployer: "myco-finance" },
    annexIII:    "essential-services",
    timestamp:   Date.parse("2026-05-06T10:00:00Z"),
    outcome:     "ok",
    metadata:    { datasetVersion: "2026-Q2", modelVersion: "3.1.4" },
  });
  check("logging: rich event aiActArticle",              rich.aiActArticle === "Art. 12");
  check("logging: rich event metadata",                  rich.metadata.datasetVersion === "2026-Q2");
  check("logging: rich event timestamp",                 rich.timestamp.indexOf("2026") === 0);

  // ---- logEvent emits ----
  var le = l.logEvent({
    systemId: "myco/x", kind: "shutdown", outcome: "ok",
  });
  check("logEvent: returns record",                      le && le.kind === "shutdown");

  // ---- DEADLINE accessibility ----
  check("DEADLINES has highRiskAnnexIII",                aiAct.DEADLINES.highRiskAnnexIII === "2027-08-02");
  check("DEADLINES has generalPurposeAI",                aiAct.DEADLINES.generalPurposeAI === "2026-08-02");

  // ---- deployerChecklist ----
  check("deployerChecklist is fn",                       typeof aiAct.deployerChecklist === "function");
  rejects("deployerChecklist: bad input",
    function () { aiAct.deployerChecklist(null); }, /assessment must/);

  // High-risk
  var hrCheck = aiAct.deployerChecklist({
    tier: "high-risk", obligations: ["risk-management-art-9", "human-oversight-art-14"],
  });
  check("deployerChecklist: hr returns items",           Array.isArray(hrCheck) && hrCheck.length > 0);
  check("deployerChecklist: hr has Art. 9",              hrCheck.some(function (i) { return i.article === "Art. 9"; }));
  check("deployerChecklist: hr has Art. 12",             hrCheck.some(function (i) { return i.article === "Art. 12"; }));
  check("deployerChecklist: hr has Art. 71",             hrCheck.some(function (i) { return i.article === "Art. 71"; }));
  check("deployerChecklist: hr Art. 9 required",         hrCheck.find(function (i) { return i.article === "Art. 9"; }).status === "required");

  // Law-enforcement / migration high-risk includes FRIA Art. 27
  var leCheck = aiAct.deployerChecklist({
    tier: "high-risk",
    obligations: ["risk-management-art-9", "fundamental-rights-impact-assessment-art-27"],
  });
  check("deployerChecklist: FRIA included when in obligations",
        leCheck.some(function (i) { return i.article === "Art. 27"; }));

  // Prohibited
  var prohibChk = aiAct.deployerChecklist({ tier: "prohibited", prohibitedHits: ["social-scoring"] });
  check("deployerChecklist: prohibited do-not-deploy",   prohibChk[0].action === "do-not-deploy");
  check("deployerChecklist: prohibited cites Art. 5",    prohibChk[0].article === "Art. 5");

  // Limited-risk
  var lrChk = aiAct.deployerChecklist({ tier: "limited-risk", obligations: ["Art. 50"] });
  check("deployerChecklist: limited-risk has transparency", lrChk[0].action === "transparency-disclosure");
  check("deployerChecklist: limited-risk Art. 50",       lrChk[0].article === "Art. 50");

  // GPAI non-systemic
  var gpaiChk = aiAct.deployerChecklist({ tier: "general-purpose", isSystemicRisk: false, obligations: [] });
  check("deployerChecklist: gpai non-systemic items",     gpaiChk.length >= 4);
  check("deployerChecklist: gpai includes copyright",     gpaiChk.some(function (i) { return i.article === "Art. 53(1)(c)"; }));

  // GPAI systemic
  var gpaiSysChk = aiAct.deployerChecklist({ tier: "general-purpose", isSystemicRisk: true, obligations: [] });
  check("deployerChecklist: gpai systemic includes Art. 55",
        gpaiSysChk.some(function (i) { return i.article === "Art. 55"; }));
  check("deployerChecklist: gpai systemic 8+ items",     gpaiSysChk.length >= 8);

  // Minimal-risk → just voluntary codes deferred
  var minChk = aiAct.deployerChecklist({ tier: "minimal-risk", obligations: [] });
  check("deployerChecklist: minimal-risk deferred",      minChk[0].status === "deferred");

  // ---- v0.8.81: ISO 42001 + 23894 cross-walk ----
  var fullCw = aiAct.crossWalkIso42001();
  check("crossWalkIso42001: returns array",                    Array.isArray(fullCw));
  check("crossWalkIso42001: covers >= 15 AI Act citations",    fullCw.length >= 15);
  check("crossWalkIso42001: every entry has aiAct field",      fullCw.every(function (r) { return typeof r.aiAct === "string"; }));
  check("crossWalkIso42001: every entry has iso42001 array",   fullCw.every(function (r) { return Array.isArray(r.iso42001); }));
  check("crossWalkIso42001: every entry has iso23894 array",   fullCw.every(function (r) { return Array.isArray(r.iso23894); }));

  var art10 = aiAct.crossWalkIso42001("Art. 10 (Data and data governance)");
  check("crossWalkIso42001(Art. 10): present",                 art10 !== null);
  check("crossWalkIso42001(Art. 10): cites A.7 data controls",
        art10.iso42001.some(function (c) { return /A\.7/.test(c); }));

  check("crossWalkIso42001(bogus): null",                      aiAct.crossWalkIso42001("not-a-real-citation") === null);
  check("crossWalkIso42001(non-string): null",                 aiAct.crossWalkIso42001(123) === null);

  var subset = aiAct.crossWalkIso23894();
  check("crossWalkIso23894: returns only entries with iso23894 clauses",
        subset.every(function (r) { return r.iso23894.length > 0; }));
  check("crossWalkIso23894: at least 10 entries",              subset.length >= 10);

  // Defensive copies — caller mutation must not affect internal table
  var firstRow = aiAct.crossWalkIso42001()[0];
  firstRow.iso42001.push("MUTATION");
  var freshRow = aiAct.crossWalkIso42001()[0];
  check("crossWalkIso42001: returns defensive copies",
        freshRow.iso42001.indexOf("MUTATION") === -1);

  // ---- v0.14.11: GPAI Code-of-Practice signed adherence declaration ----
  var gpaiCop = aiAct.gpai;
  check("gpai.adherenceForm is fn",                      typeof gpaiCop.adherenceForm === "function");
  check("gpai.declareAdherence is fn",                   typeof gpaiCop.declareAdherence === "function");
  check("gpai.verifyAdherence is fn",                    typeof gpaiCop.verifyAdherence === "function");

  var copPair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var evidence = b.crypto.sha3Hash("annex-xi-technical-documentation-v1");
  check("evidence hash is 128 hex chars",                /^[0-9a-f]{128}$/.test(evidence));

  function _copCommitments(articles) {
    return articles.map(function (a) {
      return { article: a, statement: "evidence for " + a, evidenceHash: evidence };
    });
  }
  var ART_53_ALL = ["Art. 53(1)(a)", "Art. 53(1)(b)", "Art. 53(1)(c)", "Art. 53(1)(d)"];

  // adherenceForm derives the four Art. 53 obligations (no systemic chapter)
  var copForm = gpaiCop.adherenceForm({
    modelId: "acme-llm-7b", modelVersion: "1.0",
    commitments: _copCommitments(["Art. 53(1)(a)"]),
  });
  check("adherenceForm: 4 derived obligations",          copForm.commitments.length === 4);
  check("adherenceForm: not systemic by default",        copForm.isSystemicRisk === false);
  check("adherenceForm: articles Art. 53 only",          copForm.articles.length === 1 && copForm.articles[0] === "Art. 53");
  check("adherenceForm: first commitment evidenced",     copForm.commitments[0].evidenced === true);
  check("adherenceForm: unsupplied obligation surfaced", copForm.commitments[1].evidenced === false);
  check("adherenceForm: deadlines bound into form",      copForm.deadlines.generalPurposeAI === "2026-08-02");
  check("adherenceForm: copVersion default",             copForm.copVersion === "2025-07");

  // Round-trip: build → sign → verify
  var copEnv = gpaiCop.declareAdherence({
    modelId: "acme-llm-7b", modelVersion: "1.0",
    commitments: _copCommitments(ART_53_ALL),
    privateKeyPem: copPair.privateKey,
  });
  check("declareAdherence: returns signed envelope",     typeof copEnv.signature === "string" && copEnv.signature.length > 0);
  check("declareAdherence: no unsigned path (has bom)",  copEnv.bom && copEnv.bom.bomFormat === "CycloneDX");
  check("declareAdherence: surfaces adherence form",     copEnv.adherence && copEnv.adherence.modelId === "acme-llm-7b");

  var copVerdict = gpaiCop.verifyAdherence(copEnv, copPair.publicKey);
  check("verifyAdherence: round-trip valid",             copVerdict.valid === true);
  check("verifyAdherence: surfaces required articles",   copVerdict.adherence.requiredArticles.indexOf("Art. 53(1)(d)") !== -1);
  check("verifyAdherence: reason null on success",       copVerdict.reason === null);

  // Signature-substitution defense: tamper a BOM field, signature must fail
  var copTampered = { bom: JSON.parse(JSON.stringify(copEnv.bom)), signature: copEnv.signature };
  copTampered.bom.metadata.component.version = "9.9.9";
  check("verifyAdherence: tampered bom rejected",        gpaiCop.verifyAdherence(copTampered, copPair.publicKey).valid === false);

  // Refusal 1 — hollow attestation / bad evidenceHash
  rejects("declareAdherence: junk evidenceHash refused",
    function () {
      gpaiCop.declareAdherence({
        modelId: "m", modelVersion: "1",
        commitments: [{ article: "Art. 53(1)(a)", statement: "x", evidenceHash: "x" }],
        privateKeyPem: copPair.privateKey,
      });
    }, /evidenceHash/);

  // Refusal 2 — scope downgrade: 3e25-FLOP systemic model OMITTING the Art. 55 chapter
  rejects("declareAdherence: systemic model omitting Art. 55 refused",
    function () {
      gpaiCop.declareAdherence({
        modelId: "big", modelVersion: "1", trainingFlops: 3e25,
        commitments: _copCommitments(ART_53_ALL),   // omits Art. 55
        privateKeyPem: copPair.privateKey,
      });
    }, /Art\. 55/);

  // Systemic model that DOES cover Art. 55 succeeds + marks systemic risk
  var copSysEnv = gpaiCop.declareAdherence({
    modelId: "big", modelVersion: "1", trainingFlops: 3e25,
    commitments: _copCommitments(ART_53_ALL.concat(["Art. 55"])),
    privateKeyPem: copPair.privateKey,
  });
  var copSysVerdict = gpaiCop.verifyAdherence(copSysEnv, copPair.publicKey);
  check("declareAdherence: systemic model with Art. 55 valid", copSysVerdict.valid === true);
  check("declareAdherence: systemic flag set",                 copSysVerdict.adherence.isSystemicRisk === true);
  check("declareAdherence: systemic articles include Art. 55", copSysVerdict.adherence.articles.indexOf("Art. 55") !== -1);

  // Refusal 3 — missing modelId / modelVersion
  rejects("declareAdherence: missing modelId refused",
    function () {
      gpaiCop.declareAdherence({ modelVersion: "1", privateKeyPem: copPair.privateKey });
    }, /modelId/);
  rejects("declareAdherence: missing modelVersion refused",
    function () {
      gpaiCop.declareAdherence({ modelId: "m", privateKeyPem: copPair.privateKey });
    }, /modelVersion/);
  rejects("declareAdherence: missing signing key refused",
    function () {
      gpaiCop.declareAdherence({ modelId: "m", modelVersion: "1" });
    }, /privateKeyPem/);

  // Refusal 4 — stale / replayed declaration past its validity window
  var copStaleEnv = gpaiCop.declareAdherence({
    modelId: "m", modelVersion: "1",
    validityMs: 1000,
    generatedAt: new Date(Date.now() - 60000).toISOString(),
    commitments: _copCommitments(ART_53_ALL),
    privateKeyPem: copPair.privateKey,
  });
  var copStaleVerdict = gpaiCop.verifyAdherence(copStaleEnv, copPair.publicKey);
  check("verifyAdherence: expired declaration rejected", copStaleVerdict.valid === false && copStaleVerdict.reason === "expired");

  // A fresh declaration verified within its window passes; the `now`
  // override drives the clock without a setTimeout wait.
  var copFreshVerdict = gpaiCop.verifyAdherence(copStaleEnv, copPair.publicKey, {
    now: Date.parse(copStaleEnv.adherence.generatedAt) + 500,
  });
  check("verifyAdherence: within-window declaration valid", copFreshVerdict.valid === true);

  // Unknown opt key throws at config time
  rejects("declareAdherence: unknown opt key refused",
    function () {
      gpaiCop.declareAdherence({
        modelId: "m", modelVersion: "1", privateKeyPem: copPair.privateKey, bogusKey: 1,
      });
    }, /unknown option/);

  // Bad copVersion month group refused (shape-only regex with real month)
  rejects("adherenceForm: copVersion month 13 refused",
    function () {
      gpaiCop.adherenceForm({
        modelId: "m", modelVersion: "1", copVersion: "2025-13",
        commitments: _copCommitments(["Art. 53(1)(a)"]),
      });
    }, /copVersion/);

  console.log("OK — compliance-ai-act tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
