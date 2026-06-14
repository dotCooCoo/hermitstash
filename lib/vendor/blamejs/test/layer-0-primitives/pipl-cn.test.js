"use strict";
// b.pipl.sccFilingAssessment + b.pipl.securityAssessmentCertificate —
// China PIPL Art. 38/40/55 cross-border transfer record-builders (pure;
// no DB). Drives the real b.pipl.* consumer path, asserts frozen records +
// audit emission via a captured injected sink, and the config-time throws.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A b.audit-shaped capture sink — the builder prefers an injected
// opts.audit object over the global b.audit (drop-silent without a DB
// handler), so this is how the test asserts emission.
function _captureAudit() {
  var events = [];
  return { events: events, safeEmit: function (ev) { events.push(ev); } };
}

function expectCode(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "") === code);
}

function expectThrows(label, fn) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw instanceof Error);
}

function run() {
  check("sccFilingAssessment is a function", typeof b.pipl.sccFilingAssessment === "function");
  check("securityAssessmentCertificate is a function", typeof b.pipl.securityAssessmentCertificate === "function");
  check("PiplError exposed on b.frameworkError", typeof b.frameworkError.PiplError === "function");
  check("b.pipl.PiplError is the same constructor", b.pipl.PiplError === b.frameworkError.PiplError);
  check("LEGAL_BASES is the Art. 38(1) triad",
    b.pipl.LEGAL_BASES.length === 3 &&
    b.pipl.LEGAL_BASES.indexOf("standard-contract") !== -1 &&
    b.pipl.LEGAL_BASES.indexOf("security-assessment") !== -1 &&
    b.pipl.LEGAL_BASES.indexOf("certification") !== -1);
  check("pipl-cn is a cross-border-regulated posture",
    b.compliance.isCrossBorderRegulated("pipl-cn") === true);

  var recordedAt = 1700000000000;

  // ---- sccFilingAssessment: below-threshold standard contract ----
  var sink1 = _captureAudit();
  var scc = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-1", transferType: "processor", recipientJurisdiction: "US",
    dataCategories: ["contact", "billing"], legalBasis: "standard-contract",
    volume: 5000, sensitivePI: false, recordedAt: recordedAt, audit: sink1,
  });
  check("scc: honors standard-contract below thresholds", scc.mechanismRequired === "standard-contract");
  check("scc: securityAssessmentRequired false", scc.securityAssessmentRequired === false);
  check("scc: record frozen", Object.isFrozen(scc));
  check("scc: dataCategories frozen", Object.isFrozen(scc.dataCategories));
  check("scc: nextReviewDueBy = recordedAt + 1 year",
    scc.nextReviewDueBy === recordedAt + b.constants.TIME.days(365));
  check("scc: emitted pipl.transfer.assessed",
    sink1.events.length === 1 && sink1.events[0].action === "pipl.transfer.assessed");
  check("scc: audit carries mechanismRequired",
    sink1.events[0].metadata.mechanismRequired === "standard-contract");

  // ---- CIIO forces security assessment over declared basis ----
  var ciio = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-2", transferType: "controller-to-controller", recipientJurisdiction: "EU",
    dataCategories: ["health"], legalBasis: "standard-contract",
    volume: 100, sensitivePI: true, ciio: true, recordedAt: recordedAt,
  });
  check("scc: CIIO forces security-assessment", ciio.mechanismRequired === "security-assessment");
  check("scc: CIIO sets securityAssessmentRequired", ciio.securityAssessmentRequired === true);
  check("scc: CIIO trigger named", ciio.securityAssessmentTriggers.indexOf("ciio") !== -1);
  check("scc: mandated assessment carries 3-year clock",
    ciio.nextReviewDueBy === recordedAt + b.constants.TIME.days(365 * 3));

  // ---- >1M non-sensitive PI forces it ----
  var bigVol = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-3", transferType: "processor", recipientJurisdiction: "SG",
    dataCategories: ["contact"], legalBasis: "certification",
    volume: 1000001, sensitivePI: false, recordedAt: recordedAt,
  });
  check("scc: >1M non-sensitive volume forces security-assessment",
    bigVol.mechanismRequired === "security-assessment" &&
    bigVol.securityAssessmentTriggers.indexOf("non-sensitive-pi-volume") !== -1);

  // ---- 100k-1M non-sensitive band is SCC, NOT security-assessment (the
  //      100k cumulative threshold is the standard-contract tier per the CAC
  //      2024 Provisions; a 200k non-sensitive transfer must not over-classify) ----
  var midBand = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-3b", transferType: "processor", recipientJurisdiction: "US",
    dataCategories: ["contact"], legalBasis: "standard-contract",
    volume: 200000, sensitivePI: false, recordedAt: recordedAt,
  });
  check("scc: 200k non-sensitive stays standard-contract (no over-classify)",
    midBand.mechanismRequired === "standard-contract" &&
    midBand.securityAssessmentRequired === false);

  // ---- THIS transfer's volume counts toward the cumulative sensitive
  //      threshold: a first transfer of 10,001 sensitive subjects forces it
  //      even with cumulativeSensitivePI omitted (defaults 0) ----
  var firstSens = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-3c", transferType: "processor", recipientJurisdiction: "US",
    dataCategories: ["biometric"], legalBasis: "standard-contract",
    volume: 10001, sensitivePI: true, recordedAt: recordedAt,
  });
  check("scc: first 10,001 sensitive-PI transfer forces it (own volume counts)",
    firstSens.securityAssessmentRequired === true &&
    firstSens.securityAssessmentTriggers.indexOf("sensitive-pi-volume") !== -1);

  // ---- cumulative sensitive-PI threshold (this transfer + prior cumulative) ----
  var cumSens = b.pipl.sccFilingAssessment({
    assessmentId: "xfer-4", transferType: "processor", recipientJurisdiction: "US",
    dataCategories: ["biometric"], legalBasis: "standard-contract",
    volume: 200, sensitivePI: true, cumulativeSensitivePI: 10001, recordedAt: recordedAt,
  });
  check("scc: >10k cumulative sensitive-PI forces it",
    cumSens.securityAssessmentRequired === true &&
    cumSens.securityAssessmentTriggers.indexOf("sensitive-pi-volume") !== -1);

  // ---- securityAssessmentCertificate: happy path ----
  var sink3 = _captureAudit();
  var cert = b.pipl.securityAssessmentCertificate({
    certId: "sa-1", assessmentScope: "CRM outbound replication",
    dataExporter: "Acme (Shanghai) Co., Ltd.", overseasRecipient: "Acme Inc.",
    riskRating: "medium", safeguards: ["XChaCha20 at rest", "standard contractual clauses"],
    filingRef: "CAC-2026-0042", recordedAt: recordedAt, audit: sink3,
  });
  check("cert: record frozen", Object.isFrozen(cert));
  check("cert: safeguards frozen", Object.isFrozen(cert.safeguards));
  check("cert: validUntil = recordedAt + 3 years",
    cert.validUntil === recordedAt + b.constants.TIME.days(365 * 3));
  check("cert: filingRef carried", cert.filingRef === "CAC-2026-0042");
  check("cert: emitted pipl.security_assessment.recorded",
    sink3.events.length === 1 && sink3.events[0].action === "pipl.security_assessment.recorded");
  check("cert: filingRef omitted defaults null",
    b.pipl.securityAssessmentCertificate({
      certId: "sa-2", assessmentScope: "s", dataExporter: "e", overseasRecipient: "r",
      riskRating: "low", safeguards: ["x"], recordedAt: recordedAt,
    }).filingRef === null);

  // ---- Config-time throws ----
  expectCode("scc: non-object opts throws",
    function () { b.pipl.sccFilingAssessment("nope"); }, "pipl/bad-opts");
  expectThrows("scc: unknown opt key throws",
    function () { b.pipl.sccFilingAssessment({ assessmentId: "x", bogusKey: 1 }); });
  expectCode("scc: missing assessmentId throws",
    function () { b.pipl.sccFilingAssessment({ transferType: "p", recipientJurisdiction: "US", dataCategories: ["c"], legalBasis: "standard-contract", volume: 1, sensitivePI: false, recordedAt: recordedAt }); }, "pipl/bad-assessment-id");
  expectCode("scc: empty dataCategories throws",
    function () { b.pipl.sccFilingAssessment({ assessmentId: "x", transferType: "p", recipientJurisdiction: "US", dataCategories: [], legalBasis: "standard-contract", volume: 1, sensitivePI: false, recordedAt: recordedAt }); }, "pipl/bad-data-categories");
  expectCode("scc: bad legalBasis throws",
    function () { b.pipl.sccFilingAssessment({ assessmentId: "x", transferType: "p", recipientJurisdiction: "US", dataCategories: ["c"], legalBasis: "bogus", volume: 1, sensitivePI: false, recordedAt: recordedAt }); }, "pipl/bad-legal-basis");
  expectCode("scc: non-boolean sensitivePI throws",
    function () { b.pipl.sccFilingAssessment({ assessmentId: "x", transferType: "p", recipientJurisdiction: "US", dataCategories: ["c"], legalBasis: "standard-contract", volume: 1, sensitivePI: "yes", recordedAt: recordedAt }); }, "pipl/bad-sensitive-pi");
  expectCode("scc: missing recordedAt throws",
    function () { b.pipl.sccFilingAssessment({ assessmentId: "x", transferType: "p", recipientJurisdiction: "US", dataCategories: ["c"], legalBasis: "standard-contract", volume: 1, sensitivePI: false }); }, "pipl/bad-recorded-at");

  expectCode("cert: missing certId throws",
    function () { b.pipl.securityAssessmentCertificate({ assessmentScope: "s", dataExporter: "e", overseasRecipient: "r", riskRating: "low", safeguards: ["x"], recordedAt: recordedAt }); }, "pipl/bad-cert-id");
  expectCode("cert: bad riskRating throws",
    function () { b.pipl.securityAssessmentCertificate({ certId: "c", assessmentScope: "s", dataExporter: "e", overseasRecipient: "r", riskRating: "critical", safeguards: ["x"], recordedAt: recordedAt }); }, "pipl/bad-risk-rating");
  expectCode("cert: empty safeguards throws",
    function () { b.pipl.securityAssessmentCertificate({ certId: "c", assessmentScope: "s", dataExporter: "e", overseasRecipient: "r", riskRating: "low", safeguards: [], recordedAt: recordedAt }); }, "pipl/bad-safeguards");
  expectCode("cert: bad audit sink shape throws",
    function () { b.pipl.securityAssessmentCertificate({ certId: "c", assessmentScope: "s", dataExporter: "e", overseasRecipient: "r", riskRating: "low", safeguards: ["x"], recordedAt: recordedAt, audit: { nope: 1 } }); }, "pipl/bad-audit");
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[pipl-cn] OK"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
