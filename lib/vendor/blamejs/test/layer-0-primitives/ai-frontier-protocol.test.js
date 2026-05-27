"use strict";
/**
 * Layer 0 — b.ai.frontierModelProtocol (California SB 53, Transparency in
 * Frontier AI Act).
 *
 * Oracle: the statute's thresholds and deadlines (Cal. Bus. & Prof. Code
 * §22757.10) — a frontier model exceeds 10^26 training FLOPs, a large frontier
 * developer exceeds $500M revenue, and a critical-incident report is due to the
 * CA OES within 15 days of discovery (24 hours when there is imminent risk to
 * life). The four incident categories are enumerated.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
var fp = b.ai.frontierModelProtocol;

function testSurface() {
  check("b.ai.frontierModelProtocol is a function", typeof fp === "function");
  check("incidentReport is a function", typeof fp.incidentReport === "function");
  check("INCIDENT_TYPES has the four categories", fp.INCIDENT_TYPES.length === 4);
  check("REQUIRED_FRAMEWORK_ELEMENTS present", fp.REQUIRED_FRAMEWORK_ELEMENTS.length === 5);
  check("FrontierProtocolError is a class", typeof fp.FrontierProtocolError === "function");
}

function testThresholds() {
  var big = fp({ trainingFlops: 5e26, annualRevenueUsd: 1e9 });
  check("above 10^26 FLOPs is a frontier model", big.isFrontierModel === true);
  check("frontier + >$500M is a large frontier developer", big.isLargeFrontierDeveloper === true);
  check("large developer gets all four obligations", big.obligations.length === 4 && big.obligations.indexOf("publish-annual-safety-framework") !== -1);

  check("below 10^26 FLOPs is not a frontier model", fp({ trainingFlops: 1e25, annualRevenueUsd: 1e9 }).isFrontierModel === false);
  check("exactly 10^26 FLOPs is not a frontier model (strict >)", fp({ trainingFlops: 1e26 }).isFrontierModel === false);

  var smallCo = fp({ trainingFlops: 5e26, annualRevenueUsd: 1e8 });
  check("frontier model at a small developer: frontier yes, large no", smallCo.isFrontierModel === true && smallCo.isLargeFrontierDeveloper === false);
  check("small developer gets only the frontier obligations", smallCo.obligations.length === 2 && smallCo.obligations.indexOf("report-critical-safety-incidents") !== -1);
  check("revenue defaults to 0 when omitted", fp({ trainingFlops: 5e26 }).isLargeFrontierDeveloper === false);
}

function testFrameworkCheck() {
  var gaps = fp({ trainingFlops: 5e26, annualRevenueUsd: 1e9, framework: { riskIdentification: 1, governance: 1 } });
  check("framework gaps detected", JSON.stringify(gaps.frameworkGaps) === JSON.stringify(["riskMitigation", "cybersecurity", "standardsAlignment"]));
  check("frameworkComplete false with gaps", gaps.frameworkComplete === false);
  var complete = fp({ trainingFlops: 5e26, annualRevenueUsd: 1e9, framework: { riskIdentification: 1, riskMitigation: 1, governance: 1, cybersecurity: 1, standardsAlignment: 1 } });
  check("frameworkComplete true when all elements present", complete.frameworkComplete === true && complete.frameworkGaps.length === 0);
}

function testIncidentReport() {
  var r15 = fp.incidentReport({ type: "loss-of-control-harm", discoveredAt: new Date("2026-06-01T00:00:00Z") });
  check("default deadline is 15 days (360h)", r15.deadlineHours === 360);
  check("15-day dueAt computed", r15.dueAt === "2026-06-16T00:00:00.000Z");
  check("routine report goes to CA OES", r15.recipient.indexOf("Office of Emergency Services") !== -1);
  check("type description carried", r15.typeDescription.indexOf("Loss of control") !== -1);

  var r24 = fp.incidentReport({ type: "weights-exfiltration-harm", discoveredAt: new Date("2026-06-01T00:00:00Z"), imminentRiskToLife: true });
  check("imminent-risk deadline is 24 hours", r24.deadlineHours === 24);
  check("24-hour dueAt computed", r24.dueAt === "2026-06-02T00:00:00.000Z");
  // §22757.13: imminent risk routes to an applicable authority, not OES.
  check("imminent-risk routes to an applicable authority, not OES", r24.recipient.indexOf("Office of Emergency Services") === -1 && r24.recipient.indexOf("applicable authority") !== -1);
  // §22757.10(i): the weights category is death/bodily-injury only — no property.
  check("weights-incident description excludes property", r24.typeDescription.toLowerCase().indexOf("property") === -1);
}

function testErrors() {
  check("unknown incident type throws", code(function () { fp.incidentReport({ type: "made-up" }); }) === "frontier/bad-incident-type");
  check("bad discoveredAt throws",       code(function () { fp.incidentReport({ type: "loss-of-control-harm", discoveredAt: -5 }); }) === "frontier/bad-value");
  check("missing trainingFlops throws",  code(function () { fp({}); }) === "frontier/bad-value");
  check("negative trainingFlops throws", code(function () { fp({ trainingFlops: -1 }); }) === "frontier/bad-value");
  check("unknown opt throws",            code(function () { fp({ trainingFlops: 1e26, bogus: 1 }); }) === "frontier/bad-opts");
  check("non-object framework throws",   code(function () { fp({ trainingFlops: 5e26, framework: 7 }); }) === "frontier/bad-value");
}

async function run() {
  testSurface();
  testThresholds();
  testFrameworkCheck();
  testIncidentReport();
  testErrors();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[ai-frontier-protocol] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
