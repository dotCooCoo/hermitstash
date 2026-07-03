// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.dsa — EU Digital Services Act (Reg 2022/2065) record-builders:
// Art. 16 noticeAndAction, Art. 17 statementOfReasons, Art. 15/24(3)
// transparencyReport. Pure builders (no DB); audit emission is captured
// by swapping b.audit.safeEmit for the duration of each assertion.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Capture the audit events a builder emits. b.dsa resolves its audit
// sink via require("./audit"), the same module object as b.audit, so
// swapping b.audit.safeEmit intercepts the emission. Always restore in a
// finally so a thrown assertion can't leak the stub.
function captureAudit(fn) {
  var events = [];
  var orig = b.audit.safeEmit;
  b.audit.safeEmit = function (ev) { events.push(ev); };
  try { fn(events); }
  finally { b.audit.safeEmit = orig; }
  return events;
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
  // ---- surface ----
  check("noticeAndAction is a function",         typeof b.dsa.noticeAndAction === "function");
  check("statementOfReasons is a function",      typeof b.dsa.statementOfReasons === "function");
  check("transparencyReport is a function",      typeof b.dsa.transparencyReport === "function");
  check("listTransparencyMetrics is a function", typeof b.dsa.listTransparencyMetrics === "function");
  check("DsaError exposed on b.frameworkError",  typeof b.frameworkError.DsaError === "function");
  check("b.dsa.DsaError is the same constructor", b.dsa.DsaError === b.frameworkError.DsaError);

  // ===== Art. 16 — noticeAndAction =====
  var submittedAt = 1700000000000;
  var nEvents = captureAudit(function () {
    var n = b.dsa.noticeAndAction({
      contentId:     "post-9931",
      noticeType:    "illegal-content",
      reason:        "Depicts a sale prohibited under national law.",
      submittedAt:   submittedAt,
      submitterType: "trusted-flagger",
    });
    check("notice: record frozen",                Object.isFrozen(n));
    check("notice: status recorded",              n.status === "recorded");
    check("notice: default noticeId derived",     n.noticeId === "dsa-notice-" + submittedAt);
    check("notice: actionDueBy = submittedAt+24h", n.actionDueBy === submittedAt + b.constants.TIME.hours(24));
    check("notice: illegal-content requires SoR",  n.statementOfReasonsRequired === true);
  });
  check("notice: emitted one audit event",        nEvents.length === 1);
  check("notice: audit action dsa.notice.recorded", nEvents[0] && nEvents[0].action === "dsa.notice.recorded");
  check("notice: audit metadata carries contentId", nEvents[0] && nEvents[0].metadata.contentId === "post-9931");

  var nTerms = b.dsa.noticeAndAction({
    contentId: "post-1", noticeType: "terms-violation", reason: "Breaches guidelines.",
    submittedAt: submittedAt, submitterType: "individual",
    noticeId: "op-77", actionWindowMs: b.constants.TIME.hours(48),
  });
  check("notice: terms-violation no SoR",       nTerms.statementOfReasonsRequired === false);
  check("notice: explicit noticeId honored",    nTerms.noticeId === "op-77");
  check("notice: explicit actionWindow honored", nTerms.actionDueBy === submittedAt + b.constants.TIME.hours(48));

  expectCode("notice: non-object opts throws",
    function () { b.dsa.noticeAndAction("nope"); }, "dsa/bad-opts");
  expectThrows("notice: unknown opt key throws",
    function () { b.dsa.noticeAndAction({ contentId: "c", noticeType: "other", reason: "r", submittedAt: submittedAt, submitterType: "individual", bogus: 1 }); });
  expectCode("notice: missing contentId throws",
    function () { b.dsa.noticeAndAction({ noticeType: "other", reason: "r", submittedAt: submittedAt, submitterType: "individual" }); }, "dsa/bad-content-id");
  expectCode("notice: unknown noticeType throws",
    function () { b.dsa.noticeAndAction({ contentId: "c", noticeType: "wat", reason: "r", submittedAt: submittedAt, submitterType: "individual" }); }, "dsa/unknown-notice-type");
  expectCode("notice: missing submittedAt throws",
    function () { b.dsa.noticeAndAction({ contentId: "c", noticeType: "other", reason: "r", submitterType: "individual" }); }, "dsa/bad-submitted-at");
  expectCode("notice: unknown submitterType throws",
    function () { b.dsa.noticeAndAction({ contentId: "c", noticeType: "other", reason: "r", submittedAt: submittedAt, submitterType: "robot" }); }, "dsa/unknown-submitter-type");

  // ===== Art. 17 — statementOfReasons =====
  var sEvents = captureAudit(function () {
    var s = b.dsa.statementOfReasons({
      contentId: "post-9931", decision: "content-removed",
      legalGround: "National law prohibiting the depicted sale.",
      facts: "Listing offered a prohibited item for sale.", automated: false,
      redressOptions: ["internal-complaint", "judicial-redress"], noticeId: "dsa-notice-" + submittedAt,
    });
    check("sor: record frozen",            Object.isFrozen(s));
    check("sor: default sorId derived",    /^dsa-sor-\d+$/.test(s.sorId));
    check("sor: groundType legal",         s.groundType === "legal");
    check("sor: contractualGround null",   s.contractualGround === null);
    check("sor: redressOptions frozen",    Object.isFrozen(s.redressOptions) && s.redressOptions.length === 2);
    check("sor: noticeId linked",          s.noticeId === "dsa-notice-" + submittedAt);
  });
  check("sor: emitted one audit event",    sEvents.length === 1);
  check("sor: audit action dsa.sor.recorded", sEvents[0] && sEvents[0].action === "dsa.sor.recorded");

  var sC = b.dsa.statementOfReasons({
    contentId: "post-2", decision: "account-suspended",
    contractualGround: "Terms section 4.2 — repeated spam.", facts: "Five spam posts in 24h.",
    automated: true, redressOptions: ["internal-complaint"],
  });
  check("sor: groundType contractual", sC.groundType === "contractual");
  check("sor: legalGround null",       sC.legalGround === null);
  check("sor: automated true",         sC.automated === true);

  expectCode("sor: unknown decision throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "nuke", legalGround: "x", facts: "f", automated: false, redressOptions: ["internal-complaint"] }); }, "dsa/unknown-decision");
  expectCode("sor: non-boolean automated throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "no-action", legalGround: "x", facts: "f", automated: "no", redressOptions: ["internal-complaint"] }); }, "dsa/bad-automated");
  expectCode("sor: neither ground throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "no-action", facts: "f", automated: false, redressOptions: ["internal-complaint"] }); }, "dsa/ground-required");
  expectCode("sor: both grounds throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "no-action", legalGround: "x", contractualGround: "y", facts: "f", automated: false, redressOptions: ["internal-complaint"] }); }, "dsa/ground-required");
  expectCode("sor: empty redressOptions throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "content-removed", legalGround: "x", facts: "f", automated: false, redressOptions: [] }); }, "dsa/redress-required");
  expectCode("sor: unknown redress option throws",
    function () { b.dsa.statementOfReasons({ contentId: "c", decision: "content-removed", legalGround: "x", facts: "f", automated: false, redressOptions: ["call-the-mayor"] }); }, "dsa/unknown-redress-option");

  // ===== Art. 15 / 24(3) — transparencyReport =====
  var metricNames = b.dsa.listTransparencyMetrics();
  check("metrics: frozen list", Array.isArray(metricNames) && Object.isFrozen(metricNames));
  check("metrics: includes noticesReceived", metricNames.indexOf("noticesReceived") !== -1);

  var period = { from: Date.UTC(2025, 0, 1), to: Date.UTC(2025, 11, 31) };
  var rEvents = captureAudit(function () {
    var r = b.dsa.transparencyReport({
      period: period,
      metrics: { noticesReceived: 1200, actionsTaken: 940, automatedDecisions: 610, appeals: 75 },
      service: "example-platform",
    });
    check("report: record frozen",            Object.isFrozen(r));
    check("report: metrics frozen",           Object.isFrozen(r.metrics));
    check("report: period frozen",            Object.isFrozen(r.period));
    check("report: supplied metric carried",  r.metrics.noticesReceived === 1200);
    check("report: omitted metric defaults 0", r.metrics.statementsOfReasons === 0);
    check("report: all metric fields present", metricNames.every(function (m) { return typeof r.metrics[m] === "number"; }));
    check("report: default reportId derived", r.reportId === "dsa-transparency-" + period.to);
    check("report: nextReportDueBy = to+365d", r.nextReportDueBy === period.to + b.constants.TIME.days(365));
  });
  check("report: emitted one audit event",        rEvents.length === 1);
  check("report: audit action transparency event", rEvents[0] && rEvents[0].action === "dsa.transparency_report.generated");
  check("report: audit metadata actionsTaken",    rEvents[0] && rEvents[0].metadata.actionsTaken === 940);

  expectCode("report: missing period throws",
    function () { b.dsa.transparencyReport({ metrics: {} }); }, "dsa/bad-period");
  expectCode("report: from >= to throws",
    function () { b.dsa.transparencyReport({ period: { from: period.to, to: period.from } }); }, "dsa/bad-period-order");
  expectCode("report: unknown metric key throws",
    function () { b.dsa.transparencyReport({ period: period, metrics: { bogusMetric: 1 } }); }, "dsa/unknown-metric");
  expectCode("report: negative metric throws",
    function () { b.dsa.transparencyReport({ period: period, metrics: { appeals: -3 } }); }, "dsa/bad-metric-value");
  expectCode("report: non-integer metric throws",
    function () { b.dsa.transparencyReport({ period: period, metrics: { appeals: 2.5 } }); }, "dsa/bad-metric-value");
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[dsa] OK"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
