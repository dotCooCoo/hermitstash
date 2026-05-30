"use strict";
/**
 * b.auditDailyReview — PCI DSS 4.0 Req 10.4.1.1 daily-review primitive.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeAudit(rows) {
  var emitted = [];
  return {
    safeEmit: function (event) { emitted.push(event); },
    query:    async function () { return rows.slice(); },
    _emitted: emitted,
  };
}

function testSurface() {
  check("auditDailyReview.create is a function",
        typeof b.auditDailyReview.create === "function");
  check("frameworkError.AuditDailyReviewError exposed",
        typeof b.frameworkError.AuditDailyReviewError === "function");
  check("auditDailyReview.AuditDailyReviewError is fn",
        typeof b.auditDailyReview.AuditDailyReviewError === "function");
  check("SEVERITY_ORDER includes critical",
        b.auditDailyReview.SEVERITY_ORDER.indexOf("critical") !== -1);
}

async function testRunSummary() {
  var rows = [
    { action: "auth.login.success",        outcome: "success", recordedAt: Date.now() },
    { action: "auth.login.failed",         outcome: "failure", recordedAt: Date.now() },
    { action: "honeytoken.tripped",        outcome: "denied",  recordedAt: Date.now() },
    { action: "ato.killSwitch.tripped",    outcome: "denied",  recordedAt: Date.now() },
    { action: "subject.export",            outcome: "success", recordedAt: Date.now() },
  ];
  var fakeAudit = _fakeAudit(rows);
  var review = b.auditDailyReview.create({
    audit:             fakeAudit,
    severityThreshold: "warning",
    notify:            null,
  });
  var summary = await review.run();
  check("run returns totalEvents = 5",            summary.totalEvents === 5);
  check("classify alert hit",                      summary.bySeverity.alert >= 1);
  check("classify critical hit",                   summary.bySeverity.critical >= 1);
  check("byOutcome.success counted",               summary.byOutcome.success >= 2);
  check("thresholdHits >= 3 (warning+)",           summary.hitCount >= 3);
  check("review.lastRun returns the same summary", review.lastRun().totalEvents === 5);
  check("audit.daily_review.completed emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "audit.daily_review.completed"; }));
}

async function testNotifyTriggered() {
  var notified = null;
  var rows = [
    { action: "auth.failed", outcome: "failure", recordedAt: Date.now() },
  ];
  var fakeAudit = _fakeAudit(rows);
  var review = b.auditDailyReview.create({
    audit: fakeAudit,
    severityThreshold: "alert",
    notify: function (summary) { notified = summary; return Promise.resolve(); },
  });
  await review.run();
  check("notify was triggered with summary",
        notified !== null && typeof notified.totalEvents === "number");
  check("audit.daily_review.notified emitted",
        fakeAudit._emitted.some(function (e) { return e.action === "audit.daily_review.notified"; }));
}

function testPostureRequiresNotify() {
  var fakeAudit = _fakeAudit([]);
  var threw = null;
  try {
    b.auditDailyReview.create({
      audit: fakeAudit,
      posture: "pci-dss",
      // notify intentionally omitted
    });
  } catch (e) { threw = e; }
  check("pci-dss posture without notify throws",
        threw && /notify-required-under-posture/.test(threw.code || ""));

  // sox-404 (SOX §404 ICFR — the audit/internal-controls regime this
  // primitive serves) is an advertised notify-required posture too.
  var threw404 = null;
  try {
    b.auditDailyReview.create({ audit: _fakeAudit([]), posture: "sox-404" });
  } catch (e) { threw404 = e; }
  check("sox-404 posture without notify throws",
        threw404 && /notify-required-under-posture/.test(threw404.code || ""));
}

function testBadSeverity() {
  var fakeAudit = _fakeAudit([]);
  var threw = null;
  try {
    b.auditDailyReview.create({
      audit: fakeAudit, severityThreshold: "bogus",
    });
  } catch (e) { threw = e; }
  check("bad severityThreshold throws",
        threw && /bad-severity/.test(threw.code || ""));
}

async function testNotifyFailure() {
  var rows = [
    { action: "auth.failed", outcome: "failure", recordedAt: Date.now() },
  ];
  var fakeAudit = _fakeAudit(rows);
  var review = b.auditDailyReview.create({
    audit: fakeAudit,
    severityThreshold: "warning",
    notify: function () { return Promise.reject(new Error("smtp-down")); },
  });
  // run() should NOT throw — notify failure is non-fatal.
  var summary = await review.run();
  check("run survives notify failure", typeof summary.totalEvents === "number");
  check("audit.daily_review.notify_failed emitted",
        fakeAudit._emitted.some(function (e) {
          return e.action === "audit.daily_review.notify_failed";
        }));
}

async function run() {
  testSurface();
  await testRunSummary();
  await testNotifyTriggered();
  testPostureRequiresNotify();
  testBadSeverity();
  await testNotifyFailure();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
