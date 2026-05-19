"use strict";
/**
 * b.mail.spamScore — operator-supplied spam-scorer facade.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var mailSpamScore = require("../../lib/mail-spam-score");

function _fakeAudit() {
  var emitted = [];
  return {
    emitted: emitted,
    safeEmit: function (rec) { emitted.push(rec); },
  };
}

function _scorer(score, reasons) {
  return function (_ctx) {
    return Promise.resolve({ score: score, reasons: reasons || [] });
  };
}

function testSurface() {
  check("create is fn",                   typeof mailSpamScore.create === "function");
  check("compliancePosture is fn",        typeof mailSpamScore.compliancePosture === "function");
  check("MailSpamScoreError is fn",       typeof mailSpamScore.MailSpamScoreError === "function");
  check("PROFILES.strict threshold 5.0",  mailSpamScore.PROFILES.strict.threshold === 5.0);
  check("PROFILES.balanced threshold 7.5", mailSpamScore.PROFILES.balanced.threshold === 7.5);
  check("PROFILES.permissive threshold 10.0",
    mailSpamScore.PROFILES.permissive.threshold === 10.0);
  check("posture hipaa → strict", mailSpamScore.compliancePosture("hipaa") === "strict");
}

function expectThrow(label, fn, expectedCodePrefix) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && typeof threw.code === "string" &&
    threw.code.indexOf(expectedCodePrefix) === 0);
}

function testRefuseMissingScorer() {
  expectThrow("refuses missing scorer",
    function () { mailSpamScore.create({}); },
    "mail-spam-score/bad-scorer");
}

function testRefuseBadScorerType() {
  expectThrow("refuses scorer not-a-fn",
    function () { mailSpamScore.create({ scorer: "not-a-fn" }); },
    "mail-spam-score/bad-scorer");
}

function testRefuseBadProfile() {
  expectThrow("refuses unknown profile",
    function () { mailSpamScore.create({ scorer: _scorer(0), profile: "loose" }); },
    "mail-spam-score/bad-profile");
}

function testRefuseBadThreshold() {
  expectThrow("refuses non-finite threshold",
    function () { mailSpamScore.create({ scorer: _scorer(0), threshold: Infinity }); },
    "mail-spam-score/bad-threshold");
  expectThrow("refuses NaN threshold",
    function () { mailSpamScore.create({ scorer: _scorer(0), threshold: NaN }); },
    "mail-spam-score/bad-threshold");
  expectThrow("refuses string threshold",
    function () { mailSpamScore.create({ scorer: _scorer(0), threshold: "5" }); },
    "mail-spam-score/bad-threshold");
}

function testRefuseUnknownOpt() {
  var threw = null;
  try { mailSpamScore.create({ scorer: _scorer(0), bogus: 1 }); }
  catch (e) { threw = e; }
  check("refuses unknown opt", threw && /unknown option/i.test(threw.message || ""));
}

function testHandleSurface() {
  var h = mailSpamScore.create({ scorer: _scorer(0) });
  check("handle.score is fn",       typeof h.score === "function");
  check("handle.threshold 5.0",     h.threshold === 5.0);
  check("handle.profile strict",    h.profile === "strict");
}

async function testScoreBelowThresholdAccepts() {
  var audit = _fakeAudit();
  var h = mailSpamScore.create({ scorer: _scorer(3.2, ["BAYES_50"]), audit: audit });
  var rv = await h.score({ rawBytes: Buffer.from("body") });
  check("score 3.2 below 5.0 → accept", rv.verdict === "accept");
  check("score value preserved",         rv.score === 3.2);
  check("reasons preserved",             rv.reasons[0] === "BAYES_50");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.spam_score.score",
    seen.indexOf("mail.spam_score.score") !== -1);
  check("audit emitted mail.spam_score.accept",
    seen.indexOf("mail.spam_score.accept") !== -1);
}

async function testScoreEqualsThresholdScoreTags() {
  // strict threshold = 5.0; exact match should be "score-tag" verdict.
  var audit = _fakeAudit();
  var h = mailSpamScore.create({ scorer: _scorer(5.0, ["EXACT_MATCH"]), audit: audit });
  var rv = await h.score({ rawBytes: Buffer.from("body") });
  check("score === threshold → score-tag",  rv.verdict === "score-tag");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.spam_score.score_tag",
    seen.indexOf("mail.spam_score.score_tag") !== -1);
}

async function testScoreAboveThresholdRefuses() {
  var audit = _fakeAudit();
  var h = mailSpamScore.create({ scorer: _scorer(8.7, ["BAYES_99", "URIBL_RED"]), audit: audit });
  var rv = await h.score({ rawBytes: Buffer.from("body") });
  check("score 8.7 above 5.0 → refuse", rv.verdict === "refuse");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.spam_score.refuse",
    seen.indexOf("mail.spam_score.refuse") !== -1);
}

async function testScorerReturnsNanScoreRefused() {
  var h = mailSpamScore.create({ scorer: _scorer(NaN) });
  var threw = null;
  try { await h.score({ rawBytes: Buffer.from("body") }); } catch (e) { threw = e; }
  check("scorer NaN score → refused", threw && threw.code === "mail-spam-score/bad-score");
}

async function testScorerThrowsBubblesError() {
  var audit = _fakeAudit();
  var h = mailSpamScore.create({
    scorer: function () { throw new Error("scorer down"); },
    audit:  audit,
  });
  var threw = null;
  try { await h.score({ rawBytes: Buffer.from("body") }); } catch (e) { threw = e; }
  check("scorer throw → wrapped as mail-spam-score/scorer-threw",
    threw && threw.code === "mail-spam-score/scorer-threw");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.spam_score.error",
    seen.indexOf("mail.spam_score.error") !== -1);
}

async function testRefuseControlByteInReason() {
  // Compromised scorer tries to smuggle CRLF into a reason tag.
  var h = mailSpamScore.create({ scorer: _scorer(3.0, ["GOOD\r\nX-Inject: bad"]) });
  var threw = null;
  try { await h.score({ rawBytes: Buffer.from("body") }); } catch (e) { threw = e; }
  check("CRLF in reason refused",
    threw && threw.code === "mail-spam-score/control-byte");
}

async function testRefuseOversizeReason() {
  var huge = new Array(300).join("X");                                                             // 299 chars > 256-byte cap
  var h = mailSpamScore.create({ scorer: _scorer(3.0, [huge]) });
  var threw = null;
  try { await h.score({ rawBytes: Buffer.from("body") }); } catch (e) { threw = e; }
  check("oversize reason refused",
    threw && threw.code === "mail-spam-score/oversize-reason");
}

async function testRefuseTooManyReasons() {
  var many = [];
  for (var i = 0; i < 50; i += 1) many.push("R" + i);
  var h = mailSpamScore.create({ scorer: _scorer(3.0, many) });
  var threw = null;
  try { await h.score({ rawBytes: Buffer.from("body") }); } catch (e) { threw = e; }
  check("too-many reasons refused",
    threw && threw.code === "mail-spam-score/too-many-reasons");
}

async function testCustomThresholdHonored() {
  var h = mailSpamScore.create({ scorer: _scorer(3.0), threshold: 1.5 });
  var rv = await h.score({ rawBytes: Buffer.from("body") });
  check("score 3.0 above custom 1.5 → refuse", rv.verdict === "refuse");
  check("handle.threshold reflects custom",     h.threshold === 1.5);
}

function run() {
  testSurface();
  testRefuseMissingScorer();
  testRefuseBadScorerType();
  testRefuseBadProfile();
  testRefuseBadThreshold();
  testRefuseUnknownOpt();
  testHandleSurface();

  return Promise.resolve()
    .then(testScoreBelowThresholdAccepts)
    .then(testScoreEqualsThresholdScoreTags)
    .then(testScoreAboveThresholdRefuses)
    .then(testScorerReturnsNanScoreRefused)
    .then(testScorerThrowsBubblesError)
    .then(testRefuseControlByteInReason)
    .then(testRefuseOversizeReason)
    .then(testRefuseTooManyReasons)
    .then(testCustomThresholdHonored);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[mail-spam-score] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}
