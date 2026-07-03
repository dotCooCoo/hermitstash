// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.ai.aedtBiasAudit (NYC Local Law 144 AEDT bias audit).
 *
 * Oracle: the EEOC four-fifths rule and the DCWP §5-300 impact-ratio formula.
 * The canonical worked example — a tool passing 60% of men and 42% of women —
 * yields an impact ratio of 42/60 = 0.70 for women, below the 0.8 threshold.
 * Boundary, scoring-rate, intersectional, sub-2% exclusion, and the
 * most-selected basis are each asserted against the formula.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function row(report, dim, cat) { return report.results[dim].filter(function (r) { return r.category === cat; })[0]; }

var MD = { tool: "ResumeRanker v3", auditor: "Acme Audit LLC", auditDate: "2026-05-26" };

function testSurface() {
  check("b.ai.aedtBiasAudit is a function", typeof b.ai.aedtBiasAudit === "function");
  check("b.ai.aedtBiasAudit.FOUR_FIFTHS is 0.8", b.ai.aedtBiasAudit.FOUR_FIFTHS === 0.8);
  check("b.ai.aedtBiasAudit.AedtBiasAuditError is a class", typeof b.ai.aedtBiasAudit.AedtBiasAuditError === "function");
}

function testFourFifthsWorkedExample() {
  var r = b.ai.aedtBiasAudit({
    type: "selection",
    metadata: MD,
    categories: { sex: { Male: { selected: 60, total: 100 }, Female: { selected: 42, total: 100 } } },
  });
  var f = row(r, "sex", "Female"), m = row(r, "sex", "Male");
  check("Female selection rate 0.42", f.rate === 0.42);
  check("Female impact ratio 0.70 (42/60)", Math.abs(f.impactRatio - 0.7) < 1e-9);
  check("Female flagged adverse (< 0.8)", f.adverseImpact === true);
  check("Male is the most-selected (ratio 1)", m.impactRatio === 1 && m.adverseImpact === false);
  check("most-selected sex group is Male", r.summary.mostSelected.sex === "Male");
  check("anyAdverseImpact true", r.summary.anyAdverseImpact === true);
  check("adverseImpactGroups names Female", r.summary.adverseImpactGroups.length === 1 && r.summary.adverseImpactGroups[0].category === "Female");
  check("metadata echoed", r.metadata.tool === MD.tool && r.metadata.auditor === MD.auditor && r.metadata.distributionDate === null);
}

function testFourFifthsBoundary() {
  // Exactly 0.80 is NOT adverse (strictly-less-than threshold); 0.79 is.
  var at = b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { X: { selected: 100, total: 100 }, Y: { selected: 80, total: 100 } } } });
  check("impact ratio exactly 0.80 is not adverse", row(at, "sex", "Y").adverseImpact === false);
  var below = b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { X: { selected: 100, total: 100 }, Y: { selected: 79, total: 100 } } } });
  check("impact ratio 0.79 is adverse", row(below, "sex", "Y").adverseImpact === true);
}

function testScoringRate() {
  // Scoring tools: rate = scored-above-overall-median / total.
  var r = b.ai.aedtBiasAudit({ type: "scoring", metadata: MD, categories: { sex: { M: { scoredAboveMedian: 50, total: 100 }, F: { scoredAboveMedian: 30, total: 100 } } } });
  check("scoring rate F 0.30", row(r, "sex", "F").rate === 0.3);
  check("scoring impact ratio F 0.60 (30/50)", Math.abs(row(r, "sex", "F").impactRatio - 0.6) < 1e-9);
}

function testIntersectionalAndRace() {
  var r = b.ai.aedtBiasAudit({
    type: "selection",
    metadata: MD,
    categories: {
      raceEthnicity: { "White": { selected: 80, total: 100 }, "Black or African American": { selected: 48, total: 100 } },
      intersectional: { "Male - White": { selected: 90, total: 100 }, "Female - Black or African American": { selected: 45, total: 100 } },
    },
  });
  check("race dimension computed", row(r, "raceEthnicity", "Black or African American").impactRatio === 0.6);
  check("intersectional dimension computed", row(r, "intersectional", "Female - Black or African American").impactRatio === 0.5);
  check("intersectional adverse flagged", row(r, "intersectional", "Female - Black or African American").adverseImpact === true);
}

function testSubTwoPercentExclusion() {
  var r = b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { Big: { selected: 90, total: 1000 }, Tiny: { selected: 0, total: 10 } } } });
  check("sub-2% category excluded", row(r, "sex", "Tiny").excluded === true);
  check("excluded category has null impact ratio", row(r, "sex", "Tiny").impactRatio === null);
  check("excluded category not flagged adverse", row(r, "sex", "Tiny").adverseImpact === false);
  // A higher minCategoryShare excludes more.
  var r2 = b.ai.aedtBiasAudit({ type: "selection", metadata: MD, minCategoryShare: 0, categories: { sex: { Big: { selected: 90, total: 1000 }, Tiny: { selected: 0, total: 10 } } } });
  check("minCategoryShare 0 includes Tiny", row(r2, "sex", "Tiny").excluded === false);
}

function testErrors() {
  check("bad type throws",        code(function () { b.ai.aedtBiasAudit({ type: "x", metadata: MD, categories: { sex: { M: { selected: 1, total: 1 } } } }); }) === "aedt/bad-type");
  check("missing metadata throws", code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: {}, categories: { sex: { M: { selected: 1, total: 1 } } } }); }) === "aedt/bad-metadata");
  check("no categories throws",    code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: {} }); }) === "aedt/no-categories");
  check("selected > total throws", code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { M: { selected: 5, total: 2 } } } }); }) === "aedt/bad-count");
  check("negative count throws",   code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { M: { selected: -1, total: 2 } } } }); }) === "aedt/bad-count");
  check("bad minCategoryShare throws", code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, minCategoryShare: 1, categories: { sex: { M: { selected: 1, total: 1 } } } }); }) === "aedt/bad-share");
  // A typoed/unknown option must surface as AedtBiasAuditError (not a generic
  // Error from validateOpts), so e.code / instanceof handling is reliable.
  check("unknown opt throws aedt/bad-opts", code(function () { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { M: { selected: 1, total: 1 } } }, minCategoryshare: 0.01 }); }) === "aedt/bad-opts");
  var threw = null;
  try { b.ai.aedtBiasAudit({ type: "selection", metadata: MD, categories: { sex: { M: { selected: 1, total: 1 } } }, bogus: 1 }); } catch (e) { threw = e; }
  check("unknown opt error is an AedtBiasAuditError", threw instanceof b.ai.aedtBiasAudit.AedtBiasAuditError);
}

async function run() {
  testSurface();
  testFourFifthsWorkedExample();
  testFourFifthsBoundary();
  testScoringRate();
  testIntersectionalAndRace();
  testSubTwoPercentExclusion();
  testErrors();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[ai-aedt-bias-audit] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
