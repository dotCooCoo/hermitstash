// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ai.aedtBiasAudit
 * @nav    Compliance
 * @title  AEDT Bias Audit
 *
 * @intro
 *   Compute the bias-audit statistics New York City Local Law 144 requires
 *   before an Automated Employment Decision Tool (AEDT) may be used to screen
 *   candidates or employees. The law (NYC Admin. Code §20-870 et seq., in force
 *   since 2023-07-05; DCWP rules 6 RCNY §5-300 et seq.) requires an independent
 *   annual audit that reports, for each demographic category, the rate at which
 *   the tool selects (or scores above the median for) that group and the
 *   <em>impact ratio</em> — that group's rate divided by the rate of the
 *   most-selected group. An impact ratio below the four-fifths (0.8) threshold
 *   from the EEOC Uniform Guidelines flags potential adverse impact; the law
 *   requires the number to be calculated and published, not any particular
 *   remediation.
 *
 *   The audit is computed across three dimensions: sex, race/ethnicity, and
 *   the intersection of the two, using the EEOC categories. Categories that
 *   make up less than 2% of the audited data may be excluded from the impact-
 *   ratio calculation at the auditor's discretion (DCWP §5-301). This primitive
 *   takes the per-category counts — selected/total for a pass-fail tool, or
 *   scored-above-the-overall-median/total for a continuous-score tool — and
 *   returns the selection (or scoring) rate, impact ratio, and adverse-impact
 *   flag per group, plus the most-selected group and an overall flag. It is a
 *   pure calculation: the operator supplies the data an independent auditor
 *   collected, and gets back the figures the published summary must contain.
 *
 * @card
 *   NYC Local Law 144 AEDT bias audit (`b.ai.aedtBiasAudit`) — selection /
 *   scoring rates and four-fifths-rule impact ratios across sex, race/ethnicity,
 *   and their intersection, with the most-selected group and adverse-impact
 *   flags for the published audit summary.
 */

var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var AedtBiasAuditError = defineClass("AedtBiasAuditError", { alwaysPermanent: true });

var FOUR_FIFTHS = 4 / 5;         // EEOC Uniform Guidelines four-fifths adverse-impact threshold
var DEFAULT_MIN_SHARE = 0.02;    // DCWP §5-301 — categories under 2% may be excluded
var DIMENSIONS = ["sex", "raceEthnicity", "intersectional"];

function _str(v, label) {
  if (typeof v !== "string" || v.length === 0) throw new AedtBiasAuditError("aedt/bad-metadata", "aedtBiasAudit: metadata." + label + " must be a non-empty string");
  return v;
}
function _count(v, label) {
  if (!numericBounds.isNonNegativeFiniteInt(v)) throw new AedtBiasAuditError("aedt/bad-count", "aedtBiasAudit: " + label + " must be a non-negative integer");
  return v;
}

// Reduce one dimension's per-group counts to the LL-144 figures.
function _auditDimension(groups, type, minShare) {
  var names = Object.keys(groups);
  var rows = [];
  var dimensionTotal = 0;
  var numeratorKey = type === "scoring" ? "scoredAboveMedian" : "selected";

  names.forEach(function (name) {
    var g = groups[name];
    if (!g || typeof g !== "object") throw new AedtBiasAuditError("aedt/bad-count", "aedtBiasAudit: group '" + name + "' must be an object with " + numeratorKey + " + total");
    var total = _count(g.total, name + ".total");
    var num = _count(g[numeratorKey], name + "." + numeratorKey);
    if (num > total) throw new AedtBiasAuditError("aedt/bad-count", "aedtBiasAudit: " + name + "." + numeratorKey + " (" + num + ") exceeds total (" + total + ")");
    dimensionTotal += total;
    rows.push({ category: name, total: total, _num: num, rate: total === 0 ? 0 : num / total });
  });

  // Exclude sub-threshold categories (auditor discretion), then find the
  // most-selected group among those that remain.
  var maxRate = 0;
  var mostSelected = null;
  rows.forEach(function (r) {
    r.share = dimensionTotal === 0 ? 0 : r.total / dimensionTotal;
    r.excluded = dimensionTotal > 0 && r.share < minShare;
    if (!r.excluded && r.rate > maxRate) { maxRate = r.rate; mostSelected = r.category; }
  });

  rows.forEach(function (r) {
    r.impactRatio = (r.excluded || maxRate === 0) ? null : r.rate / maxRate;
    r.adverseImpact = r.impactRatio !== null && r.impactRatio < FOUR_FIFTHS;
    delete r._num;
  });
  // Stable order: highest rate first, then category name.
  rows.sort(function (a, b) { return b.rate - a.rate || (a.category < b.category ? -1 : a.category > b.category ? 1 : 0); });
  return { rows: rows, mostSelected: mostSelected };
}

/**
 * @primitive  b.ai.aedtBiasAudit
 * @signature  b.ai.aedtBiasAudit(opts)
 * @since      0.13.5
 * @status     stable
 * @compliance nyc-ll144, soc2
 * @related    b.ai.disclosure.applyAll, b.ai.disclosure.chatbot
 *
 * Compute the NYC Local Law 144 bias-audit figures from per-category counts.
 * <code>type</code> is <code>"selection"</code> for a pass-fail tool (each
 * group entry is <code>{ selected, total }</code>) or <code>"scoring"</code>
 * for a continuous-score tool (<code>{ scoredAboveMedian, total }</code>, where
 * the count is candidates scoring above the <em>overall</em> median). Returns
 * the selection/scoring rate, impact ratio (group rate ÷ most-selected group's
 * rate), and an <code>adverseImpact</code> flag (impact ratio &lt; 0.8) per
 * group, across the <code>sex</code>, <code>raceEthnicity</code>, and
 * <code>intersectional</code> dimensions, plus the most-selected group per
 * dimension. Categories under <code>minCategoryShare</code> (2% by default) are
 * marked <code>excluded</code> and left out of the impact-ratio basis. Throws
 * <code>AedtBiasAuditError</code> on malformed input. The result is the data an
 * employer must publish; the law mandates the calculation, not any remediation.
 *
 * @opts
 *   type:             string,   // "selection" | "scoring" (required)
 *   metadata:         object,   // { tool, auditor, auditDate, distributionDate? } (tool/auditor/auditDate required)
 *   categories:       object,   // { sex?, raceEthnicity?, intersectional? } → { <group>: { selected|scoredAboveMedian, total } }
 *   minCategoryShare: number,   // default: 0.02 (DCWP §5-301 — sub-2% categories may be excluded)
 *
 * @example
 *   var report = b.ai.aedtBiasAudit({
 *     type: "selection",
 *     metadata: { tool: "ResumeRanker v3", auditor: "Acme Audit LLC", auditDate: "2026-05-26" },
 *     categories: { sex: { Male: { selected: 60, total: 100 }, Female: { selected: 42, total: 100 } } },
 *   });
 *   report.results.sex[1].impactRatio;   // → 0.7  (Female: 42% / 60%)
 *   report.results.sex[1].adverseImpact; // → true (below the 0.8 four-fifths threshold)
 */
function aedtBiasAudit(opts) {
  opts = opts || {};
  // Surface an unknown/typoed option as this primitive's own error type rather
  // than the generic Error validateOpts throws, so the malformed-input contract
  // (AedtBiasAuditError / e.code) holds for every bad-config path.
  try { validateOpts(opts, ["type", "metadata", "categories", "minCategoryShare"], "aedtBiasAudit"); }
  catch (e) { throw new AedtBiasAuditError("aedt/bad-opts", e && e.message || "aedtBiasAudit: invalid options"); }
  if (opts.type !== "selection" && opts.type !== "scoring") throw new AedtBiasAuditError("aedt/bad-type", "aedtBiasAudit: type must be 'selection' or 'scoring'");

  var md = opts.metadata || {};
  var metadata = {
    tool:             _str(md.tool, "tool"),
    auditor:          _str(md.auditor, "auditor"),
    auditDate:        _str(md.auditDate, "auditDate"),
    distributionDate: md.distributionDate != null ? _str(md.distributionDate, "distributionDate") : null,
  };

  var minShare = opts.minCategoryShare != null ? opts.minCategoryShare : DEFAULT_MIN_SHARE;
  if (typeof minShare !== "number" || !isFinite(minShare) || minShare < 0 || minShare >= 1) throw new AedtBiasAuditError("aedt/bad-share", "aedtBiasAudit: minCategoryShare must be a number in [0, 1)");

  var cats = opts.categories || {};
  var present = DIMENSIONS.filter(function (d) { return cats[d] && typeof cats[d] === "object" && Object.keys(cats[d]).length > 0; });
  if (present.length === 0) throw new AedtBiasAuditError("aedt/no-categories", "aedtBiasAudit: at least one of sex / raceEthnicity / intersectional must carry group counts");

  var results = {};
  var mostSelected = {};
  var adverseImpactGroups = [];
  present.forEach(function (dim) {
    var out = _auditDimension(cats[dim], opts.type, minShare);
    results[dim] = out.rows;
    mostSelected[dim] = out.mostSelected;
    out.rows.forEach(function (r) { if (r.adverseImpact) adverseImpactGroups.push({ dimension: dim, category: r.category, impactRatio: r.impactRatio }); });
  });

  return {
    type:     opts.type,
    metadata: metadata,
    results:  results,
    summary:  {
      mostSelected:        mostSelected,
      adverseImpactGroups: adverseImpactGroups,
      anyAdverseImpact:    adverseImpactGroups.length > 0,
      fourFifthsThreshold: FOUR_FIFTHS,
    },
  };
}

aedtBiasAudit.FOUR_FIFTHS = FOUR_FIFTHS;
aedtBiasAudit.AedtBiasAuditError = AedtBiasAuditError;

module.exports = aedtBiasAudit;
