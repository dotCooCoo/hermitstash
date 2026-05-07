"use strict";
/**
 * b.compliance.eaa — EU Accessibility Act declared-conformance.
 *
 * Directive (EU) 2019/882 (the European Accessibility Act) requires
 * digital products + services placed on the EU market to meet WCAG
 * 2.1 AA accessibility requirements (extended to 2.2 by national
 * implementing law in many member states). Operators producing a
 * compliant deployment ship a "conformance statement" — a document
 * declaring the product, the assessed standards (WCAG 2.1 / 2.2 /
 * EN 301 549), the scope of testing, and any non-conforming
 * features with operator-supplied justification.
 *
 *   var eaa = b.compliance.eaa.create({
 *     audit:        b.audit,
 *     productName:  "Acme Customer Portal",
 *     productScope: "https://portal.acme.example",
 *     standards:    ["WCAG 2.2 AA", "EN 301 549 v3.2.1"],
 *   });
 *   eaa.declareCriterion("1.1.1", { conformance: "supports", note: "..." });
 *   eaa.declareCriterion("1.4.3", { conformance: "supports", note: "ratio >= 4.5:1" });
 *   eaa.declareNonConformance({
 *     criterion: "2.5.5",
 *     reason:    "legacy desktop-only interaction, replacement Q3 2026",
 *     mitigation: "alternative keyboard path documented",
 *   });
 *   var doc = eaa.export({ format: "markdown" });
 *
 * The exported document goes alongside the operator's product
 * documentation and serves as the "Accessibility Statement" required
 * by Article 13 §3.
 */

var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var audit = lazyRequire(function () { return require("./audit"); });

var ComplianceEaaError = defineClass("ComplianceEaaError", { alwaysPermanent: true });

var VALID_CONFORMANCE = Object.freeze({
  "supports":          1,                                                                // criterion fully met
  "partially-supports": 1,                                                               // some content meets, gaps documented
  "does-not-support":  1,                                                                // criterion not met (declared non-conformance)
  "not-applicable":    1,                                                                // criterion does not apply to product
  "not-evaluated":     1,                                                                // outside the assessed scope
});

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "productName", "productScope", "standards",
    "contact", "supervisoryAuthority", "now",
  ], "compliance.eaa");

  validateOpts.requireNonEmptyString(opts.productName,
    "compliance.eaa.create: opts.productName is required (Article 13 §3 requires product identification)",
    ComplianceEaaError, "compliance-eaa/bad-product");
  if (!Array.isArray(opts.standards) || opts.standards.length === 0) {
    throw new ComplianceEaaError("compliance-eaa/bad-standards",
      "compliance.eaa.create: opts.standards is required (e.g. ['WCAG 2.2 AA', 'EN 301 549 v3.2.1'])");
  }
  var productName = opts.productName;
  var productScope = opts.productScope || null;
  var standards = opts.standards.slice();
  var contact = opts.contact || null;
  var supervisoryAuthority = opts.supervisoryAuthority || null;
  var auditOn = opts.audit !== false;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  var criteria = new Map();
  var nonConformances = [];

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "compliance.eaa." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function declareCriterion(id, decl) {
    if (typeof id !== "string" || id.length === 0) {
      throw new ComplianceEaaError("compliance-eaa/bad-criterion-id",
        "compliance.eaa.declareCriterion: id must be a non-empty string (e.g. '1.1.1')");
    }
    if (!decl || typeof decl !== "object") {
      throw new ComplianceEaaError("compliance-eaa/bad-decl",
        "compliance.eaa.declareCriterion: decl must be an object with { conformance, note? }");
    }
    if (!VALID_CONFORMANCE[decl.conformance]) {
      throw new ComplianceEaaError("compliance-eaa/bad-conformance",
        "compliance.eaa.declareCriterion: conformance must be one of " + Object.keys(VALID_CONFORMANCE).join(", "));
    }
    criteria.set(id, {
      criterion:   id,
      conformance: decl.conformance,
      note:        decl.note || "",
      declaredAt:  now(),
    });
    _emitAudit("criterion_declared", "success", { criterion: id, conformance: decl.conformance });
  }

  function declareNonConformance(decl) {
    if (!decl || typeof decl !== "object" || !decl.criterion || !decl.reason) {
      throw new ComplianceEaaError("compliance-eaa/bad-non-conformance",
        "compliance.eaa.declareNonConformance: decl must include { criterion, reason, mitigation? }");
    }
    nonConformances.push({
      criterion:   decl.criterion,
      reason:      decl.reason,
      mitigation:  decl.mitigation || null,
      declaredAt:  now(),
    });
    criteria.set(decl.criterion, {
      criterion:   decl.criterion,
      conformance: "does-not-support",
      note:        decl.reason + (decl.mitigation ? " (mitigation: " + decl.mitigation + ")" : ""),
      declaredAt:  now(),
    });
    _emitAudit("non_conformance_declared", "warning", { criterion: decl.criterion });
  }

  function _stats() {
    var counts = { supports: 0, "partially-supports": 0, "does-not-support": 0, "not-applicable": 0, "not-evaluated": 0 };
    criteria.forEach(function (c) { counts[c.conformance] += 1; });
    return counts;
  }

  function _exportJson() {
    var c = []; criteria.forEach(function (rec) { c.push(rec); });
    return {
      directive:            "(EU) 2019/882",
      article:              "13",
      generatedAt:          new Date(now()).toISOString(),
      product:              { name: productName, scope: productScope },
      standards:            standards,
      contact:              contact,
      supervisoryAuthority: supervisoryAuthority,
      criteria:             c,
      nonConformances:      nonConformances,
      stats:                _stats(),
    };
  }
  function _exportMarkdown() {
    var stats = _stats();
    var c = []; criteria.forEach(function (rec) { c.push(rec); });
    var md = "# Accessibility Statement — " + productName + "\n\n";
    md += "**Standards:** " + standards.join(", ") + "\n\n";
    if (productScope) md += "**Scope:** " + productScope + "\n\n";
    md += "Generated: " + new Date(now()).toISOString() + "\n\n";
    md += "## Conformance summary\n\n";
    md += "- Supports: " + stats.supports + "\n";
    md += "- Partially supports: " + stats["partially-supports"] + "\n";
    md += "- Does not support: " + stats["does-not-support"] + "\n";
    md += "- Not applicable: " + stats["not-applicable"] + "\n\n";
    if (nonConformances.length > 0) {
      md += "## Non-conformances\n\n";
      for (var i = 0; i < nonConformances.length; i++) {
        var nc = nonConformances[i];
        md += "### " + nc.criterion + "\n\n";
        md += "- Reason: " + nc.reason + "\n";
        if (nc.mitigation) md += "- Mitigation: " + nc.mitigation + "\n";
        md += "\n";
      }
    }
    md += "## Per-criterion declarations\n\n";
    for (var ci = 0; ci < c.length; ci++) {
      md += "- **" + c[ci].criterion + "** — " + c[ci].conformance;
      if (c[ci].note) md += " — " + c[ci].note;
      md += "\n";
    }
    if (contact) md += "\n## Contact\n\n" + (contact.name || "") + " (" + (contact.email || "") + ")\n";
    return md;
  }

  function exportEaa(eopts) {
    eopts = eopts || {};
    var format = (eopts.format || "json").toLowerCase();
    _emitAudit("exported", "success", { format: format, criteriaCount: criteria.size });
    if (format === "json")     return _exportJson();
    if (format === "markdown") return _exportMarkdown();
    throw new ComplianceEaaError("compliance-eaa/bad-format",
      "compliance.eaa.export: format must be 'json' or 'markdown'");
  }

  return {
    declareCriterion:       declareCriterion,
    declareNonConformance:  declareNonConformance,
    "export":               exportEaa,
    stats:                  _stats,
    VALID_CONFORMANCE:      Object.keys(VALID_CONFORMANCE),
  };
}

module.exports = {
  create:               create,
  ComplianceEaaError:   ComplianceEaaError,
  VALID_CONFORMANCE:    Object.keys(VALID_CONFORMANCE),
};
