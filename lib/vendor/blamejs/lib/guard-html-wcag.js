"use strict";
/**
 * WCAG 2.2 audit-only scanner for HTML.
 *
 * Scans operator-supplied HTML for accessibility violations against
 * the WCAG 2.2 Recommendation (https://www.w3.org/TR/WCAG22/) without
 * modifying the document. Returns a structured report of findings the
 * operator wires into a CI gate, audit log, or development warning.
 *
 *   var audit = b.guardHtml.wcag.audit(htmlString, {
 *     level:    "AA",          // | "A" | "AAA"
 *     ignore:   ["1.4.3"],      // SCs the operator's deployment opts out of
 *   });
 *
 * Design constraints:
 *   - PURE static analysis — no rendering, no JS execution.
 *   - The scanner is conservative: it flags clear violations (missing
 *     alt text, empty heading text) and high-confidence patterns
 *     (out-of-order headings, form fields without label / aria-label /
 *     aria-labelledby). It does NOT attempt color-contrast checks,
 *     focus-indicator checks, or text-spacing checks (require rendered
 *     styles or runtime CSS).
 */

var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var GuardHtmlWcagError = defineClass("GuardHtmlWcagError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("./observability"); });
var aria = require("./guard-html-wcag-aria");
var tables = require("./guard-html-wcag-tables");
var forms = require("./guard-html-wcag-forms");
var tagwalk = require("./guard-html-wcag-tagwalk");

var SC_REGISTRY = Object.freeze({
  "1.1.1": { level: "A",   name: "Non-text Content" },
  "1.3.1": { level: "A",   name: "Info and Relationships" },
  "2.4.1": { level: "A",   name: "Bypass Blocks" },
  "2.4.2": { level: "A",   name: "Page Titled" },
  "2.4.4": { level: "A",   name: "Link Purpose (In Context)" },
  "3.1.1": { level: "A",   name: "Language of Page" },
  "3.3.2": { level: "A",   name: "Labels or Instructions" },
  "4.1.1": { level: "A",   name: "Parsing (deprecated in 2.2; retained for back-compat)" },
  "4.1.2": { level: "A",   name: "Name, Role, Value" },
  "2.4.11": { level: "AA",  name: "Focus Not Obscured (Minimum)" },
  "2.4.13": { level: "AAA", name: "Focus Appearance" },
  "2.5.7":  { level: "AA",  name: "Dragging Movements" },
  "2.5.8":  { level: "AA",  name: "Target Size (Minimum)" },
  "3.2.6":  { level: "A",   name: "Consistent Help" },
  "3.3.7":  { level: "A",   name: "Redundant Entry" },
  "3.3.8":  { level: "AA",  name: "Accessible Authentication (Minimum)" },
  "3.3.9":  { level: "AAA", name: "Accessible Authentication (Enhanced)" },
});

var VALID_LEVELS = Object.freeze(["A", "AA", "AAA"]);

function _meetsLevel(scLevel, requestedLevel) {
  if (requestedLevel === "AAA") return true;
  if (requestedLevel === "AA")  return scLevel === "A" || scLevel === "AA";
  return scLevel === "A";
}

function _newReport(scopeUrl) {
  return {
    findings:      [],
    summary:       { error: 0, warning: 0, info: 0 },
    totalFindings: 0,
    scopeUrl:      scopeUrl || null,
    scannedAt:     Date.now(),
  };
}

function _addFinding(report, finding) {
  report.findings.push(finding);
  report.totalFindings += 1;
  report.summary[finding.severity] = (report.summary[finding.severity] || 0) + 1;
}

var _TAG_RE = tagwalk.TAG_RE;
var _parseAttrs = tagwalk.parseAttrs;
var _lineColAt = tagwalk.lineColAt;

function _innerText(html, tagOpenEnd, tagName) {
  var lower = tagName.toLowerCase();
  var closeRe = new RegExp("</\\s*" + lower + "\\s*>", "i");                       // allow:dynamic-regex — `lower` is a tag name from the framework's static SC registry, not operator input; `\\s*` and tag name are RegExp-safe (no special chars)
  closeRe.lastIndex = tagOpenEnd;
  var m = closeRe.exec(html);
  if (!m) return "";
  var raw = html.slice(tagOpenEnd, m.index);
  return raw.replace(/<[^>]+>/g, "").replace(/&[a-z]+;|&#\d+;/gi, "").trim();
}

// ---- Per-element checks ----

function _checkImgAlt(html, attrs, tagName, offset, report, opts) {
  if (tagName !== "img") return;
  if (opts.ignore.indexOf("1.1.1") !== -1) return;
  if ("alt" in attrs) return;
  var pos = _lineColAt(html, offset);
  _addFinding(report, {
    sc:          "1.1.1",
    level:       "A",
    severity:    "error",
    element:     "img",
    line:        pos.line,
    column:      pos.column,
    message:     "img element missing alt attribute (use alt=\"\" for purely decorative images)",
    remediation: "Add alt=\"<descriptive text>\" or alt=\"\" if purely decorative",
  });
}

function _checkInputLabel(html, attrs, tagName, offset, report, opts, ctx) {
  if (tagName !== "input") return;
  if (opts.ignore.indexOf("3.3.2") !== -1) return;
  var inputType = (attrs.type || "text").toLowerCase();
  if (["hidden", "submit", "button", "image", "reset"].indexOf(inputType) !== -1) return;
  var hasLabel = "aria-label" in attrs ||
                 "aria-labelledby" in attrs ||
                 "title" in attrs ||
                 (attrs.id && ctx.labelledIds[attrs.id]);
  if (!hasLabel) {
    var pos = _lineColAt(html, offset);
    _addFinding(report, {
      sc:          "3.3.2",
      level:       "A",
      severity:    "error",
      element:     "input",
      line:        pos.line,
      column:      pos.column,
      message:     "Form input has no associated label (no aria-label, aria-labelledby, title, or matching <label for=...>)",
      remediation: "Add <label for=\"<id>\">...</label> or aria-label=\"<text>\" attribute",
    });
  }
  if (!("name" in attrs) && opts.ignore.indexOf("4.1.2") === -1) {
    var pos2 = _lineColAt(html, offset);
    _addFinding(report, {
      sc:          "4.1.2",
      level:       "A",
      severity:    "warning",
      element:     "input",
      line:        pos2.line,
      column:      pos2.column,
      message:     "input element has no name attribute (required for form submission + assistive-tech identification)",
      remediation: "Add name=\"<field-name>\" attribute",
    });
  }
}

function _checkAnchorScheduled(html, attrs, tagName, offset, report, opts) {
  if (tagName !== "a") return null;
  if (opts.ignore.indexOf("2.4.4") !== -1) return null;
  if (!("href" in attrs)) return null;
  var hasAccessibleName = "aria-label" in attrs ||
                          "aria-labelledby" in attrs ||
                          "title" in attrs;
  return { offset: offset, attrs: attrs, hasAccessibleName: hasAccessibleName };
  // void the unused vars so the linter is happy
}

function _checkButtonText(html, tagOpenEnd, attrs, offset, report, opts) {
  if (opts.ignore.indexOf("4.1.2") !== -1) return;
  var inner = _innerText(html, tagOpenEnd, "button");
  if (inner.length > 0) return;
  if ("aria-label" in attrs || "aria-labelledby" in attrs ||
      "title" in attrs) return;
  var pos = _lineColAt(html, offset);
  _addFinding(report, {
    sc:          "4.1.2",
    level:       "A",
    severity:    "error",
    element:     "button",
    line:        pos.line,
    column:      pos.column,
    message:     "button has no visible text and no aria-label / title (assistive tech reads it as \"button\" with no purpose)",
    remediation: "Add visible text content, aria-label=\"<purpose>\", or aria-labelledby=\"<idref>\"",
  });
}

function _checkHeadingOrder(html, attrs, tagName, offset, report, opts, ctx) {
  if (!/^h[1-6]$/.test(tagName)) return;
  if (opts.ignore.indexOf("1.3.1") !== -1) return;
  var level = parseInt(tagName.charAt(1), 10);                                     // base-10 parse radix
  if (ctx.headingLevels.length === 0) {
    if (level !== 1) {
      var pos = _lineColAt(html, offset);
      _addFinding(report, {
        sc:          "1.3.1",
        level:       "A",
        severity:    "warning",
        element:     tagName,
        line:        pos.line,
        column:      pos.column,
        message:     "First heading on the page is " + tagName + " (expected h1; missing/late h1 hurts navigation for screen readers)",
        remediation: "Promote the first heading to h1, or insert an h1 above it",
      });
    }
  } else {
    var lastLevel = ctx.headingLevels[ctx.headingLevels.length - 1];
    if (level > lastLevel + 1) {
      var pos2 = _lineColAt(html, offset);
      _addFinding(report, {
        sc:          "1.3.1",
        level:       "A",
        severity:    "warning",
        element:     tagName,
        line:        pos2.line,
        column:      pos2.column,
        message:     "Heading skips levels (" + tagName + " follows h" + lastLevel +
                     "; intermediate level skipped)",
        remediation: "Insert intermediate heading or demote " + tagName + " to h" + (lastLevel + 1),
      });
    }
  }
  var inner = _innerText(html, ctx.lastTagEndOffset, tagName);
  if (inner.length === 0) {
    var pos3 = _lineColAt(html, offset);
    _addFinding(report, {
      sc:          "1.3.1",
      level:       "A",
      severity:    "error",
      element:     tagName,
      line:        pos3.line,
      column:      pos3.column,
      message:     "Empty heading element (" + tagName + " has no text content)",
      remediation: "Add the heading text or remove the empty heading element",
    });
  }
  ctx.headingLevels.push(level);
}

// ---- Page-level checks ----

function _checkHtmlLang(html, report, opts) {
  if (opts.ignore.indexOf("3.1.1") !== -1) return;
  var m = /<html\b([^>]*)>/i.exec(html);
  if (!m) return;
  var attrs = _parseAttrs(m[1]);
  if (!attrs.lang || !attrs.lang.trim()) {
    var pos = _lineColAt(html, m.index);
    _addFinding(report, {
      sc:          "3.1.1",
      level:       "A",
      severity:    "error",
      element:     "html",
      line:        pos.line,
      column:      pos.column,
      message:     "html element missing lang attribute (assistive tech can't pick the right voice / pronunciation)",
      remediation: "Add lang=\"<BCP47-tag>\" e.g. lang=\"en\" or lang=\"en-US\"",
    });
  }
}

function _checkPageTitle(html, report, opts) {
  if (opts.ignore.indexOf("2.4.2") !== -1) return;
  if (!/<head\b/i.test(html)) return;
  var m = /<title\b[^>]*>([^]*?)<\/title>/i.exec(html);
  if (!m) {
    var pos = _lineColAt(html, html.search(/<head\b/i));
    _addFinding(report, {
      sc:          "2.4.2",
      level:       "A",
      severity:    "error",
      element:     "title",
      line:        pos.line,
      column:      pos.column,
      message:     "Page has no <title> element",
      remediation: "Add <title>Descriptive page title</title> inside <head>",
    });
    return;
  }
  var title = m[1].replace(/<[^>]+>/g, "").trim();
  if (title.length === 0) {
    var pos2 = _lineColAt(html, m.index);
    _addFinding(report, {
      sc:          "2.4.2",
      level:       "A",
      severity:    "error",
      element:     "title",
      line:        pos2.line,
      column:      pos2.column,
      message:     "<title> element is empty",
      remediation: "Add descriptive text inside <title>",
    });
    return;
  }
  if (title.length < 4 || /^untitled/i.test(title)) {
    var pos3 = _lineColAt(html, m.index);
    _addFinding(report, {
      sc:          "2.4.2",
      level:       "A",
      severity:    "warning",
      element:     "title",
      line:        pos3.line,
      column:      pos3.column,
      message:     "<title> is too short or generic (\"" + title + "\")",
      remediation: "Use a descriptive page title that distinguishes the page from siblings",
    });
  }
}

function _checkSkipLink(html, report, opts) {
  if (opts.ignore.indexOf("2.4.1") !== -1) return;
  if (!/<body\b/i.test(html)) return;
  if (/<a[^>]+href=["']#[a-zA-Z][^"']*["'][^>]*>\s*(skip|jump)\b/i.test(html)) return;
  var bodyMatch = /<body\b[^>]*>/i.exec(html);
  var pos = _lineColAt(html, bodyMatch ? bodyMatch.index : 0);
  _addFinding(report, {
    sc:          "2.4.1",
    level:       "A",
    severity:    "info",
    element:     "body",
    line:        pos.line,
    column:      pos.column,
    message:     "No \"skip to content\" link detected at the start of the page",
    remediation: "Add <a href=\"#main\" class=\"sr-only\">Skip to content</a> as the first focusable element in <body>",
  });
}

function _checkAnchors(html, scheduled, report) {
  for (var i = 0; i < scheduled.length; i++) {
    var s = scheduled[i];
    var tagOpen = html.indexOf(">", s.offset);
    if (tagOpen === -1) continue;
    var inner = _innerText(html, tagOpen + 1, "a");
    var visibleText = inner.length > 0;
    if (visibleText || s.hasAccessibleName) continue;
    var pos = _lineColAt(html, s.offset);
    _addFinding(report, {
      sc:          "2.4.4",
      level:       "A",
      severity:    "error",
      element:     "a",
      line:        pos.line,
      column:      pos.column,
      message:     "Link has no accessible name (no visible text, aria-label, aria-labelledby, or title)",
      remediation: "Add link text, aria-label=\"<purpose>\", or aria-labelledby=\"<idref>\"",
    });
  }
}

// ---- Main audit ----

function audit(html, opts) {
  opts = opts || {};
  validateOpts(opts, [
    "level", "ignore", "checkAll", "scopeUrl",
    "skipAria", "allowedRoles", "skipTables",
    "skipForms", "allowedAutocomplete",
  ], "guardHtml.wcag.audit");
  if (typeof html !== "string") {
    throw new GuardHtmlWcagError("guard-html-wcag/bad-input",
      "audit: html must be a string");
  }
  var level = opts.level || "AA";
  if (VALID_LEVELS.indexOf(level) === -1) {
    throw new GuardHtmlWcagError("guard-html-wcag/bad-level",
      "audit: level must be one of " + VALID_LEVELS.join(", "));
  }
  var ignore = Array.isArray(opts.ignore) ? opts.ignore : [];
  for (var i = 0; i < ignore.length; i++) {
    if (typeof ignore[i] !== "string") {
      throw new GuardHtmlWcagError("guard-html-wcag/bad-ignore",
        "audit: ignore[" + i + "] must be a string SC like \"1.4.3\"");
    }
  }
  var report = _newReport(opts.scopeUrl);
  var scanOpts = { level: level, ignore: ignore };

  // Page-level checks
  _checkHtmlLang(html, report, scanOpts);
  _checkPageTitle(html, report, scanOpts);
  _checkSkipLink(html, report, scanOpts);

  // Per-element walker
  var ctx = {
    headingLevels:  [],
    labelledIds:    Object.create(null),
    lastTagEndOffset: 0,
    scheduledAnchors: [],
  };
  var labelRe = /<label\b[^>]*\bfor\s*=\s*["']([^"']+)["'][^>]*>/gi;
  var lm;
  while ((lm = labelRe.exec(html))) {
    ctx.labelledIds[lm[1]] = true;
  }

  function _scLevelEligible(sc) {
    var sce = SC_REGISTRY[sc];
    if (!sce) return true;
    return _meetsLevel(sce.level, level);
  }

  _TAG_RE.lastIndex = 0;
  var m;
  while ((m = _TAG_RE.exec(html))) {
    // Skip closing tags (m[0] starts with "</"); only run per-element
    // checks on opening tags so we don't double-fire on each pair.
    if (m[0].charAt(1) === "/") continue;
    var tagName = m[1].toLowerCase();
    var attrs = _parseAttrs(m[2]);
    var offset = m.index;
    var endOffset = m.index + m[0].length;
    ctx.lastTagEndOffset = endOffset;

    if (_scLevelEligible("1.1.1")) _checkImgAlt(html, attrs, tagName, offset, report, scanOpts);
    if (_scLevelEligible("3.3.2") || _scLevelEligible("4.1.2")) _checkInputLabel(html, attrs, tagName, offset, report, scanOpts, ctx);
    if (_scLevelEligible("2.4.4")) {
      var sched = _checkAnchorScheduled(html, attrs, tagName, offset, report, scanOpts);
      if (sched) ctx.scheduledAnchors.push(sched);
    }
    if (_scLevelEligible("4.1.2") && tagName === "button") {
      _checkButtonText(html, endOffset, attrs, offset, report, scanOpts);
    }
    if (_scLevelEligible("1.3.1")) _checkHeadingOrder(html, attrs, tagName, offset, report, scanOpts, ctx);
  }

  _checkAnchors(html, ctx.scheduledAnchors, report);

  // ARIA validation pass — fold its findings into the report.
  if (opts.skipAria !== true) {
    var ariaFindings = aria.audit(html, {
      allowedRoles: opts.allowedRoles,
      scopeUrl:     opts.scopeUrl,
    });
    for (var ai = 0; ai < ariaFindings.length; ai++) {
      _addFinding(report, ariaFindings[ai]);
    }
  }
  // Table-semantics pass — caption / scope / layout-table heuristics.
  if (opts.skipTables !== true) {
    var tableFindings = tables.audit(html, { scopeUrl: opts.scopeUrl });
    for (var ti = 0; ti < tableFindings.length; ti++) {
      _addFinding(report, tableFindings[ti]);
    }
  }
  // Forms pass — fieldset/legend / autocomplete / textarea labelling.
  if (opts.skipForms !== true) {
    var formFindings = forms.audit(html, {
      allowedAutocomplete: opts.allowedAutocomplete,
      scopeUrl:            opts.scopeUrl,
    });
    for (var fi = 0; fi < formFindings.length; fi++) {
      _addFinding(report, formFindings[fi]);
    }
  }

  // Heuristic score: 1 - weighted-violations / heuristic-max
  var weighted = report.summary.error * 3 + report.summary.warning * 1.5 +        // severity weights for heuristic score
                 report.summary.info * 0.5;                                        // severity weights for heuristic score
  var maxFor = Math.max(50, weighted * 2);                                         // heuristic-score floor
  report.score = Math.max(0, 1 - weighted / maxFor);

  try { observability().safeEvent("guard-html.wcag.audited", 1, {
    level: level, errors: String(report.summary.error),
  }); } catch (_e) { /* drop-silent */ }

  return report;
}

module.exports = {
  audit:                audit,
  aria:                 aria,
  tables:               tables,
  forms:                forms,
  SC_REGISTRY:          SC_REGISTRY,
  VALID_LEVELS:         VALID_LEVELS,
  GuardHtmlWcagError:   GuardHtmlWcagError,
};
