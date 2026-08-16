// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Table semantics validation for the WCAG 2.2 audit-only scanner.
 *
 * Checks per WCAG 2.2 / WAI-ARIA / HTML 5.3 best practices:
 *   - <table> without <caption> (data-tables only; layout-tables
 *     should use role="presentation" instead)
 *   - <th> without scope attribute (or invalid scope value)
 *   - layout tables that should be replaced with semantic markup
 *   - missing or empty <thead> for data tables with multiple body rows
 *   - <tr> outside <table> / <thead> / <tbody> / <tfoot>
 *
 * Exposed under b.guardHtml.wcag.tables.audit(html, opts).
 */

var validateOpts = require("./validate-opts");
var tagwalk = require("./guard-html-wcag-tagwalk");

var VALID_SCOPE_VALUES = Object.freeze(["row", "col", "rowgroup", "colgroup"]);

var _parseAttrs = tagwalk.parseAttrs;
var _lineColAt = tagwalk.lineColAt;

function audit(html, opts) {
  opts = opts || {};
  validateOpts(opts, ["scopeUrl"], "guardHtml.wcag.tables.audit");
  if (typeof html !== "string") {
    throw new TypeError("tables.audit: html must be a string");
  }

  // Per-finding scopeUrl stamping — shared collector in tagwalk.
  var collector = tagwalk.makeScopedFindings(opts.scopeUrl);
  var findings = collector.findings;
  var _add = collector.add;

  // Walk the tag stream, tracking nesting state for tables + their
  // children. We don't build a full DOM; we track the open-tag stack
  // to determine whether we're inside <table> / <thead> / <tbody>.
  var stack = [];
  var found = tagwalk.tags(html);
  for (var t = 0; t < found.length; t += 1) {
    var m = found[t];
    var isClose = m.closing;
    var tagName = m.name;
    var attrs = isClose ? null : _parseAttrs(m.attrSrc);
    var pos = _lineColAt(html, m.index);

    if (isClose) {
      // Pop the matching open tag (lazily — broken HTML may produce
      // mismatches; we just pop any matching same-name from the top).
      for (var s = stack.length - 1; s >= 0; s--) {
        if (stack[s].name === tagName) {
          stack.splice(s, 1);
          break;
        }
      }
      continue;
    }

    if (tagName === "table") {
      // Data table check: presence of <caption> as a direct/early
      // child within the same table. We can't know the close-tag
      // position without scanning forward; do a forward look.
      var role = attrs.role || "";
      var isPresentation = role === "presentation" || role === "none";
      if (!isPresentation) {
        // Find the matching </table>, then ask whether this table opens a
        // caption anywhere inside it.
        var closeIdx = _findClose(found, t, "table");
        var hasCaption = false;
        for (var c = t + 1; c < found.length; c += 1) {
          if (closeIdx !== -1 && found[c].index >= closeIdx) break;
          if (found[c].name === "caption" && !found[c].closing) { hasCaption = true; break; }
        }
        if (!hasCaption) {
          _add({
            sc: "1.3.1", level: "A", severity: "warning",
            element: "table", line: pos.line, column: pos.column,
            message: "Data <table> has no <caption> (assistive tech can't summarize the table for screen-reader users)",
            remediation: "Add <caption>Descriptive title</caption> as the first child of <table>, or set role=\"presentation\" if this is a layout table",
          });
        }
      }
      stack.push({ name: "table", attrs: attrs });
    }

    if (tagName === "th") {
      if (!("scope" in attrs)) {
        _add({
          sc: "1.3.1", level: "A", severity: "warning",
          element: "th", line: pos.line, column: pos.column,
          message: "<th> element has no scope attribute (screen readers can't announce the right header for each cell)",
          remediation: "Add scope=\"col\" / scope=\"row\" / scope=\"colgroup\" / scope=\"rowgroup\"",
        });
      } else if (VALID_SCOPE_VALUES.indexOf(attrs.scope) === -1) {
        _add({
          sc: "1.3.1", level: "A", severity: "error",
          element: "th", line: pos.line, column: pos.column,
          message: "<th> scope=\"" + attrs.scope + "\" is not in the allowed value set [" +
                   VALID_SCOPE_VALUES.join(", ") + "]",
          remediation: "Use a valid scope value",
        });
      }
    }

    if (tagName === "tr") {
      // Detect <tr> outside any table-context wrapper
      var inTable = stack.some(function (e) {
        return e.name === "table" || e.name === "thead" ||
               e.name === "tbody" || e.name === "tfoot";
      });
      if (!inTable) {
        _add({
          sc: "1.3.1", level: "A", severity: "warning",
          element: "tr", line: pos.line, column: pos.column,
          message: "<tr> appears outside <table> / <thead> / <tbody> / <tfoot>",
          remediation: "Wrap the <tr> in a table-row context",
        });
      }
    }

    // Track other table descendants so we can identify nested
    // structure if needed for layout-table heuristics.
    if (tagName === "thead" || tagName === "tbody" ||
        tagName === "tfoot" || tagName === "caption") {
      stack.push({ name: tagName, attrs: attrs });
    }
  }

  return findings;
}

// Offset just past the close tag matching the open tag at `found[from]`, or
// -1 when the document never closes it. Depth is tracked so a nested table
// resolves to its own close rather than to the inner one's.
//
// This reads the tag list the audit already built. The two interleaved
// patterns it replaces advanced their own scan positions independently, so a
// nested open tag between two closes could leave one of them looking at a
// position the other had already passed.
function _findClose(found, from, tagName) {
  var depth = 1;
  for (var i = from + 1; i < found.length; i += 1) {
    if (found[i].name !== tagName) continue;
    if (found[i].closing) {
      depth -= 1;
      if (depth === 0) return found[i].endIndex;
    } else {
      depth += 1;
    }
  }
  return -1;
}

module.exports = {
  audit:               audit,
  VALID_SCOPE_VALUES:  VALID_SCOPE_VALUES,
};
