// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

  var collector = tagwalk.makeScopedFindings(opts.scopeUrl);
  var findings = collector.findings;
  var _add = collector.add;

  var stack = [];
  var found = tagwalk.tags(html);
  for (var t = 0; t < found.length; t += 1) {
    var m = found[t];
    var isClose = m.closing;
    var tagName = m.name;
    var attrs = isClose ? null : _parseAttrs(m.attrSrc);
    var pos = _lineColAt(html, m.index);

    if (isClose) {
      for (var s = stack.length - 1; s >= 0; s--) {
        if (stack[s].name === tagName) {
          stack.splice(s, 1);
          break;
        }
      }
      continue;
    }

    if (tagName === "table") {
      var role = attrs.role || "";
      var isPresentation = role === "presentation" || role === "none";
      if (!isPresentation) {
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

    if (tagName === "thead" || tagName === "tbody" ||
        tagName === "tfoot" || tagName === "caption") {
      stack.push({ name: tagName, attrs: attrs });
    }
  }

  return findings;
}

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
