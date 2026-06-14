"use strict";
/**
 * Shared tag-walker helpers for the WCAG 2.2 audit-only scanner
 * modules. Extracted from guard-html-wcag.js / -aria.js / -tables.js
 * so the regex constants live in one place.
 */

// HTML5 open + close tag regex. Captures: 1=tag-name, 2=attribute body.
var TAG_RE = /<\/?([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>/g;

// Per-attribute parser: name then (optional) value in double-quoted /
// single-quoted / unquoted form.
var ATTR_RE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function parseAttrs(attrString) {
  var out = Object.create(null);
  if (!attrString) return out;
  ATTR_RE.lastIndex = 0;
  var m;
  while ((m = ATTR_RE.exec(attrString))) {
    var name = m[1].toLowerCase();
    var value = m[3] !== undefined ? m[3] :
                m[4] !== undefined ? m[4] :
                m[5] !== undefined ? m[5] : "";
    out[name] = value;
  }
  return out;
}

function lineColAt(html, offset) {
  var line = 1;
  var lastNl = -1;
  for (var i = 0; i < offset; i++) {
    if (html.charCodeAt(i) === 10) { line += 1; lastNl = i; }                      // ASCII LF
  }
  return { line: line, column: offset - lastNl };
}

// Shared findings collector for the sub-scanners' audit(html, opts)
// entry points. scopeUrl annotates every finding with the page it came
// from so a direct caller of a sub-scanner (aria/forms/tables) can
// correlate a finding back to its source document; the parent
// wcag.audit also records scopeUrl at report level, but stamping
// per-finding keeps the value useful when a sub-scanner is invoked on
// its own. Returns { findings, add } — push findings through add() so
// the stamp applies uniformly.
function makeScopedFindings(scopeUrlOpt) {
  var scopeUrl = (typeof scopeUrlOpt === "string" && scopeUrlOpt.length > 0)
    ? scopeUrlOpt : null;
  var findings = [];
  function add(f) {
    if (scopeUrl !== null) f.scopeUrl = scopeUrl;
    findings.push(f);
  }
  return { findings: findings, add: add };
}

module.exports = {
  TAG_RE:       TAG_RE,
  ATTR_RE:      ATTR_RE,
  parseAttrs:   parseAttrs,
  lineColAt:    lineColAt,
  makeScopedFindings: makeScopedFindings,
};
