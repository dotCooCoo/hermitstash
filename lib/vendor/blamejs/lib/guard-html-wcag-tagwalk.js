// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared tag-walker helpers for the WCAG 2.2 audit-only scanner modules
 * (guard-html-wcag.js and its -aria / -forms / -tables sub-scanners), so the
 * tokenizer lives in one place rather than once per scanner.
 *
 * The walk composes lib/markup-tokenizer.js — the same tokenizer the HTML and
 * SVG guards read markup with. Sharing it matters beyond removing a copy: the
 * tokenizer knows a `>` inside a quoted attribute value does not end the tag,
 * which is what a browser does. A screen that ends the tag there reads
 * `<img alt="a > b" src=x>` as an `img` with no `alt`, and reports a missing
 * text alternative on a page that has one.
 */

var codepointClass = require("./codepoint-class");
var markupTokenizer = require("./markup-tokenizer");

/**
 * Every tag in `html`, in document order, as
 * `{ name, attrSrc, index, endIndex, closing }`:
 *
 *   name      lower-cased element name
 *   attrSrc   the text between the name and the closing `>`
 *   index     offset of the `<`
 *   endIndex  offset just past the `>`
 *   closing   true for `</name>`
 *
 * A `<` that does not begin a tag name is text, and is skipped.
 */
function tags(html) {
  var out = [];
  if (typeof html !== "string") return out;
  var len = html.length;
  var i = 0;
  while (i < len) {
    var lt = html.indexOf("<", i);
    if (lt === -1) break;
    var nameAt = html.charAt(lt + 1) === "/" ? lt + 2 : lt + 1;
    if (!codepointClass.isAsciiLetter(html.charCodeAt(nameAt))) { i = lt + 1; continue; }
    var gt = markupTokenizer.scanToTagEnd(html, nameAt, len);
    if (gt >= len) break;                                                          // unterminated: not a tag
    var split = markupTokenizer.splitTagNameAttrs(html.slice(nameAt, gt),
                                                  markupTokenizer.HTML_TAG_NAME_TAIL);
    out.push({
      name:     split.tagName,
      attrSrc:  split.attrSrc,
      index:    lt,
      endIndex: gt + 1,
      closing:  nameAt === lt + 2,
    });
    i = gt + 1;
  }
  return out;
}

/**
 * The attributes in a tag's `attrSrc`, as an object keyed by LOWER-cased name.
 * A repeated attribute keeps the last value, matching what a browser does with
 * the DOM property — though HTML itself keeps the first, so a document with a
 * duplicate is malformed either way.
 */
function parseAttrs(attrString) {
  var out = Object.create(null);
  if (!attrString) return out;
  var parsed = markupTokenizer.parseAttrs(attrString);
  for (var i = 0; i < parsed.length; i += 1) {
    out[parsed[i].name.toLowerCase()] = parsed[i].value;
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
  tags:         tags,
  parseAttrs:   parseAttrs,
  lineColAt:    lineColAt,
  makeScopedFindings: makeScopedFindings,
};
