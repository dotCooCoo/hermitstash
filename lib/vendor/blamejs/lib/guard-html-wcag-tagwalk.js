// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");
var markupTokenizer = require("./markup-tokenizer");

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
    if (gt >= len) break;
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
    if (html.charCodeAt(i) === 10) { line += 1; lastNl = i; }
  }
  return { line: line, column: offset - lastNl };
}

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
