// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");

function scanToTagEnd(s, from, len) {
  var p = from;
  var inQuote = "";
  while (p < len) {
    var ch = s.charAt(p);
    if (inQuote) {
      if (ch === inQuote) inQuote = "";
    } else {
      if (ch === '"' || ch === "'") inQuote = ch;
      else if (ch === ">") break;
    }
    p += 1;
  }
  return p;
}

function splitTagNameAttrs(inner, tailChars) {
  if (!codepointClass.isAsciiLetter(inner.charCodeAt(0))) {
    return { tagName: "", attrSrc: "" };
  }
  var i = 1;
  while (i < inner.length && tailChars.indexOf(inner.charAt(i)) !== -1) i += 1;
  return {
    tagName: inner.slice(0, i).toLowerCase(),
    attrSrc: inner.slice(i),
  };
}

var HTML_TAG_NAME_TAIL = codepointClass.ASCII_ALNUM + ":-";
var XML_TAG_NAME_TAIL  = codepointClass.ASCII_ALNUM + ":-_";

var XML_PREDEFINED_REFS = {
  amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'",
};

var DEC_DIGITS_RE = /^[0-9]+$/;
var HEX_DIGITS_RE = /^[0-9A-Fa-f]+$/;

var MAX_CHAR_REF_DIGITS = 7;

function decodeCharRefs(s) {
  if (s.indexOf("&") === -1) return s;
  var out = "";
  var i = 0;
  while (i < s.length) {
    var amp = s.indexOf("&", i);
    if (amp === -1) { out += s.slice(i); break; }
    out += s.slice(i, amp);
    var semi = s.indexOf(";", amp + 1);
    if (semi === -1) { out += s.slice(amp); break; }
    var body = s.slice(amp + 1, semi);
    var decoded = null;
    if (body.charAt(0) === "#") {
      var hex = body.charAt(1) === "x" || body.charAt(1) === "X";
      var digits = hex ? body.slice(2) : body.slice(1);
      var firstSignificant = 0;
      while (firstSignificant < digits.length - 1 &&
             digits.charAt(firstSignificant) === "0") firstSignificant += 1;
      var significant = digits.slice(firstSignificant);
      var wellFormed = significant.length > 0 &&
                       significant.length <= MAX_CHAR_REF_DIGITS &&
                       (hex ? HEX_DIGITS_RE.test(significant) : DEC_DIGITS_RE.test(significant));
      if (wellFormed) {
        var cp = parseInt(significant, hex ? 16 : 10);
        if (cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)) {
          decoded = String.fromCodePoint(cp);
        }
      }
    } else if (Object.prototype.hasOwnProperty.call(XML_PREDEFINED_REFS, body)) {
      decoded = XML_PREDEFINED_REFS[body];
    }
    out += decoded === null ? s.slice(amp, semi + 1) : decoded;
    i = semi + 1;
  }
  return out;
}

function xmlCommentEnd(s, lt) {
  var end = s.indexOf("-->", lt + 4);
  return end === -1 ? -1 : end + 3;
}

function htmlCommentEnd(s, lt) {
  var i = lt + 4;
  if (s.charAt(i) === ">") return i + 1;
  if (s.charAt(i) === "-" && s.charAt(i + 1) === ">") return i + 2;
  var a = s.indexOf("-->", i);
  var b = s.indexOf("--!>", i);
  if (a === -1 && b === -1) return -1;
  if (a === -1) return b + 4;
  if (b === -1) return a + 3;
  return a <= b ? a + 3 : b + 4;
}

function isMarkupSpace(cc) {
  return codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES);
}

function skipMarkupSpace(s, i) {
  while (i < s.length && isMarkupSpace(s.charCodeAt(i))) i += 1;
  return i;
}

var ATTR_NAME_STOP_CHARS = "=>/";

function parseAttrs(src) {
  var attrs = [];
  var s = String(src).trim();
  var len = s.length;
  var p = 0;
  while (p < len) {
    p = skipMarkupSpace(s, p);
    if (p >= len) break;
    var nameStart = p;
    while (p < len && !isMarkupSpace(s.charCodeAt(p)) &&
           ATTR_NAME_STOP_CHARS.indexOf(s.charAt(p)) === -1) p += 1;
    var attrName = s.slice(nameStart, p);
    if (!attrName) break;
    p = skipMarkupSpace(s, p);
    var attrValue = "";
    var raw = attrName;
    if (p < len && s.charAt(p) === "=") {
      p = skipMarkupSpace(s, p + 1);
      var q = s.charAt(p);
      if (q === '"' || q === "'") {
        var endQ = s.indexOf(q, p + 1);
        if (endQ === -1) endQ = len;
        attrValue = s.slice(p + 1, endQ);
        raw = attrName + "=" + s.slice(p, endQ + 1);
        p = endQ + 1;
      } else {
        var valStart = p;
        while (p < len && !isMarkupSpace(s.charCodeAt(p)) && s.charAt(p) !== ">") p += 1;
        attrValue = s.slice(valStart, p);
        raw = attrName + "=" + attrValue;
      }
    }
    attrs.push({ name: attrName, value: attrValue, raw: raw });
  }
  return attrs;
}

function endTagName(inner) {
  var tokens = codepointClass.splitOnWhitespace(inner);
  return (tokens.length > 0 ? tokens[0] : "").toLowerCase();
}

var SCHEME_TAIL_CHARS = codepointClass.ASCII_ALNUM + "+-.";

function extractScheme(rawUrl) {
  var s = codepointClass.stripUrlSchemeWhitespace(
    codepointClass.decodeMarkupEntities(String(rawUrl || "").trim()));
  if (!codepointClass.isAsciiLetter(s.charCodeAt(0))) return "";
  var i = 1;
  while (i < s.length && SCHEME_TAIL_CHARS.indexOf(s.charAt(i)) !== -1) i += 1;
  return s.charAt(i) === ":" ? s.slice(0, i).toLowerCase() : "";
}

function isDataUrlOfType(rawUrl, subtypes) {
  var s = String(rawUrl || "").trim();
  for (var i = 0; i < subtypes.length; i += 1) {
    var prefix = "data:image/" + subtypes[i] + ";";
    if (codepointClass.containsFolded(s.slice(0, prefix.length), prefix)) return true;
  }
  return false;
}

function isEventHandlerAttr(name) {
  return name.length >= 3 &&
         codepointClass.containsFolded(name.slice(0, 2), "on") &&
         codepointClass.isAsciiLetter(name.charCodeAt(2));
}

var CSS_DANGEROUS_SHAPES = Object.freeze([
  { word: "expression",   suffix: "(" },
  { word: "behavior",     suffix: ":" },
  { word: "-moz-binding", suffix: null },
  { word: "javascript",   suffix: ":" },
  { word: "vbscript",     suffix: ":" },
  { word: "livescript",   suffix: ":" },
  { word: "@import",      suffix: null },
  { word: "@namespace",   suffix: null },
]);

function hasDangerousCss(value) {
  var decoded = codepointClass.stripUrlSchemeWhitespace(
    codepointClass.decodeMarkupEntities(value));
  for (var i = 0; i < CSS_DANGEROUS_SHAPES.length; i += 1) {
    if (_hasCssShape(decoded, CSS_DANGEROUS_SHAPES[i])) return true;
  }
  return false;
}

function _hasCssShape(text, shape) {
  var word = shape.word;
  for (var i = 0; i + word.length <= text.length; i += 1) {
    if (!codepointClass.containsFolded(text.slice(i, i + word.length), word)) continue;
    if (shape.suffix === null) return true;
    var j = skipMarkupSpace(text, i + word.length);
    if (text.charAt(j) === shape.suffix) return true;
  }
  return false;
}

module.exports = {
  scanToTagEnd: scanToTagEnd,
  splitTagNameAttrs: splitTagNameAttrs,
  htmlCommentEnd: htmlCommentEnd,
  xmlCommentEnd: xmlCommentEnd,
  decodeCharRefs: decodeCharRefs,
  HTML_TAG_NAME_TAIL: HTML_TAG_NAME_TAIL,
  XML_TAG_NAME_TAIL: XML_TAG_NAME_TAIL,
  isMarkupSpace: isMarkupSpace,
  skipMarkupSpace: skipMarkupSpace,
  parseAttrs: parseAttrs,
  endTagName: endTagName,
  extractScheme: extractScheme,
  isDataUrlOfType: isDataUrlOfType,
  isEventHandlerAttr: isEventHandlerAttr,
  hasDangerousCss: hasDangerousCss,
  CSS_DANGEROUS_SHAPES: CSS_DANGEROUS_SHAPES,
};
