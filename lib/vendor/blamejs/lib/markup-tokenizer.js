// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");

// markup-tokenizer — neutral lexing helpers shared by the markup sanitizers
// (b.guardHtml, b.guardSvg) and the BIMI SVG Tiny PS validator (b.mail.bimi).
// Each of those keeps its OWN tokenizer loop because their security postures
// genuinely diverge — guard-html/guard-svg recover leniently from a truncated
// tag (emit what was scanned, keep going), while the BIMI validator fails
// closed (throws on any malformation), and each recognizes a different set of
// declaration forms (`<?`, `<!ENTITY>`, balanced `<!DOCTYPE [...]>`). What they
// share verbatim is the one quote-aware step below; centralizing it keeps the
// attribute-quote handling — the part a bypass hides in — identical everywhere.

// scanToTagEnd(s, from, len) — advance from `from` (the index just past the
// opening "<") to the tag's closing ">", treating a ">" that appears inside a
// single- or double-quoted attribute value as a literal, not a terminator
// (e.g. `<a title="a>b">` ends at the SECOND ">"). Returns the index of the
// terminating ">", or `len` if the tag is unterminated (the caller decides
// whether that is lenient end-of-input or a hard error).
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

// splitTagNameAttrs(inner, tailChars) — given a start tag's inner text (the
// bytes between "<" and ">", with any trailing self-closing "/" already
// stripped by the caller), split it into the lower-cased `tagName` and the raw
// `attrSrc` remainder. A tag name always begins with an ASCII letter;
// `tailChars` is the caller's grammar for the REST of it — HTML allows
// alphanumerics plus `:` and `-`, while the XML-family grammars (SVG, BIMI SVG
// Tiny PS) also allow `_`. A tag whose start is not a letter yields an empty
// name and an empty attrSrc, and the caller treats it as a bogus tag.
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

// The two tag-name grammars the markup family uses, so a caller names one
// rather than restating it.
var HTML_TAG_NAME_TAIL = codepointClass.ASCII_ALNUM + ":-";
var XML_TAG_NAME_TAIL  = codepointClass.ASCII_ALNUM + ":-_";

// htmlCommentEnd(s, lt) — given that an HTML comment opens at index `lt`
// (s.startsWith("<!--", lt)), return the index ONE PAST the comment's
// terminator per the WHATWG HTML tokenizer, not just the legacy "-->" form.
// A browser also closes a comment at "--!>" (comment-end-bang state) and
// ABRUPTLY closes one that begins "<!-->" or "<!--->". A scanner that honours
// only "-->" therefore disagrees with the browser about where the comment
// ends, so markup AFTER an early "--!>" / abrupt close is swallowed as inert
// comment by the sanitizer but parsed as a LIVE element by the browser (mXSS,
// the comment-parser differential). Returns -1 if the comment is unterminated
// so each caller keeps its own policy (lenient end-of-input vs. fail-closed
// throw). NOTE: HTML/SVG-in-HTML only — XML comments do NOT have these forms.
function htmlCommentEnd(s, lt) {
  var i = lt + 4;                                  // first char after "<!--"
  if (s.charAt(i) === ">") return i + 1;           // <!--> abrupt close
  if (s.charAt(i) === "-" && s.charAt(i + 1) === ">") return i + 2;   // <!---> abrupt close
  var a = s.indexOf("-->", i);
  var b = s.indexOf("--!>", i);
  if (a === -1 && b === -1) return -1;             // unterminated
  if (a === -1) return b + 4;
  if (b === -1) return a + 3;
  return a <= b ? a + 3 : b + 4;                   // earliest terminator wins
}

// isMarkupSpace(cc) — whitespace inside a tag. The full ECMAScript `\s` set,
// which is wider than HTML's own five: a browser's tolerance for exotic
// separators is what an attribute-splitting bypass is built out of, so the
// sanitizer treats more characters as separators than the spec requires, not
// fewer.
function isMarkupSpace(cc) {
  return codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES);
}

// skipMarkupSpace(s, i) — index of the next character at or after `i` that is
// not markup whitespace.
function skipMarkupSpace(s, i) {
  while (i < s.length && isMarkupSpace(s.charCodeAt(i))) i += 1;
  return i;
}

// The characters that end an attribute name besides whitespace.
var ATTR_NAME_STOP_CHARS = "=>/";

// parseAttrs(src) — the attributes of a start tag, from the text after the tag
// name, as `{ name, value, raw }` in source order. Attribute-name casing is
// preserved; consumers lower-case as they need to. A value may be double- or
// single-quoted or bare, and an unterminated quote runs to the end of the
// source rather than swallowing the rest of the document.
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

// endTagName(inner) — the lower-cased name from an end tag's inner text (what
// sits between `</` and `>`). Anything after the first whitespace run is
// discarded, which is what a browser does with `</div foo>`.
function endTagName(inner) {
  var tokens = codepointClass.splitOnWhitespace(inner);
  return (tokens.length > 0 ? tokens[0] : "").toLowerCase();
}

// RFC 3986 §3.1 scheme: a letter, then letters, digits, `+`, `-` and `.`, up
// to the colon.
var SCHEME_TAIL_CHARS = codepointClass.ASCII_ALNUM + "+-.";

// extractScheme(rawUrl) — the lower-cased scheme of a URL, or `""`. Entity
// references are decoded and the whitespace a browser strips before resolving
// a scheme is folded away FIRST, so neither `java<TAB>script:` nor
// `&#32;javascript:` reads as scheme-less.
function extractScheme(rawUrl) {
  var s = codepointClass.stripUrlSchemeWhitespace(
    codepointClass.decodeMarkupEntities(String(rawUrl || "").trim()));
  if (!codepointClass.isAsciiLetter(s.charCodeAt(0))) return "";
  var i = 1;
  while (i < s.length && SCHEME_TAIL_CHARS.indexOf(s.charAt(i)) !== -1) i += 1;
  return s.charAt(i) === ":" ? s.slice(0, i).toLowerCase() : "";
}

// isDataUrlOfType(rawUrl, subtypes) — is this a `data:` URL whose media type is
// `image/<one of subtypes>`, with the `;` that ends the type? The semicolon is
// what makes the claim complete: without it a longer subtype would also match.
function isDataUrlOfType(rawUrl, subtypes) {
  var s = String(rawUrl || "").trim();
  for (var i = 0; i < subtypes.length; i += 1) {
    var prefix = "data:image/" + subtypes[i] + ";";
    if (codepointClass.containsFolded(s.slice(0, prefix.length), prefix)) return true;
  }
  return false;
}

// isEventHandlerAttr(name) — `on` then at least one letter, so `on` alone and
// `on-something` are not handlers. Compared without regard to ASCII case.
function isEventHandlerAttr(name) {
  return name.length >= 3 &&
         codepointClass.containsFolded(name.slice(0, 2), "on") &&
         codepointClass.isAsciiLetter(name.charCodeAt(2));
}

// The CSS constructs a sanitizer refuses inside a style attribute. Each is a
// word plus the punctuation that must follow it, with any run of whitespace
// between the two; a `null` suffix means the word alone is the finding.
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

// hasDangerousCss(value) — does this style attribute carry one of the shapes
// above? A style attribute is character-reference-decoded before the CSS
// parser sees it, so `ex&#x70;ression(` arrives as `expression(`; the same
// decode and whitespace fold the URL-scheme check applies is applied here, so
// an entity-encoded payload cannot pass.
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
