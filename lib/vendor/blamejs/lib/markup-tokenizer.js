"use strict";

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

// splitTagNameAttrs(inner, tagNameRe) — given a start tag's inner text (the
// bytes between "<" and ">", with any trailing self-closing "/" already
// stripped by the caller), split it into the lower-cased `tagName` and the raw
// `attrSrc` remainder. `tagNameRe` is the caller's tag-name grammar (it must
// capture the name in group 1) — HTML allows `[A-Za-z][A-Za-z0-9:-]*`, while
// the XML-family grammars (SVG, BIMI SVG Tiny PS) also allow `_`. A tag whose
// start does not match the grammar yields an empty name + empty attrSrc (the
// caller treats it as a bogus tag).
function splitTagNameAttrs(inner, tagNameRe) {
  var nameMatch = inner.match(tagNameRe);
  return {
    tagName: nameMatch ? nameMatch[1].toLowerCase() : "",
    attrSrc: nameMatch ? inner.slice(nameMatch[0].length) : "",
  };
}

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

module.exports = {
  scanToTagEnd: scanToTagEnd,
  splitTagNameAttrs: splitTagNameAttrs,
  htmlCommentEnd: htmlCommentEnd,
};
