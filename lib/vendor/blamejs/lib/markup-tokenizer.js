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

module.exports = {
  scanToTagEnd: scanToTagEnd,
  splitTagNameAttrs: splitTagNameAttrs,
};
