"use strict";

// markup-escape — the shared XML/HTML text + attribute escaper used wherever
// the framework SERIALIZES a value into markup (mail report / DAV / autoconfig
// XML, the Azure blob XML API, and — once routed — the b.guardHtml / b.guardSvg
// sanitizer output). Distinct from markup-tokenizer (which LEXES markup for the
// sanitizers) and xml-c14n (which canonicalizes for XMLDSig with a different
// escape set, e.g. \r\n\t and NO ">").
//
// markupEscape(str, opts) escapes the four always-dangerous markup
// metacharacters — & < > " — to their entity forms, with "&" first so the
// entities it emits are not double-escaped. The one axis that genuinely varies
// across callers is the apostrophe, so it is a parameter:
//   opts.apos omitted / falsy → "'" is left as-is (element content and
//     double-quoted attributes don't require it escaped)
//   opts.apos === "&#39;"     → HTML numeric form
//   opts.apos === "&apos;"    → XML named form
// Input COERCION stays with the caller (some map null/undefined or any
// non-string to "" before serializing); markupEscape String()s defensively so
// a stray number/boolean still escapes rather than throwing.
function markupEscape(str, opts) {
  var s = String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
  var apos = opts && opts.apos;
  return apos ? s.replace(/'/g, apos) : s;
}

module.exports = { markupEscape: markupEscape };
