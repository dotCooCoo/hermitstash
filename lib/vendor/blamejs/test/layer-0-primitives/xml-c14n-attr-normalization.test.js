// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.xmlC14n.canonicalize — XML attribute-value normalization (canonical
 * collision defense).
 *
 * RFC 3741 Exclusive c14n operates on the post-parse InfoSet, so a
 * conforming XML processor has already applied line-ending normalization
 * (XML 1.0 §2.11: CRLF / lone-CR -> LF) and attribute-value
 * normalization (§3.3.3: a literal TAB / CR / LF in an attribute value
 * -> a single SPACE) BEFORE c14n runs. Whitespace introduced through a
 * character reference (&#9; / &#xA; / &#xD;) is NOT normalized, and c14n
 * escapes it back to &#x9; / &#xA; / &#xD; so it survives a re-parse.
 *
 * Pre-fix, xml-c14n's readAttrValue skipped attribute-value
 * normalization: a literal TAB and a &#9; character reference both
 * reached _escapeAttrValue as a real TAB byte and were emitted as
 * "&#x9;". Two DISTINCT documents (`a="x<TAB>y"` vs `a="x&#9;y"`) — whose
 * InfoSet attribute values differ ("x y" vs "x\ty") — canonicalized to
 * IDENTICAL bytes. That distinct-input / identical-output collision
 * defeats the module's stated purpose (preventing XML-signature-wrapping
 * byte collisions): a signed document could be swapped for a
 * semantically different one whose canonical bytes still match the
 * signature.
 *
 * These build the hostile whitespace bytes in the test (never as lib
 * literals) and assert the collision is closed AND the compliant
 * fold-vs-preserve split holds.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var c14n    = require("../../lib/xml-c14n");

function _c(xml) { return c14n.canonicalize(xml).toString("utf8"); }

// A literal TAB (U+0009) inside an attribute value must fold to a SPACE;
// a TAB delivered via a character reference must be preserved (escaped
// back to &#x9;). The two therefore MUST NOT collide.
function testLiteralTabVsCharRefTabDoNotCollide() {
  var litTab = '<r a="x' + String.fromCharCode(0x09) + 'y"/>';
  var refTab = '<r a="x&#9;y"/>';
  var oLit = _c(litTab);
  var oRef = _c(refTab);

  check("literal-TAB and char-ref-TAB attribute values must canonicalize distinctly",
    oLit !== oRef);
  check("literal-TAB attribute value folds to a single SPACE",
    oLit === '<r a="x y"></r>');
  check("char-ref-TAB attribute value is preserved as &#x9;",
    oRef === '<r a="x&#x9;y"></r>');
}

// Same invariant for a literal newline (U+000A) vs a &#10; reference.
function testLiteralNewlineVsCharRefNewlineDoNotCollide() {
  var litNl = '<r a="x' + String.fromCharCode(0x0a) + 'y"/>';
  var refNl = '<r a="x&#10;y"/>';
  var oLit = _c(litNl);
  var oRef = _c(refNl);

  check("literal-LF and char-ref-LF attribute values must canonicalize distinctly",
    oLit !== oRef);
  check("literal-LF attribute value folds to a single SPACE",
    oLit === '<r a="x y"></r>');
  check("char-ref-LF attribute value is preserved as &#xA;",
    oRef === '<r a="x&#xA;y"></r>');
}

// A literal CRLF is one line ending: §2.11 collapses it to a single LF,
// then §3.3.3 folds that to a single SPACE — one space, not two escapes.
function testLiteralCrlfFoldsToSingleSpace() {
  var litCrlf = '<r a="x' + String.fromCharCode(0x0d) + String.fromCharCode(0x0a) + 'y"/>';
  check("literal-CRLF attribute value folds to a single SPACE",
    _c(litCrlf) === '<r a="x y"></r>');

  var litCr = '<r a="x' + String.fromCharCode(0x0d) + 'y"/>';
  check("literal lone-CR attribute value folds to a single SPACE",
    _c(litCr) === '<r a="x y"></r>');
}

// A plain literal SPACE must be left untouched (identity), and multiple
// literal spaces are NOT collapsed for CDATA attribute values.
function testLiteralSpacesPreserved() {
  check("single literal SPACE is preserved",
    _c('<r a="x y"/>') === '<r a="x y"></r>');
  check("consecutive literal SPACEs are not collapsed",
    _c('<r a="x  y"/>') === '<r a="x  y"></r>');
}

// The signature-wrapping shape: two documents identical except that a
// security-significant attribute carries a literal TAB in one and the
// &#9; reference in the other. A verifier that canonicalizes them to the
// same bytes would accept one signature for both — the collision this
// module exists to prevent.
function testWrappingStyleAttributesDoNotCollide() {
  var signed  = '<Assertion Role="admin&#9;ops">v</Assertion>';
  var swapped = '<Assertion Role="admin' + String.fromCharCode(0x09) + 'ops">v</Assertion>';
  check("signed vs whitespace-swapped assertion must canonicalize distinctly",
    _c(signed) !== _c(swapped));
}

// canonicalizeElementById must inherit the same normalization on the
// subtree it extracts.
function testCanonicalizeByIdNormalizes() {
  var doc = '<root><a ID="s" v="p' + String.fromCharCode(0x09) + 'q">t</a></root>';
  var out = c14n.canonicalizeElementById(doc, "s").toString("utf8");
  check("canonicalizeElementById folds a literal TAB attribute to a SPACE",
    out === '<a ID="s" v="p q">t</a>');
}

// The same collision class in ELEMENT TEXT (not just attribute values): XML
// 1.0 §2.11 folds a literal CR / CRLF in character data to a single LF, while
// the &#xD; reference is preserved and c14n escapes the surviving CR to &#xD;.
// Without §2.11 normalization a literal CR in text and the &#xD; reference both
// canonicalize to &#xD; — the identical-bytes collision, in the text nodes SAML
// signatures cover.
function testTextLiteralCrVsCharRefCrDoNotCollide() {
  var litCr = '<r>x' + String.fromCharCode(0x0d) + 'y</r>';
  var refCr = '<r>x&#xD;y</r>';
  var oLit = _c(litCr);
  var oRef = _c(refCr);
  check("literal-CR and char-ref-CR TEXT content must canonicalize distinctly",
    oLit !== oRef);
  check("literal-CR text folds to a bare LF (§2.11)",
    oLit === '<r>x' + String.fromCharCode(0x0a) + 'y</r>');
  check("char-ref-CR text is preserved as &#xD;",
    oRef === '<r>x&#xD;y</r>');
}

// CDATA is character data too: a literal CR inside CDATA folds to LF (§2.11),
// so it cannot collide with the &#xD; reference in ordinary text.
function testCdataLiteralCrFoldsToLf() {
  var cdataCr = '<r><![CDATA[x' + String.fromCharCode(0x0d) + 'y]]></r>';
  check("literal-CR inside CDATA folds to a bare LF, not &#xD;",
    _c(cdataCr) === '<r>x' + String.fromCharCode(0x0a) + 'y</r>');
}

// Wrapping shape in element text: a signed assertion whose text carries the
// &#xD; reference vs a swapped copy carrying the literal CR must not collide.
function testTextWrappingStyleDoNotCollide() {
  var signed  = '<Assertion>admin&#xD;ops</Assertion>';
  var swapped = '<Assertion>admin' + String.fromCharCode(0x0d) + 'ops</Assertion>';
  check("signed vs CR-swapped assertion TEXT must canonicalize distinctly",
    _c(signed) !== _c(swapped));
}

function run() {
  testLiteralTabVsCharRefTabDoNotCollide();
  testLiteralNewlineVsCharRefNewlineDoNotCollide();
  testTextLiteralCrVsCharRefCrDoNotCollide();
  testCdataLiteralCrFoldsToLf();
  testTextWrappingStyleDoNotCollide();
  testLiteralCrlfFoldsToSingleSpace();
  testLiteralSpacesPreserved();
  testWrappingStyleAttributesDoNotCollide();
  testCanonicalizeByIdNormalizes();
}

if (require.main === module) {
  try { run(); console.log("OK — xml-c14n-attr-normalization"); process.exit(0); }
  catch (e) { console.error(e && e.message ? e.message : e); process.exit(1); }
}
module.exports = { run: run };
