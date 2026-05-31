"use strict";
/**
 * codepoint-class — shared codepoint-table threat catalog and regex
 * compiler for the guard-* family.
 *
 * Threat detectors that need to match Unicode bidi overrides, C0
 * control characters, zero-width / invisible chars, etc. compose
 * regex character classes from numeric codepoint range tables here
 * instead of embedding the attack characters directly in their
 * source files. Centralizing the tables means:
 *
 *   - Source files in lib/guard-* stay pure ASCII (zero
 *     irregular-whitespace lint findings, no eslint-disable comments
 *     for this category).
 *   - Adding / removing a codepoint from the catalog is a single
 *     edit; every guard picks up the change.
 *   - The detector composes the way an attacker would compose the
 *     payload (programmatic codepoint emission, not literal typing).
 *
 * Surface:
 *
 *   hex4(cp)              -> "\\uXXXX" escape for a single codepoint
 *   charClass(ranges)     -> regex character class body for a range
 *                            table (e.g. [0x200E, [0x202A,0x202E]])
 *   fromCp(cp)            -> String.fromCharCode shorthand
 *   ranges()              -> { BIDI_RANGES, C0_CTRL_RANGES,
 *                              ZERO_WIDTH_RANGES }
 *   compiled()            -> { BIDI_RE, BIDI_RE_G, C0_CTRL_RE,
 *                              C0_CTRL_RE_G, ZERO_WIDTH_RE, ZW_RE_G,
 *                              NULL_RE_G, NULL_BYTE, BOM_CHAR }
 *
 * The compiled() exports are RegExp instances built from the
 * codepoint tables at module load. Consumers grab them once at boot.
 *
 * Codepoint tables:
 *
 *   BIDI_RANGES — Unicode bidi-override family (CVE-2021-42574
 *     Trojan Source). LRM U+200E / RLM U+200F / ALM U+061C / LRE
 *     U+202A / RLE U+202B / PDF U+202C / LRO U+202D / RLO U+202E /
 *     LRI U+2066 / RLI U+2067 / FSI U+2068 / PDI U+2069.
 *
 *   C0_CTRL_RANGES — C0 control characters minus tab (U+09) / lf
 *     (U+0A) / cr (U+0D) — those are dialect-shaped chars that
 *     parsers handle separately. Everything else (U+00, U+01-U+08,
 *     U+0B-U+0C, U+0E-U+1F) flagged as control-byte injection.
 *
 *   ZERO_WIDTH_RANGES — invisible-formatting / zero-width chars
 *     attackers use to hide payloads:
 *     SHY  U+00AD  ZWSP U+200B  ZWNJ U+200C  ZWJ  U+200D
 *     WJ   U+2060  BOM  U+FEFF
 */

var HEX_RADIX = 16;                                                 // base-16 radix, not byte size

function hex4(cp) {
  var s = cp.toString(HEX_RADIX).toUpperCase();
  while (s.length < 4) s = "0" + s;
  return "\\u" + s;
}
function charClass(rangeList) {
  return rangeList.map(function (r) {
    return Array.isArray(r) ? hex4(r[0]) + "-" + hex4(r[1]) : hex4(r);
  }).join("");
}
function fromCp(cp) { return String.fromCharCode(cp); }

var BIDI_RANGES       = [0x200E, 0x200F, 0x061C, [0x202A, 0x202E], [0x2066, 0x2069]];
var C0_CTRL_RANGES    = [[0x0000, 0x0008], 0x000B, 0x000C, [0x000E, 0x001F]];
var ZERO_WIDTH_RANGES = [0x00AD, [0x200B, 0x200D], 0x2060, 0xFEFF];

// allow:dynamic-regex — codepoints from BIDI_RANGES literal table
var BIDI_RE       = new RegExp("[" + charClass(BIDI_RANGES) + "]");
// allow:dynamic-regex — codepoints from BIDI_RANGES literal table
var BIDI_RE_G     = new RegExp("[" + charClass(BIDI_RANGES) + "]", "g");
// allow:dynamic-regex — codepoints from C0_CTRL_RANGES literal table
var C0_CTRL_RE    = new RegExp("[" + charClass(C0_CTRL_RANGES) + "]");
// allow:dynamic-regex — codepoints from C0_CTRL_RANGES literal table
var C0_CTRL_RE_G  = new RegExp("[" + charClass(C0_CTRL_RANGES) + "]", "g");
// allow:dynamic-regex — codepoints from ZERO_WIDTH_RANGES literal table
var ZERO_WIDTH_RE = new RegExp("[" + charClass(ZERO_WIDTH_RANGES) + "]");
// allow:dynamic-regex — codepoints from ZERO_WIDTH_RANGES literal table
var ZW_RE_G       = new RegExp("[" + charClass(ZERO_WIDTH_RANGES) + "]", "g");
// allow:dynamic-regex — single literal codepoint U+0000
var NULL_RE_G     = new RegExp(hex4(0x0000), "g");

var NULL_BYTE = fromCp(0x0000);
var BOM_CHAR  = fromCp(0xFEFF);

// Unicode script-range catalog for IDN-homograph / mixed-script
// confusable detection (UTS #39). Used by guard-domain, guard-email,
// safe-url IDN host-label classification, and any future caller that
// needs "is this label entirely one writing system?". Centralizing the
// table keeps the codepoint definitions in one place — adding a script
// is a single edit.
var SCRIPT_RANGES = {
  latin:    [[0x0041, 0x005A], [0x0061, 0x007A],
             [0x00C0, 0x024F], [0x1E00, 0x1EFF]],                                 // Unicode script ranges
  cyrillic: [[0x0400, 0x04FF], [0x0500, 0x052F]],                                 // Unicode Cyrillic + Cyrillic Supplement
  greek:    [[0x0370, 0x03FF], [0x1F00, 0x1FFF]],                                 // Unicode Greek + Greek Extended
  armenian: [[0x0530, 0x058F]],                                                   // Unicode Armenian
  cherokee: [[0x13A0, 0x13FF], [0xAB70, 0xABBF]],                                 // Unicode Cherokee + Cherokee Supplement
  han:      [[0x4E00, 0x9FFF]],                                                   // CJK Unified Ideographs
  hiragana: [[0x3040, 0x309F]],                                                   // Hiragana
  katakana: [[0x30A0, 0x30FF]],                                                   // Katakana
  hangul:   [[0xAC00, 0xD7AF]],                                                   // Hangul Syllables
  arabic:   [[0x0600, 0x06FF]],                                                   // Arabic
  hebrew:   [[0x0590, 0x05FF]],                                                   // Hebrew
};

// scriptFor(cp) — returns the script-name string for a codepoint, or
// null when the codepoint is in a script not in the catalog (digits,
// punctuation, symbols, etc. are not script-classifying).
function scriptFor(cp) {
  var keys = Object.keys(SCRIPT_RANGES);
  for (var i = 0; i < keys.length; i += 1) {
    var ranges = SCRIPT_RANGES[keys[i]];
    for (var j = 0; j < ranges.length; j += 1) {
      if (cp >= ranges[j][0] && cp <= ranges[j][1]) return keys[i];
    }
  }
  return null;
}

// detectMixedScripts(label, allowedScripts?) — returns null when the
// label is single-script (or every script appears in the optional
// allowedScripts allowlist), or an array of the detected script names
// when the label mixes scripts (homograph attack shape — Cyrillic 'а'
// inside an otherwise-Latin label, etc.). The result is the FULL set
// of scripts seen; callers decide refuse / audit / strip.
//
// allowedScripts: an array of script names the caller treats as
// acceptable; when supplied, a label whose every script is on the list
// returns null even if multiple scripts appear (legitimate mixed-
// script content like an English word inside a Japanese label).
function detectMixedScripts(label, allowedScripts) {
  if (typeof label !== "string" || label.length === 0) return null;
  var seen = {};
  for (var i = 0; i < label.length; i += 1) {
    var script = scriptFor(label.charCodeAt(i));
    if (script === null) continue;
    seen[script] = true;
  }
  var scripts = Object.keys(seen);
  if (scripts.length <= 1) return null;
  if (!allowedScripts) return scripts;
  for (var k = 0; k < scripts.length; k += 1) {
    if (allowedScripts.indexOf(scripts[k]) === -1) return scripts;
  }
  return null;
}

// detectCharThreats — returns an array of issue objects for character-
// class threats (bidi / null / C0-control) per the opts policy. Emits
// at most one issue per class. Used by guard-* primitives' detection
// pass instead of repeating the per-class match-and-push block.
//
// Issue shape mirrors guard-* convention:
//   { kind, severity, ruleId, location, snippet }
//
//   issues.push.apply(issues,
//     codepointClass.detectCharThreats(text, opts, "html"));
function detectCharThreats(text, opts, codePrefix) {
  var issues = [];
  if (typeof text !== "string") return issues;
  if (opts && opts.bidiPolicy !== "allow") {
    var bidiMatch = text.match(BIDI_RE);
    if (bidiMatch) {
      issues.push({
        kind: "bidi-override", severity: "critical",
        ruleId: codePrefix + ".bidi",
        location: bidiMatch.index,
        snippet: "Unicode bidi override (CVE-2021-42574 Trojan Source)",
      });
    }
  }
  if (opts && opts.nullBytePolicy !== "allow") {
    var nullIdx = text.indexOf(NULL_BYTE);
    if (nullIdx >= 0) {
      issues.push({
        kind: "null-byte", severity: "critical",
        ruleId: codePrefix + ".null-byte",
        location: nullIdx,
        snippet: "null byte at byte " + nullIdx,
      });
    }
  }
  if (opts && opts.controlPolicy !== "allow") {
    var ctrlMatch = text.match(C0_CTRL_RE);
    if (ctrlMatch) {
      issues.push({
        kind: "control-char", severity: "high",
        ruleId: codePrefix + ".control",
        location: ctrlMatch.index,
        snippet: "C0 control char U+" + ctrlMatch[0].charCodeAt(0).toString(HEX_RADIX),
      });
    }
  }
  return issues;
}

// assertNoCharThreats — throws an instance of errorFactory(code, msg)
// when the text contains a class that's set to "reject" in opts.
// Opt-name vocabulary: bidiPolicy / nullBytePolicy / controlPolicy
// (the standard guard-* family naming; older guard-csv uses different
// names and keeps its inline checks).
function assertNoCharThreats(text, opts, errorFactory, codePrefix) {
  if (typeof text !== "string") return;
  if (opts && opts.bidiPolicy === "reject" && BIDI_RE.test(text)) {           // allow:regex-no-length-cap — caller bounds length before invoking
    throw errorFactory(codePrefix + ".bidi",
      "input contains Unicode bidi override (CVE-2021-42574)");
  }
  if (opts && opts.nullBytePolicy === "reject" && text.indexOf(NULL_BYTE) !== -1) {
    throw errorFactory(codePrefix + ".null-byte",
      "input contains null byte");
  }
  if (opts && opts.controlPolicy === "reject" && C0_CTRL_RE.test(text)) {     // allow:regex-no-length-cap — caller bounds length before invoking
    throw errorFactory(codePrefix + ".control",
      "input contains C0 control character");
  }
}

// applyCharStripPolicies — given a text and a policy object, apply
// strip-mode replacements for each character-class threat. Reads:
//   opts.bidiPolicy === "strip"      -> strip BIDI overrides
//   opts.controlPolicy === "strip"   -> strip C0 controls
//   opts.nullBytePolicy === "strip"  -> strip null bytes
//   opts.zeroWidthPolicy === "strip" -> strip zero-widths
// Returns the cleaned string. Used by every guard's sanitize path so
// each one doesn't reinvent the same sequence of replace() calls.
function applyCharStripPolicies(text, opts) {
  if (typeof text !== "string") return text;
  var out = text;
  if (opts && opts.bidiPolicy === "strip")      out = out.replace(BIDI_RE_G, "");
  if (opts && opts.controlPolicy === "strip")   out = out.replace(C0_CTRL_RE_G, "");
  if (opts && opts.nullBytePolicy === "strip")  out = out.replace(NULL_RE_G, "");
  if (opts && opts.zeroWidthPolicy === "strip") out = out.replace(ZW_RE_G, "");
  return out;
}

module.exports = {
  hex4:              hex4,
  charClass:         charClass,
  fromCp:            fromCp,
  BIDI_RANGES:       BIDI_RANGES,
  C0_CTRL_RANGES:    C0_CTRL_RANGES,
  ZERO_WIDTH_RANGES: ZERO_WIDTH_RANGES,
  BIDI_RE:           BIDI_RE,
  BIDI_RE_G:         BIDI_RE_G,
  C0_CTRL_RE:        C0_CTRL_RE,
  C0_CTRL_RE_G:      C0_CTRL_RE_G,
  ZERO_WIDTH_RE:     ZERO_WIDTH_RE,
  ZW_RE_G:           ZW_RE_G,
  NULL_RE_G:         NULL_RE_G,
  NULL_BYTE:         NULL_BYTE,
  BOM_CHAR:          BOM_CHAR,
  applyCharStripPolicies: applyCharStripPolicies,
  assertNoCharThreats:    assertNoCharThreats,
  detectCharThreats:      detectCharThreats,
  SCRIPT_RANGES:          SCRIPT_RANGES,
  scriptFor:              scriptFor,
  detectMixedScripts:     detectMixedScripts,
};
