// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.codepointClass
 * @nav    Validation
 * @title  Codepoint Class
 *
 * @intro
 *   The Unicode threat-codepoint catalog the <code>b.guard*</code> family
 *   screens with — bidi overrides, C0 controls, zero-width and invisible
 *   formatting, the null byte, the Unicode Tags block, and UTS&nbsp;#39
 *   confusable-script classification. Each class is a numeric range table plus
 *   the scanners that read it, so a consumer building a custom free-text screen
 *   composes the same tables the guards do instead of retyping a character
 *   class (where the zero-width set comes out one codepoint short and the
 *   astral Tags block — the "ASCII smuggling" carrier — is missed entirely).
 *   For a ready-made screen over unconstrained free text reach for
 *   <code>b.guardText</code>; use this catalog when you need the raw
 *   detectors, tables, or the script classifier.
 *
 *   The scanners walk codepoints and carry no regular expression. A character
 *   class assembled as a pattern is a second grammar between the table and the
 *   text, and it is where this catalog's misses have come from: an astral
 *   codepoint written as a four-digit escape re-parses into a range that
 *   matches almost everything, and a global pattern reused across calls carries
 *   its own cursor and answers differently the second time. A walk over
 *   <code>codePointAt</code> has neither failure available to it.
 *
 *   Attack characters are emitted from the numeric tables at runtime rather
 *   than typed, so every file in the family stays pure ASCII and a payload
 *   cannot hide in a source literal.
 *
 * Surface:
 *
 *   inRanges(cp, ranges)      -> is this codepoint in the table?
 *   firstInRanges(s, ranges)  -> index of the first member, or -1
 *   stripRanges(s, ranges)    -> `s` with every member removed
 *   indexOfAny(s, chars)      -> index of the first char from a set, or -1
 *   replaceAny(s, chars, to)  -> every char from a set replaced
 *   trimChars(s, chars)       -> leading + trailing run of a set removed
 *   containsFolded(s, needle) -> substring search, ASCII case-insensitive
 *   indexOfFolded(s, needle)  -> the same search, reporting where
 *   matchesAtFolded(s, at, n) -> does `n` sit exactly at this index?
 *   hex4(cp)                  -> "\\uXXXX" escape for one codepoint
 *   charClass(ranges)         -> character-class body for a range table,
 *                                for a caller assembling a pattern of
 *                                its own (the guards do not)
 *   fromCp(cp)                -> String.fromCharCode shorthand
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
 *
 * @card
 *   The Unicode threat-codepoint catalog (bidi / control / zero-width / Tags
 *   tables plus confusable-script detection) the guard family screens with —
 *   exposed so you can build a custom free-text screen without retyping the
 *   character classes.
 */

var caseFoldClasses = require("./case-fold-classes");

var HEX_RADIX = 16;                                                 // base-16 radix, not byte size

/**
 * @primitive b.codepointClass.hex4
 * @signature b.codepointClass.hex4(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.charClass, b.codepointClass.fromCp
 *
 * Format a codepoint as a 4-digit `\uXXXX` regex escape (zero-padded, upper
 * case) — the building block `charClass` uses to compile a range table into a
 * character-class body without embedding the attack character as a literal.
 *
 * @example
 *   b.codepointClass.hex4(0x202E);   // returns the escape "\\u202E"
 */
function hex4(cp) {
  var s = cp.toString(HEX_RADIX).toUpperCase();
  while (s.length < 4) s = "0" + s;
  return "\\u" + s;
}
/**
 * @primitive b.codepointClass.charClass
 * @signature b.codepointClass.charClass(rangeList)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.hex4, b.codepointClass.detectCharThreats
 *
 * Compile a codepoint range table — numbers and `[lo, hi]` pairs — into a regex
 * character-class body (the inner text of `[...]`), so a detector can build its
 * own class from a catalog table without typing the codepoints as literals.
 *
 * A codepoint above U+FFFF is emitted as `\u{...}`, which the resulting regex
 * needs the `u` flag to read. The 4-digit form cannot express one, and the
 * failure is not a missed match: `0-F` re-parses as ``, the
 * range `0`-``, and `F` — a class matching nearly every character, so a
 * threat matcher built from an astral table would fire on ordinary text. A
 * table of only BMP codepoints compiles as before and needs no flag.
 *
 * @example
 *   var body = b.codepointClass.charClass([0x200E, [0x202A, 0x202E]]);
 *   var re = new RegExp("[" + body + "]");
 *
 *   // Astral table — the compiled class requires the `u` flag.
 *   var tags = b.codepointClass.charClass([[0xE0000, 0xE007F]]);
 *   var tagRe = new RegExp("[" + tags + "]", "u");
 */
function charClass(rangeList) {
  return rangeList.map(function (r) {
    return Array.isArray(r) ? _classEscape(r[0]) + "-" + _classEscape(r[1])
                            : _classEscape(r);
  }).join("");
}

// `\uXXXX` for a BMP codepoint (what every existing caller compiles without a
// flag), `\u{...}` above it — the only form that can express an astral
// codepoint, and one the caller reads with the `u` flag.
function _classEscape(cp) {
  return cp > 0xFFFF ? "\\u{" + cp.toString(16).toUpperCase() + "}" : hex4(cp);
}

/**
 * @primitive b.codepointClass.inRanges
 * @signature b.codepointClass.inRanges(cp, ranges)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.firstInRanges, b.codepointClass.stripRanges
 *
 * Whether codepoint `cp` falls in a range table — the same tables the threat
 * catalog is built from, where each entry is a bare codepoint or a `[lo, hi]`
 * pair.
 *
 * @example
 *   b.codepointClass.inRanges(0x202E, b.codepointClass.BIDI_RANGES);   // → true
 */
function inRanges(cp, ranges) {
  for (var i = 0; i < ranges.length; i += 1) {
    var r = ranges[i];
    if (typeof r === "number") { if (cp === r) return true; continue; }
    if (cp >= r[0] && cp <= r[1]) return true;
  }
  return false;
}

/**
 * @primitive b.codepointClass.firstInRanges
 * @signature b.codepointClass.firstInRanges(text, ranges, from?)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.inRanges, b.codepointClass.stripRanges
 *
 * Index of the first codepoint of `text` at or after `from` that falls in
 * `ranges`, or `-1`. The index is a UTF-16 code-unit offset, matching a JS
 * string index.
 *
 * The walk reads whole codepoints and steps over surrogate pairs, which the
 * astral tables require: the Unicode Tags block lives at U+E0000 and up, and a
 * `charCodeAt` walk would read its two surrogates as unrelated BMP codepoints
 * and never match the block at all.
 *
 * @example
 *   b.codepointClass.firstInRanges("ok" + String.fromCodePoint(0xE0041),
 *     b.codepointClass.TAG_RANGES);                                   // → 2
 */
function firstInRanges(text, ranges, from) {
  if (typeof text !== "string") return -1;
  // Floored, because the returned value is a string index: `codePointAt`
  // truncates internally, so a fractional `from` would otherwise carry its
  // fraction into the answer and name an offset no character starts at.
  var start = from > 0 ? Math.floor(from) : 0;
  // A `from` landing on the second half of a surrogate pair belongs to a
  // character that STARTS before `from`, so it is not at or after it. Step
  // past the orphaned half rather than back onto a character the caller has
  // already scanned past — returning an index below `from` would make a
  // caller that advances `from` in a loop run forever.
  if (start > 0 && start < text.length) {
    var here = text.charCodeAt(start);
    var before = text.charCodeAt(start - 1);
    if (here >= 0xDC00 && here <= 0xDFFF && before >= 0xD800 && before <= 0xDBFF) {
      start += 1;
    }
  }
  for (var i = start; i < text.length; ) {
    var cp = text.codePointAt(i);
    if (inRanges(cp, ranges)) return i;
    i += cp > 0xFFFF ? 2 : 1;
  }
  return -1;
}

// The shape the detectors want: `{ index, char, codePoint }` for the first
// codepoint of `text` in `ranges`, or null. `char` is the WHOLE codepoint,
// which for an astral hit is a surrogate pair.
function _firstHit(text, ranges) {
  var i = firstInRanges(text, ranges);
  if (i === -1) return null;
  var cp = text.codePointAt(i);
  return { index: i, char: String.fromCodePoint(cp), codePoint: cp };
}

/**
 * @primitive b.codepointClass.stripRanges
 * @signature b.codepointClass.stripRanges(text, ranges)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.firstInRanges, b.codepointClass.applyCharStripPolicies
 *
 * `text` with every codepoint in `ranges` removed. Returns the original string
 * when nothing matched, so a clean input costs no copy.
 *
 * @example
 *   b.codepointClass.stripRanges("a" + String.fromCharCode(0x200B) + "b",
 *     b.codepointClass.ZERO_WIDTH_RANGES);                            // → "ab"
 */
function stripRanges(text, ranges) {
  return replaceRanges(text, ranges, "");
}

/**
 * @primitive b.codepointClass.replaceRanges
 * @signature b.codepointClass.replaceRanges(text, ranges, replacement)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.stripRanges, b.codepointClass.replaceAny
 *
 * `text` with every codepoint in `ranges` replaced by `replacement`.
 * `stripRanges` is this with an empty replacement.
 *
 * One replacement per CODEPOINT, so a character above U+FFFF becomes a single
 * `replacement` rather than two — a filename sanitizer that emits one
 * underscore per surrogate has told the operator a single character was two.
 *
 * @example
 *   b.codepointClass.replaceRanges("a" + String.fromCharCode(0x202E) + "b",
 *     b.codepointClass.BIDI_RANGES, "_");                             // → "a_b"
 */
function replaceRanges(text, ranges, replacement) {
  if (typeof text !== "string") return text;
  var out = "";
  var keepFrom = 0;
  for (var i = 0; i < text.length; ) {
    var cp = text.codePointAt(i);
    var w = cp > 0xFFFF ? 2 : 1;
    if (inRanges(cp, ranges)) {
      out += text.slice(keepFrom, i) + replacement;
      keepFrom = i + w;
    }
    i += w;
  }
  return keepFrom === 0 ? text : out + text.slice(keepFrom);
}
/**
 * @primitive b.codepointClass.indexOfAny
 * @signature b.codepointClass.indexOfAny(text, chars, from?)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.replaceAny, b.codepointClass.trimChars
 *
 * Index of the first character of `text` that appears in `chars`, at or after
 * `from`, or `-1`. `chars` is a plain string used as a set — the characters to
 * find, in any order, with no pattern syntax in it.
 *
 * The set form is what a guard usually wants. A character class written as a
 * pattern has to escape whatever the class syntax reserves, and the reserved
 * set differs between the inside and the outside of the brackets: a `]` or a
 * `-` in the wrong place ends the class early or opens a range, and the result
 * still compiles.
 *
 * Both the set and the subject are read as codepoints, so a character above
 * U+FFFF in either is one member rather than two surrogate halves — a set
 * holding one cannot match half of an unrelated pair.
 *
 * @example
 *   b.codepointClass.indexOfAny("report<final>.csv", "<>:\"/\\|?*");   // → 6
 */
function indexOfAny(text, chars, from) {
  if (typeof text !== "string" || typeof chars !== "string") return -1;
  return firstInRanges(text, _charsToRanges(chars), from);
}

/**
 * @primitive b.codepointClass.replaceAny
 * @signature b.codepointClass.replaceAny(text, chars, replacement)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.indexOfAny, b.codepointClass.stripRanges
 *
 * `text` with EVERY character that appears in `chars` replaced by
 * `replacement` (pass `""` to remove them). Returns the original string when
 * nothing matched.
 *
 * Every one, not the first: a sanitizer that replaces a single occurrence
 * leaves the rest of them in place, and the caller has no way to tell from the
 * return value that it did. One replacement per CODEPOINT, so a character
 * above U+FFFF becomes a single `replacement` rather than two.
 *
 * @example
 *   b.codepointClass.replaceAny("a<b>c", "<>", "_");                  // → "a_b_c"
 */
function replaceAny(text, chars, replacement) {
  if (typeof text !== "string" || typeof chars !== "string") return text;
  return replaceRanges(text, _charsToRanges(chars), replacement);
}

/**
 * @primitive b.codepointClass.trimChars
 * @signature b.codepointClass.trimChars(text, chars, opts?)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.indexOfAny, b.codepointClass.replaceAny
 *
 * `text` with a leading and trailing run of characters drawn from `chars`
 * removed. `opts.leading` / `opts.trailing` (both default `true`) restrict it
 * to one end.
 *
 * @opts
 *   leading:  boolean,   // default: true — trim the run at the start
 *   trailing: boolean,   // default: true — trim the run at the end
 *
 * @example
 *   b.codepointClass.trimChars("  report. ", " .");                   // → "report"
 */
function trimChars(text, chars, opts) {
  if (typeof text !== "string" || typeof chars !== "string") return text;
  return trimRanges(text, _charsToRanges(chars), opts);
}

// A literal character set read as a range table — one entry per CODEPOINT, so
// a set containing an astral character cannot match half of a surrogate pair.
// Character sets reach these helpers spelled out — `ASCII_ALNUM + "._-"` — and
// the same spelling arrives on every call from a hot path. Building the table
// once per distinct set, with adjacent codepoints collapsed into a range, turns
// a per-character membership test over sixty-five entries into one over four.
// The cache is bounded because a caller may pass a set it derived from input.
var _RANGE_CACHE = new Map();
var _RANGE_CACHE_MAX = 256;

function _charsToRanges(chars) {
  var cached = _RANGE_CACHE.get(chars);
  if (cached !== undefined) return cached;

  var points = [];
  for (var i = 0; i < chars.length; ) {
    var cp = chars.codePointAt(i);
    points.push(cp);
    i += cp > 0xFFFF ? 2 : 1;
  }
  points.sort(function (a, b) { return a - b; });

  var out = [];
  for (var k = 0; k < points.length; ) {
    var lo = points[k];
    var hi = lo;
    k += 1;
    while (k < points.length && points[k] <= hi + 1) { hi = points[k]; k += 1; }
    out.push(hi === lo ? lo : [lo, hi]);
  }

  if (_RANGE_CACHE.size >= _RANGE_CACHE_MAX) _RANGE_CACHE.clear();
  _RANGE_CACHE.set(chars, out);
  return out;
}

/**
 * @primitive b.codepointClass.trimRanges
 * @signature b.codepointClass.trimRanges(text, ranges, opts?)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.trimChars, b.codepointClass.stripRanges
 *
 * `trimChars` over a codepoint range table instead of a literal set — for the
 * classes too large to type out, `WHITESPACE_RANGES` above all.
 *
 * @opts
 *   leading:  boolean,   // default: true — trim the run at the start
 *   trailing: boolean,   // default: true — trim the run at the end
 *
 * @example
 *   var nbsp = String.fromCharCode(0x00A0);
 *   b.codepointClass.trimRanges(nbsp + " report\t",
 *     b.codepointClass.WHITESPACE_RANGES);                            // → "report"
 */
function trimRanges(text, ranges, opts) {
  if (typeof text !== "string") return text;
  var start = 0;
  var end = text.length;
  // Whole codepoints from both ends: a `charCodeAt` walk reads an astral
  // member as two unrelated surrogates, so a table like TAG_RANGES would trim
  // nothing at all.
  if (!opts || opts.leading !== false) {
    while (start < end) {
      var lead = text.codePointAt(start);
      if (!inRanges(lead, ranges)) break;
      start += lead > 0xFFFF ? 2 : 1;
    }
  }
  if (!opts || opts.trailing !== false) {
    while (end > start) {
      var width = _trailingCodePointWidth(text, end);
      var trail = text.codePointAt(end - width);
      if (!inRanges(trail, ranges)) break;
      end -= width;
    }
  }
  return start === 0 && end === text.length ? text : text.slice(start, end);
}

// How many code units the codepoint ENDING at `end` occupies: 2 when the two
// units before `end` are a surrogate pair, 1 otherwise.
function _trailingCodePointWidth(text, end) {
  if (end < 2) return 1;
  var low = text.charCodeAt(end - 1);
  var high = text.charCodeAt(end - 2);
  var isPair = high >= 0xD800 && high <= 0xDBFF && low >= 0xDC00 && low <= 0xDFFF;
  return isPair ? 2 : 1;
}


/**
 * @primitive b.codepointClass.isRunOf
 * @signature b.codepointClass.isRunOf(text, chars, min?, max?)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.indexOfAny, b.codepointClass.isAsciiLetter
 *
 * Is every character of `text` drawn from `chars`, with a length between `min`
 * (default 1) and `max` (default unbounded)? The anchored, length-bounded
 * token shape a protocol grammar is written in — an IMAP tag, a message
 * number, an ESMTP parameter name.
 *
 * Both the set and the length are read in CODEPOINTS. For the ASCII token
 * grammars this exists for the two are the same count; for anything else, a
 * character above U+FFFF is one member and one unit of length rather than
 * two surrogate halves.
 *
 * `ASCII_DIGITS`, `ASCII_ALPHA`, `ASCII_ALNUM` and `ASCII_HEX` ship beside it
 * so a set reads as `b.codepointClass.ASCII_ALNUM + "._-"` rather than as
 * sixty-two typed characters.
 *
 * @example
 *   var CP = b.codepointClass;
 *   CP.isRunOf("A001", CP.ASCII_ALNUM + "._-", 1, 64);               // → true
 *   CP.isRunOf("", CP.ASCII_DIGITS);                                 // → false
 */
function isRunOf(text, chars, min, max) {
  if (typeof chars !== "string") return false;
  return isRunOfRanges(text, _charsToRanges(chars), min, max);
}

/**
 * @primitive b.codepointClass.isRunOfRanges
 * @signature b.codepointClass.isRunOfRanges(text, ranges, min?, max?)
 * @since     0.18.31
 * @status    stable
 * @related   b.codepointClass.isRunOf, b.codepointClass.inRanges
 *
 * `isRunOf` against a RANGE TABLE rather than a spelled-out set — for the
 * grammars whose alphabet is a span rather than a list, where writing out the
 * ninety-five printable ASCII characters would obscure what the rule is.
 *
 * @example
 *   var CP = b.codepointClass;
 *   CP.isRunOfRanges("hi there", [0x0009, [0x0020, 0x007E]], 0);      // → true
 */
function isRunOfRanges(text, ranges, min, max) {
  if (typeof text !== "string" || !Array.isArray(ranges)) return false;
  var lo = typeof min === "number" ? min : 1;
  // Codepoints on both sides: a set holding a character above U+FFFF would
  // otherwise admit either surrogate half on its own, and a length bound
  // measured in code units would count one character as two.
  var count = 0;
  for (var i = 0; i < text.length; ) {
    var cp = text.codePointAt(i);
    if (!inRanges(cp, ranges)) return false;
    count += 1;
    if (typeof max === "number" && count > max) return false;
    i += cp > 0xFFFF ? 2 : 1;
  }
  // The bound is checked again here so it also applies to a zero-length run,
  // which never enters the loop.
  if (typeof max === "number" && count > max) return false;
  return count >= lo;
}

var ASCII_DIGITS = "0123456789";
var ASCII_ALPHA  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
var ASCII_ALNUM  = ASCII_ALPHA + ASCII_DIGITS;
var ASCII_HEX    = ASCII_DIGITS + "ABCDEFabcdef";

/**
 * @primitive b.codepointClass.containsFolded
 * @signature b.codepointClass.containsFolded(haystack, needle)
 * @since     0.18.29
 * @status    stable
 * @related   b.codepointClass.indexOfAny
 *
 * Does `haystack` contain `needle`, comparing ASCII letters without regard to
 * case? Non-ASCII characters compare exactly.
 *
 * The ASCII-only fold is the point. Lower-casing the whole subject first is
 * the obvious alternative and it moves the text underneath the answer: several
 * codepoints case-map to more than one character, so an index into the folded
 * string no longer refers to the same place in the original — and the caller
 * that then reports an offset, or slices around the hit, is off by however
 * many characters expanded ahead of it.
 *
 * @example
 *   b.codepointClass.containsFolded("dir/%2E%2E/etc", "%2e%2e");      // → true
 */
function containsFolded(haystack, needle) {
  return indexOfFolded(haystack, needle, 0) !== -1;
}

/**
 * @primitive b.codepointClass.matchesAtFolded
 * @signature b.codepointClass.matchesAtFolded(text, at, needle)
 * @since     0.18.31
 * @status    stable
 * @related   b.codepointClass.indexOfFolded, b.codepointClass.containsFolded
 *
 * Does `needle` appear in `text` starting exactly at index `at`, comparing
 * ASCII letters without regard to case? Non-ASCII characters compare exactly.
 *
 * This is the shape a scanner needs when it has already found its anchor and
 * wants to know what follows it — the question a `.startsWith` on a slice
 * answers by allocating a copy of the rest of the document at every candidate
 * position, which is how a screen that reads in one pass becomes one that
 * reads in a pass per character.
 *
 * @example
 *   b.codepointClass.matchesAtFolded("<!DOCTYPE html>", 0, "<!doctype");   // → true
 */
function matchesAtFolded(text, at, needle) {
  if (typeof text !== "string" || typeof needle !== "string") return false;
  if (at < 0 || at + needle.length > text.length) return false;
  for (var j = 0; j < needle.length; j += 1) {
    if (_foldAscii(text.charCodeAt(at + j)) !== _foldAscii(needle.charCodeAt(j))) return false;
  }
  return true;
}

/**
 * @primitive b.codepointClass.indexOfFolded
 * @signature b.codepointClass.indexOfFolded(haystack, needle, from?)
 * @since     0.18.31
 * @status    stable
 * @related   b.codepointClass.containsFolded, b.codepointClass.matchesAtFolded
 *
 * Index of the first occurrence of `needle` in `haystack` at or after `from`
 * (default 0), comparing ASCII letters without regard to case, or `-1`. The
 * index refers to the ORIGINAL string — see `containsFolded` for why folding
 * the subject first moves the answer out from under the caller.
 *
 * @example
 *   b.codepointClass.indexOfFolded("a <!ENTITY x>", "<!entity");          // → 2
 */
function indexOfFolded(haystack, needle, from) {
  if (typeof haystack !== "string" || typeof needle !== "string") return -1;
  var start = from > 0 ? Math.floor(from) : 0;
  if (needle.length === 0) return start <= haystack.length ? start : -1;
  var limit = haystack.length - needle.length;
  for (var i = start; i <= limit; i += 1) {
    if (matchesAtFolded(haystack, i, needle)) return i;
  }
  return -1;
}

// Upper-case ASCII letters fold to lower case; everything else is itself.
function _foldAscii(cc) { return cc >= 0x41 && cc <= 0x5A ? cc + 0x20 : cc; }

/**
 * @primitive b.codepointClass.fromCp
 * @signature b.codepointClass.fromCp(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.hex4
 *
 * `String.fromCharCode` shorthand — emit the actual character for a codepoint
 * at runtime (e.g. to build a test fixture) instead of typing the attack
 * character as a source literal.
 *
 * @example
 *   var rlo = b.codepointClass.fromCp(0x202E);   // the U+202E override char
 */
function fromCp(cp) { return String.fromCharCode(cp); }

var BIDI_RANGES       = [0x200E, 0x200F, 0x061C, [0x202A, 0x202E], [0x2066, 0x2069]];
var C0_CTRL_RANGES    = [[0x0000, 0x0008], 0x000B, 0x000C, [0x000E, 0x001F]];
var ZERO_WIDTH_RANGES = [0x00AD, [0x200B, 0x200D], 0x2060, 0xFEFF];
// TAG_RANGES — Unicode Tags block U+E0000..U+E007F. TAG U+E0001 plus
// the printable-ASCII tag map U+E0020..U+E007E carry an invisible copy
// of an ASCII instruction that renders as nothing but is read verbatim
// by an LLM tokenizer — the "ASCII smuggling" / Unicode-Tags prompt-
// injection class. Stripping the block from untrusted prompt segments
// removes the hidden instruction channel.
var TAG_RANGES        = [[0xE0000, 0xE007F]];

// The null byte as a range table, so the strip path reads every class the same
// way rather than special-casing this one.
var NULL_RANGES   = [0x0000];

// The characters a `.` in a regular expression does not match: LF, CR, and
// the two Unicode line separators. Named because "everything except a line
// terminator" is a rule several parsers inherited from the patterns they
// replaced, and a walk has to state it rather than get it for free.
var LINE_TERMINATOR_RANGES = [0x000A, 0x000D, 0x2028, 0x2029];

// Exactly what a regular expression means by `\s`: the WhiteSpace and
// LineTerminator productions together. Written out because the set is much
// wider than the ASCII five and a guard that trims "whitespace" by listing
// space and tab leaves a filename ending in U+00A0 or U+3000 — which Windows
// still trims when it creates the file, so the name on disk is not the name
// that was screened.
var WHITESPACE_RANGES = [
  [0x0009, 0x000D], 0x0020, 0x00A0, 0x1680, [0x2000, 0x200A],
  0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
];

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

/**
 * @primitive b.codepointClass.scriptFor
 * @signature b.codepointClass.scriptFor(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectMixedScripts
 *
 * Return the Unicode script name for a codepoint (`"latin"`, `"cyrillic"`,
 * `"greek"`, `"han"`, ...), or `null` when the codepoint is script-neutral
 * (digits, punctuation, symbols). The classifier `detectMixedScripts` uses to
 * spot homograph / confusable mixing (UTS&nbsp;#39).
 *
 * @example
 *   b.codepointClass.scriptFor("a".charCodeAt(0));   // returns "latin"
 *   b.codepointClass.scriptFor(0x0430);              // returns "cyrillic" (the confusable a)
 */
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

/**
 * @primitive b.codepointClass.detectMixedScripts
 * @signature b.codepointClass.detectMixedScripts(label, allowedScripts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.scriptFor, b.guardText
 *
 * UTS&nbsp;#39 confusable detection: return `null` when `label` is single-script
 * (or every script it uses is in the optional `allowedScripts` allowlist), or
 * the full array of script names when it mixes scripts — the homograph attack
 * shape (a Cyrillic confusable letter inside an otherwise-Latin label). Callers
 * decide refuse / audit / strip. Pass `allowedScripts` to permit legitimate
 * mixing (an ASCII word inside a non-Latin label).
 *
 * @example
 *   b.codepointClass.detectMixedScripts("paypal");   // null (single-script)
 *   var spoof = "pa" + b.codepointClass.fromCp(0x0443) + "pal";  // Cyrillic u (U+0443)
 *   b.codepointClass.detectMixedScripts(spoof);                       // ["latin", "cyrillic"]
 *   b.codepointClass.detectMixedScripts(spoof, ["latin", "cyrillic"]); // null (allowlisted)
 */
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

/**
 * @primitive b.codepointClass.detectCharThreats
 * @signature b.codepointClass.detectCharThreats(text, opts, codePrefix, zeroWidthSeverity)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.assertNoCharThreats, b.codepointClass.applyCharStripPolicies, b.guardText
 *
 * Scan `text` for the character-class threats — bidi override, null byte, C0
 * control, Unicode Tags, and (opt-in) zero-width — and return an array of issue
 * objects `{ kind, severity, ruleId, location, snippet }`, at most one per
 * class. Each class is gated by an opts policy that isn't `"allow"`; `ruleId`
 * is prefixed with `codePrefix`. The non-throwing detection pass the `b.guard*`
 * family shares instead of re-rolling the per-class match-and-push.
 * `zeroWidthSeverity` opts the zero-width scan in and stamps its severity;
 * Unicode Tags follows `tagsPolicy`, or `zeroWidthPolicy` when the guard names
 * no policy of its own.
 *
 * `location` is a UTF-16 code-unit offset into `text`, which is what a JS
 * string index is — NOT a UTF-8 byte offset. After a multibyte character the
 * two differ (an emoji occupies one byte offset of 4 and one code-unit offset
 * of 2), so a caller converting the value for a byte-addressed report converts
 * it explicitly.
 *
 * @opts
 *   bidiPolicy:      string,   // non-"allow" -> flag bidi overrides
 *   nullBytePolicy:  string,   // non-"allow" -> flag null bytes
 *   controlPolicy:   string,   // non-"allow" -> flag C0 controls
 *   zeroWidthPolicy: string,   // non-"allow" (+ zeroWidthSeverity) -> flag zero-width
 *
 * @example
 *   var issues = b.codepointClass.detectCharThreats(
 *     userText, { bidiPolicy: "reject", nullBytePolicy: "reject" }, "comment");
 *   if (issues.length) refuse(issues[0].ruleId);
 */
function detectCharThreats(text, opts, codePrefix, zeroWidthSeverity) {
  var issues = [];
  if (typeof text !== "string") return issues;
  if (opts && opts.bidiPolicy !== "allow") {
    var bidiMatch = _firstHit(text, BIDI_RANGES);
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
        snippet: "null byte at offset " + nullIdx,
      });
    }
  }
  if (opts && opts.controlPolicy !== "allow") {
    var ctrlMatch = _firstHit(text, C0_CTRL_RANGES);
    if (ctrlMatch) {
      issues.push({
        kind: "control-char", severity: "high",
        ruleId: codePrefix + ".control",
        location: ctrlMatch.index,
        snippet: "C0 control char U+" + ctrlMatch.codePoint.toString(HEX_RADIX),
      });
    }
  }
  // Zero-width / invisible-formatting chars — the fourth Trojan-source-class
  // character threat, detected here alongside its siblings so no guard
  // hand-rolls it. OPT-IN AND severity via zeroWidthSeverity: a caller that
  // wants zero-width detection passes the context-appropriate severity
  // ("high" where an invisible char spoofs an identifier / filename / line of
  // text; "warn" where it is cosmetic), and omitting it skips the scan. Gated
  // further on a defined non-`allow` zeroWidthPolicy — flagged under `strip`
  // too (like bidi / null / control) so a zero-width-only input under `strip`
  // reaches the sanitizer and is removed rather than served unchanged.
  if (zeroWidthSeverity && opts && opts.zeroWidthPolicy &&
      opts.zeroWidthPolicy !== "allow") {
    var zwMatch = _firstHit(text, ZERO_WIDTH_RANGES);
    if (zwMatch) {
      issues.push({
        kind: "zero-width", severity: zeroWidthSeverity,
        ruleId: codePrefix + ".zero-width",
        location: zwMatch.index,
        snippet: "zero-width / invisible-formatting char U+" +
                 zwMatch.codePoint.toString(HEX_RADIX) + " at offset " + zwMatch.index,
      });
    }
  }
  // Unicode Tags, under the same policy the strip and assert paths read (an
  // explicit tagsPolicy, else the zero-width one). Detection has to exist for
  // the enforcement to be reachable: a content gate validates first and only
  // sanitizes once validation found something, so a class that is stripped but
  // never reported is stripped only by a direct sanitize call — through the
  // gate the document validates clean and is served with the character intact.
  //
  // Severity follows the resolved POLICY, not the threat's worst case. Several
  // guards refuse a critical finding before their transform runs, so stamping
  // this critical while the policy says `strip` makes their public `sanitize`
  // throw on input it was configured to repair. `reject` is the operator
  // asking to refuse, and gets the severity that refuses; `strip` is a repair
  // instruction and is rated where the repair can happen.
  var tagsPolicy = _tagsPolicy(opts);
  if (tagsPolicy && tagsPolicy !== "allow") {
    var tagMatch = _firstHit(text, TAG_RANGES);
    if (tagMatch) {
      issues.push({
        kind: "unicode-tags",
        severity: tagsPolicy === "reject" ? "critical"
                : tagsPolicy === "audit"  ? "warn" : "high",
        ruleId: codePrefix + ".unicode-tags",
        location: tagMatch.index,
        snippet: "Unicode Tags block char U+" +
                 tagMatch.codePoint.toString(HEX_RADIX).toUpperCase() +
                 " at offset " + tagMatch.index + " (ASCII smuggling)",
      });
    }
  }
  return issues;
}

/**
 * @primitive b.codepointClass.assertNoCharThreats
 * @signature b.codepointClass.assertNoCharThreats(text, opts, errorFactory, codePrefix)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats, b.guardText
 *
 * Throw — via `errorFactory(code, message)` — when `text` contains a character
 * class whose opts policy is `"reject"` (bidi / null byte / C0 control /
 * zero-width / Unicode Tags). The throwing counterpart of `detectCharThreats`,
 * covering the same classes as `applyCharStripPolicies` strips so that between
 * the two every class has an enforcement path at every policy value;
 * `errorFactory` lets the caller raise its own typed error and `codePrefix`
 * namespaces the rule code.
 *
 * The scans are unbounded, so a caller handling untrusted input bounds it
 * first — with `assertWithinMaxBytes`, or with whatever ceiling the guard
 * already applies. This is not done here because several callers reach this
 * point having already refused, truncated or repaired an oversized input under
 * their own rule, and a second ceiling with a different error code would
 * override theirs.
 *
 * A sanitize path calls this BEFORE `applyCharStripPolicies`: the strip table
 * removes only what is set to `"strip"`, so without the assert a class set to
 * `"reject"` would be neither refused nor repaired and the caller would get
 * the threat back verbatim.
 *
 * @opts
 *   bidiPolicy:      string,   // "reject" -> throw on a bidi override
 *   nullBytePolicy:  string,   // "reject" -> throw on a null byte
 *   controlPolicy:   string,   // "reject" -> throw on a C0 control
 *   zeroWidthPolicy: string,   // "reject" -> throw on a zero-width char
 *   tagsPolicy:      string,   // "reject" -> throw on a Unicode Tags char
 *
 * @example
 *   b.codepointClass.assertNoCharThreats(value,
 *     { bidiPolicy: "reject", nullBytePolicy: "reject" },
 *     function (code, msg) { return new TypeError(code + ": " + msg); }, "note");
 */
function assertNoCharThreats(text, opts, errorFactory, codePrefix) {
  if (typeof text !== "string") return;
  if (opts && opts.bidiPolicy === "reject" && firstInRanges(text, BIDI_RANGES) !== -1) {
    throw errorFactory(codePrefix + ".bidi",
      "input contains Unicode bidi override (CVE-2021-42574)");
  }
  if (opts && opts.nullBytePolicy === "reject" && text.indexOf(NULL_BYTE) !== -1) {
    throw errorFactory(codePrefix + ".null-byte",
      "input contains null byte");
  }
  if (opts && opts.controlPolicy === "reject" && firstInRanges(text, C0_CTRL_RANGES) !== -1) {
    throw errorFactory(codePrefix + ".control",
      "input contains C0 control character");
  }
  if (opts && opts.zeroWidthPolicy === "reject" &&
      firstInRanges(text, ZERO_WIDTH_RANGES) !== -1) {
    throw errorFactory(codePrefix + ".zero-width",
      "input contains zero-width / invisible-formatting character");
  }
  if (_tagsPolicy(opts) === "reject" && firstInRanges(text, TAG_RANGES) !== -1) {
    throw errorFactory(codePrefix + ".unicode-tags",
      "input contains Unicode Tags block character (ASCII smuggling)");
  }
}

/**
 * @primitive b.codepointClass.assertWithinMaxBytes
 * @signature b.codepointClass.assertWithinMaxBytes(text, opts, errorFactory, codePrefix)
 * @since     0.18.28
 * @status    stable
 * @related   b.codepointClass.assertNoCharThreats, b.codepointClass.scrubCharThreats
 *
 * Throw `<codePrefix>.too-large` — via `errorFactory(code, message)` — when
 * `text` exceeds `opts.maxBytes` UTF-8 bytes. A no-op when `opts.maxBytes` is
 * absent.
 *
 * This is the ceiling `assertNoCharThreats` and `detectCharThreats` expect a
 * caller to have applied: their scans are unbounded, so on untrusted input the
 * size refusal has to come first or the scans run on whatever an attacker
 * sends. It is a separate call rather than part of those functions because a
 * guard that already refuses, truncates or repairs an oversized input under
 * its own rule must keep its own error, not inherit this one.
 *
 * @opts
 *   maxBytes: number,   // UTF-8 byte ceiling; absent means unbounded
 *
 * @example
 *   b.codepointClass.assertWithinMaxBytes(body, { maxBytes: 1048576 },
 *     function (code, msg) { return new TypeError(code + ": " + msg); }, "note");
 */
function assertWithinMaxBytes(text, opts, errorFactory, codePrefix) {
  if (typeof text !== "string") return;
  if (!opts || typeof opts.maxBytes !== "number") return;
  var nb = Buffer.byteLength(text, "utf8");
  if (nb > opts.maxBytes) {
    throw errorFactory(codePrefix + ".too-large",
      "input " + nb + " bytes exceeds maxBytes " + opts.maxBytes);
  }
}

/**
 * @primitive b.codepointClass.scrubCharThreats
 * @signature b.codepointClass.scrubCharThreats(text, opts, errorFactory, codePrefix)
 * @since     0.18.28
 * @status    stable
 * @related   b.codepointClass.assertNoCharThreats, b.codepointClass.applyCharStripPolicies, b.guardText
 *
 * Bound the input, refuse every character class set to `"reject"`, strip every
 * class set to `"strip"`, and return the cleaned string — the whole sanitize
 * front end for a content guard in one call.
 *
 * The steps belong together because the order between them is what makes a
 * policy mean anything. `applyCharStripPolicies` removes only what is set to
 * `"strip"`, so a guard that calls it alone hands a `"reject"` class straight
 * back to the caller: not refused, not repaired, and no error to say so. And
 * the scans behind the assert are unbounded, so the ceiling has to precede
 * them. Callers that composed the pieces by hand got both of those wrong.
 *
 * Throws `<codePrefix>.too-large` when the input exceeds `opts.maxBytes`
 * (measured in UTF-8 bytes), then whichever `<codePrefix>.<class>` the reject
 * policies name. `errorFactory(code, message)` builds the guard's own typed
 * error.
 *
 * @opts
 *   maxBytes:        number,   // UTF-8 byte ceiling; omitted means unbounded
 *   bidiPolicy:      string,   // "reject" -> throw; "strip" -> remove
 *   nullBytePolicy:  string,
 *   controlPolicy:   string,
 *   zeroWidthPolicy: string,
 *   tagsPolicy:      string,   // defaults to zeroWidthPolicy when unset
 *
 * @example
 *   var clean = b.codepointClass.scrubCharThreats(input,
 *     { maxBytes: 1048576, bidiPolicy: "reject", zeroWidthPolicy: "strip" },
 *     function (code, msg) { return new TypeError(code + ": " + msg); }, "note");
 */
function scrubCharThreats(text, opts, errorFactory, codePrefix) {
  if (typeof text !== "string") return text;
  assertWithinMaxBytes(text, opts, errorFactory, codePrefix);
  assertNoCharThreats(text, opts, errorFactory, codePrefix);
  return applyCharStripPolicies(text, opts);
}

/**
 * @primitive b.codepointClass.applyCharStripPolicies
 * @signature b.codepointClass.applyCharStripPolicies(text, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats, b.guardText
 *
 * Strip each character-class threat whose opts policy is `"strip"` and return
 * the cleaned string — the sanitize counterpart of `detectCharThreats`, shared
 * by every guard's sanitize path so none re-rolls the same sequence of
 * `replace()` calls. Removes bidi overrides, C0 controls, null bytes,
 * zero-width chars, and the Unicode-Tags block ("ASCII smuggling") per policy.
 *
 * @opts
 *   bidiPolicy:      string,   // "strip" -> remove bidi overrides
 *   controlPolicy:   string,   // "strip" -> remove C0 controls
 *   nullBytePolicy:  string,   // "strip" -> remove null bytes
 *   zeroWidthPolicy: string,   // "strip" -> remove zero-width / invisible chars
 *   tagsPolicy:      string,   // "strip" -> remove the Unicode Tags block
 *
 * @example
 *   var clean = b.codepointClass.applyCharStripPolicies(userText,
 *     { bidiPolicy: "strip", zeroWidthPolicy: "strip", tagsPolicy: "strip" });
 */
// The Unicode Tags block is the same threat as a zero-width character — an
// invisible codepoint that renders as nothing in every editor and viewer a
// reviewer would open the content in, so there is no rendering to compare
// against. A guard that has taken a position on zero-width has taken it on
// Tags, and every guard but one names only the former; reading the Tags policy
// through to it closes the ASCII-smuggling channel across the family instead
// of at one member. An explicit tagsPolicy always wins.
function _tagsPolicy(opts) {
  if (!opts) return undefined;
  return opts.tagsPolicy === undefined ? opts.zeroWidthPolicy : opts.tagsPolicy;
}

/**
 * @primitive b.codepointClass.resolveTagsPolicy
 * @signature b.codepointClass.resolveTagsPolicy(opts)
 * @since     0.18.28
 * @related   b.codepointClass.detectCharThreats, b.codepointClass.applyCharStripPolicies
 *
 * The Unicode Tags policy actually in force: `opts.tagsPolicy` when the guard
 * names one, otherwise the `zeroWidthPolicy` it inherits from. Returns
 * `undefined` when neither is set.
 *
 * Exported because the inheritance is a rule, not a convention. A caller that
 * re-derives it by testing `zeroWidthPolicy` alone silently ignores an
 * explicit `tagsPolicy: "allow"` — validation then reports nothing while the
 * scrub path removes the character anyway.
 *
 * @opts
 *   tagsPolicy:      string,   // when set, this is the answer
 *   zeroWidthPolicy: string,   // inherited only when tagsPolicy is unset
 *
 * @example
 *   if (b.codepointClass.resolveTagsPolicy(opts) === "strip") {
 *     text = b.codepointClass.stripRanges(text, b.codepointClass.TAG_RANGES);
 *   }
 */
function resolveTagsPolicy(opts) { return _tagsPolicy(opts); }

function applyCharStripPolicies(text, opts) {
  if (typeof text !== "string") return text;
  var out = text;
  if (opts && opts.bidiPolicy === "strip")      out = stripRanges(out, BIDI_RANGES);
  if (opts && opts.controlPolicy === "strip")   out = stripRanges(out, C0_CTRL_RANGES);
  if (opts && opts.nullBytePolicy === "strip")  out = stripRanges(out, NULL_RANGES);
  if (opts && opts.zeroWidthPolicy === "strip") out = stripRanges(out, ZERO_WIDTH_RANGES);
  if (_tagsPolicy(opts) === "strip")            out = stripRanges(out, TAG_RANGES);
  return out;
}

// REGEXP_META_RE — the full ECMAScript RegExp metacharacter set
// (. * + ? ^ $ { } ( ) | [ ] \).
var REGEXP_META_RE = /[.*+?^${}()|[\]\\]/g;

/**
 * @primitive b.codepointClass.escapeRegExp
 * @signature b.codepointClass.escapeRegExp(s)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.charClass
 *
 * Escape every ECMAScript RegExp metacharacter in a string so an operator- or
 * input-supplied token matches literally when spliced into a `new RegExp(...)`
 * — a token destined for dynamic compilation cannot inject a pattern.
 *
 * @example
 *   var re = new RegExp(b.codepointClass.escapeRegExp("a.b*c"));
 *   re.test("a.b*c");   // true — the . and * are literal
 */
function escapeRegExp(s) {
  return String(s).replace(REGEXP_META_RE, "\\$&");
}

// HEX_PAIR_RE — a percent-escape's two-hex-digit value (RFC 3986 §2.1
// pct-encoded). Percent-decoders test the two characters after a `%`
// against this before parseInt with the hex radix; shared so the literal
// lives once.
var HEX_PAIR_RE = /^[0-9A-Fa-f]{2}$/;

/**
 * @primitive b.codepointClass.isAsciiAlnum
 * @signature b.codepointClass.isAsciiAlnum(cc)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isUnreserved
 *
 * Test whether a char code is an ASCII letter or digit (`A-Z` / `a-z` / `0-9`)
 * — the alphanumeric range check that recurs across every byte-class parser
 * (URL unreserved, XML name chars, header tokens), centralized so the range
 * literals live once.
 *
 * @example
 *   b.codepointClass.isAsciiAlnum("Z".charCodeAt(0));   // true
 *   b.codepointClass.isAsciiAlnum("-".charCodeAt(0));   // false
 */
function isAsciiAlnum(cc) {
  return isAsciiLetter(cc) || isAsciiDigit(cc);
}

/**
 * @primitive b.codepointClass.isAsciiLetter
 * @signature b.codepointClass.isAsciiLetter(cc)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.isAsciiDigit, b.codepointClass.isAsciiAlnum
 *
 * Is this code unit an ASCII letter, `A`-`Z` or `a`-`z`?
 *
 * @example
 *   b.codepointClass.isAsciiLetter("Q".charCodeAt(0));               // → true
 */
function isAsciiLetter(cc) {
  return (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
}

/**
 * @primitive b.codepointClass.isAsciiDigit
 * @signature b.codepointClass.isAsciiDigit(cc)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.isAsciiLetter, b.codepointClass.isAsciiAlnum
 *
 * Is this code unit an ASCII digit, `0`-`9`?
 *
 * @example
 *   b.codepointClass.isAsciiDigit("7".charCodeAt(0));                // → true
 */
function isAsciiDigit(cc) { return cc >= 0x30 && cc <= 0x39; }

/**
 * @primitive b.codepointClass.isAsciiHexDigit
 * @signature b.codepointClass.isAsciiHexDigit(cc)
 * @since     0.18.31
 * @status    stable
 * @related   b.codepointClass.isAsciiDigit, b.codepointClass.isRunOf
 *
 * Is this code unit a hexadecimal digit in either case? The token every
 * percent-escape, numeric character reference, colour literal and binary-
 * encoded identifier is spelled in.
 *
 * @example
 *   b.codepointClass.isAsciiHexDigit("F".charCodeAt(0));             // → true
 */
function isAsciiHexDigit(cc) {
  return isAsciiDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}

/**
 * @primitive b.codepointClass.isIdentifierChar
 * @signature b.codepointClass.isIdentifierChar(cc)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.isAsciiAlnum
 *
 * Is this code unit one a bare identifier is made of — a letter, a digit or an
 * underscore? This is the boundary a token screen tests against: a keyword
 * that runs into one of these is a longer word, so `DATABASE` is not `DATA`
 * and `#ends` is not `#end`.
 *
 * @example
 *   var CP = b.codepointClass;
 *   CP.isIdentifierChar("_".charCodeAt(0));                          // → true
 *   CP.isIdentifierChar("-".charCodeAt(0));                          // → false
 */
function isIdentifierChar(cc) {
  return isAsciiAlnum(cc) || cc === 0x5F;                             // "_"
}

/**
 * @primitive b.codepointClass.splitLines
 * @signature b.codepointClass.splitLines(text)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.splitOnWhitespace
 *
 * Split on LF, dropping a CR immediately before it — a message's lines,
 * whether it uses CRLF or bare LF. A bare CR does NOT end a line, which is
 * what makes one the signal a line-protocol guard screens for.
 *
 * @example
 *   b.codepointClass.splitLines("a\r\nb\nc");                        // → ["a","b","c"]
 */
function splitLines(text) {
  var out = [];
  if (typeof text !== "string") return out;
  var start = 0;
  for (var i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) !== 0x0A) continue;
    var end = i > start && text.charCodeAt(i - 1) === 0x0D ? i - 1 : i;
    out.push(text.slice(start, end));
    start = i + 1;
  }
  out.push(text.slice(start));
  return out;
}

/**
 * @primitive b.codepointClass.splitLinesAny
 * @signature b.codepointClass.splitLinesAny(text)
 * @since     0.18.31
 * @status    stable
 * @related   b.codepointClass.splitLines
 *
 * `splitLines`, but a LONE carriage return ends a line too. This is the rule
 * the wire formats use — a vCard, a delivery status notification, an old-Mac
 * text file — where a producer that emits CR alone still means a new line, and
 * a reader that only knows LF folds the whole document into one.
 *
 * @example
 *   b.codepointClass.splitLinesAny("a\rb\r\nc\nd");            // → ["a","b","c","d"]
 */
function splitLinesAny(text) {
  var out = [];
  if (typeof text !== "string") return out;
  var start = 0;
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc !== 0x0A && cc !== 0x0D) continue;
    out.push(text.slice(start, i));
    // CRLF is one break, not two.
    if (cc === 0x0D && text.charCodeAt(i + 1) === 0x0A) i += 1;
    start = i + 1;
  }
  out.push(text.slice(start));
  return out;
}

/**
 * @primitive b.codepointClass.splitOnWhitespace
 * @signature b.codepointClass.splitOnWhitespace(text)
 * @since     0.18.30
 * @status    stable
 * @related   b.codepointClass.splitLines, b.codepointClass.trimRanges
 *
 * Split on runs of whitespace, dropping the empty pieces — the tokens of a
 * protocol line. Whitespace is the full `\s` set, so a token separated by a
 * no-break space is separated here too.
 *
 * @example
 *   b.codepointClass.splitOnWhitespace("  MAIL   FROM ");            // → ["MAIL","FROM"]
 */
function splitOnWhitespace(text) {
  var out = [];
  if (typeof text !== "string") return out;
  var start = -1;
  for (var i = 0; i < text.length; i += 1) {
    if (inRanges(text.charCodeAt(i), WHITESPACE_RANGES)) {
      if (start !== -1) { out.push(text.slice(start, i)); start = -1; }
    } else if (start === -1) {
      start = i;
    }
  }
  if (start !== -1) out.push(text.slice(start));
  return out;
}

/**
 * @primitive b.codepointClass.isUnreserved
 * @signature b.codepointClass.isUnreserved(cc)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isAsciiAlnum
 *
 * Test whether a char code is in the RFC&nbsp;3986 §2.3 unreserved set —
 * `ALPHA` / `DIGIT` / `-` / `.` / `_` / `~`. A percent-escape of an unreserved
 * character is over-encoding the URI spec says SHOULD be decoded (§6.2.2.3).
 *
 * @example
 *   b.codepointClass.isUnreserved("~".charCodeAt(0));   // true
 *   b.codepointClass.isUnreserved("/".charCodeAt(0));   // false
 */
function isUnreserved(cc) {
  return isAsciiAlnum(cc) ||
         cc === 0x2d ||   // -
         cc === 0x2e ||   // .
         cc === 0x5f ||   // _
         cc === 0x7e;     // ~
}

/**
 * @primitive b.codepointClass.isForbiddenControlChar
 * @signature b.codepointClass.isForbiddenControlChar(code, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.firstControlCharOffset
 *
 * The header-injection / RFC&nbsp;5322 control-byte predicate every "refuse
 * control bytes in a header / line / value" loop shares. Returns `true` for DEL
 * (`0x7f`) and any C0 control (`< 0x20`) other than TAB (`0x09`); LF and CR are
 * refused by default but can be permitted per call (a reader that already split
 * on CRLF, or a folding grammar). Distinct from the `C0_CTRL_RANGES` scanning
 * table, which always exempts LF/CR and never matches DEL.
 *
 * @opts
 *   forbidTab: boolean,   // also forbid TAB -> predicate is `code < 0x20 || code === 0x7f`
 *   allowLf:   boolean,   // permit LF (0x0a)
 *   allowCr:   boolean,   // permit CR (0x0d)
 *
 * @example
 *   b.codepointClass.isForbiddenControlChar(0x00);                 // true (NUL)
 *   b.codepointClass.isForbiddenControlChar(0x09, { forbidTab: true }); // true (TAB forbidden)
 */
function isForbiddenControlChar(code, opts) {
  if (code === 0x7f) return true;          // DEL
  if (code >= 0x20) return false;
  if (code === 0x09 && (!opts || !opts.forbidTab)) return false;  // TAB — permitted unless forbidTab
  if (opts) {
    if (opts.allowLf && code === 0x0a) return false;
    if (opts.allowCr && code === 0x0d) return false;
  }
  return true;
}

/**
 * @primitive b.codepointClass.firstControlCharOffset
 * @signature b.codepointClass.firstControlCharOffset(s, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isForbiddenControlChar
 *
 * Return the index of the first forbidden control char in `s` (under the same
 * `opts` as `isForbiddenControlChar`), or `-1` when none. Callers wrap it as a
 * boolean (`!== -1`), throw with the offending code (`s.charCodeAt(offset)`),
 * or derive a byte offset — replacing the open-coded control-byte scan each
 * parser previously rolled by hand.
 *
 * @opts
 *   forbidTab: boolean,   // also treat TAB as forbidden
 *   allowLf:   boolean,   // permit LF (0x0a)
 *   allowCr:   boolean,   // permit CR (0x0d)
 *
 * @example
 *   b.codepointClass.firstControlCharOffset("ok\x00bad");   // 2 (the NUL)
 *   b.codepointClass.firstControlCharOffset("clean");          // -1
 */
function firstControlCharOffset(s, opts) {
  for (var i = 0; i < s.length; i += 1) {
    if (isForbiddenControlChar(s.charCodeAt(i), opts)) return i;
  }
  return -1;
}

// Decode HTML numeric character references (hex &#x..; and decimal &#..;) just
// enough to expose a scheme hidden behind entity-encoding. The trailing
// semicolon is OPTIONAL — a browser decodes `&#106avascript:` (no semicolon)
// the same as `&#106;avascript:`, so a semicolon-required decoder lets the
// no-semicolon form bypass a scheme allowlist. Shared so guard-html / guard-svg
// / guard-markdown cannot drift on this (the bug class that shipped one buggy
// + one correct copy).
//
// Scanned character by character rather than matched with a regex: a decoder
// that misses one form of a reference is a scheme-allowlist bypass, and the
// regex forms of this have twice shipped a miss nobody could see by reading
// them. `_decodeEntityAt` is the whole grammar in one place, and
// `testEntityDecodersMatchARegexReference` proves it equal to an independently
// written reference over generated input.
var HEX_RADIX_16   = 16;
var DEC_RADIX_10   = 10;
var MAX_CODE_POINT = 0x10FFFF;

function _isAsciiDigit(cc)    { return cc >= 0x30 && cc <= 0x39; }
function _isAsciiHexDigit(cc) {
  return _isAsciiDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}
function _isAsciiAlpha(cc) {
  return (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
}

// One numeric character reference starting at `s[at]` (which the caller has
// already confirmed is `&`), or null when the grammar does not match there.
// Returns the DECODED text plus the index just past the reference, so the
// caller advances exactly as far as the reference ran. A reference whose value
// is out of Unicode range decodes to itself verbatim, matching what a browser
// does with it.
function _decodeNumericEntityAt(s, at) {
  if (s.charCodeAt(at + 1) !== 0x23) return null;                    // "#"
  var c   = s.charCodeAt(at + 2);
  var hex = c === 0x78 || c === 0x58;                                // "x" / "X"
  var i   = at + (hex ? 3 : 2);
  var start = i;
  while (i < s.length &&
         (hex ? _isAsciiHexDigit(s.charCodeAt(i)) : _isAsciiDigit(s.charCodeAt(i)))) i++;
  if (i === start) return null;
  var digits = s.slice(start, i);
  if (s.charCodeAt(i) === 0x3B) i++;                                 // ";" is OPTIONAL
  var verbatim = s.slice(at, i);
  var cp = parseInt(digits, hex ? HEX_RADIX_16 : DEC_RADIX_10);
  if (!isFinite(cp) || cp < 0 || cp > MAX_CODE_POINT) return { text: verbatim, next: i };
  var decoded;
  try { decoded = String.fromCodePoint(cp); } catch (_e) { return { text: verbatim, next: i }; }
  return { text: decoded, next: i };
}
/**
 * @primitive b.codepointClass.decodeNumericEntities
 * @signature b.codepointClass.decodeNumericEntities(s)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats
 *
 * Decode HTML numeric character references (hex `&#x..;` and decimal `&#..;`)
 * just enough to expose a scheme hidden behind entity-encoding. The trailing
 * semicolon is OPTIONAL — a browser decodes `&#106avascript:` (no semicolon)
 * the same as `&#106;avascript:`, so a semicolon-required decoder lets the
 * no-semicolon form slip a scheme past an allowlist. Shared so the markup
 * guards cannot drift on this.
 *
 * @example
 *   b.codepointClass.decodeNumericEntities("&#106;avascript:");   // "javascript:"
 *   b.codepointClass.decodeNumericEntities("&#106avascript:");    // "javascript:" (no semicolon)
 */
function decodeNumericEntities(s) {
  return _decodeEntityRun(String(s == null ? "" : s), _decodeNumericEntityAt);
}

// Walk `text` left to right, handing every `&` to `decodeAt`. Decoded output is
// never re-scanned — an `&` the decode produced stays literal, which is what a
// browser does and what the single-pass regex form did. A run of ordinary
// characters is copied in one slice rather than per character.
function _decodeEntityRun(text, decodeAt) {
  var out     = "";
  var copyFrom = 0;
  var i       = 0;
  while (i < text.length) {
    if (text.charCodeAt(i) !== 0x26) { i++; continue; }               // "&"
    var hit = decodeAt(text, i);
    if (hit === null) { i++; continue; }
    out += text.slice(copyFrom, i) + hit.text;
    i = copyFrom = hit.next;
  }
  return copyFrom === 0 ? text : out + text.slice(copyFrom);
}

// The HTML5 named-entity ASCII subset a browser resolves inside URL and CSS
// attribute contexts — the scheme/whitespace-significant characters an attacker
// hides a payload behind (`java&Tab;script:` / `behavior&colon;`). One table so
// guard-html / guard-svg / guard-markdown decode the SAME set and cannot drift
// (guard-markdown shipped without named-entity decoding at all, so `&Tab;` /
// `&NewLine;` slipped past its scheme denylist).
var NAMED_ENTITY_ASCII = {
  // Whitespace + control chars browsers strip inside URL schemes
  Tab: "\t", NewLine: "\n",
  // Scheme-significant punctuation
  colon: ":", semi: ";", period: ".", sol: "/", bsol: "\\",
  num: "#", excl: "!", quest: "?", lpar: "(", rpar: ")",
  lsqb: "[", rsqb: "]", lcub: "{", rcub: "}",
  // Quotes / brackets
  quot: "\"", apos: "'", lt: "<", gt: ">",
  // Misc ASCII
  amp: "&", commat: "@", dollar: "$", percnt: "%",
  ast: "*", plus: "+", lowbar: "_", hyphen: "-",
  // Latin-1 space browsers treat as URL-strippable
  nbsp: " ",
};
// One named reference starting at `s[at]`: `&`, an ASCII letter, one or more
// further alphanumerics, and a REQUIRED semicolon. A name outside the table
// above decodes to itself, so an unknown entity survives the pass unchanged.
function _decodeNamedEntityAt(s, at) {
  var start = at + 1;
  if (!_isAsciiAlpha(s.charCodeAt(start))) return null;
  var i = start + 1;
  while (i < s.length &&
         (_isAsciiAlpha(s.charCodeAt(i)) || _isAsciiDigit(s.charCodeAt(i)))) i++;
  if (i === start + 1) return null;                                  // needs 2+ name chars
  if (s.charCodeAt(i) !== 0x3B) return null;                         // ";" is REQUIRED
  var name = s.slice(start, i);
  i++;
  if (!Object.prototype.hasOwnProperty.call(NAMED_ENTITY_ASCII, name)) {
    return { text: s.slice(at, i), next: i };
  }
  return { text: NAMED_ENTITY_ASCII[name], next: i };
}

/**
 * @primitive b.codepointClass.decodeMarkupEntities
 * @signature b.codepointClass.decodeMarkupEntities(value)
 * @since     0.16.19
 * @status    stable
 * @related   b.codepointClass.decodeNumericEntities, b.codepointClass.stripUrlSchemeWhitespace
 *
 * Decode the character references a browser resolves inside an attribute value
 * -- numeric (hex/decimal, semicolon OPTIONAL) then the named-entity ASCII
 * subset browsers honor in URL/CSS contexts -- and drop the C0 controls and
 * zero-widths a payload hides behind. The single decoder every content guard
 * routes a scheme / CSS-token danger check through, so a threat cannot slip
 * past the guard that forgot to decode an encoding a sibling strips. Pair with
 * `stripUrlSchemeWhitespace` for a URL-scheme check.
 *
 * @example
 *   b.codepointClass.decodeMarkupEntities("ex&#x70;ression(");   // "expression("
 *   b.codepointClass.decodeMarkupEntities("behavior&colon;");    // "behavior:"
 */
function decodeMarkupEntities(value) {
  var s = decodeNumericEntities(String(value == null ? "" : value));
  s = _decodeEntityRun(s, _decodeNamedEntityAt);
  return stripRanges(stripRanges(s, C0_CTRL_RANGES), ZERO_WIDTH_RANGES);
}

// ASCII tab / LF / CR, which the WHATWG URL parser removes from ANYWHERE in a
// URL, and the leading/trailing run it trims (every C0 control plus space).
var URL_TAB_NEWLINE_RANGES = [0x0009, 0x000A, 0x000D];
var URL_C0_SPACE_RANGES    = [[0x0000, 0x0020]];
/**
 * @primitive b.codepointClass.stripUrlSchemeWhitespace
 * @signature b.codepointClass.stripUrlSchemeWhitespace(s)
 * @since     0.16.19
 * @status    stable
 * @related   b.codepointClass.decodeMarkupEntities, b.codepointClass.decodeNumericEntities
 *
 * Fold away exactly the whitespace the WHATWG URL parser removes before it
 * resolves a scheme: ASCII tab / LF / CR from ANYWHERE, plus a leading/trailing
 * C0-control-or-space run. tab/lf/cr are excluded from the C0-control catalog
 * and space is not a control, so a danger check that strips only C0/zero-width
 * still lets `java<TAB>script:` or an entity-encoded leading space
 * (`&#32;javascript:`) read as scheme-less. Run AFTER entity decoding; every
 * guard that extracts a URL scheme for a denylist routes the decoded value
 * through this.
 *
 * @example
 *   b.codepointClass.stripUrlSchemeWhitespace("  javascript:x");   // "javascript:x"
 */
function stripUrlSchemeWhitespace(s) {
  var text = stripRanges(String(s == null ? "" : s), URL_TAB_NEWLINE_RANGES);
  var start = 0;
  var end   = text.length;
  while (start < end && inRanges(text.charCodeAt(start), URL_C0_SPACE_RANGES)) start++;
  while (end > start && inRanges(text.charCodeAt(end - 1), URL_C0_SPACE_RANGES)) end--;
  return start === 0 && end === text.length ? text : text.slice(start, end);
}

/**
 * @primitive  b.codepointClass.canonicalizeForCase
 * @signature  b.codepointClass.canonicalizeForCase(codePoint, unicode)
 * @since      0.18.19
 * @status     stable
 * @related    b.regexLinear.compile, b.guardRegex.assertSafe
 *
 * The character a regular-expression engine compares when `i` is in force,
 * given a code point and whether the `u` (or `v`) flag applies.
 *
 * It is not "the upper case" and it is not "the lower case". Without `u` the
 * language folds through upper case, keeps a character whose upper case runs to
 * more than one character, and refuses to fold a non-ASCII character onto an
 * ASCII one — the last of which is why `/k/i` does not match a Kelvin sign, and
 * why converting both characters and comparing gets the wrong answer.
 *
 * Under `u` the rule changes to case FOLDING: the ASCII guard drops, so a long
 * s folds onto an `s`, and an expanding upper case no longer stops the fold —
 * a Greek eta with a iota subscript and its capital form both upper-case to two
 * characters and are still the same character there.
 *
 * Two characters are the same under `i` exactly when this returns the same code
 * point for both.
 *
 * @example
 *   var same = b.codepointClass.canonicalizeForCase;
 *   same("k".codePointAt(0), false) === same("K".codePointAt(0), false);   // → true
 *   same("k".codePointAt(0), false) === same(0x212a, false);               // → false (Kelvin)
 *   same("s".codePointAt(0), true)  === same(0x17f, true);                 // → true (long s, under u)
 */
function canonicalizeForCase(cp, unicode) {
  var ch = String.fromCodePoint(cp);
  var upper = ch.toUpperCase();
  // Tolerates a table that predates this field, so the generator that WRITES
  // the table can load this module to build it.
  var corrections = (unicode ? caseFoldClasses.UNICODE_CANONICAL
                             : caseFoldClasses.PLAIN_CANONICAL) || {};
  var corrected = corrections[cp];
  if (corrected !== undefined) return corrected;           // folding lands it wrongly
  if (unicode) {
    // Under `u` the rule is FOLDING, and "the upper case is more than one
    // character" is not part of it. Where the upper case does expand there is
    // nothing to fold through, but the character can still share a simple lower
    // case with its class: a Greek eta with a iota subscript and its capital
    // form both upper-case to two characters and both lower-case to the same
    // one, so stopping at the expansion left them strangers.
    if (_oneCodePoint(upper)) {
      var folded = upper.toLowerCase();
      if (_oneCodePoint(folded)) return folded.codePointAt(0);
    }
    var lowered = ch.toLowerCase();
    return _oneCodePoint(lowered) ? lowered.codePointAt(0) : cp;
  }
  // Without `u` the rule IS upper case, and a character whose upper case runs
  // to more than one keeps itself — which is why `/eta-with-subscript/i` does
  // not match its own capital form although `/…/iu` does. "More than one" is
  // counted in CODE POINTS: counting UTF-16 units would call every astral
  // letter a multi-character mapping and leave Deseret unfolded.
  if (_oneCodePoint(upper) === false) return cp;
  var canon = upper.codePointAt(0);
  if (cp >= 128 && canon < 128) return cp;
  return canon;
}

function _oneCodePoint(s) {
  if (s.length === 1) return true;
  return s.length === 2 && s.codePointAt(0) > 0xFFFF;
}

/**
 * @primitive  b.codepointClass.caseFoldPartners
 * @signature  b.codepointClass.caseFoldPartners(codePoint, unicode)
 * @since      0.18.19
 * @related    b.codepointClass.canonicalizeForCase, b.regexLinear.compile
 *
 * Every OTHER code point a regular expression treats as the same character as
 * this one under `i`, given whether the `u` (or `v`) flag applies.
 *
 * Use it where the characters to compare against are not a list you can walk —
 * matching a character against a class of ranges, say. Where you hold both
 * characters already, `canonicalizeForCase` answers directly and this is not
 * needed.
 *
 * Most partners are the character's own upper and lower forms. Several hundred
 * are not reachable that way — a micro sign and a Greek mu, a final sigma and an
 * ordinary one, the title-case digraphs, under `u` a Kelvin sign and a `k`, the
 * Greek letters carrying a iota subscript beside their capital forms, and two
 * ligatures that share only the "ST" they upper-case to — and those come from a
 * table derived from the running platform's own case mappings rather than
 * transcribed from a Unicode revision.
 *
 * @example
 *   var partners = b.codepointClass.caseFoldPartners;
 *   partners("σ".codePointAt(0), true);   // sigma → includes the final sigma
 *   partners("k".codePointAt(0), false);       // → [ "K" ] — not the Kelvin sign
 */
function caseFoldPartners(cp, unicode) {
  var ch = String.fromCodePoint(cp);
  var target = canonicalizeForCase(cp, unicode);
  var out = [];
  var seen = Object.create(null);
  // Casing REACHES more than it equals. A Kelvin sign lower-cases to a `k` and
  // is still not a `k` without the `u` flag, so each candidate has to canonicalize
  // with the character before it counts as the same one.
  function offer(candidate) {
    if (!_oneCodePoint(candidate)) return;
    var other = candidate.codePointAt(0);
    if (other === cp || seen[other]) return;
    if (canonicalizeForCase(other, unicode) !== target) return;
    seen[other] = true;
    out.push(other);
  }
  offer(ch.toLowerCase());
  offer(ch.toUpperCase());
  offer(ch.toUpperCase().toLowerCase());
  var table = unicode ? caseFoldClasses.UNICODE : caseFoldClasses.PLAIN;
  var extra = table[cp];
  if (extra !== undefined) {
    for (var i = 0; i < extra.length; i += 1) {
      if (extra[i] === cp || seen[extra[i]]) continue;
      seen[extra[i]] = true;
      out.push(extra[i]);
    }
  }
  return out;
}

module.exports = {
  canonicalizeForCase:     canonicalizeForCase,
  caseFoldPartners:        caseFoldPartners,
  isForbiddenControlChar:  isForbiddenControlChar,
  firstControlCharOffset:  firstControlCharOffset,
  decodeNumericEntities:   decodeNumericEntities,
  decodeMarkupEntities:    decodeMarkupEntities,
  NAMED_ENTITY_ASCII:      NAMED_ENTITY_ASCII,
  stripUrlSchemeWhitespace: stripUrlSchemeWhitespace,
  isAsciiAlnum:      isAsciiAlnum,
  isUnreserved:      isUnreserved,
  hex4:              hex4,
  charClass:         charClass,
  inRanges:          inRanges,
  firstInRanges:     firstInRanges,
  stripRanges:       stripRanges,
  replaceRanges:     replaceRanges,
  indexOfAny:        indexOfAny,
  replaceAny:        replaceAny,
  trimChars:         trimChars,
  trimRanges:        trimRanges,
  containsFolded:    containsFolded,
  matchesAtFolded:   matchesAtFolded,
  indexOfFolded:     indexOfFolded,
  isRunOf:           isRunOf,
  isRunOfRanges:     isRunOfRanges,
  isAsciiLetter:     isAsciiLetter,
  isAsciiDigit:      isAsciiDigit,
  isAsciiHexDigit:   isAsciiHexDigit,
  isIdentifierChar:  isIdentifierChar,
  splitLines:        splitLines,
  splitLinesAny:     splitLinesAny,
  splitOnWhitespace: splitOnWhitespace,
  ASCII_DIGITS:      ASCII_DIGITS,
  ASCII_ALPHA:       ASCII_ALPHA,
  ASCII_ALNUM:       ASCII_ALNUM,
  ASCII_HEX:         ASCII_HEX,
  WHITESPACE_RANGES: WHITESPACE_RANGES,
  LINE_TERMINATOR_RANGES: LINE_TERMINATOR_RANGES,
  fromCp:            fromCp,
  escapeRegExp:      escapeRegExp,
  HEX_PAIR_RE:       HEX_PAIR_RE,
  BIDI_RANGES:       BIDI_RANGES,
  C0_CTRL_RANGES:    C0_CTRL_RANGES,
  ZERO_WIDTH_RANGES: ZERO_WIDTH_RANGES,
  TAG_RANGES:        TAG_RANGES,
  NULL_RANGES:       NULL_RANGES,
  NULL_BYTE:         NULL_BYTE,
  BOM_CHAR:          BOM_CHAR,
  applyCharStripPolicies: applyCharStripPolicies,
  assertWithinMaxBytes:   assertWithinMaxBytes,
  resolveTagsPolicy:      resolveTagsPolicy,
  scrubCharThreats:       scrubCharThreats,
  assertNoCharThreats:    assertNoCharThreats,
  detectCharThreats:      detectCharThreats,
  SCRIPT_RANGES:          SCRIPT_RANGES,
  scriptFor:              scriptFor,
  detectMixedScripts:     detectMixedScripts,
};
