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

var HEX_RADIX = 16;

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
 * table of only BMP codepoints compiles as before and does not require the
 * flag.
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
 * @primitive b.codepointClass.trimTrailingChars
 * @signature b.codepointClass.trimTrailingChars(text, chars)
 * @since     0.18.60
 * @status    stable
 * @related   b.codepointClass.splitOnWhitespace, b.codepointClass.escapeRegExp
 *
 * Remove the run of characters at the END of `text` that are all in `chars`.
 * Returns `text` unchanged when it is not a string or nothing at the end
 * matches.
 *
 * The regex spelling of this, `text.replace(/\/+$/, "")`, has no start anchor,
 * so the engine retries the run from every position and a long run costs time
 * proportional to the SQUARE of its length: about 20ms for a single call on
 * 8192 characters, which is a CPU amplifier when the text arrives on a
 * request. This walks back from the end once.
 *
 * @example
 *   b.codepointClass.trimTrailingChars("https://x.example///", "/");
 *   // → "https://x.example"
 *
 * @example
 *   b.codepointClass.trimTrailingChars("host.example...", ".");
 *   // → "host.example"
 */
function trimTrailingChars(text, chars) {
  if (typeof text !== "string" || typeof chars !== "string" || chars.length === 0) return text;
  var end = text.length;
  if (chars.length === 1) {
    while (end > 0 && text.charAt(end - 1) === chars) end -= 1;
    return end === text.length ? text : text.slice(0, end);
  }
  var set = Object.create(null);
  for (var c = 0; c < chars.length;) {
    var cp = chars.codePointAt(c);
    set[cp] = true;
    c += cp > 0xFFFF ? 2 : 1;
  }
  for (;;) {
    if (end <= 0) break;
    var width = 1;
    var last = text.charCodeAt(end - 1);
    if (end >= 2 && last >= 0xDC00 && last <= 0xDFFF) {
      var prev = text.charCodeAt(end - 2);
      if (prev >= 0xD800 && prev <= 0xDBFF) width = 2;
    }
    if (set[text.codePointAt(end - width)] !== true) break;
    end -= width;
  }
  return end === text.length ? text : text.slice(0, end);
}

/**
 * @primitive b.codepointClass.firstDelimited
 * @signature b.codepointClass.firstDelimited(text, open, close, from?)
 * @since     0.18.60
 * @status    stable
 * @related   b.codepointClass.trimTrailingChars
 *
 * The first non-empty `open`...`close` group at or after `from`, as
 * `{ body, start, end }` where `start` is the index of `open` and `end` the
 * index of `close`. Returns `null` when there is none, and when either
 * delimiter is not a single character. An empty group is skipped and the
 * search continues, which is what `[^close]+` requiring one character does.
 *
 * Single characters only, as `lastDelimited` is. Skipping an empty group
 * advances by one and searches again, so a long delimiter would be re-matched
 * from almost the same place every time and the scan would be quadratic in
 * the delimiter's length.
 *
 * The regex spelling, `/<([^>]+)>/`, restarts at every `open` it finds, so a
 * value of nothing but `<` costs time proportional to its SQUARE: about 20ms
 * for a single call on 8192 characters. This walks the text once.
 *
 * @example
 *   b.codepointClass.firstDelimited("Name <a@b.example>", "<", ">").body;
 *   // → "a@b.example"
 */
function firstDelimited(text, open, close, from) {
  if (typeof text !== "string") return null;
  if (typeof open !== "string" || open.length !== 1) return null;
  if (typeof close !== "string" || close.length !== 1) return null;
  if (open === close) return null;
  var i = typeof from === "number" && from > 0 ? from : 0;
  for (;;) {
    var start = text.indexOf(open, i);
    if (start === -1) return null;
    var end = text.indexOf(close, start + 1);
    if (end === -1) return null;
    if (end > start + 1) return { body: text.slice(start + 1, end), start: start, end: end };
    i = start + 1;
  }
}

/**
 * @primitive b.codepointClass.lastDelimited
 * @signature b.codepointClass.lastDelimited(text, open, close)
 * @since     0.18.60
 * @status    stable
 * @related   b.codepointClass.firstDelimited
 *
 * The `open`...`close` group that ENDS the text, ignoring trailing whitespace,
 * as `{ body, start, end }`. Returns `null` when the last non-space character
 * is not `close`, when no `open` precedes it, or when the group is empty.
 *
 * The end-anchored regex, `/<([^>]+)>\s*$/`, still scans for its opening
 * character from every position and costs time proportional to the SQUARE of
 * the text. This walks back from the end once.
 *
 * @example
 *   b.codepointClass.lastDelimited("List <a@b.example>  ", "<", ">").body;
 *   // → "a@b.example"
 */
function lastDelimited(text, open, close) {
  if (typeof text !== "string") return null;
  if (typeof open !== "string" || open.length !== 1) return null;
  if (typeof close !== "string" || close.length !== 1) return null;
  if (open === close) return null;
  var end = text.length - 1;
  while (end >= 0 && inRanges(text.charCodeAt(end), WHITESPACE_RANGES)) end -= 1;
  if (end < 1 || text.charAt(end) !== close) return null;
  var start = -1;
  for (var i = end - 1; i >= 0; i -= 1) {
    var c = text.charAt(i);
    if (c === close) break;
    if (c === open) start = i;
  }
  if (start === -1 || start + 1 === end) return null;
  return { body: text.slice(start + 1, end), start: start, end: end };
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
  var start = from > 0 ? Math.floor(from) : 0;
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

/**
 * @primitive  b.codepointClass.isAuditPolicy
 * @signature  b.codepointClass.isAuditPolicy(policy)
 * @since      0.18.47
 * @status     stable
 * @related    b.gateContract.policyDisposition, b.gateContract.charPolicyEnums
 *
 * Whether a policy value asks for an AUDIT — reporting the finding rather than
 * refusing or repairing. `audit-only` is the framework's own synonym for
 * `audit`, and this is the one place that decides so.
 *
 * It exists because the two spellings disagreed. The disposition mapper treated
 * them as the same thing while the severity calculation recognized only the
 * literal `audit`, so `zeroWidthPolicy: "audit-only"` produced a high-severity
 * issue and a failed validation where `audit` produced a warning and a pass.
 * Two spellings of one setting is how they come to disagree; asking one
 * predicate is how they stop.
 *
 * @example
 *   b.codepointClass.isAuditPolicy("audit");       // → true
 *   b.codepointClass.isAuditPolicy("audit-only");  // → true
 *   b.codepointClass.isAuditPolicy("reject");      // → false
 */
function isAuditPolicy(policy) {
  return policy === "audit" || policy === "audit-only";
}

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
  var count = 0;
  for (var i = 0; i < text.length; ) {
    var cp = text.codePointAt(i);
    if (!inRanges(cp, ranges)) return false;
    count += 1;
    if (typeof max === "number" && count > max) return false;
    i += cp > 0xFFFF ? 2 : 1;
  }
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
var CTRL_RANGES       = C0_CTRL_RANGES.concat([0x007F]);
var ZERO_WIDTH_RANGES = [0x00AD, [0x200B, 0x200D], [0x2060, 0x2064], 0xFEFF];
var TAG_RANGES        = [[0xE0000, 0xE007F]];

var NULL_RANGES   = [0x0000];

var LINE_TERMINATOR_RANGES = [0x000A, 0x000D, 0x2028, 0x2029];

var WHITESPACE_RANGES = [
  [0x0009, 0x000D], 0x0020, 0x00A0, 0x1680, [0x2000, 0x200A],
  0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
];

var NULL_BYTE = fromCp(0x0000);
var BOM_CHAR  = fromCp(0xFEFF);

var SCRIPT_RANGES = {
  latin:    [[0x0041, 0x005A], [0x0061, 0x007A],
             [0x00C0, 0x024F], [0x1E00, 0x1EFF]],
  cyrillic: [[0x0400, 0x04FF], [0x0500, 0x052F]],
  greek:    [[0x0370, 0x03FF], [0x1F00, 0x1FFF]],
  armenian: [[0x0530, 0x058F]],
  cherokee: [[0x13A0, 0x13FF], [0xAB70, 0xABBF]],
  han:      [[0x4E00, 0x9FFF]],
  hiragana: [[0x3040, 0x309F]],
  katakana: [[0x30A0, 0x30FF]],
  hangul:   [[0xAC00, 0xD7AF]],
  arabic:   [[0x0600, 0x06FF]],
  hebrew:   [[0x0590, 0x05FF]],
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
 * @signature b.codepointClass.detectCharThreats(text, opts, codePrefix)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.assertNoCharThreats, b.codepointClass.applyCharStripPolicies, b.guardText
 *
 * Scan `text` for the character-class threats — bidi override, null byte,
 * control character, zero-width and Unicode Tags — and return an array of issue
 * objects `{ kind, severity, ruleId, location, snippet }`, at most one per
 * class. Each class is gated by an opts policy that isn't `"allow"`; `ruleId`
 * is prefixed with `codePrefix`. The non-throwing detection pass the `b.guard*`
 * family shares instead of re-rolling the per-class match-and-push. Unicode
 * Tags follows `tagsPolicy`, or `zeroWidthPolicy` when the guard names no
 * policy of its own.
 *
 * Every class scans on the same terms, and a caller cannot ask for a class to
 * be skipped or stamp a severity of its own. `severity` is NOT a uniform
 * function of the policy, so do not read an outcome out of it — pass the
 * finding to `b.gateContract.charThreatDisposition`, which resolves every one
 * of the five from its own policy. What each reports:
 *
 *   - `zero-width` and `unicode-tags` follow the policy: `reject` is
 *     `critical`, `audit` is `warn`, a repair policy such as `strip` is
 *     `high`.
 *   - `control-char` follows it too, except that its refusing severity is
 *     `high` rather than `critical`. A validator narrowed to `["critical"]`
 *     does not throw on one; the gate still refuses it.
 *   - `bidi-override` and `null-byte` are `critical` whatever the policy
 *     says. `bidiPolicy: "audit"` reports at refusing severity, so a caller
 *     filtering on severity refuses what the operator asked only to record.
 *     `charThreatDisposition` reads the policy and does not.
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
 *   controlPolicy:   string,   // non-"allow" -> flag control chars (C0 + DEL)
 *   zeroWidthPolicy: string,   // non-"allow" -> flag zero-width
 *
 * @example
 *   var issues = b.codepointClass.detectCharThreats(
 *     userText, { bidiPolicy: "reject", nullBytePolicy: "reject" }, "comment");
 *   if (issues.length) refuse(issues[0].ruleId);
 */
function detectCharThreats(text, opts, codePrefix) {
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
    var ctrlMatch = _firstHit(text, CTRL_RANGES);
    if (ctrlMatch) {
      issues.push({
        kind: "control-char",
        severity: opts.controlPolicy === "reject" ? "high"
                : isAuditPolicy(opts.controlPolicy) ? "warn" : "high",
        ruleId: codePrefix + ".control",
        location: ctrlMatch.index,
        snippet: "control char U+" + ctrlMatch.codePoint.toString(HEX_RADIX),
      });
    }
  }
  if (opts && opts.zeroWidthPolicy && opts.zeroWidthPolicy !== "allow") {
    var zwMatch = _firstHit(text, ZERO_WIDTH_RANGES);
    if (zwMatch) {
      issues.push({
        kind: "zero-width",
        severity: opts.zeroWidthPolicy === "reject" ? "critical"
                : isAuditPolicy(opts.zeroWidthPolicy) ? "warn" : "high",
        ruleId: codePrefix + ".zero-width",
        location: zwMatch.index,
        snippet: "zero-width / invisible-formatting char U+" +
                 zwMatch.codePoint.toString(HEX_RADIX) + " at offset " + zwMatch.index,
      });
    }
  }
  var tagsPolicy = _tagsPolicy(opts);
  if (tagsPolicy && tagsPolicy !== "allow") {
    var tagMatch = _firstHit(text, TAG_RANGES);
    if (tagMatch) {
      issues.push({
        kind: "unicode-tags",
        severity: tagsPolicy === "reject" ? "critical"
                : isAuditPolicy(tagsPolicy) ? "warn" : "high",
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
  if (opts && opts.controlPolicy === "reject" && firstInRanges(text, CTRL_RANGES) !== -1) {
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
  if (opts && opts.controlPolicy === "strip")   out = stripRanges(out, CTRL_RANGES);
  if (opts && opts.nullBytePolicy === "strip")  out = stripRanges(out, NULL_RANGES);
  if (opts && opts.zeroWidthPolicy === "strip") out = stripRanges(out, ZERO_WIDTH_RANGES);
  if (_tagsPolicy(opts) === "strip")            out = stripRanges(out, TAG_RANGES);
  return out;
}

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
 * percent-escape, numeric character reference, color literal and binary-
 * encoded identifier is spelled in.
 *
 * @example
 *   b.codepointClass.isAsciiHexDigit("F".charCodeAt(0));             // → true
 */
function isAsciiHexDigit(cc) {
  return isAsciiDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}

/**
 * @primitive b.codepointClass.isAsciiWhitespace
 * @signature b.codepointClass.isAsciiWhitespace(cc)
 * @since     0.20.1
 * @status    stable
 * @related   b.codepointClass.isAsciiLetter, b.markupTokenizer.isMarkupSpace
 *
 * Is this code unit one of the five ASCII whitespace characters: tab, line
 * feed, form feed, carriage return or space? This is the set the HTML
 * tokenizer and the CSS tokenizer separate tokens on. A no-break space or any
 * other Unicode space is not in it.
 *
 * @example
 *   b.codepointClass.isAsciiWhitespace(0x0C);                        // → true
 *   b.codepointClass.isAsciiWhitespace(0xA0);                        // → false
 */
function isAsciiWhitespace(cc) {
  return cc === 0x20 || cc === 0x09 || cc === 0x0A || cc === 0x0C || cc === 0x0D;
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
  return isAsciiAlnum(cc) || cc === 0x5F;
}

/**
 * @primitive b.codepointClass.hasPairWhere
 * @signature b.codepointClass.hasPairWhere(text, first, second, accept)
 * @since     0.18.54
 * @status    stable
 * @related   b.codepointClass.splitLines
 *
 * Is there a place where `first` is immediately followed by `second`, and
 * `accept` says that place counts? `accept(i)` is called with the index of
 * `first`, and returns whether the construct opening there is a real one.
 *
 * This is the frame every two-character construct screen was writing out by
 * hand: a path traversal opening on `..`, a regex inline-flag group on `(?`, a
 * YAML merge key on `<<`. The literals and the follow-on tests differ, the scan
 * does not, and three copies of a scan are three places for an off-by-one to
 * live. It reads the string one character at a time, which is the property a
 * guard needs: asking the question with a pattern would be a screen running the
 * construct it screens over hostile text.
 *
 * `accept` decides alone — the scan does not skip past a hit it rejected, so
 * overlapping openers are all offered. A screen that needs to COUNT
 * non-overlapping occurrences is asking a different question and keeps its own
 * cursor.
 *
 * @example
 *   var CP = b.codepointClass;
 *   CP.hasPairWhere("a/../b", ".", ".", function () { return true; });  // → true
 *   CP.hasPairWhere("a.b", ".", ".", function () { return true; });     // → false
 */
function hasPairWhere(text, first, second, accept) {
  if (typeof text !== "string") return false;
  for (var i = 0; i + 1 < text.length; i += 1) {
    if (text.charAt(i) !== first || text.charAt(i + 1) !== second) continue;
    if (accept(i)) return true;
  }
  return false;
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
         cc === 0x2d ||
         cc === 0x2e ||
         cc === 0x5f ||
         cc === 0x7e;
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
  if (code === 0x7f) return true;
  if (code >= 0x20) return false;
  if (code === 0x09 && (!opts || !opts.forbidTab)) return false;
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

/**
 * @primitive b.codepointClass.firstLineInjectionCharOffset
 * @signature b.codepointClass.firstLineInjectionCharOffset(s)
 * @since     0.18.54
 * @status    stable
 * @related   b.codepointClass.firstControlCharOffset
 *
 * Return the index of the first CR, LF or NUL in `s`, or `-1` when there is
 * none. These three are the bytes that end a line-oriented protocol record,
 * so a value carrying one splits the record it is written into and the
 * remainder is read as a second, attacker-chosen line: the header-injection
 * class in HTTP and Set-Cookie, and the command-injection class in SMTP,
 * POP3, IMAP and ManageSieve.
 *
 * Narrower than `firstControlCharOffset`, deliberately. That one refuses every
 * C0 control and DEL, which is right for text a human wrote; this one answers
 * the specific question a wire-protocol writer asks, so a caller adopting it
 * does not silently start refusing values it used to accept.
 *
 * @example
 *   b.codepointClass.firstLineInjectionCharOffset("nonce-42");        // -1
 *   b.codepointClass.firstLineInjectionCharOffset("abc\r\nOK");       // 3
 */
function firstLineInjectionCharOffset(s) {
  if (typeof s !== "string") return -1;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charCodeAt(i);
    if (c === 0x0d || c === 0x0a || c === 0x00) return i;
  }
  return -1;
}

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

function _decodeNumericEntityAt(s, at) {
  if (s.charCodeAt(at + 1) !== 0x23) return null;
  var c   = s.charCodeAt(at + 2);
  var hex = c === 0x78 || c === 0x58;
  var i   = at + (hex ? 3 : 2);
  var start = i;
  while (i < s.length &&
         (hex ? _isAsciiHexDigit(s.charCodeAt(i)) : _isAsciiDigit(s.charCodeAt(i)))) i++;
  if (i === start) return null;
  var digits = s.slice(start, i);
  if (s.charCodeAt(i) === 0x3B) i++;
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

function _decodeEntityRun(text, decodeAt) {
  var out     = "";
  var copyFrom = 0;
  var i       = 0;
  while (i < text.length) {
    if (text.charCodeAt(i) !== 0x26) { i++; continue; }
    var hit = decodeAt(text, i);
    if (hit === null) { i++; continue; }
    out += text.slice(copyFrom, i) + hit.text;
    i = copyFrom = hit.next;
  }
  return copyFrom === 0 ? text : out + text.slice(copyFrom);
}

var NAMED_ENTITY_ASCII = {
  Tab: "\t", NewLine: "\n",
  colon: ":", semi: ";", period: ".", sol: "/", bsol: "\\",
  num: "#", excl: "!", quest: "?", lpar: "(", rpar: ")",
  lsqb: "[", rsqb: "]", lcub: "{", rcub: "}",
  quot: "\"", apos: "'", lt: "<", gt: ">",
  amp: "&", commat: "@", dollar: "$", percnt: "%",
  ast: "*", plus: "+", lowbar: "_",
};

NAMED_ENTITY_ASCII.hyphen = String.fromCharCode(0x2010);
NAMED_ENTITY_ASCII.nbsp = String.fromCharCode(0x00A0);

function _decodeNamedEntityAt(s, at) {
  var start = at + 1;
  if (!_isAsciiAlpha(s.charCodeAt(start))) return null;
  var i = start + 1;
  while (i < s.length &&
         (_isAsciiAlpha(s.charCodeAt(i)) || _isAsciiDigit(s.charCodeAt(i)))) i++;
  if (i === start + 1) return null;
  if (s.charCodeAt(i) !== 0x3B) return null;
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
 * Decode the character references a browser resolves inside an attribute
 * value: numeric (hex/decimal, semicolon OPTIONAL) first, then the
 * named-entity ASCII subset browsers honor in URL/CSS contexts. Drop the C0
 * controls and zero-widths a payload hides behind. The single decoder every content guard
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
  return stripRanges(stripRanges(s, CTRL_RANGES), ZERO_WIDTH_RANGES);
}

var URL_TAB_NEWLINE_RANGES = [0x0009, 0x000A, 0x000D];
var URL_C0_SPACE_RANGES    = [[0x0000, 0x0020]];

/**
 * @primitive b.codepointClass.decodeEntityAt
 * @signature b.codepointClass.decodeEntityAt(s, at)
 * @since     0.20.0
 * @status    stable
 * @related   b.codepointClass.decodeReferenceAt, b.codepointClass.decodeMarkupEntities, b.codepointClass.decodeNumericEntities
 *
 * Decode the one entity reference that begins at index `at` of `s`, which
 * must be an ampersand: a numeric reference, or failing that a named one.
 * Returns `{ text, next }`: the decoded text and the index just after the
 * reference. Returns `null` when no numeric or named reference begins there.
 *
 * This reads one reference in isolation. `decodeMarkupEntities` decodes
 * numeric references in one pass and named references in a second pass over
 * the result, so a numeric reference that yields an ampersand can complete a
 * named reference with the text after it, and this does not model that:
 * walking `"&#38;colon;"` with it gives `"&colon;"` where the whole-string
 * decoder gives `":"`. Use `decodeReferenceAt` for a walk that agrees with
 * `decodeMarkupEntities`.
 *
 * @example
 *   b.codepointClass.decodeEntityAt("&#x6A;s", 0);   // → { text: "j", next: 6 }
 *   b.codepointClass.decodeEntityAt("&Tab;", 0);     // → { text: "\t", next: 5 }
 *   b.codepointClass.decodeEntityAt("&x", 0);        // → null
 */
function decodeEntityAt(s, at) {
  var text = String(s == null ? "" : s);
  if (text.charCodeAt(at) !== 0x26) return null;
  return _decodeNumericEntityAt(text, at) || _decodeNamedEntityAt(text, at);
}

/**
 * @primitive b.codepointClass.isUrlSchemeStrippable
 * @signature b.codepointClass.isUrlSchemeStrippable(cp)
 * @since     0.20.0
 * @status    stable
 * @related   b.codepointClass.stripUrlSchemeWhitespace, b.codepointClass.decodeMarkupEntities
 *
 * Report whether a code point is one the URL-scheme normalization removes:
 * a C0 control or space, tab, line feed, carriage return, or a zero-width
 * character. `decodeMarkupEntities` and `stripUrlSchemeWhitespace` together
 * drop these before a scheme is read, so a reader locating a scheme by
 * position skips exactly this set.
 *
 * @example
 *   b.codepointClass.isUrlSchemeStrippable(0x01);   // → true
 *   b.codepointClass.isUrlSchemeStrippable(0x200B); // → true
 *   b.codepointClass.isUrlSchemeStrippable(0x6A);   // → false
 */
function isUrlSchemeStrippable(cp) {
  return inRanges(cp, URL_C0_SPACE_RANGES) || inRanges(cp, CTRL_RANGES) ||
         inRanges(cp, ZERO_WIDTH_RANGES);
}

/**
 * @primitive b.codepointClass.decodeNamedEntityAt
 * @signature b.codepointClass.decodeNamedEntityAt(s, at)
 * @since     0.20.0
 * @status    stable
 * @related   b.codepointClass.decodeReferenceAt, b.codepointClass.decodeEntityAt, b.codepointClass.decodeMarkupEntities
 *
 * Decode the one named entity reference that begins at index `at` of `s`,
 * which must be a literal ampersand, and nothing else: a numeric reference
 * at `at` returns `null`, whatever it decodes to. Returns `{ text, next }` or
 * `null`. `decodeMarkupEntities` decodes numeric references in one pass and
 * named references in a second pass over the result, so the second pass sees
 * a name whose letters, or whose closing semicolon, were written as numeric
 * references: `&co&#108;on;` is `&colon;` to it. This reads the name the same
 * way, so a caller walking by position recognizes exactly the references the
 * whole-string decoder does. A numeric reference that produces an ampersand
 * can likewise complete a named reference with the text after it;
 * `decodeReferenceAt` reads that composition.
 *
 * @example
 *   b.codepointClass.decodeNamedEntityAt("&colon;x", 0);  // → { text: ":", next: 7 }
 *   b.codepointClass.decodeNamedEntityAt("&#38;", 0);     // → null
 */
var MAX_NAMED_ENTITY_NAME_LEN = 7;

function _asciiAlnumFromNumericAt(s, at) {
  var hit = _decodeNumericEntityAt(s, at);
  if (hit === null || hit.text.length !== 1) return null;
  var c = hit.text.charCodeAt(0);
  if (!_isAsciiAlpha(c) && !_isAsciiDigit(c)) return null;
  return { ch: hit.text, next: hit.next };
}

function decodeNamedEntityAt(s, at) {
  var text = String(s == null ? "" : s);
  if (text.charCodeAt(at) !== 0x26) return null;
  if (_decodeNumericEntityAt(text, at) !== null) return null;
  return _decodeNamedEntityFrom(text, at, at + 1);
}

/**
 * @primitive b.codepointClass.decodeReferenceAt
 * @signature b.codepointClass.decodeReferenceAt(s, at)
 * @since     0.20.0
 * @status    stable
 * @related   b.codepointClass.decodeNamedEntityAt, b.codepointClass.decodeEntityAt, b.codepointClass.decodeMarkupEntities
 *
 * Decode the character reference that begins at index `at` of `s`, which
 * must be an ampersand, the way `decodeMarkupEntities` reads it: a named
 * reference, or a numeric reference, and when the numeric reference produces
 * an ampersand, the named reference that ampersand completes with the text
 * after it. Returns `{ text, next }` or `null`. `decodeNamedEntityAt` reads
 * only a literal ampersand; this is the one call that walks by position and
 * still sees `&#38;colon;` as `&colon;`.
 *
 * @example
 *   b.codepointClass.decodeReferenceAt("&#38;colon;x", 0);  // → { text: ":", next: 11 }
 *   b.codepointClass.decodeReferenceAt("&#38;x", 0);        // → { text: "&", next: 5 }
 *   b.codepointClass.decodeReferenceAt("&colon;", 0);       // → { text: ":", next: 7 }
 */
function decodeReferenceAt(s, at) {
  var text = String(s == null ? "" : s);
  if (text.charCodeAt(at) !== 0x26) return null;
  var lead = _decodeNumericEntityAt(text, at);
  if (lead === null) return _decodeNamedEntityFrom(text, at, at + 1);
  if (lead.text !== "&") return lead;
  return _decodeNamedEntityFrom(text, at, lead.next) || lead;
}

function _decodeNamedEntityFrom(text, at, i) {
  var name = "";
  while (name.length < MAX_NAMED_ENTITY_NAME_LEN + 1 && i < text.length) {
    var c = text.charCodeAt(i);
    if (_isAsciiAlpha(c) || _isAsciiDigit(c)) { name += text.charAt(i); i += 1; continue; }
    if (c === 0x26) {
      var piece = _asciiAlnumFromNumericAt(text, i);
      if (piece === null) break;
      name += piece.ch;
      i = piece.next;
      continue;
    }
    break;
  }
  if (name.length < 2 || name.length > MAX_NAMED_ENTITY_NAME_LEN) return null;
  if (!_isAsciiAlpha(name.charCodeAt(0))) return null;
  var end;
  if (text.charCodeAt(i) === 0x3B) {
    end = i + 1;
  } else if (text.charCodeAt(i) === 0x26) {
    var term = _decodeNumericEntityAt(text, i);
    if (term === null || term.text !== ";") return null;
    end = term.next;
  } else {
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(NAMED_ENTITY_ASCII, name)) {
    return { text: "&" + name + ";", next: end };
  }
  return { text: NAMED_ENTITY_ASCII[name], next: end };
}
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
  var corrections = (unicode ? caseFoldClasses.UNICODE_CANONICAL
                             : caseFoldClasses.PLAIN_CANONICAL) || {};
  var corrected = corrections[cp];
  if (corrected !== undefined) return corrected;
  if (unicode) {
    if (_oneCodePoint(upper)) {
      var folded = upper.toLowerCase();
      if (_oneCodePoint(folded)) return folded.codePointAt(0);
    }
    var lowered = ch.toLowerCase();
    return _oneCodePoint(lowered) ? lowered.codePointAt(0) : cp;
  }
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
  firstLineInjectionCharOffset: firstLineInjectionCharOffset,
  decodeNumericEntities:   decodeNumericEntities,
  decodeMarkupEntities:    decodeMarkupEntities,
  NAMED_ENTITY_ASCII:      NAMED_ENTITY_ASCII,
  stripUrlSchemeWhitespace: stripUrlSchemeWhitespace,
  decodeEntityAt:          decodeEntityAt,
  isUrlSchemeStrippable:   isUrlSchemeStrippable,
  decodeNamedEntityAt:     decodeNamedEntityAt,
  decodeReferenceAt:       decodeReferenceAt,
  isAsciiAlnum:      isAsciiAlnum,
  isUnreserved:      isUnreserved,
  hex4:              hex4,
  charClass:         charClass,
  inRanges:          inRanges,
  isAuditPolicy:     isAuditPolicy,
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
  isAsciiWhitespace: isAsciiWhitespace,
  isIdentifierChar:  isIdentifierChar,
  hasPairWhere:      hasPairWhere,
  splitLines:        splitLines,
  splitLinesAny:     splitLinesAny,
  splitOnWhitespace: splitOnWhitespace,
  trimTrailingChars: trimTrailingChars,
  firstDelimited:    firstDelimited,
  lastDelimited:     lastDelimited,
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
  CTRL_RANGES:       CTRL_RANGES,
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
