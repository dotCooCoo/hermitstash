// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardRegex
 * @nav    Guards
 * @title  Guard Regex
 *
 * @intro
 *   Regex-pattern content-safety guard — refuses user-supplied
 *   pattern strings that exhibit catastrophic-backtracking (ReDoS)
 *   shapes BEFORE the framework compiles them with `new RegExp(...)`.
 *   Operator-untrusted patterns flow into search filters, allow-lists,
 *   route matchers, and form validators; this primitive screens them
 *   so a hostile input can't pin a CPU at 100% inside the regex
 *   engine. KIND=`identifier`; the gate consumes `ctx.identifier`
 *   (or `ctx.pattern`) and refuses on hostile shapes. Composes with
 *   framework parsers (`b.safeJson` / `b.safeBuffer` / route helpers)
 *   so any operator-fed pattern hits the guard first.
 *
 *   Threat catalog: nested quantifiers (`(a+)+`, `(a*)+`, `(.+)+` —
 *   the canonical ReDoS class, e.g. CVE-2024-21538 cross-spawn and
 *   CVE-2022-25929 chartjs-adapter-luxon); alternation-with-
 *   quantifier (`(a|a)*`, `(\d|\d{2})*`) where two branches can match
 *   at the same position and the overlap amplifies search paths — an
 *   alternation whose branches cannot start on the same character is
 *   the character class it is written out long-hand as, and passes;
 *   quantifier-inside-lookaround
 *   (`(?=.*+)`, `(?!a*)`) — catastrophic in some engines; bounded
 *   repetition with a large upper bound (gated by
 *   `maxBoundedRepeat`); per-pattern byte cap to defend against
 *   parser-stage DoS; BIDI override / zero-width / C0 control /
 *   null-byte universal refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators
 *   select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline. Nested-quantifier rejection holds at every
 *   profile — the catastrophic class is never an operator opt-in.
 *
 *   Pattern strings can't be repaired safely — `sanitize` either
 *   passes through clean input or throws `GuardRegexError`; the
 *   gate returns `serve` / `audit-only` / `refuse` (no `sanitize`
 *   action). Detector regexes themselves are length-bounded by
 *   `maxPatternBytes` so the screener can't be DoS'd by its own
 *   inputs, and the unambiguity analysis spends a fixed work budget
 *   — a pattern too expensive to reason about exhausts it and stays
 *   refused, so cost cannot buy leniency.
 *
 * @card
 *   Regex-pattern content-safety guard — refuses user-supplied pattern strings that exhibit catastrophic-backtracking (ReDoS) shapes BEFORE the framework compiles them with `new RegExp(...)`.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var boundedMap = require("./bounded-map");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { GuardRegexError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardRegexError.factory;

// Nested-quantifier detector: `(group)+`-style followed by another
// quantifier or repetition that operates on the grouped match.
// (The flat single-group nested-quantifier case is handled by the paren-aware
// structural scanner _hasNestedQuantifier, which — unlike a flat regex — requires
// the OUTER quantifier to be UNBOUNDED (`*`/`+`/`{n,}`, not `?`/`{0,1}`/`{n,m}`)
// and does not miscount a `(?:` group prefix as an inner quantifier, so it does
// not false-positive on linear shapes like `(?:X+)?` / `(X+)?` / `(?:bar)*`.)

// Alternation-with-quantifier — `(a|b|...)+`, `(a|b)*`. A shape check only:
// it says nothing about whether the branches can actually overlap, so a hit
// is passed to _alternationBranchesProvablyDisjoint before it becomes a
// finding. It walks groups the same way that analysis does, because a flat
// regex here disagreed with it twice over: `[^()]*` cannot span a nested
// group, so one paren around a branch — `((a)|a)+` — hid an exponential
// pattern the same shape refused as `(a|a)+`; and matching only `*`/`+` after
// the group missed `{n,}`, which is the identical unbounded repetition spelled
// differently. Both were accepted at every profile.

// Nested extglob detector — picomatch `*(...)` / `+(...)` / `?(...)` /
// `@(...)` / `!(...)` containing another extglob inside (CVE-2026-33671
// nested-extglob catastrophic-backtracking class). Two extglob heads in
// the same pattern with no closing paren between them indicates nesting.
//
// The characters that open one. Everything in this module reads its input a
// character at a time: a screen for catastrophic patterns must not be built out
// of patterns, or it carries the failure it exists to refuse — this module had
// its own runaway scan (2,177 ms on 1 KiB) while it was.
var EXTGLOB_HEADS = "*+?@!";

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "reject",
    boundedRepeatPolicy:       "reject",
    lookaroundQuantPolicy:     "reject",
    unanchoredScanPolicy:      "reject",
    consecutiveStarPolicy:    "reject",
    nestedExtglobPolicy:      "reject",
    inputKind:                "regex",                                            // CVE-2026-26996 + CVE-2026-33671 detectors apply only when inputKind=="glob"
    maxBoundedRepeat:          100,                                              // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(1),
    maxBytes:                  C.BYTES.kib(1),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "audit",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    unanchoredScanPolicy:      "audit",
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          1000,                                             // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(2),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",                                          // canonical ReDoS class refused at every profile
    alternationQuantPolicy:    "allow",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    unanchoredScanPolicy:      "allow",
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          10000,                                            // bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // `**` recursive glob permitted; >=3 refused
    maxPatternBytes:           C.BYTES.kib(8),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var MAX_CLASS_RANGE = 256;

// The unambiguity analysis spends a fixed work budget. A pattern too expensive
// to reason about exhausts it and stays refused, so cost cannot buy leniency.
// The budget is charged where the work happens — building a character set
// charges its width, and a set is folded once when it is built rather than
// again at each reader — so the units bought are proportional to the work
// done. Everyday patterns spend a few hundred.
var ANALYSIS_BUDGET = 20000;

function _ignoresCase(flags) {
  return typeof flags === "string" && flags.indexOf("i") !== -1;
}

// The `v` flag changes what a character class means, so a class this parser
// read under the old rules cannot be trusted to say what the engine sees.
// Nothing is proven safe under it.
function _declinesOnFlags(flags) {
  return typeof flags === "string" && flags.indexOf("v") !== -1;
}

// Does the class starting at `from` use the set syntax the `v` flag brings —
// a nested class, a difference, an intersection, or a string literal? Read one
// character at a time from the opening bracket, honouring escapes, and stopping
// at the `]` that closes the OUTERMOST class. Only asked under `v`, where these
// spellings mean something; without it a nested `[` is an ordinary member.
function _classUsesSetSyntax(text, from) {
  var depth = 0;
  for (var i = from; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (c === "\\") {
      if (text.charAt(i + 1) === "q" && text.charAt(i + 2) === "{") return true;
      i += 1;                                                                    // skip the escaped one
      continue;
    }
    if (c === "[") {
      depth += 1;
      if (depth > 1) return true;                                                // a class inside a class
      continue;
    }
    if (c === "]") {
      depth -= 1;
      if (depth <= 0) return false;                                              // the outermost closed
      continue;
    }
    if (depth >= 1 && (c === "-" || c === "&") && text.charAt(i + 1) === c) return true;
  }
  return false;                                                                  // unterminated — not our call
}

// ---- pattern parsing ------------------------------------------------------
//
// Every analysis below reads a parse tree. None of them reads the pattern
// source. Reading source with regexes is what this module used to do, and each
// reader drew the token boundaries a little differently: one could not see
// past a nested group, one decided whether a `?` was a quantifier by looking at
// the previous CHARACTER (so the `?` in `\*?` read as a lazy marker and the
// length variation it contributes was lost), one capped the digits inside
// `{n,m}` (so a longer bound read as no quantifier at all). Each disagreement
// was a way to write a catastrophic pattern that one reader found and another
// waved through, and patching them one at a time only moved the edge.
//
// So: one tokenizer, one tree, and anything it cannot represent becomes an
// OPAQUE node — which every analysis treats as "cannot prove", never as
// "nothing here". Failing closed is a property of the representation rather
// than something each reader has to remember.

// ---- character sets ----
//
// `any` is the set this analysis cannot characterise. It contains everything
// and intersects everything, so it can never be proven disjoint and can never
// prove a delimiter unreachable — the conservative answer in both directions.

function _anySet() { return { any: true, negated: false, chars: null }; }

function _mkSet(chars, negated) {
  var set = chars instanceof Set ? chars : new Set(chars);
  return { any: false, negated: !!negated, chars: set };
}

function _setSize(s) { return s.any ? 0 : s.chars.size; }

// Fold a set so it covers both cases, the way the engine does under `i`.
// Widening a positive set makes an intersection MORE likely; widening a
// complement's exclusions makes the complement narrower. Both push toward
// declining to prove, which is the safe direction. Sets are folded once, when
// they are built, so no two readers can disagree about whether folding
// happened — the bug that let `[^ab]` unioned with `A` exclude the very `a`
// the `A` was contributing.
function _foldSet(s) {
  if (s.any) return s;
  var out = new Set();
  s.chars.forEach(function (c) {
    out.add(c);
    _addIfOneCharacter(out, c.toLowerCase());
    _addIfOneCharacter(out, c.toUpperCase());
  });
  return _mkSet(out, s.negated);
}

// A case partner counts when it is ONE character. That is a single UTF-16
// unit, or two that form a surrogate pair — an astral letter's partner is
// astral too, and a length check that only accepted one unit dropped it. It is
// not a multi-unit expansion such as the uppercase of the sharp s, which is
// two characters and which the engine does not fold to either.
function _addIfOneCharacter(out, candidate) {
  if (candidate.length === 1) { out.add(candidate); return; }
  if (candidate.length === 2 && candidate.codePointAt(0) > 0xffff) out.add(candidate);
}

function _setHas(s, ch) {
  if (s.any) return true;
  return s.negated ? !s.chars.has(ch) : s.chars.has(ch);
}

// Two complements always share members (the alphabet is far larger than any
// pair of exclusion lists), and `any` shares with everything.
function _setsIntersect(a, b) {
  if (a.any || b.any) return true;
  if (a.negated && b.negated) return true;
  if (!a.negated && !b.negated) {
    var small = a.chars.size <= b.chars.size ? a : b;
    var large = small === a ? b : a;
    var hit = false;
    small.chars.forEach(function (c) { if (large.chars.has(c)) hit = true; });
    return hit;
  }
  var pos = a.negated ? b : a;
  var neg = a.negated ? a : b;
  var out = false;
  pos.chars.forEach(function (c) { if (!neg.chars.has(c)) out = true; });
  return out;
}

// Union, with complements read the way a complement means. A complement
// covers everything except what it excludes, so a union containing one is
// itself a complement: it excludes what EVERY complement excludes and NO
// positive set supplies.
function _unionSets(sets) {
  var i;
  var negs = [], poss = [];
  for (i = 0; i < sets.length; i += 1) {
    if (sets[i].any) return _anySet();
    (sets[i].negated ? negs : poss).push(sets[i]);
  }
  if (negs.length === 0) {
    var all = new Set();
    for (i = 0; i < poss.length; i += 1) {
      poss[i].chars.forEach(function (c) { all.add(c); });
    }
    return _mkSet(all, false);
  }
  var excluded = new Set();
  negs[0].chars.forEach(function (ch) {
    for (var n = 1; n < negs.length; n += 1) if (!negs[n].chars.has(ch)) return;
    for (var q = 0; q < poss.length; q += 1) if (poss[q].chars.has(ch)) return;
    excluded.add(ch);
  });
  return _mkSet(excluded, true);
}

var WORD_CHARS = (function () {
  var out = [];
  var i;
  for (i = 48; i <= 57; i += 1) out.push(String.fromCharCode(i));
  for (i = 65; i <= 90; i += 1) out.push(String.fromCharCode(i));
  for (i = 97; i <= 122; i += 1) out.push(String.fromCharCode(i));
  out.push("_");
  return out;
})();
var DIGIT_CHARS = "0123456789".split("");
// Source stays pure ASCII: every character these tables name is written as an
// escape, so a copy of this file cannot silently carry the character itself.
var SPACE_CHARS = [
  "\u0020", "\u0009", "\u000a", "\u000b", "\u000c", "\u000d",
  "\u00a0", "\u1680", "\u2000", "\u2001", "\u2002", "\u2003",
  "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009",
  "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000",
  "\ufeff",
];
var LINE_TERMINATORS = ["\u000a", "\u000d", "\u2028", "\u2029"];
var CONTROL_ESCAPES = {
  n: "\u000a", r: "\u000d", t: "\u0009",
  f: "\u000c", v: "\u000b", 0: "\u0000",
};

// The set an escape denotes, or null when it is not one this reads (a
// backreference, a property escape, an assertion).
function _escapeSet(ch) {
  if (ch === "w") return _mkSet(WORD_CHARS, false);
  if (ch === "W") return _mkSet(WORD_CHARS, true);
  if (ch === "d") return _mkSet(DIGIT_CHARS, false);
  if (ch === "D") return _mkSet(DIGIT_CHARS, true);
  if (ch === "s") return _mkSet(SPACE_CHARS, false);
  if (ch === "S") return _mkSet(SPACE_CHARS, true);
  if (Object.prototype.hasOwnProperty.call(CONTROL_ESCAPES, ch)) {
    return _mkSet([CONTROL_ESCAPES[ch]], false);
  }
  // backref / property / assertion / code escape — none of them a plain literal
  if ("0123456789kpPbBuxc".indexOf(ch) !== -1) return null;
  return _mkSet([ch], false);                          // an escaped literal
}

// ---- the parser ----
//
// Node shapes, all carrying the flags in force where they appear:
//   { type: "alt",    branches: [seq] }
//   { type: "seq",    terms: [term] }
//   term:  { node, min, max }            max may be Infinity
//   { type: "set",    set }              literal / class / escape / dot
//   { type: "group",  body: alt }        capturing, non-capturing, named, modifier
//   { type: "look" }                     lookaround — a different detector owns it
//   { type: "anchor" }                   zero-width, matches no characters
//   { type: "opaque" }                   anything not represented — never proven

// A ReDoS backstop on this parser's own recursion, set far above any
// pattern an operator writes. Nesting past it leaves the pattern unparsed,
// which is reported rather than waved through.
var MAX_PARSE_DEPTH = 200;

var FLAG_LETTERS = "dgimsuvy";

function _isFlagLetter(ch) { return FLAG_LETTERS.indexOf(ch) !== -1; }

function _isDigitChar(ch) { return ch >= "0" && ch <= "9"; }

function _isNameStart(ch) {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || ch === "_" || ch === "$";
}

// `(?=` `(?!` `(?<=` `(?<!` at `at` (which stands on the `?`), or null.
function _scanLookHead(src, at) {
  if (src.charAt(at) !== "?") return null;
  var next = src.charAt(at + 1);
  if (next === "=" || next === "!") {
    return { negated: next === "!", behind: false, end: at + 2 };
  }
  if (next !== "<") return null;
  var third = src.charAt(at + 2);
  if (third !== "=" && third !== "!") return null;         // `(?<name>` — not a lookaround
  return { negated: third === "!", behind: true, end: at + 3 };
}

// `(?<name>` at `at`, giving the offset past the `>`, or -1.
function _scanNamedGroupHead(src, at) {
  if (src.charAt(at) !== "?" || src.charAt(at + 1) !== "<") return -1;
  var i = at + 2;
  if (!_isNameStart(src.charAt(i))) return -1;
  i += 1;
  while (i < src.length) {
    var ch = src.charAt(i);
    if (ch === ">") return i + 1;
    if (!_isNameStart(ch) && !_isDigitChar(ch)) return -1;
    i += 1;
  }
  return -1;
}

// `(?flags:` or `(?flags-flags:` at `at`, giving which flags it turns on and
// off, or null when the group is something else.
function _scanModifierHead(src, at) {
  if (src.charAt(at) !== "?") return null;
  var i = at + 1;
  var on = "";
  var off = "";
  while (i < src.length && _isFlagLetter(src.charAt(i))) { on += src.charAt(i); i += 1; }
  if (src.charAt(i) === "-") {
    i += 1;
    var offStart = i;
    while (i < src.length && _isFlagLetter(src.charAt(i))) { off += src.charAt(i); i += 1; }
    if (i === offStart) return null;                       // a dash naming nothing
  }
  if (src.charAt(i) !== ":") return null;
  return { on: on, off: off, end: i + 1 };
}

// `{n}` / `{n,}` / `{n,m}` from `at`, or null when the brace is a literal one.
// A digit run of any length is read: the pattern is already capped by
// maxPatternBytes, so a count on the digits bought nothing and its edge was a
// bypass — a bound one digit too long read as no quantifier at all.
function _scanBraces(src, at) {
  var i = at + 1;                                          // past the `{`
  var loStart = i;
  while (i < src.length && _isDigitChar(src.charAt(i))) i += 1;
  if (i === loStart) return null;
  var lo = parseInt(src.slice(loStart, i), 10);            // base-10 radix
  var hi = lo;
  if (src.charAt(i) === ",") {
    i += 1;
    var hiStart = i;
    while (i < src.length && _isDigitChar(src.charAt(i))) i += 1;
    hi = i === hiStart ? Infinity : parseInt(src.slice(hiStart, i), 10);  // base-10 radix
  }
  if (src.charAt(i) !== "}") return null;
  return { min: lo, max: hi, end: i + 1 };
}

// Does a modifier group turn case-insensitivity ON somewhere in the pattern?
// `(?i:...)`, `(?im:...)`, `(?i-s:...)` — the `i` has to be on the enabling
// side of the dash, so `(?-i:...)` is not one.
//
// Read one character at a time. Asking this with a pattern would be the screen
// running the construct it screens over operator-supplied text, which is the
// shape this module exists to keep away from.
function _turnsFoldingOn(src) {
  for (var i = 0; i + 2 < src.length; i += 1) {
    if (src.charAt(i) !== "(" || src.charAt(i + 1) !== "?") continue;
    var at = i + 2;
    var enablesFold = false;
    while (at < src.length && _isFlagLetter(src.charAt(at))) {
      if (src.charAt(at) === "i") enablesFold = true;
      at += 1;
    }
    if (src.charAt(at) === "-") {                          // the disabling side
      at += 1;
      while (at < src.length && _isFlagLetter(src.charAt(at))) at += 1;
    }
    if (enablesFold && src.charAt(at) === ":") return true;
  }
  return false;
}

function _parsePattern(src, flags, budget) {
  var pos = 0;
  // Folding can be switched on INSIDE the pattern, so the map cannot be
  // decided from the outer flags alone: `(?i:...)` in a pattern carrying no
  // `i` still needs the equivalences for its body.
  var foldsAnywhere = flags.indexOf("i") !== -1 || _turnsFoldingOn(src);
  var foldGroups = !foldsAnywhere ? new Map()
    : _foldGroups(src, flags.indexOf("i") === -1 ? flags + "i" : flags);

  function fail() { return null; }

  function spend(n) { budget.left -= n; return budget.left >= 0; }

  function parseAlt(depth, activeFlags) {
    if (depth > MAX_PARSE_DEPTH) return fail();
    var branches = [];
    var branch = parseSeq(depth, activeFlags);
    if (branch === null) return fail();
    branches.push(branch);
    while (src.charAt(pos) === "|") {
      pos += 1;
      branch = parseSeq(depth, activeFlags);
      if (branch === null) return fail();
      branches.push(branch);
    }
    return { type: "alt", branches: branches, flags: activeFlags };
  }

  function parseSeq(depth, activeFlags) {
    var terms = [];
    while (pos < src.length) {
      var c = src.charAt(pos);
      if (c === "|" || c === ")") break;
      var atom = parseAtom(depth, activeFlags);
      if (atom === null) return fail();
      var quant = parseQuant();
      if (quant === null) return fail();
      if (!spend(1)) return fail();
      terms.push({ node: atom, min: quant.min, max: quant.max });
    }
    return { type: "seq", terms: terms, flags: activeFlags };
  }

  // A quantifier is read here and only here, so every analysis agrees on what
  // one is. A digit run of any length is read: the whole pattern is already
  // capped by maxPatternBytes, so a count on the digits bought nothing and its
  // edge was a bypass — a bound one digit too long read as no quantifier.
  function parseQuant() {
    var c = src.charAt(pos);
    var min, max;
    if (c === "*") { min = 0; max = Infinity; pos += 1; }
    else if (c === "+") { min = 1; max = Infinity; pos += 1; }
    else if (c === "?") { min = 0; max = 1; pos += 1; }
    else if (c === "{") {
      var braced = _scanBraces(src, pos);
      if (braced === null) return { min: 1, max: 1 };                            // a literal `{`
      min = braced.min;
      max = braced.max;
      if (max < min) return null;                                                // `{5,2}` — not a pattern this reads
      pos = braced.end;
    } else return { min: 1, max: 1 };
    if (src.charAt(pos) === "?") pos += 1;                                       // lazy — backtracks the same
    return { min: min, max: max };
  }

  function parseAtom(depth, activeFlags) {
    var c = src.charAt(pos);
    if (c === "(") return parseGroup(depth, activeFlags);
    if (c === "[") return parseClass(activeFlags);
    if (c === "^" || c === "$") {
      pos += 1;
      // Which end it asserts matters: a trailing `$` after a run that reached
      // the end of the input succeeds, while a trailing `^` cannot — it
      // demands the start, so after anything non-empty it fails and sends the
      // engine back to try another split.
      return { type: "anchor", edge: c === "$" ? "end" : "start", flags: activeFlags };
    }
    if (c === ".") {
      pos += 1;
      var dot = activeFlags.indexOf("s") !== -1
        ? _mkSet([], true)                                                       // everything
        : _mkSet(LINE_TERMINATORS, true);
      return { type: "set", set: dot, flags: activeFlags };
    }
    if (c === "\\") {
      var esc = src.charAt(pos + 1);
      if (esc === "") return fail();
      pos += 2;
      // A word boundary is an assertion that can FAIL where a start-or-end
      // anchor after a run that reached the end cannot, so the two are not
      // interchangeable to the analysis that asks whether a match can fail.
      if (esc === "b" || esc === "B") {
        return { type: "anchor", edge: "word", negated: esc === "B", flags: activeFlags };
      }
      var set = _escapeSet(esc);
      if (set === null) return { type: "opaque", flags: activeFlags };
      if (!spend(_setSize(set))) return fail();
      return { type: "set", set: _applyFold(set, activeFlags, foldGroups), flags: activeFlags };
    }
    if (c === "*" || c === "+" || c === "?" || c === ")") return fail();         // a quantifier with nothing to quantify
    // Under `u` (and `v`) a surrogate pair is ONE character to the engine, so a
    // quantifier after it repeats the whole code point. Advancing a single code
    // unit would read an astral literal as a fixed lead followed by a repeated
    // trail — which is how `(?:<emoji>+)+` read as something other than the
    // nested quantifier it is.
    var literal = _codePointAt(src, pos, activeFlags);
    pos += literal.length;
    return { type: "set", set: _applyFold(_mkSet([literal], false), activeFlags, foldGroups), flags: activeFlags };
  }

  function parseClass(activeFlags) {
    var start = pos;
    // Under `v` a class may be a SET EXPRESSION — `[[a-z]--[x]]`,
    // `[[a-z]&&[aeiou]]`, `[\q{abc}]` — and this tokenizer has no
    // representation for one. Read as an ordinary class it comes apart at the
    // first `]`, and the rest is tokenized as though it were pattern text: the
    // repetition then appears to belong to a character that is really the tail
    // of the class, and an analysis that trusted the tree called
    // `[[a-z]--[x]]+b` linear where the same shape written `[a-y]+b` is
    // quadratic. Nothing here can represent it, so nothing here judges it —
    // the whole parse is abandoned and the caller reports what it cannot prove.
    if (activeFlags.indexOf("v") !== -1 && _classUsesSetSyntax(src, pos)) return fail();
    pos += 1;                                                                    // the `[`
    var negated = false;
    if (src.charAt(pos) === "^") { negated = true; pos += 1; }
    var members = new Set();
    var characterised = true;
    var closed = false;
    while (pos < src.length) {
      var c = src.charAt(pos);
      // `]` ends the class wherever it appears. `[]` is the empty class and
      // `[^]` is every character; treating the first `]` as a member instead
      // walked past the real terminator and ate the rest of the pattern as
      // class members, so every repetition after it vanished from the tree.
      if (c === "]") { pos += 1; closed = true; break; }
      var lo = _classMember(activeFlags);
      if (lo === null) { characterised = false; if (pos <= start) return fail(); continue; }
      if (src.charAt(pos) === "-" && src.charAt(pos + 1) !== "]" && pos + 1 < src.length) {
        pos += 1;
        var hi = _classMember(activeFlags);
        if (hi === null || typeof lo !== "string" || typeof hi !== "string" ||
            lo.length !== 1 || hi.length !== 1) { characterised = false; continue; }
        var from = lo.charCodeAt(0);
        var to = hi.charCodeAt(0);
        if (to < from || to - from + 1 > MAX_CLASS_RANGE) { characterised = false; continue; }
        if (!spend(to - from + 1)) return fail();
        for (var code = from; code <= to; code += 1) members.add(String.fromCharCode(code));
        continue;
      }
      if (typeof lo === "string") {
        if (!spend(1)) return fail();
        members.add(lo);
      } else {
        // Only a POSITIVE shorthand can join the member list. A negated one —
        // `[^\D]`, which is the digits — is a complement, and copying its
        // exclusions in as members then applying the class's own negation
        // states the opposite of what it means.
        if (lo.negated) { characterised = false; continue; }
        lo.chars.forEach(function (m) { members.add(m); });
        if (!spend(_setSize(lo))) return fail();
      }
    }
    if (!closed) return fail();                                                  // unterminated class
    if (!characterised) return { type: "set", set: _anySet(), flags: activeFlags };
    return { type: "set", set: _applyFold(_mkSet(members, negated), activeFlags, foldGroups), flags: activeFlags };
  }

  // One member of a class: a string for a plain character, a set for a
  // shorthand escape, or null when it is not one this reads.
  function _classMember(activeFlags) {
    var c = src.charAt(pos);
    if (c === "\\") {
      var esc = src.charAt(pos + 1);
      pos += 2;
      var set = _escapeSet(esc);
      if (set === null) return null;
      if (set.chars.size === 1 && !set.negated) {
        var only = null;
        set.chars.forEach(function (m) { only = m; });
        return only;
      }
      return set;
    }
    var member = _codePointAt(src, pos, activeFlags);
    pos += member.length;
    return member;
  }

  function parseGroup(depth, activeFlags) {
    var open = pos;
    pos += 1;                                                                    // the `(`
    var innerFlags = activeFlags;
    if (src.charAt(pos) === "?") {
      var look = _scanLookHead(src, pos);
      if (look !== null) {
        // The body is parsed and kept. A lookaround consumes nothing, so it
        // never takes characters from what follows — but the engine still
        // backtracks INSIDE it, so a catastrophic repetition placed there is
        // catastrophic. Skipping to the closing paren left it unexamined, and
        // the quantifier-in-lookaround rule that was meant to cover it reads
        // the source and cannot see through nested parentheses.
        var negatedLook = look.negated;
        var behindLook = look.behind;
        pos = look.end;
        var lookBody = parseAlt(depth + 1, innerFlags);
        if (lookBody === null) return fail();
        if (src.charAt(pos) !== ")") return fail();
        pos += 1;
        return {
          type: "look", body: lookBody, negated: negatedLook, behind: behindLook,
          flags: activeFlags,
        };
      }
      var namedEnd = _scanNamedGroupHead(src, pos);
      if (namedEnd !== -1) pos = namedEnd;
      else {
        var mod = _scanModifierHead(src, pos);
        if (mod === null) {
          var skip = _skipToGroupEnd(open);
          if (skip === -1) return fail();
          pos = skip + 1;
          return { type: "opaque", flags: activeFlags };
        }
        // A modifier group changes the flags for what it encloses, so the
        // analysis inside it has to fold the way the engine will: `(?i:a|A)`
        // is one branch written twice, not two disjoint ones.
        // Every flag the modifier names changes what its body MEANS — `s`
        // decides whether a dot covers a newline as surely as `i` decides
        // which characters are one — so all of them are applied, not the one
        // that happened to be fixed first.
        var f;
        for (f = 0; f < mod.on.length; f += 1) {
          innerFlags = _withFlag(innerFlags, mod.on.charAt(f), true);
        }
        for (f = 0; f < mod.off.length; f += 1) {
          innerFlags = _withFlag(innerFlags, mod.off.charAt(f), false);
        }
        pos = mod.end;
      }
    }
    var body = parseAlt(depth + 1, innerFlags);
    if (body === null) return fail();
    if (src.charAt(pos) !== ")") return fail();
    pos += 1;
    return { type: "group", body: body, flags: activeFlags };
  }

  function _skipToGroupEnd(from) {
    var depth = 0;
    var inClass = false;
    for (var i = from; i < src.length; i += 1) {
      var c = src.charAt(i);
      if (c === "\\") { i += 1; continue; }
      if (inClass) { if (c === "]") inClass = false; continue; }
      if (c === "[") { inClass = true; continue; }
      if (c === "(") depth += 1;
      else if (c === ")") { depth -= 1; if (depth === 0) return i; }
    }
    return -1;
  }

  var ast = parseAlt(0, typeof flags === "string" ? flags : "");
  if (ast === null || pos !== src.length) return null;
  return ast;
}

// One character at `at`, as the engine counts characters: a whole code point
// under `u` or `v`, a single code unit otherwise.
function _codePointAt(src, at, flags) {
  var one = src.charAt(at);
  if (flags.indexOf("u") === -1 && flags.indexOf("v") === -1) return one;
  var code = src.charCodeAt(at);
  if (code < 0xd800 || code > 0xdbff || at + 1 >= src.length) return one;
  var next = src.charCodeAt(at + 1);
  if (next < 0xdc00 || next > 0xdfff) return one;
  return src.slice(at, at + 2);
}

// Which characters the ENGINE treats as one under these flags.
//
// A lower/upper pass does not compute the fold class: the Kelvin sign folds to
// `k`, but `k` uppercases to `K` and never back to the Kelvin sign, so a pass
// starting at `K` never reaches it and two branches that both match it were
// proven disjoint. Which characters an engine treats as equal under `i` is a
// rule the language states, so the rule is applied — it used to be discovered
// by building a RegExp per pair of characters and seeing which ones matched,
// which is the screen reaching for the construct it exists to screen.
//
// Only characters PRESENT in the pattern can create an overlap between two of
// its sets, so the comparison is made over that alphabet alone. Pairs whose
// lower/upper forms already link them are skipped; that leaves the handful of
// characters where the answer is not obvious.
var MAX_FOLD_ALPHABET = 64;

// The whole character, so a surrogate pair is canonicalized as one.
function _canonical(ch, unicodeMode) {
  return codepointClass.canonicalizeForCase(ch.codePointAt(0), unicodeMode);
}

function _foldGroups(src, flags) {
  var unicodeMode = flags.indexOf("u") !== -1 || flags.indexOf("v") !== -1;
  var alphabet = [];
  var seen = new Set();
  for (var i = 0; i < src.length; i += 1) {
    var ch = _codePointAt(src, i, flags);
    if (ch.length === 2) i += 1;                           // a surrogate pair is one character
    if (ch.charCodeAt(0) < 0x80) continue;                 // ASCII closes under lower/upper
    if (seen.has(ch)) continue;
    seen.add(ch);
    alphabet.push(ch);
    if (alphabet.length > MAX_FOLD_ALPHABET) return null;   // too many to ask about — prove nothing
  }
  if (alphabet.length === 0) return new Map();
  // Every ASCII letter is a candidate partner: the Kelvin sign's partner is an
  // ordinary `k`, which need not appear in the pattern beside it.
  for (var code = 0x41; code <= 0x7a; code += 1) {
    if (code > 0x5a && code < 0x61) continue;               // the punctuation between the two runs
    var letter = String.fromCharCode(code);
    if (!seen.has(letter)) { seen.add(letter); alphabet.push(letter); }
  }
  var groups = new Map();
  for (var a = 0; a < alphabet.length; a += 1) {
    for (var b = a + 1; b < alphabet.length; b += 1) {
      var x = alphabet[a], y = alphabet[b];
      if (_linkedByCase(x, y)) continue;                    // already found by folding
      // Which characters an engine treats as the same under `i` is a rule, not
      // something to be discovered by asking. This used to build a RegExp per
      // pair and see whether one matched the other — the screen reaching for
      // the very construct it screens, and a pattern's worth of them per call.
      // The rule itself is exact and costs a comparison.
      if (_canonical(x, unicodeMode) !== _canonical(y, unicodeMode)) continue;
      _linkFold(groups, x, y);
      _linkFold(groups, y, x);
    }
  }
  return groups;
}

// Does folding one of them already reach the other? Sharing a lowercase is not
// the same question: the Kelvin sign and `K` both lower-case to `k`, yet
// folding `K` never produces the Kelvin sign — which is exactly the pair that
// has to be asked about rather than assumed.
function _linkedByCase(x, y) {
  return x.toLowerCase() === y || x.toUpperCase() === y ||
         y.toLowerCase() === x || y.toUpperCase() === x;
}

function _linkFold(groups, from, to) {
  var list = boundedMap.getOrInsert(groups, from, function () { return []; });
  if (list.indexOf(to) === -1) list.push(to);
}

function _escapeLiteral(ch) {
  var out = "";
  for (var i = 0; i < ch.length; i += 1) {
    out += "\\u" + ("000" + ch.charCodeAt(i).toString(16)).slice(-4);
  }
  return out;
}

function _applyFold(set, flags, foldGroups) {
  if (flags.indexOf("i") === -1) return set;
  if (foldGroups === null) return _anySet();                // the fold could not be settled
  var folded = _foldSet(set);
  if (folded.any || foldGroups.size === 0) return folded;
  var out = new Set(folded.chars);
  folded.chars.forEach(function (c) {
    var extra = foldGroups.get(c);
    if (extra) for (var i = 0; i < extra.length; i += 1) out.add(extra[i]);
  });
  return _mkSet(out, folded.negated);
}

function _withFlag(flags, flag, on) {
  var has = flags.indexOf(flag) !== -1;
  if (on === has) return flags;
  return on ? flags + flag : flags.split(flag).join("");
}

// ---- reading the tree -----------------------------------------------------

// The characters a node can begin with, or null when it can match nothing at
// all — a nullable head can start anywhere, so it is never provably disjoint.
function _firstSet(node) {
  if (node.type === "set") return node.set;
  // A lookaround consumes nothing, so for everything the enclosing sequence
  // needs to know — where a term can start, what it can take, how long it is —
  // it behaves as an anchor does. What backtracks INSIDE it is judged on its
  // own, by walking its body.
  if (node.type === "anchor" || node.type === "look") return null;
  if (node.type === "opaque") return _anySet();
  if (node.type === "group") return _firstSet(node.body);
  if (node.type === "alt") {
    var parts = [];
    for (var b = 0; b < node.branches.length; b += 1) {
      var f = _firstSet(node.branches[b]);
      if (f === null) return null;
      parts.push(f);
    }
    return _unionSets(parts);
  }
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.node.type === "anchor") continue;
    var s = _firstSet(t.node);
    if (s === null) return null;
    if (t.min === 0) return null;                    // the head is optional
    return s;
  }
  return null;                                       // matches nothing
}

// Does this node match ANY string over `alphabet` long enough to reach the end
// of it? Not "can it match one" — the input is the attacker's to choose, so a
// suffix that works for some strings over the run's characters and not others
// is one they will pick against.
//
// This is what a run has to be able to say about whatever follows it before the
// pattern can be called a single attempt rather than a scan. `a+a` qualifies:
// every character the run eats is one the trailing `a` accepts, so wherever the
// run got to, handing one back finishes the match. `[ab]+(?=ab)` does not — the
// run eats `a` and `b` alike, and against a subject of nothing but `a` the `b`
// is never there.
//
// Knowing only what the suffix can START with is not enough, and the shape of
// the suffix does not matter: `(?:ab){2}` hides the same `b` behind a group and
// a count that a bare `ab` shows plainly.
//
// Anything unreadable — a nested assertion, an unparsed construct — answers no,
// which classes the enclosing pattern as a repeated scan rather than vouching
// for it.
function _alwaysSatisfiedBy(node, alphabet) {
  return _setIsSubsetOf(alphabet, _satisfiedOn(node, alphabet));
}

// The characters a run can hand back and be certain `node` matches on, whatever
// follows them — the set the alphabet has to fit inside. Branches contribute to
// it together rather than one at a time, because `(?:a|b)` is the class `[ab]`
// written out long and the engine picks the branch the character calls for.
function _satisfiedOn(node, alphabet) {
  if (node.type === "set") return node.set;
  if (node.type === "group") return _satisfiedOn(node.body, alphabet);
  if (node.type === "anchor" || node.type === "look" || node.type === "opaque") {
    return _mkSet([], false);
  }
  if (node.type === "alt") {
    var parts = [];
    for (var b = 0; b < node.branches.length; b += 1) {
      parts.push(_satisfiedOn(node.branches[b], alphabet));
    }
    return parts.length === 0 ? _mkSet([], false) : _unionSets(parts);
  }
  // A sequence is certain on whatever its first mandatory part is certain on,
  // and only while everything after that part is certain across the WHOLE
  // alphabet — what follows the first character is the subject's to choose, so
  // `(?:a|b)` carries `[ab]+` where `(?:ab|b)` does not.
  var head = null;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.min === 0) continue;                         // it can be left out
    if (head === null) {
      head = _satisfiedOn(t.node, alphabet);
      // Its own repeats begin on characters nothing has pinned down either.
      if (t.min > 1 && !_alwaysSatisfiedBy(t.node, alphabet)) return _mkSet([], false);
      continue;
    }
    if (!_alwaysSatisfiedBy(t.node, alphabet)) return _mkSet([], false);
  }
  return head === null ? _anySet() : head;             // nothing mandatory: it matches empty
}

// Everything a node can match anywhere inside it.
function _allSet(node) {
  if (node.type === "set") return node.set;
  if (node.type === "anchor" || node.type === "look") return _mkSet([], false);
  if (node.type === "opaque") return _anySet();
  if (node.type === "group") return _allSet(node.body);
  var parts = [];
  var list = node.type === "alt" ? node.branches : node.terms;
  for (var i = 0; i < list.length; i += 1) {
    parts.push(_allSet(node.type === "alt" ? list[i] : list[i].node));
  }
  return parts.length === 0 ? _mkSet([], false) : _unionSets(parts);
}

// How many ways a node can match, or Infinity. A repetition whose ways are
// few explores a fixed number of them however long the input is, which is why
// three dotted octets — twenty-seven ways — is an ordinary pattern.
var MAX_BOUNDED_PATHS = 4096;

function _waysToMatch(node) {
  if (node.type === "set" || node.type === "anchor" || node.type === "look") return 1;
  if (node.type === "opaque") return Infinity;
  if (node.type === "group") return _waysToMatch(node.body);
  if (node.type === "alt") {
    var sum = 0;
    for (var b = 0; b < node.branches.length; b += 1) {
      sum += _waysToMatch(node.branches[b]);
      if (sum > MAX_BOUNDED_PATHS) return Infinity;
    }
    return sum;
  }
  var product = 1;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.max === Infinity) return Infinity;
    var perCopy = _waysToMatch(t.node);
    if (perCopy === Infinity) return Infinity;
    var spans = t.max - t.min + 1;                   // how many repetition counts
    var ways = spans * Math.pow(perCopy, t.max);
    if (!isFinite(ways) || ways > MAX_BOUNDED_PATHS) return Infinity;
    product *= ways;
    if (product > MAX_BOUNDED_PATHS) return Infinity;
  }
  return product;
}

// Can this node match runs of different lengths? That is what a repetition
// backtracks over.
function _isVariableLength(node) {
  if (node.type === "set" || node.type === "anchor" || node.type === "look") return false;
  if (node.type === "opaque") return true;
  if (node.type === "group") return _isVariableLength(node.body);
  if (node.type === "alt") {
    var len = _fixedLength(node.branches[0]);
    for (var b = 1; b < node.branches.length; b += 1) {
      if (_fixedLength(node.branches[b]) !== len) return true;
    }
    return len === null;
  }
  for (var i = 0; i < node.terms.length; i += 1) {
    if (node.terms[i].min !== node.terms[i].max) return true;
    if (_isVariableLength(node.terms[i].node)) return true;
  }
  return false;
}

// The one length a node always matches, or null when it varies.
function _fixedLength(node) {
  if (node.type === "anchor" || node.type === "look") return 0;
  if (node.type === "set") return 1;
  if (node.type === "opaque") return null;
  if (node.type === "group") return _fixedLength(node.body);
  if (node.type === "alt") {
    var len = _fixedLength(node.branches[0]);
    for (var b = 1; b < node.branches.length; b += 1) {
      if (_fixedLength(node.branches[b]) !== len) return null;
    }
    return len;
  }
  var total = 0;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.min !== t.max) return null;
    var one = _fixedLength(t.node);
    if (one === null) return null;
    total += one * t.min;
  }
  return total;
}

function _isNullable(node) {
  if (node.type === "anchor" || node.type === "look") return true;
  if (node.type === "set") return false;
  if (node.type === "opaque") return true;
  if (node.type === "group") return _isNullable(node.body);
  if (node.type === "alt") {
    for (var b = 0; b < node.branches.length; b += 1) {
      if (_isNullable(node.branches[b])) return true;
    }
    return false;
  }
  for (var i = 0; i < node.terms.length; i += 1) {
    if (node.terms[i].min === 0) continue;
    if (!_isNullable(node.terms[i].node)) return false;
  }
  return true;
}

// ---- the proofs -----------------------------------------------------------
//
// A repeated body is ambiguous when one repetition could have taken characters
// the next one takes instead. These prove the cases where it cannot.

// Every repetition must contain a particular character that nothing else in
// the body can match, so the occurrences of that character pin where each
// repetition ends: `(?:[a-z]+-)*` is decided, `(?:[a-z]+a)*` is not. The
// delimiter may sit at either end — a separator leading each repetition pins
// the split exactly as one trailing it does.
function _delimiterForcesSplit(body) {
  return _splitDelimiter(body) !== null;
}


// The body varies in length, but the variation cannot be re-attributed to the
// neighbouring repetition: every repetition must begin at a character none of
// the varying parts can match, and the varying parts cannot trade with each
// other either. `(?:ab?)+` is decided on those terms; `(?:a*a*-)*` is not,
// because its two varying parts match the same characters.
function _variationCannotMove(body) {
  if (body.type !== "alt" || body.branches.length !== 1) return false;
  var terms = body.branches[0].terms;
  var head = _firstSet(body);
  if (head === null) return false;
  var varying = [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min === t.max && !_isVariableLength(t.node)) continue;
    if (t.max === Infinity) return false;                          // the delimiter rule owns those
    varying.push(_allSet(t.node));
  }
  if (varying.length === 0) return false;
  for (var v = 0; v < varying.length; v += 1) {
    if (_setsIntersect(varying[v], head)) return false;
    for (var w = v + 1; w < varying.length; w += 1) {
      if (_setsIntersect(varying[v], varying[w])) return false;
    }
  }
  return true;
}

// Alternation branches that cannot start on the same character decide which
// branch matches with one character. That settles the CHOICE; it settles the
// EXTENT only if each branch matches one length, so `(?:ab?|b)+` — where the
// short form of the first branch leaves a character that starts the second —
// is not covered.
function _branchesDecideThemselves(body) {
  if (body.type !== "alt" || body.branches.length < 2) return false;
  var firsts = [];
  for (var b = 0; b < body.branches.length; b += 1) {
    if (_fixedLength(body.branches[b]) === null) return false;
    var f = _firstSet(body.branches[b]);
    if (f === null) return false;
    firsts.push(f);
  }
  for (var i = 0; i < firsts.length; i += 1) {
    for (var j = i + 1; j < firsts.length; j += 1) {
      if (_setsIntersect(firsts[i], firsts[j])) return false;
    }
  }
  return true;
}

// Branches can overlap on their first character and still be unambiguous,
// because one of them REQUIRES a character the other can never match: of
// semver's three numeric-identifier branches, the one carrying a letter is not
// reachable by the two that are all digits, whatever prefix they share. If a
// branch must contain a character outside everything another branch can match,
// no string is in both, so the choice between them is decided by the input
// rather than guessed and backtracked.
function _mustContain(branch) {
  var parts = [];
  var terms = branch.type === "seq" ? branch.terms : [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min < 1) continue;                        // it may match nothing
    if (t.node.type === "anchor" || t.node.type === "look") continue;
    var head = _firstSet(t.node);
    if (head === null) continue;                    // nullable — requires nothing
    parts.push(head);
  }
  return parts.length === 0 ? null : _unionSets(parts);
}

function _branchLanguagesDisjoint(alt) {
  if (alt.type !== "alt" || alt.branches.length < 2) return false;
  var required = [], reachable = [];
  for (var b = 0; b < alt.branches.length; b += 1) {
    required.push(_mustContain(alt.branches[b]));
    reachable.push(_allSet(alt.branches[b]));
  }
  for (var i = 0; i < alt.branches.length; i += 1) {
    for (var j = i + 1; j < alt.branches.length; j += 1) {
      var iNeedsWhatJCannot = required[i] !== null && !_setsIntersect(required[i], reachable[j]);
      var jNeedsWhatICannot = required[j] !== null && !_setsIntersect(required[j], reachable[i]);
      if (!iNeedsWhatJCannot && !jNeedsWhatICannot) return false;
    }
  }
  return true;
}

// An alternation nested anywhere inside a repeated body whose branches can
// start on the same character is a choice made afresh at every repetition,
// whatever the body's own length does — `((a|a))+` repeats a fixed-length body
// and is still exponential, because the wrapper changes nothing about the
// choice inside it.
function _containsUndecidedChoice(node) {
  if (node === null || typeof node !== "object") return false;
  if (node.type === "look") return node.body ? _containsUndecidedChoice(node.body) : true;
  if (node.type === "opaque") return true;
  if (node.type === "group") return _containsUndecidedChoice(node.body);
  if (node.type === "alt") {
    if (node.branches.length > 1 && !_branchesDecideThemselves(node) &&
        !_branchLanguagesDisjoint(node)) return true;
    for (var b = 0; b < node.branches.length; b += 1) {
      if (_containsUndecidedChoice(node.branches[b])) return true;
    }
    return false;
  }
  if (node.type !== "seq") return false;
  for (var i = 0; i < node.terms.length; i += 1) {
    if (_containsUndecidedChoice(node.terms[i].node)) return true;
  }
  return false;
}

// A repeated term is safe when any one of the proofs holds. Ways-to-match is
// checked first because it is the cheapest and the most general: a repetition
// with few ways to match explores all of them in constant time.
// Both the repetition count and the body's own variation are finite, and the
// ways they combine are few: the engine enumerates all of them in constant
// time however long the input is. Three dotted octets is twenty-seven ways.
// This holds whatever the neighbouring terms do, so it is asked first and on
// its own.
// How many ways a term — its node and its repetition together — can match, or
// Infinity. Two positions side by side cost the PRODUCT of their ways, so this
// is what composes; asking whether each is separately small does not, and let
// four `a{0,4095}` positions through at 4.5 seconds a request.
function _repetitionWays(term) {
  if (term.max === Infinity) return Infinity;
  var perCopy = _waysToMatch(term.node);
  if (perCopy === Infinity) return Infinity;
  var total = (term.max - term.min + 1) * Math.pow(perCopy, term.max);
  return isFinite(total) ? total : Infinity;
}

function _repetitionIsEnumerable(term) {
  if (term.max === Infinity) return false;
  var perCopy = _waysToMatch(term.node);
  if (perCopy === Infinity) return false;
  var total = (term.max - term.min + 1) * Math.pow(perCopy, term.max);
  return isFinite(total) && total <= MAX_BOUNDED_PATHS;
}

function _repetitionIsDecided(term) {
  var body = term.node.type === "group" ? term.node.body : term.node;
  if (_delimiterForcesSplit(body)) return true;
  if (_variationCannotMove(body)) return true;
  if (_branchesDecideThemselves(body)) return true;
  return false;
}

// ---- the findings ---------------------------------------------------------
//
// The boundaries BETWEEN a sequence's terms matter as much as any one term:
// five individually-decided `(?:a|b)+` groups in a row are each unambiguous
// while the ways to divide one run of input among them are not. A term is only
// judged in isolation when the terms around it cannot take its characters.

function _boundariesForced(seq) {
  var variable = [];
  for (var i = 0; i < seq.terms.length; i += 1) {
    var t = seq.terms[i];
    if (t.min !== t.max || _isVariableLength(t.node)) variable.push(i);
  }
  if (variable.length <= 1) return true;
  for (var v = 0; v < variable.length - 1; v += 1) {
    var idx = variable[v];
    var body = seq.terms[idx].node.type === "group" ? seq.terms[idx].node.body : seq.terms[idx].node;
    // The plainest reason a boundary cannot float: nothing any LATER term can
    // begin with is something the earlier one could have taken instead. That
    // is what pins `[a-z0-9]+` against `(?:-[a-z0-9]+)*` — every repetition of
    // the group starts on a hyphen, and the run before it cannot match one.
    var reach = _allSet(seq.terms[idx].node);
    var pinned = true;
    for (var k = idx + 1; k < seq.terms.length; k += 1) {
      var later = seq.terms[k];
      if (later.node.type === "anchor" || later.node.type === "look") continue;
      // A null head means the term can match nothing, so it can begin
      // anywhere — that pins nothing and must not read as "no conflict".
      var head = _firstSet(later.node);
      if (head === null || _setsIntersect(reach, head)) { pinned = false; break; }
      // A term that MUST match is a wall: the run before it has to stop where
      // the wall begins, and nothing past the wall can reach back across it.
      // That is what pins an email local part against its `@`.
      if (later.min > 0) break;
    }
    if (pinned) continue;
    var delimiter = _splitDelimiter(body);
    if (delimiter === null) return false;
    for (var beyond = idx + 1; beyond < seq.terms.length; beyond += 1) {
      if (_setsIntersect(_allSet(seq.terms[beyond].node), delimiter)) return false;
    }
  }
  return true;
}

// The characters a repeated body must contain and nothing else in it can
// match, or null. The separator sits at one END — a leading one pins the split
// exactly as a trailing one does — and it may be more than one term long: `::`
// is two terms, `\s+` is one that repeats. So the run is grown from the end
// while it still overlaps the rest, and what remains has to be unambiguous on
// its own. It is a SET rather than a character because under `i` a
// one-character separator covers both of its cases.
function _splitDelimiter(body) {
  if (body.type !== "alt" || body.branches.length !== 1) return null;
  var terms = body.branches[0].terms;
  if (terms.length < 2) return null;
  var trailing = _endRunDelimiter(terms, true);
  if (trailing !== null) return trailing;
  return _endRunDelimiter(terms, false);
}

function _endRunDelimiter(terms, fromEnd) {
  for (var size = 1; size < terms.length; size += 1) {
    var run = fromEnd ? terms.slice(terms.length - size) : terms.slice(0, size);
    var rest = fromEnd ? terms.slice(0, terms.length - size) : terms.slice(size);
    if (rest.length === 0) return null;
    var runSets = [];
    var mandatory = false;
    var readable = true;
    for (var i = 0; i < run.length && readable; i += 1) {
      var node = run[i].node;
      // Only a positive, characterised set can be a separator: a complement or
      // an unreadable atom says nothing about what the rest cannot match.
      if (node.type !== "set" || node.set.any || node.set.negated) readable = false;
      // A separator has to be able to swallow a WHOLE run of its own
      // characters, or the boundary floats inside that run: `-+` takes every
      // dash and the next repetition must start on something else, while
      // `\d{1,3}` caps itself at three and a run of six digits divides among
      // repetitions several ways. Exact counts and open-ended repeats can;
      // a capped-but-varying one cannot.
      else if (run[i].min !== run[i].max && run[i].max !== Infinity) readable = false;
      else {
        if (run[i].min > 0) mandatory = true;
        runSets.push(node.set);
      }
    }
    if (!readable) return null;                     // it cannot grow past this
    if (!mandatory) continue;                       // every repetition must contain it
    var runSet = _unionSets(runSets);
    var restSets = [];
    for (var r = 0; r < rest.length; r += 1) restSets.push(_allSet(rest[r].node));
    // Still shared with the rest — a longer run may separate them, as the
    // second colon of `::` does.
    if (_setsIntersect(runSet, _unionSets(restSets))) continue;
    // An OPEN-ENDED separator needs something on the other side of it that
    // must match. `(?:b*a)+` is pinned because each single `a` ends exactly one
    // repetition, whatever `b*` does; `(?:b*a+)+` is not, because a run of a's
    // divides among repetitions every possible way once the rest can match
    // nothing between them — that is `(a+)+` wearing a nullable decoration.
    var runIsOpenEnded = false;
    for (var q = 0; q < run.length; q += 1) {
      if (run[q].max === Infinity) runIsOpenEnded = true;
    }
    if (runIsOpenEnded && !_someTermMustMatch(rest)) return null;
    // The run has to be unambiguous itself, not only the rest: growing it over
    // several varying terms would otherwise let THEM trade inside it.
    if (!_varyingPartsCannotTrade(run)) return null;
    if (!_varyingPartsCannotTrade(rest)) return null;
    return runSet;
  }
  return null;
}

// A separator pins where each repetition ENDS. The paths through the whole
// match are the PRODUCT of the paths through each repetition, so what is left
// of the body has to have one parse of its own — which is a question about
// whether its varying parts can take each other's characters, not about how
// many of them there are. `(?:,\s*[a-z]+)*` has two and they are disjoint;
// `(?:a*a*-)*` has two that are not, and it is exponential.
// Far above any real pattern's fixed run of atoms; a pattern that reaches it is
// reported rather than read further.
var MAX_BRIDGE_STEPS = 256;
var BRIDGE_UNREADABLE = { unreadable: true };

function _varyingPartsCannotTrade(terms) {
  var varying = [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min === t.max && !_isVariableLength(t.node)) continue;
    varying.push({ at: i, set: _allSet(t.node) });
  }
  for (var v = 0; v < varying.length; v += 1) {
    for (var w = v + 1; w < varying.length; w += 1) {
      if (_setsIntersect(varying[v].set, varying[w].set)) return false;
      // They can also trade THROUGH the fixed-width terms between them: in
      // `a*[ab]b*` the segment "aab" parses two ways, because `[ab]` can take
      // the character either neighbour gives up. Comparing only the varying
      // parts to each other reads {a} and {b} as disjoint and misses it.
      //
      // The hand-off runs the whole way along, not one atom at a time. In
      // `a*[ab][bc]c*` no single atom touches both ends, and yet `abc` parses
      // twice — every atom takes its neighbour's character and the whole
      // segment shifts by one. So the chain is walked, and it carries only
      // while each step overlaps the one before it.
      var steps = _bridgeSteps(terms, varying[v].at + 1, varying[w].at);
      if (steps === BRIDGE_UNREADABLE) return false;   // unread, so unproven
      if (steps === null) continue;                    // an adjacent pair covers it
      var carried = varying[v].set;
      var chained = true;
      for (var s = 0; s < steps.length; s += 1) {
        if (!_setsIntersect(carried, steps[s])) { chained = false; break; }
        carried = steps[s];
      }
      if (chained && _setsIntersect(carried, varying[w].set)) return false;
    }
  }
  return true;
}

// The characters between two positions, ONE AT A TIME. A hand-off moves the
// whole segment along by a single character, so it has to be read that way:
// `(?:ax)` is an `a` then an `x`, and the union {a,x} would invent a step from
// `a` straight to `b` that no shift can make. Written out or parenthesised, the
// same characters must give the same answer.
//
// Null when something between them is variable-width — that pair is covered by
// the adjacent pairs on either side of it, which are checked in their own turn.
function _bridgeSteps(terms, from, to) {
  var steps = [];
  for (var i = from; i < to; i += 1) {
    var ok = _pushBridgeSteps(terms[i], steps);
    if (ok === false) return null;                   // variable-width between them
    if (ok === null) return BRIDGE_UNREADABLE;       // too much to read: fail closed
  }
  return steps;
}

// A count is never expanded into a step per repetition. `[ab]{1000000000}` is
// one step: a set that overlaps its neighbour still overlaps it however many
// times it repeats, so the extra copies say nothing the first did not — and
// writing them out would let a short pattern spend the screen's memory, which
// is the very thing this module exists to prevent.
function _pushBridgeSteps(term, steps) {
  var node = term.node;
  if (node.type === "anchor" || node.type === "look") return true;   // no characters
  if (term.min !== term.max) return false;                           // variable-width
  if (term.min === 0) return true;                                   // no characters
  if (steps.length >= MAX_BRIDGE_STEPS) return null;
  if (node.type === "set") {
    steps.push(node.set);
    return true;
  }
  if (node.type === "group" && node.body && node.body.type === "alt" &&
      node.body.branches.length === 1 && node.body.branches[0].type === "seq") {
    // Two rounds show every hand-off there is, including the one across the
    // join between repetitions; a third only repeats what the second showed.
    var inner = node.body.branches[0].terms;
    var rounds = term.min > 1 ? 2 : 1;
    for (var r = 0; r < rounds; r += 1) {
      for (var j = 0; j < inner.length; j += 1) {
        var ok = _pushBridgeSteps(inner[j], steps);
        if (ok !== true) return ok;
      }
    }
    return true;
  }
  // A choice, or something unread: carry everything it can match, which can
  // only make the chain easier to complete and the pattern harder to vouch for.
  steps.push(_allSet(node));
  return true;
}

// Does at least one term here have to match a character? A body of nothing but
// optional parts can match empty, which is what makes a separator beside it no
// separator at all.
function _someTermMustMatch(terms) {
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min < 1) continue;
    if (t.node.type === "anchor" || t.node.type === "look") continue;
    if (!_isNullable(t.node)) return true;
  }
  return false;
}

// Two positions in one sequence that repeat over characters they share divide
// a run of those characters between them every possible way — quadratic for
// two, degree k for k. Nullable terms between them do not separate them: they
// can match nothing, which is exactly what makes the two neighbours. It only
// costs anything when something after the pair can FAIL and send the engine
// back to try another split, so a later term that must match and cannot match
// what the pair matches is what turns the ambiguity into work. Without one —
// `^\s*.*$` — the first attempt succeeds and there is nothing to explore.
function _adjacentAmbiguity(seq, outerCanFail) {
  for (var i = 0; i < seq.terms.length; i += 1) {
    var left = seq.terms[i];
    if (!_repeatsVariably(left)) continue;
    var leftSet = _allSet(left.node);
    var leftWays = _repetitionWays(left);
    for (var j = i + 1; j < seq.terms.length; j += 1) {
      var right = seq.terms[j];
      // The two positions can only trade characters at the boundary between
      // them, so what matters is what the later one can BEGIN with — a group
      // that must start on a hyphen takes nothing from a run of digits, however
      // many digits it can match further in.
      var rightHead = _firstSet(right.node);
      if (rightHead === null) rightHead = _allSet(right.node);
      if (_repeatsVariably(right) && _setsIntersect(leftSet, rightHead)) {
        // Together the two positions divide a run of shared characters
        // leftWays x rightWays ways. Few enough of those and the engine
        // enumerates them in constant time however long the run is.
        var pairWays = leftWays * _repetitionWays(right);
        if (!(isFinite(pairWays) && pairWays <= MAX_BOUNDED_PATHS) &&
            _canFailAfter(seq, j + 1, _unionSets([leftSet, _allSet(right.node)]),
                          outerCanFail)) return true;
        break;
      }
      if (!_termIsNullable(right)) break;                          // a mandatory term separates them
    }
  }
  return false;
}

function _repeatsVariably(term) {
  if (term.min !== term.max) return true;
  return term.min > 0 && _isVariableLength(term.node);
}

function _termIsNullable(term) {
  return term.min === 0 || _isNullable(term.node);
}

// Can the match still fail once the pair has been passed? Only then does the
// engine come back to try another split. Anything that MUST match can be
// absent from the input. If everything left is optional, the match fails only
// on a character nothing here accepts — so it cannot fail at all when the pair
// and the optional remainder between them cover every character, which is why
// `^\s*.*$` is linear while `^a*a*$` is quadratic.
// Whether anything at or after `from` can refuse, ignoring what the pair
// covers. Used to tell a nested sequence that its enclosing context has a
// failure point of its own — a group hides the `!` that follows it, and
// without this the inside of `^(?:\s*.*)!$` reads as a match that cannot fail.
function _tailCanFail(seq, from) {
  for (var i = from; i < seq.terms.length; i += 1) {
    var t = seq.terms[i];
    if (t.node.type === "look") return true;
    if (t.node.type === "anchor") {
      if (t.node.edge === "end") continue;
      return true;
    }
    if (t.min > 0) return true;
  }
  return false;
}

function _canFailAfter(seq, from, covered, outerCanFail) {
  if (outerCanFail) return true;
  var reach = [covered];
  for (var i = from; i < seq.terms.length; i += 1) {
    var t = seq.terms[i];
    // An assertion consumes nothing but can still refuse, and a refusal is
    // what sends the engine back for another split. Only a start-or-end
    // anchor is safe here, and only because the pair covering every character
    // means the greedy first attempt already reached the end. A word boundary
    // or a lookaround can fail wherever it sits.
    if (t.node.type === "look") return true;
    if (t.node.type === "anchor") {
      if (t.node.edge === "end") continue;
      return true;
    }
    if (t.min > 0) return true;                                    // must match, so it can be missing
    reach.push(_allSet(t.node));
  }
  var all = _unionSets(reach);
  return !(all.any || (all.negated && all.chars.size === 0));
}

// Walk every sequence in the tree, judging each repeated term and each
// sequence's own boundaries.
function _findAmbiguity(node, out, outerCanFail) {
  if (node === null || typeof node !== "object") return;
  outerCanFail = outerCanFail === true;
  if (node.type === "alt") {
    for (var b = 0; b < node.branches.length; b += 1) {
      _findAmbiguity(node.branches[b], out, outerCanFail);
    }
    return;
  }
  if (node.type === "group") { _findAmbiguity(node.body, out, outerCanFail); return; }
  if (node.type === "look") {
    // A lookaround consumes nothing, so it never takes characters from what
    // follows — but the engine still backtracks INSIDE it, and a catastrophic
    // repetition placed there is catastrophic. What it contains is judged the
    // same way, and reported under the lookaround rule as well so an operator
    // who tightened that one specifically still gets the finding.
    if (node.body) {
      var inner = { nested: false, alternation: false, lookaround: false };
      _findAmbiguity(node.body, inner, outerCanFail);
      if (inner.nested) out.nested = true;
      if (inner.alternation) out.alternation = true;
      if (inner.nested || inner.alternation || inner.lookaround) out.lookaround = true;
    }
    return;
  }
  if (node.type !== "seq") return;

  // Boundaries proven forced are boundaries that cannot float, which is the
  // whole of what the adjacency check looks for — asking it again would only
  // re-derive, less precisely, what the proof already settled.
  var forced = _boundariesForced(node);
  if (!forced && _adjacentAmbiguity(node, outerCanFail)) out.nested = true;
  for (var i = 0; i < node.terms.length; i += 1) {
    var term = node.terms[i];
    // What follows THIS term inside the sequence, or failing that whatever the
    // enclosing context can refuse with, is the continuation its contents face.
    _findAmbiguity(term.node, out, _tailCanFail(node, i + 1) || outerCanFail);
    if (term.max <= 1) continue;                                   // taken at most once
    var body = term.node.type === "group" ? term.node.body : term.node;
    var isAlternation = body.type === "alt" && body.branches.length > 1;
    if (!_isVariableLength(term.node) && !isAlternation &&
        !_containsUndecidedChoice(body)) continue;
    if (_repetitionIsEnumerable(term)) continue;
    if (forced && _repetitionIsDecided(term) && !_containsUndecidedChoice(body)) continue;
    if (isAlternation) out.alternation = true;
    else out.nested = true;
  }
}

// The most characters a node can match, or Infinity.
function _maxLength(node) {
  if (node.type === "anchor" || node.type === "look") return 0;
  if (node.type === "set") return 1;
  if (node.type === "opaque") return Infinity;
  if (node.type === "group") return _maxLength(node.body);
  if (node.type === "alt") {
    var widest = 0;
    for (var b = 0; b < node.branches.length; b += 1) {
      var one = _maxLength(node.branches[b]);
      if (one === Infinity) return Infinity;
      if (one > widest) widest = one;
    }
    return widest;
  }
  var total = 0;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    var per = _maxLength(t.node);
    if (per === 0) continue;
    if (per === Infinity || t.max === Infinity) return Infinity;
    total += per * t.max;
  }
  return total;
}

// The fewest characters this node can consume. A body that can consume none
// matches wherever it is asked, including where there is nothing behind it —
// which is what makes a NEGATIVE lookbehind over it fail everywhere: `(?<!)`
// and `(?<!a?)` are refusals at every position, not assertions that hold at the
// start of the subject.
function _minLength(node) {
  if (node.type === "anchor" || node.type === "look") return 0;
  if (node.type === "set") return 1;
  if (node.type === "opaque") return 0;                      // never proven to need one
  if (node.type === "group") return _minLength(node.body);
  if (node.type === "alt") {
    var shortest = Infinity;
    for (var b = 0; b < node.branches.length; b += 1) {
      var one = _minLength(node.branches[b]);
      if (one < shortest) shortest = one;
    }
    return shortest === Infinity ? 0 : shortest;
  }
  var total = 0;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.min < 1) continue;
    total += _minLength(t.node) * t.min;
  }
  return total;
}

// A pattern that is not anchored at the start is retried at EVERY position in
// the subject. That costs nothing when an attempt fails at once — a leading
// literal is checked and rejected in constant time — but when the pattern can
// consume an unbounded amount BEFORE reaching something that must match, each
// attempt walks the rest of the input before discovering the failure, and the
// whole scan is quadratic in the subject length.
//
// No ambiguity is involved, so none of the backtracking rules see it: `/a+b/`
// and `/(\w+)\s+(\d+)/` are each unambiguous on one attempt and each cost
// seconds on a few tens of kilobytes of attacker-controlled input. The remedy
// is to anchor the pattern, make it sticky, or bound the subject — so this is
// its own finding under its own policy, and an operator who bounds the subject
// can turn it off without giving up the backtracking classes.
function _unanchoredScanIsQuadratic(ast, flags) {
  var text = typeof flags === "string" ? flags : "";
  if (text.indexOf("y") !== -1) return false;              // sticky — one position, not every one
  var multiline = text.indexOf("m") !== -1;
  if (ast.type !== "alt") return false;
  for (var b = 0; b < ast.branches.length; b += 1) {
    if (_branchScanIsQuadratic(ast.branches[b], multiline)) return true;
  }
  return false;
}

// A group that neither repeats nor offers a choice changes nothing about how
// many positions the engine tries the pattern at, so its contents are part of
// the same scan. Reading only the outermost term list let one pair of
// parentheses hide the cost: `(a+b)` is `a+b`.
function _inlineForScan(terms) {
  var out = [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min === 1 && t.max === 1 && t.node.type === "group" &&
        t.node.body.type === "alt" && t.node.body.branches.length === 1) {
      out = out.concat(_inlineForScan(t.node.body.branches[0].terms));
      continue;
    }
    out.push(t);
  }
  return out;
}

// Expanding a choice re-reads everything around it, so a pattern made of them
// could cost more to screen than to run. Far above any real pattern, and a
// pattern that reaches it is reported rather than waved through.
var MAX_SCAN_EXPANSIONS = 2048;

// Stands in for an assertion carried past the one being read: it consumes
// nothing and it can refuse, which is all the scan analysis needs of it.
var ASSERTION_STOP = { node: { type: "anchor", edge: "assertion" }, min: 1, max: 1 };

function _branchScanIsQuadratic(seq, multiline, budget) {
  if (seq.type !== "seq") return false;
  return _termsScanIsQuadratic(_inlineForScan(seq.terms), multiline,
                               budget || { left: MAX_SCAN_EXPANSIONS });
}

function _termsScanIsQuadratic(terms, multiline, budget) {
  // Anchored to one position, so nothing inside it is repeated per character.
  if (_pinnedToOnePosition(terms, multiline)) return false;

  // A lookaround consumes nothing, which is not the same as costing nothing.
  // `(?=a+b)` re-runs its body at every position in the subject and each run
  // walks what is left, so the assertion is the scan. Its body is a pattern in
  // its own right and is read as one — including its own anchors, so `(?=^a+b)`
  // is one attempt like any other anchored pattern.
  for (var k = 0; k < terms.length; k += 1) {
    var look = terms[k];
    if (look.node.type !== "look" || !look.node.body) continue;
    // A lookBEHIND matches its body backwards from the position, so the same
    // reading applies to it reversed: what it tests first is what stands
    // immediately before. It is the difference between `(?<=a+b)`, which fails
    // on the neighbouring `b` at nearly every position, and `(?<=ba+)`, which
    // walks back through everything before it at every one.
    var body = look.node.behind ? _reversedForLookbehind(look.node.body) : look.node.body;
    if (body.type !== "alt") continue;
    if (!_lookIsReachableEverywhere(terms, k, body)) continue;
    // What follows the assertion is part of the same attempt, so it is where
    // the attempt can fail. An assertion that always SUCCEEDS still costs what
    // its run costs, and something failing after it makes the engine pay that
    // again from the next position: `(?=a+)[^a]` walks the whole subject at
    // every position, though `(?=a+)` alone matches at the first.
    // The body consumes nothing, so what follows the assertion is tested at the
    // same position the body started from, not after it. Reading a following
    // assertion as though it stood past the body would judge it against the
    // body's run — so it is carried as what it is here: something that can
    // refuse without consuming.
    var continuation = [];
    if (look.node.negated) {
      // For a NEGATED assertion the body succeeding IS the failure, so nothing
      // after it matters: `(?!a+)` refuses at every position, each time having
      // walked the rest of the subject to find the `a+` it forbids.
      continuation.push(ASSERTION_STOP);
    } else {
      for (var c = k + 1; c < terms.length; c += 1) {
        continuation.push(terms[c].node.type === "look" ? ASSERTION_STOP : terms[c]);
      }
    }
    for (var lb = 0; lb < body.branches.length; lb += 1) {
      var branch = body.branches[lb];
      if (branch.type !== "seq") continue;
      var withRest = _inlineForScan(branch.terms).concat(continuation);
      if (_termsScanIsQuadratic(withRest, multiline, budget)) return true;
    }
  }

  // A choice is several scans, not one: only one branch of `(?:x|a+b)` runs
  // away, and that is enough. It need not be the FIRST thing in the pattern —
  // `a(?:x|a+b)` enters the same branch from every starting position, so the
  // search continues past whatever fixed atoms precede it.
  for (var g = 0; g < terms.length; g += 1) {
    var term = terms[g];
    if (term.min === 1 && term.max === 1 && term.node.type === "group" &&
        term.node.body.type === "alt" && term.node.body.branches.length > 1) {
      var after = terms.slice(g + 1);
      var before = terms.slice(0, g);
      for (var br = 0; br < term.node.body.branches.length; br += 1) {
        budget.left -= 1;
        if (budget.left <= 0) return true;                // unread, so reported
        var spliced = _inlineForScan(term.node.body.branches[br].terms).concat(after);
        if (_termsScanIsQuadratic(before.concat(spliced), multiline, budget)) return true;
      }
      return false;                                      // the branches cover every path
    }
    // Stop at the first term that runs away. Past it a choice belongs to the
    // suffix, where the engine tries every branch of it at each step back
    // through the run — `[ab]+(?:a|b)` is not `[ab]+a` or `[ab]+b` but both at
    // once, which is what makes it the class `[ab]`. Reading the suffix is the
    // suffix rule's job, and it reads a choice as the cover it is.
    if (_isRunawayTerm(term)) break;
  }
  return _headRunsAway(terms, multiline, budget);
}

// A term that can consume an unbounded amount, which is what makes an attempt
// cost the length of what remains rather than a constant.
function _isRunawayTerm(term) {
  if (term.node.type === "anchor" || term.node.type === "look") return false;
  var span = _maxLength(term.node);
  return span === Infinity || (term.max === Infinity && span > 0);
}

// A `^` before anything is consumed means one attempt, whatever follows it.
// Under `m` it matches at every line start instead, which is fewer positions
// than characters but still grows with the input.
function _pinnedToOnePosition(terms, multiline) {
  for (var i = 0; i < terms.length; i += 1) {
    // An assertion standing BEFORE the anchor is evaluated before the anchor
    // can refuse, so the anchor does not save it from being tried everywhere.
    // Whether it costs anything is the assertion rule's question, not this
    // one's — this one only stops answering.
    if (terms[i].node.type === "look") return false;
    if (terms[i].node.type === "anchor") {
      if (terms[i].node.edge === "start" && !_multilineAt(terms[i].node, multiline)) return true;
      continue;
    }
    return false;
  }
  return false;
}

// Whether `^` means the start of the SUBJECT or the start of a line, where this
// anchor stands. A modifier group turns it on for part of a pattern — inside
// `(?m: ... )` the anchor matches at every line start whatever the pattern's own
// flags say — so the answer comes from the flags in force at the anchor.
function _multilineAt(node, fallback) {
  return typeof node.flags === "string" ? node.flags.indexOf("m") !== -1 : fallback;
}

// The characters a negative lookahead rules out at its own position, or null
// when it rules out no single character. Forbidding `a` forbids the character;
// forbidding `ab` forbids only the pair, and leaves every `a` not followed by
// a `b` exactly where it was.
function _forbiddenHeadSet(body) {
  return body ? _soleSetOf(body) : null;
}

// One mandatory character and nothing else asked for.
function _soleSetOf(node) {
  if (node.type === "set") return node.set;
  if (node.type === "group") return _soleSetOf(node.body);
  // A group's body is an alternation, so parentheses alone must not change the
  // answer: `(?!(?:a))` forbids what `(?!a)` forbids, and a choice between
  // single characters forbids all of them at once.
  if (node.type === "alt") {
    var parts = [];
    for (var b = 0; b < node.branches.length; b += 1) {
      var branchSet = _soleSetOf(node.branches[b]);
      if (branchSet === null) return null;
      parts.push(branchSet);
    }
    return parts.length === 0 ? null : _unionSets(parts);
  }
  if (node.type !== "seq") return null;
  var found = null;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.min !== 1) return null;                        // a prefix, not a character
    if (found !== null) return null;                     // more than one part is required
    found = _soleSetOf(t.node);
    if (found === null) return null;
  }
  return found;
}

// A lookbehind's body, written the way it is matched — last part first. Only
// the ORDER changes: a set reads the same from either side, and an anchor is
// left alone because every anchor is already treated as somewhere an attempt
// can fail.
function _reversedForLookbehind(node) {
  if (!node) return node;
  if (node.type === "alt") {
    var branches = [];
    for (var b = 0; b < node.branches.length; b += 1) {
      branches.push(_reversedForLookbehind(node.branches[b]));
    }
    return { type: "alt", branches: branches };
  }
  if (node.type === "seq") {
    var terms = [];
    for (var i = node.terms.length - 1; i >= 0; i -= 1) {
      var t = node.terms[i];
      terms.push({ node: _reversedForLookbehind(t.node), min: t.min, max: t.max });
    }
    return { type: "seq", terms: terms };
  }
  if (node.type === "group") return { type: "group", body: _reversedForLookbehind(node.body) };
  return node;
}

// Is the assertion reached from most starting positions? The same question the
// run asks, and the same answer: only when one input can both match everything
// mandatory before it and supply what its body needs to get going. `x(?=a+b)`
// cannot — a subject of `x` reaches the assertion everywhere and gives the
// `a+` nothing to eat, and a subject of `a` feeds the run but matches the `x`
// nowhere — so its body runs a bounded number of times and the scan is linear.
function _lookIsReachableEverywhere(terms, at, body) {
  var head = _firstSet(body);
  if (head === null) head = _allSet(body);
  // What holds a scan is judged on what the scan WALKS, which is neither the
  // character it starts on nor everything the assertion can match.
  var walks = _scanSetOfBody(body);
  for (var i = 0; i < at; i += 1) {
    var t = terms[i];
    if (t.node.type === "look") {
      // A positive lookAHEAD in front of this one tests the same position, so
      // it decides where this one is reached at all. `(?=x)(?=a+b)` runs its
      // `a+` only where an `x` stands, and there it stops at once. A negative
      // one forbids rather than requires, and a lookBEHIND speaks about the
      // text before the position, so neither narrows this.
      if (t.node.behind) {
        if (_lookbehindSeparates(t.node, walks)) return false;
        continue;
      }
      if (!t.node.body) continue;
      if (t.node.negated) {
        // A negative one narrows too, when what it forbids is a character
        // rather than a sequence: `(?!a)(?=a+b)` reaches the `a+` only where
        // there is no `a` for it. `(?!ab)` forbids the pair and leaves every
        // `a` that is not followed by `b`, so it rules nothing out here.
        var forbidden = _forbiddenHeadSet(t.node.body);
        if (forbidden !== null && _setIsSubsetOf(head, forbidden)) return false;
        continue;
      }
      var required = _firstSet(t.node.body);
      if (required !== null && !_setsIntersect(required, head)) return false;
      continue;
    }
    if (t.node.type === "anchor") {
      // What the assertion STARTS by consuming, the same set the direct form
      // is judged on. It is the run that reaches the next separator or reads
      // past it; what the assertion goes on to ask for afterwards is bounded
      // by wherever that run stopped.
      if (_anchorBoundsTheScan(t.node, walks)) return false;
      continue;
    }
    if (t.min < 1) continue;                                 // optional — costs nothing
    if (!_setsIntersect(_allSet(t.node), head)) return false;
  }
  return true;
}

// The characters an assertion's scan actually WALKS: those of its first
// runaway part. Not the character it starts on — `(?=a[ax]*z)` starts on an `a`
// and then walks over `x` as well, so an `x` in front of it separates nothing.
// And not everything it can match — `(?=\w+\s+\d+)` walks only over `\w`, and
// stops at the space, which is exactly why a word boundary holds it.
function _scanSetOfBody(body) {
  var parts = [];
  if (body && body.type === "alt") {
    for (var b = 0; b < body.branches.length; b += 1) {
      var branch = body.branches[b];
      if (branch.type !== "seq") continue;
      var flat = _inlineForScan(branch.terms);
      for (var i = 0; i < flat.length; i += 1) {
        if (_isRunawayTerm(flat[i])) { parts.push(_allSet(flat[i].node)); break; }
      }
    }
  }
  // Nothing found is not the same as nothing there — a scan nested inside
  // another assertion consumes nothing that `_allSet` can see. So the answer is
  // everything, and no separator gets to claim it holds a scan this could not
  // read.
  return parts.length === 0 ? _anySet() : _unionSets(parts);
}

// A positive lookBEHIND in front of a scan says what stands immediately before
// every viable start. When the scan cannot eat that character, the starts are
// separated by something it has to stop at, so the runs from them do not
// overlap and their lengths add up to the subject rather than multiplying by
// it: `(?<=x)a+b` is linear where `(?<=a)a+b` is quadratic.
function _lookbehindSeparates(node, scanSet) {
  if (!node.behind || node.negated || !node.body) return false;
  // ANY position it insists on will do, not only the one nearest the start.
  // `(?<=xa)a+b` puts the `x` two characters back, and a scan of `a`s stops at
  // it just the same — every viable start still has one in front of it, so the
  // runs do not overlap.
  var positions = [];
  if (_flatSets(_reversedForLookbehind(node.body), positions, MAX_BEHIND_POSITIONS)) {
    for (var i = 0; i < positions.length; i += 1) {
      if (!_setsIntersect(positions[i], scanSet)) return true;
    }
    return false;
  }
  var before = _firstSet(_reversedForLookbehind(node.body));
  return before !== null && !_setsIntersect(before, scanSet);
}

// Does an anchor standing in front of a scan hold it to a bounded number of
// runs? Only two do, and for different reasons.
//
// `$` outside multiline succeeds at one place in the subject, so whatever
// follows it runs once: `$(?=a+b)` is linear where `(?=a+b)` is quadratic.
//
// The others succeed far more often, and whether that matters depends on the
// scan. Their firings are separated by a character of a particular kind — a
// newline for a line anchor, a character of the other class for `\b` — so a
// scan that cannot match across that separator gets no further than the next
// one, and the number of firings and the distance between them trade off
// exactly: `(?m)^a+b` and `\b\w+\s+\d+` are linear. A scan that CAN cross
// reaches the end of the subject from every firing and stays quadratic:
// `\b.*z` is not saved by its `\b`, nor `(?m)^[\s\S]*z` by its `^`.
function _anchorBoundsTheScan(anchor, scanSet) {
  if (anchor.edge === "word") {
    // `\B` is the opposite: it succeeds everywhere EXCEPT the transitions, so
    // it fires all the way through a run instead of separating one from the
    // next and bounds nothing. `\B\w+z` scans from nearly every position.
    if (anchor.negated) return false;
    return _setIsSubsetOf(scanSet, _escapeSet("w")) ||
           _setIsSubsetOf(scanSet, _escapeSet("W"));
  }
  if (!_multilineAt(anchor, false)) return anchor.edge === "end";
  // Every line terminator, not just the newline. `^` under `m` fires after a
  // carriage return and after the two Unicode separators as well, so a scan
  // that stops only at `\n` reads straight past them: `/^[^\n]*z/m` is
  // quadratic on a subject of carriage returns.
  return !_setsIntersect(scanSet, _mkSet(LINE_TERMINATORS, false));
}

function _headRunsAway(terms, multiline, budget) {
  var i = 0;
  for (; i < terms.length; i += 1) {
    if (terms[i].node.type === "look") continue;
    if (terms[i].node.type === "anchor") {
      if (terms[i].node.edge === "start" && !_multilineAt(terms[i].node, multiline)) return false;
      continue;
    }
    break;
  }
  // The runaway term need not be the FIRST one. A fixed atom in front costs an
  // attempt nothing — `aa+b` and `a.*b` pass their leading `a` in constant time
  // and then scan the whole remaining suffix before failing, exactly as `a+b`
  // does. Any position from here on can be the one that runs away.
  for (var r = i; r < terms.length; r += 1) {
    var term = terms[r];
    if (term.node.type === "anchor" || term.node.type === "look") continue;
    var reach = _maxLength(term.node);
    var runsAway = reach === Infinity || (term.max === Infinity && reach > 0);
    if (!runsAway) continue;
    if (!_runIsReachableEverywhere(terms, i, r)) continue;
    if (_canFailAfterRun(terms, r)) return true;
    // The failure can be INSIDE the term that runs away. `(?:a+b)+` has nothing
    // after it to fail on, and fails on its own `b` at every position all the
    // same, so the body is read as the pattern it is.
    //
    // Only while the term is MANDATORY. One that can be left out matches empty
    // and the attempt succeeds there and then, whatever its body would have
    // failed on: `(?:[a-z]+-)*` is linear.
    if (term.min >= 1 && term.node.type === "group" && term.node.body &&
        term.node.body.type === "alt") {
      for (var gb = 0; gb < term.node.body.branches.length; gb += 1) {
        if (_branchScanIsQuadratic(term.node.body.branches[gb], multiline, budget)) return true;
      }
    }
  }
  return false;
}

// Can one input both match everything before the run AND feed the run? Only
// then does the run get to walk the input from most starting positions.
//
// `aa+b` qualifies: a string of `a`s matches the leading `a` at every position
// and the `a+` then eats the rest. `\.[a-f0-9]{8,}\.` does not: an all-dots
// input matches the leading dot everywhere but the run cannot eat a dot, and a
// hex input feeds the run but matches the leading dot nowhere. A mandatory
// prefix over characters the run cannot consume bounds the scan.
function _runIsReachableEverywhere(terms, from, runAt) {
  // What the run can BEGIN with, not everything it can match. The optional
  // build-metadata group of a version string can match letters, but it has to
  // start on `-` or `+`; a stream of version prefixes never supplies one where
  // the group begins, so the run never gets going and the scan stays linear.
  var runHead = _firstSet(terms[runAt].node);
  if (runHead === null) runHead = _allSet(terms[runAt].node);
  // From the start of the pattern, not from the first consuming term: an
  // anchor in front of the run is one of the things that can bound it.
  for (var i = 0; i < runAt; i += 1) {
    var t = terms[i];
    if (t.node.type === "look") {
      if (_lookbehindSeparates(t.node, _allSet(terms[runAt].node))) return false;
      continue;
    }
    if (t.node.type === "anchor") {
      if (_anchorBoundsTheScan(t.node, _allSet(terms[runAt].node))) return false;
      continue;
    }
    if (t.min < 1) continue;                                 // optional — costs an attempt nothing
    if (!_setsIntersect(_allSet(t.node), runHead)) return false;
  }
  return true;
}

// Is there something after the runaway term that an attempt can fail on?
//
// Not every mandatory suffix qualifies. `a+a` and `\w+\w` always succeed on the
// first attempt wherever the run is long enough, and where it is not, there is
// nothing for the run to scan — the suffix asks only for a character the run
// itself has been eating, so it can always hand one back. What makes the scan
// quadratic is a suffix the run CANNOT satisfy out of its own characters, so
// every attempt walks the run to its end and then fails.
//
// An assertion counts too. `a+$` and `a+(?=b)` consume nothing, but `$` fails
// on any input with a trailing character the run did not eat, and the engine
// then repeats that walk from every start position.
function _canFailAfterRun(terms, from) {
  var reach = _allSet(terms[from].node);
  // The fewest characters the run can leave behind an endpoint. `a*` can leave
  // none, `a+` one, `(?:ab)+` two — which is what a negative lookbehind has to
  // outreach before it can be settled by failing to match. Nothing may stand in
  // front of the run for this to hold, not even something zero-width: a `\B`
  // there refuses position zero, so the first attempt to reach the run begins
  // somewhere with characters behind it, and `\Ba*(?<!a)` walks the rest of the
  // subject from every one of them.
  var shortestRun = _minLength(terms[from].node) * terms[from].min;
  for (var j = from + 1; j < terms.length; j += 1) {
    var later = terms[j];
    if (later.node.type === "look") {
      // A lookaround the run can settle out of its own characters is not a
      // failure point. A POSITIVE one has to be satisfiable in full from what
      // the run eats: `a+(?=a)` hands one `a` back and the first viable attempt
      // completes, exactly as `a+a` does, while `a+(?=b)` never can. Its first
      // character alone does not answer that — `a+(?=a[^a])` starts on ground
      // the run covers and then asks for something it never supplies.
      //
      // A NEGATIVE one is settled by the assertion failing, so what matters is
      // whether it can even begin — and that answer depends on WHICH WAY it
      // looks, because the two directions read opposite ground.
      //
      // Looking AHEAD, it reads what the run did not eat. When everything it
      // forbids is something the run eats — `a+(?!a)` — a greedy run stops at a
      // character it could not eat, so the assertion holds on the first try.
      // When it forbids nothing the run eats — `a+(?!b)` — one handed-back
      // character is enough. Only the partial overlap fails repeatedly:
      // `a+(?![ab])` meets the forbidden `b` past the run and then walks back
      // through a run of forbidden `a`s, refusing at every step.
      //
      // Looking BEHIND, it reads the characters the run just ate, so forbidding
      // them is the WORST case rather than the safe one: `a+(?<!a)` refuses at
      // the end of the greedy run, refuses again at every character it hands
      // back, and does the whole walk again from every later start — quadratic,
      // and it was being waved through by the lookahead's own argument. Only
      // forbidding something the run never eats — `a+(?<!b)` — settles at once.
      var body = later.node.body;
      if (body) {
        if (later.node.negated && later.node.behind) {
          // A negative lookbehind is settled by FAILING to match, and it reads
          // the characters the run just ate — so it refuses at every endpoint
          // exactly when the run's own characters can spell the whole of it.
          // `a+(?<!a)` is that case, and quadratic. `a+(?<!ab)` and `a+(?<!ba)`
          // are not: neither can be spelled out of `a`s, so the assertion holds
          // where the greedy run stops and the first attempt completes. The
          // whole body has to be weighed and not just the character beside the
          // position — `a+(?<!.a)` and `a+(?<![ab]a)` can be spelled from the
          // run as well, and both walk the subject again from every start.
          // Where both the assertion and the run are fixed shapes, they are
          // read against each other position by position, nearest the endpoint
          // first. That is what distinguishes `(?:ab)+(?<!ab)`, which matches at
          // every endpoint and is quadratic, from `(?:ab)+(?<!bb)`, which needs
          // a `b` where the run always leaves an `a` and so can never match at
          // one — although both are spelled entirely out of characters the run
          // eats, which is all a set-membership test can see.
          var behindSeq = [];
          if (_flatSets(_reversedForLookbehind(body), behindSeq, MAX_BEHIND_POSITIONS) &&
              behindSeq.length > 0) {
            var runPositions = _positionsBehindRun(terms[from].node, behindSeq.length);
            if (runPositions !== null) {
              var canMatchThere = true;
              for (var k = 0; k < behindSeq.length; k += 1) {
                if (!_setsIntersect(behindSeq[k], runPositions[k])) canMatchThere = false;
              }
              if (!canMatchThere) continue;                  // holds where the run stops
              // The run also hands characters back, down to its shortest, and
              // reaching past THAT the assertion meets the character in front of
              // the run — which the run demonstrably did not eat, or it would
              // have started there. An assertion needing a run character in that
              // position can never match at the short endpoint, so it holds and
              // the search ends after one walk: `a+(?<!aa)` settles on the single
              // character the run owes and `(?:ab)+(?<!abab)` on its one
              // repetition, while `a+(?<!.a)` asks for anything at all there and
              // gets it. Only where nothing stands in front of the run and the
              // assertion follows it immediately — the `(?!a)` in
              // `a*(?!a)(?<!a)` refuses the short endpoint and the walk repeats
              // from every position.
              //
              // That argument holds only for a run that eats ONE character at a
              // time, because only such a run would have started one position
              // earlier. `(?:ab)+` advances two at a time and begins at each
              // `a`, so the character in front of it can perfectly well be a `b`
              // it also eats — and `(?:ab)+(?<!bab)` finds exactly that and
              // fails at every repetition.
              if (from === 0 && j === from + 1 &&
                  _minLength(terms[from].node) === 1 && _maxLength(terms[from].node) === 1 &&
                  behindSeq.length > shortestRun &&
                  _setIsSubsetOf(behindSeq[shortestRun], reach)) continue;
            }
          }
          if (!_spellableFrom(body, reach)) continue;
        } else if (later.node.negated) {
          var starts = _firstSet(body);
          if (starts !== null &&
              (_setIsSubsetOf(starts, reach) || !_setsIntersect(reach, starts))) continue;
        } else if (_alwaysSatisfiedBy(body, reach)) continue;
      }
      return true;
    }
    if (later.node.type === "anchor") return true;            // `$` fails on a trailing extra
    if (later.min < 1) continue;                             // optional — never the failure
    // Everything the run can eat would also satisfy this, so wherever the run
    // matched enough characters the suffix is already met and the first
    // attempt succeeds: `a+a` and `\w+\w` are linear. The direction matters —
    // `.*b` has a suffix INSIDE the run's set and is still quadratic, because
    // an input of nothing but non-`b` characters feeds the run and then fails.
    if (_alwaysSatisfiedBy(later.node, reach)) continue;
    return true;
  }
  return false;
}

// A cap on how far back a lookbehind is read position by position. Far above
// any assertion an operator writes; past it the coarser test takes over.
var MAX_BEHIND_POSITIONS = 64;

// The node read backwards as a flat run of single-character sets, appended to
// `out`. Only a fixed shape can be read this way — a plain sequence of
// characters, classes and groups of them. An alternation of more than one
// branch, a variable count, or anything zero-width returns false, and the
// caller falls back to what it can prove from the run's characters alone.
function _flatSets(node, out, limit) {
  if (out.length >= limit) return true;
  if (node.type === "set") { out.push(node.set); return true; }
  if (node.type === "group") return _flatSets(node.body, out, limit);
  if (node.type === "alt") {
    if (node.branches.length !== 1) return false;
    return _flatSets(node.branches[0], out, limit);
  }
  if (node.type !== "seq") return false;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.node.type === "anchor" || t.node.type === "look") return false;
    if (t.min !== t.max) return false;                       // not a fixed shape
    for (var rep = 0; rep < t.min; rep += 1) {
      if (!_flatSets(t.node, out, limit)) return false;
      if (out.length >= limit) return true;
    }
  }
  return true;
}

// The characters standing behind an endpoint of a run, nearest first. A run
// repeats whole copies of its body, so they are the body read backwards over
// and over: `(?:ab)+` leaves a `b`, then an `a`, then a `b`, behind every one of
// its endpoints — which is why `(?<!bb)` can never match at one, however many
// `b`s the run has eaten in total.
function _positionsBehindRun(runNode, count) {
  var reversed = _reversedForLookbehind(runNode);
  var out = [];
  while (out.length < count) {
    var before = out.length;
    if (!_flatSets(reversed, out, count)) return null;
    if (out.length === before) return null;                  // consumes nothing to repeat
  }
  return out;
}

// Can this node be spelled out of characters the run eats? Not whether it MUST
// be — whether it CAN. A negative lookbehind the run's own characters can spell
// refuses at every endpoint of the run, so the attempt walks the run and fails,
// and does it again from every later start. One that needs a character the run
// never eats cannot match where the run stops, so the assertion holds there and
// the first attempt completes.
//
// Asking whether EVERY character of the run satisfies the body is the wrong
// question and answers it backwards: `[ab]+(?<!a)` has a `b` in the run that
// does not satisfy the `a`, and is quadratic all the same, because the run can
// end on an `a`.
function _spellableFrom(node, reach) {
  if (!node) return true;
  if (node.type === "alt") {
    for (var brIndex = 0; brIndex < node.branches.length; brIndex += 1) {
      if (_spellableFrom(node.branches[brIndex], reach)) return true;
    }
    return false;
  }
  if (node.type === "seq") {
    for (var termIndex = 0; termIndex < node.terms.length; termIndex += 1) {
      var term = node.terms[termIndex];
      if (term.min < 1) continue;                            // can be left out entirely
      if (!_spellableFrom(term.node, reach)) return false;
    }
    return true;
  }
  if (node.type === "group") return _spellableFrom(node.body, reach);
  if (node.type === "set") return _setsIntersect(node.set, reach);
  if (node.type === "anchor") {
    // A `^` or `$` INSIDE the assertion pins it to one end of the subject, and
    // the endpoints of a run are neither: `a+(?<!a$)` can only match where the
    // run ends at the end of the input, so one backtrack settles it and the
    // scan stays linear. A word boundary is not so easily placed — `a+(?<!a\B)`
    // holds between two word characters, which is every endpoint inside a run
    // of them, and is quadratic — so it stays unproven.
    return node.edge === "word" || node.edge === "assertion";
  }
  if (node.type === "look") return true;                     // consumes nothing, unproven
  return true;                                               // opaque — never proven away
}

// Every member of `inner` is also a member of `outer`.
function _setIsSubsetOf(inner, outer) {
  if (inner.any) return !!outer.any;
  if (outer.any) return true;
  if (!inner.negated && !outer.negated) {
    var missing = false;
    inner.chars.forEach(function (c) { if (!outer.chars.has(c)) missing = true; });
    return !missing;
  }
  if (inner.negated && outer.negated) {
    // ¬A ⊆ ¬B iff B ⊆ A.
    var uncovered = false;
    outer.chars.forEach(function (c) { if (!inner.chars.has(c)) uncovered = true; });
    return !uncovered;
  }
  if (!inner.negated && outer.negated) {
    var excluded = false;
    inner.chars.forEach(function (c) { if (outer.chars.has(c)) excluded = true; });
    return !excluded;
  }
  return false;                                              // ¬A ⊆ B — never, for any real alphabet
}

// The two ambiguity findings, from one parse of the pattern.
//
// A pattern that fails to parse HERE but compiles as a RegExp is a gap in this
// parser, not a safe pattern, so it is reported rather than waved through — the
// alternative is a construct nobody thought of becoming a way past the guard.
// Input that is not a regex at all (a glob fragment, which this same gate
// screens) has no repetition structure to judge and is left to the detectors
// that do read it.
function _ambiguityFindings(src, flags) {
  var out = { nested: false, alternation: false, lookaround: false, unanchored: false };
  var text = String(src);
  var ast = _parsePattern(text, typeof flags === "string" ? flags : "",
                          { left: ANALYSIS_BUDGET });
  if (ast === null) {
    // Asked WITH the flags it was given, because some syntax exists only under
    // one of them: `[[a-z]--[x]]` is a class under `v` and a syntax error
    // without it. Asking without the flags called such a pattern "not a regex
    // at all" and returned every finding false, so a quadratic pattern using
    // any of that syntax walked straight past this gate.
    var compiles = true;
    try { RegExp(text, typeof flags === "string" ? flags : ""); }
    catch (_e) { compiles = false; }
    if (compiles) {
      out.nested = true;
      out.lookaround = true;
      out.unanchored = true;                                 // unread, so unproven
    }
    return out;
  }
  if (_declinesOnFlags(flags)) {
    // Suppressions are off, so any repetition of something that varies counts.
    _findAmbiguityUnproven(ast, out);
    out.unanchored = _unanchoredScanIsQuadratic(ast, flags);
    return out;
  }
  _findAmbiguity(ast, out);
  out.unanchored = _unanchoredScanIsQuadratic(ast, flags);
  return out;
}

// The same walk with every proof withheld.
function _findAmbiguityUnproven(node, out) {
  if (node === null || typeof node !== "object") return;
  if (node.type === "alt") {
    for (var b = 0; b < node.branches.length; b += 1) _findAmbiguityUnproven(node.branches[b], out);
    return;
  }
  if (node.type === "group") { _findAmbiguityUnproven(node.body, out); return; }
  if (node.type === "look") {
    if (node.body) {
      var innerUnproven = { nested: false, alternation: false, lookaround: false };
      _findAmbiguityUnproven(node.body, innerUnproven);
      if (innerUnproven.nested) out.nested = true;
      if (innerUnproven.alternation) out.alternation = true;
      if (innerUnproven.nested || innerUnproven.alternation) out.lookaround = true;
    }
    return;
  }
  if (node.type !== "seq") return;
  for (var i = 0; i < node.terms.length; i += 1) {
    var term = node.terms[i];
    _findAmbiguityUnproven(term.node, out);
    if (term.max <= 1) continue;
    var body = term.node.type === "group" ? term.node.body : term.node;
    var isAlternation = body.type === "alt" && body.branches.length > 1;
    if (!_isVariableLength(term.node) && !isAlternation) continue;
    if (isAlternation) out.alternation = true;
    else out.nested = true;
  }
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "regex", noun: "regex pattern", cap: { bytes: opts.maxPatternBytes, kind: "pattern-cap", snippet: "regex pattern exceeds maxPatternBytes " + opts.maxPatternBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var ambiguity = (opts.nestedQuantPolicy !== "allow" ||
                   opts.alternationQuantPolicy !== "allow" ||
                   opts.lookaroundQuantPolicy !== "allow" ||
                   opts.unanchoredScanPolicy !== "allow")
    ? _ambiguityFindings(input, opts.regexFlags)
    : { nested: false, alternation: false, lookaround: false, unanchored: false };

  if (opts.nestedQuantPolicy !== "allow" && ambiguity.nested) {
    issues.push({
      kind: "nested-quantifier", severity: "critical",
      ruleId: "regex.nested-quantifier",
      snippet: "pattern contains nested-quantifier shape (e.g. " +
               "`(a+)+` / `((a)+)+`) — canonical ReDoS catastrophic-" +
               "backtracking class (CVE-2024-21538 cross-spawn / CVE-2022-25929)",
    });
  }


  if (opts.alternationQuantPolicy !== "allow" && ambiguity.alternation) {
    issues.push({
      kind: "alternation-quantifier",
      severity: opts.alternationQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.alternation-quantifier",
      snippet: "pattern contains alternation-with-quantifier shape whose " +
               "branches can match at the same position (e.g. `(a|a)*`, " +
               "`(\\d|\\d{2})*`) — the overlap amplifies search paths. " +
               "Branches that cannot start on the same character are " +
               "accepted; give each one a distinct leading character",
    });
  }

  if (opts.unanchoredScanPolicy !== "allow" && ambiguity.unanchored) {
    issues.push({
      kind: "unanchored-scan",
      severity: opts.unanchoredScanPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.unanchored-scan",
      snippet: "pattern is not anchored at the start and can consume an " +
               "unbounded amount before something that must match (e.g. " +
               "`a+b`, `(\\w+)\\s+(\\d+)`) — it is retried at every position " +
               "in the subject and each attempt walks the rest of it, which " +
               "is quadratic in the input; anchor it with `^`, make it " +
               "sticky, or bound the subject length",
    });
  }

  if (opts.lookaroundQuantPolicy !== "allow" && ambiguity.lookaround) {
    issues.push({
      kind: "lookaround-quantifier",
      severity: opts.lookaroundQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.lookaround-quantifier",
      snippet: "pattern contains a repetition inside a lookaround whose parts " +
               "compete for the same input (e.g. `(?=(a|a)+)`) — the engine " +
               "backtracks inside an assertion exactly as it does outside one",
    });
  }

  if (opts.boundedRepeatPolicy !== "allow") {
    for (var bi = 0; bi < input.length; bi += 1) {
      if (input.charAt(bi) !== "{") continue;
      var braces = _scanBraces(input, bi);
      if (braces === null) continue;
      var lower = braces.min;
      var upper = braces.max;
      var written = input.slice(bi, braces.end);
      bi = braces.end - 1;                                 // resume past what was read
      var ceiling = (upper === Infinity || upper > lower) ? upper : lower;
      if (ceiling > opts.maxBoundedRepeat) {
        issues.push({
          kind: "bounded-repeat-cap",
          severity: opts.boundedRepeatPolicy === "reject" ? "high" : "warn",
          ruleId: "regex.bounded-repeat-cap",
          snippet: "bounded-repeat `" + written + "` upper bound " +
                   (ceiling === Infinity ? "unbounded" : ceiling) +
                   " exceeds maxBoundedRepeat " + opts.maxBoundedRepeat,
        });
        break;
      }
    }
  }

  _detectConsecutiveStar(input, opts, issues);
  _detectNestedExtglob(input, opts, issues);

  return issues;
}

// Consecutive-star wildcard cap (CVE-2026-26996). Operator-supplied
// glob fragments compile to minimatch / picomatch / RegExp; a long run
// of `*` against a non-matching literal walks O(4^N). Three-or-more
// consecutive `*` is the canonical bad shape; `**` (recursive glob)
// stays permitted, gated by the profile's `maxConsecutiveStars`.
function _detectConsecutiveStar(input, opts, issues) {
  if (opts.consecutiveStarPolicy === "allow") return;
  // CVE-2026-26996 is a minimatch glob-shape backtracking class —
  // `***+literal` walks O(4^N) when minimatch translates the run to a
  // backtracking-heavy regex. Native ECMAScript regex syntax cannot
  // produce three consecutive `*` quantifiers (it's a SyntaxError),
  // so applying this detector to `inputKind: "regex"` strings only
  // produces false positives on legitimate regex shapes like
  // `a*(b)*` where `*(` is quantifier+group, not extglob.
  if (opts.inputKind !== "glob") return;
  var starRun = 0;
  var starRunMax = 0;
  for (var si = 0; si < input.length; si += 1) {
    if (input.charAt(si) === "*") {
      starRun += 1;
      if (starRun > starRunMax) starRunMax = starRun;
    } else {
      starRun = 0;
    }
  }
  var starCeiling = opts.maxConsecutiveStars === undefined ?
                    2 : opts.maxConsecutiveStars;                                // `**` glob ceiling
  if (starRunMax > starCeiling) {
    issues.push({
      kind: "consecutive-star",
      severity: opts.consecutiveStarPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.consecutive-star",
      snippet: "pattern has " + starRunMax + " consecutive `*` " +
               "wildcards (cap " + starCeiling + ") — O(4^N) " +
               "backtracking on non-matching literal (CVE-2026-26996)",
    });
  }
}

// Nested-extglob detector (CVE-2026-33671). picomatch `*(...)` /
// `+(...)` / `?(...)` / `@(...)` / `!(...)` containing another
// extglob inside compiles to catastrophic-backtracking regex.
function _detectNestedExtglob(input, opts, issues) {
  if (opts.nestedExtglobPolicy === "allow") return;
  // CVE-2026-33671 is picomatch-specific: the extglob heads `*(`/
  // `+(`/`?(`/`@(`/`!(` collide with valid ECMAScript regex shapes
  // (quantifier + capturing group). Restricting this detector to
  // `inputKind: "glob"` avoids false-positive refusal of regex
  // patterns like `a*(b+(c))` where the heads are quantifier
  // groupings, not extglob.
  if (opts.inputKind !== "glob") return;
  // Where each extglob head stands, read straight off the input. Matching for
  // them and then hunting for the offsets of what was matched did the same walk
  // twice, and did the first half of it with a pattern.
  var heads = [];
  for (var hh = 0; hh + 1 < input.length; hh += 1) {
    if (input.charAt(hh + 1) !== "(") continue;
    if (EXTGLOB_HEADS.indexOf(input.charAt(hh)) === -1) continue;
    heads.push(hh);
    if (heads.length > 1024) break;                                              // head-count safety cap
  }
  if (heads.length < 2) return;
  var nested = false;
  for (var hi = 0; hi < heads.length && !nested; hi += 1) {
    var headStart = heads[hi];
    // Walk forward tracking paren depth. Inner head before close = nested.
    var pdepth = 1;
    for (var pj = headStart + 2; pj < input.length && pdepth > 0; pj += 1) {
      var ch = input.charAt(pj);
      if (ch === "(") {
        pdepth += 1;
        if (pj > 0) {
          var preVerb = input.charAt(pj - 1);
          if (preVerb === "*" || preVerb === "+" || preVerb === "?" ||
              preVerb === "@" || preVerb === "!") {
            nested = true;
            break;
          }
        }
      } else if (ch === ")") {
        pdepth -= 1;
      }
    }
  }
  if (nested) {
    issues.push({
      kind: "nested-extglob",
      severity: opts.nestedExtglobPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.nested-extglob",
      snippet: "pattern contains nested extglob quantifier " +
               "(`*(...*(...))`) — catastrophic backtracking class " +
               "(CVE-2026-33671 picomatch)",
    });
  }
}

/**
 * @primitive  b.guardRegex.validate
 * @signature  b.guardRegex.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.gate, b.guardRegex.sanitize
 *
 * Inspect a user-supplied regex pattern string and return an
 * aggregated issue list. Pure inspection — never throws on hostile
 * patterns; caller decides what to do with the issues. The `ok`
 * flag is `true` only when zero `critical` / `high` issues fire.
 * Throws `GuardRegexError("regex.bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"audit"|"allow",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *   maxBytes:               number,
 *   maxRuntimeMs:           number,
 *
 * @example
 *   var clean = b.guardRegex.validate("^[a-z]+$", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardRegex.validate("(a+)+b", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "nested-quantifier"; });  // → true
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues), with the positive-finite-int caps declared via `intOpts`.
// The @primitive block above documents the resulting ABI.

/**
 * @primitive  b.guardRegex.sanitize
 * @signature  b.guardRegex.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.gate
 *
 * Pass-through-or-throw. Regex patterns cannot be safely repaired
 * (stripping a `+` from a quantifier silently changes match
 * semantics); this primitive returns the input unchanged when no
 * `critical` or `high` issue fires, otherwise throws
 * `GuardRegexError` with the offending rule id (e.g.
 * `regex.nested-quantifier`, `regex.lookaround-quantifier`,
 * `regex.bounded-repeat-cap`). Operators that need a "best-effort
 * cleanup" semantic should reject the input at the boundary
 * instead.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var safe = b.guardRegex.sanitize("^[a-z]+$", { profile: "strict" });
 *   safe;                                              // → "^[a-z]+$"
 *
 *   try {
 *     b.guardRegex.sanitize("(a+)+b", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "regex.nested-quantifier"
 *   }
 */
// _sanitizeTransform — the normalize tail applied by defineGuard's generated
// sanitize AFTER resolve -> detect -> throwOnRefusalSeverity. Regex patterns
// cannot be safely repaired, so the transform is a pass-through: a non-string
// or any critical/high finding refuses upstream, clean input returns verbatim.
function _sanitizeTransform(input) {
  return input;
}

/**
 * @primitive  b.guardRegex.gate
 * @signature  b.guardRegex.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.sanitize
 *
 * Build a `b.gateContract` gate that screens `ctx.identifier` (or
 * `ctx.pattern`) before any compilation step. Action chain:
 * `serve` (no issues) → `audit-only` (warn-only) → `refuse` (any
 * `critical` or `high`). No `sanitize` action — pattern strings
 * cannot be repaired. Compose into framework parsers / form
 * validators / route matchers so operator-fed patterns hit the
 * guard before reaching `new RegExp()`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:                   string,    // override gate name in audit emissions
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var gate = b.guardRegex.gate({ profile: "strict" });
 *
 *   gate.check({ identifier: "(a+)+b" }).then(function (rv) {
 *     rv.ok;                                           // → false
 *     rv.action;                                       // → "refuse"
 *   });
 *
 *   gate.check({ identifier: "^[a-z]+$" }).then(function (rv) {
 *     rv.action;                                       // → "serve"
 *   });
 */
function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardRegex:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var pattern = ctx && (ctx.identifier || ctx.pattern);
      if (pattern === undefined || pattern === null) {
        return { ok: true, action: "serve" };
      }
      var rv = module.exports.validate(pattern, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("^[a-z]+$", "(a+)+b");

/**
 * @primitive  b.guardRegex.assertSafe
 * @signature  b.guardRegex.assertSafe(input, label?, ErrorClass?, code?, opts?)
 * @since      0.15.39
 * @status     stable
 * @related    b.guardRegex.sanitize, b.guardRegex.validate, b.regexLinear.compile
 *
 * Screen an already-compiled <code>RegExp</code> (or a raw pattern string) for
 * catastrophic-backtracking (ReDoS) shapes, throwing if the pattern is unsafe.
 *
 * Screening asks whether a pattern LOOKS dangerous, which is a different
 * question from running it safely. If what you need is to match an operator's
 * pattern against request data, <code>b.regexLinear.compile</code> runs it in
 * time proportional to the subject whatever the pattern is, and needs no
 * screening at all — no shape it accepts can be made to backtrack. Screening is
 * for the cases where the platform engine must do the matching: a pattern handed
 * to a library, to <code>String.prototype.replace</code>, or to anything else
 * that takes a <code>RegExp</code>. The two are complements, and the runner
 * names the constructs it cannot take (backreferences, lookaround) so the choice
 * between them is visible rather than implied.
 * This is the config-time guard for request-lifecycle code that matches an
 * operator-supplied regex against attacker-controlled input (User-Agent,
 * Origin, request path, form field, HELO) — an accidentally-catastrophic
 * operator pattern would otherwise be a per-request DoS once a hostile input
 * triggers the backtracking.
 *
 * Pass a <code>RegExp</code> instance (its <code>.source</code> is screened) or
 * a pattern string. On a hostile shape it throws <code>ErrorClass(code, ...)</code>
 * when an error class is supplied, otherwise the underlying
 * <code>GuardRegexError</code>. Returns the input unchanged on success.
 *
 * By default it rejects the catastrophic-backtracking classes — nested,
 * alternation-with, and lookaround quantifiers — but ALLOWS large/open bounded
 * repeats (<code>{8,}</code>, <code>{n,m}</code>): a single counted repeat is
 * linear, not exponential, and legitimate patterns (e.g. a hex hash of 8+
 * digits) use them. Pass an explicit <code>opts</code> to override.
 *
 * <b>What it can and cannot tell you.</b> Two costs decide what a match against
 * hostile input is worth, and the analysis reaches both, but by different
 * means and with different confidence.
 *
 * The first is what one match attempt costs — whether a repetition's parts
 * compete for the same characters, so the engine explores many ways to divide
 * the input between them. That is the backtracking analysis, and it is
 * conservative by construction: a pattern it cannot characterise is refused
 * rather than waved through. It is not a decision procedure, though. It proves
 * unambiguity for the shapes it knows and refuses the rest, so a pattern that
 * is in fact linear can still be turned away — the refusal names the shape, and
 * rewriting to a form it can prove (a distinct leading character per branch, a
 * separator no other part matches) is usually a small edit.
 *
 * The second is how many attempts there are. An unanchored pattern is retried
 * at every position in the subject, and when it can consume an unbounded amount
 * before reaching something that must match, each attempt walks the rest of the
 * input — quadratic overall, with no ambiguity anywhere for the first analysis
 * to find. That is reported separately as <code>regex.unanchored-scan</code>,
 * under <code>unanchoredScanPolicy</code>, so an operator who bounds the subject
 * length instead can turn it off without giving up the backtracking classes.
 * Anchoring the pattern, or compiling it sticky, removes the cost outright.
 *
 * Neither answers the question a running system actually asks, which is how
 * long THIS match will take on THIS input. Screening the pattern removes the
 * shapes whose cost explodes; it does not make an unbounded subject safe. Where
 * the input is attacker-controlled, cap its length as well.
 *
 * @opts
 *   profile:              string,   // guardRegex profile (default: "strict")
 *   boundedRepeatPolicy:  string,   // default: "allow" (large bounded repeats are linear)
 *   unanchoredScanPolicy: string,   // "reject" at strict, "audit" at balanced, "allow" at permissive
 *
 * @example
 *   b.guardRegex.assertSafe(/^[a-z]+$/);            // ok — returns the RegExp
 *   b.guardRegex.assertSafe(/\.[a-f0-9]{8,}\./);    // ok — a single bounded repeat is linear
 *   try { b.guardRegex.assertSafe(/((a)+)+$/); }    // throws — nested quantifier
 *   catch (e) { e.code; }                           // → "regex/unsafe-pattern"
 */
function assertSafe(input, label, ErrorClass, code, opts) {
  var source = (input instanceof RegExp) ? input.source : input;
  // The flags decide what the source means. Screening `.source` alone reads
  // `(a|A)+` as two disjoint branches when under `i` the engine sees one
  // branch twice — the exact overlap the alternation rule exists to catch. A
  // RegExp carries its flags, so they travel with it; a caller screening a
  // raw string that they will later compile case-insensitively passes
  // `regexFlags` themselves.
  if (input instanceof RegExp && (!opts || opts.regexFlags === undefined)) {
    opts = Object.assign({ profile: "strict", boundedRepeatPolicy: "allow" },
                         opts || {}, { regexFlags: input.flags });
  }
  try {
    // Screen the catastrophic-backtracking classes (nested / alternation /
    // lookaround quantifiers — held at every profile) but allow large bounded
    // repeats: a counted repeat matches in linear time, and rejecting `{n,}`
    // would refuse legitimate operator patterns (and the framework's own
    // defaults, e.g. b.staticServe.DEFAULT_HASHED_PATTERN's `{8,}`).
    _guard.sanitize(source, opts || { profile: "strict", boundedRepeatPolicy: "allow" });
  } catch (e) {
    if (ErrorClass) {
      throw new ErrorClass(code || "regex/unsafe-pattern",
        (label || "regex") + ": pattern rejected as unsafe (ReDoS shape) - " + (e && e.message));
    }
    throw e;
  }
  return input;
}

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize / gate). The bespoke `gate` carries
// guardRegex's ctx.identifier || ctx.pattern dispatch unchanged.
var _guard = module.exports = gateContract.defineGuard({
  name:        "regex",
  kind:        "identifier",
  errorClass:  GuardRegexError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes", "maxPatternBytes", "maxBoundedRepeat", "maxConsecutiveStars"],
  gate:        gate,
});

_guard.assertSafe = assertSafe;
