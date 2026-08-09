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

// Bounded repetition — captures the upper bound when present.
var BOUNDED_REPEAT_RE = /\{(\d+)(?:,(\d*))?\}/g;

// Nested extglob detector — picomatch `*(...)` / `+(...)` / `?(...)` /
// `@(...)` / `!(...)` containing another extglob inside (CVE-2026-33671
// nested-extglob catastrophic-backtracking class). Two extglob heads in
// the same pattern with no closing paren between them indicates nesting.
// The consecutive-star detector (CVE-2026-26996) walks the input by
// char so doesn't need a regex literal.
var EXTGLOB_HEAD_RE = /[*+?@!]\(/g;                                                  // allow:regex-no-length-cap — input bounded by maxPatternBytes

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "reject",
    boundedRepeatPolicy:       "reject",
    lookaroundQuantPolicy:     "reject",
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
  if (/[0-9kpPbBuxc]/.test(ch)) return null;          // backref / property / assertion / code escape
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
// A modifier group that turns case-insensitivity ON somewhere in the pattern.
var ENABLES_FOLD_RE = /\(\?[dgmsuvy]*i[dgimsuvy]*(?:-[dgimsuvy]+)?:/;

var MAX_PARSE_DEPTH = 200;

function _parsePattern(src, flags, budget) {
  var pos = 0;
  // Folding can be switched on INSIDE the pattern, so the map cannot be
  // decided from the outer flags alone: `(?i:...)` in a pattern carrying no
  // `i` still needs the engine-derived equivalences for its body.
  var foldsAnywhere = flags.indexOf("i") !== -1 || ENABLES_FOLD_RE.test(src);   // allow:regex-no-length-cap — input bounded by maxPatternBytes
  var foldGroups = !foldsAnywhere ? new Map()
    : _engineFoldGroups(src, flags.indexOf("i") === -1 ? flags + "i" : flags);

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
      var m = /^\{(\d+)(?:,(\d*))?\}/.exec(src.slice(pos));                     // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
      if (m === null) return { min: 1, max: 1 };                                 // a literal `{`
      min = parseInt(m[1], 10);                                                  // base-10 radix
      max = m[2] === undefined ? min : (m[2] === "" ? Infinity : parseInt(m[2], 10));  // base-10 radix
      if (max < min) return null;                                                // `{5,2}` — not a pattern this reads
      pos += m[0].length;
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
      if (esc === "b" || esc === "B") return { type: "anchor", edge: "word", flags: activeFlags };
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
      var rest = src.slice(pos);                                                 // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
      var look = /^\?(?:<=|<!|=|!)/.exec(rest.slice(0, 3));
      if (look) {
        // The body is parsed and kept. A lookaround consumes nothing, so it
        // never takes characters from what follows — but the engine still
        // backtracks INSIDE it, so a catastrophic repetition placed there is
        // catastrophic. Skipping to the closing paren left it unexamined, and
        // the quantifier-in-lookaround rule that was meant to cover it reads
        // the source and cannot see through nested parentheses.
        pos += look[0].length;
        var lookBody = parseAlt(depth + 1, innerFlags);
        if (lookBody === null) return fail();
        if (src.charAt(pos) !== ")") return fail();
        pos += 1;
        return { type: "look", body: lookBody, flags: activeFlags };
      }
      var named = /^\?<[A-Za-z_$][A-Za-z0-9_$]*>/.exec(rest);                    // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
      if (named) pos += named[0].length;
      else {
        var mod = /^\?([dgimsuvy]*)(?:-([dgimsuvy]+))?:/.exec(rest);             // allow:regex-no-length-cap — bounded slice of a maxPatternBytes-capped input
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
        for (f = 0; mod[1] && f < mod[1].length; f += 1) {
          innerFlags = _withFlag(innerFlags, mod[1].charAt(f), true);
        }
        for (f = 0; mod[2] && f < mod[2].length; f += 1) {
          innerFlags = _withFlag(innerFlags, mod[2].charAt(f), false);
        }
        pos += mod[0].length;
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
// proven disjoint. Closing the class from a table of the awkward characters
// only holds until Unicode adds one, so the engine is asked instead — it is
// the authority on its own equivalence, and it cannot fall out of date.
//
// Only characters PRESENT in the pattern can create an overlap between two of
// its sets, so the question is asked over that alphabet alone. Pairs whose
// lower/upper forms already link them are skipped; that leaves the handful of
// characters where the answer is not obvious.
var MAX_FOLD_ALPHABET = 64;

function _engineFoldGroups(src, flags) {
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
      var equal;
      // The source is one \uXXXX escape this function wrote for a single
      // character, plus the pattern own already-validated flags; no operator
      // text reaches it.
      // allow:dynamic-regex
      try { equal = new RegExp("^" + _escapeLiteral(x) + "$", flags).test(y); }
      catch (_e) { return null; }                           // cannot ask — prove nothing
      if (!equal) continue;
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

// A delimiter pins where each repetition ENDS. The paths through the whole
// match are the PRODUCT of the paths through each repetition, so a body with
// two parts that can trade characters has two parses per repetition and the
// delimiter buys nothing: `(?:a}?}?)+` and `(?:a*a*-)*` are exponential.
function _atMostOneVaryingPart(terms, edge) {
  var varying = 0;
  for (var i = 0; i < terms.length; i += 1) {
    if (terms[i] === edge) continue;
    if (terms[i].min !== terms[i].max || _isVariableLength(terms[i].node)) varying += 1;
  }
  return varying <= 1;
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
    if (node.branches.length > 1 && !_branchesDecideThemselves(node)) return true;
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
    for (var k = idx + 1; k < seq.terms.length && pinned; k += 1) {
      // A null head means the term can match nothing, so it can begin
      // anywhere — that pins nothing and must not read as "no conflict".
      var head = seq.terms[k].node.type === "anchor" ? _mkSet([], false)
               : _firstSet(seq.terms[k].node);
      if (head === null || _setsIntersect(reach, head)) pinned = false;
    }
    if (pinned) continue;
    var delimiter = _splitDelimiter(body);
    if (delimiter === null) return false;
    for (var later = idx + 1; later < seq.terms.length; later += 1) {
      if (_setsIntersect(_allSet(seq.terms[later].node), delimiter)) return false;
    }
  }
  return true;
}

// The characters a repeated body must contain exactly once, when it has such a
// position, or null. The delimiter may sit at either end — a separator leading
// each repetition pins the split exactly as one trailing it does — and it is a
// SET rather than a character, because under `i` a one-character delimiter
// covers both of its cases and a term that can match either of them can take
// it.
function _splitDelimiter(body) {
  if (body.type !== "alt" || body.branches.length !== 1) return null;
  var terms = body.branches[0].terms;
  if (terms.length < 2) return null;
  var ends = [terms[terms.length - 1], terms[0]];
  for (var e = 0; e < ends.length; e += 1) {
    var edge = ends[e];
    if (edge.min !== 1 || edge.max !== 1) continue;                // must occur exactly once
    if (edge.node.type !== "set" || edge.node.set.any) continue;
    if (edge.node.set.negated || edge.node.set.chars.size === 0) continue;
    var mark = edge.node.set;
    var reachable = false;
    for (var i = 0; i < terms.length && !reachable; i += 1) {
      if (terms[i] === edge) continue;
      if (_setsIntersect(_allSet(terms[i].node), mark)) reachable = true;
    }
    if (!reachable && _atMostOneVaryingPart(terms, edge)) return mark;
  }
  return null;
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

// The two ambiguity findings, from one parse of the pattern.
//
// A pattern that fails to parse HERE but compiles as a RegExp is a gap in this
// parser, not a safe pattern, so it is reported rather than waved through — the
// alternative is a construct nobody thought of becoming a way past the guard.
// Input that is not a regex at all (a glob fragment, which this same gate
// screens) has no repetition structure to judge and is left to the detectors
// that do read it.
function _ambiguityFindings(src, flags) {
  var out = { nested: false, alternation: false, lookaround: false };
  var text = String(src);
  var ast = _parsePattern(text, typeof flags === "string" ? flags : "",
                          { left: ANALYSIS_BUDGET });
  if (ast === null) {
    var compiles = true;
    try { RegExp(text); } catch (_e) { compiles = false; }
    if (compiles) { out.nested = true; out.lookaround = true; }
    return out;
  }
  if (_declinesOnFlags(flags)) {
    // Suppressions are off, so any repetition of something that varies counts.
    _findAmbiguityUnproven(ast, out);
    return out;
  }
  _findAmbiguity(ast, out);
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
                   opts.lookaroundQuantPolicy !== "allow")
    ? _ambiguityFindings(input, opts.regexFlags)
    : { nested: false, alternation: false, lookaround: false };

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
    BOUNDED_REPEAT_RE.lastIndex = 0;
    var match;
    while ((match = BOUNDED_REPEAT_RE.exec(input)) !== null) {                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
      var lower = parseInt(match[1], 10);                                        // base-10 radix
      var upper = match[2] === undefined ? lower :
                  match[2] === "" ? Infinity : parseInt(match[2], 10);           // base-10 radix
      var ceiling = (upper === Infinity || upper > lower) ? upper : lower;
      if (ceiling > opts.maxBoundedRepeat) {
        issues.push({
          kind: "bounded-repeat-cap",
          severity: opts.boundedRepeatPolicy === "reject" ? "high" : "warn",
          ruleId: "regex.bounded-repeat-cap",
          snippet: "bounded-repeat `" + match[0] + "` upper bound " +
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
  // Collect extglob head positions via match() — read-only scan.
  var heads = [];
  var allHeads = input.match(EXTGLOB_HEAD_RE);                                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
  if (allHeads === null || allHeads.length < 2) return;
  // Locate each head index manually (match returns substrings, not idx).
  var scanFrom = 0;
  for (var hh = 0; hh < allHeads.length; hh += 1) {
    var ch0 = allHeads[hh].charAt(0);
    var idx = scanFrom;
    while (idx < input.length - 1) {
      var c0 = input.charAt(idx);
      var c1 = input.charAt(idx + 1);
      if (c1 === "(" && c0 === ch0) break;
      idx += 1;
    }
    heads.push(idx);
    scanFrom = idx + 1;
    if (heads.length > 1024) break;                                              // head-count safety cap
  }
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
 * @related    b.guardRegex.sanitize, b.guardRegex.validate
 *
 * Screen an already-compiled <code>RegExp</code> (or a raw pattern string) for
 * catastrophic-backtracking (ReDoS) shapes, throwing if the pattern is unsafe.
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
 * @opts
 *   profile:             string,   // guardRegex profile (default: "strict")
 *   boundedRepeatPolicy: string,   // default: "allow" (large bounded repeats are linear)
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
