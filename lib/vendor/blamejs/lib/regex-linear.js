// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.regexLinear
 * @nav        Security
 * @title      Linear regex
 * @order      70
 * @slug       regex-linear
 *
 * @intro
 *   Run an operator-supplied pattern in time proportional to the subject,
 *   whatever the pattern is.
 *
 *   The backtracking engine every JavaScript runtime ships explores one path at
 *   a time and reconsiders when a path fails. For most patterns that is quick
 *   and for some it is catastrophic: `(a+)+$` against forty `a`s and a `!`
 *   takes longer than the request that carried it, and the pattern that does it
 *   is a few characters long. Where the pattern comes from an operator's
 *   configuration and the subject from a request, that is a denial of service
 *   with no payload.
 *
 *   Screening the pattern first — `b.guardRegex` — decides whether a pattern
 *   LOOKS dangerous. It is a conservative screen, and conservative screens have
 *   two failure modes: they turn away patterns that were fine, and they cannot
 *   promise to catch every shape that is not.
 *
 *   This runs the pattern instead. It simulates every path at once, one
 *   character of the subject at a time, keeping at most one live position per
 *   instruction. A path that dies costs nothing to abandon because it was never
 *   the only one being followed, and no input makes the work grow faster than
 *   the length of the subject times the size of the pattern. There is nothing
 *   to tune, no budget to exhaust and no shape to special-case.
 *
 *   What it will not do is guess. Backreferences and lookaround cannot be
 *   simulated this way, so a pattern using them is refused by name at compile
 *   time rather than quietly handed to the engine that can be made to hang.
 *
 * @card
 *   Run an operator's regex in time proportional to the subject, whatever the
 *   pattern.
 */

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var frameworkError = require("./framework-error");

var RegexLinearError = frameworkError.defineClass("RegexLinearError", {
  alwaysPermanent: true,
});

var MAX_CODE_POINT = 0x10FFFF;

// A pattern longer than this is refused unread. Operators write patterns; this
// is far above any of them, and a compiled program grows with the source.
var MAX_SOURCE_BYTES = C.BYTES.kib(64);

// Bounded repeats are compiled by copying the body, so the counts an operator
// writes bound the program's size. `{1000000}` is a pattern that would build a
// program larger than the subject it screens.
var MAX_REPEAT_EXPANSION = 4096;

// And a ceiling on the compiled program however the counts are arranged, since
// nesting multiplies them. Far above any pattern an operator writes.
var MAX_PROGRAM_LENGTH = 65536;

// ---- character sets, as exact code-point ranges -----------------------------
//
// A set is a sorted, non-overlapping list of `[lo, hi]` code-point ranges. The
// analysis parser in `b.guardRegex` enumerates class members instead and widens
// to "anything" when a range is too large to enumerate, which is the right
// answer for an over-approximating screen and the wrong one here: an engine
// that matches a widened set matches a different language than the operator
// wrote. So this keeps ranges, and a class spanning the whole code space costs
// one of them rather than a member each.

// Sorted, non-overlapping, and — this is the part that matters — built out of
// PAIRS OF ITS OWN. A class is assembled by concatenating the members' range
// lists, and a positive shorthand contributes the shared `DIGIT` / `WORD` /
// `SPACE` table itself rather than a copy of it. Widening a pair in place to
// absorb a neighbour therefore edited that table for the whole process: after
// one `[\d:]`, every `\d` compiled anywhere in the program matched a colon, and
// the operator's other validators quietly widened with it.
function _norm(ranges) {
  var sorted = ranges.map(function (r) { return [r[0], r[1]]; });
  if (sorted.length < 2) return sorted;
  sorted.sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; });
  var out = [sorted[0]];
  for (var i = 1; i < sorted.length; i += 1) {
    var last = out[out.length - 1];
    var next = sorted[i];
    if (next[0] <= last[1] + 1) {
      if (next[1] > last[1]) last[1] = next[1];
    } else out.push(next);
  }
  return out;
}

// Deep-frozen so that a future write through a shared table fails loudly at the
// line that made it, rather than silently widening a shorthand everywhere.
function _sealed(ranges) {
  ranges.forEach(function (r) { Object.freeze(r); });
  return Object.freeze(ranges);
}

function _one(cp) { return [[cp, cp]]; }

function _union(a, b) { return _norm(a.concat(b)); }

function _negate(ranges) {
  var sorted = _norm(ranges);
  var out = [];
  var at = 0;
  for (var i = 0; i < sorted.length; i += 1) {
    if (sorted[i][0] > at) out.push([at, sorted[i][0] - 1]);
    at = Math.max(at, sorted[i][1] + 1);
  }
  if (at <= MAX_CODE_POINT) out.push([at, MAX_CODE_POINT]);
  return out;
}

// Everything that shares a case with a member of these ranges. A set that is
// COMPLEMENTED under `i` has to be complemented on its case closure rather than
// on itself: under `iu` a Kelvin sign folds to `k`, so it is a word character
// and belongs outside `\W`. Complementing the bare list put it in `\W` as well,
// and then the fold test found `k` there and `[\W]` matched a letter.
//
// Only the shorthand sets are ever complemented, so this walks a hundred or so
// code points; it is not a general-purpose closure over an arbitrary class.
function _caseClosure(ranges, icase, unicode) {
  if (!icase) return ranges;
  var out = ranges.slice();
  for (var i = 0; i < ranges.length; i += 1) {
    for (var cp = ranges[i][0]; cp <= ranges[i][1]; cp += 1) {
      var partners = codepointClass.caseFoldPartners(cp, unicode);
      for (var p = 0; p < partners.length; p += 1) {
        out.push([partners[p], partners[p]]);
      }
    }
  }
  return _norm(out);
}

// Does the pattern declare a named group anywhere in it? Read with an eye to
// where a `(` does NOT open a group: behind a backslash, or inside a class,
// where `(?<` is four ordinary members. A lookbehind head — `(?<=` or `(?<!` —
// names nothing either.
function _declaresNamedGroup(text) {
  var inClass = false;
  for (var i = 0; i < text.length; i += 1) {
    var ch = text.charAt(i);
    if (ch === "\\") { i += 1; continue; }
    if (inClass) { if (ch === "]") inClass = false; continue; }
    if (ch === "[") { inClass = true; continue; }
    if (ch === "(" && text.charAt(i + 1) === "?" && text.charAt(i + 2) === "<" &&
        text.charAt(i + 3) !== "=" && text.charAt(i + 3) !== "!") {
      return true;
    }
  }
  return false;
}

function _has(ranges, cp) {
  var lo = 0;
  var hi = ranges.length - 1;
  while (lo <= hi) {
    var mid = (lo + hi) >> 1;
    if (cp < ranges[mid][0]) hi = mid - 1;
    else if (cp > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

var DIGIT = _sealed([[0x30, 0x39]]);
var WORD = _sealed([[0x30, 0x39], [0x41, 0x5A], [0x5F, 0x5F], [0x61, 0x7A]]);
var SPACE = _sealed(_norm([
  [0x09, 0x0D], [0x20, 0x20], [0xA0, 0xA0], [0x1680, 0x1680], [0x2000, 0x200A],
  [0x2028, 0x2029], [0x202F, 0x202F], [0x205F, 0x205F], [0x3000, 0x3000],
  [0xFEFF, 0xFEFF],
]));
var LINE_TERMINATORS = _sealed([[0x0A, 0x0A], [0x0D, 0x0D], [0x2028, 0x2029]]);

var CONTROL_ESCAPES = {
  n: 0x0A, r: 0x0D, t: 0x09, f: 0x0C, v: 0x0B, 0: 0x00,
};

// ---- parsing ----------------------------------------------------------------
//
// Its own parser, for the reason above: this one has to be exact where the
// screen's may approximate, and it has to refuse rather than widen.

function _fail(message, code) {
  throw new RegexLinearError(code, "regexLinear.compile: " + message);
}

// Scanning helpers, spelled out. A pattern is read one character code at a
// time — not matched against patterns of its own, and never by slicing the
// source at every position, which would cost more than reading it.

function _isDigit(code) { return code >= 0x30 && code <= 0x39; }

function _hexDigit(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  return -1;
}

// `min`..`max` hex digits from `at`, or null.
function _readHex(src, at, min, max) {
  var value = 0;
  var count = 0;
  while (count < max && at + count < src.length) {
    var digit = _hexDigit(src.charCodeAt(at + count));
    if (digit < 0) break;
    value = value * 16 + digit;
    count += 1;
  }
  if (count < min) return null;
  return { value: value, end: at + count };
}

// A repetition count. Anything with more digits than a real count could have is
// answered as one past what the compiler will expand, so it is refused there
// with the message about program size rather than silently becoming Infinity.
function _readCount(src, from, to) {
  if (to - from > 9) return MAX_REPEAT_EXPANSION + 1;
  var value = 0;
  for (var at = from; at < to; at += 1) value = value * 10 + (src.charCodeAt(at) - 0x30);
  return value;
}

// The characters a capture name is SPELLED WITH, with the identifier escapes
// the language allows resolved: a name written as an escape for the letter `a`
// is the name `a`, and `groups` carries it under that key. Returns null where
// the spelling is not one the language would read, so the caller can refuse it
// by the same route as any other bad name.
function _decodeCaptureName(spelling) {
  var out = "";
  var i = 0;
  while (i < spelling.length) {
    var ch = spelling.charAt(i);
    if (ch !== "\\") { out += ch; i += 1; continue; }
    if (spelling.charAt(i + 1) !== "u") return null;      // only `\u` names a character
    if (spelling.charAt(i + 2) === "{") {
      var braced = _readHex(spelling, i + 3, 1, 6);
      if (braced === null || spelling.charAt(braced.end) !== "}") return null;
      if (braced.value > MAX_CODE_POINT) return null;
      out += String.fromCodePoint(braced.value);
      i = braced.end + 1;
      continue;
    }
    var four = _readHex(spelling, i + 2, 4, 4);
    if (four === null) return null;
    out += String.fromCharCode(four.value);
    i = four.end;
  }
  return out;
}

// A capture name is an identifier: it does not start with a digit and carries
// no punctuation. `(?<1>a)` and `(?<->a)` are patterns the platform refuses, so
// they are refused here rather than quietly given a meaning of their own.
function _isCaptureName(name) {
  if (name.length === 0) return false;
  for (var i = 0; i < name.length; i += 1) {
    var code = name.charCodeAt(i);
    var isLetter = (code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A);
    var isDigit = code >= 0x30 && code <= 0x39;
    var isNameSign = code === 0x24 || code === 0x5F;              // `$` and `_`
    // Deliberately ASCII. Which characters beyond it may start or continue an
    // identifier is a Unicode property, and admitting everything above ASCII
    // would take names the platform refuses — `(?<{co}py>a)` is not a name. A
    // name outside ASCII is refused with a message saying so, rather than given
    // a meaning here that `RegExp` would not give it.
    if (isLetter || isNameSign) continue;
    if (isDigit && i > 0) continue;
    return false;
  }
  return true;
}

// The same rules `RegExp` applies: known letters, each at most once, and never
// both Unicode modes. A flag string this refuses is one the platform refuses.
function _badFlags(flags) {
  var seen = "";
  for (var i = 0; i < flags.length; i += 1) {
    var ch = flags.charAt(i);
    if ("dgimsuvy".indexOf(ch) === -1) return "unknown flag " + JSON.stringify(ch);
    if (seen.indexOf(ch) !== -1) return "repeated flag " + JSON.stringify(ch);
    seen += ch;
  }
  if (seen.indexOf("u") !== -1 && seen.indexOf("v") !== -1) {
    return "the u and v flags cannot both be set";
  }
  return null;
}

function _parse(src, flags) {
  var pos = 0;
  var captureCount = 0;
  // Without a prototype, because a group may legitimately be named
  // `__proto__` and assigning that to an ordinary object sets the prototype
  // instead of recording the name.
  var names = Object.create(null);
  var unicode = flags.indexOf("u") !== -1 || flags.indexOf("v") !== -1;
  var icase = flags.indexOf("i") !== -1;
  // Answered once, from the whole source, because it is a property of the
  // pattern rather than of the position being read. Asked at each `\k` instead,
  // a source carrying many of them would be re-scanned once per escape, and a
  // matcher that promises linear MATCHING would have taken time quadratic in
  // the pattern to compile.
  var namesAGroup = _declaresNamedGroup(src);

  function peek() { return src.charAt(pos); }
  function eat(ch) { if (src.charAt(pos) === ch) { pos += 1; return true; } return false; }

  function parseAlt() {
    var branches = [parseSeq()];
    while (eat("|")) branches.push(parseSeq());
    return { t: "alt", bs: branches };
  }

  function parseSeq() {
    var terms = [];
    for (;;) {
      var ch = peek();
      if (ch === "" || ch === "|" || ch === ")") break;
      var capLo = captureCount;
      var atom = parseAtom();                             // refuses rather than returning nothing
      var capHi = captureCount;
      var quant = parseQuantifier();
      if (quant.min > quant.max) {
        _fail("numbers out of order in {} quantifier", "regex/bad-quantifier");
      }
      // Nothing repeats an assertion. `^{1}a` and `\b{0}a` are syntax errors in
      // JavaScript, and reading them as "the assertion, once" or "the assertion,
      // never" would give an invalid pattern a meaning of its own — the second
      // one silently dropping the boundary the operator asked for.
      if (quant.present && (atom.t === "bol" || atom.t === "eol" ||
                            atom.t === "wb" || atom.t === "nwb")) {
        _fail("nothing to repeat — a quantifier cannot be applied to an assertion",
              "regex/bad-quantifier");
      }
      terms.push({
        n: atom, min: quant.min, max: quant.max, lazy: quant.lazy,
        capLo: capLo, capHi: capHi,
      });
    }
    return { t: "seq", xs: terms };
  }

  // `present` says whether a quantifier was WRITTEN, which is not the same as
  // whether it changes anything: `^{1}` is a syntax error even though repeating
  // once would have meant nothing.
  function parseQuantifier() {
    var plain = { min: 1, max: 1, lazy: false, present: false };
    var ch = peek();
    var min, max;
    if (ch === "*") { pos += 1; min = 0; max = Infinity; }
    else if (ch === "+") { pos += 1; min = 1; max = Infinity; }
    else if (ch === "?") { pos += 1; min = 0; max = 1; }
    else if (ch === "{") {
      var scanned = scanBraceQuantifier(pos);
      if (scanned === null) return plain;                 // a literal `{`
      pos = scanned.end;
      min = scanned.min;
      max = scanned.max;
    } else return plain;
    var lazy = eat("?");
    // `a++` is a syntax error in JavaScript. Swallowing it as a possessive
    // quantifier would accept a pattern the platform refuses, and quietly.
    if (!lazy && peek() === "+") _fail("nothing to repeat", "regex/bad-quantifier");
    return { min: min, max: max, lazy: lazy, present: true };
  }

  // `{n}` / `{n,}` / `{n,m}`, read one character at a time.
  function scanBraceQuantifier(from) {
    var at = from + 1;                                    // past the `{`
    var loStart = at;
    while (at < src.length && _isDigit(src.charCodeAt(at))) at += 1;
    if (at === loStart) return null;
    var lo = _readCount(src, loStart, at);
    var hi = lo;
    if (src.charAt(at) === ",") {
      at += 1;
      var hiStart = at;
      while (at < src.length && _isDigit(src.charCodeAt(at))) at += 1;
      hi = at === hiStart ? Infinity : _readCount(src, hiStart, at);
    }
    if (src.charAt(at) !== "}") return null;
    return { min: lo, max: hi, end: at + 1 };
  }

  function parseAtom() {
    var ch = peek();
    if (ch === "(") return parseGroup();
    if (ch === "[") return parseClass();
    if (ch === "^") { pos += 1; return { t: "bol" }; }
    if (ch === "$") { pos += 1; return { t: "eol" }; }
    if (ch === ".") {
      pos += 1;
      return flags.indexOf("s") !== -1
        ? { t: "set", r: [[0, MAX_CODE_POINT]], neg: false }
        : { t: "set", r: LINE_TERMINATORS, neg: true };
    }
    if (ch === "\\") return parseEscape();
    if (ch === "*" || ch === "+" || ch === "?") {
      _fail("nothing to repeat", "regex/bad-quantifier");
    }
    // A COMPLETE `{n}` / `{n,}` / `{n,m}` standing where an atom belongs is a
    // syntax error rather than literal text — `{1}` and `a{0}{1}` are both
    // refused by the platform. Reading them as the characters they are spelled
    // with would give a pattern nobody can run a private meaning here. An
    // incomplete brace — `{1`, `{a}` — really is literal, and stays so.
    if (ch === "{" && scanBraceQuantifier(pos) !== null) {
      _fail("nothing to repeat", "regex/bad-quantifier");
    }
    refuseLoneSyntaxChar(ch);
    pos += 1;
    if (unicode) {
      var cp = src.codePointAt(pos - 1);
      if (cp > 0xFFFF) pos += 1;
      return { t: "set", r: _one(cp), neg: false };
    }
    return { t: "set", r: _one(ch.charCodeAt(0)), neg: false };
  }

  // Under `u` a bare `{`, `}` or `]` outside a class is a syntax error rather
  // than a literal. Reading them as literals would take a pattern the platform
  // refuses and give it a meaning of its own.
  function refuseLoneSyntaxChar(ch) {
    if (!unicode) return;
    if (ch === "{" || ch === "}" || ch === "]") {
      _fail("lone " + JSON.stringify(ch) + " is a syntax error under the u flag — " +
            "escape it as \\" + ch, "regex/bad-escape");
    }
  }

  function parseGroup() {
    pos += 1;                                             // the `(`
    var capture = null;
    var name = null;
    if (peek() === "?") {
      var rest = src.slice(pos, pos + 3);
      if (rest.charAt(1) === "=" || rest.charAt(1) === "!" ||
          (rest.charAt(1) === "<" && (rest.charAt(2) === "=" || rest.charAt(2) === "!"))) {
        _fail("lookaround cannot be run in linear time — screen it with " +
              "b.guardRegex.assertSafe and run it with the platform engine, or " +
              "rewrite the pattern without it", "regex/unsupported-lookaround");
      }
      if (rest.charAt(1) === "<") {                       // named group
        pos += 2;
        var end = src.indexOf(">", pos);
        if (end === -1) _fail("invalid capture group name", "regex/bad-group");
        var spelling = src.slice(pos, end);
        // A name may spell its characters with the identifier escapes the
        // language allows, so it is decoded before it is judged: a group whose
        // name is written as an escape for the letter `a` IS named `a`. Reading
        // the source spelling refused a name the platform accepts, and would
        // have recorded the escape itself as the key in `groups`.
        name = _decodeCaptureName(spelling);
        if (name === null || !_isCaptureName(name)) {
          _fail("capture group name " + JSON.stringify(spelling) + " — a name here is " +
                "ASCII letters, digits, `$` and `_`, not starting with a digit. " +
                "Which characters beyond ASCII may name a group is a Unicode " +
                "property this does not carry, so such a name is refused rather " +
                "than given a meaning the platform would not give it",
                "regex/bad-group");
        }
        pos = end + 1;
        captureCount += 1;
        capture = captureCount;
        if (Object.prototype.hasOwnProperty.call(names, name)) {
          _fail("duplicate capture group name " + JSON.stringify(name), "regex/bad-group");
        }
        names[name] = capture;
      } else if (rest.charAt(1) === ":") {
        pos += 2;
      } else {
        _fail("unsupported group " + JSON.stringify(src.slice(pos - 1, pos + 3)),
              "regex/unsupported-group");
      }
    } else {
      captureCount += 1;
      capture = captureCount;
    }
    var body = parseAlt();
    if (!eat(")")) _fail("unterminated group", "regex/bad-group");
    return { t: "grp", b: body, cap: capture, name: name };
  }

  // A shorthand outside a class, or a single escaped character.
  function parseEscape() {
    pos += 1;                                             // the backslash
    var ch = peek();
    if (ch === "") _fail("trailing backslash", "regex/bad-escape");
    if (ch === "b") { pos += 1; return { t: "wb" }; }
    if (ch === "B") { pos += 1; return { t: "nwb" }; }
    if (ch >= "1" && ch <= "9") {
      // `\1` is a backreference where a first group exists and a legacy octal
      // escape where none does — a distinction that cannot be made until the
      // whole pattern has been read, and one the operator can make at a glance.
      // A backreference cannot be simulated in linear time, so both are refused
      // and the message names the escape that says what was meant.
      _fail("a digit escape is a backreference, which cannot be run in linear " +
            "time — screen it with b.guardRegex.assertSafe and run it with the " +
            "platform engine, or rewrite it without the backreference. If a " +
            "character was meant, write it as \\xNN or \\uNNNN rather than as a " +
            "legacy octal escape", "regex/unsupported-backreference");
    }
    // `\k` names a group where the pattern declares one and is an identity
    // escape where it declares none — `/\k/` matches a `k`. The group may be
    // written after the `\k` that names it, so the answer comes from the whole
    // pattern rather than from what has been read so far. Under `u` a `\k` that
    // names nothing is a syntax error, which the identity path already reports.
    if (ch === "k" && namesAGroup) {
      _fail("a named backreference cannot be run in linear time — screen it " +
            "with b.guardRegex.assertSafe and run it with the platform engine, " +
            "or rewrite the pattern without it", "regex/unsupported-backreference");
    }
    var shorthand = _shorthand(ch);
    if (shorthand !== null) { pos += 1; return { t: "set", r: shorthand.r, neg: shorthand.neg }; }
    return { t: "set", r: _one(_escapedCodePoint(false)), neg: false };
  }

  function _shorthand(ch) {
    if (ch === "d") return { r: DIGIT, neg: false };
    if (ch === "D") return { r: DIGIT, neg: true };
    if (ch === "w") return { r: WORD, neg: false };
    if (ch === "W") return { r: WORD, neg: true };
    if (ch === "s") return { r: SPACE, neg: false };
    if (ch === "S") return { r: SPACE, neg: true };
    return null;
  }

  // The code point an escape stands for, having consumed it. `inClass` matters
  // because the legacy grammar reads several escapes differently between the two
  // places: `\c1` names a control inside a class and is a literal backslash
  // outside one.
  function _escapedCodePoint(inClass) {
    var ch = src.charAt(pos);
    // Outside Unicode mode a run of octal digits after a backslash is ONE
    // character: `\07` is a bell, not a NUL followed by a seven. Reading only
    // the `\0` left the digit behind as an atom of its own, which compiles
    // happily and matches something else.
    if (ch >= "0" && ch <= "7" && !unicode) {
      var value = 0;
      var digits = 0;
      while (digits < 3 && pos < src.length) {
        var digit = src.charCodeAt(pos) - 0x30;
        if (digit < 0 || digit > 7) break;
        if (value * 8 + digit > 0xFF) break;               // three digits only up to \377
        value = value * 8 + digit;
        pos += 1;
        digits += 1;
      }
      return value;
    }
    if (Object.prototype.hasOwnProperty.call(CONTROL_ESCAPES, ch)) {
      // Under `u`, `\0` stands alone: `\01` and `\08` are invalid decimal
      // escapes, not a NUL beside a digit.
      if (ch === "0" && unicode && _isDigit(src.charCodeAt(pos + 1))) {
        _fail("a digit cannot follow \\0 under the u flag", "regex/bad-escape");
      }
      pos += 1;
      return CONTROL_ESCAPES[ch];
    }
    if (ch === "x") {
      var hex = _readHex(src, pos + 1, 2, 2);
      if (hex !== null) { pos = hex.end; return hex.value; }
      // Without `u`, an `\x` that is not followed by two hex digits is an
      // identity escape rather than an error: `\xZZ` matches an `x` and two
      // `Z`s. It falls through to the identity path below.
      if (unicode) _fail("invalid \\x escape", "regex/bad-escape");
    }
    if (ch === "u") {
      // `\u{...}` is Unicode-mode syntax. Without `u` the platform reads it as
      // a `u` followed by a brace, so accepting it here would match a different
      // language than the same pattern handed to `RegExp`.
      if (src.charAt(pos + 1) === "{" && unicode) {
        var braced = _readHex(src, pos + 2, 1, 6);
        if (braced === null || src.charAt(braced.end) !== "}") {
          _fail("invalid \\u escape", "regex/bad-escape");
        }
        if (braced.value > MAX_CODE_POINT) _fail("invalid \\u escape", "regex/bad-escape");
        pos = braced.end + 1;
        return braced.value;
      }
      var four = _readHex(src, pos + 1, 4, 4);
      if (four === null) {
        // Outside Unicode mode a `\u` that is not followed by four hex digits
        // is just an escaped `u`, and what comes after it is read on its own —
        // `\u{61}` is a `u` repeated. Refusing it would turn away a pattern the
        // platform accepts.
        if (unicode) _fail("invalid \\u escape", "regex/bad-escape");
        pos += 1;
        return 0x75;                                      // the letter `u`
      }
      pos = four.end;
      // Under `u`, a surrogate pair spells ONE character. Left as two halves it
      // would never match a subject that is read a code point at a time.
      if (unicode && four.value >= 0xD800 && four.value <= 0xDBFF &&
          src.charAt(pos) === "\\" && src.charAt(pos + 1) === "u") {
        var low = _readHex(src, pos + 2, 4, 4);
        if (low !== null && low.value >= 0xDC00 && low.value <= 0xDFFF) {
          pos = low.end;
          return (four.value - 0xD800) * 0x400 + (low.value - 0xDC00) + 0x10000;
        }
      }
      return four.value;
    }
    if (ch === "c") {
      var letter = src.charCodeAt(pos + 1);
      var isLetter = (letter >= 0x41 && letter <= 0x5A) || (letter >= 0x61 && letter <= 0x7A);
      // Inside a class and without `u`, a digit or an underscore names a control
      // character as well: `[\c1]` is U+0011 and `[\c_]` is U+001F.
      var isClassControl = !unicode && inClass &&
        ((letter >= 0x30 && letter <= 0x39) || letter === 0x5F);
      if (isLetter || isClassControl) {
        pos += 2;
        return (letter & 0x1F);                           // the control it names
      }
      if (unicode) _fail("invalid \\c escape", "regex/bad-escape");
      // Without `u`, a `\c` that names no control is a LITERAL BACKSLASH and the
      // `c` behind it is read on its own — `/\c1/` matches the three characters
      // `\c1`, and `[\c]` holds a backslash and a `c`. Leaving `pos` on the `c`
      // is what hands it back to the caller as an ordinary character.
      return 0x5C;
    }
    // A property escape is Unicode-mode syntax. Without `u` the platform reads
    // `\p{L}` as a `p`, a brace, an `L` and a brace, so refusing it there turned
    // away a pattern that runs perfectly well.
    if ((ch === "p" || ch === "P") && unicode) {
      _fail("a unicode property escape is not supported — name the characters " +
            "in a class instead", "regex/unsupported-property");
    }
    // An identity escape. Outside Unicode mode the platform lets a backslash
    // stand in front of anything; under `u` only the syntax characters may be
    // escaped, and `\a` is a syntax error. Accepting it here would take a
    // pattern the platform refuses.
    // Inside a class the hyphen joins them, because that is where escaping one
    // means something: `[A-Za-z0-9_\-]` says the hyphen is a member and not the
    // start of a range. Outside a class there is no range to disambiguate and
    // `\-` stays a syntax error under `u`.
    var escapable = unicode && inClass ? "^$\\.*+?()[]{}|/-" : "^$\\.*+?()[]{}|/";
    if (unicode && escapable.indexOf(ch) === -1) {
      _fail("invalid escape \\" + ch + " under the u flag — only a syntax " +
            "character may be escaped there", "regex/bad-escape");
    }
    pos += 1;
    // Outside Unicode mode the subject is read a UTF-16 unit at a time, so an
    // escaped astral character is TWO units and has to compile as two. Taking
    // the whole code point here would build a matcher that never matches it.
    if (!unicode) return src.charCodeAt(pos - 1);
    var cp = src.codePointAt(pos - 1);
    if (cp > 0xFFFF) pos += 1;
    return cp;
  }

  function parseClass() {
    pos += 1;                                             // the `[`
    var negated = eat("^");
    var ranges = [];
    var closed = false;
    while (pos < src.length) {
      if (eat("]")) { closed = true; break; }
      var lo = classMember();
      // A shorthand is a set, not a bound: `[\d-x]` is the digits, a hyphen
      // and an `x`, and treating it as a range start would be a different class.
      if (lo.set !== null) {
        if (peek() === "-" && src.charAt(pos + 1) !== "]" && pos + 1 < src.length) {
          // `[\d-x]` is a syntax error under `u` for the same reason `[a-\d]` is:
          // a shorthand cannot stand at either end of a range.
          if (unicode) {
            _fail("a shorthand cannot be an end of a range under the u flag",
                  "regex/bad-class");
          }
          // Without `u` those are three members — the shorthand, a hyphen, and
          // whatever followed the hyphen — and all three are taken HERE. Left
          // for the next turn of the loop, the tail of `[\d-a-z]` reads as an
          // `a`-to-`z` range and the class matches every letter between them;
          // the platform takes only the `a` and the `z`.
          pos += 1;                                         // the `-`
          var tail = classMember();
          ranges = ranges.concat(lo.set);
          ranges.push([0x2D, 0x2D]);
          if (tail.set !== null) ranges = ranges.concat(tail.set);
          else ranges.push([tail.cp, tail.cp]);
          continue;
        }
        ranges = ranges.concat(lo.set);
        continue;
      }
      if (peek() === "-" && src.charAt(pos + 1) !== "]" && pos + 1 < src.length) {
        pos += 1;
        var hi = classMember();
        if (hi.set !== null) {                            // `[a-\d]` — not a range
          // Outside Unicode mode that is three members: an `a`, a hyphen and
          // the digits. Under `u` it is a syntax error, and reading it as the
          // three would take a pattern the platform refuses.
          if (unicode) {
            _fail("a shorthand cannot be the end of a range under the u flag",
                  "regex/bad-class");
          }
          ranges.push([lo.cp, lo.cp]);
          ranges.push([0x2D, 0x2D]);
          ranges = ranges.concat(hi.set);
          continue;
        }
        if (hi.cp < lo.cp) _fail("range out of order in character class", "regex/bad-class");
        ranges.push([lo.cp, hi.cp]);
        continue;
      }
      ranges.push([lo.cp, lo.cp]);
    }
    if (!closed) _fail("unterminated character class", "regex/bad-class");
    // The `^` is carried rather than applied. Under `i` a class matches when
    // any MEMBER shares a case with the character, and a negated class matches
    // when none does — so the negation has to come after that test, not before
    // it. Pre-negating let `[^abc]` match a `b`, because `B` was in the
    // complement.
    return { t: "set", r: _norm(ranges), neg: negated };
  }

  function classMember() {
    if (peek() === "\\") {
      pos += 1;
      var ch = peek();
      if (ch === "") _fail("trailing backslash", "regex/bad-escape");
      // `\b` is a backspace inside a class, not a boundary.
      if (ch === "b") { pos += 1; return { cp: 0x08, set: null }; }
      // Once a pattern names a group, `\k` stops being an ordinary character
      // ANYWHERE in it — including inside a class, where the grammar has no
      // production for it at all, so `/(?<n>a)[\k]/` is a syntax error. Without
      // a named group the same class holds a `k`.
      if (ch === "k" && namesAGroup) {
        _fail("invalid escape \\k inside a character class — a pattern that " +
              "names a group cannot also use \\k as an ordinary character",
              "regex/bad-escape");
      }
      var shorthand = _shorthand(ch);
      if (shorthand !== null) {
        pos += 1;
        return {
          cp: -1,
          set: shorthand.neg
            ? _negate(_caseClosure(shorthand.r, icase, unicode))
            : shorthand.r,
        };
      }
      return { cp: _escapedCodePoint(true), set: null };
    }
    // Inside a class as outside it: without `u` an astral character is its two
    // surrogate units, and reading the whole code point while advancing one
    // unit records a character the subject never presents.
    if (!unicode) {
      pos += 1;
      return { cp: src.charCodeAt(pos - 1), set: null };
    }
    var cp = src.codePointAt(pos);
    pos += cp > 0xFFFF ? 2 : 1;
    return { cp: cp, set: null };
  }

  var ast = parseAlt();
  if (pos < src.length) {
    _fail("unmatched " + JSON.stringify(src.charAt(pos)), "regex/unbalanced");
  }
  return { ast: ast, captureCount: captureCount, names: names };
}

// ---- compiling to a program -------------------------------------------------
//
// Instructions: `c` consumes a character, `s` splits into two paths in priority
// order, `j` jumps, `v` records a capture boundary, `a` tests a zero-width
// assertion, `m` matches. Nothing in this set can backtrack, because nothing in
// it ever un-does a step.

// Can this match without consuming anything?
function _isNullable(n) {
  if (n.t === "set") return false;
  if (n.t === "bol" || n.t === "eol" || n.t === "wb" || n.t === "nwb") return true;
  if (n.t === "grp") return _isNullable(n.b);
  if (n.t === "alt") {
    for (var b = 0; b < n.bs.length; b += 1) if (_isNullable(n.bs[b])) return true;
    return false;
  }
  for (var i = 0; i < n.xs.length; i += 1) {
    var t = n.xs[i];
    if (t.min > 0 && !_isNullable(t.n)) return false;
  }
  return true;
}

function _compile(ast, captureCount) {
  var prog = [];
  // The whole program, not one quantifier at a time. Counts multiply when they
  // nest — `(a{4096}){4096}` passes any per-term cap and asks for sixteen
  // million instructions — so what is bounded is the total, which is the thing
  // that actually costs memory.
  function emit(instruction) {
    if (prog.length >= MAX_PROGRAM_LENGTH) {
      _fail("the pattern expands to more than " + MAX_PROGRAM_LENGTH + " steps — " +
            "repetition counts multiply where they nest, so a short pattern can " +
            "ask for a very large program", "regex/repeat-too-large");
    }
    prog.push(instruction);
    return prog.length - 1;
  }

  function node(n) {
    if (n.t === "set") { emit({ op: "c", set: { r: n.r, neg: !!n.neg } }); return; }
    if (n.t === "bol" || n.t === "eol" || n.t === "wb" || n.t === "nwb") {
      emit({ op: "a", k: n.t });
      return;
    }
    if (n.t === "grp") {
      if (n.cap !== null) emit({ op: "v", i: n.cap * 2 });
      alt(n.b);
      if (n.cap !== null) emit({ op: "v", i: n.cap * 2 + 1 });
      return;
    }
    if (n.t === "alt") { alt(n); return; }
    if (n.t === "seq") { seq(n); return; }
    _fail("unsupported construct", "regex/unsupported");
  }

  function seq(s) {
    for (var i = 0; i < s.xs.length; i += 1) term(s.xs[i]);
  }

  // One pass through a repeated body. Each pass starts with the groups inside
  // it forgotten: a group that took part in an earlier repetition and not in
  // the last one reads as absent, which is what `(?:(a)|b)+` against "ab" says
  // about its group. Carrying the earlier value forward would report a capture
  // the match did not make.
  function iteration(t) {
    if ((t.min !== 1 || t.max !== 1) && t.capHi > t.capLo) {
      emit({ op: "clr", lo: t.capLo + 1, hi: t.capHi });
    }
    node(t.n);
  }

  function alt(a) {
    if (a.bs.length === 1) { seq(a.bs[0]); return; }
    var jumps = [];
    for (var i = 0; i < a.bs.length; i += 1) {
      if (i === a.bs.length - 1) { seq(a.bs[i]); break; }
      var split = emit({ op: "s", x: 0, y: 0 });
      prog[split].x = prog.length;
      seq(a.bs[i]);
      jumps.push(emit({ op: "j", x: 0 }));
      prog[split].y = prog.length;
    }
    for (var j = 0; j < jumps.length; j += 1) prog[jumps[j]].x = prog.length;
  }

  // A repeat is compiled by writing the body out: `n` mandatory copies, then
  // the optional ones. That is what bounds the program by the counts the
  // operator wrote, and why those counts are capped.
  function term(t) {
    var min = t.min;
    var max = t.max;
    if (max !== Infinity && max - min > MAX_REPEAT_EXPANSION) {
      _fail("a repetition of more than " + MAX_REPEAT_EXPANSION + " is refused — " +
            "the program would be larger than the subject", "regex/repeat-too-large");
    }
    if (min > MAX_REPEAT_EXPANSION) {
      _fail("a repetition of more than " + MAX_REPEAT_EXPANSION + " is refused — " +
            "the program would be larger than the subject", "regex/repeat-too-large");
    }
    // A repetition over a body that can match nothing is refused, and refused
    // rather than approximated. Simulating every path at once is what makes
    // this linear, and it works by keeping ONE live position per instruction —
    // so two paths that reach the same instruction at the same place are the
    // same path from here on. That is true of everything except an empty
    // iteration, where whether the repetition may go round again depends on
    // where its body began rather than on where it is now. Telling those paths
    // apart means keeping a live position per instruction PER STARTING POINT,
    // which is the quadratic behaviour this exists to avoid.
    //
    // Nothing is lost by saying so. `x*` where `x` can match nothing means
    // exactly what `x` means, and the shapes this turns away — `(a*)*`,
    // `(a*b*?)*` — are the ones that hang the platform engine.
    if (max > min && _isNullable(t.n)) {
      _fail("a repetition of something that can match nothing — rewrite the body " +
            "so each repetition must consume, or drop the repetition, which " +
            "means the same thing", "regex/nullable-repetition");
    }
    var i;
    for (i = 0; i < min; i += 1) iteration(t);
    if (max === Infinity) {
      if (min === 0) star(t);
      else plusTail(t);                                   // the copies above were the `min`
      return;
    }
    // Every optional copy skips to the END of the whole construct, not into the
    // next copy. Landing in the next one matches the same language and gets the
    // ORDER wrong — `x{0,3}` would try one `x` before three — and order is what
    // decides which capture an operator sees.
    var skips = [];
    for (i = min; i < max; i += 1) {
      var split = emit({ op: "s", x: 0, y: 0 });
      var body = prog.length;
      iteration(t);
      skips.push(split);
      if (t.lazy) prog[split].y = body; else prog[split].x = body;
    }
    var end = prog.length;
    for (var k = 0; k < skips.length; k += 1) {
      if (t.lazy) prog[skips[k]].x = end; else prog[skips[k]].y = end;
    }
  }

  function star(t) {
    var lazy = t.lazy;
    var split = emit({ op: "s", x: 0, y: 0 });
    var body = prog.length;
    iteration(t);
    emit({ op: "j", x: split });
    var after = prog.length;
    prog[split].x = lazy ? after : body;
    prog[split].y = lazy ? body : after;
  }

  // `x+` after its mandatory copy: loop back over one more, or fall through.
  function plusTail(t) {
    var lazy = t.lazy;
    var back = prog.length;
    var split = emit({ op: "s", x: 0, y: 0 });
    var body = prog.length;
    iteration(t);
    emit({ op: "j", x: back });
    var after = prog.length;
    prog[split].x = lazy ? after : body;
    prog[split].y = lazy ? body : after;
  }

  emit({ op: "v", i: 0 });
  node(ast);
  emit({ op: "v", i: 1 });
  emit({ op: "m" });
  return { prog: prog, slots: (captureCount + 1) * 2 };
}

// ---- running ----------------------------------------------------------------

// A class matches when one of its MEMBERS is the character, or shares a case
// with it. Its `^` is applied to that answer, not to the members: `[^abc]`
// under `i` refuses `B` because `b` is a member, and negating the member list
// first would have said the opposite.
function _matchesSet(set, cp, icase, unicode) {
  var member = _has(set.r, cp);
  if (!member && icase) member = _sharesCase(set.r, cp, unicode);
  return set.neg ? !member : member;
}

// Two characters are the same under `i` when they CANONICALIZE alike, which is
// not the same as one being the other's upper or lower case. The language folds
// through upper case, keeps a character whose upper case is more than one
// character, and — the rule that catches people out — refuses to fold a
// non-ASCII character onto an ASCII one. That last is why `/k/i` does not match
// a Kelvin sign, and why converting both ways and comparing gets it wrong.
//
// Under `u` the rule is different again: characters are folded rather than
// upper-cased, and the ASCII guard does not apply — which is why `/s/iu` DOES
// match a long s, and `/s/i` does not.
function _canonicalize(cp, unicode) {
  return codepointClass.canonicalizeForCase(cp, unicode);
}

// Is some member of these ranges the same character as `cp` under `i`? The
// class is asked for in full rather than guessed at from `cp`'s own upper and
// lower forms: a final sigma is an ordinary sigma, and no amount of casing the
// ordinary one leads to it.
function _sharesCase(ranges, cp, unicode) {
  var partners = codepointClass.caseFoldPartners(cp, unicode);
  for (var i = 0; i < partners.length; i += 1) {
    if (_has(ranges, partners[i])) return true;
  }
  return false;
}

function _run(compiled, subject, startAt, opts) {
  var prog = compiled.prog;
  var slots = compiled.slots;
  var icase = opts.icase;
  var multiline = opts.multiline;
  var unicode = opts.unicode;
  var sticky = opts.sticky;
  var len = subject.length;

  // One live position per instruction, which is what makes the whole thing
  // linear: a path that arrives where another already is has nothing new to
  // explore, so it is dropped rather than followed.
  //
  // Each list keeps its OWN record of what it has admitted. Sharing one between
  // the current step and the next lets a position already taken in this step
  // turn away the path that reaches it in the next, and the loop back over a
  // repetition is exactly such a path — `a*` came out empty for want of this.
  var marksC = { seen: new Array(prog.length), gen: 1 };
  var marksN = { seen: new Array(prog.length), gen: 1 };
  var clist = [];
  var nlist = [];
  var matched = null;

  function codePointAt(at) {
    if (at >= len) return -1;
    if (!unicode) return subject.charCodeAt(at);
    return subject.codePointAt(at);
  }

  function widthAt(at) {
    if (!unicode) return 1;
    var cp = subject.codePointAt(at);
    return cp > 0xFFFF ? 2 : 1;
  }

  // A character that folds onto a word character IS one, for boundaries as much
  // as for `\w`: under `iu` a Kelvin sign folds to `k`, so it stands inside a
  // word rather than beside one.
  function isWordAt(cp) {
    if (cp < 0) return false;
    if (_has(WORD, cp)) return true;
    return icase && _sharesCase(WORD, cp, unicode);
  }

  function assertionHolds(kind, at) {
    var before = at > 0 ? subject.charCodeAt(at - 1) : -1;
    var here = at < len ? subject.charCodeAt(at) : -1;
    if (kind === "bol") {
      return at === 0 || (multiline && _has(LINE_TERMINATORS, before));
    }
    if (kind === "eol") {
      return at === len || (multiline && _has(LINE_TERMINATORS, here));
    }
    var wordBefore = at > 0 && isWordAt(before);
    var wordHere = at < len && isWordAt(here);
    if (kind === "wb") return wordBefore !== wordHere;
    return wordBefore === wordHere;                       // `\B`
  }

  // Where the capture boundaries recorded so far are kept: a chain, one link
  // per boundary, shared by every path that passed through it. Recording one
  // costs a link rather than a copy of every slot — with an array, a pattern of
  // N groups copied 2N slots at each of its 2N boundaries, so matching grew
  // with the SQUARE of the pattern and the promised bound held only for
  // patterns that were small anyway. The chain is read once, when something
  // matches.
  //
  // Following the zero-width steps to the characters they lead to, with an
  // explicit stack rather than the call stack. A pattern can chain thousands of
  // them — `(){2000}` is nothing but zero-width steps — and recursion would
  // overflow on a pattern the platform matches without trouble.
  //
  // The stack keeps priority: a split's preferred side is pushed LAST so it
  // comes off first, which is what makes greedy greedy.
  function add(list, marks, startPc, at, startCaps) {
    var stack = [{ pc: startPc, caps: startCaps }];
    while (stack.length !== 0) {
      var step = stack.pop();
      var pc = step.pc;
      if (marks.seen[pc] === marks.gen) continue;
      marks.seen[pc] = marks.gen;
      var caps = step.caps;
      var instruction = prog[pc];
      if (instruction.op === "j") { stack.push({ pc: instruction.x, caps: caps }); continue; }
      if (instruction.op === "s") {
        stack.push({ pc: instruction.y, caps: caps });
        stack.push({ pc: instruction.x, caps: caps });
        continue;
      }
      if (instruction.op === "v") {
        stack.push({ pc: pc + 1, caps: { slot: instruction.i, at: at, prev: caps } });
        continue;
      }
      if (instruction.op === "a") {
        if (assertionHolds(instruction.k, at)) stack.push({ pc: pc + 1, caps: caps });
        continue;
      }
      if (instruction.op === "clr") {
        stack.push({ pc: pc + 1, caps: { lo: instruction.lo, hi: instruction.hi, prev: caps } });
        continue;
      }
      list.push({ pc: pc, caps: caps });
    }
  }

  var at = startAt;

  for (;;) {
    // A new attempt from this position, at the lowest priority, so an earlier
    // start always wins — which is what "leftmost" means. Once something has
    // matched, no later start can improve on it.
    if (matched === null && (!sticky || at === startAt)) add(clist, marksC, 0, at, null);
    // An empty list means nothing survived FROM HERE — `\b` refusing at the
    // first position, say. The search still moves on, because a later position
    // may start an attempt that does survive. Two things make that pointless: a
    // match already in hand, since no later start could be further left, and the
    // `y` flag, which allows exactly one start — once its attempt has died there
    // is nothing left to seed and walking the rest of the subject would be pure
    // cost. A sticky pattern refused twenty million characters in about a second
    // before this, reading every one of them to reach an answer it already had.
    if (clist.length === 0 && (matched !== null || sticky)) break;

    var cp = codePointAt(at);
    var width = at < len ? widthAt(at) : 0;
    for (var i = 0; i < clist.length; i += 1) {
      var thread = clist[i];
      var instruction = prog[thread.pc];
      if (instruction.op === "m") {
        matched = thread.caps;
        break;                                            // lower-priority threads lose
      }
      if (instruction.op === "c" && cp >= 0 && _matchesSet(instruction.set, cp, icase, unicode)) {
        add(nlist, marksN, thread.pc + 1, at + width, thread.caps);
      }
    }

    // Between the halves of an astral character there is a position the engine
    // still looks at, and a zero-width pattern still matches there: `/\B/u`
    // against "a<astral>b" reports an empty match at the index INSIDE the pair.
    // Nothing that consumes can match there — the character does not begin at
    // that index — so only an empty match is looked for, and only after the
    // position before it has been settled, which keeps the leftmost one.
    if (matched === null && unicode && width === 2 && (!sticky || at + 1 === startAt)) {
      var splitList = [];
      var splitMarks = { seen: new Array(prog.length), gen: 1 };
      add(splitList, splitMarks, 0, at + 1, null);
      for (var sp = 0; sp < splitList.length; sp += 1) {
        if (prog[splitList[sp].pc].op === "m") { matched = splitList[sp].caps; break; }
      }
    }

    if (at >= len) break;
    at += width;
    var swapList = clist;
    clist = nlist;
    nlist = swapList;
    nlist.length = 0;
    var swapMarks = marksC;
    marksC = marksN;
    marksN = swapMarks;
    marksN.gen += 1;                                      // clear it for the next step
  }
  return matched === null ? null : _readCaptures(matched, slots);
}

// Read the chain back into slots, once, for the path that matched. Walking it
// from the end means the FIRST value found for a slot is the most recent one
// written, which is the one that counts; a clearing link answers for every slot
// in its range that nothing later has already answered for.
function _readCaptures(node, slots) {
  var out = new Array(slots);
  var known = new Array(slots);
  var i;
  for (i = 0; i < slots; i += 1) { out[i] = -1; known[i] = false; }
  var link = node;
  while (link !== null) {
    if (link.slot !== undefined) {
      if (!known[link.slot]) { out[link.slot] = link.at; known[link.slot] = true; }
    } else {
      for (var g = link.lo; g <= link.hi; g += 1) {
        var open = g * 2;
        var close = open + 1;
        if (!known[open]) { out[open] = -1; known[open] = true; }
        if (!known[close]) { out[close] = -1; known[close] = true; }
      }
    }
    link = link.prev;
  }
  return out;
}

/**
 * @primitive  b.regexLinear.compile
 * @signature  b.regexLinear.compile(source, flags?)
 * @since      0.18.19
 * @status     stable
 * @related    b.guardRegex.assertSafe, b.guardRegex.validate
 *
 * Compile a pattern into a matcher that runs in time proportional to the
 * subject, whatever the pattern is.
 *
 * `source` is the pattern without delimiters, as `RegExp` takes it, or a
 * `RegExp` whose source and flags are used. Flags `i`, `m`, `s`, `u` and `y`
 * are honoured. `g` is not, because the matcher returns one match and the
 * caller decides what to do next.
 *
 * Two are refused by name rather than ignored, both under
 * `regex/unsupported-flag`. `v` brings class set operations — intersection,
 * subtraction, string properties — that this does not implement, and reading it
 * as a `u` would quietly match a different language; use `u`, or name the
 * characters in a plain class. `d` asks for the index of every capture, which
 * this does not record; drop it, or run the pattern with the platform engine
 * once it has been screened.
 *
 * The returned matcher exposes `test(subject)` and `exec(subject, from?)`.
 * `exec` returns `null` or a result shaped like the platform's: index 0 is the
 * whole match, higher indices are the capture groups, `index` is where the
 * match began, and `groups` carries the named ones.
 *
 * Backreferences and lookaround are refused at compile time, by name, with the
 * code `regex/unsupported-backreference` or `regex/unsupported-lookaround`.
 * They cannot be simulated without exploring paths one at a time, which is the
 * thing being avoided — so the choice is made where an operator can see it,
 * rather than by handing the pattern to an engine that can be made to hang.
 *
 * Four more are refused for narrower reasons, each under its own code and each
 * with a message saying what to write instead: a repetition whose body can
 * match nothing (`regex/nullable-repetition` — `(a*)*` means what `a*` means);
 * a group named outside ASCII, and a name reused across alternatives
 * (`regex/bad-group`); an inline flag modifier such as `(?i:...)`
 * (`regex/unsupported-group`), whose scoped flags this does not yet carry; and
 * a Unicode property escape under `u`, such as `\p{L}` (
 * `regex/unsupported-property`) — name the characters in a class instead.
 * Without `u` there is no property escape to refuse: `\p{L}` is a `p`, a brace,
 * an `L` and a brace there, and it compiles.
 * These are patterns the platform accepts, so a pattern using one has to be
 * screened and run with the platform engine, or rewritten. Everything else
 * accepted here returns exactly what `RegExp` returns, with one exception that
 * belongs to the platform rather than to this matcher: under `u`, an unanchored
 * pattern ending in a CHARACTER CLASS that can match at most one code point,
 * then `$`, misses a subject ending in an astral character.
 * `new RegExp("[^a]$", "u")` finds nothing in a single emoji, while
 * `new RegExp("^[^a]$", "u")` finds it — and a `^` can only take match
 * positions away, never add one. This returns the match, which is what the
 * language specifies, so on that one shape the two answers differ. A class that
 * may run on (`[^a]+$`, `[^a]*$`), a shorthand (`\W$`), the dot, and the
 * character written out are all unaffected.
 *
 * @opts
 *   (none — flags are passed as the second argument, as `RegExp` takes them)
 *
 * @example
 *   var m = b.regexLinear.compile("^(\\w+)@([\\w.]+)$");
 *   m.test("ada@example.com");             // → true
 *   m.exec("ada@example.com")[2];          // → "example.com"
 *
 *   // The shape that hangs the platform engine runs in linear time here.
 *   b.regexLinear.compile("(a+)+$").test("a".repeat(40) + "!");   // → false
 */
function compile(source, flags) {
  if (source instanceof RegExp) {
    flags = flags === undefined ? source.flags : flags;
    source = source.source;
  }
  if (typeof source !== "string") {
    throw new TypeError("regexLinear.compile: source must be a string or a RegExp");
  }
  if (flags === undefined || flags === null) flags = "";
  if (typeof flags !== "string") {
    throw new TypeError("regexLinear.compile: flags must be a string");
  }
  var flagProblem = _badFlags(flags);
  if (flagProblem !== null) {
    throw new TypeError("regexLinear.compile: " + flagProblem);
  }
  // (2) `v` brings set intersection, subtraction and nested classes. Reading
  // `[a&&b]` as ordinary members would match a different language than the
  // operator wrote, so the flag is refused until those are implemented rather
  // than accepted and approximated.
  if (flags.indexOf("d") !== -1) {
    throw new RegexLinearError("regex/unsupported-flag",
      "regexLinear.compile: the d flag promises match indices this does not " +
      "produce — drop it, or use the platform engine for that result");
  }
  if (flags.indexOf("v") !== -1) {
    throw new RegexLinearError("regex/unsupported-flag",
      "regexLinear.compile: the v flag brings class set operations that are not " +
      "implemented — use u, or name the characters in a plain class");
  }
  if (Buffer.byteLength(source, "utf8") > MAX_SOURCE_BYTES) {
    throw new RegexLinearError("regex/pattern-too-large",
      "regexLinear.compile: pattern longer than " + MAX_SOURCE_BYTES + " bytes");
  }

  var parsed = _parse(source, flags);
  var compiled = _compile(parsed.ast, parsed.captureCount);
  var runOpts = {
    icase:     flags.indexOf("i") !== -1,
    multiline: flags.indexOf("m") !== -1,
    unicode:   flags.indexOf("u") !== -1 || flags.indexOf("v") !== -1,
    sticky:    flags.indexOf("y") !== -1,
  };

  function exec(subject, from) {
    if (typeof subject !== "string") {
      throw new TypeError("regexLinear.exec: subject must be a string");
    }
    var startAt = from === undefined ? 0 : from;
    // A whole number of characters. A fraction reaches the string operations,
    // which truncate it, while the capture slots keep it — and the match comes
    // back claiming to start at index 1.5.
    if (typeof startAt !== "number" || !Number.isInteger(startAt) || startAt < 0) {
      throw new TypeError("regexLinear.exec: from must be a non-negative integer");
    }
    if (startAt > subject.length) return null;
    // Under `u` an offset that splits a surrogate pair does not name a place a
    // character starts. The platform's own answer there is not one rule — a
    // zero-width assertion can match at the split index while a consuming
    // pattern reports the index before it — so rather than pick one and differ
    // from `RegExp` silently, the offset is refused. A caller stepping through
    // matches under `u` advances by code point, and one that lands here has a
    // bug worth seeing.
    if (runOpts.unicode && startAt > 0 && startAt < subject.length) {
      var high = subject.charCodeAt(startAt - 1);
      var low = subject.charCodeAt(startAt);
      if (high >= 0xD800 && high <= 0xDBFF && low >= 0xDC00 && low <= 0xDFFF) {
        throw new RangeError("regexLinear.exec: from " + startAt + " splits a surrogate " +
          "pair — under the u flag an offset must fall where a character starts");
      }
    }
    var caps = _run(compiled, subject, startAt, runOpts);
    if (caps === null) return null;
    var result = [];
    for (var g = 0; g <= parsed.captureCount; g += 1) {
      var lo = caps[g * 2];
      var hi = caps[g * 2 + 1];
      result[g] = (lo < 0 || hi < 0) ? undefined : subject.slice(lo, hi);
    }
    result.index = caps[0];
    result.input = subject;
    var named = Object.keys(parsed.names);
    if (named.length === 0) result.groups = undefined;
    else {
      var groups = Object.create(null);
      for (var n = 0; n < named.length; n += 1) groups[named[n]] = result[parsed.names[named[n]]];
      result.groups = groups;
    }
    return result;
  }

  return {
    source:       source,
    flags:        flags,
    groupCount:   parsed.captureCount,
    groupNames:   Object.keys(parsed.names),
    test:         function (subject) { return exec(subject, 0) !== null; },
    exec:         exec,
  };
}

module.exports = {
  compile:          compile,
  RegexLinearError: RegexLinearError,
};
