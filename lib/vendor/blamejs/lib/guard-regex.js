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

var EXTGLOB_HEADS = "*+?@!";

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
    inputKind:                "regex",
    maxBoundedRepeat:          100,
    maxConsecutiveStars:        2,
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
    consecutiveStarPolicy:    "reject",
    nestedExtglobPolicy:      "reject",
    maxBoundedRepeat:          1000,
    maxConsecutiveStars:        2,
    maxPatternBytes:           C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(2),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "allow",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    unanchoredScanPolicy:      "allow",
    consecutiveStarPolicy:    "reject",
    nestedExtglobPolicy:      "reject",
    maxBoundedRepeat:          10000,
    maxConsecutiveStars:        2,
    maxPatternBytes:           C.BYTES.kib(8),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var MAX_CLASS_RANGE = 256;

var ANALYSIS_BUDGET = 20000;

function _declinesOnFlags(flags) {
  return typeof flags === "string" && flags.indexOf("v") !== -1;
}

function _classUsesSetSyntax(text, from) {
  var depth = 0;
  for (var i = from; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (c === "\\") {
      if (text.charAt(i + 1) === "q" && text.charAt(i + 2) === "{") return true;
      i += 1;
      continue;
    }
    if (c === "[") {
      depth += 1;
      if (depth > 1) return true;
      continue;
    }
    if (c === "]") {
      depth -= 1;
      if (depth <= 0) return false;
      continue;
    }
    if (depth >= 1 && (c === "-" || c === "&") && text.charAt(i + 1) === c) return true;
  }
  return false;
}

function _anySet() { return { any: true, negated: false, chars: null }; }

function _mkSet(chars, negated) {
  var set = chars instanceof Set ? chars : new Set(chars);
  return { any: false, negated: !!negated, chars: set };
}

function _setSize(s) { return s.any ? 0 : s.chars.size; }

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

function _addIfOneCharacter(out, candidate) {
  if (candidate.length === 1) { out.add(candidate); return; }
  if (candidate.length === 2 && candidate.codePointAt(0) > 0xffff) out.add(candidate);
}

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
  if ("0123456789kpPbBuxc".indexOf(ch) !== -1) return null;
  return _mkSet([ch], false);
}

var MAX_PARSE_DEPTH = 200;

var FLAG_LETTERS = "dgimsuvy";

function _isFlagLetter(ch) { return FLAG_LETTERS.indexOf(ch) !== -1; }

function _isDigitChar(ch) { return ch >= "0" && ch <= "9"; }

function _isNameStart(ch) {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || ch === "_" || ch === "$";
}

function _scanLookHead(src, at) {
  if (src.charAt(at) !== "?") return null;
  var next = src.charAt(at + 1);
  if (next === "=" || next === "!") {
    return { negated: next === "!", behind: false, end: at + 2 };
  }
  if (next !== "<") return null;
  var third = src.charAt(at + 2);
  if (third !== "=" && third !== "!") return null;
  return { negated: third === "!", behind: true, end: at + 3 };
}

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
    if (i === offStart) return null;
  }
  if (src.charAt(i) !== ":") return null;
  return { on: on, off: off, end: i + 1 };
}

function _scanBraces(src, at) {
  var i = at + 1;
  var loStart = i;
  while (i < src.length && _isDigitChar(src.charAt(i))) i += 1;
  if (i === loStart) return null;
  var lo = parseInt(src.slice(loStart, i), 10);
  var hi = lo;
  if (src.charAt(i) === ",") {
    i += 1;
    var hiStart = i;
    while (i < src.length && _isDigitChar(src.charAt(i))) i += 1;
    hi = i === hiStart ? Infinity : parseInt(src.slice(hiStart, i), 10);
  }
  if (src.charAt(i) !== "}") return null;
  return { min: lo, max: hi, end: i + 1 };
}

function _turnsFoldingOn(src) {
  return codepointClass.hasPairWhere(src, "(", "?", function (i) {
    var at = i + 2;
    var enablesFold = false;
    while (at < src.length && _isFlagLetter(src.charAt(at))) {
      if (src.charAt(at) === "i") enablesFold = true;
      at += 1;
    }
    if (src.charAt(at) === "-") {
      at += 1;
      while (at < src.length && _isFlagLetter(src.charAt(at))) at += 1;
    }
    return enablesFold && src.charAt(at) === ":";
  });
}

function _parsePattern(src, flags, budget) {
  var pos = 0;
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

  function parseQuant() {
    var c = src.charAt(pos);
    var min, max;
    if (c === "*") { min = 0; max = Infinity; pos += 1; }
    else if (c === "+") { min = 1; max = Infinity; pos += 1; }
    else if (c === "?") { min = 0; max = 1; pos += 1; }
    else if (c === "{") {
      var braced = _scanBraces(src, pos);
      if (braced === null) return { min: 1, max: 1 };
      min = braced.min;
      max = braced.max;
      if (max < min) return null;
      pos = braced.end;
    } else return { min: 1, max: 1 };
    if (src.charAt(pos) === "?") pos += 1;
    return { min: min, max: max };
  }

  function parseAtom(depth, activeFlags) {
    var c = src.charAt(pos);
    if (c === "(") return parseGroup(depth, activeFlags);
    if (c === "[") return parseClass(activeFlags);
    if (c === "^" || c === "$") {
      pos += 1;
      return { type: "anchor", edge: c === "$" ? "end" : "start", flags: activeFlags };
    }
    if (c === ".") {
      pos += 1;
      var dot = activeFlags.indexOf("s") !== -1
        ? _mkSet([], true)
        : _mkSet(LINE_TERMINATORS, true);
      return { type: "set", set: dot, flags: activeFlags };
    }
    if (c === "\\") {
      var esc = src.charAt(pos + 1);
      if (esc === "") return fail();
      pos += 2;
      if (esc === "b" || esc === "B") {
        return { type: "anchor", edge: "word", negated: esc === "B", flags: activeFlags };
      }
      var set = _escapeSet(esc);
      if (set === null) return { type: "opaque", flags: activeFlags };
      if (!spend(_setSize(set))) return fail();
      return { type: "set", set: _applyFold(set, activeFlags, foldGroups), flags: activeFlags };
    }
    if (c === "*" || c === "+" || c === "?" || c === ")") return fail();
    var literal = _codePointAt(src, pos, activeFlags);
    pos += literal.length;
    return { type: "set", set: _applyFold(_mkSet([literal], false), activeFlags, foldGroups), flags: activeFlags };
  }

  function parseClass(activeFlags) {
    var start = pos;
    if (activeFlags.indexOf("v") !== -1 && _classUsesSetSyntax(src, pos)) return fail();
    pos += 1;
    var negated = false;
    if (src.charAt(pos) === "^") { negated = true; pos += 1; }
    var members = new Set();
    var characterised = true;
    var closed = false;
    while (pos < src.length) {
      var c = src.charAt(pos);
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
        if (lo.negated) { characterised = false; continue; }
        lo.chars.forEach(function (m) { members.add(m); });
        if (!spend(_setSize(lo))) return fail();
      }
    }
    if (!closed) return fail();
    if (!characterised) return { type: "set", set: _anySet(), flags: activeFlags };
    return { type: "set", set: _applyFold(_mkSet(members, negated), activeFlags, foldGroups), flags: activeFlags };
  }

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
    pos += 1;
    var innerFlags = activeFlags;
    if (src.charAt(pos) === "?") {
      var look = _scanLookHead(src, pos);
      if (look !== null) {
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

function _codePointAt(src, at, flags) {
  var one = src.charAt(at);
  if (flags.indexOf("u") === -1 && flags.indexOf("v") === -1) return one;
  var code = src.charCodeAt(at);
  if (code < 0xd800 || code > 0xdbff || at + 1 >= src.length) return one;
  var next = src.charCodeAt(at + 1);
  if (next < 0xdc00 || next > 0xdfff) return one;
  return src.slice(at, at + 2);
}

var MAX_FOLD_ALPHABET = 64;

function _canonical(ch, unicodeMode) {
  return codepointClass.canonicalizeForCase(ch.codePointAt(0), unicodeMode);
}

function _foldGroups(src, flags) {
  var unicodeMode = flags.indexOf("u") !== -1 || flags.indexOf("v") !== -1;
  var alphabet = [];
  var seen = new Set();
  for (var i = 0; i < src.length; i += 1) {
    var ch = _codePointAt(src, i, flags);
    if (ch.length === 2) i += 1;
    if (ch.charCodeAt(0) < 0x80) continue;
    if (seen.has(ch)) continue;
    seen.add(ch);
    alphabet.push(ch);
    if (alphabet.length > MAX_FOLD_ALPHABET) return null;
  }
  if (alphabet.length === 0) return new Map();
  for (var code = 0x41; code <= 0x7a; code += 1) {
    if (code > 0x5a && code < 0x61) continue;
    var letter = String.fromCharCode(code);
    if (!seen.has(letter)) { seen.add(letter); alphabet.push(letter); }
  }
  var groups = new Map();
  for (var a = 0; a < alphabet.length; a += 1) {
    for (var b = a + 1; b < alphabet.length; b += 1) {
      var x = alphabet[a], y = alphabet[b];
      if (_linkedByCase(x, y)) continue;
      if (_canonical(x, unicodeMode) !== _canonical(y, unicodeMode)) continue;
      _linkFold(groups, x, y);
      _linkFold(groups, y, x);
    }
  }
  return groups;
}

function _linkedByCase(x, y) {
  return x.toLowerCase() === y || x.toUpperCase() === y ||
         y.toLowerCase() === x || y.toUpperCase() === x;
}

function _linkFold(groups, from, to) {
  var list = boundedMap.getOrInsert(groups, from, function () { return []; });
  if (list.indexOf(to) === -1) list.push(to);
}

function _applyFold(set, flags, foldGroups) {
  if (flags.indexOf("i") === -1) return set;
  if (foldGroups === null) return _anySet();
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

function _firstSet(node) {
  if (node.type === "set") return node.set;
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
    if (t.min === 0) return null;
    return s;
  }
  return null;
}

function _alwaysSatisfiedBy(node, alphabet) {
  return _setIsSubsetOf(alphabet, _satisfiedOn(node, alphabet));
}

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
  var head = null;
  for (var i = 0; i < node.terms.length; i += 1) {
    var t = node.terms[i];
    if (t.min === 0) continue;
    if (head === null) {
      head = _satisfiedOn(t.node, alphabet);
      if (t.min > 1 && !_alwaysSatisfiedBy(t.node, alphabet)) return _mkSet([], false);
      continue;
    }
    if (!_alwaysSatisfiedBy(t.node, alphabet)) return _mkSet([], false);
  }
  return head === null ? _anySet() : head;
}

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
    var spans = t.max - t.min + 1;
    var ways = spans * Math.pow(perCopy, t.max);
    if (!isFinite(ways) || ways > MAX_BOUNDED_PATHS) return Infinity;
    product *= ways;
    if (product > MAX_BOUNDED_PATHS) return Infinity;
  }
  return product;
}

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

function _delimiterForcesSplit(body) {
  return _splitDelimiter(body) !== null;
}


function _variationCannotMove(body) {
  if (body.type !== "alt" || body.branches.length !== 1) return false;
  var terms = body.branches[0].terms;
  var head = _firstSet(body);
  if (head === null) return false;
  var varying = [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min === t.max && !_isVariableLength(t.node)) continue;
    if (t.max === Infinity) return false;
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

function _mustContain(branch) {
  var parts = [];
  var terms = branch.type === "seq" ? branch.terms : [];
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min < 1) continue;
    if (t.node.type === "anchor" || t.node.type === "look") continue;
    var head = _firstSet(t.node);
    if (head === null) continue;
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
    var reach = _allSet(seq.terms[idx].node);
    var pinned = true;
    for (var k = idx + 1; k < seq.terms.length; k += 1) {
      var later = seq.terms[k];
      if (later.node.type === "anchor" || later.node.type === "look") continue;
      var head = _firstSet(later.node);
      if (head === null || _setsIntersect(reach, head)) { pinned = false; break; }
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
      if (node.type !== "set" || node.set.any || node.set.negated) readable = false;
      else if (run[i].min !== run[i].max && run[i].max !== Infinity) readable = false;
      else {
        if (run[i].min > 0) mandatory = true;
        runSets.push(node.set);
      }
    }
    if (!readable) return null;
    if (!mandatory) continue;
    var runSet = _unionSets(runSets);
    var restSets = [];
    for (var r = 0; r < rest.length; r += 1) restSets.push(_allSet(rest[r].node));
    if (_setsIntersect(runSet, _unionSets(restSets))) continue;
    var runIsOpenEnded = false;
    for (var q = 0; q < run.length; q += 1) {
      if (run[q].max === Infinity) runIsOpenEnded = true;
    }
    if (runIsOpenEnded && !_someTermMustMatch(rest)) return null;
    if (!_varyingPartsCannotTrade(run)) return null;
    if (!_varyingPartsCannotTrade(rest)) return null;
    return runSet;
  }
  return null;
}

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
      var steps = _bridgeSteps(terms, varying[v].at + 1, varying[w].at);
      if (steps === BRIDGE_UNREADABLE) return false;
      if (steps === null) continue;
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

function _bridgeSteps(terms, from, to) {
  var steps = [];
  for (var i = from; i < to; i += 1) {
    var ok = _pushBridgeSteps(terms[i], steps);
    if (ok === false) return null;
    if (ok === null) return BRIDGE_UNREADABLE;
  }
  return steps;
}

function _pushBridgeSteps(term, steps) {
  var node = term.node;
  if (node.type === "anchor" || node.type === "look") return true;
  if (term.min !== term.max) return false;
  if (term.min === 0) return true;
  if (steps.length >= MAX_BRIDGE_STEPS) return null;
  if (node.type === "set") {
    steps.push(node.set);
    return true;
  }
  if (node.type === "group" && node.body && node.body.type === "alt" &&
      node.body.branches.length === 1 && node.body.branches[0].type === "seq") {
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
  steps.push(_allSet(node));
  return true;
}

function _someTermMustMatch(terms) {
  for (var i = 0; i < terms.length; i += 1) {
    var t = terms[i];
    if (t.min < 1) continue;
    if (t.node.type === "anchor" || t.node.type === "look") continue;
    if (!_isNullable(t.node)) return true;
  }
  return false;
}

function _adjacentAmbiguity(seq, outerCanFail) {
  for (var i = 0; i < seq.terms.length; i += 1) {
    var left = seq.terms[i];
    if (!_repeatsVariably(left)) continue;
    var leftSet = _allSet(left.node);
    var leftWays = _repetitionWays(left);
    for (var j = i + 1; j < seq.terms.length; j += 1) {
      var right = seq.terms[j];
      var rightHead = _firstSet(right.node);
      if (rightHead === null) rightHead = _allSet(right.node);
      if (_repeatsVariably(right) && _setsIntersect(leftSet, rightHead)) {
        var pairWays = leftWays * _repetitionWays(right);
        if (!(isFinite(pairWays) && pairWays <= MAX_BOUNDED_PATHS) &&
            _canFailAfter(seq, j + 1, _unionSets([leftSet, _allSet(right.node)]),
                          outerCanFail)) return true;
        break;
      }
      if (!_termIsNullable(right)) break;
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
    if (t.node.type === "look") return true;
    if (t.node.type === "anchor") {
      if (t.node.edge === "end") continue;
      return true;
    }
    if (t.min > 0) return true;
    reach.push(_allSet(t.node));
  }
  var all = _unionSets(reach);
  return !(all.any || (all.negated && all.chars.size === 0));
}

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

  var forced = _boundariesForced(node);
  if (!forced && _adjacentAmbiguity(node, outerCanFail)) out.nested = true;
  for (var i = 0; i < node.terms.length; i += 1) {
    var term = node.terms[i];
    _findAmbiguity(term.node, out, _tailCanFail(node, i + 1) || outerCanFail);
    if (term.max <= 1) continue;
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

function _minLength(node) {
  if (node.type === "anchor" || node.type === "look") return 0;
  if (node.type === "set") return 1;
  if (node.type === "opaque") return 0;
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

function _unanchoredScanIsQuadratic(ast, flags) {
  var text = typeof flags === "string" ? flags : "";
  if (text.indexOf("y") !== -1) return false;
  var multiline = text.indexOf("m") !== -1;
  if (ast.type !== "alt") return false;
  for (var b = 0; b < ast.branches.length; b += 1) {
    if (_branchScanIsQuadratic(ast.branches[b], multiline)) return true;
  }
  return false;
}

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

var MAX_SCAN_EXPANSIONS = 2048;

var ASSERTION_STOP = { node: { type: "anchor", edge: "assertion" }, min: 1, max: 1 };

function _branchScanIsQuadratic(seq, multiline, budget) {
  if (seq.type !== "seq") return false;
  return _termsScanIsQuadratic(_inlineForScan(seq.terms), multiline,
                               budget || { left: MAX_SCAN_EXPANSIONS });
}

function _termsScanIsQuadratic(terms, multiline, budget) {
  if (_pinnedToOnePosition(terms, multiline)) return false;

  for (var k = 0; k < terms.length; k += 1) {
    var look = terms[k];
    if (look.node.type !== "look" || !look.node.body) continue;
    var body = look.node.behind ? _reversedForLookbehind(look.node.body) : look.node.body;
    if (body.type !== "alt") continue;
    if (!_lookIsReachableEverywhere(terms, k, body)) continue;
    var continuation = [];
    if (look.node.negated) {
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

  for (var g = 0; g < terms.length; g += 1) {
    var term = terms[g];
    if (term.min === 1 && term.max === 1 && term.node.type === "group" &&
        term.node.body.type === "alt" && term.node.body.branches.length > 1) {
      var after = terms.slice(g + 1);
      var before = terms.slice(0, g);
      for (var br = 0; br < term.node.body.branches.length; br += 1) {
        budget.left -= 1;
        if (budget.left <= 0) return true;
        var spliced = _inlineForScan(term.node.body.branches[br].terms).concat(after);
        if (_termsScanIsQuadratic(before.concat(spliced), multiline, budget)) return true;
      }
      return false;
    }
    if (_isRunawayTerm(term)) break;
  }
  return _headRunsAway(terms, multiline, budget);
}

function _isRunawayTerm(term) {
  if (term.node.type === "anchor" || term.node.type === "look") return false;
  var span = _maxLength(term.node);
  return span === Infinity || (term.max === Infinity && span > 0);
}

function _pinnedToOnePosition(terms, multiline) {
  for (var i = 0; i < terms.length; i += 1) {
    if (terms[i].node.type === "look") return false;
    if (terms[i].node.type === "anchor") {
      if (terms[i].node.edge === "start" && !_multilineAt(terms[i].node, multiline)) return true;
      continue;
    }
    return false;
  }
  return false;
}

function _multilineAt(node, fallback) {
  return typeof node.flags === "string" ? node.flags.indexOf("m") !== -1 : fallback;
}

function _forbiddenHeadSet(body) {
  return body ? _soleSetOf(body) : null;
}

function _soleSetOf(node) {
  if (node.type === "set") return node.set;
  if (node.type === "group") return _soleSetOf(node.body);
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
    if (t.min !== 1) return null;
    if (found !== null) return null;
    found = _soleSetOf(t.node);
    if (found === null) return null;
  }
  return found;
}

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

function _lookIsReachableEverywhere(terms, at, body) {
  var head = _firstSet(body);
  if (head === null) head = _allSet(body);
  var walks = _scanSetOfBody(body);
  for (var i = 0; i < at; i += 1) {
    var t = terms[i];
    if (t.node.type === "look") {
      if (t.node.behind) {
        if (_lookbehindSeparates(t.node, walks)) return false;
        continue;
      }
      if (!t.node.body) continue;
      if (t.node.negated) {
        var forbidden = _forbiddenHeadSet(t.node.body);
        if (forbidden !== null && _setIsSubsetOf(head, forbidden)) return false;
        continue;
      }
      var required = _firstSet(t.node.body);
      if (required !== null && !_setsIntersect(required, head)) return false;
      continue;
    }
    if (t.node.type === "anchor") {
      if (_anchorBoundsTheScan(t.node, walks)) return false;
      continue;
    }
    if (t.min < 1) continue;
    if (!_setsIntersect(_allSet(t.node), head)) return false;
  }
  return true;
}

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
  return parts.length === 0 ? _anySet() : _unionSets(parts);
}

function _lookbehindSeparates(node, scanSet) {
  if (!node.behind || node.negated || !node.body) return false;
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

function _anchorBoundsTheScan(anchor, scanSet) {
  if (anchor.edge === "word") {
    if (anchor.negated) return false;
    return _setIsSubsetOf(scanSet, _escapeSet("w")) ||
           _setIsSubsetOf(scanSet, _escapeSet("W"));
  }
  if (!_multilineAt(anchor, false)) return anchor.edge === "end";
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
  for (var r = i; r < terms.length; r += 1) {
    var term = terms[r];
    if (term.node.type === "anchor" || term.node.type === "look") continue;
    var reach = _maxLength(term.node);
    var runsAway = reach === Infinity || (term.max === Infinity && reach > 0);
    if (!runsAway) continue;
    if (!_runIsReachableEverywhere(terms, i, r)) continue;
    if (_canFailAfterRun(terms, r)) return true;
    if (term.min >= 1 && term.node.type === "group" && term.node.body &&
        term.node.body.type === "alt") {
      for (var gb = 0; gb < term.node.body.branches.length; gb += 1) {
        if (_branchScanIsQuadratic(term.node.body.branches[gb], multiline, budget)) return true;
      }
    }
  }
  return false;
}

function _runIsReachableEverywhere(terms, from, runAt) {
  var runHead = _firstSet(terms[runAt].node);
  if (runHead === null) runHead = _allSet(terms[runAt].node);
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
    if (t.min < 1) continue;
    if (!_setsIntersect(_allSet(t.node), runHead)) return false;
  }
  return true;
}

function _canFailAfterRun(terms, from) {
  var reach = _allSet(terms[from].node);
  var shortestRun = _minLength(terms[from].node) * terms[from].min;
  for (var j = from + 1; j < terms.length; j += 1) {
    var later = terms[j];
    if (later.node.type === "look") {
      var body = later.node.body;
      if (body) {
        if (later.node.negated && later.node.behind) {
          var behindSeq = [];
          if (_flatSets(_reversedForLookbehind(body), behindSeq, MAX_BEHIND_POSITIONS) &&
              behindSeq.length > 0) {
            var runPositions = _positionsBehindRun(terms[from].node, behindSeq.length);
            if (runPositions !== null) {
              var canMatchThere = true;
              for (var k = 0; k < behindSeq.length; k += 1) {
                if (!_setsIntersect(behindSeq[k], runPositions[k])) canMatchThere = false;
              }
              if (!canMatchThere) continue;
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
    if (later.node.type === "anchor") return true;
    if (later.min < 1) continue;
    if (_alwaysSatisfiedBy(later.node, reach)) continue;
    return true;
  }
  return false;
}

var MAX_BEHIND_POSITIONS = 64;

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
    if (t.min !== t.max) return false;
    for (var rep = 0; rep < t.min; rep += 1) {
      if (!_flatSets(t.node, out, limit)) return false;
      if (out.length >= limit) return true;
    }
  }
  return true;
}

function _positionsBehindRun(runNode, count) {
  var reversed = _reversedForLookbehind(runNode);
  var out = [];
  while (out.length < count) {
    var before = out.length;
    if (!_flatSets(reversed, out, count)) return null;
    if (out.length === before) return null;
  }
  return out;
}

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
      if (term.min < 1) continue;
      if (!_spellableFrom(term.node, reach)) return false;
    }
    return true;
  }
  if (node.type === "group") return _spellableFrom(node.body, reach);
  if (node.type === "set") return _setsIntersect(node.set, reach);
  if (node.type === "anchor") {
    return node.edge === "word" || node.edge === "assertion";
  }
  if (node.type === "look") return true;
  return true;
}

function _setIsSubsetOf(inner, outer) {
  if (inner.any) return !!outer.any;
  if (outer.any) return true;
  if (!inner.negated && !outer.negated) {
    var missing = false;
    inner.chars.forEach(function (c) { if (!outer.chars.has(c)) missing = true; });
    return !missing;
  }
  if (inner.negated && outer.negated) {
    var uncovered = false;
    outer.chars.forEach(function (c) { if (!inner.chars.has(c)) uncovered = true; });
    return !uncovered;
  }
  if (!inner.negated && outer.negated) {
    var excluded = false;
    inner.chars.forEach(function (c) { if (outer.chars.has(c)) excluded = true; });
    return !excluded;
  }
  return false;
}

function _ambiguityFindings(src, flags) {
  var out = { nested: false, alternation: false, lookaround: false, unanchored: false };
  var text = String(src);
  var ast = _parsePattern(text, typeof flags === "string" ? flags : "",
                          { left: ANALYSIS_BUDGET });
  if (ast === null) {
    var compiles = true;
    // eslint-disable-next-line blamejs/no-regex-in-content-safety
    try { RegExp(text, typeof flags === "string" ? flags : ""); }
    catch (_e) { compiles = false; }
    if (compiles) {
      out.nested = true;
      out.lookaround = true;
      out.unanchored = true;
    }
    return out;
  }
  if (_declinesOnFlags(flags)) {
    _findAmbiguityUnproven(ast, out);
    out.unanchored = _unanchoredScanIsQuadratic(ast, flags);
    return out;
  }
  _findAmbiguity(ast, out);
  out.unanchored = _unanchoredScanIsQuadratic(ast, flags);
  return out;
}

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
      bi = braces.end - 1;
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

function _detectConsecutiveStar(input, opts, issues) {
  if (opts.consecutiveStarPolicy === "allow") return;
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
                    2 : opts.maxConsecutiveStars;
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

function _detectNestedExtglob(input, opts, issues) {
  if (opts.nestedExtglobPolicy === "allow") return;
  if (opts.inputKind !== "glob") return;
  var heads = [];
  for (var hh = 0; hh + 1 < input.length; hh += 1) {
    if (input.charAt(hh + 1) !== "(") continue;
    if (EXTGLOB_HEADS.indexOf(input.charAt(hh)) === -1) continue;
    heads.push(hh);
    if (heads.length > 1024) break;
  }
  if (heads.length < 2) return;
  var nested = false;
  for (var hi = 0; hi < heads.length && !nested; hi += 1) {
    var headStart = heads[hi];
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
 * Throws `GuardRegexError("regex/bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"audit"|"allow",
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
var _sanitizeTransform = gateContract.identitySanitize;

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
      var pattern = gateContract.ctxValueFrom(ctx, ["identifier", "pattern"]);
      if (pattern === undefined || pattern === null) {
        return { ok: true, action: "serve" };
      }
      var rv = module.exports.validate(pattern, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

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
 * conservative by construction: a pattern it cannot characterize is refused
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
  if (input instanceof RegExp && (!opts || opts.regexFlags === undefined)) {
    opts = Object.assign({ profile: "strict", boundedRepeatPolicy: "allow" },
                         opts || {}, { regexFlags: input.flags });
  }
  try {
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

var POLICY_ENUM = gateContract.policyVocabulary([
  "nestedQuantPolicy", "alternationQuantPolicy", "boundedRepeatPolicy",
  "lookaroundQuantPolicy", "consecutiveStarPolicy", "nestedExtglobPolicy",
  "unanchoredScanPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow);

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
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
