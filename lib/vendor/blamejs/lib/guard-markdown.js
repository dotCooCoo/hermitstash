// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardMarkdown
 * @nav    Guards
 * @title  Guard Markdown
 *
 * @intro
 *   CommonMark validator + sanitizer for user-supplied markdown.
 *   Refuses raw HTML by default, applies a URL-scheme allowlist on
 *   inline links / autolinks / images / reference defs, and caps
 *   image dimensions and structural depth to defang renderer DoS.
 *   KIND="content" — the gate consumes `ctx.bytes` /
 *   `ctx.bodyText`.
 *
 *   The primitive is a SOURCE-LEVEL gate: it inspects raw markdown
 *   text BEFORE any downstream renderer (marked / markdown-it /
 *   commonmark / remark / parsedown) sees it. Source-level
 *   discipline matters because the most dangerous shapes —
 *   `__proto__` in JSON, `<script\n>` in markdown — exploit
 *   specific parser internals; sanitizing on the post-parse tree
 *   is too late.
 *
 *   Threat catalog grounded in current CVE research:
 *   CVE-2026-30838 (CommonMark DisallowedRawHtml whitespace-tag
 *   bypass — `<script\n>` / `<script\t>` evades naive `<script>`
 *   matchers); CVE-2025-9540 (Markup Markdown stored XSS via
 *   `javascript:` link); CVE-2025-7969 (markdown-it ReDoS class);
 *   CVE-2025-6493 (CodeMirror Markdown Mode catastrophic
 *   backtracking); CVE-2025-24981 (MDC autolink XSS);
 *   CVE-2026-33500 (AVideo Parsedown inlineLink/inlineUrlTag
 *   bypass); Joplin GHSA-hff8-hjwv-j9q7 (RCE via untrusted markdown
 *   link).
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   CommonMark validator + sanitizer for user-supplied markdown.
 */

var codepointClass = require("./codepoint-class");
var markupTokenizer = require("./markup-tokenizer");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var markupEscape = require("./markup-escape").markupEscape;
var C = require("./constants");
var { GuardMarkdownError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardMarkdownError.factory;

var DANGEROUS_TAGS    = [
  "script", "iframe", "object", "embed", "applet", "form", "input",
  "button", "textarea", "select", "option", "meta", "link", "base",
  "frame", "frameset", "noscript", "noembed", "svg", "math", "video",
  "audio", "source", "track", "style", "template", "portal", "marquee",
];

var DANGEROUS_SCHEMES = [
  "javascript", "vbscript", "livescript", "mocha", "view-source",
  "data", "jar", "blob", "feed", "tel", "facetime", "facetime-audio",
];

function _tagNameStartAt(s, at) {
  if (s.charAt(at) !== "<") return -1;
  var i = markupTokenizer.skipMarkupSpace(s, at + 1);
  if (s.charAt(i) === "/") i = markupTokenizer.skipMarkupSpace(s, i + 1);
  return codepointClass.isAsciiLetter(s.charCodeAt(i)) ? i : -1;
}

function _hasRawHtmlTag(s) {
  for (var i = 0; i < s.length; i += 1) {
    var nameAt = _tagNameStartAt(s, i);
    if (nameAt === -1) continue;
    return s.indexOf(">", nameAt) !== -1;
  }
  return false;
}

function _endsName(ch) {
  return ch === "" || !codepointClass.isIdentifierChar(ch.charCodeAt(0));
}

var DANGEROUS_TAG_SET = (function () {
  var m = Object.create(null);
  for (var i = 0; i < DANGEROUS_TAGS.length; i += 1) m[DANGEROUS_TAGS[i]] = true;
  return m;
})();

function _hasDangerousTag(s) {
  for (var i = 0; i < s.length; i += 1) {
    var nameAt = _tagNameStartAt(s, i);
    if (nameAt === -1) continue;
    var end = nameAt;
    while (end < s.length && codepointClass.isIdentifierChar(s.charCodeAt(end))) end += 1;
    if (DANGEROUS_TAG_SET[s.slice(nameAt, end).toLowerCase()] === true) return true;
    i = end - 1;
  }
  return false;
}

function _leadingLetterRun(s) {
  var i = 0;
  while (i < s.length && codepointClass.isAsciiLetter(s.charCodeAt(i))) i += 1;
  return s.slice(0, i).toLowerCase();
}

function _leadingSchemeOf(s, schemes) {
  for (var i = 0; i < schemes.length; i += 1) {
    var name = schemes[i];
    if (!codepointClass.containsFolded(s.slice(0, name.length), name)) continue;
    var j = markupTokenizer.skipMarkupSpace(s, name.length);
    if (s.charAt(j) === ":") return name;
  }
  return null;
}

var SPAN_INDEX_MIN_ROOM = 16;

function _makeSpanIndex() {
  var starts = [];
  var ends   = [];
  var values = [];
  var head = 0;
  function locate(i) {
    var lo = head;
    var hi = starts.length - 1;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (starts[mid] > i) hi = mid - 1;
      else if (ends[mid] < i) lo = mid + 1;
      else return mid;
    }
    return -(lo + 1);
  }
  function insertAt(slot, start, end, value) {
    if (slot === starts.length) {
      starts.push(start);
      ends.push(end);
      values.push(value);
      return;
    }
    if (slot === head) {
      if (head === 0) {
        var room = Math.max(SPAN_INDEX_MIN_ROOM, starts.length);
        starts = new Array(room).fill(0).concat(starts);
        ends = new Array(room).fill(0).concat(ends);
        values = new Array(room).fill(0).concat(values);
        head = room;
      }
      head -= 1;
      starts[head] = start;
      ends[head] = end;
      values[head] = value;
      return;
    }
    starts.splice(slot, 0, start);
    ends.splice(slot, 0, end);
    values.splice(slot, 0, value);
  }
  return {
    find: function (i) {
      var at = locate(i);
      return at >= 0 ? values[at] : undefined;
    },
    add: function (start, end, value) {
      if (end < start) return;
      var at = locate(start);
      if (at >= 0) return;
      var slot = -(at + 1);
      if (slot < starts.length && starts[slot] <= end + 1 && values[slot] === value) {
        starts[slot] = start;
        return;
      }
      if (slot < starts.length && starts[slot] <= end) end = starts[slot] - 1;
      if (end < start) return;
      if (slot > head && ends[slot - 1] === start - 1 && values[slot - 1] === value) {
        ends[slot - 1] = end;
        return;
      }
      insertAt(slot, start, end, value);
    },
  };
}

function _makeUrlRunScanner(input) {
  var stopAt = _makeSpanIndex();
  return function (from) {
    var known = stopAt.find(from);
    if (known !== undefined) return known;
    var p = from;
    while (p < input.length && input.charAt(p) !== ")" &&
           !markupTokenizer.isMarkupSpace(input.charCodeAt(p))) {
      var ahead = stopAt.find(p);
      if (ahead !== undefined) { p = ahead; break; }
      p += 1;
    }
    stopAt.add(from, p, p);
    return p;
  };
}

var MAX_VALIDATE_OPENERS = 65536;

function _countOpeners(input) {
  var openers = 0;
  for (var c = 0; c < input.length; c += 1) {
    if (input.charCodeAt(c) === 0x5B) openers += 1;
  }
  return openers;
}

function _squareMates(input, openers, spans) {
  var n = input.length;
  if (openers === undefined) openers = _countOpeners(input);
  if (openers === 0 || openers > MAX_VALIDATE_OPENERS) return null;
  if (spans === undefined) spans = _codeSpans(input);
  var mate = new Map();
  var stack = new Int32Array(openers);
  var top = 0;
  var sp = 0;
  var spanCount = spans === null ? 0 : spans.count;
  for (var i = 0; i < n; i += 1) {
    if (sp < spanCount && spans.list[sp] === i) { i = spans.list[sp + 1] - 1; sp += 2; continue; }
    var code = input.charCodeAt(i);
    if (code === 0x0A) { if (_blankLineAfter(input, i)) top = 0; continue; }
    if (code === 0x60) {
      while (i + 1 < n && input.charCodeAt(i + 1) === 0x60) i += 1;
      continue;
    }
    if (code === 0x5C) { i += 1; continue; }
    if (code === 0x5B) { stack[top] = i; top += 1; continue; }
    if (code === 0x5D && top > 0) { top -= 1; mate.set(stack[top], i); }
  }
  return mate;
}

function _backtickRuns(input) {
  var runs = 0;
  var lts = 0;
  var escaped = false;
  var inRun = false;
  for (var c = 0; c < input.length; c += 1) {
    var code = input.charCodeAt(c);
    if (code === 0x5C) {
      if (input.charCodeAt(c + 1) === 0x60) escaped = true;
      else c += 1;
      inRun = false;
      continue;
    }
    if (code === 0x3C) lts += 1;
    var isTick = code === 0x60;
    if (isTick && !inRun) runs += 1;
    inRun = isTick;
  }
  return { count: runs, escaped: escaped, lts: lts };
}

function _runStartsIn(input, from, to) {
  var runs = 0;
  var inRun = false;
  for (var j = from; j < to; j += 1) {
    var isTick = input.charCodeAt(j) === 0x60;
    if (isTick && !inRun) runs += 1;
    inRun = isTick;
  }
  return runs;
}

function _blankLineBefore(input, at) {
  for (var j = at - 1; j >= 0; j -= 1) {
    var c = input.charCodeAt(j);
    if (c === 0x0A) return true;
    if (c !== 0x20 && c !== 0x09 && c !== 0x0D) return false;
  }
  return true;
}

function _blankLineAfter(input, at) {
  for (var j = at + 1; j < input.length; j += 1) {
    var c = input.charCodeAt(j);
    if (c === 0x0A) return true;
    if (c !== 0x20 && c !== 0x09 && c !== 0x0D) return false;
  }
  return true;
}

function _codeSpans(input) {
  var n = input.length;
  var runs = _backtickRuns(input);
  var closeEnd = new Int32Array(runs.count);
  var closeEndShort = runs.escaped ? new Int32Array(runs.count) : null;
  var lastByLen = new Map();
  var k = runs.count;
  for (var i = n - 1; i >= 0; i -= 1) {
    var code = input.charCodeAt(i);
    if (code === 0x0A) { if (_blankLineBefore(input, i)) lastByLen.clear(); continue; }
    if (code !== 0x60) continue;
    var end = i + 1;
    while (i > 0 && input.charCodeAt(i - 1) === 0x60) i -= 1;
    var len = end - i;
    k -= 1;
    var next = lastByLen.get(len);
    closeEnd[k] = next === undefined ? -1 : next;
    if (closeEndShort !== null) {
      var nextShort = len > 1 ? lastByLen.get(len - 1) : undefined;
      closeEndShort[k] = nextShort === undefined ? -1 : nextShort;
    }
    lastByLen.set(len, end);
  }
  return _inertSpans(input, closeEnd, closeEndShort, runs.lts);
}

function _makeNextFinder(input, term) {
  var from = -1;
  var found = -1;
  return function (at) {
    if (from !== -1 && at >= from && (found === -1 || at <= found)) return found;
    from = at;
    found = input.indexOf(term, at);
    return found;
  };
}

function _skipHtmlSpace(input, j) {
  while (j < input.length && codepointClass.isAsciiWhitespace(input.charCodeAt(j))) j += 1;
  return j;
}

function _isAsciiDigitCode(c) {
  return c >= 0x30 && c <= 0x39;
}

function _isAsciiUpperCode(c) {
  return c >= 0x41 && c <= 0x5A;
}

function _isTagNameChar(c) {
  return codepointClass.isAsciiLetter(c) || _isAsciiDigitCode(c) || c === 0x2D;
}

function _isAttrNameStart(c) {
  return codepointClass.isAsciiLetter(c) || c === 0x5F || c === 0x3A;
}

function _isAttrNameChar(c) {
  return _isAttrNameStart(c) || _isAsciiDigitCode(c) || c === 0x2E || c === 0x2D;
}

function _isUnquotedValueChar(c) {
  return !codepointClass.isAsciiWhitespace(c) && c !== 0x22 && c !== 0x27 && c !== 0x3D &&
         c !== 0x3C && c !== 0x3E && c !== 0x60;
}

function _htmlTagEndAt(input, i, find) {
  if (input.charCodeAt(i) !== 0x3C) return -1;
  var n = input.length;
  var c = input.charCodeAt(i + 1);
  var at;
  if (c === 0x21) {
    if (input.startsWith("<!--", i)) { at = find.comment(i + 4); return at === -1 ? -1 : at + 3; }
    if (input.startsWith("<![CDATA[", i)) { at = find.cdata(i + 9); return at === -1 ? -1 : at + 3; }
    if (!codepointClass.isAsciiLetter(input.charCodeAt(i + 2))) return -1;
    at = find.gt(i + 2);
    return at === -1 ? -1 : at + 1;
  }
  if (c === 0x3F) { at = find.pi(i + 2); return at === -1 ? -1 : at + 2; }
  var j = i + 1;
  var closing = c === 0x2F;
  if (closing) j += 1;
  if (!codepointClass.isAsciiLetter(input.charCodeAt(j))) return -1;
  j += 1;
  while (j < n && _isTagNameChar(input.charCodeAt(j))) j += 1;
  if (closing) {
    j = _skipHtmlSpace(input, j);
    return input.charCodeAt(j) === 0x3E ? j + 1 : -1;
  }
  for (;;) {
    var k = _skipHtmlSpace(input, j);
    var d = input.charCodeAt(k);
    if (d === 0x3E) return k + 1;
    if (d === 0x2F) return input.charCodeAt(k + 1) === 0x3E ? k + 2 : -1;
    if (k === j || !_isAttrNameStart(d)) return -1;
    k += 1;
    while (k < n && _isAttrNameChar(input.charCodeAt(k))) k += 1;
    var e = _skipHtmlSpace(input, k);
    if (input.charCodeAt(e) !== 0x3D) { j = k; continue; }
    var v = _skipHtmlSpace(input, e + 1);
    var q = input.charCodeAt(v);
    if (q === 0x22 || q === 0x27) {
      var close = q === 0x22 ? find.dq(v + 1) : find.sq(v + 1);
      if (close === -1) return -1;
      j = close + 1;
      continue;
    }
    var u = v;
    while (u < n && _isUnquotedValueChar(input.charCodeAt(u))) u += 1;
    if (u === v) return -1;
    j = u;
  }
}

function _inertSpans(input, closeEnd, closeEndShort, lts) {
  var n = input.length;
  var list = new Int32Array(closeEnd.length + 2 * lts);
  var count = 0;
  var quoted = false;
  var k = 0;
  var find = {
    comment: _makeNextFinder(input, "-->"),
    cdata:   _makeNextFinder(input, "]]>"),
    pi:      _makeNextFinder(input, "?>"),
    gt:      _makeNextFinder(input, ">"),
    dq:      _makeNextFinder(input, "\""),
    sq:      _makeNextFinder(input, "'"),
  };
  function emit(start, end) {
    list[count] = start;
    list[count + 1] = end;
    count += 2;
    if (!quoted) quoted = _hasSquare(input, start, end);
  }
  for (var i = 0; i < n; i += 1) {
    var code = input.charCodeAt(i);
    if (code === 0x5C) {
      if (input.charCodeAt(i + 1) !== 0x60) { i += 1; continue; }
      var s = i + 2;
      var shortEnd = closeEndShort !== null && input.charCodeAt(s) === 0x60 ? closeEndShort[k] : -1;
      if (shortEnd >= 0) {
        emit(s, shortEnd);
        k += _runStartsIn(input, i + 1, shortEnd);
        i = shortEnd - 1;
        continue;
      }
      i += 1;
      while (i + 1 < n && input.charCodeAt(i + 1) === 0x60) i += 1;
      k += 1;
      continue;
    }
    if (code === 0x3C) {
      var tagEnd = _autolinkEndAt(input, i);
      if (tagEnd < 0) tagEnd = _htmlTagEndAt(input, i, find);
      if (tagEnd < 0) continue;
      emit(i, tagEnd);
      k += _runStartsIn(input, i, tagEnd);
      i = tagEnd - 1;
      continue;
    }
    if (code !== 0x60) continue;
    var end = closeEnd[k];
    if (end >= 0) {
      emit(i, end);
      k += _runStartsIn(input, i, end);
      i = end - 1;
      continue;
    }
    while (i + 1 < n && input.charCodeAt(i + 1) === 0x60) i += 1;
    k += 1;
  }
  return { list: list, count: count, quoted: quoted };
}

function _hasSquare(input, from, to) {
  for (var i = from; i < to; i += 1) {
    var c = input.charCodeAt(i);
    if (c === 0x5B || c === 0x5D) return true;
  }
  return false;
}

function _unionMatches(first, second) {
  if (second.length === 0) return first;
  var seen = new Set();
  var openers = new Set();
  var out = [];
  for (var i = 0; i < first.length; i += 1) {
    seen.add(first[i].index + ":" + first[i].urlStart);
    openers.add(first[i].index);
    out.push(first[i]);
  }
  for (var j = 0; j < second.length; j += 1) {
    var m = second[j];
    var key = m.index + ":" + m.urlStart;
    if (seen.has(key)) continue;
    seen.add(key);
    if (openers.has(m.index)) m = _sameConstructAs(m);
    else openers.add(m.index);
    out.push(m);
  }
  out.sort(function (a, c) {
    return a.urlStart !== c.urlStart ? a.urlStart - c.urlStart : a.index - c.index;
  });
  return out;
}

function _sameConstructAs(match) {
  var copy = { counted: false };
  Object.keys(match).forEach(function (k) {
    var d = Object.getOwnPropertyDescriptor(match, k);
    if (d.get) Object.defineProperty(copy, k, { enumerable: true, get: d.get });
    else copy[k] = match[k];
  });
  copy.counted = false;
  return copy;
}

function _mateOf(mates, i) {
  if (mates === null) return -1;
  var close = mates.get(i);
  return close === undefined ? -1 : close;
}

function _inlineMatch(input, bang, urlStart, urlEnd, index) {
  var m = { bang: bang, urlStart: urlStart, urlEnd: urlEnd, index: index };
  Object.defineProperty(m, "url", {
    enumerable: true,
    get: function () { return input.slice(urlStart, urlEnd); },
  });
  return m;
}

function _inlineLinks(input, limit, mates) {
  var out = [];
  var urlRunEnd = _makeUrlRunScanner(input);
  if (mates === undefined) mates = _squareMates(input);
  var failedStop = -1;
  var closes = null;
  var nextSpans = new Map();
  function nextOf(ch, from) {
    var span = nextSpans.get(ch);
    if (span === undefined) {
      span = { lo: -1, answer: -1 };
      nextSpans.set(ch, span);
    }
    return _nextIndexOf(input, ch, from, span);
  }
  var spaceSpan = { lo: -1, answer: -1 };
  function skipSpace(from) {
    if (from >= input.length ||
        !markupTokenizer.isMarkupSpace(input.charCodeAt(from))) return from;
    return _nextNonSpace(input, from, spaceSpan);
  }
  function closesAt(at) {
    if (closes === null) closes = new Uint8Array(input.length + 1);
    var known = closes[at];
    if (known !== 0) return known === 2;
    var v = _linkCloses(input, at, nextOf, skipSpace);
    closes[at] = v ? 2 : 1;
    return v;
  }
  var backoff = new Map();
  function backOffMemo(from, to) {
    var state = backoff.get(to);
    if (state === undefined) { state = { scannedDownTo: to, best: -1 }; backoff.set(to, state); }
    if (state.best > from) return state.best;
    for (var k = state.scannedDownTo - 1; k > from; k -= 1) {
      if (TITLE_OPENERS.indexOf(input.charAt(k)) !== -1 && closesAt(k)) {
        state.best = k;
        break;
      }
    }
    state.scannedDownTo = from + 1;
    return state.best > from ? state.best : -1;
  }
  for (var i = 0; i < input.length; i += 1) {
    if (input.charAt(i) !== "[") continue;
    var bang = i > 0 && input.charAt(i - 1) === "!" ? "!" : "";
    var close = _mateOf(mates, i);
    if (close === -1) continue;
    if (input.charAt(close + 1) !== "(") continue;
    var urlStart = markupTokenizer.skipMarkupSpace(input, close + 2);
    if (input.charAt(urlStart) === "<") {
      var gt = _angleDestEnd(input, urlStart);
      if (gt !== -1 && closesAt(gt + 1)) {
        out.push(_inlineMatch(input, bang, urlStart + 1, gt, i));
        if (limit !== undefined && out.length >= limit) break;
        continue;
      }
    }
    var u = urlRunEnd(urlStart);
    if (u === urlStart) continue;
    if (u === failedStop) continue;
    var urlEnd = closesAt(u) ? u : backOffMemo(urlStart, u);
    if (urlEnd === -1) { failedStop = u; continue; }
    out.push(_inlineMatch(input, bang, urlStart, urlEnd, i));
    if (limit !== undefined && out.length >= limit) break;
  }
  return out;
}

function _angleDestEnd(input, at) {
  for (var i = at + 1; i < input.length; i += 1) {
    var c = input.charCodeAt(i);
    if (c === 0x0A) return -1;
    if (c === 0x5C) { i += 1; continue; }
    if (c === 0x3C) return -1;
    if (c === 0x3E) return i;
  }
  return -1;
}

var TITLE_OPENERS = "\"'(";

function _titleCloserFor(ch) {
  if (ch === "\"") return "\"";
  if (ch === "'") return "'";
  if (ch === "(") return ")";
  return "";
}

function _nextWhere(s, from, span, matches) {
  if (from >= s.length) return -1;
  if (span.lo !== -1 && from >= span.lo &&
      (span.answer === -1 ? true : from <= span.answer)) {
    return span.answer;
  }
  var stop = span.lo !== -1 && from < span.lo ? span.lo : s.length;
  var i = from;
  while (i < stop && !matches(i)) i += 1;
  if (i < stop) {
    span.lo = from;
    span.answer = i;
    return i;
  }
  if (stop === s.length) {
    span.lo = from;
    span.answer = -1;
    return -1;
  }
  span.lo = from;
  return span.answer;
}

function _isBackslashEscaped(s, i) {
  var n = 0;
  while (i - 1 - n >= 0 && s.charCodeAt(i - 1 - n) === 0x5C) n += 1;
  return (n % 2) === 1;
}

function _nextIndexOf(s, ch, from, span) {
  return _nextWhere(s, from, span, function (i) {
    return s.charAt(i) === ch && !_isBackslashEscaped(s, i);
  });
}

function _nextNonSpace(s, from, span) {
  var at = _nextWhere(s, from, span, function (i) {
    return !markupTokenizer.isMarkupSpace(s.charCodeAt(i));
  });
  return at === -1 ? s.length : at;
}

function _linkCloses(s, at, nextOf, skipSpace) {
  var p = skipSpace(at);
  var closer = _titleCloserFor(s.charAt(p));
  if (closer !== "") {
    var q = nextOf(closer, p + 1);
    if (q === -1) return false;
    p = skipSpace(q + 1);
  }
  return s.charAt(p) === ")";
}

var AUTOLINK_SCHEME_TAIL_MAX = 32;

function _autolinkEndAt(input, i) {
  if (input.charAt(i) !== "<") return -1;
  if (!codepointClass.isAsciiLetter(input.charCodeAt(i + 1))) return -1;
  var j = i + 2;
  var tail = 0;
  while (j < input.length && tail < AUTOLINK_SCHEME_TAIL_MAX &&
         SCHEME_TAIL_CHARS.indexOf(input.charAt(j)) !== -1) { j += 1; tail += 1; }
  if (input.charAt(j) !== ":") return -1;
  var b = j + 1;
  while (b < input.length && input.charAt(b) !== ">" && input.charAt(b) !== "<" &&
         !markupTokenizer.isMarkupSpace(input.charCodeAt(b))) b += 1;
  if (b === j + 1 || input.charAt(b) !== ">") return -1 - b;
  return b + 1;
}

function _autolinks(input) {
  var out = [];
  for (var i = 0; i < input.length; i += 1) {
    if (input.charAt(i) !== "<") continue;
    var end = _autolinkEndAt(input, i);
    if (end === -1) continue;
    if (end < 0) { i = -end - 2; continue; }
    out.push({ url: input.slice(i + 1, end - 1), index: i });
    i = end - 1;
  }
  return out;
}

var SCHEME_TAIL_CHARS = codepointClass.ASCII_ALNUM + "+-.";

var TITLE_OPEN = 1;
var TITLE_CLOSED = 2;
var TITLE_TEXT = 3;

function _titleRunIn(s, from, end, closer) {
  var c = from;
  while (c < end && (s.charAt(c) !== closer || _isBackslashEscaped(s, c))) {
    if (closer === ")" && s.charAt(c) === "(" && !_isBackslashEscaped(s, c)) return TITLE_TEXT;
    c += 1;
  }
  if (c >= end) return TITLE_OPEN;
  var rest = c + 1;
  while (rest < end && _isSpaceOrTab(s.charAt(rest))) rest += 1;
  return rest >= end ? TITLE_CLOSED : TITLE_TEXT;
}

var READING_MODES = [
  { commonmark: true, html: true, tables: false },
  { commonmark: false, html: true, tables: true },
  { commonmark: false, html: false, tables: true },
  { commonmark: false, html: true, tables: false },
  { commonmark: false, html: false, tables: false },
];

function _readingsWith(unicodeBreaks) {
  return Object.freeze(READING_MODES.map(function (mode) {
    return Object.freeze({
      commonmark: mode.commonmark, html: mode.html, tables: mode.tables, unicodeBreaks: unicodeBreaks,
    });
  }));
}

var READINGS = _readingsWith(false);
var UNICODE_BREAK_READINGS = _readingsWith(true);

function _readingsFor(input) {
  return codepointClass.firstInRanges(input, UNICODE_LINE_BREAK_RANGES) === -1
    ? READINGS : READINGS.concat(UNICODE_BREAK_READINGS);
}

function _refDefs(input, mates) {
  if (mates === undefined) mates = _squareMates(input);
  var readings = _readingsFor(input);
  var out = _readBlocks(input, mates, readings[0]).definitions;
  for (var r = 1; r < readings.length; r += 1) {
    out = _unionMatches(out, _readBlocks(input, mates, readings[r]).definitions);
  }
  return out;
}

var SCAN_LABEL = 1;
var SCAN_DESTINATION = 2;
var SCAN_TITLE = 3;

var SCAN_CONTINUES = 1;
var SCAN_TITLE_STARTS = 2;
var SCAN_DEFINED = 3;
var SCAN_NO_TITLE = 4;
var SCAN_FAILS = 5;

function _readBlocks(input, mates, reading) {
  var out = [];
  var fences = [];
  var blocks = _blockTracker(reading);
  var at = 0;
  var previous = null;
  var defined = false;
  var scan = null;
  while (at < input.length || scan !== null) {
    var verdict = 0;
    var end = 0;
    var next = 0;
    var leaf = null;
    if (at >= input.length) {
      verdict = _scanFailure(scan);
    } else {
      end = _lineEndAt(input, at, reading.unicodeBreaks);
      next = _nextLineStart(input, end);
      blocks.scanning(scan !== null);
      leaf = _leafStart(input.slice(at, end), blocks);
      leaf.at = at;
      leaf.end = end;
      var state = blocks.leafLine(input.slice(at, end), leaf);
      if (state === LEAF_FENCE_OPENS) fences.push({ at: at, info: blocks.fenceInfo() });
      var tableStarts = reading.tables && state === 0 && !blocks.table() &&
        _tableStartsAt(input, previous, leaf);
      if (scan !== null) {
        verdict = tableStarts ? _scanFailure(scan) : _scanLine(scan, input, at, end, leaf, state);
        if (verdict === SCAN_CONTINUES || verdict === SCAN_TITLE_STARTS || verdict === SCAN_DEFINED) {
          _inheritDepth(leaf, previous);
        }
      } else {
        var joins = previous !== null && !leaf.blank && !leaf.opens &&
          (leaf.depth === previous.depth || (leaf.depth < previous.depth && previous.lazyOk !== false));
        var continues = joins && previous.paragraph && leaf.text && leaf.html === null;
        var chained = joins && defined && reading.commonmark;
        if (tableStarts) {
          blocks.table(true);
          continues = true;
        }
        var tabled = tableStarts || (reading.tables && blocks.table());
        if (tabled) {
          leaf.lazyOk = false;
          continues = true;
        }
        if (continues) leaf.paragraph = true;
        if (continues || chained) _inheritDepth(leaf, previous);
        previous = leaf;
        defined = false;
        if (state !== 0 || leaf.blank || continues || (leaf.code && !chained)) { at = next; continue; }
        var i = at + leaf.index;
        var close = input.charAt(i) === "[" ? _mateOf(mates, i) : -1;
        if (close === -1 || input.charAt(close + 1) !== ":" || !_isLinkLabel(input, i + 1, close)) {
          if (!leaf.code && input.charAt(i) === "[") leaf.paragraph = true;
          if (close !== -1 && close !== i + 1 && close < end && input.charAt(close + 1) === ":") {
            _readDestinationAfter(input, i, close, end, out);
          }
          at = next;
          continue;
        }
        scan = { phase: SCAN_LABEL, i: i, close: close, closer: "", textBefore: blocks.textBefore(),
                 definition: null, titleOnDestinationLine: false, resume: null, titleResume: null };
        verdict = close < end ? _scanDestination(scan, input, close + 2, end) : SCAN_CONTINUES;
      }
    }
    if (scan.definition !== null) {
      out.push(scan.definition);
      scan.definition = null;
    }
    if (verdict === SCAN_DEFINED) {
      blocks.commit();
      blocks.definition(scan.textBefore);
      defined = true;
      leaf.paragraph = false;
      previous = leaf;
      scan = null;
      at = next;
      continue;
    }
    if (verdict === SCAN_CONTINUES || verdict === SCAN_TITLE_STARTS) {
      var point = { at: next, previous: leaf, fences: fences.length, mark: blocks.mark() };
      if (scan.resume === null) scan.resume = point;
      if (verdict === SCAN_TITLE_STARTS) {
        scan.titleResume = point;
        scan.phase = SCAN_TITLE;
      }
      previous = leaf;
      at = next;
      continue;
    }
    if (scan.resume === null) {
      leaf.paragraph = true;
      at = next;
    } else {
      var resume = verdict === SCAN_NO_TITLE ? scan.titleResume : scan.resume;
      blocks.rollback(resume.mark);
      at = resume.at;
      previous = resume.previous;
      fences.length = resume.fences;
      if (verdict === SCAN_NO_TITLE) {
        blocks.definition(scan.textBefore);
        previous.paragraph = false;
      } else {
        previous.paragraph = true;
      }
    }
    defined = verdict === SCAN_NO_TITLE;
    scan = null;
  }
  return { definitions: out, fences: fences };
}

function _scanFailure(scan) {
  return scan.phase === SCAN_TITLE && !scan.titleOnDestinationLine ? SCAN_NO_TITLE : SCAN_FAILS;
}

function _scanLine(scan, input, at, end, leaf, state) {
  if (state !== 0 || leaf.blank || leaf.opens || !leaf.text) return _scanFailure(scan);
  if (scan.phase === SCAN_LABEL) {
    return scan.close < end ? _scanDestination(scan, input, scan.close + 2, end) : SCAN_CONTINUES;
  }
  var from = at + leaf.index;
  if (scan.phase === SCAN_DESTINATION) return _scanDestination(scan, input, from, end);
  var run;
  if (scan.closer === "") {
    scan.closer = _titleCloserFor(input.charAt(from));
    if (scan.closer === "") return SCAN_NO_TITLE;
    run = _titleRunIn(input, from + 1, end, scan.closer);
  } else {
    run = _titleRunIn(input, from, end, scan.closer);
  }
  if (run === TITLE_CLOSED) return SCAN_DEFINED;
  return run === TITLE_OPEN ? SCAN_CONTINUES : _scanFailure(scan);
}

function _scanDestination(scan, input, from, end) {
  var urlStart = _skipSpaceOrTab(input, from);
  if (urlStart >= end) {
    if (scan.phase === SCAN_DESTINATION) return SCAN_FAILS;
    scan.phase = SCAN_DESTINATION;
    return SCAN_CONTINUES;
  }
  var target = _destinationEnd(input, urlStart, end);
  if (!target.valid) return SCAN_FAILS;
  scan.definition = { label: input.slice(scan.i + 1, scan.close), url: target.url,
                      index: scan.i, urlStart: target.urlStart };
  var run = _titleOnLine(input, target.end, end);
  if (run === TITLE_CLOSED) return SCAN_DEFINED;
  if (run === TITLE_TEXT) return SCAN_FAILS;
  scan.titleOnDestinationLine = run === TITLE_OPEN;
  scan.closer = run === TITLE_OPEN ? _titleCloserFor(input.charAt(_skipSpaceOrTab(input, target.end))) : "";
  return SCAN_TITLE_STARTS;
}

function _readDestinationAfter(input, i, close, end, out) {
  var urlStart = _skipSpaceOrTab(input, close + 2);
  if (urlStart >= end) return;
  var target = _destinationEnd(input, urlStart, end);
  if (!target.valid) return;
  out.push({ label: input.slice(i + 1, close), url: target.url, index: i, urlStart: target.urlStart });
}

function _isLinkLabel(s, from, to) {
  var content = false;
  for (var i = from; i < to; i += 1) {
    var ch = s.charAt(i);
    if (ch === "\\") { i += 1; content = true; continue; }
    if (ch === "[" || ch === "]") return false;
    if (!content && !markupTokenizer.isMarkupSpace(s.charCodeAt(i))) content = true;
  }
  return content;
}

function _inheritDepth(leaf, previous) {
  if (previous === null || leaf.depth >= previous.depth) return;
  leaf.ownDepth = leaf.depth;
  leaf.depth = previous.depth;
}

var TABLE_DELIMITER_CHARS = "|-: \t";

function _tableStartsAt(input, previous, leaf) {
  if (previous === null || previous.blank || leaf.blank || leaf.opens || leaf.code || previous.code ||
      !previous.text || previous.lazyOk === false || previous.ownDepth !== undefined ||
      leaf.depth !== previous.depth) {
    return false;
  }
  var cells = _tableDelimiterCells(input, leaf.at + leaf.index, leaf.end);
  return cells > 0 && cells === _tableHeaderCells(input, previous.at + previous.index, previous.end);
}

function _tableDelimiterCells(s, from, end) {
  while (end > from && _isSpaceOrTab(s.charAt(end - 1))) end -= 1;
  if (end - from < 2) return -1;
  var first = s.charAt(from);
  var second = s.charAt(from + 1);
  if (first !== "|" && first !== "-" && first !== ":") return -1;
  if (TABLE_DELIMITER_CHARS.indexOf(second) === -1 || (first === "-" && _isSpaceOrTab(second))) return -1;
  var cells = 0;
  var cellStart = from;
  for (var i = from; i <= end; i += 1) {
    if (i < end && s.charAt(i) !== "|") {
      if (TABLE_DELIMITER_CHARS.indexOf(s.charAt(i)) === -1) return -1;
      continue;
    }
    var a = cellStart;
    var z = i;
    while (a < z && _isSpaceOrTab(s.charAt(a))) a += 1;
    while (z > a && _isSpaceOrTab(s.charAt(z - 1))) z -= 1;
    if (a === z) {
      if (cellStart !== from && i !== end) return -1;
    } else {
      if (s.charAt(a) === ":") a += 1;
      if (z > a && s.charAt(z - 1) === ":") z -= 1;
      if (a === z) return -1;
      for (var d = a; d < z; d += 1) if (s.charAt(d) !== "-") return -1;
      cells += 1;
    }
    cellStart = i + 1;
  }
  return cells;
}

function _tableHeaderCells(s, from, end) {
  while (end > from && _isSpaceOrTab(s.charAt(end - 1))) end -= 1;
  var cells = [];
  var cellStart = from;
  var escaped = false;
  var sawPipe = false;
  for (var i = from; i < end; i += 1) {
    var ch = s.charAt(i);
    if (ch === "|") {
      sawPipe = true;
      if (!escaped) {
        cells.push(i > cellStart);
        cellStart = i + 1;
      }
    }
    escaped = ch === "\\";
  }
  if (!sawPipe) return -1;
  cells.push(end > cellStart);
  if (cells.length > 0 && cells[0] === false) cells.shift();
  if (cells.length > 0 && cells[cells.length - 1] === false) cells.pop();
  return cells.length;
}

var TITLE_PENDING = 4;

function _destinationEnd(s, from, end) {
  if (s.charAt(from) === "<") {
    var c = from + 1;
    while (c < end && s.charAt(c) !== ">" && s.charAt(c) !== "<") {
      c += s.charAt(c) === "\\" ? 2 : 1;
    }
    if (c < end && s.charAt(c) === ">") {
      return { end: c + 1, url: s.slice(from + 1, c), urlStart: from + 1, valid: true };
    }
    return { end: from, url: "", urlStart: from, valid: false };
  }
  var u = from;
  var depth = 0;
  while (u < end && !markupTokenizer.isMarkupSpace(s.charCodeAt(u))) {
    var ch = s.charAt(u);
    if (ch === "\\" && u + 1 < end) { u += 2; continue; }
    if (ch === "(") depth += 1;
    else if (ch === ")") { if (depth === 0) break; depth -= 1; }
    u += 1;
  }
  return { end: u, url: s.slice(from, u), urlStart: from, valid: depth === 0 && u > from };
}

function _titleOnLine(s, from, end) {
  var rest = _skipSpaceOrTab(s, from);
  if (rest >= end) return TITLE_PENDING;
  var opener = _titleCloserFor(s.charAt(rest));
  return opener === "" ? TITLE_TEXT : _titleRunIn(s, rest + 1, end, opener);
}

var ATTR_BREAKING_CHARS = "<>\"'`";

var CONTAINER_MAX_INDENT = 3;
var LIST_MARKER_MAX_SPACES = 4;
var ORDERED_MARKER_MAX_DIGITS = 9;
var LIST_BULLET_CHARS = "-+*";
var TAB_STOP = 4;

function _columnAfter(column, ch) {
  return ch === "\t" ? column + TAB_STOP - (column % TAB_STOP) : column + 1;
}

function _isSpaceOrTab(ch) { return ch === " " || ch === "\t"; }

function _markerEnd(line, at) {
  var ch = line.charAt(at);
  if (ch === "") return -1;
  if (ch === ">") return at + 1;
  var d = at;
  if (LIST_BULLET_CHARS.indexOf(ch) !== -1) {
    d = at + 1;
  } else {
    while (d < line.length && d - at < ORDERED_MARKER_MAX_DIGITS &&
           _isAsciiDigitCode(line.charCodeAt(d))) d += 1;
    if (d === at || (line.charAt(d) !== "." && line.charAt(d) !== ")")) return -1;
    d += 1;
  }
  return d >= line.length || _isSpaceOrTab(line.charAt(d)) ? d : -1;
}

var HEADING_MAX_LEVEL = 6;
var THEMATIC_BREAK_MIN = 3;
var FENCE_MIN_RUN = 3;

function _markerAt(line, at, memo) {
  return _isThematicBreakAt(line, at, memo) ? -1 : _markerEnd(line, at);
}

function _markerInterrupts(line, at, markerEnd) {
  var rest = markerEnd;
  while (rest < line.length && _isSpaceOrTab(line.charAt(rest))) rest += 1;
  if (rest >= line.length) return false;
  if (LIST_BULLET_CHARS.indexOf(line.charAt(at)) !== -1) return true;
  return line.charAt(at) === "1" && !_isAsciiDigitCode(line.charCodeAt(at + 1));
}

function _isRunLine(line, at, ch) {
  var end = at;
  while (end < line.length && line.charAt(end) === ch) end += 1;
  if (end === at) return false;
  while (end < line.length && _isSpaceOrTab(line.charAt(end))) end += 1;
  return end >= line.length;
}

function _breakMemo() {
  return { ch: "", from: 0, bad: -1, count: 0 };
}

function _isThematicBreakAt(line, at, memo) {
  var ch = line.charAt(at);
  if (ch !== "*" && ch !== "_" && ch !== "-") return false;
  var t;
  if (memo.ch === ch && memo.from <= at && at < memo.bad) {
    for (t = memo.from; t < at; t += 1) {
      if (line.charAt(t) === ch) memo.count -= 1;
    }
    memo.from = at;
    return memo.bad >= line.length && memo.count >= THEMATIC_BREAK_MIN;
  }
  var count = 0;
  for (t = at; t < line.length; t += 1) {
    if (line.charAt(t) === ch) count += 1;
    else if (!_isSpaceOrTab(line.charAt(t))) break;
  }
  memo.ch = ch;
  memo.from = at;
  memo.bad = t;
  memo.count = count;
  return t >= line.length && count >= THEMATIC_BREAK_MIN;
}

function _leafInterrupts(line, at, memo) {
  var ch = line.charAt(at);
  var end = at;
  if (ch === "#") {
    while (end < line.length && line.charAt(end) === "#") end += 1;
    return end - at <= HEADING_MAX_LEVEL &&
      (end >= line.length || _isSpaceOrTab(line.charAt(end)));
  }
  if (ch === "`" || ch === "~") {
    while (end < line.length && line.charAt(end) === ch) end += 1;
    if (end - at < FENCE_MIN_RUN) return false;
    return ch === "~" || line.indexOf("`", end) === -1;
  }
  return _isThematicBreakAt(line, at, memo);
}

function _fenceOpenAt(line, at) {
  var ch = line.charAt(at);
  if (ch !== "`" && ch !== "~") return null;
  var end = at;
  while (end < line.length && line.charAt(end) === ch) end += 1;
  if (end - at < FENCE_MIN_RUN) return null;
  if (ch === "`" && line.indexOf("`", end) !== -1) return null;
  return { ch: ch, run: end - at, info: line.slice(end) };
}

function _fenceClosesAt(line, at, fence) {
  var end = at;
  while (end < line.length && line.charAt(end) === fence.ch) end += 1;
  if (end - at < fence.run) return false;
  while (end < line.length && _isSpaceOrTab(line.charAt(end))) end += 1;
  return end >= line.length;
}

var LEAF_FENCE_OPENS = 1;
var LEAF_FENCE_CONTENT = 2;
var LEAF_FENCE_CLOSES = 3;
var LEAF_HTML = 4;
var LEAF_HTML_ENDS = 5;

var HTML_RAW_TAGS = Object.freeze(["script", "pre", "style", "textarea"]);
var HTML_DELIMITED_STARTS = Object.freeze([
  { start: "<!--", end: "-->" },
  { start: "<?", end: "?>" },
  { start: "<![CDATA[", end: "]]>" },
]);
var HTML_BLOCK_TAGS = Object.freeze([
  "address", "article", "aside", "base", "basefont", "blockquote", "body",
  "caption", "center", "col", "colgroup", "dd", "details", "dialog", "dir",
  "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
  "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header",
  "hr", "html", "iframe", "legend", "li", "link", "main", "menu", "menuitem",
  "nav", "noframes", "ol", "optgroup", "option", "p", "param", "search",
  "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead",
  "title", "tr", "track", "ul",
]);

function _htmlTagNameAt(line, at, names) {
  for (var t = 0; t < names.length; t += 1) {
    var name = names[t];
    if (!codepointClass.matchesAtFolded(line, at, name)) continue;
    var after = line.charAt(at + name.length);
    if (after === "" || after === ">" || _isSpaceOrTab(after)) return name;
    if (after === "/" && line.charAt(at + name.length + 1) === ">") return name;
  }
  return null;
}

var ATTR_NAME_START_CHARS = codepointClass.ASCII_ALPHA + "_:";
var ATTR_NAME_CHARS = codepointClass.ASCII_ALNUM + "_.:-";
var UNQUOTED_VALUE_STOP_CHARS = " \t\"'=<>`";

function _skipSpaceOrTab(line, at) {
  while (at < line.length && _isSpaceOrTab(line.charAt(at))) at += 1;
  return at;
}

function _attributeEnd(line, at) {
  if (ATTR_NAME_START_CHARS.indexOf(line.charAt(at)) === -1 || at >= line.length) return -1;
  var i = at + 1;
  while (i < line.length && ATTR_NAME_CHARS.indexOf(line.charAt(i)) !== -1) i += 1;
  var eq = _skipSpaceOrTab(line, i);
  if (line.charAt(eq) !== "=") return i;
  var v = _skipSpaceOrTab(line, eq + 1);
  var quote = line.charAt(v);
  if (quote === "\"" || quote === "'") {
    var close = line.indexOf(quote, v + 1);
    return close === -1 ? -1 : close + 1;
  }
  var u = v;
  while (u < line.length && UNQUOTED_VALUE_STOP_CHARS.indexOf(line.charAt(u)) === -1) u += 1;
  return u === v ? -1 : u;
}

function _isLoneTagLine(line, at) {
  var i = at + 1;
  var closing = line.charAt(i) === "/";
  if (closing) i += 1;
  var nameStart = i;
  if (!codepointClass.isAsciiLetter(line.charCodeAt(i))) return false;
  while (i < line.length &&
         (codepointClass.isAsciiAlnum(line.charCodeAt(i)) || line.charAt(i) === "-")) i += 1;
  if (!closing && HTML_RAW_TAGS.indexOf(line.slice(nameStart, i).toLowerCase()) !== -1) return false;
  for (;;) {
    var s = _skipSpaceOrTab(line, i);
    var ch = line.charAt(s);
    if (ch === ">") { i = s + 1; break; }
    if (!closing && ch === "/" && line.charAt(s + 1) === ">") { i = s + 2; break; }
    if (closing || s === i) return false;
    i = _attributeEnd(line, s);
    if (i === -1) return false;
  }
  return _skipSpaceOrTab(line, i) >= line.length;
}

function _htmlBlockAt(line, at, paragraphOpen) {
  if (line.charAt(at) !== "<") return null;
  for (var i = 0; i < HTML_DELIMITED_STARTS.length; i += 1) {
    if (line.startsWith(HTML_DELIMITED_STARTS[i].start, at)) {
      return { end: HTML_DELIMITED_STARTS[i].end };
    }
  }
  if (line.charAt(at + 1) === "!" && _isAsciiUpperCode(line.charCodeAt(at + 2))) {
    return { end: ">" };
  }
  if (_htmlTagNameAt(line, at + 1, HTML_RAW_TAGS) !== null) return { end: HTML_RAW_END };
  var nameAt = line.charAt(at + 1) === "/" ? at + 2 : at + 1;
  if (_htmlTagNameAt(line, nameAt, HTML_BLOCK_TAGS) !== null) return { end: null };
  if (!paragraphOpen && _isLoneTagLine(line, at)) return { end: null };
  return null;
}

var HTML_RAW_END = Object.freeze(HTML_RAW_TAGS.map(function (name) { return "</" + name + ">"; }));

function _htmlBlockEndsIn(line, end, from) {
  if (typeof end === "string") return codepointClass.indexOfFolded(line, end, from) !== -1;
  for (var i = 0; i < end.length; i += 1) {
    if (codepointClass.indexOfFolded(line, end[i], from) !== -1) return true;
  }
  return false;
}

function _restorePush(cols, depth, value) {
  return function () { cols[depth].push(value); };
}

function _restoreCounter(counters, depth, value) {
  return function () { counters[depth] = value; };
}

function _restoreOpen(cols, depth) {
  var created = cols[depth] === undefined;
  var length = cols.length;
  return function () {
    if (!created) { cols[depth].pop(); return; }
    if (depth >= length) cols.length = length;
    else cols[depth] = undefined;
  };
}

function _restoreArrays(cols, blank, prefix) {
  var blankCopy = prefix === -1 ? blank.slice() : blank.slice(0, prefix + 1);
  var blankLength = blank.length;
  var colsCopy = prefix === -1
    ? cols.map(function (list) { return list === undefined ? undefined : list.slice(); }) : null;
  var colsLength = cols.length;
  return function () {
    for (var j = 0; j < blankCopy.length; j += 1) blank[j] = blankCopy[j];
    blank.length = blankLength;
    if (colsCopy === null) return;
    for (var k = 0; k < colsCopy.length; k += 1) {
      if (colsCopy[k] === undefined) { cols[k] = undefined; continue; }
      if (cols[k] === undefined) cols[k] = [];
      cols[k].length = 0;
      for (var m = 0; m < colsCopy[k].length; m += 1) cols[k].push(colsCopy[k][m]);
    }
    cols.length = colsLength;
  };
}

function _blockTracker(reading) {
  var cols = [];
  var blank = [];
  var pops = [];
  var armed = -1;
  var opened = false;
  var lazy = false;
  var paragraph = false;
  var paragraphText = false;
  var textBefore = false;
  var previousDepth = 0;
  var leafBlock = null;
  var html = null;
  var openedInfo = "";
  var scanning = false;
  var table = false;
  var journal = null;
  function noteScalars() {
    if (journal === null) return;
    var a = armed, o = opened, l = lazy, p = paragraph, pt = paragraphText, tb = textBefore;
    var pd = previousDepth, lb = leafBlock, h = html, oi = openedInfo, t = table;
    journal.push(function () {
      armed = a; opened = o; lazy = l; paragraph = p; paragraphText = pt; textBefore = tb;
      previousDepth = pd; leafBlock = lb; html = h; openedInfo = oi; table = t;
    });
  }
  return {
    lazy: function () { return lazy; },
    paragraph: function () { return paragraph; },
    paragraphText: function () { return paragraphText; },
    textBefore: function () { return textBefore; },
    definition: function (before) {
      noteScalars();
      paragraphText = before === undefined ? textBefore : before;
      paragraph = false;
      if (!reading.commonmark) lazy = false;
    },
    scanning: function (open) {
      if (open !== undefined) scanning = open;
      return scanning;
    },
    table: function (open) {
      if (open === true) {
        noteScalars();
        table = true;
        lazy = false;
        paragraph = false;
        paragraphText = false;
      }
      return table;
    },
    mark: function () {
      if (journal === null) journal = [];
      return journal.length;
    },
    commit: function () { journal = null; },
    rollback: function (position) {
      var undo = journal;
      journal = null;
      for (var k = undo.length - 1; k >= position; k -= 1) undo[k]();
    },
    previousDepth: function () { return previousDepth; },
    base: function (depth) {
      var list = cols[depth];
      return list === undefined || list.length === 0 ? 0 : list[list.length - 1];
    },
    landing: function (depth, indent) {
      var list = cols[depth];
      if (list === undefined || list.length === 0 || list[0] > indent) return 0;
      var lo = 0;
      var hi = list.length - 1;
      while (lo < hi) {
        var mid = (lo + hi + 1) >> 1;
        if (list[mid] <= indent) lo = mid;
        else hi = mid - 1;
      }
      return list[lo];
    },
    enter: function (depth, indent, interrupts) {
      if (blank[depth] !== true && !interrupts && lazy) return false;
      var list = cols[depth];
      var popped = false;
      while (list !== undefined && list.length > 0 && list[list.length - 1] > indent) {
        var col = list.pop();
        if (journal !== null) journal.push(_restorePush(cols, depth, col));
        popped = true;
      }
      if (popped) {
        if (journal !== null) journal.push(_restoreCounter(pops, depth, pops[depth]));
        pops[depth] = (pops[depth] || 0) + 1;
      }
      return popped;
    },
    leafLine: function (line, leaf) {
      noteScalars();
      if (leafBlock !== null &&
          (leaf.depth < leafBlock.depth || (pops[leafBlock.depth] || 0) !== leafBlock.pops)) {
        leafBlock = null;
      }
      if (leafBlock !== null) {
        if (!leaf.blank && !leaf.code && _fenceClosesAt(line, leaf.index, leafBlock)) {
          leafBlock = null;
          return LEAF_FENCE_CLOSES;
        }
        return LEAF_FENCE_CONTENT;
      }
      if (html !== null &&
          (leaf.depth < html.depth || (pops[html.depth] || 0) !== html.pops)) html = null;
      if (html !== null) {
        var ends = html.end === null
          ? leaf.blank : _htmlBlockEndsIn(line, html.end, leaf.blank ? 0 : leaf.index);
        if (!ends) return LEAF_HTML;
        html = null;
        if (leaf.blank) return 0;
        paragraph = false;
        paragraphText = false;
        leaf.paragraph = false;
        return LEAF_HTML_ENDS;
      }
      if (leaf.blank || leaf.code) return 0;
      if (leaf.html !== null) {
        if (leaf.html.end === null || !_htmlBlockEndsIn(line, leaf.html.end, leaf.index + 1)) {
          html = { end: leaf.html.end, depth: leaf.depth, pops: pops[leaf.depth] || 0 };
          return LEAF_HTML;
        }
        paragraph = false;
        paragraphText = false;
        leaf.paragraph = false;
        return LEAF_HTML_ENDS;
      }
      var opening = _fenceOpenAt(line, leaf.index);
      if (opening === null) return 0;
      openedInfo = opening.info;
      leafBlock = {
        ch: opening.ch, run: opening.run,
        depth: leaf.depth, pops: pops[leaf.depth] || 0,
      };
      return LEAF_FENCE_OPENS;
    },
    fenceInfo: function () { return openedInfo; },
    inHtml: function () { return html !== null; },
    reading: function () { return reading; },
    leafDepth: function () {
      if (leafBlock !== null) return leafBlock.depth;
      return html === null ? -1 : html.depth;
    },
    dropLeaf: function () { noteScalars(); leafBlock = null; html = null; },
    open: function (depth, col) {
      noteScalars();
      if (journal !== null) journal.push(_restoreOpen(cols, depth));
      if (cols[depth] === undefined) cols[depth] = [];
      cols[depth].push(col);
      opened = true;
    },
    line: function (depth, isBlank, text, startsNoDefinition, opens, lazyOk) {
      noteScalars();
      var isText = !isBlank && text === true;
      var lazyLine = isText && lazy && !opens && depth < previousDepth;
      var closes = !isBlank && !lazyLine && depth + 1 < cols.length;
      if (journal !== null) journal.push(_restoreArrays(cols, blank, isBlank || closes ? -1 : depth));
      if (closes) {
        cols.length = depth + 1;
        if (blank.length > depth + 1) blank.length = depth + 1;
      }
      var continuing = isText && lazy && !opens;
      textBefore = continuing ? paragraphText : false;
      lazy = isText && lazyOk !== false;
      paragraph = !isBlank && startsNoDefinition === true;
      paragraphText = isText;
      if (table) {
        table = isText && !opens && depth >= previousDepth;
        if (table) { lazy = false; paragraph = false; paragraphText = false; }
      }
      if (!lazyLine) previousDepth = depth;
      for (var j = 0; j < depth; j += 1) blank[j] = false;
      blank[depth] = isBlank;
      if (isBlank && armed === depth && !opened && cols[depth] !== undefined) cols[depth].pop();
      armed = isBlank && opened ? depth : -1;
      opened = false;
      if (isBlank && cols.length > depth + 1) cols.length = depth + 1;
      if (isBlank && blank.length > depth + 1) blank.length = depth + 1;
    },
  };
}

var PARAGRAPH_ENDING_CHARS = "=|[";

function _leafStart(line, blocks) {
  var i = 0;
  var column = 0;
  var carried = 0;
  var depth = 0;
  var residual = 0;
  var base = 0;
  var entered = false;
  var opens = false;
  var fenceDepth = blocks.leafDepth();
  var fenced = fenceDepth >= 0;
  var commonmark = blocks.reading().commonmark;
  var htmlBlocks = blocks.reading().html;
  var scanning = !commonmark && blocks.scanning();
  var tabled = !commonmark && blocks.table();
  var breakMemo = _breakMemo();
  for (;;) {
    var j = i;
    var runColumn = column;
    while (j < line.length && _isSpaceOrTab(line.charAt(j))) {
      runColumn = _columnAfter(runColumn, line.charAt(j));
      j += 1;
    }
    if (j >= line.length) {
      blocks.line(depth, true, false, false, opens);
      return {
        index: j, blank: true, code: false, text: false, html: null, depth: depth,
        opens: opens, paragraph: false,
      };
    }
    var indent = runColumn - residual;
    var scanDeep = scanning && indent - blocks.base(depth) > CONTAINER_MAX_INDENT &&
      !(line.charAt(j) === ">" && depth < blocks.previousDepth());
    var deep = scanDeep || (!fenced && line.charAt(j) !== ">" &&
      indent - blocks.landing(depth, indent) > CONTAINER_MAX_INDENT);
    var markerEnd = fenced
      ? (depth < fenceDepth && line.charAt(j) === ">" ? j + 1 : -1)
      : deep ? -1 : _markerAt(line, j, breakMemo);
    if (fenced && depth < fenceDepth && markerEnd === -1) {
      fenced = false;
      blocks.dropLeaf();
      markerEnd = _markerAt(line, j, breakMemo);
    }
    var inParagraph = !opens && !scanning && !tabled &&
      (commonmark ? blocks.lazy() : blocks.paragraphText()) &&
      depth === blocks.previousDepth() && indent >= blocks.base(depth);
    if (markerEnd !== -1 && line.charAt(j) !== ">" && inParagraph &&
        !_markerInterrupts(line, j, markerEnd)) {
      markerEnd = -1;
    }
    var html = fenced || markerEnd !== -1 || !htmlBlocks || scanning || deep
      ? null : _htmlBlockAt(line, j, inParagraph || tabled || (!opens && blocks.lazy()));
    var erasedInItem = deep && !scanDeep && !commonmark && !fenced && depth === blocks.previousDepth() &&
      indent < blocks.base(depth) &&
      (_leafInterrupts(line, j, breakMemo) || (htmlBlocks && _htmlBlockAt(line, j, true) !== null));
    if (!entered) {
      var interrupts = !fenced && (erasedInItem || (!deep &&
        (markerEnd !== -1 || html !== null || _leafInterrupts(line, j, breakMemo))));
      if (blocks.enter(depth, runColumn - residual, interrupts)) {
        opens = true;
        inParagraph = false;
        if (fenced) {
          fenced = false;
          blocks.dropLeaf();
          markerEnd = _markerAt(line, j, breakMemo);
          html = markerEnd !== -1 || !htmlBlocks ? null : _htmlBlockAt(line, j, blocks.lazy());
        }
      }
      base = residual + blocks.base(depth);
      entered = true;
    }
    var rel = runColumn - base;
    if (!commonmark && rel > CONTAINER_MAX_INDENT && line.charAt(j) === ">" &&
        depth < blocks.previousDepth() && markerEnd !== -1) {
      rel = 0;
    }
    if (rel > CONTAINER_MAX_INDENT) {
      var erased = !commonmark && blocks.previousDepth() >= depth + 2 &&
        (_markerAt(line, j, breakMemo) !== -1 || _leafInterrupts(line, j, breakMemo) ||
         (htmlBlocks && _htmlBlockAt(line, j, true) !== null));
      var shallower = !commonmark && (erased || (!scanning && !blocks.lazy())) && depth < blocks.previousDepth();
      var lazy = !fenced && !opens && !shallower && !erasedInItem && (scanning || blocks.lazy());
      var continued = !fenced && !opens && !shallower && blocks.paragraph();
      blocks.line(depth, false, lazy, continued, opens);
      return {
        index: j, blank: false, code: true, text: lazy, html: null, depth: depth,
        opens: opens, paragraph: continued,
      };
    }
    if (markerEnd === -1) {
      var text = !fenced && (deep || !_leafInterrupts(line, j, breakMemo));
      var paragraph = text && PARAGRAPH_ENDING_CHARS.indexOf(line.charAt(j)) === -1;
      var ch = line.charAt(j);
      var underline = false;
      if (text && (ch === "=" || ch === "-") && _isRunLine(line, j, ch) && !scanning) {
        underline = inParagraph && blocks.paragraphText();
        text = !underline;
        paragraph = !underline;
      }
      var lazyOk = text && !fenced && html === null && !blocks.inHtml();
      blocks.line(depth, false, text, paragraph, opens, lazyOk);
      return {
        index: j, blank: false, code: false, text: text, underline: underline, lazyOk: lazyOk,
        html: fenced ? null : html, depth: depth, opens: opens, paragraph: paragraph,
      };
    }
    if (line.charAt(j) === ">") {
      if (depth + 1 > blocks.previousDepth()) opens = true;
    } else {
      opens = true;
    }
    column = runColumn;
    for (var k = j; k < markerEnd; k += 1) column = _columnAfter(column, line.charAt(k));
    i = markerEnd;
    carried = 0;
    if (line.charAt(j) === ">") {
      if (line.charAt(i) === " ") { column += 1; i += 1; }
      else if (line.charAt(i) === "\t") {
        var stop = _columnAfter(column, "\t");
        carried = stop - column - 1;
        column = stop;
        i += 1;
      }
      depth += 1;
      residual = column - carried;
      entered = false;
      continue;
    }
    var s = i;
    var sColumn = column;
    while (s < line.length && _isSpaceOrTab(line.charAt(s))) {
      sColumn = _columnAfter(sColumn, line.charAt(s));
      s += 1;
    }
    if (s >= line.length || sColumn - column > LIST_MARKER_MAX_SPACES) {
      if (line.charAt(i) === "\t") {
        var tabStop = _columnAfter(column, "\t");
        carried = tabStop - column - 1;
        column = tabStop;
      } else {
        column += 1;
      }
      i = s >= line.length ? s : i + 1;
    } else {
      i = s;
      column = sColumn;
    }
    base = column - carried;
    blocks.open(depth, base - residual);
  }
}

function _codeFenceLangs(input, mates, rawMates) {
  if (mates === undefined) {
    var codeSpans = _codeSpans(input);
    mates = _squareMates(input, undefined, codeSpans);
    rawMates = codeSpans.quoted ? _squareMates(input, undefined, null) : null;
  }
  var found = [];
  var seen = new Set();
  var mateSets = rawMates === null || rawMates === undefined ? [mates] : [mates, rawMates];
  var readings = _readingsFor(input);
  for (var s = 0; s < mateSets.length; s += 1) {
    for (var r = 0; r < readings.length; r += 1) {
      var fences = _readBlocks(input, mateSets[s], readings[r]).fences;
      for (var f = 0; f < fences.length; f += 1) {
        if (seen.has(fences[f].at)) continue;
        seen.add(fences[f].at);
        found.push(fences[f]);
      }
    }
  }
  found.sort(function (a, b) { return a.at - b.at; });
  return found.map(function (fence) { return fence.info; });
}

var UNICODE_LINE_BREAK_RANGES = [0x2028, 0x2029];

function _lineEndAt(s, at, unicodeBreaks) {
  var i = at;
  while (i < s.length) {
    var c = s.charCodeAt(i);
    if (c === 0x0A || c === 0x0D) break;
    if (unicodeBreaks === true && (c === 0x2028 || c === 0x2029)) break;
    i += 1;
  }
  return i;
}

function _nextLineStart(s, end) {
  if (end >= s.length) return s.length;
  if (s.charCodeAt(end) === 0x0D && s.charCodeAt(end + 1) === 0x0A) return end + 2;
  return end + 1;
}

function _markdownLines(s) {
  var out = [];
  var start = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (!codepointClass.inRanges(s.charCodeAt(i),
                                 codepointClass.LINE_TERMINATOR_RANGES)) continue;
    out.push(s.slice(start, i));
    if (s.charCodeAt(i) === 0x0D && s.charCodeAt(i + 1) === 0x0A) i += 1;
    start = i + 1;
  }
  out.push(s.slice(start));
  return out;
}

function _hasFrontMatter(s, fence) {
  if (s.slice(0, fence.length) !== fence) return false;
  var afterOpen = markupTokenizer.skipMarkupSpace(s, fence.length);
  var firstLf = s.indexOf("\n", fence.length);
  if (firstLf === -1 || afterOpen < firstLf) return false;
  for (var i = firstLf + 1; i < s.length; i += 1) {
    if (s.charCodeAt(i - 1) !== 0x0A) continue;
    if (s.slice(i, i + fence.length) !== fence) continue;
    var afterClose = i + fence.length;
    while (afterClose < s.length &&
           (s.charCodeAt(afterClose) === 0x20 || s.charCodeAt(afterClose) === 0x09)) {
      afterClose += 1;
    }
    if (afterClose < s.length && s.charCodeAt(afterClose) !== 0x0A &&
        s.charCodeAt(afterClose) !== 0x0D) continue;
    if (i < firstLf + 3) continue;
    return true;
  }
  return false;
}

function _hasHtmlComment(s) {
  var at = s.indexOf("<!--");
  return at !== -1 && markupTokenizer.htmlCommentEnd(s, at) !== -1;
}

function _hasDoctype(s) {
  for (var i = 0; i + 9 <= s.length; i += 1) {
    if (!codepointClass.containsFolded(s.slice(i, i + 9), "<!DOCTYPE")) continue;
    if (_endsName(s.charAt(i + 9))) return true;
  }
  return false;
}

var EMPHASIS_RUN_FLOOR = 20;
var EMPHASIS_CHARS = "*_";

function _hasLongEmphasisRun(s) {
  var run = 0;
  for (var i = 0; i < s.length; i += 1) {
    if (EMPHASIS_CHARS.indexOf(s.charAt(i)) !== -1) {
      run += 1;
      if (run >= EMPHASIS_RUN_FLOOR) return true;
    } else {
      run = 0;
    }
  }
  return false;
}


var SCHEME_RAW_PREFIX = 24;

function _rawPrefixIsPlain(url) {
  var n = Math.min(url.length, SCHEME_RAW_PREFIX);
  for (var i = 0; i < n; i += 1) {
    var c = url.charCodeAt(i);
    if (c < 0x21 || c > 0x7E || c === 0x26 || c === 0x25) return false;
  }
  return true;
}

function _isDangerousUrl(url, opts) {
  if (typeof url !== "string") return null;
  var s;
  if (_rawPrefixIsPlain(url)) {
    s = url.slice(0, SCHEME_RAW_PREFIX);
  } else {
    s = codepointClass.stripUrlSchemeWhitespace(
      codepointClass.decodeMarkupEntities(url.trim()));
  }
  return _classifyNormalized(s, opts);
}

function _classifyNormalized(s, opts) {
  if (_leadingSchemeOf(s, DANGEROUS_SCHEMES) !== null) return _leadingLetterRun(s);
  if (_leadingSchemeOf(s, ["file"]) !== null && opts.filePolicy !== "allow") return "file";
  return null;
}

var SCHEME_SIGNIFICANT_CHARS = 32;

function _readAt(input, pos) {
  if (input.charCodeAt(pos) === 0x26) {
    var ref = codepointClass.decodeReferenceAt(input, pos);
    if (ref !== null) return ref;
  }
  var cp = input.codePointAt(pos);
  var text = String.fromCodePoint(cp);
  return { text: text, next: pos + text.length };
}

function _textIsStrippable(text) {
  for (var k = 0; k < text.length; k += 1) {
    var cp = text.codePointAt(k);
    if (!codepointClass.isUrlSchemeStrippable(cp)) return false;
    if (cp > 0xFFFF) k += 1;
  }
  return true;
}

function _textIsStrippableAnywhere(text) {
  for (var k = 0; k < text.length; k += 1) {
    var cp = text.codePointAt(k);
    if (cp === 0x20 || !codepointClass.isUrlSchemeStrippable(cp)) return false;
    if (cp > 0xFFFF) k += 1;
  }
  return true;
}

function _makeSkipIndex(input, isSkippable) {
  var n = input.length;
  var nextSig = _makeSpanIndex();
  return function (i, end) {
    if (i >= end) return end;
    var known = nextSig.find(i);
    if (known !== undefined) return Math.min(known, end);
    var j = i;
    while (j < end) {
      var ahead = nextSig.find(j);
      if (ahead !== undefined) { j = ahead; break; }
      var r = _readAt(input, j);
      if (!isSkippable(r.text)) break;
      j = r.next;
    }
    nextSig.add(i, Math.min(j, n) - 1, j);
    return Math.min(j, end);
  };
}

function _textIsMarkupSpace(text) {
  if (text.length === 0) return false;
  var cp = text.codePointAt(0);
  if (String.fromCodePoint(cp).length !== text.length) return false;
  return codepointClass.inRanges(cp, codepointClass.WHITESPACE_RANGES);
}

function _textIsSpaceOrStrippableAnywhere(text) {
  return _textIsMarkupSpace(text) || _textIsStrippableAnywhere(text);
}

function _makeSignificantIndex(input) {
  return {
    lead: _makeSkipIndex(input, _textIsStrippable),
    any:  _makeSkipIndex(input, _textIsStrippableAnywhere),
    ws:   _makeSkipIndex(input, _textIsSpaceOrStrippableAnywhere),
  };
}

function _schemePrefixAt(input, start, end, sig) {
  var out = "";
  var pos = sig.lead(start, end);
  var count = 0;
  while (pos < end && count < SCHEME_SIGNIFICANT_CHARS) {
    var r = _readAt(input, pos);
    if (_textIsMarkupSpace(r.text)) {
      if (out.charAt(out.length - 1) !== " ") { out += " "; count += 1; }
      pos = sig.ws(r.next, end);
      continue;
    }
    out += r.text;
    count += 1;
    pos = sig.any(r.next, end);
  }
  return out;
}

function _isDangerousUrlAt(input, start, end, sig, opts) {
  return _classifyNormalized(_schemePrefixAt(input, start, end, sig), opts);
}

var PROFILES = Object.freeze({
  "strict": {
    rawHtmlPolicy:          "reject",
    dangerousTagPolicy:     "reject",
    dangerousSchemePolicy:  "reject",
    autolinkSchemePolicy:   "reject",
    referenceLinkPolicy:    "reject",
    imageSchemePolicy:      "reject",
    htmlCommentPolicy:      "reject",
    frontMatterPolicy:      "reject",
    codeFenceLangPolicy:    "reject",
    doctypePolicy:          "reject",
    emphasisRunPolicy:      "reject",
    filePolicy:             "reject",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    maxBytes:               C.BYTES.mib(1),
    maxLines:               4096,
    maxLinks:               256,
    maxImages:              128,
    maxAutolinks:           128,
    maxRefDefs:             64,
    maxListDepth:           16,
    maxBlockquoteDepth:     16,
  },
  "balanced": {
    rawHtmlPolicy:          "audit",
    dangerousTagPolicy:     "reject",
    dangerousSchemePolicy:  "reject",
    autolinkSchemePolicy:   "reject",
    referenceLinkPolicy:    "audit",
    imageSchemePolicy:      "reject",
    htmlCommentPolicy:      "audit",
    frontMatterPolicy:      "audit",
    codeFenceLangPolicy:    "audit",
    doctypePolicy:          "reject",
    emphasisRunPolicy:      "audit",
    filePolicy:             "reject",
    bidiPolicy:             "strip",
    controlPolicy:          "strip",
    nullBytePolicy:         "strip",
    zeroWidthPolicy:        "strip",
    maxBytes:               C.BYTES.mib(8),
    maxLines:               32768,
    maxLinks:               2048,
    maxImages:              1024,
    maxAutolinks:           1024,
    maxRefDefs:             512,
    maxListDepth:           64,
    maxBlockquoteDepth:     64,
  },
  "permissive": {
    rawHtmlPolicy:          "allow",
    dangerousTagPolicy:     "reject",
    dangerousSchemePolicy:  "reject",
    autolinkSchemePolicy:   "audit",
    referenceLinkPolicy:    "allow",
    imageSchemePolicy:      "audit",
    htmlCommentPolicy:      "allow",
    frontMatterPolicy:      "allow",
    codeFenceLangPolicy:    "audit",
    doctypePolicy:          "audit",
    emphasisRunPolicy:      "audit",
    filePolicy:             "audit",
    bidiPolicy:             "audit",
    controlPolicy:          "strip",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "audit",
    maxBytes:               C.BYTES.mib(64),
    maxLines:               262144,
    maxLinks:               16384,
    maxImages:              8192,
    maxAutolinks:           8192,
    maxRefDefs:             4096,
    maxListDepth:           256,
    maxBlockquoteDepth:     256,
  },
});

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "markdown", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;
  var report = gateContract.makeIssueReporter(issues);

  var lineCount = 0;
  for (var li = 0; li < input.length; li += 1) {
    if (input.charCodeAt(li) === 10) lineCount += 1;
  }
  if (lineCount > opts.maxLines) {
    report({
      kind: "line-cap", severity: "high", ruleId: "markdown.line-cap",
      snippet: "line count " + lineCount + " exceeds maxLines " + opts.maxLines,
    });
  }

  if (opts.frontMatterPolicy !== "allow") {
    if (_hasFrontMatter(input, "---") || _hasFrontMatter(input, "+++")) {
      report({
        kind: "front-matter",
        severity: opts.frontMatterPolicy === "reject" ? "high" : "warn",
        ruleId: "markdown.front-matter",
        snippet: "leading front-matter block — payload class equals guardYaml",
      });
    }
  }

  if (opts.doctypePolicy !== "allow" && _hasDoctype(input)) {
    report({
      kind: "doctype",
      severity: opts.doctypePolicy === "reject" ? "critical" : "warn",
      ruleId: "markdown.doctype",
      snippet: "DOCTYPE in markdown source (XXE-shaped if rendered)",
    });
  }

  if (opts.dangerousTagPolicy !== "allow" && _hasDangerousTag(input)) {
    report({
      kind: "dangerous-tag", severity: "critical",
      ruleId: "markdown.dangerous-tag",
      snippet: "raw HTML tag from danger list (script/iframe/object/etc. " +
               "— whitespace-tolerant per CVE-2026-30838 class)",
    });
  }

  if (opts.rawHtmlPolicy !== "allow" && _hasRawHtmlTag(input)) {
    report({
      kind: "raw-html",
      severity: opts.rawHtmlPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.raw-html",
      snippet: "raw HTML tag in markdown source — compose with guardHtml",
    });
  }

  if (opts.htmlCommentPolicy !== "allow" && _hasHtmlComment(input)) {
    report({
      kind: "html-comment",
      severity: opts.htmlCommentPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.html-comment",
      snippet: "HTML comment block — payload-smuggling vector",
    });
  }

  var linkCount = 0;
  var imageCount = 0;
  var openers = _countOpeners(input);
  var mates = null;
  var rawMates = null;
  var inlineMatches = [];
  if (openers > MAX_VALIDATE_OPENERS) {
    report({
      kind: "delimiter-cap", severity: "high", ruleId: "markdown.delimiter-cap",
      snippet: "bracket opener count " + openers + " exceeds " + MAX_VALIDATE_OPENERS +
               ", so links and reference definitions were not extracted",
    });
  } else {
    var codeSpans = _codeSpans(input);
    var inlineLimit = opts.maxLinks + opts.maxImages + 2;
    mates = _squareMates(input, openers, codeSpans);
    inlineMatches = _inlineLinks(input, inlineLimit, mates);
    if (codeSpans.quoted) {
      rawMates = _squareMates(input, openers, null);
      inlineMatches = _unionMatches(inlineMatches,
        _inlineLinks(input, inlineLimit, rawMates));
    }
  }
  var sigIndex = _makeSignificantIndex(input);
  for (var im = 0; im < inlineMatches.length; im += 1) {
    var m = inlineMatches[im];
    var isImage = m.bang === "!";
    if (m.counted !== false) { if (isImage) imageCount += 1; else linkCount += 1; }
    var scheme = _isDangerousUrlAt(input, m.urlStart, m.urlEnd, sigIndex, opts);
    if (scheme === null) continue;
    var policy = isImage ? opts.imageSchemePolicy : opts.dangerousSchemePolicy;
    report({
      kind: isImage ? "image-scheme" : "link-scheme",
      severity: policy === "reject" ? "critical" : "high",
      ruleId: isImage ? "markdown.image-scheme" : "markdown.link-scheme",
      snippet: (isImage ? "image" : "link") +
               " uses dangerous scheme '" + scheme + ":'",
    });
    if (issues.length > 256) break;
  }
  if (linkCount > opts.maxLinks) {
    report({
      kind: "link-cap", severity: "high", ruleId: "markdown.link-cap",
      snippet: "link count " + linkCount + " exceeds maxLinks " + opts.maxLinks,
    });
  }
  if (imageCount > opts.maxImages) {
    report({
      kind: "image-cap", severity: "high", ruleId: "markdown.image-cap",
      snippet: "image count " + imageCount +
               " exceeds maxImages " + opts.maxImages,
    });
  }

  var autolinkCount = 0;
  var autolinkMatches = _autolinks(input);
  for (var am = 0; am < autolinkMatches.length; am += 1) {
    autolinkCount += 1;
    var aScheme = _isDangerousUrl(autolinkMatches[am].url, opts);
    if (aScheme === null) continue;
    report({
      kind: "autolink-scheme",
      severity: opts.autolinkSchemePolicy === "reject" ? "critical" : "high",
      ruleId: "markdown.autolink-scheme",
      snippet: "autolink uses dangerous scheme '" + aScheme + ":'",
    });
    if (issues.length > 256) break;
  }
  if (autolinkCount > opts.maxAutolinks) {
    report({
      kind: "autolink-cap", severity: "high",
      ruleId: "markdown.autolink-cap",
      snippet: "autolink count " + autolinkCount +
               " exceeds maxAutolinks " + opts.maxAutolinks,
    });
  }

  var refDefCount = 0;
  var refDefMatches = _refDefs(input, mates);
  if (rawMates !== null) {
    refDefMatches = _unionMatches(refDefMatches, _refDefs(input, rawMates));
  }
  for (var rm = 0; rm < refDefMatches.length; rm += 1) {
    if (refDefMatches[rm].counted !== false) refDefCount += 1;
    var rScheme = _isDangerousUrl(refDefMatches[rm].url, opts);
    if (rScheme === null) continue;
    report({
      kind: "reference-link-scheme",
      severity: opts.referenceLinkPolicy === "reject" ? "critical" : "high",
      ruleId: "markdown.reference-link-scheme",
      snippet: "reference-link definition uses dangerous scheme '" +
               rScheme + ":' (smuggled through `[ref]` text)",
    });
    if (issues.length > 256) break;
  }
  if (refDefCount > opts.maxRefDefs) {
    report({
      kind: "ref-def-cap", severity: "high",
      ruleId: "markdown.ref-def-cap",
      snippet: "reference-def count " + refDefCount +
               " exceeds maxRefDefs " + opts.maxRefDefs,
    });
  }

  if (opts.codeFenceLangPolicy !== "allow") {
    var fenceMatches = _codeFenceLangs(input, mates, rawMates);
    for (var fm = 0; fm < fenceMatches.length; fm += 1) {
      var lang = fenceMatches[fm];
      if (!lang) continue;
      if (codepointClass.indexOfAny(lang, ATTR_BREAKING_CHARS) !== -1) {
        report({
          kind: "code-fence-lang",
          severity: opts.codeFenceLangPolicy === "reject" ? "critical" : "high",
          ruleId: "markdown.code-fence-lang",
          snippet: "code-fence language tag contains attribute-breaking " +
                   "characters: " + JSON.stringify(lang.slice(0, 64)),
        });
        if (issues.length > 256) break;
      }
    }
  }

  if (opts.emphasisRunPolicy !== "allow" && _hasLongEmphasisRun(input)) {
    report({
      kind: "emphasis-run",
      severity: opts.emphasisRunPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.emphasis-run",
      snippet: "long *_ run — catastrophic backtracking shape (CVE-2025-6493 class)",
    });
  }

  var maxListDepthSeen = 0;
  var maxBqDepthSeen = 0;
  var lines = input.split("\n");
  for (var lj = 0; lj < lines.length; lj += 1) {
    var line = lines[lj];
    var bq = 0;
    var k = 0;
    while (k < line.length && (line.charAt(k) === " " || line.charAt(k) === ">")) {
      if (line.charAt(k) === ">") bq += 1;
      k += 1;
    }
    if (bq > maxBqDepthSeen) maxBqDepthSeen = bq;
    var leading = 0;
    while (leading < line.length && line.charAt(leading) === " ") leading += 1;
    if (leading > 0 && leading < line.length) {
      var marker = line.charAt(leading);
      if (marker === "-" || marker === "*" || marker === "+" ||
          (marker >= "0" && marker <= "9")) {
        var depth = Math.floor(leading / 2);
        if (depth > maxListDepthSeen) maxListDepthSeen = depth;
      }
    }
  }
  if (maxListDepthSeen > opts.maxListDepth) {
    report({
      kind: "list-depth-cap", severity: "high",
      ruleId: "markdown.list-depth-cap",
      snippet: "list nesting depth " + maxListDepthSeen +
               " exceeds maxListDepth " + opts.maxListDepth,
    });
  }
  if (maxBqDepthSeen > opts.maxBlockquoteDepth) {
    report({
      kind: "blockquote-depth-cap", severity: "high",
      ruleId: "markdown.blockquote-depth-cap",
      snippet: "blockquote nesting depth " + maxBqDepthSeen +
               " exceeds maxBlockquoteDepth " + opts.maxBlockquoteDepth,
    });
  }

  codepointClass.detectCharThreats(input, opts, "markdown").forEach(report);

  return issues;
}

/**
 * @primitive  b.guardMarkdown.validate
 * @signature  b.guardMarkdown.validate(input, opts?)
 * @since      0.7.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardMarkdown.sanitize, b.guardMarkdown.gate
 *
 * Inspect raw markdown source against the resolved profile and
 * return `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `markdown.bad-input` issue
 * rather than throwing — callers that prefer an exception use
 * `b.guardMarkdown.sanitize`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:          "reject"|"strip"|"allow",
 *   nullBytePolicy:         "reject"|"strip"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"allow",
 *   dangerousTagPolicy:     "reject"|"strip"|"audit"|"allow",
 *   dangerousSchemePolicy:  "reject"|"strip"|"audit"|"allow",
 *   imageSchemePolicy:      "reject"|"strip"|"audit"|"allow",
 *   autolinkSchemePolicy:   "reject"|"strip"|"audit"|"allow",
 *   referenceLinkPolicy:    "reject"|"strip"|"audit"|"allow",
 *   codeFenceLangPolicy:    "reject"|"strip"|"audit"|"allow",
 *   doctypePolicy:          "reject"|"strip"|"audit"|"allow",
 *   maxBytes:               number,
 *   maxLines:               number,
 *   maxLinks:               number,
 *   maxImages:              number,
 *   maxAutolinks:           number,
 *   maxRefDefs:             number,
 *   maxListDepth:           number,
 *   maxBlockquoteDepth:     number,
 *
 * @example
 *   var rv = b.guardMarkdown.validate("# hello\n\n[link](https://example.com)",
 *                                     { profile: "strict" });
 *   rv.ok;                                             // → true
 *
 *   var bad = b.guardMarkdown.validate("[click](javascript:alert(1))",
 *                                      { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].ruleId;                              // → "markdown.dangerous-scheme"
 */

/**
 * @primitive  b.guardMarkdown.sanitize
 * @signature  b.guardMarkdown.sanitize(input, opts?)
 * @since      0.7.16
 * @status     stable
 * @related    b.guardMarkdown.validate, b.guardMarkdown.gate
 *
 * Strip BIDI / zero-width / control / null-byte codepoints under
 * their resolved policies and return the cleaned markdown source.
 * Throws `GuardMarkdownError` when any `critical` issue fires
 * (raw `<script>`, `javascript:` link, doctype injection). Use
 * `validate` to inspect issues without throwing.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardMarkdown.validate opts,
 *
 * @example
 *   var clean = b.guardMarkdown.sanitize("hello\u200Bworld",
 *                                        { profile: "balanced" });
 *   clean;                                             // → "helloworld"
 *
 *   try {
 *     b.guardMarkdown.sanitize("<script>alert(1)</script>",
 *                              { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "markdown.dangerous-tag"
 *   }
 */
function _sanitizeTransform(input, opts) {
  return codepointClass.applyCharStripPolicies(input, opts);
}

/**
 * @primitive  b.guardMarkdown.gate
 * @signature  b.guardMarkdown.gate(opts?)
 * @since      0.7.16
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardMarkdown.validate, b.guardMarkdown.sanitize, b.guardAll.gate, b.staticServe.create
 *
 * Build a guard gate whose async `check(ctx)` returns `{ ok, action, issues }`, consumable
 * by `b.guardAll`, `b.staticServe`, `b.fileUpload`, and any host
 * that ingests user-supplied markdown. The gate decodes
 * `ctx.bytes` / `ctx.bodyText`, runs `validate`, and maps
 * severity to action: zero issues `serve`; only low/medium
 * `audit-only`; sanitizable issues `sanitize` (returning the
 * cleaned bytes); any unfixable critical `refuse`.
 *
 * @opts
 *   name:                   string,    // gate label for audit / observability
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardMarkdown.validate opts,
 *
 * @example
 *   var g = b.guardMarkdown.gate({ profile: "strict" });
 *   var rv = await g.check({ bytes: Buffer.from("# hello\n", "utf8") });
 *   rv.action;                                         // → "serve"
 *
 *   var bad = await g.check({ bytes: Buffer.from("[x](javascript:1)", "utf8") });
 *   bad.action;                                        // → "refuse"
 */
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "dangerous-tag":         return gateContract.policyDisposition(opts.dangerousTagPolicy);
    case "raw-html":              return gateContract.policyDisposition(opts.rawHtmlPolicy);
    case "html-comment":          return gateContract.policyDisposition(opts.htmlCommentPolicy);
    case "front-matter":          return gateContract.policyDisposition(opts.frontMatterPolicy);
    case "doctype":               return gateContract.policyDisposition(opts.doctypePolicy);
    case "image-scheme":
    case "link-scheme":
    case "autolink-scheme":
    case "reference-link-scheme": return "refuse";
    case "code-fence-lang":       return gateContract.policyDisposition(opts.codeFenceLangPolicy);
    case "emphasis-run":          return gateContract.policyDisposition(opts.emphasisRunPolicy);
    case "bad-input":
    case "too-large":
    case "line-cap":
    case "link-cap":
    case "image-cap":
    case "autolink-cap":
    case "ref-def-cap":
    case "list-depth-cap":
    case "delimiter-cap":
    case "blockquote-depth-cap":  return "refuse";
    default:                      return null;
  }
}

function gate(opts) {
  opts = module.exports.resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardMarkdown:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor: _gateDispositionFor,
    produceSanitized: function (text, o) { return _sanitizeTransform(text, o); },
  });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "text/markdown",
  extension:    ".md",
  benignBytes:  Buffer.from(
    "# Title\n\nA [link](https://example.com) and *emphasis*.\n", "utf8"),
  hostileBytes: Buffer.from(
    "# x\n\n[click](javascript:alert(1))\n", "utf8"),
});

var MAX_OUTPUT_AMPLIFICATION = 4;

var MIN_SOURCE_FOR_RATIO = C.BYTES.kib(64);

var _outputBudget = null;

function _charge(n) {
  if (_outputBudget === null) return;
  _outputBudget.used += n;
  if (_outputBudget.used > _outputBudget.max) {
    throw _err("markdown/output-amplification",
      "b.guardMarkdown.render: rendered output would exceed " +
      MAX_OUTPUT_AMPLIFICATION + "x the " + _outputBudget.sourceBytes +
      "-byte source. Both escaping and generated markup expand a document - " +
      "`'` becomes `&#39;`, and a link becomes an anchor carrying its rel " +
      "list - so a source written of little else can render to several times " +
      "its own size.");
  }
}

function _escapedLength(s) {
  var extra = 0;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (c === "&") extra += 4;
    else if (c === "<" || c === ">") extra += 3;
    else if (c === '"') extra += 5;
    else if (c === "'") extra += 4;
  }
  return Buffer.byteLength(s, "utf8") + extra;
}

function _escapeText(s) {
  if (_outputBudget !== null) {
    _charge(_escapedLength(s));
  }
  return markupEscape(s, { apos: "&#39;" });
}

var _ATTR_UNSAFE = "\"'<>`";

function _safeHref(url, opts) {
  if (typeof url !== "string") return null;
  if (codepointClass.firstControlCharOffset(url, { forbidTab: true }) !== -1) return null;
  var trimmed = url.trim();
  if (trimmed.length === 0) return null;
  if (_isDangerousUrl(trimmed, opts) !== null) return null;
  for (var i = 0; i < trimmed.length; i += 1) {
    if (_ATTR_UNSAFE.indexOf(trimmed.charAt(i)) !== -1) return null;
  }
  var scheme = _schemeOf(trimmed);
  if (scheme !== null && RENDER_ALLOWED_SCHEMES.indexOf(scheme) === -1) return null;
  return _escapeText(trimmed);
}

var RENDER_ALLOWED_SCHEMES = ["http", "https", "mailto"];

function _hasScheme(s) {
  if (s.length === 0) return false;
  if (!codepointClass.isAsciiLetter(s.charCodeAt(0))) return false;
  for (var i = 1; i < s.length; i += 1) {
    var cc = s.charCodeAt(i);
    if (cc === 0x3A) return true;
    if (codepointClass.isAsciiAlnum(cc)) continue;
    if (cc === 0x2B || cc === 0x2D || cc === 0x2E) continue;
    return false;
  }
  return false;
}

function _schemeOf(s) {
  if (!_hasScheme(s)) return null;
  var end = 0;
  while (s.charCodeAt(end) !== 0x3A) end += 1;
  return s.slice(0, end).toLowerCase();
}

function _renderInline(s, opts, depth, rootMatch, off) {
  var d = depth === undefined ? 0 : depth;
  if (d > MAX_INLINE_DEPTH) return _escapeText(s);

  var out = "";
  var i = 0;
  var textStart = 0;
  var base = off === undefined ? 0 : off;
  var match = rootMatch === undefined ? _bracketMap(s) : rootMatch;
  var cursor = match ? { i: _lowerBound(match.pos, match.count, base) } : null;
  function flush(upTo) { out += _escapeText(s.slice(textStart, upTo)); }

  while (i < s.length) {
    var ch = s.charAt(i);

    if (ch === "\\" && i + 1 < s.length) {
      flush(i);
      out += _escapeText(s.charAt(i + 1));
      i += 2;
      textStart = i;
      continue;
    }

    if (ch === "`") {
      var tickRun = _runLength(s, i, "`", MAX_DELIMITER_RUN);
      var close = _findRun(s, i + tickRun, "`", tickRun);
      if (close !== -1) {
        flush(i);
        _charge(13);
        out += "<code>" + _escapeText(s.slice(i + tickRun, close)) + "</code>";
        i = close + tickRun;
        textStart = i;
        continue;
      }
    }

    if (ch === "!" && s.charAt(i + 1) === "[") {
      var img = _parseLink(s, i + 1, match, base, cursor);
      if (img !== null) {
        flush(i);
        out += _escapeText(s.slice(i, img.end));
        i = img.end;
        textStart = i;
        continue;
      }
    }

    if (ch === "[") {
      var link = _parseLink(s, i, match, base, cursor);
      if (link !== null) {
        flush(i);
        var href = _safeHref(link.url, opts);
        var label = _renderInline(link.text, opts, d + 1, match, base + i + 1);
        if (href !== null) _charge(50);
        out += href === null ? label
          : '<a href="' + href + '" rel="nofollow noopener noreferrer">' + label + "</a>";
        i = link.end;
        textStart = i;
        continue;
      }
    }

    if (ch === "*" || ch === "_") {
      var run = _runLength(s, i, ch, 2);
      var want = run >= 2 ? 2 : 1;
      var end = _findRun(s, i + want, ch, want);
      if (end !== -1 && end > i + want) {
        flush(i);
        var innerHtml = _renderInline(s.slice(i + want, end), opts, d + 1,
                                      match, base + i + want);
        _charge(want === 2 ? 17 : 9);
        out += want === 2 ? "<strong>" + innerHtml + "</strong>"
                          : "<em>" + innerHtml + "</em>";
        i = end + want;
        textStart = i;
        continue;
      }
    }

    i += 1;
  }
  flush(s.length);
  return out;
}

function _runLength(s, at, ch, cap) {
  var n = 0;
  var limit = cap === undefined ? s.length : cap;
  while (n < limit && at + n < s.length && s.charAt(at + n) === ch) n += 1;
  return n;
}

function _findRun(s, from, ch, n) {
  for (var i = from; i < s.length; i += 1) {
    if (s.charAt(i) !== ch) continue;
    if (_runLength(s, i, ch, n) < n) continue;
    return i;
  }
  return -1;
}

var _bracketMapsBuilt = 0;
var _bracketArraysAllocated = 0;
var _bracketIndexEntries = 0;
var _bracketLookupSteps = 0;
var _blockOffsetArrays = 0;

function _bracketMap(s) {
  _bracketMapsBuilt += 1;
  var n = s.length;
  var i, c;

  var nSquare = 0, nRound = 0;
  for (i = 0; i < n; i += 1) {
    c = s.charAt(i);
    if (c === "\\") { i += 1; continue; }
    if (c === "[") nSquare += 1;
    else if (c === "(") nRound += 1;
  }
  var nOpen = nSquare + nRound;
  if (nOpen === 0) return null;
  if (nOpen > MAX_INLINE_DELIMITERS) {
    throw _err("markdown/too-many-delimiters",
      "b.guardMarkdown.render: source contains " + nOpen + " bracket delimiters, " +
      "over the " + MAX_INLINE_DELIMITERS + " the inline index will hold");
  }

  var pos = new Int32Array(nOpen);
  var mate = new Int32Array(nOpen);
  var sqStack = new Int32Array(nSquare);
  var rdStack = new Int32Array(nRound);
  _bracketArraysAllocated += 1;
  _bracketIndexEntries = nOpen;

  var sqTop = 0, rdTop = 0, k = 0;
  for (i = 0; i < n; i += 1) {
    c = s.charAt(i);
    if (c === "\\") { i += 1; continue; }
    if (c === "[") { pos[k] = i; sqStack[sqTop] = k; sqTop += 1; k += 1; }
    else if (c === "(") { pos[k] = i; rdStack[rdTop] = k; rdTop += 1; k += 1; }
    else if (c === "]") { if (sqTop > 0) { sqTop -= 1; mate[sqStack[sqTop]] = i; } }
    else if (c === ")") { if (rdTop > 0) { rdTop -= 1; mate[rdStack[rdTop]] = i; } }
  }
  return { pos: pos, mate: mate, count: k };
}

function _lowerBound(pos, count, target) {
  var lo = 0;
  var hi = count;
  while (lo < hi) {
    var mid = (lo + hi) >> 1;
    if (pos[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function _matchIn(match, base, len, z, cursor) {
  if (match === null || match === undefined) return -1;
  var target = z + base;
  var at;
  if (cursor) {
    while (cursor.i < match.count && match.pos[cursor.i] < target) {
      cursor.i += 1;
      _bracketLookupSteps += 1;
    }
    at = cursor.i;
  } else {
    at = _lowerBound(match.pos, match.count, target);
    _bracketLookupSteps += 1;
  }
  if (at >= match.count || match.pos[at] !== target) return -1;
  var m = match.mate[at];
  if (m === 0) return -1;
  m -= base;
  return (m >= 0 && m < len) ? m : -1;
}

function _parseLink(s, at, match, base, cursor) {
  if (s.charAt(at) !== "[") return null;
  var off = base === undefined ? 0 : base;
  var textEnd = _matchIn(match, off, s.length, at, cursor);
  if (textEnd === -1 || s.charAt(textEnd + 1) !== "(") return null;
  var urlEnd = _matchIn(match, off, s.length, textEnd + 1, null);
  if (urlEnd === -1) return null;
  var target = s.slice(textEnd + 2, urlEnd);
  var sp = _firstSpace(target);
  if (sp !== -1) target = target.slice(0, sp);
  return { text: s.slice(at + 1, textEnd), url: target, end: urlEnd + 1 };
}

function _isMdSpace(cc) {
  return cc === 0x20 || (cc >= 0x09 && cc <= 0x0D);
}

function _firstSpace(s) {
  for (var i = 0; i < s.length; i += 1) {
    if (_isMdSpace(s.charCodeAt(i))) return i;
  }
  return -1;
}

function _leadingSpaces(line) {
  var n = 0;
  while (n < line.length && (line.charAt(n) === " " || line.charAt(n) === "\t")) n += 1;
  return n;
}

function _isBlank(line) {
  for (var i = 0; i < line.length; i += 1) {
    if (!_isMdSpace(line.charCodeAt(i))) return false;
  }
  return true;
}

function _isThematicBreak(line) {
  var t = line.trim();
  if (t.length < 3) return false;
  var ch = t.charAt(0);
  if (ch !== "-" && ch !== "*" && ch !== "_") return false;
  for (var i = 0; i < t.length; i += 1) if (t.charAt(i) !== ch) return false;
  return true;
}

function _bulletAt(line) {
  var n = _leadingSpaces(line);
  var ch = line.charAt(n);
  if (ch !== "-" && ch !== "*" && ch !== "+") return -1;
  if (line.charAt(n + 1) !== " ") return -1;
  return n + 2;
}

function _orderedAt(line) {
  var n = _leadingSpaces(line);
  var d = n;
  while (d < line.length && codepointClass.isAsciiDigit(line.charCodeAt(d))) d += 1;
  if (d === n) return -1;
  var sep = line.charAt(d);
  if (sep !== "." && sep !== ")") return -1;
  if (line.charAt(d + 1) !== " ") return -1;
  return d + 2;
}

function _fenceAt(line) {
  var n = _leadingSpaces(line);
  var ch = line.charAt(n);
  if (ch !== "`" && ch !== "~") return null;
  var run = _runLength(line, n, ch);
  if (run < 3) return null;
  return { ch: ch, run: run, info: line.slice(n + run).trim() };
}

var MAX_HEADING_LEVEL = 6;

function _headingAt(line) {
  var at = _leadingSpaces(line);
  if (line.charAt(at) !== "#") return null;
  var level = _runLength(line, at, "#", MAX_HEADING_LEVEL + 1);
  if (level > MAX_HEADING_LEVEL) return null;
  if (at + level !== line.length && line.charAt(at + level) !== " ") return null;
  var text = line.slice(at + level).trim();
  while (text.length > 0 && text.charAt(text.length - 1) === "#") {
    text = text.slice(0, text.length - 1);
  }
  return { level: level, text: text.trim() };
}

var INDENTED_CODE_COLUMNS = 4;

function _isIndentedCode(line) {
  if (_isBlank(line)) return false;
  if (line.charAt(0) === "\t") return true;
  for (var i = 0; i < INDENTED_CODE_COLUMNS; i += 1) {
    if (line.charAt(i) !== " ") return false;
  }
  return true;
}

function _startsBlock(line) {
  return _fenceAt(line) !== null ||
         _isThematicBreak(line) ||
         _headingAt(line) !== null ||
         line.charAt(_leadingSpaces(line)) === ">" ||
         _bulletAt(line) !== -1 ||
         _orderedAt(line) !== -1;
}

var MAX_INLINE_DEPTH = 24;

var MAX_BLOCKQUOTE_RECURSION = 512;

var MAX_INLINE_DELIMITERS = 2000000;

var MAX_DELIMITER_RUN = 8;

function _renderBlocks(lines, opts, depth, off, from, to) {
  var d = depth === undefined ? 0 : depth;
  var lo = from === undefined ? 0 : from;
  var hi = to === undefined ? lines.length : to;
  var offs = off;
  if (offs === undefined) { offs = new Int32Array(lines.length); _blockOffsetArrays += 1; }
  function L(k) {
    var o = offs[k];
    return o === 0 ? lines[k] : lines[k].slice(o);
  }
  var out = "";
  var i = lo;
  while (i < hi) {
    var line = L(i);

    if (_isBlank(line)) { i += 1; continue; }

    var fence = _fenceAt(line);
    if (fence !== null) {
      var body = [];
      i += 1;
      while (i < hi) {
        var f = _fenceAt(L(i));
        if (f !== null && f.ch === fence.ch && f.run >= fence.run && f.info === "") { i += 1; break; }
        body.push(L(i));
        i += 1;
      }
      var cls = fence.info.length > 0
        ? ' class="language-' + _escapeText(_firstWord(fence.info)) + '"' : "";
      _charge(fence.info.length > 0 ? 43 : 25);
      out += "<pre><code" + cls + ">" + _escapeText(body.join("\n")) + "</code></pre>\n";
      continue;
    }

    if (_isThematicBreak(line)) { _charge(5); out += "<hr>\n"; i += 1; continue; }

    var heading = _headingAt(line);
    if (heading !== null) {
      _charge(9);
      out += "<h" + heading.level + ">" + _renderInline(heading.text, opts) +
             "</h" + heading.level + ">\n";
      i += 1;
      continue;
    }

    if (_isIndentedCode(line)) {
      var codeLines = [];
      while (i < hi && (_isIndentedCode(L(i)) || _isBlank(L(i)))) {
        if (_isBlank(L(i))) {
          var j = i + 1;
          while (j < hi && _isBlank(L(j))) j += 1;
          if (j >= hi || !_isIndentedCode(L(j))) break;
          codeLines.push("");
          i += 1;
          continue;
        }
        var codeLine = L(i);
        codeLines.push(codeLine.charAt(0) === "\t"
          ? codeLine.slice(1)
          : codeLine.slice(INDENTED_CODE_COLUMNS));
        i += 1;
      }
      _charge(25);
      out += "<pre><code>" + _escapeText(codeLines.join("\n")) + "</code></pre>\n";
      continue;
    }

    if (line.charAt(_leadingSpaces(line)) === ">") {
      var bqCap = opts.maxBlockquoteDepth < MAX_BLOCKQUOTE_RECURSION
        ? opts.maxBlockquoteDepth
        : MAX_BLOCKQUOTE_RECURSION;
      if (d >= bqCap) {
        throw _err("markdown/blockquote-depth",
          "b.guardMarkdown.render: blockquote nesting exceeds " +
          (bqCap === opts.maxBlockquoteDepth
            ? "maxBlockquoteDepth (" + opts.maxBlockquoteDepth + ")"
            : "the " + MAX_BLOCKQUOTE_RECURSION + "-level renderer ceiling, below " +
              "the configured maxBlockquoteDepth of " + opts.maxBlockquoteDepth));
      }
      var qStart = i;
      while (i < hi) {
        var ql = L(i);
        if (_isBlank(ql) || ql.charAt(_leadingSpaces(ql)) !== ">") break;
        var adv = _leadingSpaces(ql) + 1;
        if (ql.charAt(adv) === " ") adv += 1;
        offs[i] += adv;
        i += 1;
      }
      _charge(27);
      out += "<blockquote>\n" + _renderBlocks(lines, opts, d + 1, offs, qStart, i) +
             "</blockquote>\n";
      continue;
    }

    var bullet = _bulletAt(line);
    var ordered = bullet === -1 ? _orderedAt(line) : -1;
    if (bullet !== -1 || ordered !== -1) {
      var isOrdered = bullet === -1;
      var tag = isOrdered ? "ol" : "ul";
      _charge(tag.length + 3);
      out += "<" + tag + ">\n";
      while (i < hi) {
        var listLine = L(i);
        var at = isOrdered ? _orderedAt(listLine) : _bulletAt(listLine);
        if (at === -1) break;
        _charge(10);
        out += "<li>" + _renderInline(listLine.slice(at).trim(), opts) + "</li>\n";
        i += 1;
      }
      _charge(tag.length + 4);
      out += "</" + tag + ">\n";
      continue;
    }

    var para = [line.trim()];
    i += 1;
    while (i < hi) {
      var paraLine = L(i);
      if (_isBlank(paraLine) || _startsBlock(paraLine)) break;
      para.push(paraLine.trim());
      i += 1;
    }
    _charge(8);
    out += "<p>" + _renderInline(para.join("\n"), opts) + "</p>\n";
  }
  return out;
}

function _firstWord(s) {
  var sp = _firstSpace(s);
  return sp === -1 ? s : s.slice(0, sp);
}

/**
 * @primitive  b.guardMarkdown.render
 * @signature  b.guardMarkdown.render(source, opts?)
 * @since      0.18.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardMarkdown.validate, b.guardMarkdown.sanitize, b.template.escapeHtml
 *
 * Render Markdown to an HTML fragment, escaping by default.
 *
 * Every text node leaves through the shared markup escaper, every link target
 * is screened before it can become an `href`, and raw HTML is emitted as
 * escaped text rather than passed through. Those are the three things a
 * hand-rolled emitter gets wrong, and each of them is a stored-XSS hole
 * wherever author-supplied prose is shown to a visitor.
 *
 * The subset is deliberate: paragraphs, ATX headings, bullet and ordered
 * lists, fenced and indented code, blockquotes, thematic breaks, emphasis,
 * strong, code spans and links. Anything outside it - images, tables,
 * reference links, footnotes, raw HTML - renders as escaped text. That is a
 * display limitation by choice: an unrecognized construct that shows its own
 * source is a formatting bug, while one that becomes markup is a
 * vulnerability.
 *
 * Link targets are limited to `http`, `https`, `mailto` and relative
 * references. A target carrying any other scheme, an attribute-breaking
 * character, or a control character is refused - the link's TEXT is still
 * rendered, so a refusal never silently deletes the author's words. Anchors
 * carry `rel="nofollow noopener noreferrer"`.
 *
 * BIDI, zero-width, C0-control and NUL characters are stripped before parsing
 * regardless of profile. Unlike validation, where an operator may want to be
 * told about them and decide, an invisible character reaching rendered HTML is
 * never what the author meant.
 *
 * The output is a fragment, not a document: no wrapper element, no doctype.
 * It is meant to be inserted into a page whose own Content-Security-Policy is
 * doing its job, not to replace one.
 *
 * What the profile changes is worth stating, because the two halves differ.
 * The SAFETY floor is profile-independent — escaping, the link-target
 * allowlist and raw-HTML-as-text are identical at every profile, since there
 * is no safe way to loosen them. What varies is the SIZE budget, enforced
 * before anything is parsed: `maxBytes` (1 MiB / 8 MiB / 64 MiB, measured in
 * BYTES so a non-ASCII document is not silently allowed several times the
 * stated size), `maxLines` (4,096 / 32,768 / 262,144) and
 * `maxBlockquoteDepth` (16 / 64 / 256). Choose the profile for the document
 * sizes you intend to accept, not for how much escaping you want.
 *
 * A `maxBlockquoteDepth` raised past 512 is bounded at 512, because the
 * renderer recurses once per level and what the call stack survives is not an
 * operator setting. Nesting beyond the effective bound is refused with
 * `markdown/blockquote-depth`, which is a verdict a caller can handle, rather
 * than the stack overflow it would otherwise become.
 *
 * @opts
 *   profile:            "strict"|"balanced"|"permissive",
 *   compliancePosture:  "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                same shape as b.guardMarkdown.validate opts,
 *
 * @example
 *   b.guardMarkdown.render("# Title\n\nA [link](https://example.com).");
 *   // -> "<h1>Title</h1>\n<p>A <a href=\"https://example.com\" rel=\"nofollow noopener noreferrer\">link</a>.</p>\n"
 *
 *   b.guardMarkdown.render("[x](javascript:alert(1))");
 *   // -> "<p>x</p>\n"   (the target is refused, the text survives)
 */
function render(source, opts) {
  if (typeof source !== "string") {
    throw _err("markdown/bad-input",
      "b.guardMarkdown.render: source must be a string; got " + typeof source);
  }
  var resolved = module.exports.resolveOpts(opts);

  var byteLen = Buffer.byteLength(source, "utf8");
  if (byteLen > resolved.maxBytes) {
    throw _err("markdown/too-large",
      "b.guardMarkdown.render: source is " + byteLen + " bytes, over the " +
      resolved.maxBytes + "-byte maxBytes for this profile");
  }
  var lineCount = _markdownLines(source).length;
  if (lineCount > resolved.maxLines) {
    throw _err("markdown/too-many-lines",
      "b.guardMarkdown.render: source has " + lineCount + " lines, over the " +
      resolved.maxLines + "-line maxLines for this profile");
  }

  var text = codepointClass.applyCharStripPolicies(source, {
    bidiPolicy:      "strip",
    controlPolicy:   "strip",
    nullBytePolicy:  "strip",
    zeroWidthPolicy: "strip",
  });
  _outputBudget = {
    used:        0,
    max:         byteLen < MIN_SOURCE_FOR_RATIO
      ? Infinity
      : byteLen * MAX_OUTPUT_AMPLIFICATION,
    sourceBytes: byteLen,
  };
  try {
    return _renderBlocks(_markdownLines(text), resolved);
  } finally {
    _outputBudget = null;
  }
}

var REPAIRABLE = ["dangerousTagPolicy", "dangerousSchemePolicy",
                  "autolinkSchemePolicy", "imageSchemePolicy",
                  "referenceLinkPolicy", "doctypePolicy", "codeFenceLangPolicy"];
var REPORT_ONLY = ["rawHtmlPolicy", "htmlCommentPolicy", "frontMatterPolicy",
                   "emphasisRunPolicy", "filePolicy"];

var POLICY_ENUM = gateContract.policyVocabulary(
  REPAIRABLE, gateContract.POLICY_VALUES.rejectStripAuditAllow,
  gateContract.policyVocabulary(
    REPORT_ONLY, gateContract.POLICY_VALUES.rejectAuditAllow));

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "markdown",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardMarkdownError,
  profiles:    PROFILES,
  base:        256,
  defaultsOverlay: { maxRuntimeMs: C.TIME.seconds(10) },
  mimeTypes:   ["text/markdown", "text/x-markdown", "text/x-gfm"],
  extensions:  [".md", ".markdown"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:             _detectIssues,
  sanitizeTransform:  _sanitizeTransform,
  dispositionFor:     _gateDispositionFor,
  intOpts:            ["maxBytes", "maxLines", "maxLinks", "maxImages", "maxAutolinks",
                       "maxRefDefs", "maxListDepth", "maxBlockquoteDepth"],
  gate:        gate,
  extra: {
    render: render,
    _gateDispositionForTest: _gateDispositionFor,
    _bracketMapsBuiltForTest: function () { return _bracketMapsBuilt; },
    _bracketArraysAllocatedForTest: function () { return _bracketArraysAllocated; },
    _bracketIndexEntriesForTest: function () { return _bracketIndexEntries; },
    _bracketLookupStepsForTest: function () { return _bracketLookupSteps; },
    _blockOffsetArraysForTest: function () { return _blockOffsetArrays; },
    _spanIndexForTest: _makeSpanIndex,
    _shapesForTest: {
      inlineLinks:      _inlineLinks,
      autolinks:        _autolinks,
      refDefs:          _refDefs,
      codeFenceLangs:   _codeFenceLangs,
      hasRawHtmlTag:    _hasRawHtmlTag,
      hasDangerousTag:  _hasDangerousTag,
      hasHtmlComment:   _hasHtmlComment,
      hasDoctype:       _hasDoctype,
      hasFrontMatter:   _hasFrontMatter,
      hasLongEmphasisRun: _hasLongEmphasisRun,
    },
  },
});
