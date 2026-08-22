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

// ---- Source-level threat detectors ----

var DANGEROUS_TAGS    = [
  "script", "iframe", "object", "embed", "applet", "form", "input",
  "button", "textarea", "select", "option", "meta", "link", "base",
  "frame", "frameset", "noscript", "noembed", "svg", "math", "video",
  "audio", "source", "track", "style", "template", "portal", "marquee",
];

// Dangerous URL schemes in inline links / autolinks / images / refs.
var DANGEROUS_SCHEMES = [
  "javascript", "vbscript", "livescript", "mocha", "view-source",
  "data", "jar", "blob", "feed", "tel", "facetime", "facetime-audio",
];

// The start of a raw HTML tag, whitespace-tolerant per CVE-2026-30838: `<`,
// optional whitespace, an optional `/`, more optional whitespace, then a
// letter. Returns the index just past that letter, or -1.
function _tagNameStartAt(s, at) {
  if (s.charAt(at) !== "<") return -1;
  var i = markupTokenizer.skipMarkupSpace(s, at + 1);
  if (s.charAt(i) === "/") i = markupTokenizer.skipMarkupSpace(s, i + 1);
  return codepointClass.isAsciiLetter(s.charCodeAt(i)) ? i : -1;
}

// A raw HTML tag: the opener above, a name, then anything up to a `>`.
//
// Only the FIRST opener has to be tested. A `>` that follows a later opener
// also follows the first one, so if the first opener has no `>` after it, no
// opener does — and asking the question per opener is quadratic on a document
// made of tag-shaped prefixes (`"<a".repeat(2e6)` took over a minute).
function _hasRawHtmlTag(s) {
  for (var i = 0; i < s.length; i += 1) {
    var nameAt = _tagNameStartAt(s, i);
    if (nameAt === -1) continue;
    return s.indexOf(">", nameAt) !== -1;
  }
  return false;
}

// The boundary a `\b` supplies after a name: the next character must not be a
// letter, a digit or an underscore. A HYPHEN is not one of those, so
// `<script-x>` IS a `script` finding — treating the hyphen as part of the name
// loses `<script-x>`, `<script->` and `<form-a>`, which is a miss in the
// screen that refuses script-bearing tags.
function _endsName(ch) {
  return ch === "" || !codepointClass.isIdentifierChar(ch.charCodeAt(0));
}

// Keyed by name so an opener costs ONE lookup rather than a pass over the
// whole list. A document made of tag-shaped prefixes would otherwise cost
// (openers × names) comparisons, which at the permissive size cap is seconds
// of CPU inside a single screen.
var DANGEROUS_TAG_SET = (function () {
  var m = Object.create(null);
  for (var i = 0; i < DANGEROUS_TAGS.length; i += 1) m[DANGEROUS_TAGS[i]] = true;
  return m;
})();

// A tag from the dangerous list at a tag opener. The name is the maximal run
// of identifier characters, which is exactly where a `\b` ends it — so
// `<script-x>` reads as `script` and is a finding, while `<scriptx>` reads as
// `scriptx` and is not.
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

// A scheme at the very start of `s`, allowing whitespace before the colon —
// which is what a browser tolerates. Returns the lower-cased scheme, or null.
function _leadingSchemeOf(s, schemes) {
  for (var i = 0; i < schemes.length; i += 1) {
    var name = schemes[i];
    if (!codepointClass.containsFolded(s.slice(0, name.length), name)) continue;
    var j = markupTokenizer.skipMarkupSpace(s, name.length);
    if (s.charAt(j) === ":") return name;
  }
  return null;
}

// Inline link `[text](url)` and image `![alt](url)`. Each match is
// `{ bang, text, url }` — `bang` is `"!"` for an image and `""` for a link,
// which is what the capture group this replaced held.
// Where a URL run starting at `from` stops — the first `)` or whitespace at or
// after it, or the end of input.
//
// The memo is what makes resuming after a failed candidate affordable. Every
// character between a run's start and its stop is by definition neither a `)`
// nor whitespace, so a run starting ANYWHERE inside that span stops at the
// same place. Without that, a document of `[a](` prefixes re-walks the same
// tail from each one, which is the quadratic scan this guard already had to
// fix once.
function _makeUrlRunScanner(input) {
  var spanStart = -1;
  var spanStop = -1;
  return function (from) {
    if (from >= spanStart && from <= spanStop) return spanStop;
    var p = from;
    while (p < input.length && input.charAt(p) !== ")" &&
           !markupTokenizer.isMarkupSpace(input.charCodeAt(p))) p += 1;
    spanStart = from;
    spanStop = p;
    return p;
  };
}

function _inlineLinks(input) {
  var out = [];
  var urlRunEnd = _makeUrlRunScanner(input);
  var failedStop = -1;
  for (var i = 0; i < input.length; i += 1) {
    if (input.charAt(i) !== "[") continue;
    var bang = i > 0 && input.charAt(i - 1) === "!" ? "!" : "";
    // The link text runs to the first `]`, and cannot span a line.
    var close = -1;
    var t = i + 1;
    for (; t < input.length; t += 1) {
      var tc = input.charCodeAt(t);
      if (tc === 0x0A) break;                                        // no newline in text
      if (input.charAt(t) === "]") { close = t; break; }
    }
    // No closing bracket before the line ended: every later `[` on this line
    // fails the same way, so resume at the line break rather than rescanning
    // the rest of the line from each one.
    if (close === -1) { i = t; continue; }
    if (input.charAt(close + 1) !== "(") continue;
    var urlStart = markupTokenizer.skipMarkupSpace(input, close + 2);
    // The URL runs greedily to whitespace or the closing paren.
    var u = urlRunEnd(urlStart);
    // Every failure below resumes at the NEXT character, not past the span
    // just scanned. A malformed outer link can contain a well-formed inner
    // one — `[bad]([ok](javascript:x))` — and a renderer recovers and emits
    // it, so skipping the span would carry that destination past the scheme
    // screen. The two memos keep the re-entry affordable.
    if (u === urlStart) continue;                                    // no URL
    // A candidate that failed with its run stopping at `u` settles every later
    // candidate stopping there too: the title search runs over a SUFFIX of the
    // span this one already searched, so finding nothing here means finding
    // nothing there.
    if (u === failedStop) continue;
    var urlEnd = _linkCloses(input, u) ? u : _backOffToTitle(input, urlStart, u);
    if (urlEnd === -1) { failedStop = u; continue; }
    var url = input.slice(urlStart, urlEnd);
    out.push({ bang: bang, text: input.slice(i + 1, close), url: url, index: i });
    // Resume at the next character here too, not past the URL. A destination
    // may contain a `[` that opens a link a renderer emits INSTEAD of this
    // one — CommonMark allows balanced parens in a destination, so
    // `[bad]([ok](javascript:x) trailing)` reads to this scan as an outer link
    // whose URL starts with `[`, and to a renderer as the inner link alone.
    // Screening both is the conservative reading; screening the outer only
    // carried the inner destination past the scheme check.
  }
  return out;
}

// From `at`, does the rest close the link — optional whitespace, an optional
// quoted title, optional whitespace, then `)`?
function _linkCloses(s, at) {
  var p = markupTokenizer.skipMarkupSpace(s, at);
  if (s.charAt(p) === "\"") {
    var q = s.indexOf("\"", p + 1);
    if (q === -1) return false;
    p = markupTokenizer.skipMarkupSpace(s, q + 1);
  }
  return s.charAt(p) === ")";
}

// The greedy URL run did not close the link. A pattern would backtrack it one
// character at a time, so the answer is the RIGHTMOST quote inside the run at
// which the remainder closes — that is where `[a](javascript:x"t u")` splits
// into the URL `javascript:x` and the title `"t u"`. Without it the link is
// discarded and its scheme never screened.
function _backOffToTitle(s, from, to) {
  for (var k = to - 1; k > from; k -= 1) {
    if (s.charAt(k) !== "\"") continue;
    if (_linkCloses(s, k)) return k;
  }
  return -1;
}

// The longest scheme an autolink may carry before its colon — the bound the
// pattern this replaced expressed as `{0,32}` after the first letter.
var AUTOLINK_SCHEME_TAIL_MAX = 32;

// Autolink `<scheme:...>` — the scheme is a letter then up to 32 more scheme
// characters, and the body runs to the closing `>` with no whitespace in it.
function _autolinks(input) {
  var out = [];
  for (var i = 0; i < input.length; i += 1) {
    if (input.charAt(i) !== "<") continue;
    if (!codepointClass.isAsciiLetter(input.charCodeAt(i + 1))) continue;
    var j = i + 2;
    var tail = 0;
    while (j < input.length && tail < AUTOLINK_SCHEME_TAIL_MAX &&
           SCHEME_TAIL_CHARS.indexOf(input.charAt(j)) !== -1) { j += 1; tail += 1; }
    if (input.charAt(j) !== ":") continue;
    var b = j + 1;
    // The body stops at "<" as well as at ">" and whitespace. An autolink body
    // cannot contain "<" in CommonMark, and running past one let an outer
    // candidate swallow everything nested inside it: `<a:<javascript:alert(1)>>`
    // recorded a single URL beginning `a:`, a scheme nothing objects to, and
    // resumed past the inner candidate so the scheme filter never saw it.
    while (b < input.length && input.charAt(b) !== ">" && input.charAt(b) !== "<" &&
           !markupTokenizer.isMarkupSpace(input.charCodeAt(b))) b += 1;
    // Resume past the scanned body either way. On failure every `<` inside it
    // would rescan the same span, which is quadratic on a document built of
    // `<a:` prefixes. Stopping at "<" keeps that: the scan still advances to
    // the character that ended it, and that character begins the next
    // candidate rather than being skipped over.
    if (b === j + 1 || input.charAt(b) !== ">") { i = b - 1; continue; }
    out.push({ url: input.slice(i + 1, b), index: i });
    i = b;
  }
  return out;
}

// The characters a URL scheme may carry after its first letter.
var SCHEME_TAIL_CHARS = codepointClass.ASCII_ALNUM + "+-.";

// Reference-link definition `[label]: url "title"`, at the start of a line
// with up to three spaces of indent.
var REF_DEF_MAX_INDENT = 3;

// Scanned over the WHOLE input rather than line by line: the whitespace
// between the `:` and the destination may include the line break, so
// `[x]:\njavascript:alert(1)` is a definition whose URL sits on the next line.
// A line-by-line walk discards it, and the scheme is never screened.
function _refDefs(input) {
  var out = [];
  for (var at = 0; at < input.length; at += 1) {
    if (at > 0 && !_isLineStart(input, at)) continue;
    var i = at;
    var indent = 0;
    while (i < input.length && indent < REF_DEF_MAX_INDENT &&
           markupTokenizer.isMarkupSpace(input.charCodeAt(i))) { i += 1; indent += 1; }
    if (input.charAt(i) !== "[") continue;
    // The label runs to the first `]` and cannot span a line.
    var close = -1;
    for (var c = i + 1; c < input.length; c += 1) {
      if (input.charCodeAt(c) === 0x0A) break;
      if (input.charAt(c) === "]") { close = c; break; }
    }
    if (close === -1 || close === i + 1) continue;                   // label must be non-empty
    if (input.charAt(close + 1) !== ":") continue;
    var u = markupTokenizer.skipMarkupSpace(input, close + 2);
    var urlStart = u;
    while (u < input.length && !markupTokenizer.isMarkupSpace(input.charCodeAt(u))) u += 1;
    if (u === urlStart) continue;
    out.push({ label: input.slice(i + 1, close), url: input.slice(urlStart, u) });
    at = u - 1;
  }
  return out;
}

// The characters that break out of the class attribute a renderer pastes a
// code-fence language tag into.
var ATTR_BREAKING_CHARS = "<>\"'`";

// A code fence's language tag: ``` or ~~~ at the start of a line, then the
// rest of that line.
function _codeFenceLangs(input) {
  var out = [];
  var lines = _markdownLines(input);
  for (var li = 0; li < lines.length; li += 1) {
    var line = lines[li];
    var fence = line.slice(0, 3);
    if (fence !== "```" && fence !== "~~~") continue;
    out.push(line.slice(3));
  }
  return out;
}

// A line starts at index 0 or after ANY line terminator — a lone CR and the
// two Unicode line separators start a line for a `^` under the `m` flag, so a
// scan that only knows about LF misses a fence or a reference definition on a
// CR-separated line.
function _isLineStart(s, at) {
  return at === 0 ||
         codepointClass.inRanges(s.charCodeAt(at - 1),
                                 codepointClass.LINE_TERMINATOR_RANGES);
}

// Split on any line terminator, treating CRLF as one.
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

// A front-matter block: the fence at the very start of the document followed
// by whitespace to the end of that line, at least one more line, then the same
// fence at the start of a later line.
function _hasFrontMatter(s, fence) {
  if (s.slice(0, fence.length) !== fence) return false;
  var afterOpen = markupTokenizer.skipMarkupSpace(s, fence.length);
  var firstLf = s.indexOf("\n", fence.length);
  if (firstLf === -1 || afterOpen < firstLf) return false;   // trailing junk on the fence line
  for (var i = firstLf + 1; i < s.length; i += 1) {
    if (s.charCodeAt(i - 1) !== 0x0A) continue;
    if (s.slice(i, i + fence.length) !== fence) continue;
    // The closing fence has to END its line. `---not-a-fence` opens a line
    // with the delimiter and is ordinary text, and every front-matter parser
    // reads it that way — so treating it as the close reports front matter in
    // a document that has none, which under a strict profile is a refusal.
    var afterClose = i + fence.length;
    while (afterClose < s.length &&
           (s.charCodeAt(afterClose) === 0x20 || s.charCodeAt(afterClose) === 0x09)) {
      afterClose += 1;                                       // SP / HTAB only: the line break is the terminator
    }
    if (afterClose < s.length && s.charCodeAt(afterClose) !== 0x0A &&
        s.charCodeAt(afterClose) !== 0x0D) continue;
    // At least one character has to sit between the two fences' newlines, or
    // there is no body — `---\n\n---` is two fences and nothing in between,
    // and is not front matter.
    if (i < firstLf + 3) continue;
    return true;
  }
  return false;
}

// An HTML comment, closed the way a BROWSER closes one: `-->`, the
// comment-end-bang `--!>`, or the abrupt `<!-->` / `<!--->` forms. The pattern
// this replaced honored only `-->`, so a comment a browser ends early — and
// therefore markup a browser runs — read as an unterminated comment and was
// not reported.
// Only the FIRST opener is tested, for the same reason the raw-tag scan tests
// only its first: openers are at least four characters apart, so a terminator
// that closes a later one also sits after the first — and asking per opener is
// quadratic on a document of `<!--` prefixes.
function _hasHtmlComment(s) {
  var at = s.indexOf("<!--");
  return at !== -1 && markupTokenizer.htmlCommentEnd(s, at) !== -1;
}

// A DOCTYPE declaration, not running into a further name character.
function _hasDoctype(s) {
  for (var i = 0; i + 9 <= s.length; i += 1) {
    if (!codepointClass.containsFolded(s.slice(i, i + 9), "<!DOCTYPE")) continue;
    if (_endsName(s.charAt(i + 9))) return true;
  }
  return false;
}

// A run of 20 or more emphasis characters — the shape that makes a markdown
// renderer's emphasis matching quadratic.
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


function _isDangerousUrl(url, opts) {
  if (typeof url !== "string") return null;
  // Decode the entity-hidden scheme tricks a browser resolves -- numeric AND the
  // named-entity ASCII subset (guard-markdown previously decoded numeric only, so
  // `java&Tab;script:` / a `&colon;`-hidden scheme slipped past) -- then fold away
  // the whitespace the WHATWG URL parser strips (tab/lf/cr anywhere + a leading/
  // trailing C0-control-or-space run, so `&#32;javascript:` -> " javascript:" can't
  // defeat the `^scheme:` anchor). Shared codepoint-class primitives keep
  // guard-markdown / guard-html / guard-svg from drifting on which encodings to fold.
  var s = codepointClass.stripUrlSchemeWhitespace(
    codepointClass.decodeMarkupEntities(url.trim()));
  // The reported name is the leading LETTER run, not the matched scheme — so
  // `view-source:` reports `view` and `facetime-audio:` reports `facetime`,
  // which is what the pattern this replaced returned and what the issue
  // snippets an operator matches on already say.
  if (_leadingSchemeOf(s, DANGEROUS_SCHEMES) !== null) return _leadingLetterRun(s);
  if (_leadingSchemeOf(s, ["file"]) !== null && opts.filePolicy !== "allow") return "file";
  return null;
}

// ---- Profile presets ----

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
    maxLines:               4096,                                                // line count cap
    maxLinks:               256,                                                 // link count cap
    maxImages:              128,                                                 // image count cap
    maxAutolinks:           128,                                                 // autolink count cap
    maxRefDefs:             64,                                                  // ref-def count cap
    maxListDepth:           16,                                                  // nesting depth
    maxBlockquoteDepth:     16,                                                  // nesting depth
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
    maxLines:               32768,                                               // line count cap
    maxLinks:               2048,                                                // link count cap
    maxImages:              1024,                                                // image count cap
    maxAutolinks:           1024,                                                // autolink count cap
    maxRefDefs:             512,                                                 // ref-def count cap
    maxListDepth:           64,                                                  // nesting depth
    maxBlockquoteDepth:     64,                                                  // nesting depth
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
    maxLines:               262144,                                              // line count cap
    maxLinks:               16384,                                               // link count cap
    maxImages:              8192,                                                // image count cap
    maxAutolinks:           8192,                                                // autolink count cap
    maxRefDefs:             4096,                                                // ref-def count cap
    maxListDepth:           256,                                                 // nesting depth
    maxBlockquoteDepth:     256,                                                 // nesting depth
  },
});

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "markdown", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // Line count cap — line-based parsers scale O(lines).
  var lineCount = 0;
  for (var li = 0; li < input.length; li += 1) {
    if (input.charCodeAt(li) === 10) lineCount += 1;                             // newline char code
  }
  if (lineCount > opts.maxLines) {
    issues.push({
      kind: "line-cap", severity: "high", ruleId: "markdown.line-cap",
      snippet: "line count " + lineCount + " exceeds maxLines " + opts.maxLines,
    });
  }

  // 1. Front-matter — leading YAML / TOML block.
  if (opts.frontMatterPolicy !== "allow") {
    if (_hasFrontMatter(input, "---") || _hasFrontMatter(input, "+++")) {
      issues.push({
        kind: "front-matter",
        severity: opts.frontMatterPolicy === "reject" ? "high" : "warn",
        ruleId: "markdown.front-matter",
        snippet: "leading front-matter block — payload class equals guardYaml",
      });
    }
  }

  // 2. DOCTYPE inline.
  if (opts.doctypePolicy !== "allow" && _hasDoctype(input)) {
    issues.push({
      kind: "doctype",
      severity: opts.doctypePolicy === "reject" ? "critical" : "warn",
      ruleId: "markdown.doctype",
      snippet: "DOCTYPE in markdown source (XXE-shaped if rendered)",
    });
  }

  // 3. Dangerous tag (whitespace-tolerant per CVE-2026-30838).
  if (opts.dangerousTagPolicy !== "allow" && _hasDangerousTag(input)) {
    issues.push({
      kind: "dangerous-tag", severity: "critical",
      ruleId: "markdown.dangerous-tag",
      snippet: "raw HTML tag from danger list (script/iframe/object/etc. " +
               "— whitespace-tolerant per CVE-2026-30838 class)",
    });
  }

  // 4. Raw HTML — any tag.
  if (opts.rawHtmlPolicy !== "allow" && _hasRawHtmlTag(input)) {
    issues.push({
      kind: "raw-html",
      severity: opts.rawHtmlPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.raw-html",
      snippet: "raw HTML tag in markdown source — compose with guardHtml",
    });
  }

  // 5. HTML comments.
  if (opts.htmlCommentPolicy !== "allow" && _hasHtmlComment(input)) {
    issues.push({
      kind: "html-comment",
      severity: opts.htmlCommentPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.html-comment",
      snippet: "HTML comment block — payload-smuggling vector",
    });
  }

  // 6. Inline links + images — scan for dangerous schemes (HTML-entity
  //    decode for bypass payloads like `&#x6A;avascript:`).
  var linkCount = 0;
  var imageCount = 0;
  var inlineMatches = _inlineLinks(input);
  for (var im = 0; im < inlineMatches.length; im += 1) {
    var m = inlineMatches[im];
    var isImage = m.bang === "!";
    if (isImage) imageCount += 1; else linkCount += 1;
    var scheme = _isDangerousUrl(m.url, opts);
    if (scheme === null) continue;
    var policy = isImage ? opts.imageSchemePolicy : opts.dangerousSchemePolicy;
    if (policy === "allow") continue;
    issues.push({
      kind: isImage ? "image-scheme" : "link-scheme",
      severity: policy === "reject" ? "critical" : "high",
      ruleId: isImage ? "markdown.image-scheme" : "markdown.link-scheme",
      snippet: (isImage ? "image" : "link") +
               " uses dangerous scheme '" + scheme + ":'",
    });
    if (issues.length > 256) break;                                              // issue accumulator cap
  }
  if (linkCount > opts.maxLinks) {
    issues.push({
      kind: "link-cap", severity: "high", ruleId: "markdown.link-cap",
      snippet: "link count " + linkCount + " exceeds maxLinks " + opts.maxLinks,
    });
  }
  if (imageCount > opts.maxImages) {
    issues.push({
      kind: "image-cap", severity: "high", ruleId: "markdown.image-cap",
      snippet: "image count " + imageCount +
               " exceeds maxImages " + opts.maxImages,
    });
  }

  // 7. Autolinks.
  var autolinkCount = 0;
  var autolinkMatches = _autolinks(input);
  for (var am = 0; am < autolinkMatches.length; am += 1) {
    autolinkCount += 1;
    var aScheme = _isDangerousUrl(autolinkMatches[am].url, opts);
    if (aScheme === null) continue;
    if (opts.autolinkSchemePolicy === "allow") continue;
    issues.push({
      kind: "autolink-scheme",
      severity: opts.autolinkSchemePolicy === "reject" ? "critical" : "high",
      ruleId: "markdown.autolink-scheme",
      snippet: "autolink uses dangerous scheme '" + aScheme + ":'",
    });
    if (issues.length > 256) break;                                              // issue accumulator cap
  }
  if (autolinkCount > opts.maxAutolinks) {
    issues.push({
      kind: "autolink-cap", severity: "high",
      ruleId: "markdown.autolink-cap",
      snippet: "autolink count " + autolinkCount +
               " exceeds maxAutolinks " + opts.maxAutolinks,
    });
  }

  // 8. Reference-link definitions.
  var refDefCount = 0;
  var refDefMatches = _refDefs(input);
  for (var rm = 0; rm < refDefMatches.length; rm += 1) {
    refDefCount += 1;
    var rScheme = _isDangerousUrl(refDefMatches[rm].url, opts);
    if (rScheme === null) continue;
    if (opts.referenceLinkPolicy === "allow") continue;
    issues.push({
      kind: "reference-link-scheme",
      severity: opts.referenceLinkPolicy === "reject" ? "critical" : "high",
      ruleId: "markdown.reference-link-scheme",
      snippet: "reference-link definition uses dangerous scheme '" +
               rScheme + ":' (smuggled through `[ref]` text)",
    });
    if (issues.length > 256) break;                                              // issue accumulator cap
  }
  if (refDefCount > opts.maxRefDefs) {
    issues.push({
      kind: "ref-def-cap", severity: "high",
      ruleId: "markdown.ref-def-cap",
      snippet: "reference-def count " + refDefCount +
               " exceeds maxRefDefs " + opts.maxRefDefs,
    });
  }

  // 9. Code-fence language tag — must not contain `<` `>` `"` `'` (else
  //    renderers paste it into a class attribute and break out).
  if (opts.codeFenceLangPolicy !== "allow") {
    var fenceMatches = _codeFenceLangs(input);
    for (var fm = 0; fm < fenceMatches.length; fm += 1) {
      var lang = fenceMatches[fm];
      if (!lang) continue;
      if (codepointClass.indexOfAny(lang, ATTR_BREAKING_CHARS) !== -1) {
        issues.push({
          kind: "code-fence-lang",
          severity: opts.codeFenceLangPolicy === "reject" ? "critical" : "high",
          ruleId: "markdown.code-fence-lang",
          snippet: "code-fence language tag contains attribute-breaking " +
                   "characters: " + JSON.stringify(lang.slice(0, 64)),         // snippet truncation
        });
        if (issues.length > 256) break;                                          // issue accumulator cap
      }
    }
  }

  // 10. Catastrophic emphasis runs.
  if (opts.emphasisRunPolicy !== "allow" && _hasLongEmphasisRun(input)) {
    issues.push({
      kind: "emphasis-run",
      severity: opts.emphasisRunPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.emphasis-run",
      snippet: "long *_ run — catastrophic backtracking shape (CVE-2025-6493 class)",
    });
  }

  // 11. List + blockquote depth.
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
        var depth = Math.floor(leading / 2);                                     // markdown convention: 2 spaces per nest level
        if (depth > maxListDepthSeen) maxListDepthSeen = depth;
      }
    }
  }
  if (maxListDepthSeen > opts.maxListDepth) {
    issues.push({
      kind: "list-depth-cap", severity: "high",
      ruleId: "markdown.list-depth-cap",
      snippet: "list nesting depth " + maxListDepthSeen +
               " exceeds maxListDepth " + opts.maxListDepth,
    });
  }
  if (maxBqDepthSeen > opts.maxBlockquoteDepth) {
    issues.push({
      kind: "blockquote-depth-cap", severity: "high",
      ruleId: "markdown.blockquote-depth-cap",
      snippet: "blockquote nesting depth " + maxBqDepthSeen +
               " exceeds maxBlockquoteDepth " + opts.maxBlockquoteDepth,
    });
  }

  // 12. Codepoint-class threats.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "markdown"));

  return issues;
}

// ---- Public surface ----

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
 *   schemeAllowlist:        string[],   // default ["http","https","mailto"]
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
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues), with the maxBytes/maxLines/... caps declared via `intOpts`.
// The @primitive block above documents the resulting ABI.

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
// _sanitizeTransform — the normalize tail applied by defineGuard's generated
// sanitize AFTER resolve -> detect -> throwOnRefusalSeverity. spec.sanitizeSeverities
// is ["critical"] so high-severity findings are stripped here, not thrown.
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
// Disposition of each markdown finding = what the operator's policy for that
// class selected. The markup-deviation classes (dangerous tag / raw HTML /
// HTML comment / front-matter / doctype / dangerous link & image & autolink &
// reference schemes / code-fence language / emphasis run) refuse under `reject`
// and audit under `audit` — never sanitize, since the char-strip sanitizer
// cannot excise them; the bidi / null / control char threats follow their
// shared policies (sanitize under `strip`); every count / depth cap and a bad
// input always refuse. Exhaustive over every kind _detectIssues emits.
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "dangerous-tag":         return gateContract.policyDisposition(opts.dangerousTagPolicy);
    case "raw-html":              return gateContract.policyDisposition(opts.rawHtmlPolicy);
    case "html-comment":          return gateContract.policyDisposition(opts.htmlCommentPolicy);
    case "front-matter":          return gateContract.policyDisposition(opts.frontMatterPolicy);
    case "doctype":               return gateContract.policyDisposition(opts.doctypePolicy);
    // The link / image / autolink / reference-link scheme findings fire ONLY for
    // dangerous URL schemes (javascript: / data: / vbscript: / file:) — a
    // denylist hit, so they refuse like html's dangerous-url-scheme. There is no
    // safe audit-and-serve for a known-XSS scheme; the scheme policy still gates
    // EMISSION (`allow` suppresses the finding entirely, an explicit operator
    // opt-in to serve), but any emitted finding refuses.
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
    // Only the char-threat classes the strip transform can excise ever reach
    // sanitize (and only when their policy is a mitigation); the markup classes
    // are refuse / audit by policy. produceSanitized is the strip transform
    // itself, NOT the public `sanitize` — that one throws on a critical finding
    // (e.g. a bidi override) regardless of the strip policy, which would turn a
    // policy-selected sanitize into a refuse.
    produceSanitized: function (text, o) { return _sanitizeTransform(text, o); },
  });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "text/markdown",
  extension:    ".md",
  benignBytes:  Buffer.from(
    "# Title\n\nA [link](https://example.com) and *emphasis*.\n", "utf8"),
  // Hostile: link with javascript: scheme — CVE-2025-9540 class.
  hostileBytes: Buffer.from(
    "# x\n\n[click](javascript:alert(1))\n", "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the
// per-guard inspection surface (validate / sanitize). The bespoke `gate`
// carries markdown's sanitize-and-reemit chain unchanged.
// ---- Renderer -------------------------------------------------------------
//
// Escape-by-default Markdown to HTML over a deliberately small subset. The
// three things a hand-rolled emitter gets wrong are the three this closes:
// author text reaching the output unescaped, a `javascript:` or `data:` URL
// surviving into an href, and raw HTML passed through in the hope of
// sanitising it downstream. Each is a stored-XSS hole wherever operator- or
// author-authored prose is shown to a visitor.
//
// The subset is paragraphs, ATX headings, bullet and ordered lists, fenced and
// indented code, blockquotes, thematic breaks, emphasis, strong, code spans
// and links. Everything outside it - images, tables, raw HTML, reference
// links, footnotes - degrades to escaped text. Degrading is the point: an
// unrecognised construct that renders as its own source is a display bug, and
// one that renders as markup is a vulnerability.
//
// No regex, per the guard-family rule: every scan below is an index walk.

// Every text node leaves through here. `apos: "&#39;"` matches guard-html so
// the two cannot drift on which five characters are escaped.
// How much larger the rendered output may be than the source it came from.
//
// Four, from measurement rather than instinct. Real documents are nowhere near
// it — this project's README, SECURITY.md and CHANGELOG.md render at 1.22, 1.13
// and 1.13 — but SHORT constructs carry a fixed markup cost that a small source
// cannot absorb: a page of brief fenced samples reaches 3.53, because
// `<pre><code class="language-js">` is thirty characters against a fifteen-
// character source, and a page of one-line paragraphs reaches 3.00. Three would
// have refused a documentation page of code examples, which is worse than the
// difference between a 192 MiB and a 256 MiB ceiling on a 64 MiB input.
//
// The shapes this refuses are further out: a document of nothing but
// apostrophes renders at 5.0, and one of nothing but compact links at 7.6.
var MAX_OUTPUT_AMPLIFICATION = 4;

// A SOURCE smaller than this is not bounded by ratio at all.
//
// A ratio is meaningless on a short document: `hi` renders to `<p>hi</p>\n`,
// four times its source, because the fixed cost of a paragraph tag dwarfs two
// characters of text. Every small document would be refused. What the ratio
// exists to bound is a LARGE input becoming a much larger output, and a small
// document's output is small whatever it multiplies by — 20 KiB of apostrophes
// renders to 100 KiB, which is nothing to defend against.
//
// Measured against the SOURCE, not the output allowance. Deriving it from the
// allowance instead made the ratio start biting at a quarter of this size,
// which is not what the bound says it does.
var MIN_SOURCE_FOR_RATIO = C.BYTES.kib(64);

// Set for the duration of one render() call. Rendering is synchronous from
// entry to return, so there is no interleaving to account for; render() clears
// it in a finally, including when a cap refuses partway through.
var _outputBudget = null;

// Charge the budget for markup the RENDERER generates, as opposed to author
// text, which _escapeText charges. Both count, because both are output: a
// six-character `[a](x)` emits a fifty-character anchor with its rel list, so
// a document of nothing but compact links amplified 7.6x while the escaped
// label and URL inside it stayed tiny. Metering only the author's characters
// measured the half that was not growing.
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

// How long `s` will be once escaped, counted without building it.
//
// markupEscape expands exactly five characters, and each by a known amount:
// `&` -> `&amp;` (+4), `<` -> `&lt;` (+3), `>` -> `&gt;` (+3), `"` -> `&quot;`
// (+5) and `'` -> `&#39;` (+4). Counting them is O(n) time and O(1) memory,
// which is the point: the budget has to be decided BEFORE the escaped string
// exists, or the allocation it exists to prevent has already happened.
function _escapedLength(s) {
  var extra = 0;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (c === "&") extra += 4;
    else if (c === "<" || c === ">") extra += 3;
    else if (c === '"') extra += 5;
    else if (c === "'") extra += 4;
  }
  // BYTES, via Buffer.byteLength, because the allowance is in bytes. Counting
  // `s.length` would count UTF-16 code units against a UTF-8 budget, and the
  // two diverge on exactly the input most likely to be adversarial: `é` is one
  // unit and two bytes, an emoji is two units and four bytes. The expansions
  // added above are all ASCII, so they are the same number either way.
  return Buffer.byteLength(s, "utf8") + extra;
}

function _escapeText(s) {
  if (_outputBudget !== null) {
    // Metered HERE because every character of author text passes through this
    // one function, and PREDICTED rather than measured, because a single span
    // can be the whole document: one 64 MiB line of apostrophes would build a
    // 320 MiB string before any check on the result could run.
    _charge(_escapedLength(s));
  }
  return markupEscape(s, { apos: "&#39;" });
}

// Characters that must never appear inside a quoted attribute value, whatever
// the URL parser thinks of them: they end the attribute or open a tag.
var _ATTR_UNSAFE = "\"'<>`";

// A link target is emitted only when it survives BOTH checks: the shared
// dangerous-scheme detector (which folds entity and whitespace obfuscation
// before testing the scheme) and a literal screen for attribute-breaking
// characters. Returns null when the target must not become an href.
function _safeHref(url, opts) {
  if (typeof url !== "string") return null;
  // Control bytes are screened on the RAW value, BEFORE any trim: trimming
  // first would strip the leading and trailing C0 / DEL bytes this is here to
  // refuse, and a URL whose control character sits at the edge is exactly the
  // one a parser differential exploits.
  if (codepointClass.firstControlCharOffset(url, { forbidTab: true }) !== -1) return null;
  var trimmed = url.trim();
  if (trimmed.length === 0) return null;
  if (_isDangerousUrl(trimmed, opts) !== null) return null;
  for (var i = 0; i < trimmed.length; i += 1) {
    if (_ATTR_UNSAFE.indexOf(trimmed.charAt(i)) !== -1) return null;
  }
  // A relative reference carries no scheme and is fine. A target that DOES
  // carry one is emitted only when that scheme is on the allowlist: an
  // unrecognised scheme may still be one the browser hands to a registered
  // protocol handler, so allowlisting is the only safe direction here.
  var scheme = _schemeOf(trimmed);
  if (scheme !== null && RENDER_ALLOWED_SCHEMES.indexOf(scheme) === -1) return null;
  return _escapeText(trimmed);
}

var RENDER_ALLOWED_SCHEMES = ["http", "https", "mailto"];

// Does the target carry a scheme at all, by the RFC 3986 §3.1 grammar?
//
//   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//
// Reading only the leading LETTER run is not that: it stops at the `+` in
// `web+evil:` and concludes there is no scheme, so a registered handler scheme
// is treated as a relative path and emitted as a live href. The grammar has to
// be read whole before a target can be called relative.
//
// A relative reference never matches, because RFC 3986 §4.2 requires its first
// segment to contain no colon - `a+b.c/d` and `./a+b.c` reach a `/` or `.`
// that is not part of a scheme, and the walk stops without a colon.
function _hasScheme(s) {
  if (s.length === 0) return false;
  if (!codepointClass.isAsciiLetter(s.charCodeAt(0))) return false;
  for (var i = 1; i < s.length; i += 1) {
    var cc = s.charCodeAt(i);
    if (cc === 0x3A) return true;                       // ":" ends the scheme
    if (codepointClass.isAsciiAlnum(cc)) continue;
    if (cc === 0x2B || cc === 0x2D || cc === 0x2E) continue;   // "+" "-" "."
    return false;                                       // anything else: no scheme
  }
  return false;
}

// The scheme text itself, lowercased, for an allowlist comparison. Null when
// the target carries no scheme.
function _schemeOf(s) {
  if (!_hasScheme(s)) return null;
  var end = 0;
  while (s.charCodeAt(end) !== 0x3A) end += 1;
  return s.slice(0, end).toLowerCase();
}

// ---- Inline ----

// Emit the inline span `s` (already char-stripped, not yet escaped).
// Precedence: code spans first (their contents are literal and are never
// re-parsed), then links, then strong, then emphasis.
// `rootMatch` and `off` are supplied by the recursive calls below, never by a
// caller. The bracket map is derived ONCE for the outermost span and then read
// through `_matchIn` at an offset, because both recursion paths hand down a
// contiguous slice of the span they were given. Re-deriving it per level made
// the work and the live memory scale with nesting DEPTH as well as length:
// twenty-four full-length maps for a document inside the balanced profile's
// own byte cap, which is how 6.68 MiB of input grew the heap by 1,334 MiB.
function _renderInline(s, opts, depth, rootMatch, off) {
  // Emphasis and link labels recurse. Without a bound, nesting supplied by a
  // visitor exhausts the call stack, which is a process crash rather than a
  // refusal - nothing upstream can catch it. Past the bound the span is
  // emitted as escaped text: the author's characters all survive, they just
  // stop being markup.
  var d = depth === undefined ? 0 : depth;
  if (d > MAX_INLINE_DEPTH) return _escapeText(s);

  var out = "";
  var i = 0;
  var textStart = 0;
  var base = off === undefined ? 0 : off;
  var match = rootMatch === undefined ? _bracketMap(s) : rootMatch;
  // One cursor per call, placed at this slice's first opener. The loop below
  // walks forward only, so the cursor walks with it and every lookup is O(1)
  // amortised; a nested call gets its own, which costs one search each and is
  // bounded by MAX_INLINE_DEPTH.
  var cursor = match ? { i: _lowerBound(match.pos, match.count, base) } : null;
  function flush(upTo) { out += _escapeText(s.slice(textStart, upTo)); }

  while (i < s.length) {
    var ch = s.charAt(i);

    // Backslash escape: the next character is literal, never a delimiter.
    if (ch === "\\" && i + 1 < s.length) {
      flush(i);
      out += _escapeText(s.charAt(i + 1));
      i += 2;
      textStart = i;
      continue;
    }

    // Code span - contents literal. The opening run is capped so a line of
    // nothing but backticks cannot make the fence length itself O(n).
    if (ch === "`") {
      var tickRun = _runLength(s, i, "`", MAX_DELIMITER_RUN);
      var close = _findRun(s, i + tickRun, "`", tickRun);
      if (close !== -1) {
        flush(i);
        _charge(13);                                  // <code></code>
        out += "<code>" + _escapeText(s.slice(i + tickRun, close)) + "</code>";
        i = close + tickRun;
        textStart = i;
        continue;
      }
    }

    // Image - outside the subset. Emitted as escaped text so an
    // author-controlled src never becomes an element attribute.
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

    // Link.
    if (ch === "[") {
      var link = _parseLink(s, i, match, base, cursor);
      if (link !== null) {
        flush(i);
        var href = _safeHref(link.url, opts);
        // link.text is s.slice(i + 1, ...), so it starts one past the "[".
        var label = _renderInline(link.text, opts, d + 1, match, base + i + 1);
        // A refused target still shows the author's words - dropping them
        // would hide content rather than neutralise a link.
        // The fixed wrapper only. `label` is author text charged as it was
        // escaped, and `href` came back from _safeHref THROUGH _escapeText, so
        // it was charged there too — subtracting only the label would bill the
        // target twice and refuse links whose real output is well inside the
        // bound.
        if (href !== null) _charge(50);               // <a href="" rel="...">…</a>
        out += href === null ? label
          : '<a href="' + href + '" rel="nofollow noopener noreferrer">' + label + "</a>";
        i = link.end;
        textStart = i;
        continue;
      }
    }

    // Strong, then emphasis. Both delimiters, longest run first. Only the
    // first two characters of the run decide which, so that is all we count.
    if (ch === "*" || ch === "_") {
      var run = _runLength(s, i, ch, 2);
      var want = run >= 2 ? 2 : 1;
      var end = _findRun(s, i + want, ch, want);
      if (end !== -1 && end > i + want) {
        flush(i);
        var innerHtml = _renderInline(s.slice(i + want, end), opts, d + 1,
                                      match, base + i + want);
        _charge(want === 2 ? 17 : 9);                 // <strong></strong> | <em></em>
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

// Length of the run of `ch` starting at `at`, counted no further than `cap`.
// The cap is what keeps delimiter scanning linear: every caller only needs to
// know whether the run reaches some small length, and walking the whole run to
// answer that turns an input of 20k repeated asterisks into a quadratic scan
// (measured at ~1s before the cap went in).
function _runLength(s, at, ch, cap) {
  var n = 0;
  var limit = cap === undefined ? s.length : cap;
  while (n < limit && at + n < s.length && s.charAt(at + n) === ch) n += 1;
  return n;
}

// Index of the next run of at least `n` `ch` at or after `from`, or -1.
function _findRun(s, from, ch, n) {
  for (var i = from; i < s.length; i += 1) {
    if (s.charAt(i) !== ch) continue;
    if (_runLength(s, i, ch, n) < n) continue;
    return i;
  }
  return -1;
}

// Match every `[` to its `]` and every `(` to its `)` in ONE pass, so a link
// parse is a lookup rather than a forward scan. Scanning per delimiter is what
// makes an input of 50k unmatched brackets quadratic (measured at ~1.7s before
// this map existed); an unmatched opener simply has no entry.
// Counts calls, so a test can assert that a document's nesting DEPTH does not
// multiply the number of maps built. A time or heap assertion would say the
// same thing with a threshold that has to be tuned per machine and flakes
// under a loaded runner; the allocation count is exact and depth-independent.
var _bracketMapsBuilt = 0;
var _bracketArraysAllocated = 0;
var _bracketIndexEntries = 0;
// Counts index positions examined, so a test can assert the scan stays linear
// in the delimiters. A wall-clock assertion would say the same thing with a
// threshold that moves with the machine and flakes under a loaded runner.
var _bracketLookupSteps = 0;
// One per top-level block render. Nesting must not add more - that is the
// difference between recording where a quoted line starts and copying it.
var _blockOffsetArrays = 0;

// Three arrays here are sized by the document, and none of them is allocated
// until a character needs it.
//
// A dense `new Array(s.length)` filled with -1 cost one slot per CHARACTER
// whatever the document contained, so 64 MiB of ordinary prose carrying no
// brackets at all still built 67 million slots before a word was rendered.
// Concurrent requests inside the advertised byte cap could exhaust memory on
// input with nothing hostile in it.
//
// Int32Array rather than a plain Array: four bytes a slot instead of eight,
// and the platform zeroes it, so there is no O(n) fill loop in JS either. Zero
// doubles as "no match" - a closer always sits after its opener, so a recorded
// match is never position 0 and the sentinel cannot collide with a real one.
//
// The opener stacks get the same treatment. They are the reason a run of
// unmatched `[` was expensive even though it produces no pairs: every opener
// was pushed and none popped. Measured on 8 MiB of `[`, the three-array shape
// costs 32 MiB where the plain-array one cost 221 MiB.
function _bracketMap(s) {
  _bracketMapsBuilt += 1;
  var n = s.length;
  var i, c;

  // Pass one counts the openers. Nothing here is sized by the DOCUMENT, only
  // by the delimiters actually in it, so a 64 MiB document carrying a single
  // "[" pays for one entry rather than for sixty-seven million. Counting
  // first also means no growth-and-copy: pass two allocates exactly what pass
  // one found. The escape rule has to be identical in both passes or the
  // counts and the fill disagree.
  var nSquare = 0, nRound = 0;
  for (i = 0; i < n; i += 1) {
    c = s.charAt(i);
    if (c === "\\") { i += 1; continue; }
    if (c === "[") nSquare += 1;
    else if (c === "(") nRound += 1;
  }
  var nOpen = nSquare + nRound;
  if (nOpen === 0) return null;
  // A delimiter cap, separate from the byte and line caps.
  //
  // The three arrays below are sized by the openers, which is the right unit -
  // but a document that is NOTHING but openers has as many of them as it has
  // characters, so at the permissive profile's 64 MiB they would still reserve
  // hundreds of megabytes. Byte and line caps do not bound this, because a
  // single 64 MiB line of "[" satisfies both.
  //
  // Refused rather than degraded: silently ignoring delimiters past a bound
  // would make link detection depend on how far into the document a link sits,
  // which is worse than saying no. The counting pass above is O(1) in memory,
  // so the refusal happens BEFORE anything document-scale is allocated. Two
  // million openers is far past any real document - a 64 MiB file would need a
  // bracket every 32 bytes - and bounds the index at about 24 MiB.
  if (nOpen > MAX_INLINE_DELIMITERS) {
    throw _err("markdown/too-many-delimiters",
      "b.guardMarkdown.render: source contains " + nOpen + " bracket delimiters, " +
      "over the " + MAX_INLINE_DELIMITERS + " the inline index will hold");
  }

  // `pos` holds opener positions in ascending order, which they naturally are
  // - the scan runs left to right - so a position can be found by binary
  // search rather than by indexing an array the size of the text. `mate` holds
  // each opener's closer, keyed by the same rank. Zero means unmatched: a
  // closer always sits after its opener, so a real one is never position 0.
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

// Read one entry of the root map through the window a nested span occupies.
//
// The map holds absolute positions in the outermost span; `z` is relative to
// the slice being rendered. A partner outside the slice reads as no partner,
// which is the same answer a map built for the slice alone would give: it
// never saw the character that closes the pair. `*a [b* c]` is the shape -
// the emphasis run ends before the bracket's partner, so inside the emphasis
// the `[` is unmatched either way.
// Rank of the first opener at or after `target`.
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

// Resolve the closer for the opener at slice-relative `z`.
//
// `cursor` is the scan position of the caller that is walking this slice left
// to right. Because that walk only ever moves forward, the cursor advances
// with it and each lookup costs O(1) amortised - the whole scan stays linear
// in the delimiters, which is what the profile documentation promises. A
// lookup with no cursor falls back to a search, for the one caller that asks
// about a position the main scan has already passed.
function _matchIn(match, base, len, z, cursor) {
  // No map at all means the document held no openers - nothing matches.
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
  if (m === 0) return -1;              // recorded no closer
  m -= base;
  return (m >= 0 && m < len) ? m : -1;
}

// Parse `[text](url)` starting at the `[`. Returns { text, url, end } or null.
// Nesting inside the label and inside the target is handled by the match map,
// so `[a [b] c](u)` and `(a(b))` close where a reader expects.
function _parseLink(s, at, match, base, cursor) {
  if (s.charAt(at) !== "[") return null;
  var off = base === undefined ? 0 : base;
  var textEnd = _matchIn(match, off, s.length, at, cursor);
  if (textEnd === -1 || s.charAt(textEnd + 1) !== "(") return null;
  // No cursor for the target's opening paren. It sits past the position the
  // caller's scan has reached, and moving the shared cursor there would skip
  // over openers between the two that the scan has still to visit - if this
  // parse then fails, those would never be found.
  var urlEnd = _matchIn(match, off, s.length, textEnd + 1, null);
  if (urlEnd === -1) return null;
  var target = s.slice(textEnd + 2, urlEnd);
  // A title after the target ("url \"title\"") is outside the subset; keep the
  // target and drop the rest rather than emitting an unvalidated attribute.
  var sp = _firstSpace(target);
  if (sp !== -1) target = target.slice(0, sp);
  return { text: s.slice(at + 1, textEnd), url: target, end: urlEnd + 1 };
}

// ASCII space, tab, and the line terminators - NOT the broad Unicode
// whitespace set. A NO-BREAK SPACE is content in Markdown, and treating it as
// blank would let U+00A0 end a paragraph or empty a list item.
function _isMdSpace(cc) {
  return cc === 0x20 || (cc >= 0x09 && cc <= 0x0D);
}

function _firstSpace(s) {
  for (var i = 0; i < s.length; i += 1) {
    if (_isMdSpace(s.charCodeAt(i))) return i;
  }
  return -1;
}

// ---- Block ----

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

// `---`, `***` or `___`, three or more, nothing else on the line.
function _isThematicBreak(line) {
  var t = line.trim();
  if (t.length < 3) return false;
  var ch = t.charAt(0);
  if (ch !== "-" && ch !== "*" && ch !== "_") return false;
  for (var i = 0; i < t.length; i += 1) if (t.charAt(i) !== ch) return false;
  return true;
}

// A bullet marker: "-", "*" or "+" followed by a space.
function _bulletAt(line) {
  var n = _leadingSpaces(line);
  var ch = line.charAt(n);
  if (ch !== "-" && ch !== "*" && ch !== "+") return -1;
  if (line.charAt(n + 1) !== " ") return -1;
  return n + 2;
}

// An ordered marker: digits followed by "." or ")" and a space.
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

// A fence opener: three or more backticks or tildes at the line start.
function _fenceAt(line) {
  var n = _leadingSpaces(line);
  var ch = line.charAt(n);
  if (ch !== "`" && ch !== "~") return null;
  var run = _runLength(line, n, ch);
  if (run < 3) return null;
  return { ch: ch, run: run, info: line.slice(n + run).trim() };
}

var MAX_HEADING_LEVEL = 6;

// An ATX heading, or null. `#` alone is not one, `#no-space` is not one, and
// seven hashes is not one - each of those is ordinary text.
//
// This is a NAMED predicate rather than an inline test because the block
// dispatcher and the paragraph terminator both have to agree on what starts a
// heading. When they were written separately they disagreed: the paragraph
// loop stopped at any line beginning with `#` while the dispatcher accepted
// only a well-formed one, so `#not-a-heading` matched no block, ended no
// paragraph, and was dropped without a trace.
function _headingAt(line) {
  var at = _leadingSpaces(line);
  if (line.charAt(at) !== "#") return null;
  var level = _runLength(line, at, "#", MAX_HEADING_LEVEL + 1);
  if (level > MAX_HEADING_LEVEL) return null;
  if (at + level !== line.length && line.charAt(at + level) !== " ") return null;
  var text = line.slice(at + level).trim();
  // Trailing closing hashes are decoration, not content.
  while (text.length > 0 && text.charAt(text.length - 1) === "#") {
    text = text.slice(0, text.length - 1);
  }
  return { level: level, text: text.trim() };
}

// Four spaces (or a tab) of indent opens a code block - but only where a
// paragraph or list item is not already in progress, which the caller decides.
var INDENTED_CODE_COLUMNS = 4;

function _isIndentedCode(line) {
  if (_isBlank(line)) return false;
  if (line.charAt(0) === "\t") return true;
  for (var i = 0; i < INDENTED_CODE_COLUMNS; i += 1) {
    if (line.charAt(i) !== " ") return false;
  }
  return true;
}

// The ONE answer to "does this line start a block?", shared by the dispatcher
// and the paragraph terminator so the two cannot drift apart again.
function _startsBlock(line) {
  return _fenceAt(line) !== null ||
         _isThematicBreak(line) ||
         _headingAt(line) !== null ||
         line.charAt(_leadingSpaces(line)) === ">" ||
         _bulletAt(line) !== -1 ||
         _orderedAt(line) !== -1;
}

// How deep emphasis and link labels may nest before the span is emitted as
// escaped text instead of markup. Well past any hand-written document, far
// short of the call-stack limit.
var MAX_INLINE_DEPTH = 24;

// The blockquote renderer recurses once per nesting level, so the depth it can
// survive is a property of the call stack, not of operator policy.
// maxBlockquoteDepth is an operator-settable cap and the profiles set it to
// 16 / 64 / 256; nothing stopped a caller passing 10001, at which point a
// document of 10,000 "> " prefixes exhausted the stack and threw a native
// RangeError - a process-level failure escaping a primitive whose whole job is
// to turn hostile input into a refusal. This ceiling sits above the loosest
// shipped profile, so it changes no profile's behaviour; it only bounds what a
// raised policy limit can ask the implementation to do.
var MAX_BLOCKQUOTE_RECURSION = 512;

// The most bracket delimiters the inline index will hold. See _bracketMap: the
// index is sized by openers, so a document made entirely of them is sized by
// its length however small the byte cap is set. Two million bounds the index
// at roughly 24 MiB and sits far past any real document.
var MAX_INLINE_DELIMITERS = 2000000;

// Longest delimiter run any caller needs to distinguish. Runs longer than this
// are still matched; only the COUNTING stops here, which is what keeps a line
// of repeated delimiters linear rather than quadratic.
var MAX_DELIMITER_RUN = 8;

// `src`/`off`/`from`/`to` are supplied by the blockquote recursion below and
// never by a caller. Stripping a quote level used to build a fresh array of
// fresh strings for every line in the run, at every level, with each parent's
// array still live - so a document nested to the profile's permitted depth
// retained roughly depth x length. Measured at the permissive profile, 3.94 MiB
// nested 256 deep grew the heap by 85 MiB, and the cap allows sixteen times
// that input.
//
// Now one offsets array is allocated for the whole document and a level records
// where each line's content starts, so a level costs the offsets it advances
// rather than a copy of everything below it.
function _renderBlocks(lines, opts, depth, off, from, to) {
  var d = depth === undefined ? 0 : depth;
  var lo = from === undefined ? 0 : from;
  var hi = to === undefined ? lines.length : to;
  var offs = off;
  if (offs === undefined) { offs = new Int32Array(lines.length); _blockOffsetArrays += 1; }
  // Reading a line applies its recorded offset. V8 shares the backing store for
  // a slice of this size, so this is a view rather than a copy of the text.
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
      // The info string is author-controlled, so it becomes an escaped class
      // rather than being interpolated raw.
      var cls = fence.info.length > 0
        ? ' class="language-' + _escapeText(_firstWord(fence.info)) + '"' : "";
      // The fixed markup only. `cls` embeds _escapeText(_firstWord(info)), so
      // the info token was already charged as it was escaped; adding cls.length
      // would bill it twice.
      _charge(fence.info.length > 0 ? 43 : 25);       // + ` class="language-"`
      out += "<pre><code" + cls + ">" + _escapeText(body.join("\n")) + "</code></pre>\n";
      continue;
    }

    if (_isThematicBreak(line)) { _charge(5); out += "<hr>\n"; i += 1; continue; }

    // ATX heading.
    var heading = _headingAt(line);
    if (heading !== null) {
      _charge(9);                                     // <hN></hN>\n
      out += "<h" + heading.level + ">" + _renderInline(heading.text, opts) +
             "</h" + heading.level + ">\n";
      i += 1;
      continue;
    }

    // Indented code - four spaces or a tab, contents literal. Only reachable
    // where no paragraph is in progress, because the paragraph loop below
    // consumes its own continuation lines first.
    if (_isIndentedCode(line)) {
      var codeLines = [];
      while (i < hi && (_isIndentedCode(L(i)) || _isBlank(L(i)))) {
        // A blank line inside indented code belongs to the block only if more
        // indented code follows; otherwise it ends it.
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
      _charge(25);                                    // <pre><code></code></pre>\n
      out += "<pre><code>" + _escapeText(codeLines.join("\n")) + "</code></pre>\n";
      continue;
    }

    // Blockquote - collect the run, strip one "> " level, recurse. The depth
    // is bounded by the profile's own maxBlockquoteDepth, which validate
    // already enforces; without it here, nesting supplied by a visitor
    // exhausts the call stack and takes the process down rather than
    // producing a refusal something upstream could handle.
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
      // Record where each line's content starts one level in, rather than
      // building a level's worth of new strings. The run is a contiguous window
      // of the SAME line array, so the recursion needs a window rather than a
      // copy of it.
      var qStart = i;
      while (i < hi) {
        var ql = L(i);
        if (_isBlank(ql) || ql.charAt(_leadingSpaces(ql)) !== ">") break;
        var adv = _leadingSpaces(ql) + 1;
        if (ql.charAt(adv) === " ") adv += 1;
        offs[i] += adv;
        i += 1;
      }
      _charge(27);                                    // <blockquote>\n</blockquote>\n
      out += "<blockquote>\n" + _renderBlocks(lines, opts, d + 1, offs, qStart, i) +
             "</blockquote>\n";
      continue;
    }

    // Lists.
    var bullet = _bulletAt(line);
    var ordered = bullet === -1 ? _orderedAt(line) : -1;
    if (bullet !== -1 || ordered !== -1) {
      var isOrdered = bullet === -1;
      var tag = isOrdered ? "ol" : "ul";
      _charge(tag.length + 3);                        // <ul>\n | <ol>\n
      out += "<" + tag + ">\n";
      while (i < hi) {
        var listLine = L(i);
        var at = isOrdered ? _orderedAt(listLine) : _bulletAt(listLine);
        if (at === -1) break;
        _charge(10);                                  // <li></li>\n
        out += "<li>" + _renderInline(listLine.slice(at).trim(), opts) + "</li>\n";
        i += 1;
      }
      _charge(tag.length + 4);                        // </ul>\n | </ol>\n
      out += "</" + tag + ">\n";
      continue;
    }

    // Paragraph - this line plus every following non-blank line that starts no
    // other block. The FIRST line is taken unconditionally: control only
    // reaches here when no block matched it, so testing it again could only
    // disagree with the dispatcher, which is how lines went missing before.
    var para = [line.trim()];
    i += 1;
    while (i < hi) {
      var paraLine = L(i);
      if (_isBlank(paraLine) || _startsBlock(paraLine)) break;
      para.push(paraLine.trim());
      i += 1;
    }
    _charge(8);                                       // <p></p>\n
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
 * display limitation by choice: an unrecognised construct that shows its own
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
  // resolveOpts refuses an unknown profile / posture, so a typo is a boot
  // error rather than a silent fall back to the loosest behaviour.
  var resolved = module.exports.resolveOpts(opts);

  // The profile's input caps bind here exactly as they do in validate. Without
  // them the documented options would be decorative on this path and an
  // attacker could hand over an arbitrarily large document to strip and parse
  // — and this input is untrusted by definition, which is the whole reason the
  // caps exist.
  //
  // BYTES, via Buffer.byteLength, not `source.length`. The cap is named
  // maxBytes and a character count is up to 4x short of it on non-ASCII input,
  // so measuring the wrong representation would leave the cap silently wrong
  // for exactly the documents most likely to be hostile.
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
    // Cleared whether the render returned or a cap refused, so one call's
    // budget can never be inherited by the next.
    _outputBudget = null;
  }
}

module.exports = gateContract.defineGuard({
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
  // No sanitizeSeverities — refusal comes from `dispositionFor` and each
  // finding's own policy. This guard's gate already documents why it passes the
  // raw strip transform rather than this function: the severity filter refused
  // a critical bidi control even under `bidiPolicy: "strip"`, turning a
  // policy-selected repair into a refusal. With policy deciding, the two agree.
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
    // The extractors and shape screens, exposed so the test can compare each
    // against the pattern it replaced rather than only through a whole-document
    // scan.
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
