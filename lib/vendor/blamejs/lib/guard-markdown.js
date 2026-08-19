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
    while (b < input.length && input.charAt(b) !== ">" &&
           !markupTokenizer.isMarkupSpace(input.charCodeAt(b))) b += 1;
    // Resume past the scanned body either way. On failure every `<` inside it
    // would rescan the same span, which is quadratic on a document built of
    // `<a:` prefixes.
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
module.exports = gateContract.defineGuard({
  name:        "markdown",
  kind:        "content",
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
    _gateDispositionForTest: _gateDispositionFor,
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
