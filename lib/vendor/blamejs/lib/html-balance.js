"use strict";
/**
 * @module b.htmlBalance
 * @nav    Tools
 * @title  HTML Balance
 *
 * @intro
 *   HTML tag-balance verification. Walks an HTML fragment and refuses
 *   unbalanced container tags, orphan close tags, mismatched-name
 *   close tags, void-element close tags, unterminated comments, and
 *   unterminated raw-text elements (`<script>` / `<style>` / `<title>`
 *   / `<textarea>`). Returns `null` when balanced; otherwise an issue
 *   object with `code`, `message`, `line`, and `column` so operators
 *   can surface "you forgot to close this tag at line N" feedback at
 *   save time.
 *
 *   Intent is operator-side structural feedback, not security
 *   validation. Attribute syntax, custom-element / shadow-DOM
 *   namespaces, script/style content semantics, and XSS-class checks
 *   are all out of scope here — the security pass is `b.guardHtml`,
 *   composed by `b.htmlBalance.checkSafe` for operators wanting both
 *   gates in one call.
 *
 *   Void elements (`<br>`, `<img>`, `<input>`, …) are recognised and
 *   never expected to close. Self-closing slash forms (`<foo />`)
 *   are honoured. Raw-text elements skip their content entirely so
 *   `<script>` bodies containing literal `<` / `</` aren't mis-read
 *   as markup.
 *
 * @card
 *   HTML tag-balance verification.
 */
/**
 * html-balance — minimal HTML structural sanity check.
 *
 * Scans an HTML fragment looking for unbalanced container tags
 * (unclosed `<div>`, mismatched `<table>`/`</tr>`, etc.). Returns
 * `null` when balanced; an object `{ code, message, line, column }`
 * when not. The intent is operator-side feedback at save time —
 * "you forgot to close this tag" — not security validation.
 *
 * What this catches:
 *   - container tag opened but never closed at the same nesting depth
 *   - close tag with no matching open
 *   - close tag mismatched with the most recent open tag
 *   - unterminated comment `<!-- ... ` (no `-->`)
 *
 * What this does NOT catch:
 *   - bad attribute syntax (browsers are tolerant)
 *   - unknown tag names (custom elements / shadow DOM)
 *   - script content (skipped between `<script>` / `</script>`)
 *   - style content (skipped between `<style>` / `</style>`)
 *   - XSS or sanitization concerns — that's a separate primitive
 *
 * Usage:
 *
 *   var problem = b.htmlBalance.check(operatorSubmittedHtml);
 *   if (problem) return res.status(400).render({ error: problem.message });
 */

// Tags that are NEVER closed (HTML5 void elements).
var VOID_TAGS = Object.freeze({
  area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1,
  link: 1, meta: 1, param: 1, source: 1, track: 1, wbr: 1,
});

// Tags whose content is treated as raw text (skipped by this checker).
var RAW_TEXT_TAGS = Object.freeze({ script: 1, style: 1, textarea: 1, title: 1 });

function _posToLineColumn(src, pos) {
  var line = 1, col = 1;
  for (var i = 0; i < pos && i < src.length; i++) {
    if (src.charCodeAt(i) === 10) { line++; col = 1; }
    else col++;
  }
  return { line: line, column: col };
}

/**
 * @primitive b.htmlBalance.check
 * @signature b.htmlBalance.check(html)
 * @since     0.1.0
 * @related   b.htmlBalance.checkSafe, b.guardHtml
 *
 * Returns `null` when `html` is balanced; otherwise an issue object
 * `{ code, message, line, column }`. Issue codes: `html/unterminated-comment`,
 * `html/unterminated-tag`, `html/orphan-close`, `html/mismatched-close`,
 * `html/void-close`, `html/unclosed-raw-text`, `html/unclosed-tag`.
 * Non-string inputs and the empty string return `null` (nothing to
 * balance). Self-closing slash forms and HTML5 void elements are
 * recognised; raw-text elements skip their bodies so `<script>` JS
 * containing `<` characters doesn't mis-balance.
 *
 * @example
 *   b.htmlBalance.check("<div><p>hello</p></div>");
 *   // → null
 *
 *   var issue = b.htmlBalance.check("<div><p>hello</div>");
 *   // → { code: "html/mismatched-close", message: "</div> at line 1 col 14 does not match open <p> at line 1 col 6", line: 1, column: 14 }
 */
function check(html) {
  if (typeof html !== "string" || html.length === 0) return null;
  var stack = [];   // [{ tag, openPos }]
  var i = 0;
  var len = html.length;

  while (i < len) {
    // Comment skip: <!-- ... -->
    if (html.charCodeAt(i) === 0x3C /* < */ &&
        html.charCodeAt(i + 1) === 0x21 /* ! */ &&
        html.charCodeAt(i + 2) === 0x2D &&
        html.charCodeAt(i + 3) === 0x2D) {
      var endComment = html.indexOf("-->", i + 4);
      if (endComment === -1) {
        var pos = _posToLineColumn(html, i);
        return {
          code:    "html/unterminated-comment",
          message: "unterminated <!-- comment (no closing -->) at line " +
            pos.line + " col " + pos.column,
          line:    pos.line,
          column:  pos.column,
        };
      }
      i = endComment + 3;
      continue;
    }

    // CDATA / doctype / processing-instructions are passed over.
    if (html.charCodeAt(i) === 0x3C /* < */ &&
        html.charCodeAt(i + 1) === 0x21 /* ! */) {
      var gt = html.indexOf(">", i);
      if (gt === -1) break;
      i = gt + 1;
      continue;
    }

    // Tag scan: `<` starts an element open or close.
    if (html.charCodeAt(i) === 0x3C /* < */) {
      var isClose = html.charCodeAt(i + 1) === 0x2F /* / */;
      var nameStart = i + (isClose ? 2 : 1);
      // Tag name: ASCII letters, digits, hyphen.
      var nameEnd = nameStart;
      while (nameEnd < len) {
        var c = html.charCodeAt(nameEnd);
        if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
            (c >= 0x30 && c <= 0x39) || c === 0x2D /* - */) nameEnd++;
        else break;
      }
      if (nameEnd === nameStart) {
        // Looks like a stray `<` not starting a tag — skip past it.
        i++;
        continue;
      }
      var tag = html.slice(nameStart, nameEnd).toLowerCase();
      // Find the matching `>` for this tag (skip over quoted attribute values).
      var j = nameEnd;
      var inQuote = 0;
      while (j < len) {
        var ch = html.charCodeAt(j);
        if (inQuote) {
          if (ch === inQuote) inQuote = 0;
        } else if (ch === 0x22 /* " */ || ch === 0x27 /* ' */) {
          inQuote = ch;
        } else if (ch === 0x3E /* > */) {
          break;
        }
        j++;
      }
      if (j >= len) {
        var p = _posToLineColumn(html, i);
        return {
          code:    "html/unterminated-tag",
          message: "unterminated tag '<" + (isClose ? "/" : "") + tag +
            "' (no closing >) at line " + p.line + " col " + p.column,
          line:    p.line,
          column:  p.column,
        };
      }
      // Self-closing: `<foo />` or `<foo/>` or HTML5 void elements.
      var selfClose = html.charCodeAt(j - 1) === 0x2F /* / */;
      if (isClose) {
        if (VOID_TAGS[tag]) {
          // Stray closer for a void tag — surface as error.
          var pcv = _posToLineColumn(html, i);
          return {
            code:    "html/void-close",
            message: "closing tag </" + tag + "> for a void element at line " +
              pcv.line + " col " + pcv.column,
            line:    pcv.line,
            column:  pcv.column,
          };
        }
        var top = stack[stack.length - 1];
        if (!top) {
          var pco = _posToLineColumn(html, i);
          return {
            code:    "html/orphan-close",
            message: "</" + tag + "> with no matching open tag at line " +
              pco.line + " col " + pco.column,
            line:    pco.line,
            column:  pco.column,
          };
        }
        if (top.tag !== tag) {
          var pcm = _posToLineColumn(html, i);
          var pop = _posToLineColumn(html, top.openPos);
          return {
            code:    "html/mismatched-close",
            message: "</" + tag + "> at line " + pcm.line + " col " + pcm.column +
              " does not match open <" + top.tag + "> at line " + pop.line +
              " col " + pop.column,
            line:    pcm.line,
            column:  pcm.column,
          };
        }
        stack.pop();
      } else {
        // Open tag (or self-closing).
        if (selfClose || VOID_TAGS[tag]) {
          // No push.
        } else if (RAW_TEXT_TAGS[tag]) {
          // Skip raw-text content AND its closing tag entirely. Inside
          // <script>/<style>/<textarea>/<title> the `<` characters are
          // text, not markup — re-entering the tag scanner on
          // `</script>` would otherwise treat it as an orphan close.
          var rawClose = "</" + tag;
          var found = -1;
          var search = j + 1;
          var lower = html.toLowerCase();
          while (search < len) {
            var idx = lower.indexOf(rawClose, search);
            if (idx === -1) break;
            var afterIdx = idx + rawClose.length;
            var ac = html.charCodeAt(afterIdx);
            if (afterIdx >= len || ac === 0x3E || ac <= 0x20) {
              found = idx;
              break;
            }
            search = idx + 1;
          }
          if (found === -1) {
            var pcr = _posToLineColumn(html, i);
            return {
              code:    "html/unclosed-raw-text",
              message: "unclosed <" + tag + "> raw-text element at line " +
                pcr.line + " col " + pcr.column,
              line:    pcr.line,
              column:  pcr.column,
            };
          }
          // Advance past the closing `>` of the close tag.
          var closeGt = html.indexOf(">", found);
          if (closeGt === -1) closeGt = len - 1;
          i = closeGt + 1;
          continue;
        } else {
          stack.push({ tag: tag, openPos: i });
        }
      }
      i = j + 1;
      continue;
    }
    i++;
  }

  if (stack.length > 0) {
    var leftover = stack[stack.length - 1];
    var pl = _posToLineColumn(html, leftover.openPos);
    return {
      code:    "html/unclosed-tag",
      message: "unclosed <" + leftover.tag + "> at line " + pl.line +
        " col " + pl.column + " (no matching </" + leftover.tag + ">)",
      line:    pl.line,
      column:  pl.column,
    };
  }
  return null;
}

// Optional content-safety pass for HTML rendered through the framework.
// Mirrors the same opt shape as b.fileUpload({ contentSafety }) /
// b.staticServe({ contentSafety }) so operators wiring guards across
// the stack pass a single { profile, posture } object — the pass-
// through to b.guardHtml.gate validates the HTML against the same
// strict / balanced / permissive vocabulary, plus the configured
// compliance posture.
//
//   var safe = b.htmlBalance.checkSafe(html, { profile: "strict" });
//   if (safe.issues.length) refuseRequest();
//
// checkSafe runs balance() first (cheap structural well-formedness),
// then guardHtml.gate({ profile }) for the security-class checks. The
// returned shape is { balanceIssue, guardIssues } so callers can
// distinguish a structural problem from a content-safety reject.
var lazyRequire = require("./lazy-require");
var _guardHtml = lazyRequire(function () { return require("./guard-html"); });

/**
 * @primitive b.htmlBalance.checkSafe
 * @signature b.htmlBalance.checkSafe(html, opts?)
 * @since     0.7.7
 * @related   b.htmlBalance.check, b.guardHtml
 *
 * Composes `check()` (cheap structural well-formedness) with
 * `b.guardHtml.gate({ profile })` (security-class checks against the
 * strict / balanced / permissive vocabulary plus an optional
 * compliance posture). Returns `{ balanceIssue, guardIssues, ok }`
 * so callers can distinguish a structural problem from a content-
 * safety reject and decide which path to surface to the operator.
 *
 * `opts.contentSafety` mirrors the same shape as `b.fileUpload({
 * contentSafety })` and `b.staticServe({ contentSafety })` so a
 * single `{ profile, posture }` value flows across the stack
 * unchanged.
 *
 * @opts
 *   profile:        "strict" | "balanced" | "permissive",
 *   posture:        string,                                    // compliance posture name; e.g. "hipaa", "pci-dss"
 *   contentSafety:  { profile, posture },                      // shared shape with b.fileUpload / b.staticServe
 *
 * @example
 *   var rv = b.htmlBalance.checkSafe("<div onclick=\"x()\">hi</div>", { profile: "strict" });
 *   // → { balanceIssue: null, guardIssues: [{ kind: "event-handler-attribute", ... }], ok: false }
 *
 *   b.htmlBalance.checkSafe("<p>hello</p>", { profile: "strict" });
 *   // → { balanceIssue: null, guardIssues: [], ok: true }
 */
function checkSafe(html, opts) {
  opts = opts || {};
  var balanceIssue = check(html);
  var guardIssues = [];
  if (opts.profile || opts.contentSafety) {
    var profile = opts.profile || (opts.contentSafety && opts.contentSafety.profile) || "strict";
    var posture = opts.posture || (opts.contentSafety && opts.contentSafety.posture) || null;
    var validateOpts = { profile: profile };
    if (posture) validateOpts.compliancePosture = posture;
    var rv = _guardHtml().validate(html, validateOpts);
    if (rv && Array.isArray(rv.issues)) guardIssues = rv.issues;
  }
  return {
    balanceIssue: balanceIssue,
    guardIssues:  guardIssues,
    ok:           !balanceIssue && guardIssues.length === 0,
  };
}

module.exports = { check: check, checkSafe: checkSafe };
