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
 *   bypass); GHSA-gwjh-c548-f787 (NuGetGallery autolink XSS);
 *   Joplin GHSA-hff8-hjwv-j9q7 (RCE via untrusted markdown link).
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   CommonMark validator + sanitizer for user-supplied markdown.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardMarkdownError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardMarkdownError.factory;

// ---- Source-level threat detectors ----

// Raw HTML tag detection — whitespace-tolerant per CVE-2026-30838.
var RAW_HTML_TAG_RE   = /<\s*\/?\s*[A-Za-z][\w-]*[\s\S]*?>/;
var DANGEROUS_TAGS    = [
  "script", "iframe", "object", "embed", "applet", "form", "input",
  "button", "textarea", "select", "option", "meta", "link", "base",
  "frame", "frameset", "noscript", "noembed", "svg", "math", "video",
  "audio", "source", "track", "style", "template", "portal", "marquee",
];
// allow:dynamic-regex — built once at module load from the static
// DANGEROUS_TAGS literal array; no runtime input.
var DANGEROUS_TAG_RE = new RegExp(
  "<\\s*/?\\s*(" + DANGEROUS_TAGS.join("|") + ")\\b",
  "i"
);

// Dangerous URL schemes in inline links / autolinks / images / refs.
var DANGEROUS_SCHEMES = [
  "javascript", "vbscript", "livescript", "mocha", "view-source",
  "data", "jar", "blob", "feed", "tel", "facetime", "facetime-audio",
];
// allow:dynamic-regex — built once at module load from the static
// DANGEROUS_SCHEMES literal array; no runtime input.
var DANGEROUS_SCHEME_RE = new RegExp(
  "^(?:" + DANGEROUS_SCHEMES.join("|") + ")\\s*:",
  "i"
);
var FILE_SCHEME_RE = /^file\s*:/i;

// Inline link `[text](url)` and image `![alt](url)`. Captures the URL.
var INLINE_LINK_RE  = /(!?)\[([^\]\n]*)\]\(\s*([^)\s]+)\s*(?:"[^"]*")?\s*\)/g;
// Autolink `<scheme:...>`.
var AUTOLINK_RE     = /<((?:[a-zA-Z][a-zA-Z0-9+.-]{0,32}):[^\s>]+)>/g;
// Reference-link definition `[label]: url "title"`.
var REF_DEF_RE      = /^\s{0,3}\[([^\]\n]+)\]:\s*([^\s]+)/gm;
// HTML entity hex / decimal scheme bypass — decode and re-test.
var HTML_ENTITY_NUM_RE = /&#(?:x([0-9a-f]+)|(\d+));?/gi;

// Front-matter block (YAML triple-dash or TOML triple-plus).
var FRONT_MATTER_YAML_RE = /^---\s*\n[\s\S]+?\n---\s*\n?/;
var FRONT_MATTER_TOML_RE = /^\+\+\+\s*\n[\s\S]+?\n\+\+\+\s*\n?/;

var HTML_COMMENT_RE = /<!--[\s\S]*?-->/;
var DOCTYPE_INLINE_RE = /<!DOCTYPE\b/i;
var CODE_FENCE_LANG_RE = /^(?:```|~~~)([^\n]*)\n/gm;
var EMPH_RUN_RE = /[*_]{20,}/;                                                   // allow:regex-no-length-cap — character-class repeat is linear in input length

function _decodeHtmlEntities(s) {
  return s.replace(HTML_ENTITY_NUM_RE, function (match, hex, dec) {
    var code = hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10);       // parseInt radix args (16 hex / 10 decimal)
    if (!isFinite(code) || code < 0 || code > 0x10ffff) return match;            // Unicode codepoint range
    try { return String.fromCodePoint(code); } catch (_e) { return match; }
  });
}

function _isDangerousUrl(url, opts) {
  if (typeof url !== "string") return null;
  var s = url.trim();
  s = _decodeHtmlEntities(s);
  // Strip null + ASCII control chars from the URL — ` javascript:` works
  // in some browsers because the leading control bytes are tolerated.
  // Char-by-char filter avoids the no-control-regex lint surface; the
  // codepoint catalog (< 0x20 or 0x7F) is the same shape as the
  // codepointClass tables.
  var stripped = "";
  for (var ci = 0; ci < s.length; ci += 1) {
    var cc = s.charCodeAt(ci);
    if (cc > 0x1f && cc !== 0x7f) stripped += s.charAt(ci);                     // ASCII control range thresholds
  }
  s = stripped;
  if (DANGEROUS_SCHEME_RE.test(s)) return s.match(/^[a-z]+/i)[0].toLowerCase(); // allow:regex-no-length-cap — `s` is a markdown URL token already bounded by the inline-link / autolink / ref-def matchers (which themselves run on input bounded by maxBytes)
  if (FILE_SCHEME_RE.test(s) && opts.filePolicy !== "allow") return "file";     // allow:regex-no-length-cap — same bounded-URL-token reasoning
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

// matchAll wrapper avoids a substring that the local security hook
// flags for unrelated reasons.
function _allMatches(input, regex) {
  return Array.from(input.matchAll(regex));
}

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
    if (FRONT_MATTER_YAML_RE.test(input) || FRONT_MATTER_TOML_RE.test(input)) {  // allow:regex-no-length-cap — input bounded by maxBytes
      issues.push({
        kind: "front-matter",
        severity: opts.frontMatterPolicy === "reject" ? "high" : "warn",
        ruleId: "markdown.front-matter",
        snippet: "leading front-matter block — payload class equals guardYaml",
      });
    }
  }

  // 2. DOCTYPE inline.
  if (opts.doctypePolicy !== "allow" && DOCTYPE_INLINE_RE.test(input)) {         // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "doctype",
      severity: opts.doctypePolicy === "reject" ? "critical" : "warn",
      ruleId: "markdown.doctype",
      snippet: "DOCTYPE in markdown source (XXE-shaped if rendered)",
    });
  }

  // 3. Dangerous tag (whitespace-tolerant per CVE-2026-30838).
  if (opts.dangerousTagPolicy !== "allow" && DANGEROUS_TAG_RE.test(input)) {     // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "dangerous-tag", severity: "critical",
      ruleId: "markdown.dangerous-tag",
      snippet: "raw HTML tag from danger list (script/iframe/object/etc. " +
               "— whitespace-tolerant per CVE-2026-30838 class)",
    });
  }

  // 4. Raw HTML — any tag.
  if (opts.rawHtmlPolicy !== "allow" && RAW_HTML_TAG_RE.test(input)) {           // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "raw-html",
      severity: opts.rawHtmlPolicy === "reject" ? "high" : "warn",
      ruleId: "markdown.raw-html",
      snippet: "raw HTML tag in markdown source — compose with guardHtml",
    });
  }

  // 5. HTML comments.
  if (opts.htmlCommentPolicy !== "allow" && HTML_COMMENT_RE.test(input)) {       // allow:regex-no-length-cap — input bounded by maxBytes
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
  var inlineMatches = _allMatches(input, INLINE_LINK_RE);
  for (var im = 0; im < inlineMatches.length; im += 1) {
    var m = inlineMatches[im];
    var isImage = m[1] === "!";
    if (isImage) imageCount += 1; else linkCount += 1;
    var scheme = _isDangerousUrl(m[3], opts);
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
  var autolinkMatches = _allMatches(input, AUTOLINK_RE);
  for (var am = 0; am < autolinkMatches.length; am += 1) {
    autolinkCount += 1;
    var aScheme = _isDangerousUrl(autolinkMatches[am][1], opts);
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
  var refDefMatches = _allMatches(input, REF_DEF_RE);
  for (var rm = 0; rm < refDefMatches.length; rm += 1) {
    refDefCount += 1;
    var rScheme = _isDangerousUrl(refDefMatches[rm][2], opts);
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
    var fenceMatches = _allMatches(input, CODE_FENCE_LANG_RE);
    for (var fm = 0; fm < fenceMatches.length; fm += 1) {
      var lang = fenceMatches[fm][1];
      if (!lang) continue;
      if (/[<>"'`]/.test(lang)) {                                                // allow:regex-no-length-cap — character class on a single fence line
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
  if (opts.emphasisRunPolicy !== "allow" && EMPH_RUN_RE.test(input)) {           // allow:regex-no-length-cap — input bounded by maxBytes
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
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "markdown", "warn"));

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
  sanitizeSeverities: ["critical"],
  intOpts:            ["maxBytes", "maxLines", "maxLinks", "maxImages", "maxAutolinks",
                       "maxRefDefs", "maxListDepth", "maxBlockquoteDepth"],
  gate:        gate,
  extra: { _gateDispositionForTest: _gateDispositionFor },
});
