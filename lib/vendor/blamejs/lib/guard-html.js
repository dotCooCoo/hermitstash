"use strict";
/**
 * @module b.guardHtml
 * @nav    Guards
 * @title  Guard Html
 *
 * @intro
 *   HTML / XSS defense — DOM-clobbering, mXSS, and entity-encoding
 *   bypasses. Tag and attribute allowlists; URL-scheme allowlist on
 *   every URL-bearing attribute; bidi / control / zero-width
 *   stripping. Threat catalog grounded in 2026 sanitizer research
 *   (DOMPurify CVE series, OWASP XSS / DOM-Clobbering / HTML5
 *   Security cheat sheets, PortSwigger / Sonar / trace37 mXSS
 *   write-ups, html5sec.org).
 *
 *   Three profiles ship — `strict` / `balanced` / `permissive` —
 *   plus four compliance postures (`hipaa` / `pci-dss` / `gdpr` /
 *   `soc2`) that compose on top via the strictest-wins rule.
 *   `b.guardHtml.gate(opts)` returns a guard descriptor that plugs
 *   into `b.fileUpload.contentSafety` / `b.staticServe.contentSafety`
 *   / `b.guardAll`.
 *
 *   Threat catalog covered:
 *
 *     1. Dangerous tags — script / style / link / meta / base /
 *        iframe / object / embed / applet / form / input / button /
 *        textarea / select / isindex / marquee / blink / layer /
 *        ilayer / plaintext / listing / xmp / audio / video / source
 *        / track / math / svg / template / noscript / noembed /
 *        noframes / portal / dialog / keygen / menuitem / command /
 *        frame / frameset.
 *     2. on* event-handler attributes — every attribute matching
 *        /^on[a-z]/ is denied unconditionally.
 *     3. Form-override attributes — formaction / formmethod /
 *        formenctype / formtarget / formnovalidate (CWE-1021).
 *     4. Iframe inline-HTML — srcdoc on iframe always denied.
 *     5. Custom-element registration — `is="..."` always denied.
 *     6. CSP-bypass-shaped attributes — nonce / integrity /
 *        crossorigin stripped from sanitized output.
 *     7. URL scheme validation on URL-bearing attributes — href /
 *        src / action / cite / longdesc / manifest / archive /
 *        codebase / data / classid / code / profile / ping / dynsrc
 *        / lowsrc / background / poster / icon / xlink:href.
 *        Per-profile allowlist; denied schemes (always):
 *        javascript / vbscript / livescript / mocha / data (outside
 *        image context) / file / mhtml / jar / intent / view-source.
 *     8. CSS-injection inside style="..." values — expression( (IE),
 *        behavior: (IE), -moz-binding (Firefox legacy), javascript: /
 *        vbscript: / livescript: inside url(), @import, @namespace.
 *     9. DOM clobbering — id and name attributes whose values match
 *        a well-known JS global (document / window / location /
 *        cookie / __proto__ / constructor / ...) on clobber-prone
 *        elements (form / input / button / a / img / iframe /
 *        object / embed / select / textarea).
 *    10. mXSS hint detection — namespace-context-shift parents
 *        (svg / math), CDATA inside HTML mode, template content
 *        fragments with entity-encoded payloads.
 *    11. Unicode bidi (CVE-2021-42574 Trojan Source) inside text
 *        and attribute values.
 *    12. C0 control characters, null bytes, zero-width chars —
 *        strip-or-reject per profile.
 *    13. IE conditional comments — <!--[if ...]>...<![endif]-->
 *        refused in strict, stripped in balanced.
 *    14. <base href> / <base target> — silently redirects every
 *        relative URL on the page; always denied.
 *    15. <meta http-equiv> with refresh / Set-Cookie / X-XSS-
 *        Protection — silent navigation + cookie injection.
 *    16. ARIA spoofing — flagged for audit when role mismatches
 *        the semantic tag.
 *    17. Image-context data: URLs — sanitize allows data:image/png
 *        / jpeg / gif / webp; svg+xml requires explicit opt-in.
 *    18. Total-document size cap, per-attribute-value size cap,
 *        max-tag-depth (anti-recursion), max-attribute-count-per-
 *        tag.
 *
 *   Threat-detection regex literals are composed PROGRAMMATICALLY
 *   from numeric codepoint range tables (BIDI_RANGES /
 *   C0_CTRL_RANGES / ZERO_WIDTH_RANGES). The source file never
 *   embeds the attack characters themselves.
 *
 *   Sanitize discipline: this module ships a token-level rewriter
 *   that preserves the allowlisted tag set and strips the rest.
 *   For HOSTILE sources, the documented correct response is
 *   validate + reject — not sanitize. mXSS bypasses against any
 *   non-DOM sanitizer are a known arms-race; the gate's `refuse`
 *   path is the one with strong invariants. Operators with
 *   display-of-untrusted-html requirements should additionally
 *   serve content under a strict CSP (default-src 'none' or
 *   sandboxed iframe).
 *
 * @card
 *   HTML / XSS defense — DOM-clobbering, mXSS, and entity-encoding bypasses.
 */

var codepointClass = require("./codepoint-class");
var markupTokenizer = require("./markup-tokenizer");
var markupEscape = require("./markup-escape").markupEscape;
var guardHtmlWcag = require("./guard-html-wcag");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeUrl = require("./safe-url");
var { GuardHtmlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardHtmlError.factory;

// ---- Codepoint catalog (shared via lib/codepoint-class) ----

var C0_CTRL_RE_G  = codepointClass.C0_CTRL_RE_G;
var ZW_RE_G       = codepointClass.ZW_RE_G;

// ---- Tag denylists / allowlists ----

// Always-dangerous tags. Active scripts, plugin embeds, form elements,
// frames, foreign-content (svg/math), template (mxss vector), legacy
// parser-mode-shift tags, HTML5 newer-attack-surface elements.
var DANGEROUS_TAGS = Object.freeze([
  "script", "style", "link", "meta", "base", "frame", "frameset",
  "iframe", "object", "embed", "applet", "form", "input", "button",
  "textarea", "select", "option", "optgroup", "fieldset", "legend",
  "datalist", "isindex", "marquee", "blink", "layer", "ilayer",
  "plaintext", "listing", "xmp", "audio", "video", "source", "track",
  "math", "svg", "template", "noscript", "noembed", "noframes",
  "portal", "dialog", "keygen", "menuitem", "command",
]);

// Strict text-formatting allowlist.
var STRICT_ALLOWED_TAGS = Object.freeze([
  "p", "br", "hr", "b", "i", "u", "s", "em", "strong", "code", "pre",
  "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote",
  "span", "div",
]);

// Balanced — adds links, images, tables, semantic markup.
var BALANCED_ALLOWED_TAGS = Object.freeze(STRICT_ALLOWED_TAGS.concat([
  "a", "img", "table", "thead", "tbody", "tfoot", "tr", "td", "th",
  "caption", "colgroup", "col", "dl", "dt", "dd", "del", "ins",
  "sub", "sup", "small", "abbr", "cite", "q", "kbd", "mark",
  "figure", "figcaption", "address", "time",
]));

// Permissive — every tag NOT in DANGEROUS_TAGS.
function _permissiveAllowed() {
  var deny = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { deny[t] = true; });
  // Common allowed set as the universe for the permissive list.
  var universe = [
    "html", "body", "head", "title", "main", "header", "footer",
    "nav", "section", "article", "aside", "details", "summary",
    "menu", "dir", "center", "font", "big", "tt", "strike",
    "var", "samp", "i", "b", "u", "s", "em", "strong", "code", "pre",
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "blockquote", "span", "div", "a", "img",
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
    "colgroup", "col", "dl", "dt", "dd", "del", "ins", "sub", "sup",
    "small", "abbr", "cite", "q", "kbd", "mark", "figure", "figcaption",
    "address", "time", "picture", "ruby", "rt", "rp", "wbr", "data",
    "output", "progress", "meter", "bdo", "bdi",
  ];
  return Object.freeze(universe.filter(function (t) { return !deny[t]; }));
}
var PERMISSIVE_ALLOWED_TAGS = _permissiveAllowed();

// Form-override + dangerous attributes (excluding on*).
var DANGEROUS_ATTRS = Object.freeze([
  "formaction", "formmethod", "formenctype", "formtarget", "formnovalidate",
  "srcdoc", "is", "integrity", "nonce", "crossorigin",
  "http-equiv", "manifest",
]);

// URL-bearing attributes — values get scheme-validated.
var URL_ATTRS = Object.freeze([
  "href", "src", "action", "cite", "longdesc", "manifest", "archive",
  "codebase", "data", "classid", "code", "profile", "ping", "dynsrc",
  "lowsrc", "background", "poster", "icon", "xlink:href",
]);

// Always-allowed schemes (every profile).
var SAFE_SCHEMES = gateContract.SAFE_URL_SCHEMES;

// Schemes denied by default. `data` is dangerous globally except in
// image context (data:image/*) which is the only data: payload that
// can't directly script the page; the per-attribute check below honours
// that exception when allowImageData=true and the host tag is <img>.
// Markup-attribute scheme denylist — the shared XSS / dangerous-resource set.
var DANGEROUS_SCHEMES = gateContract.DANGEROUS_URL_SCHEMES;

// CSS dangerous tokens — case-insensitive match against attribute
// value content.
var CSS_DANGEROUS_PATTERNS = Object.freeze([
  /expression\s*\(/i,
  /behavior\s*:/i,
  /-moz-binding/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /livescript\s*:/i,
  /@import/i,
  /@namespace/i,
]);

// DOM-clobbering global-name targets. Element id/name matching one of
// these on a clobber-prone tag (form / input / button / a / img /
// iframe / object) overshadows the global access path.
var CLOBBER_GLOBALS = Object.freeze([
  "document", "window", "location", "cookie", "top", "parent", "self",
  "frames", "navigator", "history", "screen", "localStorage",
  "sessionStorage", "indexedDB", "fetch", "XMLHttpRequest",
  "atob", "btoa", "eval", "Function",
  "constructor", "prototype", "__proto__", "innerHTML", "outerHTML",
  "src", "href", "action", "form", "body", "head", "html",
  "addEventListener", "removeEventListener", "postMessage",
  "globalThis", "this", "import",
]);

var CLOBBER_PRONE_TAGS = Object.freeze([
  "form", "input", "button", "a", "img", "iframe", "object",
  "embed", "select", "textarea",
]);

var EVENT_HANDLER_RE = /^on[a-z]/i;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    allowedTags:        STRICT_ALLOWED_TAGS,
    allowedAttrs:       Object.freeze(["class", "title", "lang", "dir"]),
    urlSchemes:         SAFE_SCHEMES,
    allowImageData:     false,
    allowComments:      false,
    bidiPolicy:         "reject",
    controlPolicy:      "reject",
    nullBytePolicy:     "reject",
    zeroWidthPolicy:    "strip",
    cssPolicy:          "reject",
    domClobberPolicy:   "reject",
    mxssHintPolicy:     "reject",
    maxBytes:           C.BYTES.mib(2),
    maxAttrValueBytes:  C.BYTES.kib(8),
    maxTagDepth:        128,                                          // tag-nesting depth count, not bytes
    maxAttrsPerTag:     64,                                           // attribute count per tag, not bytes
  },
  "balanced": {
    allowedTags:        BALANCED_ALLOWED_TAGS,
    allowedAttrs:       Object.freeze([
      "class", "title", "lang", "dir", "alt", "href", "src", "width",
      "height", "rel", "target", "colspan", "rowspan", "scope",
      "datetime", "cite", "id",
    ]),
    urlSchemes:         Object.freeze(SAFE_SCHEMES.concat(["ftp"])),
    allowImageData:     true,
    allowComments:      false,
    bidiPolicy:         "strip",
    controlPolicy:      "strip",
    nullBytePolicy:     "strip",
    zeroWidthPolicy:    "strip",
    cssPolicy:          "strip",
    domClobberPolicy:   "strip",
    mxssHintPolicy:     "audit",
    maxBytes:           C.BYTES.mib(8),
    maxAttrValueBytes:  C.BYTES.kib(32),
    maxTagDepth:        256,                                          // tag-nesting depth count, not bytes
    maxAttrsPerTag:     128,                                          // attribute count per tag, not bytes
  },
  "permissive": {
    allowedTags:        PERMISSIVE_ALLOWED_TAGS,
    allowedAttrs:       Object.freeze([
      "class", "title", "lang", "dir", "alt", "href", "src", "width",
      "height", "rel", "target", "colspan", "rowspan", "scope",
      "datetime", "cite", "id", "tabindex", "accesskey",
    ]),
    urlSchemes:         Object.freeze(SAFE_SCHEMES.concat(["ftp", "sftp", "ws", "wss"])),
    allowImageData:     true,
    allowComments:      true,
    bidiPolicy:         "audit",
    controlPolicy:      "strip",
    nullBytePolicy:     "strip",
    zeroWidthPolicy:    "strip",
    cssPolicy:          "audit",
    domClobberPolicy:   "audit",
    mxssHintPolicy:     "audit",
    maxBytes:           C.BYTES.mib(32),
    maxAttrValueBytes:  C.BYTES.kib(64),
    maxTagDepth:        512,                                          // tag-nesting depth count, not bytes
    maxAttrsPerTag:     256,                                          // attribute count per tag, not bytes
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

// ---- Internal helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardHtmlError,
    errCodePrefix:      "html",
  });
}

/**
 * @primitive b.guardHtml.escapeText
 * @signature b.guardHtml.escapeText(value)
 * @since     0.7.6
 * @related   b.guardHtml.escapeAttr, b.guardHtml.sanitize
 *
 * HTML entity-escape for text-content context. Encodes the five
 * core characters `&` `<` `>` `"` `'` so the result is safe to
 * embed inside an element's text body. `null` / `undefined` coerce
 * to an empty string. Use this for plain interpolation of
 * untrusted strings into rendered HTML.
 *
 * @example
 *   var html = b.guardHtml.escapeText("<oops>");
 *   // → "&lt;oops&gt;"
 *
 *   var blank = b.guardHtml.escapeText(null);
 *   // → ""
 */
function escapeText(value) {
  var s = value == null ? "" : String(value);
  return markupEscape(s, { apos: "&#39;" });
}

/**
 * @primitive b.guardHtml.escapeAttr
 * @signature b.guardHtml.escapeAttr(value)
 * @since     0.7.6
 * @related   b.guardHtml.escapeText, b.guardHtml.sanitize
 *
 * HTML entity-escape for attribute-value context. Same five
 * characters as `escapeText` plus backtick (legacy IE attribute
 * terminator) and `=` (unquoted-attribute edge). Use this when
 * interpolating an untrusted string between double-quoted attribute
 * delimiters.
 *
 * @example
 *   var attr = b.guardHtml.escapeAttr('say "hi"');
 *   // → "say &quot;hi&quot;"
 *
 *   var ie = b.guardHtml.escapeAttr("a`b=c");
 *   // → "a&#96;b&#61;c"
 */
function escapeAttr(value) {
  var s = value == null ? "" : String(value);
  // Base markup chars + apostrophe via markupEscape; the backtick + "="
  // escapes are the IE attribute-injection hardening unique to this escaper.
  return markupEscape(s, { apos: "&#39;" })
    .replace(/`/g, "&#96;")
    .replace(/=/g, "&#61;");
}

// HTML5 named entities that decode to ASCII codepoints — focused on
// the entries browsers honor inside URL contexts (whitespace, control
// chars, scheme-significant punctuation). The full WHATWG named-
// character-reference table is ~2,231 entries; this is the
// security-load-bearing subset documented in scheme-bypass writeups
// (CVE-2026-30838 class). High-codepoint named entities (e.g. mathematical
// symbols) don't affect URL scheme parsing, so they're omitted.
var NAMED_ENTITY_ASCII = {
  // Whitespace + control chars browsers strip inside URL schemes
  Tab: "\t", NewLine: "\n",
  // Scheme-significant punctuation
  colon: ":", semi: ";", period: ".", sol: "/", bsol: "\\",
  num: "#", excl: "!", quest: "?", lpar: "(", rpar: ")",
  lsqb: "[", rsqb: "]", lcub: "{", rcub: "}",
  // Quotes / brackets
  quot: "\"", apos: "'", lt: "<", gt: ">",
  // Misc ASCII
  amp: "&", commat: "@", dollar: "$", percnt: "%",
  ast: "*", plus: "+", lowbar: "_", hyphen: "-",
  // Whitespace markers (codepoints in the ASCII / Latin-1 range that
  // browsers treat as URL-strippable)
  nbsp: " ",
};

// _normalizeUrl — peel off entity-encoded leading whitespace and
// HTML/URL-encoded scheme prefix tricks, then return the lowercased
// scheme. Returns "" if no scheme.
function _extractScheme(rawUrl) {
  var s = String(rawUrl || "").trim();
  // Decode HTML numeric entities (hex &#x..; and decimal &#..;, semicolon
  // OPTIONAL) just enough to expose hidden schemes like &#x6A;avascript: or
  // the browser-decoded no-semicolon form &#106avascript:. Shared decoder so
  // guard-html / guard-svg / guard-markdown can't drift (see codepoint-class).
  s = codepointClass.decodeNumericEntities(s);
  // Decode HTML5 named entities that browsers honor inside URL
  // contexts. Without this, payloads like `java&Tab;script:alert(1)`
  // bypass the scheme allowlist (the literal `&Tab;` between `java`
  // and `script:` doesn't match any denied scheme; the browser then
  // decodes the entity, strips the tab, and executes javascript:).
  s = s.replace(/&([A-Za-z][A-Za-z0-9]+);/g, function (m, name) {
    if (Object.prototype.hasOwnProperty.call(NAMED_ENTITY_ASCII, name)) {
      return NAMED_ENTITY_ASCII[name];
    }
    return m;
  });
  // Strip embedded whitespace + control chars + zero-widths the
  // URL parser would tolerate.
  s = s.replace(C0_CTRL_RE_G, "").replace(ZW_RE_G, "");
  var m = s.match(/^([A-Za-z][A-Za-z0-9+.-]*):/);
  return m ? m[1].toLowerCase() : "";
}

function _isImageDataUrl(rawUrl) {
  var s = String(rawUrl || "").trim();
  return /^data:image\/(png|jpeg|jpg|gif|webp);/i.test(s);
}

function _isUrlAttr(name) {
  var n = name.toLowerCase();
  for (var i = 0; i < URL_ATTRS.length; i += 1) {
    if (URL_ATTRS[i] === n) return true;
  }
  return false;
}

function _isClobberProne(tag) {
  var t = tag.toLowerCase();
  for (var i = 0; i < CLOBBER_PRONE_TAGS.length; i += 1) {
    if (CLOBBER_PRONE_TAGS[i] === t) return true;
  }
  return false;
}

function _isClobberGlobal(name) {
  for (var i = 0; i < CLOBBER_GLOBALS.length; i += 1) {
    if (CLOBBER_GLOBALS[i] === name) return true;
  }
  return false;
}

function _isCssDangerous(value) {
  for (var i = 0; i < CSS_DANGEROUS_PATTERNS.length; i += 1) {
    if (CSS_DANGEROUS_PATTERNS[i].test(value)) return true;
  }
  return false;
}

// ---- Tokenizer ----
//
// Pure-JS HTML scanner. NOT a full DOM parser — designed for threat
// detection and conservative tag/attr filtering. The output is a list
// of tokens: { type: "tag" | "endTag" | "comment" | "text" | "doctype",
// name, attrs, raw, start, end }. Sanitization re-walks this list and
// emits a filtered HTML string.

function _tokenize(input, maxBytes) {
  var s = String(input || "");
  var nb = Buffer.byteLength(s, "utf8");
  if (nb > maxBytes) {
    throw _err("html.too-large",
      "input " + nb + " bytes exceeds maxBytes " + maxBytes);
  }
  var tokens = [];
  var len = s.length;
  var pos = 0;

  while (pos < len) {
    var lt = s.indexOf("<", pos);
    if (lt === -1) {
      tokens.push({ type: "text", raw: s.slice(pos), start: pos, end: len });
      break;
    }
    if (lt > pos) {
      tokens.push({ type: "text", raw: s.slice(pos, lt), start: pos, end: lt });
    }

    // Comment / CDATA / doctype
    if (s.startsWith("<!--", lt)) {
      // WHATWG comment end (covers "--!>" + abrupt "<!-->" / "<!--->"), not
      // only "-->", so a smuggled element after an early terminator is split
      // out as a live token instead of hidden inside the comment (mXSS).
      var endC = markupTokenizer.htmlCommentEnd(s, lt);
      if (endC === -1) endC = len;
      tokens.push({ type: "comment", raw: s.slice(lt, endC), start: lt, end: endC });
      pos = endC; continue;
    }
    if (s.startsWith("<![CDATA[", lt)) {
      var endX = s.indexOf("]]>", lt + 9);
      if (endX === -1) endX = len;
      else endX += 3;
      tokens.push({ type: "cdata", raw: s.slice(lt, endX), start: lt, end: endX });
      pos = endX; continue;
    }
    if (s.charAt(lt + 1) === "!") {
      var endD = s.indexOf(">", lt);
      if (endD === -1) endD = len;
      else endD += 1;
      tokens.push({ type: "doctype", raw: s.slice(lt, endD), start: lt, end: endD });
      pos = endD; continue;
    }

    // End tag
    if (s.charAt(lt + 1) === "/") {
      var endE = s.indexOf(">", lt);
      if (endE === -1) endE = len;
      else endE += 1;
      var endName = s.slice(lt + 2, endE - 1).trim().toLowerCase().split(/\s/)[0];
      tokens.push({
        type: "endTag", name: endName,
        raw: s.slice(lt, endE), start: lt, end: endE,
      });
      pos = endE; continue;
    }

    // Start tag — find the matching `>`, but skip over `>` inside
    // quoted attribute values.
    var p = markupTokenizer.scanToTagEnd(s, lt + 1, len);
    var endT = p < len ? p + 1 : len;
    var raw = s.slice(lt, endT);
    var inner = raw.slice(1, raw.charAt(raw.length - 1) === ">" ? raw.length - 1 : raw.length);
    if (inner.endsWith("/")) inner = inner.slice(0, inner.length - 1);

    var htmlParts = markupTokenizer.splitTagNameAttrs(inner, /^([A-Za-z][A-Za-z0-9:-]*)/);
    var tagName = htmlParts.tagName;
    var attrs = _parseAttrs(htmlParts.attrSrc);
    tokens.push({
      type: "tag", name: tagName, attrs: attrs,
      raw: raw, start: lt, end: endT,
      selfClosing: raw.charAt(raw.length - 2) === "/",
    });
    pos = endT;
  }
  return tokens;
}

function _parseAttrs(src) {
  // Returns array of { name, value, raw } in source order. Preserves
  // original casing of attribute names; consumers lowercase as needed.
  var attrs = [];
  var s = src.trim();
  var len = s.length;
  var p = 0;
  while (p < len) {
    while (p < len && /\s/.test(s.charAt(p))) p += 1;
    if (p >= len) break;
    var nameStart = p;
    while (p < len && !/[\s=>/]/.test(s.charAt(p))) p += 1;
    var attrName = s.slice(nameStart, p);
    if (!attrName) break;
    while (p < len && /\s/.test(s.charAt(p))) p += 1;
    var attrValue = "";
    var raw = attrName;
    if (p < len && s.charAt(p) === "=") {
      p += 1;
      while (p < len && /\s/.test(s.charAt(p))) p += 1;
      var q = s.charAt(p);
      if (q === '"' || q === "'") {
        var endQ = s.indexOf(q, p + 1);
        if (endQ === -1) endQ = len;
        attrValue = s.slice(p + 1, endQ);
        raw = attrName + "=" + s.slice(p, endQ + 1);
        p = endQ + 1;
      } else {
        var valStart = p;
        while (p < len && !/[\s>]/.test(s.charAt(p))) p += 1;
        attrValue = s.slice(valStart, p);
        raw = attrName + "=" + attrValue;
      }
    }
    attrs.push({ name: attrName, value: attrValue, raw: raw });
  }
  return attrs;
}

// ---- Detection pass ----

function _detectIssues(input, opts) {
  var s = String(input || "");
  // 1. Whole-input bidi / null-byte / control char threats.
  var issues = codepointClass.detectCharThreats(s, opts, "html", "warn");

  var tokens;
  try { tokens = _tokenize(s, opts.maxBytes); }
  catch (e) {
    issues.push({
      kind: "tokenize-failed", severity: "high", ruleId: "html.tokenize",
      snippet: e && e.message,
    });
    return issues;
  }

  var allowedTags = Object.create(null);
  (opts.allowedTags || []).forEach(function (t) { allowedTags[t.toLowerCase()] = true; });
  var dangerousTags = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { dangerousTags[t] = true; });

  var depth = 0;
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];

    if (tok.type === "comment") {
      // IE conditional comments — `<!--[if ...]>` family.
      if (/<!--\s*\[\s*if/i.test(tok.raw) && opts.allowComments !== true) {
        issues.push({
          kind: "ie-conditional-comment", severity: "high",
          ruleId: "html.ie-conditional",
          location: tok.start,
          snippet: "IE conditional comment",
        });
      }
      continue;
    }

    if (tok.type === "tag") {
      depth += 1;
      if (depth > opts.maxTagDepth) {
        issues.push({
          kind: "depth-cap", severity: "high", ruleId: "html.depth",
          location: tok.start,
          snippet: "tag nesting depth " + depth + " exceeds maxTagDepth " + opts.maxTagDepth,
        });
      }
      if (Array.isArray(tok.attrs) && tok.attrs.length > opts.maxAttrsPerTag) {
        issues.push({
          kind: "attr-count-cap", severity: "high", ruleId: "html.attr-count",
          location: tok.start,
          snippet: "attribute count " + tok.attrs.length + " exceeds maxAttrsPerTag",
        });
      }
      if (dangerousTags[tok.name]) {
        issues.push({
          kind: "dangerous-tag", severity: "critical", ruleId: "html.tag",
          location: tok.start,
          snippet: "dangerous tag <" + tok.name + ">",
        });
      } else if (Object.keys(allowedTags).length > 0 && !allowedTags[tok.name]) {
        issues.push({
          kind: "non-allowlisted-tag", severity: "high", ruleId: "html.tag",
          location: tok.start,
          snippet: "tag <" + tok.name + "> not in allowedTags",
        });
      }

      // Per-attribute checks.
      var attrs = tok.attrs || [];
      for (var ai = 0; ai < attrs.length; ai += 1) {
        var a = attrs[ai];
        var an = a.name.toLowerCase();
        if (a.value && Buffer.byteLength(a.value, "utf8") > opts.maxAttrValueBytes) {
          issues.push({
            kind: "attr-value-too-large", severity: "high",
            ruleId: "html.attr-size",
            location: tok.start,
            snippet: "attribute " + JSON.stringify(an) + " value exceeds maxAttrValueBytes",
          });
        }
        if (EVENT_HANDLER_RE.test(an)) {                              // allow:regex-no-length-cap — `an` is an attribute name from the tokenizer, length-bounded by HTML naming rules
          issues.push({
            kind: "event-handler", severity: "critical",
            ruleId: "html.event-handler",
            location: tok.start,
            snippet: "event-handler attribute " + JSON.stringify(an),
          });
          continue;
        }
        if (DANGEROUS_ATTRS.indexOf(an) !== -1) {
          issues.push({
            kind: "dangerous-attr", severity: "critical",
            ruleId: "html.attr",
            location: tok.start,
            snippet: "dangerous attribute " + JSON.stringify(an),
          });
        }
        if (_isUrlAttr(an)) {
          var scheme = _extractScheme(a.value);
          if (scheme === "" && a.value && a.value.charAt(0) !== "#" &&
              a.value.charAt(0) !== "/" && a.value.charAt(0) !== "?") {
            // Relative URL — allowed.
          } else if (scheme && DANGEROUS_SCHEMES.indexOf(scheme) !== -1) {
            // Image-context data: special-case.
            if (scheme === "data" && opts.allowImageData &&
                tok.name === "img" && _isImageDataUrl(a.value)) {
              // Allowed image data URL.
            } else {
              issues.push({
                kind: "dangerous-url-scheme", severity: "critical",
                ruleId: "html.url-scheme",
                location: tok.start,
                snippet: "dangerous URL scheme " + JSON.stringify(scheme) +
                         " in attribute " + JSON.stringify(an),
              });
            }
          } else if (scheme && opts.urlSchemes &&
                     opts.urlSchemes.indexOf(scheme) === -1) {
            if (!(scheme === "data" && opts.allowImageData &&
                  tok.name === "img" && _isImageDataUrl(a.value))) {
              issues.push({
                kind: "non-allowlisted-url-scheme", severity: "high",
                ruleId: "html.url-scheme",
                location: tok.start,
                snippet: "URL scheme " + JSON.stringify(scheme) +
                         " not in profile allowlist",
              });
            }
          }
        }
        if (an === "style" && opts.cssPolicy !== "allow") {
          if (_isCssDangerous(a.value)) {
            issues.push({
              kind: "css-injection", severity: "critical",
              ruleId: "html.css",
              location: tok.start,
              snippet: "dangerous CSS token in style attribute",
            });
          }
        }
        if ((an === "id" || an === "name") && _isClobberProne(tok.name) &&
            opts.domClobberPolicy !== "allow" &&
            _isClobberGlobal(a.value)) {
          issues.push({
            kind: "dom-clobber", severity: "critical",
            ruleId: "html.dom-clobber",
            location: tok.start,
            snippet: "DOM-clobbering " + an + "=" + JSON.stringify(a.value) +
                     " on <" + tok.name + ">",
          });
        }
      }

      // mXSS hint — namespace-context-shift tags carrying nested HTML.
      if ((tok.name === "svg" || tok.name === "math") &&
          opts.mxssHintPolicy !== "allow") {
        issues.push({
          kind: "mxss-hint", severity: "high", ruleId: "html.mxss",
          location: tok.start,
          snippet: "<" + tok.name + "> namespace-context-shift parent (mXSS vector)",
        });
      }
    } else if (tok.type === "endTag") {
      depth = Math.max(0, depth - 1);
    }
  }

  return issues;
}

// ---- Sanitize pass ----

function _sanitize(input, opts) {
  var s = String(input || "");
  var nb = Buffer.byteLength(s, "utf8");
  if (nb > opts.maxBytes) {
    throw _err("html.too-large",
      "input " + nb + " bytes exceeds maxBytes " + opts.maxBytes);
  }
  codepointClass.assertNoCharThreats(s, opts, _err, "html");
  s = codepointClass.applyCharStripPolicies(s, opts);

  var tokens;
  try { tokens = _tokenize(s, opts.maxBytes); }
  catch (e) {
    throw _err("html.tokenize-failed", "tokenizer failed: " + (e && e.message));
  }

  var allowedTags = Object.create(null);
  (opts.allowedTags || []).forEach(function (t) { allowedTags[t.toLowerCase()] = true; });
  var allowedAttrs = Object.create(null);
  (opts.allowedAttrs || []).forEach(function (a) { allowedAttrs[a.toLowerCase()] = true; });
  var dangerousTags = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { dangerousTags[t] = true; });

  // Tags whose text content is itself executable in the host parser
  // (script body = JS, style body = CSS). When we strip the open tag,
  // also skip every token until the matching close tag so the body
  // doesn't leak into output as visible text.
  var BODY_DROP_TAGS = { "script": true, "style": true, "noscript": true,
                         "noembed": true, "noframes": true, "iframe": true,
                         "object": true, "embed": true, "applet": true,
                         "template": true, "math": true, "svg": true };

  var out = [];
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];
    if (tok.type === "text") { out.push(tok.raw); continue; }
    if (tok.type === "doctype") { continue; }     // strip doctypes
    if (tok.type === "cdata") { continue; }       // strip cdata blocks
    if (tok.type === "comment") {
      if (opts.allowComments) out.push(tok.raw);
      continue;
    }
    if (tok.type === "endTag") {
      if (allowedTags[tok.name]) out.push("</" + tok.name + ">");
      continue;
    }
    // Start tag.
    if (dangerousTags[tok.name] || !allowedTags[tok.name]) {
      // For tags whose body is parsed as code (script/style/etc.), skip
      // forward to the matching close so the body doesn't surface as
      // visible text content in sanitized output.
      if (BODY_DROP_TAGS[tok.name] && !tok.selfClosing) {
        var depth2 = 1;
        var j = i + 1;
        while (j < tokens.length && depth2 > 0) {
          var t2 = tokens[j];
          if (t2.type === "tag" && t2.name === tok.name && !t2.selfClosing) depth2 += 1;
          else if (t2.type === "endTag" && t2.name === tok.name) depth2 -= 1;
          j += 1;
        }
        i = j - 1;
      }
      continue;
    }

    var attrParts = [];
    var attrs = tok.attrs || [];
    for (var ai = 0; ai < attrs.length; ai += 1) {
      var a = attrs[ai];
      var an = a.name.toLowerCase();
      if (EVENT_HANDLER_RE.test(an)) continue;
      if (DANGEROUS_ATTRS.indexOf(an) !== -1) continue;
      if (Object.keys(allowedAttrs).length > 0 && !allowedAttrs[an]) continue;
      if (a.value && Buffer.byteLength(a.value, "utf8") > opts.maxAttrValueBytes) continue;
      if (_isUrlAttr(an)) {
        var scheme = _extractScheme(a.value);
        if (scheme && DANGEROUS_SCHEMES.indexOf(scheme) !== -1) {
          if (!(scheme === "data" && opts.allowImageData &&
                tok.name === "img" && _isImageDataUrl(a.value))) {
            continue;
          }
        } else if (scheme && opts.urlSchemes &&
                   opts.urlSchemes.indexOf(scheme) === -1) {
          if (!(scheme === "data" && opts.allowImageData &&
                tok.name === "img" && _isImageDataUrl(a.value))) {
            continue;
          }
        }
      }
      if (an === "style" && _isCssDangerous(a.value)) continue;
      if ((an === "id" || an === "name") && _isClobberProne(tok.name) &&
          _isClobberGlobal(a.value)) continue;
      attrParts.push(an + "=\"" + escapeAttr(a.value) + "\"");
    }
    var open = "<" + tok.name + (attrParts.length ? " " + attrParts.join(" ") : "") +
               (tok.selfClosing ? " />" : ">");
    out.push(open);
  }
  return out.join("");
}

// ---- Public surface ----

/**
 * @primitive b.guardHtml.validate
 * @signature b.guardHtml.validate(input, opts?)
 * @since     0.7.6
 * @related   b.guardHtml.sanitize, b.guardHtml.gate
 *
 * Tokenize `input` (string or Buffer of HTML) and walk every
 * element / attribute against the resolved profile. Returns
 * `{ ok, issues }` where `issues` is an array of
 * `{ kind, severity, ruleId, location, snippet }` records.
 * Never modifies the input — call `sanitize` for that. Anti-DoS
 * caps (`maxBytes` / `maxAttrValueBytes` / `maxTagDepth` /
 * `maxAttrsPerTag`) are validated as positive finite integers;
 * passing `Infinity` throws.
 *
 * @opts
 *   profile:            string,   // "strict" | "balanced" | "permissive"
 *   compliancePosture:  string,   // "hipaa" | "pci-dss" | "gdpr" | "soc2"
 *   allowedTags:        Array<string>,
 *   allowedAttrs:       Array<string>,
 *   urlSchemes:         Array<string>,
 *   allowImageData:     boolean,
 *   allowComments:      boolean,
 *   bidiPolicy:         string,   // "reject" | "strip" | "audit"
 *   controlPolicy:      string,
 *   nullBytePolicy:     string,
 *   zeroWidthPolicy:    string,
 *   cssPolicy:          string,
 *   domClobberPolicy:   string,
 *   mxssHintPolicy:     string,
 *   maxBytes:           number,
 *   maxAttrValueBytes:  number,
 *   maxTagDepth:        number,
 *   maxAttrsPerTag:     number,
 *
 * @example
 *   var rv = b.guardHtml.validate("<p>hi</p><script>alert(1)</script>",
 *                                 { profile: "strict" });
 *   rv.ok;                   // → false
 *   rv.issues[0].kind;       // → "dangerous-tag"
 *   rv.issues[0].severity;   // → "critical"
 *
 *   var clean = b.guardHtml.validate("<p>just text</p>",
 *                                    { profile: "strict" });
 *   clean.ok;                // → true
 *   clean.issues.length;     // → 0
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxAttrValueBytes", "maxTagDepth", "maxAttrsPerTag"],
    "guardHtml.validate", GuardHtmlError, "html.bad-opt");

  return gateContract.runIssueValidator(input, opts, _detectIssues);
}

/**
 * @primitive b.guardHtml.sanitize
 * @signature b.guardHtml.sanitize(input, opts?)
 * @since     0.7.6
 * @related   b.guardHtml.validate, b.guardHtml.gate
 *
 * Token-level rewriter that drops every tag NOT in the resolved
 * profile's `allowedTags`, every attribute NOT in `allowedAttrs`,
 * every URL whose scheme falls outside the profile allowlist,
 * every event-handler / form-override / clobbering attribute, and
 * every body of a body-drop tag (script / style / template / svg
 * / math / iframe / object / embed / applet). For HOSTILE
 * sources, prefer `validate` + `refuse` — `sanitize` is best
 * effort against the documented arms-race.
 *
 * @opts
 *   profile:            string,   // "strict" | "balanced" | "permissive"
 *   compliancePosture:  string,   // "hipaa" | "pci-dss" | "gdpr" | "soc2"
 *   allowedTags:        Array<string>,
 *   allowedAttrs:       Array<string>,
 *   urlSchemes:         Array<string>,
 *   allowImageData:     boolean,
 *   allowComments:      boolean,
 *   maxBytes:           number,
 *   maxAttrValueBytes:  number,
 *   maxTagDepth:        number,
 *   maxAttrsPerTag:     number,
 *
 * @example
 *   var clean = b.guardHtml.sanitize(
 *     "<p>hi</p><script>alert(1)</script>",
 *     { profile: "balanced" });
 *   // → "<p>hi</p>"
 *
 *   // Event-handler attribute is stripped, text content preserved.
 *   var stripped = b.guardHtml.sanitize(
 *     '<a href="https://example.com" onclick="alert(1)">go</a>',
 *     { profile: "balanced" });
 *   // → '<a href="https://example.com">go</a>'
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  var text = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : null);
  if (text == null) {
    throw _err("html.bad-input", "sanitize requires string or Buffer input");
  }
  return _sanitize(text, opts);
}

/**
 * @primitive b.guardHtml.gate
 * @signature b.guardHtml.gate(opts?)
 * @since     0.7.6
 * @related   b.guardHtml.validate, b.guardHtml.sanitize, b.guardAll
 *
 * Returns a guard descriptor that plugs into the framework's
 * content-safety wiring (`b.fileUpload.contentSafety` /
 * `b.staticServe.contentSafety` / `b.guardAll`). The descriptor's
 * `check(ctx)` resolves to one of four actions: `serve` (no
 * issues), `audit-only` (low-severity issues observed), `sanitize`
 * (sanitized buffer attached when no policy is "reject"), or
 * `refuse` (critical issue with at least one reject-policy active).
 *
 * @opts
 *   name:               string,
 *   profile:            string,   // "strict" | "balanced" | "permissive"
 *   compliancePosture:  string,   // "hipaa" | "pci-dss" | "gdpr" | "soc2"
 *   mode:               string,   // "enforce" | "observe"
 *   allowedTags:        Array<string>,
 *   allowedAttrs:       Array<string>,
 *   urlSchemes:         Array<string>,
 *   bidiPolicy:         string,
 *   controlPolicy:      string,
 *   cssPolicy:          string,
 *   domClobberPolicy:   string,
 *   mxssHintPolicy:     string,
 *   maxBytes:           number,
 *   maxRuntimeMs:       number,
 *
 * @example
 *   var g = b.guardHtml.gate({ profile: "strict" });
 *   g.name;   // → "guardHtml:strict"
 *
 *   // Refuse on tag-budget exceeded — strict profile rejects <script>.
 *   var hostileBuf = Buffer.from("<p>hi</p><script>alert(1)</script>", "utf8");
 *   var rv = await g.check({ bytes: hostileBuf, contentType: "text/html" });
 *   rv.ok;       // → false
 *   rv.action;   // → "refuse"
 */
// Disposition of each html finding = what the operator's policy for that class
// selected. The configurable classes (CSS injection / DOM-clobbering / mXSS
// hint) and the bidi / null / control char threats follow their policies
// (sanitize under `strip`, refuse under `reject`, audit under `audit`). The
// always-dangerous denylist (dangerous tag / event handler / dangerous attr /
// dangerous URL scheme) refuses — stripping a script-equivalent is not a
// provable repair (an mXSS / parser-differential vector can survive); a
// non-allowlisted but otherwise-benign tag / scheme sanitizes (the allowlist
// sanitizer drops it); structural caps and a tokenizer failure refuse.
// Exhaustive over every kind the detection pass emits.
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "css-injection":             return gateContract.policyDisposition(opts.cssPolicy);
    case "dom-clobber":               return gateContract.policyDisposition(opts.domClobberPolicy);
    case "mxss-hint":                 return gateContract.policyDisposition(opts.mxssHintPolicy);
    case "non-allowlisted-tag":
    case "non-allowlisted-url-scheme": return "sanitize";
    case "dangerous-tag":
    case "event-handler":
    case "dangerous-attr":
    case "dangerous-url-scheme":      return "refuse";
    case "tokenize-failed":
    case "ie-conditional-comment":
    case "depth-cap":
    case "attr-count-cap":
    case "attr-value-too-large":      return "refuse";
    default:                          return null;
  }
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardHtml:" + (opts.profile || "default"),
    opts:     opts,
    validate: validate,
    dispositionFor: _gateDispositionFor,
    produceSanitized: function (text, o) { return sanitize(text, o); },
  });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

void safeUrl;     // reserved for future scheme-allowlist composition

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "text/html",
  extension:    ".html",
  benignBytes:  Buffer.from("<p>hello world</p>", "utf8"),
  // Hostile: <script> tag is in the dangerous-tag denylist; refused
  // unconditionally regardless of profile.
  hostileBytes: Buffer.from('<p>hi</p><script>alert(1)</script>', "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the
// per-guard inspection surface (validate / sanitize) and HTML extras
// (escapeText / escapeAttr / wcag + the tag/attr/scheme/clobber tables)
// passed through verbatim. The bespoke `gate` carries HTML's
// sanitize-and-reemit chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "html",
  kind:        "content",
  errorClass:  GuardHtmlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["text/html", "application/xhtml+xml"],
  extensions:  [".html", ".htm", ".xhtml"],
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  gate:        gate,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    escapeText:              escapeText,
    escapeAttr:              escapeAttr,
    DANGEROUS_TAGS:          DANGEROUS_TAGS,
    STRICT_ALLOWED_TAGS:     STRICT_ALLOWED_TAGS,
    BALANCED_ALLOWED_TAGS:   BALANCED_ALLOWED_TAGS,
    PERMISSIVE_ALLOWED_TAGS: PERMISSIVE_ALLOWED_TAGS,
    DANGEROUS_ATTRS:         DANGEROUS_ATTRS,
    URL_ATTRS:               URL_ATTRS,
    SAFE_SCHEMES:            SAFE_SCHEMES,
    DANGEROUS_SCHEMES:       DANGEROUS_SCHEMES,
    CLOBBER_GLOBALS:         CLOBBER_GLOBALS,
    CLOBBER_PRONE_TAGS:      CLOBBER_PRONE_TAGS,
    // WCAG 2.2 audit-only mode (b.guardHtml.wcag.audit) — accessibility
    // scanner that emits violations without modifying HTML.
    wcag:                    guardHtmlWcag,
  },
});
