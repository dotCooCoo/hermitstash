"use strict";
/**
 * @module b.guardSvg
 * @nav    Guards
 * @title  Guard Svg
 *
 * @intro
 *   SVG content-safety primitive — defends against XXE / billion-laughs
 *   entity expansion, SSRF via `xlink:href`, animation-href injection
 *   (the `<animate attributeName="href" ...>` retroactive-poisoning
 *   class), embedded `<script>` / `<foreignObject>` namespace-shift
 *   escape hatches, dangerous URL schemes, CSS injection in style
 *   attributes, SVGZ compressed payloads, and Trojan-Source bidi /
 *   zero-width / null-byte threats.
 *
 *   Element + attribute allowlist with strict default (text + shape
 *   primitives only). Profiles `strict` / `balanced` / `permissive`
 *   compose with compliance postures `hipaa` / `pci-dss` / `gdpr` /
 *   `soc2`. Integrates with `b.fileUpload` and `b.staticServe`'s
 *   contentSafety hook by default.
 *
 *   Source-of-truth references: Fortinet anatomy of SVG attack
 *   surface; Angular GHSA-jrmj-c5cx-3cw6 + GHSA-v4hv-rgfq-gp49 SVG
 *   animation/href XSS; SVGO CVE-2026-29074 billion-laughs DoS;
 *   siyuan-note GHSA-5hc8-qmg8-pw27 animate-element sanitizer bypass;
 *   cure53/DOMPurify issue #233 xlink:href filtering; insertScript
 *   SVG fun-time series; svg2raster-cheatsheet SSRF guide.
 *
 * Threat catalog covered:
 *
 *   1. Dangerous SVG tags — <script>, <foreignObject> (HTML escape
 *      hatch — namespace context shift to (X)HTML), <handler>,
 *      <listener>, <audio>, <video>, <iframe>, <embed>, <object>,
 *      <use> cross-origin (SSRF + XSS chain), <animate>/<set>/
 *      <animateMotion>/<animateTransform> (attributeName-targeting
 *      bypass — recent CVE class). Refused or stripped per profile.
 *
 *   2. SMIL animation attributeName allowlist — animate-family
 *      elements have an attributeName attribute that names the
 *      animated property. If unrestricted, attackers set
 *      attributeName="href" + values="javascript:alert(1)" to bypass
 *      sanitizers that scrub href but not animate-element targets.
 *      strict allowlist limits attributeName to a safe set (cx, cy, r,
 *      x, y, width, height, fill, stroke, opacity, transform); balanced
 *      adds visual properties only (no href / xlink:href / src / data).
 *
 *   3. on* / SMIL event-handler attribute family — every attribute
 *      matching /^on[a-z]/ denied (covers onclick / onerror / onload
 *      AND SMIL onbegin / onend / onrepeat).
 *
 *   4. href / xlink:href dangerous URL schemes — javascript /
 *      vbscript / data (outside image context on <image>) / file /
 *      mhtml / jar / view-source / feed denied. Entity-encoded scheme
 *      bypasses (`&#x6A;avascript:`) decoded before scheme check.
 *
 *   5. <use> element cross-origin xlink:href — same-origin (relative
 *      paths, fragment-only #id) allowed under strict; absolute URLs
 *      with scheme refused (SSRF + XSS chain).
 *
 *   6. <image> external href — same-origin allowed; cross-origin
 *      refused under strict (SSRF surface during server-side
 *      rasterization). Permissive allows http(s) cross-origin.
 *
 *   7. XML DOCTYPE declarations — refused unconditionally regardless
 *      of profile. Catches billion-laughs entity expansion, external
 *      entity loading (XXE), and SYSTEM identifier exfiltration.
 *
 *   8. Custom entity declarations — `<!ENTITY ...>` inside the SVG
 *      stream refused even when DOCTYPE is technically external.
 *
 *   9. CDATA sections — often used to hide payloads from naive regex
 *      scanners; refused under strict, audited under balanced.
 *
 *  10. XML processing instructions — `<?xml-stylesheet ...?>` and
 *      similar pre-document directives refused (CSS injection vector).
 *
 *  11. Compressed SVGZ payloads — magic bytes 0x1F 0x8B refused at
 *      gate level. Operators that need SVGZ ungzip first then re-gate
 *      the inner SVG.
 *
 *  12. CSS injection in style attribute values — same vocabulary as
 *      guard-html: expression( / behavior: / -moz-binding /
 *      javascript:/vbscript: in url() / @import / @namespace.
 *
 *  13. <use>-recursion DoS — `<use href="#a">` referencing `<use>`
 *      referencing back — caps via maxUseDepth + maxElementCount.
 *
 *  14. SSRF-shape attribute scan — href / xlink:href / src on <image>
 *      / <use> / <feImage> / <pattern> — absolute URL refused unless
 *      profile allows cross-origin and operator passes urlSchemes.
 *
 *  15. Unicode bidi (CVE-2021-42574 Trojan Source), C0 control chars,
 *      null bytes, zero-width chars — same codepoint catalog as
 *      guard-csv / guard-html.
 *
 *  16. Anti-DoS caps — total-document size, element-count cap (defence
 *      against entity-free DoS via repeated literal expansion),
 *      use-element nesting depth, attribute-count-per-element,
 *      per-attribute-value size.
 *
 * Threat-detection regex literals are composed PROGRAMMATICALLY from
 * numeric codepoint range tables. Source file never embeds attack
 * characters themselves.
 *
 * @card
 *   SVG content-safety primitive — defends against XXE / billion-laughs entity expansion, SSRF via `xlink:href`, animation-href injection (the `<animate attributeName="href" ...>` retroactive-poisoning class), embedded `<script>` / `<foreignObject>` namespace-shift escape hatches,...
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeUrl = require("./safe-url");
var { GuardSvgError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardSvgError.factory;
var HEX_RADIX = 16;                                                 // allow:raw-byte-literal — base-16 radix, not byte size

// ---- Codepoint catalog (shared via lib/codepoint-class) ----

var C0_CTRL_RE_G  = codepointClass.C0_CTRL_RE_G;
var ZW_RE_G       = codepointClass.ZW_RE_G;

// ---- Tag classification ----

// Always-dangerous SVG tags. Active scripts, namespace-shift escape
// hatches, plugin embeds, animation elements (per recent CVE class),
// event-handler elements.
var DANGEROUS_TAGS = Object.freeze([
  "script", "foreignobject", "handler", "listener",
  "iframe", "embed", "object", "audio", "video",
  "animate", "set", "animatemotion", "animatetransform", "discard",
]);

// Animation-element family — when allowed under non-strict profiles,
// the attributeName attribute MUST be in the safe-targets allowlist.
// Animation elements are dangerous because they can target other
// elements' attributes dynamically; sanitizers that scrub href on
// elements miss the case where <animate attributeName="href" to="..."/>
// retroactively poisons the parent's href.
var ANIMATION_TAGS = Object.freeze([
  "animate", "set", "animatemotion", "animatetransform",
]);

var ANIMATION_SAFE_TARGETS = Object.freeze([
  "cx", "cy", "r", "rx", "ry", "x", "y", "x1", "x2", "y1", "y2",
  "width", "height", "fill", "stroke", "stroke-width", "stroke-opacity",
  "fill-opacity", "opacity", "transform", "d", "points",
  "viewBox", "offset", "stop-color", "stop-opacity",
]);

// Strict allowlist — minimal text + shapes only.
var STRICT_ALLOWED_TAGS = Object.freeze([
  "svg", "g", "defs", "title", "desc", "metadata",
  "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
  "text", "tspan", "textpath",
]);

// Balanced — adds visual primitives, gradients, filters, masks, basic
// reuse via <use> + <symbol>, <image> with same-origin or http(s).
var BALANCED_ALLOWED_TAGS = Object.freeze(STRICT_ALLOWED_TAGS.concat([
  "use", "symbol", "image", "pattern", "marker", "clippath", "mask",
  "lineargradient", "radialgradient", "stop", "filter",
  "fegaussianblur", "fecolormatrix", "feoffset", "feblend", "feflood",
  "femerge", "femergenode", "fecomposite", "feimage", "feturbulence",
  "fedisplacementmap", "felighting", "fediffuselighting",
  "fespecularlighting", "fedistantlight", "fepointlight",
  "fespotlight", "fecomponenttransfer", "fefunca", "fefuncr",
  "fefuncg", "fefuncb", "fetile", "feconvolvematrix", "femorphology",
  "switch", "a",
]));

// Permissive — adds animation elements (with strict attributeName
// allowlist still enforced).
var PERMISSIVE_ALLOWED_TAGS = Object.freeze(BALANCED_ALLOWED_TAGS.concat([
  // Animation enabled in permissive — attributeName allowlist still applies.
  "animate", "set", "animatemotion", "animatetransform",
  "mpath", "altglyph", "tref", "glyphref", "view",
]));

var DANGEROUS_ATTRS = Object.freeze([
  // Animation-element href targeting — even when the element is
  // allowed, these attribute values can carry javascript:. Surfaced as
  // a dangerous attribute whose VALUE goes through scheme validation.
  "href", "xlink:href", "src", "to", "from", "by", "values",
  // SMIL begin/end can carry javascript-shape conditions.
  "begin", "end",
]);

// URL-bearing attributes — values get scheme-validated.
var URL_ATTRS = Object.freeze([
  "href", "xlink:href", "src", "data", "action", "formaction",
  "background", "poster", "icon",
]);

var SAFE_SCHEMES = Object.freeze(["http", "https", "mailto", "tel"]);

var DANGEROUS_SCHEMES = Object.freeze([
  "javascript", "vbscript", "livescript", "mocha", "ecmascript",
  "file", "mhtml", "jar", "intent", "view-source", "feed", "data",
]);

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

var EVENT_HANDLER_RE = /^on[a-z]/i;

// SVGZ magic bytes — gzip-compressed SVG. 0x1F 0x8B is the gzip
// signature; SVG spec allows compressed delivery but content-safety
// gates can't peer inside without ungzipping. Refused at gate level
// regardless of profile.
var GZIP_MAGIC = Buffer.from([0x1F, 0x8B]);                          // allow:raw-byte-literal — gzip RFC 1952 §2.3.1 magic, not byte size

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    allowedTags:           STRICT_ALLOWED_TAGS,
    allowedAttrs:          Object.freeze([
      "id", "class", "viewbox", "xmlns", "xmlns:xlink", "version",
      "width", "height", "x", "y", "x1", "x2", "y1", "y2",
      "cx", "cy", "r", "rx", "ry", "d", "points", "transform",
      "fill", "stroke", "stroke-width", "stroke-opacity", "fill-opacity",
      "opacity", "stop-color", "stop-opacity", "offset", "preserveaspectratio",
      "font-family", "font-size", "text-anchor", "dominant-baseline",
      "lang", "xml:lang",
    ]),
    urlSchemes:            SAFE_SCHEMES,
    allowImageData:        false,
    allowExternalRefs:     false,
    allowAnimation:        false,
    allowedAttrNames:      ANIMATION_SAFE_TARGETS,
    bidiPolicy:            "reject",
    controlPolicy:         "reject",
    nullBytePolicy:        "reject",
    zeroWidthPolicy:       "strip",
    cssPolicy:             "reject",
    doctypePolicy:         "reject",
    cdataPolicy:           "reject",
    processingInstrPolicy: "reject",
    svgzPolicy:            "reject",
    maxBytes:              C.BYTES.mib(2),
    maxAttrValueBytes:     C.BYTES.kib(8),
    maxElementCount:       0x2000,                                  // allow:raw-byte-literal — element count limit, not bytes
    maxUseDepth:           8,                                       // allow:raw-byte-literal — use-element nesting count, not bytes
    maxAttrsPerTag:        64,                                      // allow:raw-byte-literal — attribute count, not bytes
  },
  "balanced": {
    allowedTags:           BALANCED_ALLOWED_TAGS,
    allowedAttrs:          null,                                    // inherit strict + add per-tag
    urlSchemes:            Object.freeze(SAFE_SCHEMES.concat(["ftp"])),
    allowImageData:        true,
    allowExternalRefs:     true,
    allowAnimation:        false,
    allowedAttrNames:      ANIMATION_SAFE_TARGETS,
    bidiPolicy:            "strip",
    controlPolicy:         "strip",
    nullBytePolicy:        "strip",
    zeroWidthPolicy:       "strip",
    cssPolicy:             "strip",
    doctypePolicy:         "reject",
    cdataPolicy:           "audit",
    processingInstrPolicy: "reject",
    svgzPolicy:            "reject",
    maxBytes:              C.BYTES.mib(8),
    maxAttrValueBytes:     C.BYTES.kib(32),
    maxElementCount:       0x10000,                                 // allow:raw-byte-literal — element count limit, not bytes
    maxUseDepth:           16,                                      // allow:raw-byte-literal — use-element nesting count, not bytes
    maxAttrsPerTag:        128,                                     // allow:raw-byte-literal — attribute count, not bytes
  },
  "permissive": {
    allowedTags:           PERMISSIVE_ALLOWED_TAGS,
    allowedAttrs:          null,
    urlSchemes:            Object.freeze(SAFE_SCHEMES.concat(["ftp", "sftp"])),
    allowImageData:        true,
    allowExternalRefs:     true,
    allowAnimation:        true,
    allowedAttrNames:      ANIMATION_SAFE_TARGETS,
    bidiPolicy:            "audit",
    controlPolicy:         "strip",
    nullBytePolicy:        "strip",
    zeroWidthPolicy:       "strip",
    cssPolicy:             "audit",
    doctypePolicy:         "reject",
    cdataPolicy:           "audit",
    processingInstrPolicy: "audit",
    svgzPolicy:            "reject",
    maxBytes:              C.BYTES.mib(32),
    maxAttrValueBytes:     C.BYTES.kib(64),
    maxElementCount:       0x40000,                                 // allow:raw-byte-literal — element count limit, not bytes
    maxUseDepth:           32,                                      // allow:raw-byte-literal — use-element nesting count, not bytes
    maxAttrsPerTag:        256,                                     // allow:raw-byte-literal — attribute count, not bytes
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(30),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": {
    allowedTags:        STRICT_ALLOWED_TAGS,
    bidiPolicy:         "reject",
    controlPolicy:      "reject",
    nullBytePolicy:     "reject",
    cssPolicy:          "reject",
    doctypePolicy:      "reject",
    allowExternalRefs:  false,
    allowAnimation:     false,
    forensicSnippetBytes: C.BYTES.bytes(256),
  },
  "pci-dss": {
    allowedTags:        STRICT_ALLOWED_TAGS,
    bidiPolicy:         "reject",
    controlPolicy:      "reject",
    nullBytePolicy:     "reject",
    cssPolicy:          "reject",
    doctypePolicy:      "reject",
    allowExternalRefs:  false,
    allowAnimation:     false,
    urlSchemes:         SAFE_SCHEMES,
    forensicSnippetBytes: C.BYTES.bytes(256),
  },
  "gdpr": {
    allowedTags:        BALANCED_ALLOWED_TAGS,
    bidiPolicy:         "strip",
    controlPolicy:      "strip",
    cssPolicy:          "strip",
    doctypePolicy:      "reject",
    allowAnimation:     false,
    forensicSnippetBytes: C.BYTES.bytes(128),
  },
  "soc2": {
    allowedTags:        STRICT_ALLOWED_TAGS,
    bidiPolicy:         "reject",
    controlPolicy:      "reject",
    nullBytePolicy:     "reject",
    cssPolicy:          "reject",
    doctypePolicy:      "reject",
    allowExternalRefs:  false,
    allowAnimation:     false,
    forensicSnippetBytes: C.BYTES.bytes(512),
  },
});

// ---- Internal helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardSvgError,
    errCodePrefix:      "svg",
  });
}

// HTML5 named-entity ASCII subset — same shape as guard-html.
// Browsers honor these inside URL contexts; without decoding them,
// `java&Tab;script:` and friends bypass the scheme allowlist.
var SVG_NAMED_ENTITY_ASCII = {
  Tab: "\t", NewLine: "\n",
  colon: ":", semi: ";", period: ".", sol: "/", bsol: "\\",
  num: "#", excl: "!", quest: "?", lpar: "(", rpar: ")",
  lsqb: "[", rsqb: "]", lcub: "{", rcub: "}",
  quot: "\"", apos: "'", lt: "<", gt: ">",
  amp: "&", commat: "@", dollar: "$", percnt: "%",
  ast: "*", plus: "+", lowbar: "_", hyphen: "-",
  nbsp: " ",
};

function _extractScheme(rawUrl) {
  var s = String(rawUrl || "").trim();
  s = s.replace(/&#x([0-9a-f]+);/gi, function (_m, h) {
    return String.fromCharCode(parseInt(h, HEX_RADIX));
  });
  s = s.replace(/&#(\d+);/g, function (_m, d) {
    return String.fromCharCode(parseInt(d, 10));
  });
  s = s.replace(/&([A-Za-z][A-Za-z0-9]+);/g, function (m, name) {
    if (Object.prototype.hasOwnProperty.call(SVG_NAMED_ENTITY_ASCII, name)) {
      return SVG_NAMED_ENTITY_ASCII[name];
    }
    return m;
  });
  s = s.replace(C0_CTRL_RE_G, "").replace(ZW_RE_G, "");
  var m = s.match(/^([A-Za-z][A-Za-z0-9+.-]*):/);
  return m ? m[1].toLowerCase() : "";
}

function _isImageDataUrl(rawUrl) {
  var s = String(rawUrl || "").trim();
  return /^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);/i.test(s);
}

function _isFragmentRef(rawUrl) {
  var s = String(rawUrl || "").trim();
  return s.length === 0 || s.charAt(0) === "#";
}

function _isCssDangerous(value) {
  for (var i = 0; i < CSS_DANGEROUS_PATTERNS.length; i += 1) {
    if (CSS_DANGEROUS_PATTERNS[i].test(value)) return true;
  }
  return false;
}

// SVGZ detection — gzip magic bytes 0x1F 0x8B at byte 0.
function _isSvgz(input) {
  var buf;
  if (Buffer.isBuffer(input)) buf = input;
  else if (typeof input === "string") buf = Buffer.from(input, "utf8");
  else return false;
  if (buf.length < 2) return false;
  return buf[0] === GZIP_MAGIC[0] && buf[1] === GZIP_MAGIC[1];
}

// ---- Tokenizer (SVG-flavoured) ----
//
// Pure-JS XML/SVG scanner. Emits tokens: { type, name, attrs, raw,
// start, end }. Handles XML processing instructions (<?...?>),
// DOCTYPE, CDATA, comments, start/end tags, self-closing.

function _tokenize(input, maxBytes) {
  var s = String(input || "");
  if (s.length > maxBytes) {
    throw _err("svg.too-large",
      "input " + s.length + " bytes exceeds maxBytes " + maxBytes);
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

    if (s.startsWith("<!--", lt)) {
      var endC = s.indexOf("-->", lt + 4);
      if (endC === -1) endC = len; else endC += 3;
      tokens.push({ type: "comment", raw: s.slice(lt, endC), start: lt, end: endC });
      pos = endC; continue;
    }
    if (s.startsWith("<![CDATA[", lt)) {
      var endX = s.indexOf("]]>", lt + 9);
      if (endX === -1) endX = len; else endX += 3;
      tokens.push({ type: "cdata", raw: s.slice(lt, endX), start: lt, end: endX });
      pos = endX; continue;
    }
    if (s.startsWith("<!DOCTYPE", lt) || s.startsWith("<!doctype", lt)) {
      // DOCTYPE may carry an internal subset [...] — match balanced.
      var p = lt + 9;
      while (p < len && s.charAt(p) !== ">" && s.charAt(p) !== "[") p += 1;
      if (p < len && s.charAt(p) === "[") {
        var end1 = s.indexOf("]", p);
        if (end1 === -1) end1 = len;
        var end2 = s.indexOf(">", end1);
        if (end2 === -1) end2 = len; else end2 += 1;
        tokens.push({ type: "doctype", raw: s.slice(lt, end2), start: lt, end: end2 });
        pos = end2; continue;
      }
      var end3 = s.indexOf(">", lt);
      if (end3 === -1) end3 = len; else end3 += 1;
      tokens.push({ type: "doctype", raw: s.slice(lt, end3), start: lt, end: end3 });
      pos = end3; continue;
    }
    if (s.charAt(lt + 1) === "?") {
      var endP = s.indexOf("?>", lt + 2);
      if (endP === -1) endP = len; else endP += 2;
      tokens.push({ type: "processingInstruction", raw: s.slice(lt, endP), start: lt, end: endP });
      pos = endP; continue;
    }
    if (s.charAt(lt + 1) === "!") {
      // Other declarations (e.g. <!ENTITY ...>, <!ATTLIST ...>) — flagged.
      var endD = s.indexOf(">", lt);
      if (endD === -1) endD = len; else endD += 1;
      tokens.push({ type: "declaration", raw: s.slice(lt, endD), start: lt, end: endD });
      pos = endD; continue;
    }

    if (s.charAt(lt + 1) === "/") {
      var endE = s.indexOf(">", lt);
      if (endE === -1) endE = len; else endE += 1;
      var endName = s.slice(lt + 2, endE - 1).trim().toLowerCase().split(/\s/)[0];
      tokens.push({
        type: "endTag", name: endName,
        raw: s.slice(lt, endE), start: lt, end: endE,
      });
      pos = endE; continue;
    }

    var pp = lt + 1;
    var inQuote = "";
    while (pp < len) {
      var ch = s.charAt(pp);
      if (inQuote) { if (ch === inQuote) inQuote = ""; }
      else {
        if (ch === '"' || ch === "'") inQuote = ch;
        else if (ch === ">") break;
      }
      pp += 1;
    }
    var endT = pp < len ? pp + 1 : len;
    var raw = s.slice(lt, endT);
    var inner = raw.slice(1, raw.charAt(raw.length - 1) === ">" ? raw.length - 1 : raw.length);
    var selfClosing = inner.endsWith("/");
    if (selfClosing) inner = inner.slice(0, inner.length - 1);

    var nameMatch = inner.match(/^([A-Za-z][A-Za-z0-9:_-]*)/);
    var tagName = nameMatch ? nameMatch[1].toLowerCase() : "";
    var attrSrc = nameMatch ? inner.slice(nameMatch[0].length) : "";

    var attrs = _parseAttrs(attrSrc);
    tokens.push({
      type: "tag", name: tagName, attrs: attrs,
      raw: raw, start: lt, end: endT, selfClosing: selfClosing,
    });
    pos = endT;
  }
  return tokens;
}

function _parseAttrs(src) {
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
    if (p < len && s.charAt(p) === "=") {
      p += 1;
      while (p < len && /\s/.test(s.charAt(p))) p += 1;
      var q = s.charAt(p);
      if (q === '"' || q === "'") {
        var endQ = s.indexOf(q, p + 1);
        if (endQ === -1) endQ = len;
        attrValue = s.slice(p + 1, endQ);
        p = endQ + 1;
      } else {
        var valStart = p;
        while (p < len && !/[\s>]/.test(s.charAt(p))) p += 1;
        attrValue = s.slice(valStart, p);
      }
    }
    attrs.push({ name: attrName, value: attrValue });
  }
  return attrs;
}

// ---- Detection pass ----

function _detectIssues(input, opts) {
  if (_isSvgz(input)) {
    return [{
      kind: "svgz-compressed", severity: "critical", ruleId: "svg.svgz",
      location: 0,
      snippet: "compressed SVGZ payload (gzip magic 0x1F 0x8B); ungzip + re-validate the inner SVG",
    }];
  }

  var s = typeof input === "string" ? input : Buffer.from(input).toString("utf8");
  var issues = codepointClass.detectCharThreats(s, opts, "svg");

  var tokens;
  try { tokens = _tokenize(s, opts.maxBytes); }
  catch (e) {
    issues.push({
      kind: "tokenize-failed", severity: "high", ruleId: "svg.tokenize",
      snippet: e && e.message,
    });
    return issues;
  }

  if (tokens.length > opts.maxElementCount) {
    issues.push({
      kind: "element-count-cap", severity: "high",
      ruleId: "svg.element-count",
      snippet: "token count " + tokens.length + " exceeds maxElementCount " + opts.maxElementCount,
    });
  }

  var allowedTags = Object.create(null);
  (opts.allowedTags || []).forEach(function (t) { allowedTags[t.toLowerCase()] = true; });
  var dangerousTags = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { dangerousTags[t] = true; });
  var animationTags = Object.create(null);
  ANIMATION_TAGS.forEach(function (t) { animationTags[t] = true; });
  var safeAttrNames = Object.create(null);
  (opts.allowedAttrNames || []).forEach(function (n) { safeAttrNames[n.toLowerCase()] = true; });

  var useDepth = 0;
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];

    if (tok.type === "doctype" && opts.doctypePolicy !== "allow") {
      issues.push({
        kind: "doctype", severity: "critical", ruleId: "svg.doctype",
        location: tok.start,
        snippet: "DOCTYPE declaration (billion-laughs / XXE vector)",
      });
      // Internal-subset entity declaration.
      if (/<!ENTITY/i.test(tok.raw)) {
        issues.push({
          kind: "entity-declaration", severity: "critical",
          ruleId: "svg.entity",
          location: tok.start,
          snippet: "<!ENTITY> declaration (entity-expansion DoS / XXE)",
        });
      }
      continue;
    }
    if (tok.type === "declaration" && /<!ENTITY/i.test(tok.raw)) {
      issues.push({
        kind: "entity-declaration", severity: "critical",
        ruleId: "svg.entity",
        location: tok.start,
        snippet: "<!ENTITY> declaration",
      });
      continue;
    }
    if (tok.type === "cdata" && opts.cdataPolicy !== "allow") {
      issues.push({
        kind: "cdata", severity: opts.cdataPolicy === "reject" ? "critical" : "warn",
        ruleId: "svg.cdata",
        location: tok.start,
        snippet: "CDATA section (often used to hide payloads)",
      });
      continue;
    }
    if (tok.type === "processingInstruction" &&
        opts.processingInstrPolicy !== "allow") {
      issues.push({
        kind: "processing-instruction",
        severity: opts.processingInstrPolicy === "reject" ? "critical" : "warn",
        ruleId: "svg.pi",
        location: tok.start,
        snippet: "XML processing instruction (e.g. xml-stylesheet — CSS injection vector)",
      });
      continue;
    }

    if (tok.type !== "tag") continue;

    if (Array.isArray(tok.attrs) && tok.attrs.length > opts.maxAttrsPerTag) {
      issues.push({
        kind: "attr-count-cap", severity: "high", ruleId: "svg.attr-count",
        location: tok.start,
        snippet: "attribute count exceeds maxAttrsPerTag",
      });
    }

    if (dangerousTags[tok.name]) {
      // Animation tags are dangerous unless allowAnimation.
      if (animationTags[tok.name] && opts.allowAnimation) {
        // Allowed — fall through to attribute scan with attributeName check.
      } else {
        issues.push({
          kind: "dangerous-tag", severity: "critical", ruleId: "svg.tag",
          location: tok.start,
          snippet: "dangerous SVG tag <" + tok.name + ">",
        });
        continue;
      }
    } else if (Object.keys(allowedTags).length > 0 && !allowedTags[tok.name]) {
      issues.push({
        kind: "non-allowlisted-tag", severity: "high", ruleId: "svg.tag",
        location: tok.start,
        snippet: "tag <" + tok.name + "> not in allowedTags",
      });
    }

    if (tok.name === "use") useDepth += 1;
    if (useDepth > opts.maxUseDepth) {
      issues.push({
        kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
        location: tok.start,
        snippet: "<use> nesting depth exceeds maxUseDepth",
      });
    }

    var attrs = tok.attrs || [];
    for (var ai = 0; ai < attrs.length; ai += 1) {
      var a = attrs[ai];
      var an = a.name.toLowerCase();
      if (a.value && a.value.length > opts.maxAttrValueBytes) {
        issues.push({
          kind: "attr-value-too-large", severity: "high",
          ruleId: "svg.attr-size",
          location: tok.start,
          snippet: "attribute " + JSON.stringify(an) + " value exceeds cap",
        });
      }
      if (EVENT_HANDLER_RE.test(an)) {                              // allow:regex-no-length-cap — `an` is an attribute name from tokenizer, length-bounded by XML naming rules
        issues.push({
          kind: "event-handler", severity: "critical",
          ruleId: "svg.event-handler",
          location: tok.start,
          snippet: "event-handler attribute " + JSON.stringify(an),
        });
        continue;
      }

      // attributeName on animation elements — must be in safe-targets.
      if (animationTags[tok.name] && an === "attributename") {
        var target = a.value.toLowerCase().trim();
        if (!safeAttrNames[target]) {
          issues.push({
            kind: "animation-target", severity: "critical",
            ruleId: "svg.animation",
            location: tok.start,
            snippet: "animation attributeName " + JSON.stringify(target) +
                     " targets non-safe attribute (potential href / xlink:href hijack)",
          });
        }
      }

      // URL-bearing attribute scheme check.
      if (URL_ATTRS.indexOf(an) !== -1) {
        var scheme = _extractScheme(a.value);
        var fragment = _isFragmentRef(a.value);
        if (!fragment && scheme && DANGEROUS_SCHEMES.indexOf(scheme) !== -1) {
          // Image data exception on <image>.
          if (scheme === "data" && opts.allowImageData &&
              tok.name === "image" && _isImageDataUrl(a.value)) {
            // allowed
          } else {
            issues.push({
              kind: "dangerous-url-scheme", severity: "critical",
              ruleId: "svg.url-scheme",
              location: tok.start,
              snippet: "dangerous URL scheme " + JSON.stringify(scheme) +
                       " in " + JSON.stringify(an),
            });
          }
        } else if (!fragment && scheme && opts.urlSchemes &&
                   opts.urlSchemes.indexOf(scheme) === -1) {
          if (!(scheme === "data" && opts.allowImageData &&
                tok.name === "image" && _isImageDataUrl(a.value))) {
            issues.push({
              kind: "non-allowlisted-url-scheme", severity: "high",
              ruleId: "svg.url-scheme",
              location: tok.start,
              snippet: "URL scheme " + JSON.stringify(scheme) +
                       " not in profile allowlist",
            });
          }
        }
        // Cross-origin <use> — require fragment-only when allowExternalRefs is false.
        if ((tok.name === "use" || tok.name === "feimage") &&
            !fragment && !opts.allowExternalRefs) {
          issues.push({
            kind: "external-ref", severity: "critical",
            ruleId: "svg.external-ref",
            location: tok.start,
            snippet: "<" + tok.name + " " + an + "=> references external resource (SSRF + XSS chain)",
          });
        }
      }

      // CSS injection inside style="...".
      if (an === "style" && opts.cssPolicy !== "allow") {
        if (_isCssDangerous(a.value)) {
          issues.push({
            kind: "css-injection", severity: "critical",
            ruleId: "svg.css",
            location: tok.start,
            snippet: "dangerous CSS token in style attribute",
          });
        }
      }
    }
  }
  return issues;
}

// ---- Sanitize pass ----

function _sanitize(input, opts) {
  if (_isSvgz(input)) {
    throw _err("svg.svgz", "compressed SVGZ payload — operator must ungzip before sanitize");
  }
  var s = typeof input === "string" ? input : Buffer.from(input).toString("utf8");
  if (s.length > opts.maxBytes) {
    throw _err("svg.too-large",
      "input " + s.length + " bytes exceeds maxBytes " + opts.maxBytes);
  }
  codepointClass.assertNoCharThreats(s, opts, _err, "svg");

  s = codepointClass.applyCharStripPolicies(s, opts);

  var tokens = _tokenize(s, opts.maxBytes);
  var allowedTags = Object.create(null);
  (opts.allowedTags || []).forEach(function (t) { allowedTags[t.toLowerCase()] = true; });
  var dangerousTags = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { dangerousTags[t] = true; });
  var animationTags = Object.create(null);
  ANIMATION_TAGS.forEach(function (t) { animationTags[t] = true; });
  var safeAttrNames = Object.create(null);
  (opts.allowedAttrNames || []).forEach(function (n) { safeAttrNames[n.toLowerCase()] = true; });

  var BODY_DROP = { "script": true, "foreignobject": true, "handler": true,
                    "listener": true, "iframe": true, "embed": true,
                    "object": true, "audio": true, "video": true };

  var out = [];
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];
    if (tok.type === "text") { out.push(tok.raw); continue; }
    if (tok.type === "doctype" || tok.type === "declaration") continue;
    if (tok.type === "cdata") continue;
    if (tok.type === "processingInstruction") continue;
    if (tok.type === "comment") continue;
    if (tok.type === "endTag") {
      if (allowedTags[tok.name]) out.push("</" + tok.name + ">");
      continue;
    }
    var allowed = !dangerousTags[tok.name] && allowedTags[tok.name];
    if (animationTags[tok.name] && opts.allowAnimation && allowedTags[tok.name]) {
      // Animation element — re-check attributeName.
      var safeAnimation = true;
      (tok.attrs || []).forEach(function (a) {
        if (a.name.toLowerCase() === "attributename" &&
            !safeAttrNames[a.value.toLowerCase().trim()]) {
          safeAnimation = false;
        }
      });
      if (!safeAnimation) allowed = false;
    }
    if (!allowed) {
      if (BODY_DROP[tok.name] && !tok.selfClosing) {
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
      if (EVENT_HANDLER_RE.test(an)) continue;                      // allow:regex-no-length-cap — `an` is a tokenized attribute name, bounded
      if (a.value && a.value.length > opts.maxAttrValueBytes) continue;
      if (URL_ATTRS.indexOf(an) !== -1) {
        var scheme = _extractScheme(a.value);
        var fragment = _isFragmentRef(a.value);
        if (!fragment && scheme && DANGEROUS_SCHEMES.indexOf(scheme) !== -1) {
          if (!(scheme === "data" && opts.allowImageData &&
                tok.name === "image" && _isImageDataUrl(a.value))) {
            continue;
          }
        } else if (!fragment && scheme && opts.urlSchemes &&
                   opts.urlSchemes.indexOf(scheme) === -1) {
          if (!(scheme === "data" && opts.allowImageData &&
                tok.name === "image" && _isImageDataUrl(a.value))) {
            continue;
          }
        }
        if ((tok.name === "use" || tok.name === "feimage") &&
            !fragment && !opts.allowExternalRefs) continue;
      }
      if (an === "style" && _isCssDangerous(a.value)) continue;
      attrParts.push(an + "=\"" + a.value
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;") + "\"");
    }
    var open = "<" + tok.name + (attrParts.length ? " " + attrParts.join(" ") : "") +
               (tok.selfClosing ? "/>" : ">");
    out.push(open);
  }
  return out.join("");
}

// ---- Public surface ----

/**
 * @primitive b.guardSvg.validate
 * @signature b.guardSvg.validate(input, opts)
 * @since     0.7.7
 * @status    stable
 * @related   b.guardSvg.sanitize, b.guardSvg.gate
 *
 * Inspect an SVG payload (string or Buffer) and return
 * `{ ok, issues }` describing every threat the parser found. Never
 * throws on hostile input — callers see the full issue list and
 * decide whether to refuse, sanitize, or audit.
 *
 * Issues carry `kind` / `severity` / `ruleId` / `location` /
 * `snippet`. Severities `critical` and `high` are the gate's
 * refuse / sanitize signal; `warn` is audit-only.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   allowedTags:       Array<string>,
 *   allowedAttrs:      Array<string>,
 *   urlSchemes:        Array<string>,
 *   allowImageData:    boolean,
 *   allowExternalRefs: boolean,
 *   allowAnimation:    boolean,
 *   maxBytes:          number,
 *   maxAttrValueBytes: number,
 *   maxElementCount:   number,
 *   maxUseDepth:       number,
 *   maxAttrsPerTag:    number,
 *
 * @example
 *   var rv = b.guardSvg.validate(
 *     '<svg><script>alert(1)</script></svg>',
 *     { profile: "strict" });
 *   rv.ok;                           // → false
 *   rv.issues[0].kind;               // → "dangerous-tag"
 *   rv.issues[0].severity;           // → "critical"
 *
 *   var clean = b.guardSvg.validate(
 *     '<svg><circle r="10"/></svg>',
 *     { profile: "strict" });
 *   clean.ok;                        // → true
 *   clean.issues.length;             // → 0
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxElementCount", "maxUseDepth"],
    "guardSvg.validate", GuardSvgError, "svg.bad-opt");

  var bad = gateContract.badInputResultIfNotStringOrBuffer(input);
  if (bad) return bad;
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive b.guardSvg.sanitize
 * @signature b.guardSvg.sanitize(input, opts)
 * @since     0.7.7
 * @status    stable
 * @related   b.guardSvg.validate, b.guardSvg.gate
 *
 * Best-effort sanitizer. Strips dangerous tags (`<script>`,
 * `<foreignObject>`, plugin embeds, animation elements when the
 * profile forbids them), event-handler attributes (every
 * `/^on[a-z]/`), URL attributes carrying `javascript:` /
 * `vbscript:` / non-allowlisted schemes, CSS injection inside
 * `style="..."`, DOCTYPE / `<!ENTITY>` / processing instructions /
 * CDATA, bidi / control / null-byte / zero-width threats per the
 * profile's char policies. Throws `GuardSvgError` (`svg.svgz`) on
 * SVGZ input — operators must ungzip first then re-sanitize.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   allowedTags:       Array<string>,
 *   urlSchemes:        Array<string>,
 *   allowImageData:    boolean,
 *   allowExternalRefs: boolean,
 *   allowAnimation:    boolean,
 *   maxBytes:          number,
 *
 * @example
 *   var safe = b.guardSvg.sanitize(
 *     '<svg><script>alert(1)</script><circle r="10"/></svg>',
 *     { profile: "balanced" });
 *   safe;
 *   // → '<svg><circle r="10"></circle></svg>'
 *
 *   // Event-handler attributes are stripped:
 *   var clean = b.guardSvg.sanitize(
 *     '<svg onload="x()"><rect width="10" height="10"/></svg>',
 *     { profile: "strict" });
 *   /onload/.test(clean);            // → false
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw _err("svg.bad-input", "sanitize requires string or Buffer input");
  }
  return _sanitize(input, opts);
}

/**
 * @primitive b.guardSvg.gate
 * @signature b.guardSvg.gate(opts)
 * @since     0.7.7
 * @status    stable
 * @related   b.guardSvg.validate, b.guardSvg.sanitize, b.fileUpload, b.staticServe
 *
 * Build a uniform gate over guard-* family contract. Returns an
 * async function whose verdict is `{ ok, action, issues?,
 * sanitized? }` where `action` is `serve` / `audit-only` /
 * `sanitize` / `refuse`. SVGZ inputs always refuse — operators
 * ungzip and re-gate the inner SVG. External `xlink:href` on
 * `<use>` / `<feImage>` refuses under `strict` (SSRF + XSS chain).
 * Sanitize path is taken when no policy is set to `reject` and the
 * issue set is repairable.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   mode:              "enforce" | "audit-only",
 *   audit:             AuditEmitter,
 *   observability:     ObservabilityEmitter,
 *   forensicEvidenceStore: ForensicStore,
 *   allowedTags:       Array<string>,
 *   urlSchemes:        Array<string>,
 *   allowExternalRefs: boolean,
 *   allowAnimation:    boolean,
 *   maxBytes:          number,
 *   maxRuntimeMs:      number,
 *
 * @example
 *   var g = b.guardSvg.gate({ profile: "strict" });
 *   var verdict = await g({
 *     bytes: Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
 *   });
 *   verdict.action;                  // → "serve"
 *
 *   // Refuses external xlink:href under strict:
 *   var refuse = await g({
 *     bytes: Buffer.from(
 *       '<svg><use xlink:href="https://evil.example/x.svg#a"/></svg>',
 *       "utf8"),
 *   });
 *   refuse.action;                   // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardSvg:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var bytes = ctx.bytes;
      if (!bytes) return { ok: true, action: "serve" };
      var rv = validate(bytes, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) return { ok: true, action: "audit-only", issues: rv.issues };

      // SVGZ never sanitizable — refuse.
      if (rv.issues.some(function (i) { return i.kind === "svgz-compressed"; })) {
        return { ok: false, action: "refuse", issues: rv.issues };
      }

      if (opts.bidiPolicy !== "reject" &&
          opts.controlPolicy !== "reject" &&
          opts.nullBytePolicy !== "reject" &&
          opts.cssPolicy !== "reject" &&
          opts.doctypePolicy !== "reject") {
        try {
          var clean = sanitize(bytes, opts);
          return {
            ok: true, action: "sanitize",
            sanitized: Buffer.from(clean, "utf8"),
            issues: rv.issues,
          };
        } catch (_e) { /* fall through */ }
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive b.guardSvg.compliancePosture
 * @signature b.guardSvg.compliancePosture(name)
 * @since     0.7.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.guardSvg.gate, b.compliance.set
 *
 * Look up a regulatory-posture override. Returns a shallow clone
 * of the named posture's option overlay; throws
 * `GuardSvgError` (`svg.bad-posture`) on unknown names. Operators
 * pass it through `gate({ compliancePosture: "hipaa" })` rather
 * than calling this directly — exposed for introspection and
 * audit-evidence collection.
 *
 * @example
 *   var hipaa = b.guardSvg.compliancePosture("hipaa");
 *   hipaa.bidiPolicy;                // → "reject"
 *   hipaa.allowExternalRefs;         // → false
 *   hipaa.allowAnimation;            // → false
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "svg");
}

var _svgRulePacks = gateContract.makeRulePackLoader(GuardSvgError, "svg");
var loadRulePack = _svgRulePacks.load;

void safeUrl;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "svg",
  KIND:                "content",
  MIME_TYPES:          Object.freeze(["image/svg+xml"]),
  EXTENSIONS:          Object.freeze([".svg", ".svgz"]),
  INTEGRATION_FIXTURES: Object.freeze({
    kind:         "content",
    contentType:  "image/svg+xml",
    extension:    ".svg",
    benignBytes:  Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
    // Hostile: <script> inside SVG; refused regardless of profile.
    hostileBytes: Buffer.from('<svg><script>alert(1)</script></svg>', "utf8"),
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  DANGEROUS_TAGS:      DANGEROUS_TAGS,
  ANIMATION_TAGS:      ANIMATION_TAGS,
  ANIMATION_SAFE_TARGETS: ANIMATION_SAFE_TARGETS,
  STRICT_ALLOWED_TAGS: STRICT_ALLOWED_TAGS,
  BALANCED_ALLOWED_TAGS: BALANCED_ALLOWED_TAGS,
  PERMISSIVE_ALLOWED_TAGS: PERMISSIVE_ALLOWED_TAGS,
  DANGEROUS_ATTRS:     DANGEROUS_ATTRS,
  URL_ATTRS:           URL_ATTRS,
  SAFE_SCHEMES:        SAFE_SCHEMES,
  DANGEROUS_SCHEMES:   DANGEROUS_SCHEMES,
  GuardSvgError:       GuardSvgError,
};
