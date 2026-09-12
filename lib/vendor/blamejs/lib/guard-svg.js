// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *  16. Anti-DoS caps — total-document size, element-count cap (defense
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

var MAX_USE_DEPTH_ISSUES = 8;

var MAX_USE_EXPANSION = 100000;
var USE_EXPANSION_FLOOR = 256;
var USE_AMPLIFICATION_MAX = 8;

function _refText(value) {
  var raw = String(value === undefined || value === null ? "" : value);
  return markupTokenizer.decodeCharRefs(raw);
}

var URL_REMOVED_CHARS = String.fromCharCode(0x09, 0x0A, 0x0D);

var NON_RENDERING_CONTAINERS = Object.freeze({
  defs: true, symbol: true, clippath: true, mask: true, marker: true,
  pattern: true, lineargradient: true, radialgradient: true, filter: true,
});

function _urlNormalize(s) {
  var stripped = codepointClass.replaceAny(s, URL_REMOVED_CHARS, "");
  var from = 0;
  var to = stripped.length;
  while (from < to && codepointClass.isAsciiWhitespace(stripped.charCodeAt(from))) from += 1;
  while (to > from && codepointClass.isAsciiWhitespace(stripped.charCodeAt(to - 1))) to -= 1;
  return stripped.slice(from, to);
}

function _idOf(tok) {
  var attrs = tok.attrs || [];
  for (var i = 0; i < attrs.length; i += 1) {
    if (attrs[i].name.toLowerCase() === "id") return _refText(attrs[i].value);
  }
  return null;
}

function _percentDecode(s) {
  if (s.indexOf("%") === -1) return s;
  var out = "";
  var bytes = [];
  function flush() {
    if (bytes.length === 0) return;
    try { out += Buffer.from(bytes).toString("utf8"); }
    catch (_e) {
      for (var bi = 0; bi < bytes.length; bi += 1) out += String.fromCharCode(bytes[bi]);
    }
    bytes.length = 0;
  }
  for (var i = 0; i < s.length; i += 1) {
    if (s.charAt(i) !== "%") { flush(); out += s.charAt(i); continue; }
    var hex = s.slice(i + 1, i + 3);
    if (hex.length !== 2 ||
        !codepointClass.isRunOf(hex, codepointClass.ASCII_HEX)) {
      flush();
      out += "%";
      continue;
    }
    bytes.push(parseInt(hex, 16));
    i += 2;
  }
  flush();
  return out;
}

var HREF_LOCAL = "href";
var HREF_SUFFIX = ":" + HREF_LOCAL;

function _isHrefName(name) {
  return name === HREF_LOCAL ||
    (name.length > HREF_SUFFIX.length &&
     name.slice(name.length - HREF_SUFFIX.length) === HREF_SUFFIX);
}

function _useTargetsOf(tok) {
  var attrs = tok.attrs || [];
  var out = [];
  var seen = new Set();
  for (var i = 0; i < attrs.length; i += 1) {
    if (!_isHrefName(attrs[i].name.toLowerCase())) continue;
    var v = _urlNormalize(_refText(attrs[i].value));
    if (v.charAt(0) !== "#") continue;
    var id = _percentDecode(v.slice(1));
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

function _addEdge(map, from, to) {
  var list = map.get(from);
  if (list === undefined) map.set(from, [to]);
  else list.push(to);
}

function _renderOwner(openIds, defsBoundary) {
  if (openIds.length === 0) return null;
  if (defsBoundary.length > 0 &&
      openIds.length - 1 < defsBoundary[defsBoundary.length - 1]) return null;
  return openIds[openIds.length - 1];
}

function _addPaintRefs(g, rendered, node, refs, renders) {
  for (var i = 0; i < refs.length; i += 1) _addEdge(g.paints, node, refs[i]);
  if (renders && refs.length > 0 && !g.paintRoots.has(node)) {
    g.paintRoots.add(node);
    rendered.push({ node: node, self: 0 });
  }
}

function _animationHosts(tokens, animationTags) {
  var hosts = new Set();
  var open = [];
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];
    if (tok.type === "endTag") {
      if (tok.name !== "use" || (open.length > 0 && tokens[open[open.length - 1]].name === "use")) open.pop();
      continue;
    }
    if (tok.type !== "tag") continue;
    if (animationTags[tok.name] === true && open.length > 0 &&
        _useTargetsOf(tok).length === 0 && _functionalRefsOf(tok, true).inherited.length > 0) {
      hosts.add(open[open.length - 1]);
    }
    if (!tok.selfClosing) open.push(i);
  }
  return hosts;
}

var URL_FUNC_NAME = "url";
var CSS_ARGUMENT_EXHAUSTED = Object.freeze({ exhausted: true });
var CSS_CUSTOM_PREFIX = "--";
var STYLE_ATTR = "style";
var CSS_NAME_CHARS = codepointClass.ASCII_ALNUM + "-_";
var CSS_SPACE_CHARS = " \t\n\r\f";
var CSS_ASCII_MAX = 0x7F;

var FUNC_IRI_ATTRS = Object.freeze({
  "clip-path": true, "color-profile": true, cursor: true, fill: true,
  filter: true, marker: true, "marker-end": true, "marker-mid": true,
  "marker-start": true, mask: true, stroke: true, "shape-inside": true,
  "shape-subtract": true, style: true,
});

var INHERITED_FUNC_IRI_ATTRS = Object.freeze({
  "color-profile": true, cursor: true, fill: true, marker: true,
  "marker-end": true, "marker-mid": true, "marker-start": true, stroke: true,
});

var ANIMATION_VALUE_ATTRS = Object.freeze({
  from: true, to: true, by: true, values: true,
});

var ANIMATION_TARGET_ATTR = "attributename";

var HREF_TEMPLATE_TAGS = Object.freeze({
  use: true, pattern: true, lineargradient: true, radialgradient: true,
  textpath: true, mpath: true, feimage: true,
});

function _isCssNameChar(ch) {
  return CSS_NAME_CHARS.indexOf(ch) !== -1 || ch.charCodeAt(0) > CSS_ASCII_MAX;
}

function _cssStringEnd(s, at) {
  var quote = s.charAt(at);
  var i = at + 1;
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "\\") { i = markupTokenizer.cssEscapeAt(s, i).end; continue; }
    if (ch === quote) return i + 1;
    i += 1;
  }
  return s.length;
}

function _cssStringValue(s, at) {
  var quote = s.charAt(at);
  var text = "";
  var i = at + 1;
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "\\") {
      var esc = markupTokenizer.cssEscapeAt(s, i);
      text += esc.text;
      i = esc.end;
      continue;
    }
    if (ch === quote) return { value: text, end: i + 1 };
    text += ch;
    i += 1;
  }
  return { value: text, end: s.length };
}

function _skipCssFiller(s, at) {
  var i = at;
  while (i < s.length) {
    if (CSS_SPACE_CHARS.indexOf(s.charAt(i)) !== -1) { i += 1; continue; }
    if (s.charAt(i) === "/" && s.charAt(i + 1) === "*") {
      var end = s.indexOf("*/", i + 2);
      i = end === -1 ? s.length : end + 2;
      continue;
    }
    return i;
  }
  return i;
}

function _cssUrlArgument(s, at) {
  var i = _skipCssFiller(s, at);
  var quote = s.charAt(i);
  if (quote === "\"" || quote === "'") {
    var str = _cssStringValue(s, i);
    i = _skipCssFiller(s, str.end);
    if (s.charAt(i) !== ")") return null;
    return { value: str.value, end: i + 1 };
  }
  var text = "";
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "\\") {
      var esc = markupTokenizer.cssEscapeAt(s, i);
      text += esc.text;
      i = esc.end;
      continue;
    }
    if (ch === ")") return { value: text, end: i + 1 };
    text += ch;
    i += 1;
  }
  return CSS_ARGUMENT_EXHAUSTED;
}

function _walkCssValue(s, onFunction) {
  var lastClose = s.lastIndexOf(")");
  var name = "";
  var i = 0;
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "/" && s.charAt(i + 1) === "*") {
      var end = s.indexOf("*/", i + 2);
      i = end === -1 ? s.length : end + 2;
      name = "";
      continue;
    }
    if (ch === "\"" || ch === "'") {
      i = _cssStringEnd(s, i);
      name = "";
      continue;
    }
    if (ch === "\\") {
      var esc = markupTokenizer.cssEscapeAt(s, i);
      name += esc.text;
      i = esc.end;
      continue;
    }
    if (ch === "(") {
      var next = onFunction(name.toLowerCase(), i, lastClose);
      name = "";
      i = next > i ? next : i + 1;
      continue;
    }
    if (_isCssNameChar(ch)) { name += ch; i += 1; continue; }
    name = "";
    i += 1;
  }
}


function _cssSplit(s, separator) {
  var out = [];
  var depth = 0;
  var start = 0;
  var i = 0;
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "/" && s.charAt(i + 1) === "*") {
      var end = s.indexOf("*/", i + 2);
      i = end === -1 ? s.length : end + 2;
      continue;
    }
    if (ch === "\"" || ch === "'") { i = _cssStringEnd(s, i); continue; }
    if (ch === "\\") { i = markupTokenizer.cssEscapeAt(s, i).end; continue; }
    if (ch === "(") { depth += 1; i += 1; continue; }
    if (ch === ")") { if (depth > 0) depth -= 1; i += 1; continue; }
    if (ch === separator && depth === 0) {
      out.push(s.slice(start, i));
      start = i + 1;
      i += 1;
      continue;
    }
    i += 1;
  }
  out.push(s.slice(start));
  return out;
}

function _stripCssComments(s) {
  if (s.indexOf("/*") === -1) return s;
  var out = "";
  var i = 0;
  while (i < s.length) {
    var ch = s.charAt(i);
    if (ch === "/" && s.charAt(i + 1) === "*") {
      var end = s.indexOf("*/", i + 2);
      i = end === -1 ? s.length : end + 2;
      out += " ";
      continue;
    }
    if (ch === "\"" || ch === "'") {
      var strEnd = _cssStringEnd(s, i);
      out += s.slice(i, strEnd);
      i = strEnd;
      continue;
    }
    if (ch === "\\") {
      var esc = markupTokenizer.cssEscapeAt(s, i);
      out += s.slice(i, esc.end);
      i = esc.end;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function _declarationParts(decl) {
  var head = _cssSplit(decl, ":");
  if (head.length < 2) return null;
  var raw = markupTokenizer.cssUnescape(_stripCssComments(head[0])).trim();
  var custom = raw.slice(0, CSS_CUSTOM_PREFIX.length) === CSS_CUSTOM_PREFIX;
  return {
    name: custom ? raw : raw.toLowerCase(),
    value: decl.slice(head[0].length + 1),
  };
}

function _collectUrlRefs(out, s) {
  _walkCssValue(s, function (name, at, lastClose) {
    if (name !== URL_FUNC_NAME || at >= lastClose) return -1;
    var arg = _cssUrlArgument(s, at + 1);
    if (arg === CSS_ARGUMENT_EXHAUSTED) return s.length;
    if (arg === null) return -1;
    var norm = _urlNormalize(arg.value);
    if (norm.charAt(0) === "#") out.push(_percentDecode(norm.slice(1)));
    return arg.end;
  });
}

function _refsForProperty(refs, property) {
  var custom = property.slice(0, CSS_CUSTOM_PREFIX.length) === CSS_CUSTOM_PREFIX;
  return custom || Object.prototype.hasOwnProperty.call(INHERITED_FUNC_IRI_ATTRS, property)
    ? refs.inherited
    : refs.applied;
}

function _styleRefsInto(refs, value) {
  var s = _refText(value);
  var decls = _cssSplit(s, ";");
  for (var d = 0; d < decls.length; d += 1) {
    var parts = _declarationParts(decls[d]);
    if (parts === null) continue;
    var custom = parts.name.slice(0, CSS_CUSTOM_PREFIX.length) === CSS_CUSTOM_PREFIX;
    if (!custom &&
      !Object.prototype.hasOwnProperty.call(FUNC_IRI_ATTRS, parts.name)) continue;
    _collectUrlRefs(_refsForProperty(refs, parts.name), parts.value);
  }
}

function _animatedProperty(tok) {
  var attrs = tok.attrs || [];
  for (var i = 0; i < attrs.length; i += 1) {
    if (attrs[i].name.toLowerCase() === ANIMATION_TARGET_ATTR) {
      return _refText(attrs[i].value).toLowerCase().trim();
    }
  }
  return null;
}

function _functionalRefsOf(tok, animation) {
  var attrs = tok.attrs || [];
  var refs = { inherited: [], applied: [] };
  var animated = animation ? _animatedProperty(tok) : null;
  for (var i = 0; i < attrs.length; i += 1) {
    var attrName = attrs[i].name.toLowerCase();
    if (attrName === STYLE_ATTR) {
      _styleRefsInto(refs, attrs[i].value);
      continue;
    }
    var property = null;
    if (Object.prototype.hasOwnProperty.call(FUNC_IRI_ATTRS, attrName)) property = attrName;
    else if (Object.prototype.hasOwnProperty.call(ANIMATION_VALUE_ATTRS, attrName)) {
      property = animated === null ? attrName : animated;
    }
    if (property === null) continue;
    if (property === STYLE_ATTR) _styleRefsInto(refs, attrs[i].value);
    else _collectUrlRefs(_refsForProperty(refs, property), _refText(attrs[i].value));
  }
  return refs;
}

function _expandUseGraph(graph, rendered) {
  var UNVISITED = 0, OPEN = 1, DONE = 2;
  var state = new Map();
  var count = new Map();
  var elements = new Map();
  var body = new Map();
  var paintCount = new Map();
  var paintElements = new Map();
  var height = new Map();
  var cyclic = false;
  var participating = 0;

  var adjacency = new Map();
  function neighbours(id) {
    var built = adjacency.get(id);
    if (built !== undefined) return built;
    var out = [];
    var direct = graph.uses.get(id);
    if (direct !== undefined) {
      for (var i = 0; i < direct.length; i += 1) out.push({ to: direct[i], step: 1, paint: false });
    }
    var painted = graph.paints.get(id);
    if (painted !== undefined) {
      for (var k = 0; k < painted.length; k += 1) out.push({ to: painted[k], step: 1, paint: true });
    }
    var inner = graph.contains.get(id);
    if (inner !== undefined) {
      for (var j = 0; j < inner.length; j += 1) out.push({ to: inner[j], step: 0, paint: false });
    }
    adjacency.set(id, out);
    return out;
  }

  function resolve(start) {
    if (state.get(start) === DONE) return;
    var stack = [{ id: start, next: 0 }];
    state.set(start, OPEN);
    while (stack.length > 0) {
      var top = stack[stack.length - 1];
      var kids = neighbours(top.id);
      if (top.next < kids.length) {
        var kid = kids[top.next].to;
        top.next += 1;
        var st = state.get(kid) || UNVISITED;
        if (st === OPEN) { cyclic = true; continue; }
        if (st === DONE) continue;
        state.set(kid, OPEN);
        stack.push({ id: kid, next: 0 });
        continue;
      }
      var own = 1 + (graph.weight.get(top.id) || 0);
      var drawn = own;
      var painters = own;
      var instances = 0;
      var paintedElements = 0;
      var paintedInstances = 0;
      var paintRefs = 0;
      var inDocument = graph.inDocument.has(top.id);
      var tallest = 0;
      for (var i = 0; i < kids.length; i += 1) {
        var to = kids[i].to;
        var sub = count.has(to) ? count.get(to) : MAX_USE_EXPANSION;
        var el = elements.has(to) ? elements.get(to) : MAX_USE_EXPANSION;
        var bodyOf = body.has(to) ? body.get(to) : MAX_USE_EXPANSION;
        if (kids[i].paint) {
          paintedElements += el;
          paintedInstances += 1 + sub;
          paintRefs += 1;
        } else if (kids[i].step === 1) {
          drawn += el;
          painters += bodyOf;
          instances += 1 + sub;
          if (!inDocument) participating += 1;
        } else {
          drawn += el;
          painters += bodyOf;
          instances += sub;
        }
        var h = height.has(to) ? height.get(to) : 0;
        if (h + kids[i].step > tallest) tallest = h + kids[i].step;
      }
      painters = Math.min(painters, MAX_USE_EXPANSION);
      var ownPaintElements = Math.min(painters * paintedElements, MAX_USE_EXPANSION);
      var ownPaintCount = Math.min(painters * paintedInstances, MAX_USE_EXPANSION);
      participating = Math.min(participating + painters * paintRefs, MAX_USE_EXPANSION);
      body.set(top.id, painters);
      count.set(top.id, Math.min(instances + ownPaintCount, MAX_USE_EXPANSION));
      elements.set(top.id, Math.min(drawn + ownPaintElements, MAX_USE_EXPANSION));
      paintCount.set(top.id, ownPaintCount);
      paintElements.set(top.id, ownPaintElements);
      height.set(top.id, tallest);
      state.set(top.id, DONE);
      stack.pop();
    }
  }

  var instancesTotal = 0;
  var drawnTotal = 0;
  var deepest = 0;
  var targetRoots = 0;
  for (var r = 0; r < rendered.length; r += 1) {
    var root = rendered[r];
    resolve(root.node);
    var own = root.self === 1
      ? 1 + (count.has(root.node) ? count.get(root.node) : 0)
      : (paintCount.has(root.node) ? paintCount.get(root.node) : 0);
    var drawnHere = root.self === 1
      ? (elements.has(root.node) ? elements.get(root.node) : 0)
      : (paintElements.has(root.node) ? paintElements.get(root.node) : 0);
    instancesTotal = Math.min(instancesTotal + own, MAX_USE_EXPANSION);
    drawnTotal = Math.min(drawnTotal + drawnHere, MAX_USE_EXPANSION);
    var d = root.self + (height.has(root.node) ? height.get(root.node) : 0);
    if (d > deepest) deepest = d;
    targetRoots += root.self;
  }
  return {
    instances: instancesTotal,
    elements: drawnTotal,
    depth: deepest,
    cyclic: cyclic,
    participating: Math.min(participating + targetRoots, MAX_USE_EXPANSION),
  };
}
var markupTokenizer = require("./markup-tokenizer");
var markupEscape = require("./markup-escape").markupEscape;
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var safeUrl = require("./safe-url");
var { GuardSvgError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardSvgError.factory;

var DANGEROUS_TAGS = Object.freeze([
  "script", "foreignobject", "handler", "listener",
  "iframe", "embed", "object", "audio", "video",
  "animate", "set", "animatemotion", "animatetransform", "discard",
]);

var ANIMATION_TAGS = Object.freeze([
  "animate", "set", "animatemotion", "animatetransform",
]);

var ANIMATION_SAFE_TARGETS = Object.freeze([
  "cx", "cy", "r", "rx", "ry", "x", "y", "x1", "x2", "y1", "y2",
  "width", "height", "fill", "stroke", "stroke-width", "stroke-opacity",
  "fill-opacity", "opacity", "transform", "d", "points",
  "viewBox", "offset", "stop-color", "stop-opacity",
]);

var STRICT_ALLOWED_TAGS = Object.freeze([
  "svg", "g", "defs", "title", "desc", "metadata",
  "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
  "text", "tspan", "textpath",
]);

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

var PERMISSIVE_ALLOWED_TAGS = Object.freeze(BALANCED_ALLOWED_TAGS.concat([
  "animate", "set", "animatemotion", "animatetransform",
  "mpath", "altglyph", "tref", "glyphref", "view",
]));

var DANGEROUS_ATTRS = Object.freeze([
  "href", "xlink:href", "src", "to", "from", "by", "values",
  "begin", "end",
]);

var URL_ATTRS = Object.freeze([
  "href", "xlink:href", "src", "data", "action", "formaction",
  "background", "poster", "icon",
]);

function _isUrlAttr(an) {
  if (URL_ATTRS.indexOf(an) !== -1) return true;
  var colon = an.lastIndexOf(":");
  return colon !== -1 && URL_ATTRS.indexOf(an.slice(colon + 1)) !== -1;
}

var SAFE_SCHEMES = gateContract.SAFE_URL_SCHEMES;

var DANGEROUS_SCHEMES = gateContract.DANGEROUS_URL_SCHEMES;

var _isEventHandlerAttr = markupTokenizer.isEventHandlerAttr;

var GZIP_MAGIC = Buffer.from([0x1F, 0x8B]);

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
    maxElementCount:       0x2000,
    maxUseDepth:           8,
    maxAttrsPerTag:        64,
  },
  "balanced": {
    allowedTags:           BALANCED_ALLOWED_TAGS,
    allowedAttrs:          null,
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
    maxElementCount:       0x10000,
    maxUseDepth:           16,
    maxAttrsPerTag:        128,
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
    maxElementCount:       0x40000,
    maxUseDepth:           32,
    maxAttrsPerTag:        256,
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var _extractScheme = markupTokenizer.extractScheme;

var IMAGE_DATA_SUBTYPES = Object.freeze(["png", "jpeg", "jpg", "gif", "webp",
                                         "svg+xml"]);

function _isImageDataUrl(rawUrl) {
  return markupTokenizer.isDataUrlOfType(rawUrl, IMAGE_DATA_SUBTYPES);
}

function _isFragmentRef(rawUrl) {
  var s = String(rawUrl || "").trim();
  return s.length === 0 || s.charAt(0) === "#";
}

var _isCssDangerous = markupTokenizer.hasDangerousCss;

function _isSvgz(input) {
  var buf;
  if (Buffer.isBuffer(input)) buf = input;
  else if (typeof input === "string") buf = Buffer.from(input, "utf8");
  else return false;
  if (buf.length < 2) return false;
  return buf[0] === GZIP_MAGIC[0] && buf[1] === GZIP_MAGIC[1];
}

function _tokenize(input, maxBytes) {
  var s = String(input || "");
  var nb = Buffer.byteLength(s, "utf8");
  if (nb > maxBytes) {
    throw _err("svg.too-large",
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

    if (s.startsWith("<!--", lt)) {
      var endC = markupTokenizer.htmlCommentEnd(s, lt);
      if (endC === -1) endC = len;
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
      var endD = s.indexOf(">", lt);
      if (endD === -1) endD = len; else endD += 1;
      tokens.push({ type: "declaration", raw: s.slice(lt, endD), start: lt, end: endD });
      pos = endD; continue;
    }

    if (s.charAt(lt + 1) === "/") {
      var endE = s.indexOf(">", lt);
      if (endE === -1) endE = len; else endE += 1;
      var endName = markupTokenizer.endTagName(s.slice(lt + 2, endE - 1));
      tokens.push({
        type: "endTag", name: endName,
        raw: s.slice(lt, endE), start: lt, end: endE,
      });
      pos = endE; continue;
    }

    var pp = markupTokenizer.scanToTagEnd(s, lt + 1, len);
    var endT = pp < len ? pp + 1 : len;
    var raw = s.slice(lt, endT);
    var inner = raw.slice(1, raw.charAt(raw.length - 1) === ">" ? raw.length - 1 : raw.length);
    var selfClosing = inner.endsWith("/");
    if (selfClosing) inner = inner.slice(0, inner.length - 1);

    var svgParts = markupTokenizer.splitTagNameAttrs(inner, markupTokenizer.XML_TAG_NAME_TAIL);
    var tagName = svgParts.tagName;
    var attrs = _parseAttrs(svgParts.attrSrc);
    tokens.push({
      type: "tag", name: tagName, attrs: attrs,
      raw: raw, start: lt, end: endT, selfClosing: selfClosing,
    });
    pos = endT;
  }
  return tokens;
}

var _parseAttrs = markupTokenizer.parseAttrsRecovering;

function _detectIssues(input, opts) {
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    return [{ kind: "bad-input", severity: "high",
              snippet: "input is not string or Buffer" }];
  }
  if (_isSvgz(input)) {
    return [{
      kind: "svgz-compressed", severity: "critical", ruleId: "svg.svgz",
      location: 0,
      snippet: "compressed SVGZ payload (gzip magic 0x1F 0x8B); ungzip + re-validate the inner SVG",
    }];
  }

  var s = typeof input === "string" ? input : Buffer.from(input).toString("utf8");
  var issues = codepointClass.detectCharThreats(s, opts, "svg");
  var report = gateContract.makeIssueReporter(issues);

  var tokens;
  try { tokens = _tokenize(s, opts.maxBytes); }
  catch (e) {
    report({
      kind: "tokenize-failed", severity: "high", ruleId: "svg.tokenize",
      snippet: e && e.message,
    });
    return issues;
  }

  if (tokens.length > opts.maxElementCount) {
    report({
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
  var useDepthReported = 0;
  var refGraph = {
    uses: new Map(), contains: new Map(), paints: new Map(), weight: new Map(),
    inDocument: new Set(), paintRoots: new Set(),
  };
  var nextNode = 0;
  var openIds = [];
  var frameNodes = [];
  var frameTags = [];
  var renderedRefs = [];
  var defsDepth = 0;
  var defsBoundary = [];
  var styleDepth = 0;
  var sheetRefs = [];
  var elementCount = 0;
  var animationHosts = _animationHosts(tokens, animationTags);
  var allowedAttrs = null;
  if (Array.isArray(opts.allowedAttrs)) {
    allowedAttrs = Object.create(null);
    opts.allowedAttrs.forEach(function (t) { allowedAttrs[String(t).toLowerCase()] = true; });
  }
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];

    if ((tok.type === "text" || tok.type === "cdata") && styleDepth > 0) {
      var sheet = _refText(tok.raw);
      if (opts.cssPolicy !== "allow" && _isCssDangerous(sheet)) {
        report({
          kind: "css-injection", severity: "critical",
          ruleId: "svg.css",
          location: tok.start,
          snippet: "dangerous CSS token in stylesheet",
        });
      }
      _collectUrlRefs(sheetRefs, sheet);
    }

    if (tok.type === "doctype" && opts.doctypePolicy !== "allow") {
      report({
        kind: "doctype", severity: "critical", ruleId: "svg.doctype",
        location: tok.start,
        snippet: "DOCTYPE declaration (billion-laughs / XXE vector)",
      });
      if (codepointClass.containsFolded(tok.raw, "<!ENTITY")) {
        report({
          kind: "entity-declaration", severity: "critical",
          ruleId: "svg.entity",
          location: tok.start,
          snippet: "<!ENTITY> declaration (entity-expansion DoS / XXE)",
        });
      }
      continue;
    }
    if (tok.type === "declaration" && codepointClass.containsFolded(tok.raw, "<!ENTITY")) {
      report({
        kind: "entity-declaration", severity: "critical",
        ruleId: "svg.entity",
        location: tok.start,
        snippet: "<!ENTITY> declaration",
      });
      continue;
    }
    if (tok.type === "cdata" && opts.cdataPolicy !== "allow") {
      report({
        kind: "cdata", severity: opts.cdataPolicy === "reject" ? "critical" : "warn",
        ruleId: "svg.cdata",
        location: tok.start,
        snippet: "CDATA section (often used to hide payloads)",
      });
      continue;
    }
    if (tok.type === "processingInstruction" &&
        opts.processingInstrPolicy !== "allow") {
      report({
        kind: "processing-instruction",
        severity: opts.processingInstrPolicy === "reject" ? "critical" : "warn",
        ruleId: "svg.pi",
        location: tok.start,
        snippet: "XML processing instruction (e.g. xml-stylesheet — CSS injection vector)",
      });
      continue;
    }

    if (tok.type === "endTag") {
      if (tok.name === "use") {
        useDepth = Math.max(0, useDepth - 1);
        if (frameTags.length > 0 && frameTags[frameTags.length - 1] === "use") {
          frameTags.pop();
          if (frameNodes.pop() !== null) openIds.pop();
        }
      } else {
        if (Object.prototype.hasOwnProperty.call(NON_RENDERING_CONTAINERS, tok.name) &&
            defsDepth > 0) {
          defsDepth -= 1;
          defsBoundary.pop();
        }
        if (tok.name === STYLE_ATTR && styleDepth > 0) styleDepth -= 1;
        if (frameNodes.length > 0) {
          frameTags.pop();
          if (frameNodes.pop() !== null) openIds.pop();
        }
      }
      continue;
    }
    if (tok.type !== "tag") continue;
    elementCount += 1;

    if (Array.isArray(tok.attrs) && tok.attrs.length > opts.maxAttrsPerTag) {
      report({
        kind: "attr-count-cap", severity: "high", ruleId: "svg.attr-count",
        location: tok.start,
        snippet: "attribute count exceeds maxAttrsPerTag",
      });
    }

    var animation = animationTags[tok.name] === true;
    var refs = _functionalRefsOf(tok, animation);
    var nodeId = _idOf(tok);
    if (nodeId === null && ((refs.inherited.length > 0 && !animation) || animationHosts.has(i))) {
      nodeId = nextNode;
      nextNode += 1;
    }
    var dormantSelf = Object.prototype.hasOwnProperty.call(NON_RENDERING_CONTAINERS, tok.name);
    var owner = dormantSelf ? null : _renderOwner(openIds, defsBoundary);
    var renders = defsDepth === 0 && !dormantSelf;
    var from = nodeId !== null ? nodeId : owner;
    if (nodeId !== null) {
      if (renders) refGraph.inDocument.add(nodeId);
      if (owner !== null) _addEdge(refGraph.contains, owner, nodeId);
    } else if (owner !== null) {
      refGraph.weight.set(owner, (refGraph.weight.get(owner) || 0) + 1);
    }
    var once = Object.prototype.hasOwnProperty.call(HREF_TEMPLATE_TAGS, tok.name)
      ? _useTargetsOf(tok).concat(refs.applied)
      : refs.applied;
    for (var t = 0; t < once.length; t += 1) {
      if (from !== null) _addEdge(refGraph.uses, from, once[t]);
      if (renders) renderedRefs.push({ node: once[t], self: 1 });
    }
    if (refs.inherited.length > 0 && !animation) {
      _addPaintRefs(refGraph, renderedRefs, nodeId, refs.inherited, renders);
    } else if (refs.inherited.length > 0) {
      var hosts = _useTargetsOf(tok);
      if (hosts.length === 0 && frameNodes.length > 0 && frameNodes[frameNodes.length - 1] !== null) {
        hosts = [frameNodes[frameNodes.length - 1]];
      }
      for (var h = 0; h < hosts.length; h += 1) {
        _addPaintRefs(refGraph, renderedRefs, hosts[h], refs.inherited, renders);
      }
    }
    if (!tok.selfClosing) {
      var openBefore = openIds.length;
      frameNodes.push(nodeId);
      frameTags.push(tok.name);
      if (nodeId !== null) openIds.push(nodeId);
      if (dormantSelf) {
        defsDepth += 1;
        defsBoundary.push(openBefore);
      }
      if (tok.name === STYLE_ATTR) styleDepth += 1;
    }

    if (dangerousTags[tok.name]) {
      if (animationTags[tok.name] && opts.allowAnimation) {
        // Allowed — fall through to attribute scan with attributeName check.
      } else {
        report({
          kind: "dangerous-tag", severity: "critical", ruleId: "svg.tag",
          location: tok.start,
          snippet: "dangerous SVG tag <" + tok.name + ">",
        });
        continue;
      }
    } else if (!allowedTags[tok.name]) {
      report({
        kind: "non-allowlisted-tag", severity: "high", ruleId: "svg.tag",
        location: tok.start,
        snippet: "tag <" + tok.name + "> not in allowedTags",
      });
    }

    if (tok.name === "use" && !tok.selfClosing) {
      useDepth += 1;
      if (useDepth > opts.maxUseDepth && useDepthReported < MAX_USE_DEPTH_ISSUES) {
        useDepthReported += 1;
        report({
          kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
          location: tok.start,
          snippet: "<use> nesting depth " + useDepth +
                   " exceeds maxUseDepth " + opts.maxUseDepth,
        });
      }
    }
    var attrs = tok.attrs || [];
    for (var ai = 0; ai < attrs.length; ai += 1) {
      var a = attrs[ai];
      var an = a.name.toLowerCase();
      if (allowedAttrs !== null && !allowedAttrs[an]) {
        report({
          kind: "non-allowlisted-attr", severity: "high", ruleId: "svg.attr",
          location: tok.start,
          snippet: "attribute " + JSON.stringify(an) + " not in allowedAttrs",
        });
      }
      if (a.value && Buffer.byteLength(a.value, "utf8") > opts.maxAttrValueBytes) {
        report({
          kind: "attr-value-too-large", severity: "high",
          ruleId: "svg.attr-size",
          location: tok.start,
          snippet: "attribute " + JSON.stringify(an) + " value exceeds cap",
        });
      }
      if (_isEventHandlerAttr(an)) {
        report({
          kind: "event-handler", severity: "critical",
          ruleId: "svg.event-handler",
          location: tok.start,
          snippet: "event-handler attribute " + JSON.stringify(an),
        });
        continue;
      }

      if (animationTags[tok.name] && an === "attributename") {
        var target = a.value.toLowerCase().trim();
        if (!safeAttrNames[target]) {
          report({
            kind: "animation-target", severity: "critical",
            ruleId: "svg.animation",
            location: tok.start,
            snippet: "animation attributeName " + JSON.stringify(target) +
                     " targets non-safe attribute (potential href / xlink:href hijack)",
          });
        }
      }

      if (_isUrlAttr(an)) {
        var scheme = _extractScheme(a.value);
        var fragment = _isFragmentRef(a.value);
        if (!fragment && scheme && DANGEROUS_SCHEMES.indexOf(scheme) !== -1) {
          if (scheme === "data" && opts.allowImageData &&
              tok.name === "image" && _isImageDataUrl(a.value)) {
            // allowed
          } else {
            report({
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
            report({
              kind: "non-allowlisted-url-scheme", severity: "high",
              ruleId: "svg.url-scheme",
              location: tok.start,
              snippet: "URL scheme " + JSON.stringify(scheme) +
                       " not in profile allowlist",
            });
          }
        }
        if ((tok.name === "use" || tok.name === "feimage") &&
            !fragment && !opts.allowExternalRefs) {
          report({
            kind: "external-ref", severity: "critical",
            ruleId: "svg.external-ref",
            location: tok.start,
            snippet: "<" + tok.name + " " + an + "=> references external resource (SSRF + XSS chain)",
          });
        }
      }

      if (an === "style" && opts.cssPolicy !== "allow") {
        if (_isCssDangerous(a.value)) {
          report({
            kind: "css-injection", severity: "critical",
            ruleId: "svg.css",
            location: tok.start,
            snippet: "dangerous CSS token in style attribute",
          });
        }
      }
    }
  }

  if (sheetRefs.length > 0) {
    var sheetNode = nextNode;
    nextNode += 1;
    refGraph.weight.set(sheetNode, elementCount - 1);
    _addPaintRefs(refGraph, renderedRefs, sheetNode, sheetRefs, true);
  }
  var expansion = _expandUseGraph(refGraph, renderedRefs);
  if (expansion.cyclic) {
    report({
      kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
      snippet: "<use> reference cycle: the document expands without bound",
    });
  } else if (expansion.depth > opts.maxUseDepth) {
    report({
      kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
      snippet: "<use> reference chain depth " + expansion.depth +
               " exceeds maxUseDepth " + opts.maxUseDepth,
    });
  } else {
    var budget = Math.min(MAX_USE_EXPANSION - 1,
      Math.max(USE_EXPANSION_FLOOR, expansion.participating * USE_AMPLIFICATION_MAX));
    if (expansion.instances >= MAX_USE_EXPANSION || expansion.instances > budget) {
      report({
        kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
        snippet: "<use> references expand to " +
                 (expansion.instances >= MAX_USE_EXPANSION
                   ? "at least " + MAX_USE_EXPANSION
                   : String(expansion.instances)) +
                 " rendered instances from " + expansion.participating +
                 " rendered references",
      });
    } else if (expansion.elements >= MAX_USE_EXPANSION) {
      report({
        kind: "use-depth-cap", severity: "high", ruleId: "svg.use-depth",
        snippet: "<use> references render at least " + MAX_USE_EXPANSION +
                 " elements from " + expansion.participating + " rendered references",
      });
    }
  }
  return issues;
}

function _sanitize(input, opts) {
  if (_isSvgz(input)) {
    throw _err("svg.svgz", "compressed SVGZ payload — operator must ungzip before sanitize");
  }
  var s = codepointClass.scrubCharThreats(
    typeof input === "string" ? input : Buffer.from(input).toString("utf8"),
    opts, _err, "svg");

  var tokens = _tokenize(s, opts.maxBytes);
  var allowedTags = Object.create(null);
  (opts.allowedTags || []).forEach(function (t) { allowedTags[t.toLowerCase()] = true; });
  var dangerousTags = Object.create(null);
  DANGEROUS_TAGS.forEach(function (t) { dangerousTags[t] = true; });
  var animationTags = Object.create(null);
  ANIMATION_TAGS.forEach(function (t) { animationTags[t] = true; });
  var sanitizeAllowedAttrs = null;
  if (Array.isArray(opts.allowedAttrs)) {
    sanitizeAllowedAttrs = Object.create(null);
    opts.allowedAttrs.forEach(function (t) {
      sanitizeAllowedAttrs[String(t).toLowerCase()] = true;
    });
  }
  var safeAttrNames = Object.create(null);
  (opts.allowedAttrNames || []).forEach(function (n) { safeAttrNames[n.toLowerCase()] = true; });

  var BODY_DROP = { "script": true, "foreignobject": true, "handler": true,
                    "listener": true, "iframe": true, "embed": true,
                    "object": true, "audio": true, "video": true, "style": true };

  var out = [];
  var styleDepth = 0;
  for (var i = 0; i < tokens.length; i += 1) {
    var tok = tokens[i];
    if (tok.type === "text") {
      if (styleDepth > 0 && opts.cssPolicy !== "allow" && _isCssDangerous(_refText(tok.raw))) continue;
      out.push(tok.raw);
      continue;
    }
    if (tok.type === "doctype" || tok.type === "declaration") continue;
    if (tok.type === "cdata") continue;
    if (tok.type === "processingInstruction") continue;
    if (tok.type === "comment") continue;
    if (tok.type === "endTag") {
      if (tok.name === STYLE_ATTR && styleDepth > 0) styleDepth -= 1;
      if (allowedTags[tok.name]) out.push("</" + tok.name + ">");
      continue;
    }
    var allowed = !dangerousTags[tok.name] && allowedTags[tok.name];
    if (animationTags[tok.name] && opts.allowAnimation && allowedTags[tok.name]) {
      var safeAnimation = true;
      (tok.attrs || []).forEach(function (a) {
        if (a.name.toLowerCase() === "attributename" &&
            !safeAttrNames[a.value.toLowerCase().trim()]) {
          safeAnimation = false;
        }
      });
      allowed = safeAnimation;
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
      if (_isEventHandlerAttr(an)) continue;
      if (sanitizeAllowedAttrs !== null && !sanitizeAllowedAttrs[an]) continue;
      if (a.value && Buffer.byteLength(a.value, "utf8") > opts.maxAttrValueBytes) continue;
      if (_isUrlAttr(an)) {
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
      attrParts.push(an + "=\"" + markupEscape(a.value) + "\"");
    }
    var open = "<" + tok.name + (attrParts.length ? " " + attrParts.join(" ") : "") +
               (tok.selfClosing ? "/>" : ">");
    out.push(open);
    if (tok.name === STYLE_ATTR && !tok.selfClosing) styleDepth += 1;
  }
  return out.join("");
}

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
  opts = _guard.resolveOpts(opts);
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw _err("svg/bad-input", "sanitize requires string or Buffer input");
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
 * Build a uniform gate over the guard-* family contract. Returns a
 * gate whose async `check(ctx)` produces a verdict `{ ok, action,
 * issues?, sanitized? }` where `action` is `serve` / `audit-only` /
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
 *   var verdict = await g.check({
 *     bytes: Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
 *   });
 *   verdict.action;                  // → "serve"
 *
 *   // Refuses external xlink:href under strict:
 *   var refuse = await g.check({
 *     bytes: Buffer.from(
 *       '<svg><use xlink:href="https://evil.example/x.svg#a"/></svg>',
 *       "utf8"),
 *   });
 *   refuse.action;                   // → "refuse"
 */
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "css-injection":             return gateContract.policyDisposition(opts.cssPolicy);
    case "doctype":                   return gateContract.policyDisposition(opts.doctypePolicy);
    case "cdata":                     return gateContract.policyDisposition(opts.cdataPolicy);
    case "processing-instruction":    return gateContract.policyDisposition(opts.processingInstrPolicy);
    case "non-allowlisted-tag":
    case "non-allowlisted-attr":
    case "non-allowlisted-url-scheme": return "sanitize";
    case "svgz-compressed":
    case "entity-declaration":
    case "dangerous-tag":
    case "event-handler":
    case "animation-target":
    case "dangerous-url-scheme":
    case "external-ref":              return "refuse";
    case "tokenize-failed":
    case "element-count-cap":
    case "attr-count-cap":
    case "use-depth-cap":
    case "attr-value-too-large":
    case "bad-input":                 return "refuse";
    default:                          return null;
  }
}

function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardSvg:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor: _gateDispositionFor,
    ctxField: "bytes",
    sanitizeBlockingKinds: ["svgz-compressed"],
    produceSanitized: function (bytes, o) { return sanitize(bytes, o); },
  });
}

void safeUrl;

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "image/svg+xml",
  extension:    ".svg",
  benignBytes:  Buffer.from('<svg><circle r="10"/></svg>', "utf8"),
  hostileBytes: Buffer.from('<svg><script>alert(1)</script></svg>', "utf8"),
});

var POLICY_ENUM = gateContract.policyVocabulary([
  "cssPolicy", "doctypePolicy", "cdataPolicy", "processingInstrPolicy",
], gateContract.POLICY_VALUES.rejectStripAuditAllow, {
  svgzPolicy: ["reject"],
});

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "svg",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardSvgError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["image/svg+xml"],
  extensions:  [".svg", ".svgz"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:      _detectIssues,
  intOpts:     ["maxBytes", "maxElementCount", "maxUseDepth",
                "maxAttrValueBytes", "maxAttrsPerTag"],
  sanitize:    sanitize,
  gate:        gate,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    DANGEROUS_TAGS:          DANGEROUS_TAGS,
    ANIMATION_TAGS:          ANIMATION_TAGS,
    ANIMATION_SAFE_TARGETS:  ANIMATION_SAFE_TARGETS,
    STRICT_ALLOWED_TAGS:     STRICT_ALLOWED_TAGS,
    BALANCED_ALLOWED_TAGS:   BALANCED_ALLOWED_TAGS,
    PERMISSIVE_ALLOWED_TAGS: PERMISSIVE_ALLOWED_TAGS,
    DANGEROUS_ATTRS:         DANGEROUS_ATTRS,
    URL_ATTRS:               URL_ATTRS,
    SAFE_SCHEMES:            SAFE_SCHEMES,
    DANGEROUS_SCHEMES:       DANGEROUS_SCHEMES,
  },
});
