// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.xmlC14n
 * @nav        Crypto
 * @title      XML Exclusive Canonicalization
 * @order      560
 * @card       RFC 3741 Exclusive XML Canonicalization 1.0 — the
 *             canonical form XMLDSig requires, and the missing piece
 *             that lets `b.guardXml` defend against XML signature-
 *             wrapping attacks.
 *
 * @intro
 *   XML signatures cover canonicalized bytes, not the source XML.
 *   Two structurally-equivalent XML documents (different attribute
 *   ordering, different namespace prefixes, different whitespace)
 *   must produce the same canonical bytes; otherwise an attacker
 *   could swap a benign signed assertion for a malicious one whose
 *   parsed tree is identical but whose serialized bytes differ.
 *
 *   This module implements the SAML/XMLDSig-relevant subset of
 *   RFC 3741 Exclusive XML Canonicalization 1.0 plus
 *   `xml-exc-c14n#WithComments` (controlled via opts).
 *
 *   What's covered (the v1-defensible SAML/SP subset):
 *
 *     - UTF-8 output with no BOM
 *     - Element + attribute serialization with `&`, `<`, `>`, `"`,
 *       `\r`, `\t`, `\n` proper escaping per §1.3.2
 *     - Attribute ordering: namespace declarations first (alphabetical
 *       by namespace prefix, `xmlns` before `xmlns:foo`); regular
 *       attributes second (by namespace URI, then local name)
 *     - Exclusive namespace propagation: only the namespace prefixes
 *       *visibly used* by the canonicalized subtree are emitted
 *     - Empty elements expanded (`<a/>` → `<a></a>`)
 *     - Whitespace normalization in attribute values
 *     - Comments suppressed by default; `withComments: true` keeps
 *       them per `xml-exc-c14n#WithComments`
 *
 *   What's NOT covered (deferred — open conditions on first
 *   operator demand or live SAML interop need):
 *
 *     - `InclusiveNamespaces PrefixList` (the `<ec:InclusiveNamespaces
 *       PrefixList="..."/>` Transform parameter — we always operate
 *       in the strict exclusive mode without an inclusive list).
 *     - Inherited XML namespace propagation for `xml:lang`,
 *       `xml:space`, `xml:base` past the canonicalization boundary.
 *
 *   Surface:
 *
 *     b.xmlC14n.canonicalize(xmlString | parsedTree, opts?)
 *       → Buffer of canonicalized UTF-8 bytes
 *     b.xmlC14n.canonicalizeElementById(xmlString, id, opts?)
 *       → Buffer of c14n'd bytes for the element whose `ID="<id>"`
 *         attribute matches (used by XMLDSig Reference resolution)
 *     b.xmlC14n.parse(xmlString) → DOM tree (used by SAML)
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var XmlC14nError = defineClass("XmlC14nError", { alwaysPermanent: true });
function _xmlErr(code, message) { return new XmlC14nError(code, message); }

var MAX_INPUT_BYTES = 8 * 1024 * 1024;                                                          // allow:raw-byte-literal — XML doc cap (8 MiB)
var MAX_DEPTH       = 200;                                                                      // element nesting depth ceiling

/**
 * @primitive b.xmlC14n.parse
 * @signature b.xmlC14n.parse(xml)
 * @since     0.8.62
 * @status    stable
 * @related   b.xmlC14n.canonicalize, b.xmlC14n.canonicalizeElementById
 *
 * Lightweight DOM parser: produces a simple node tree with
 * `{ type, name, attrs, children, parent }`. Node types: "element"
 * / "text" / "comment". The parser is strict about what it refuses
 * (DOCTYPE, ENTITY, malformed entity references); XML c14n is a
 * security primitive and an over-permissive parser undermines the
 * canonicalization guarantees downstream. Operators rarely call
 * this directly — `canonicalize` and `canonicalizeElementById`
 * accept either a string OR a parsed node, so the parsed-tree path
 * is exposed mainly for the SAML primitive's signature-element
 * lookup and operator-side custom traversal.
 *
 * @example
 *   var tree = b.xmlC14n.parse("<root><child id=\"x\"/></root>");
 *   tree.type;            // → "element"
 *   tree.name;            // → "root"
 *   tree.children[0].name;// → "child"
 */
function parse(xml) {
  if (typeof xml !== "string") {
    if (Buffer.isBuffer(xml)) xml = xml.toString("utf8");
    else throw _xmlErr("xml-c14n/bad-input", "parse: input must be a string or Buffer");
  }
  if (xml.length === 0) throw _xmlErr("xml-c14n/empty", "parse: input is empty");
  if (xml.length > MAX_INPUT_BYTES) {
    throw _xmlErr("xml-c14n/too-large",
      "parse: input exceeds " + MAX_INPUT_BYTES + " bytes");
  }
  // Strip BOM if present
  if (xml.charCodeAt(0) === 0xFEFF) xml = xml.slice(1);
  // Refuse DOCTYPE outright (XXE, billion-laughs class)
  if (/<!DOCTYPE/i.test(xml)) {
    throw _xmlErr("xml-c14n/doctype-refused",
      "parse: <!DOCTYPE> declarations refused for canonicalization input");
  }
  if (/<!ENTITY/i.test(xml)) {
    throw _xmlErr("xml-c14n/entity-refused",
      "parse: <!ENTITY> declarations refused");
  }

  // XML 1.0 §2.11 end-of-line handling — a conforming processor folds every
  // literal CRLF and lone CR to a single LF across the WHOLE document (text,
  // CDATA, comments, attribute literals) BEFORE the InfoSet is built. A CR
  // delivered through a character reference (&#xD;) is NOT a source line
  // ending and is preserved. Doing this document-wide once (rather than the
  // attribute literal alone) closes the same distinct-input / identical-output
  // collision in element text and CDATA: without it a literal CR in text and
  // the &#xD; reference both canonicalize to `&#xD;` (the escape _escapeText
  // applies to a surviving CR), letting a signed document be swapped for one
  // whose character data differs but whose canonical bytes match. The
  // attribute §3.3.3 whitespace fold below still runs (it additionally folds
  // TAB and the now-LF to a single space, which §2.11 alone does not).
  xml = xml.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  var pos = 0;
  function err(msg) {
    throw _xmlErr("xml-c14n/parse", "parse: " + msg + " at offset " + pos);
  }

  function skipWhitespace() {
    while (pos < xml.length && /\s/.test(xml.charAt(pos))) pos += 1;
  }

  function skipProlog() {
    skipWhitespace();
    while (xml.substr(pos, 5) === "<?xml" ||
           xml.substr(pos, 4) === "<!--" ||
           xml.substr(pos, 2) === "<?") {
      if (xml.substr(pos, 4) === "<!--") {
        var end = xml.indexOf("-->", pos);
        if (end === -1) err("unterminated comment in prolog");
        pos = end + 3;
      } else {
        var endPi = xml.indexOf("?>", pos);
        if (endPi === -1) err("unterminated processing instruction");
        pos = endPi + 2;
      }
      skipWhitespace();
    }
  }

  function readName() {
    var start = pos;
    if (!/[A-Za-z_:]/.test(xml.charAt(pos))) err("expected name");
    pos += 1;
    while (pos < xml.length && /[A-Za-z0-9._:-]/.test(xml.charAt(pos))) pos += 1;
    return xml.slice(start, pos);
  }

  function readAttrValue() {
    var quote = xml.charAt(pos);
    if (quote !== "\"" && quote !== "'") err("attribute value must be quoted");
    pos += 1;
    var start = pos;
    while (pos < xml.length && xml.charAt(pos) !== quote) {
      if (xml.charAt(pos) === "<") err("'<' not allowed in attribute value");
      pos += 1;
    }
    if (pos >= xml.length) err("unterminated attribute value");
    var raw = xml.slice(start, pos);
    pos += 1; // closing quote
    // XML 1.0 §2.11 line-ending + §3.3.3 attribute-value normalization: a
    // literal TAB / CR / LF in the attribute literal (and a CRLF / lone-CR
    // line ending) folds to a single SPACE. The SAME character delivered
    // through a character reference (&#9; / &#xA; / &#xD;) is decoded AFTER
    // this fold and is therefore preserved. Because c14n later escapes the
    // surviving literal control characters back to &#x9; / &#xA; / &#xD;,
    // skipping the fold makes `a="x<TAB>y"` and `a="x&#9;y"` canonicalize
    // to IDENTICAL bytes even though their InfoSet attribute values differ
    // ("x y" vs a real TAB) — a distinct-input / identical-output collision
    // that would let a signed document be swapped for a semantically
    // different one whose canonical bytes still match (XML-signature-
    // wrapping / smuggling). Normalize the literal text BEFORE entity
    // decode so character-reference whitespace stays intact.
    var normalized = raw.replace(/\r\n/g, " ").replace(/[\r\n\t]/g, " ");
    return _decodeEntities(normalized);
  }

  function _decodeEntities(s) {
    return s.replace(/&([^;]+);/g, function (match, name) {
      switch (name) {
        case "amp":  return "&";
        case "lt":   return "<";
        case "gt":   return ">";
        case "quot": return "\"";
        case "apos": return "'";
        default:
          if (name.charAt(0) === "#") {
            var code;
            if (name.charAt(1) === "x" || name.charAt(1) === "X") {
              code = parseInt(name.slice(2), 16);                                              // hex radix
            } else {
              code = parseInt(name.slice(1), 10);
            }
            if (Number.isFinite(code) && code >= 0 && code <= 0x10ffff) {
              return String.fromCodePoint(code);
            }
          }
          throw _xmlErr("xml-c14n/unknown-entity",
            "decodeEntities: unsupported entity reference \"&" + name + ";\"");
      }
    });
  }

  function parseElement(depth) {
    // Nesting-depth cap threaded through the recursion and enforced at
    // entry, so deeply-nested untrusted XML is refused before it overflows
    // the stack — a recursive-descent parser is otherwise a stack-
    // exhaustion DoS on hostile SAML / WebDAV input.
    if (depth > MAX_DEPTH) err("max nesting depth (" + MAX_DEPTH + ") exceeded");
    if (xml.charAt(pos) !== "<") err("expected '<'");
    pos += 1;
    var name = readName();
    var attrs = [];
    var selfClosing = false;
    skipWhitespace();
    while (pos < xml.length && xml.charAt(pos) !== ">" && xml.charAt(pos) !== "/") {
      var attrName = readName();
      skipWhitespace();
      if (xml.charAt(pos) !== "=") err("expected '=' after attribute name");
      pos += 1;
      skipWhitespace();
      var value = readAttrValue();
      attrs.push({ name: attrName, value: value });
      skipWhitespace();
    }
    if (xml.charAt(pos) === "/") {
      selfClosing = true;
      pos += 1;
      if (xml.charAt(pos) !== ">") err("expected '>' after '/'");
    }
    if (xml.charAt(pos) !== ">") err("expected '>'");
    pos += 1;
    var node = {
      type:       "element",
      name:       name,
      attrs:      attrs,
      children:   [],
      parent:     null,
    };
    if (selfClosing) return node;

    var closeTag = "</" + name + ">";
    while (pos < xml.length) {
      if (xml.substr(pos, 4) === "<!--") {
        var endC = xml.indexOf("-->", pos);
        if (endC === -1) err("unterminated comment");
        node.children.push({ type: "comment", text: xml.slice(pos + 4, endC), parent: node });
        pos = endC + 3;
      } else if (xml.charAt(pos) === "<" && xml.charAt(pos + 1) !== "/") {
        if (xml.substr(pos, 9) === "<![CDATA[") {
          var endCData = xml.indexOf("]]>", pos);
          if (endCData === -1) err("unterminated CDATA");
          node.children.push({ type: "text", text: xml.slice(pos + 9, endCData), parent: node, isCdata: true });
          pos = endCData + 3;
        } else if (xml.charAt(pos + 1) === "?") {
          var endPi = xml.indexOf("?>", pos);
          if (endPi === -1) err("unterminated PI");
          // Skip — c14n drops PIs outside the canonicalized subtree
          // boundary; we can include them but operators don't need
          // them for SAML.
          pos = endPi + 2;
        } else {
          var child = parseElement(depth + 1);
          child.parent = node;
          node.children.push(child);
        }
      } else if (xml.charAt(pos) === "<" && xml.charAt(pos + 1) === "/") {
        // Closing tag
        if (xml.substr(pos, closeTag.length) !== closeTag) {
          err("expected </" + name + ">");
        }
        pos += closeTag.length;
        return node;
      } else {
        // Text content
        var textStart = pos;
        while (pos < xml.length && xml.charAt(pos) !== "<") pos += 1;
        var text = _decodeEntities(xml.slice(textStart, pos));
        node.children.push({ type: "text", text: text, parent: node });
      }
    }
    err("unterminated element </" + name + ">");
  }

  skipProlog();
  if (pos >= xml.length) err("no root element");
  var root = parseElement(0);
  return root;
}

// Build a namespace map { prefix → uri } for an element by walking
// from root to it; the empty prefix is the default namespace.
function _namespacesInScope(node) {
  var stack = [];
  var cur = node;
  while (cur) { stack.unshift(cur); cur = cur.parent; }
  var nsMap = {};
  stack.forEach(function (el) {
    if (!el.attrs) return;
    el.attrs.forEach(function (a) {
      if (a.name === "xmlns") nsMap[""] = a.value;
      else if (a.name.indexOf("xmlns:") === 0) nsMap[a.name.substring(6)] = a.value;
    });
  });
  return nsMap;
}

// Determine the prefixes a given element uses *visibly*: its own
// element prefix, any attribute prefixes, and the default namespace
// when the element has no explicit prefix.
function _prefixesUsedByElement(element) {
  var used = new Set();
  var elementPrefix = "";
  var colon = element.name.indexOf(":");
  if (colon !== -1) elementPrefix = element.name.substring(0, colon);
  used.add(elementPrefix);
  element.attrs.forEach(function (a) {
    if (a.name === "xmlns" || a.name.indexOf("xmlns:") === 0) return;
    var ac = a.name.indexOf(":");
    if (ac !== -1) used.add(a.name.substring(0, ac));
  });
  return used;
}

function _escapeAttrValue(s) {
  // Per RFC 3741 §1.3.2: "&" → "&amp;", "<" → "&lt;", `"` → "&quot;",
  // \r → "&#xD;", \n → "&#xA;", \t → "&#x9;".
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/"/g, "&quot;")
    .replace(/\r/g, "&#xD;")
    .replace(/\n/g, "&#xA;")
    .replace(/\t/g, "&#x9;");
}

function _escapeText(s) {
  // Per RFC 3741 §1.3.1: "&" → "&amp;", "<" → "&lt;", ">" → "&gt;",
  // \r → "&#xD;".
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\r/g, "&#xD;");
}

function _serializeNode(node, ancestorRendered, withComments) {
  if (node.type === "text") return _escapeText(node.text);
  if (node.type === "comment") return withComments ? "<!--" + node.text + "-->" : "";
  if (node.type !== "element") return "";

  // Compute the namespace map visible from this element's scope.
  var inScope = _namespacesInScope(node);

  // Visibly-used prefixes by this element (per Exclusive c14n §2)
  var used = _prefixesUsedByElement(node);

  // Compute the namespace declarations to RENDER on this element.
  // Exclusive c14n §2: render xmlns:p only if (a) p is in `used` and
  // (b) p's binding wasn't already rendered by an ancestor in the
  // canonicalized subtree.
  var renderedHere = {};
  var renderList = [];
  var prefixes = Object.keys(inScope).sort(function (a, b) {
    if (a === "" && b !== "") return -1;
    if (b === "" && a !== "") return 1;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  prefixes.forEach(function (p) {
    if (!used.has(p)) return;
    var uri = inScope[p];
    if (ancestorRendered[p] === uri) return; // already rendered above
    renderList.push({ prefix: p, uri: uri });
    renderedHere[p] = uri;
  });

  // Sort attributes: regular attributes per c14n §2.4 order — by
  // namespace URI (no NS first), then by local name.
  var regularAttrs = node.attrs
    .filter(function (a) { return a.name !== "xmlns" && a.name.indexOf("xmlns:") !== 0; })
    .map(function (a) {
      var aColon = a.name.indexOf(":");
      var aPrefix = aColon !== -1 ? a.name.substring(0, aColon) : "";
      var aLocal  = aColon !== -1 ? a.name.substring(aColon + 1) : a.name;
      var aUri = aPrefix && inScope[aPrefix] ? inScope[aPrefix] : "";
      return { name: a.name, value: a.value, prefix: aPrefix, local: aLocal, uri: aUri };
    })
    .sort(function (a, b) {
      if (a.uri !== b.uri) return a.uri < b.uri ? -1 : 1;
      return a.local < b.local ? -1 : a.local > b.local ? 1 : 0;
    });

  var out = "<" + node.name;

  // Render namespace declarations (sorted; xmlns first, then xmlns:foo
  // alphabetical by prefix)
  renderList.forEach(function (r) {
    if (r.prefix === "") {
      out += " xmlns=\"" + _escapeAttrValue(r.uri) + "\"";
    } else {
      out += " xmlns:" + r.prefix + "=\"" + _escapeAttrValue(r.uri) + "\"";
    }
  });
  // Render regular attributes
  regularAttrs.forEach(function (a) {
    out += " " + a.name + "=\"" + _escapeAttrValue(a.value) + "\"";
  });
  out += ">";

  // Merge ancestorRendered with renderedHere for child scope.
  var childScope = Object.assign({}, ancestorRendered, renderedHere);
  for (var i = 0; i < node.children.length; i++) {
    out += _serializeNode(node.children[i], childScope, withComments);
  }

  out += "</" + node.name + ">";
  return out;
}

/**
 * @primitive b.xmlC14n.canonicalize
 * @signature b.xmlC14n.canonicalize(input, opts?)
 * @since     0.8.62
 * @status    stable
 * @related   b.xmlC14n.canonicalizeElementById, b.guardXml
 *
 * Produce the RFC 3741 Exclusive XML Canonicalization 1.0 byte
 * sequence for an XML document or a parsed DOM node. Returns a
 * Buffer of UTF-8 bytes.
 *
 * @opts
 *   {
 *     withComments?:   boolean,    // default false (per xml-exc-c14n)
 *   }
 *
 * @example
 *   var c = b.xmlC14n.canonicalize("<a:foo xmlns:a='urn:x'><a:bar/></a:foo>");
 *   // → Buffer<<a:foo xmlns:a="urn:x"><a:bar></a:bar></a:foo>>
 */
function canonicalize(input, opts) {
  opts = opts || {};
  var node = (typeof input === "string" || Buffer.isBuffer(input)) ? parse(input) : input;
  if (!node || node.type !== "element") {
    throw _xmlErr("xml-c14n/bad-input",
      "canonicalize: input must be an XML string or a parsed element node");
  }
  var bytes = _serializeNode(node, {}, opts.withComments === true);
  return Buffer.from(bytes, "utf8");
}

/**
 * @primitive b.xmlC14n.canonicalizeElementById
 * @signature b.xmlC14n.canonicalizeElementById(xml, id, opts?)
 * @since     0.8.62
 * @status    stable
 * @related   b.xmlC14n.canonicalize, b.guardXml
 *
 * Find the element whose `ID` (or operator-specified attribute name)
 * matches the supplied id, then return its canonical-form bytes.
 * Throws if zero or more than one element matches — this single-
 * match invariant is the core defense against XML signature-wrapping
 * attacks where an attacker injects a sibling assertion with the
 * same ID hoping the verifier picks the wrong one.
 *
 * @opts
 *   {
 *     attrName?:       string,   // default "ID"
 *     withComments?:   boolean,
 *   }
 *
 * @example
 *   var bytes = b.xmlC14n.canonicalizeElementById(
 *     "<root><a ID=\"sig\">payload</a></root>",
 *     "sig"
 *   );
 *   // → Buffer<<a ID="sig">payload</a>>
 */
function canonicalizeElementById(xml, id, opts) {
  validateOpts.requireNonEmptyString(id, "canonicalizeElementById: id", XmlC14nError, "xml-c14n/no-id");
  opts = opts || {};
  var root = parse(xml);
  var attrName = opts.attrName || "ID";
  var matches = [];
  function walk(node) {
    if (node.type !== "element") return;
    if (node.attrs) {
      for (var i = 0; i < node.attrs.length; i++) {
        if (node.attrs[i].name === attrName && node.attrs[i].value === id) {
          matches.push(node);
          break;
        }
      }
    }
    for (var ci = 0; ci < node.children.length; ci++) walk(node.children[ci]);
  }
  walk(root);
  if (matches.length === 0) {
    throw _xmlErr("xml-c14n/no-match",
      "canonicalizeElementById: no element with " + attrName + "=\"" + id + "\"");
  }
  if (matches.length > 1) {
    throw _xmlErr("xml-c14n/duplicate-id",
      "canonicalizeElementById: " + matches.length + " elements share " + attrName +
      "=\"" + id + "\" — refusing (signature-wrapping defense)");
  }
  var bytes = _serializeNode(matches[0], {}, opts.withComments === true);
  return Buffer.from(bytes, "utf8");
}

module.exports = {
  parse:                   parse,
  canonicalize:            canonicalize,
  canonicalizeElementById: canonicalizeElementById,
  // Exported so SAML metadata / AuthnRequest builders can interpolate
  // operator-supplied URLs and IDs without raw string concatenation.
  // _escapeAttrValue handles double-quoted attribute-value escaping
  // (`"`, `&`, `<`, CR/LF/HT); _escapeText handles element text-node
  // escaping (`&`, `<`, `>`, CR). Both are RFC 3741 §1.3.x compliant.
  escapeAttrValue:         _escapeAttrValue,
  escapeText:              _escapeText,
  XmlC14nError:            XmlC14nError,
};
