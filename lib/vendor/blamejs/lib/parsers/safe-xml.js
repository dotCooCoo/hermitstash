// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var pick = require("../pick");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var codepointClass = require("../codepoint-class");
var { FrameworkError } = require("../framework-error");

class SafeXmlError extends FrameworkError {
  constructor(message, code, position) {
    super(message);
    this.name = "SafeXmlError";
    this.code = code || "xml/invalid";
    this.position = position || null;
    this.isSafeXmlError = true;
  }
}

var RADIX_HEX = 0x10;

var DEFAULTS = {
  maxBytes:        C.BYTES.mib(1),
  maxDepth:        100,
  maxElements:     10_000,
  maxAttributes:   100,
  allowDoctype:    false,
  allowProcessing: false,
};

var ABSOLUTE_MAX_BYTES = C.BYTES.mib(64);
var ABSOLUTE_MAX_DEPTH = 1_000;
var ABSOLUTE_MAX_ELEMENTS = 1_000_000;
var ABSOLUTE_MAX_ATTRIBUTES = 1_000;

var BUILT_IN_ENTITIES = { lt: "<", gt: ">", amp: "&", quot: "\"", apos: "'" };

function _validateAndCap(name, value, defaultValue, ceiling) {
  if (value === undefined) return defaultValue;
  if (!numericBounds.isPositiveFiniteInt(value)) {
    throw new SafeXmlError("xml/bad-opt",
      "xml.parse: " + name + " must be a positive finite integer; got " +
      numericBounds.shape(value));
  }
  return Math.min(value, ceiling);
}

function parse(input, opts) {
  opts = opts || {};

  var maxBytes      = _validateAndCap("maxBytes",      opts.maxBytes,      DEFAULTS.maxBytes,      ABSOLUTE_MAX_BYTES);
  var maxDepth      = _validateAndCap("maxDepth",      opts.maxDepth,      DEFAULTS.maxDepth,      ABSOLUTE_MAX_DEPTH);
  var maxElements   = _validateAndCap("maxElements",   opts.maxElements,   DEFAULTS.maxElements,   ABSOLUTE_MAX_ELEMENTS);
  var maxAttrs      = _validateAndCap("maxAttributes", opts.maxAttributes, DEFAULTS.maxAttributes, ABSOLUTE_MAX_ATTRIBUTES);
  var allowDoctype  = !!opts.allowDoctype;
  var allowProcessing = !!opts.allowProcessing;

  input = safeBuffer.normalizeText(input, {
    maxBytes:   maxBytes,
    errorClass: SafeXmlError,
    typeCode:   "xml/wrong-input-type",
    sizeCode:   "xml/too-large",
  });

  var pos = 0;
  var len = input.length;
  var elementCount = 0;

  function _err(msg, code) {
    return new SafeXmlError(msg + " at position " + pos, code || "xml/invalid", pos);
  }

  function skipWs() {
    while (pos < len) {
      var c = input.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D) pos += 1;
      else break;
    }
  }

  function expectChar(ch) {
    if (input.charAt(pos) !== ch) {
      throw _err("expected '" + ch + "'");
    }
    pos += 1;
  }

  function decodeEntities(s) {
    var out = "";
    var i = 0;
    while (i < s.length) {
      var ch = s.charAt(i);
      if (ch !== "&") { out += ch; i += 1; continue; }
      var end = s.indexOf(";", i);
      if (end < 0) throw _err("unterminated entity reference", "xml/bad-entity");
      var name = s.substring(i + 1, end);
      if (name.charAt(0) === "#") {
        var code;
        if (name.charAt(1) === "x" || name.charAt(1) === "X") {
          code = parseInt(name.substring(2), RADIX_HEX);
        } else {
          code = parseInt(name.substring(1), 10);
        }
        if (!Number.isFinite(code) || code < 0 || code > 0x10FFFF) {
          throw _err("invalid numeric character reference", "xml/bad-entity");
        }
        if ((code < 0x20 && code !== 0x09 && code !== 0x0A && code !== 0x0D) || (code >= 0xD800 && code <= 0xDFFF)) {
          throw _err("character reference points to forbidden codepoint", "xml/bad-entity");
        }
        out += String.fromCodePoint(code);
        i = end + 1;
      } else if (Object.prototype.hasOwnProperty.call(BUILT_IN_ENTITIES, name)) {
        out += BUILT_IN_ENTITIES[name];
        i = end + 1;
      } else {
        throw _err("unknown entity '" + name + "' (custom entities forbidden — XXE protection)", "xml/external-entity");
      }
    }
    return out;
  }

  function parseName() {
    var start = pos;
    while (pos < len) {
      var c = input.charCodeAt(pos);
      if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
          (c >= 0x30 && c <= 0x39) ||
          c === 0x2D || c === 0x5F || c === 0x2E || c === 0x3A ||
          (c >= 0x80 && c <= 0xFFFF)) {
        pos += 1;
      } else break;
    }
    if (pos === start) throw _err("expected name", "xml/bad-name");
    var parsed = input.substring(start, pos);
    if (pick.isPoisonedKey(parsed)) {
      throw _err("element/attribute name '" + parsed +
        "' is reserved (prototype-pollution defense)", "xml/forbidden-name");
    }
    return parsed;
  }

  function parseAttrValue() {
    var quote = input.charAt(pos);
    if (quote !== "\"" && quote !== "'") throw _err("expected quoted attribute value", "xml/bad-attr");
    pos += 1;
    var start = pos;
    while (pos < len && input.charAt(pos) !== quote) {
      if (input.charAt(pos) === "<") throw _err("'<' not allowed in attribute value", "xml/bad-attr");
      pos += 1;
    }
    if (pos >= len) throw _err("unterminated attribute value", "xml/bad-attr");
    var raw = input.substring(start, pos);
    pos += 1;
    return decodeEntities(raw);
  }

  function parseDocument() {
    skipWs();
    if (input.startsWith("<?xml", pos)) {
      var declEnd = input.indexOf("?>", pos);
      if (declEnd < 0) throw _err("unterminated XML declaration", "xml/bad-decl");
      pos = declEnd + 2;
    }
    skipWs();
    if (input.startsWith("<!DOCTYPE", pos)) {
      if (!allowDoctype) {
        throw _err("DOCTYPE declarations are forbidden (XXE protection)", "xml/doctype");
      }
      var doctypeEnd = pos;
      var depth = 0;
      while (doctypeEnd < len) {
        var c = input.charAt(doctypeEnd);
        if (c === "[") depth += 1;
        else if (c === "]") depth -= 1;
        else if (c === ">" && depth === 0) break;
        doctypeEnd += 1;
      }
      pos = doctypeEnd + 1;
    }
    skipWs();

    while (input.startsWith("<!--", pos) || input.startsWith("<?", pos)) {
      if (input.startsWith("<!--", pos)) {
        var commentEnd = input.indexOf("-->", pos);
        if (commentEnd < 0) throw _err("unterminated comment", "xml/bad-comment");
        pos = commentEnd + 3;
      } else {
        if (!allowProcessing) {
          throw _err("processing instructions are forbidden (allowProcessing: true to permit)", "xml/processing");
        }
        var piEnd = input.indexOf("?>", pos);
        if (piEnd < 0) throw _err("unterminated processing instruction", "xml/bad-pi");
        pos = piEnd + 2;
      }
      skipWs();
    }

    if (input.charAt(pos) !== "<") throw _err("expected root element", "xml/no-root");
    var root = parseElement(0);
    skipWs();
    if (pos !== len) {
      while (pos < len && input.startsWith("<!--", pos)) {
        var ce = input.indexOf("-->", pos);
        if (ce < 0) throw _err("unterminated trailing comment", "xml/bad-comment");
        pos = ce + 3;
        skipWs();
      }
      if (pos !== len) throw _err("unexpected content after root element", "xml/extra-content");
    }
    return root;
  }

  function parseElement(depth) {
    if (depth > maxDepth) throw _err("nesting exceeds maxDepth", "xml/too-deep");
    elementCount += 1;
    if (elementCount > maxElements) throw _err("element count exceeds maxElements", "xml/too-many-elements");

    expectChar("<");
    var name = parseName();
    var attrs = Object.create(null);
    var attrCount = 0;

    while (pos < len) {
      var c = input.charAt(pos);
      if (c === "/") { pos += 1; expectChar(">"); return _wrap(name, attrs, []); }
      if (c === ">") { pos += 1; break; }
      if (c === " " || c === "\t" || c === "\n" || c === "\r") { pos += 1; continue; }

      attrCount += 1;
      if (attrCount > maxAttrs) throw _err("attribute count exceeds maxAttributes", "xml/too-many-attrs");
      var attrName = parseName();
      skipWs();
      expectChar("=");
      skipWs();
      var attrValue = parseAttrValue();
      if (attrs[attrName] !== undefined) {
        throw _err("duplicate attribute '" + attrName + "'", "xml/duplicate-attr");
      }
      attrs[attrName] = attrValue;
    }

    var children = [];
    while (pos < len) {
      if (input.startsWith("</", pos)) {
        pos += 2;
        var endName = parseName();
        if (endName !== name) throw _err("mismatched end tag </" + endName + "> for <" + name + ">", "xml/mismatched-tag");
        skipWs();
        expectChar(">");
        return _wrap(name, attrs, children);
      }
      if (input.startsWith("<!--", pos)) {
        var commentEnd = input.indexOf("-->", pos);
        if (commentEnd < 0) throw _err("unterminated comment", "xml/bad-comment");
        pos = commentEnd + 3;
        continue;
      }
      if (input.startsWith("<![CDATA[", pos)) {
        var cdataEnd = input.indexOf("]]>", pos + 9);
        if (cdataEnd < 0) throw _err("unterminated CDATA", "xml/bad-cdata");
        children.push({ kind: "text", value: input.substring(pos + 9, cdataEnd) });
        pos = cdataEnd + 3;
        continue;
      }
      if (input.startsWith("<?", pos)) {
        if (!allowProcessing) throw _err("processing instructions forbidden", "xml/processing");
        var piEnd = input.indexOf("?>", pos);
        if (piEnd < 0) throw _err("unterminated PI", "xml/bad-pi");
        pos = piEnd + 2;
        continue;
      }
      if (input.charAt(pos) === "<") {
        children.push({ kind: "element", value: parseElement(depth + 1) });
        continue;
      }
      var textStart = pos;
      while (pos < len && input.charAt(pos) !== "<") pos += 1;
      var rawText = input.substring(textStart, pos);
      if (rawText.length > 0) {
        children.push({ kind: "text", value: decodeEntities(rawText) });
      }
    }
    throw _err("unexpected end of input inside <" + name + ">", "xml/truncated");
  }

  function _wrap(name, attrs, children) {
    var elementChildren = children.filter(function (c) { return c.kind === "element"; });
    var textParts = children.filter(function (c) { return c.kind === "text"; }).map(function (c) { return c.value; });
    var hasAttrs = Object.keys(attrs).length > 0;

    if (children.length === 0 && !hasAttrs) {
      return _make(name, "");
    }
    if (elementChildren.length === 0 && !hasAttrs) {
      return _make(name, textParts.join("").trim() === "" ? textParts.join("") : textParts.join(""));
    }
    var obj = Object.create(null);
    if (hasAttrs) obj["@attrs"] = attrs;
    var grouped = Object.create(null);
    for (var i = 0; i < elementChildren.length; i++) {
      var childWrap = elementChildren[i].value;
      var childName = Object.keys(childWrap)[0];
      var childVal = childWrap[childName];
      if (grouped[childName] === undefined) {
        grouped[childName] = childVal;
      } else if (Array.isArray(grouped[childName])) {
        grouped[childName].push(childVal);
      } else {
        grouped[childName] = [grouped[childName], childVal];
      }
    }
    Object.assign(obj, grouped);
    var combinedText = codepointClass.splitOnWhitespace(textParts.join("")).join(" ");
    if (combinedText.length > 0) obj["#text"] = combinedText;
    return _make(name, obj);
  }

  function _make(name, value) {
    var out = Object.create(null);
    out[name] = value;
    return out;
  }

  return parseDocument();
}

module.exports = {
  parse:         parse,
  SafeXmlError:  SafeXmlError,
  DEFAULTS:      DEFAULTS,
  BUILT_IN_ENTITIES: BUILT_IN_ENTITIES,
};
