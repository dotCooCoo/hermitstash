"use strict";
/**
 * Security-focused XML parser. Same security defaults blamejs's json
 * parser applies, adapted to XML's threat model.
 *
 * Native XML.parse doesn't exist in Node, and most npm libs (xml2js,
 * fast-xml-parser, sax, libxml) leave at least one of the following to
 * the caller — usually all of them:
 *
 *   - XXE (XML External Entity): <!ENTITY foo SYSTEM "file:///etc/passwd">
 *   - Billion-laughs entity expansion (DoS)
 *   - DTDs (DOCTYPE) opening the door to either of the above
 *   - Processing instructions referencing external resources
 *   - Unbounded recursion / element count / attribute count
 *   - CDATA sections of arbitrary length
 *   - Prototype pollution: an element or attribute named __proto__,
 *     constructor, or prototype landing as a key in the result tree
 *     (CWE-1321 / OWASP prototype-pollution)
 *
 * This parser closes all of them by default. DOCTYPE, external entities,
 * and processing instructions other than '<?xml ?>' are REJECTED — apps
 * that need them are using the wrong parser. Element and attribute names
 * equal to __proto__ / constructor / prototype are REJECTED with
 * xml/forbidden-name so they can never collide with an inherited member
 * or reassign an accumulator's prototype; the result tree and every
 * nested object it contains have a null prototype, so a consumer reading
 * an absent key sees undefined rather than an inherited Object member.
 *
 * Output: a plain JS object. Element with attributes + children:
 *   <root id="x"><child>text</child></root>
 * becomes:
 *   { root: { '@attrs': { id: 'x' }, child: 'text' } }
 *
 * Multiple children with the same tag become arrays. Mixed content
 * (text + elements interleaved) is preserved as { '#text': '...', ... }.
 *
 * Public API:
 *   xml.parse(input, opts?)            → JS object | throws SafeXmlError
 *   xml.SafeXmlError                   → error class
 *
 * Defaults:
 *   maxBytes:        1 MiB
 *   maxDepth:        100
 *   maxElements:     10000
 *   maxAttributes:   100 per element
 *   allowDoctype:    false
 *   allowProcessing: false  (only <?xml version="..."?> is permitted)
 */

var C = require("../constants");
var pick = require("../pick");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
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

// parseInt radix — named so the call site doesn't carry a bare 16
// integer literal that reads as a byte count.
var RADIX_HEX = 0x10;

var DEFAULTS = {
  maxBytes:        C.BYTES.mib(1),
  maxDepth:        100,
  maxElements:     10_000,
  maxAttributes:   100,
  allowDoctype:    false,
  allowProcessing: false,    // <?...?> other than the xml decl
};

var ABSOLUTE_MAX_BYTES = C.BYTES.mib(64);
var ABSOLUTE_MAX_DEPTH = 1_000;
var ABSOLUTE_MAX_ELEMENTS = 1_000_000;
var ABSOLUTE_MAX_ATTRIBUTES = 1_000;

// XML built-in entities (the ONLY entities allowed)
var BUILT_IN_ENTITIES = { lt: "<", gt: ">", amp: "&", quot: "\"", apos: "'" };

// Names that must never become a key in the result tree. A plain object
// inherits these from Object.prototype; an element/attribute named after
// one of them would otherwise collide with the inherited member (a
// consumer sees a function/object instead of undefined) or — for a
// computed-member write of an object value — reassign the accumulator's
// prototype (CWE-1321 / OWASP prototype-pollution). The accumulators are
// built with a null prototype, and these names are rejected outright so
// the result is always a clean key→value map. Mirrors the
// __proto__/constructor/prototype rejection the toml / yaml / ini
// parsers in this family already apply.

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

  // Skip whitespace
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

  // Decode &amp; / &lt; / etc. — ONLY the 5 built-ins + numeric character refs.
  // Custom entities are forbidden by design (XXE protection).
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
        // Numeric character reference
        var code;
        if (name.charAt(1) === "x" || name.charAt(1) === "X") {
          code = parseInt(name.substring(2), RADIX_HEX);
        } else {
          code = parseInt(name.substring(1), 10);
        }
        if (!Number.isFinite(code) || code < 0 || code > 0x10FFFF) {
          throw _err("invalid numeric character reference", "xml/bad-entity");
        }
        // XML 1.0 forbids most C0 control chars
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

  // Parse a name (element / attribute name)
  function parseName() {
    var start = pos;
    while (pos < len) {
      var c = input.charCodeAt(pos);
      // XML name characters — simplified subset (ASCII letters, digits, '-', '_', '.', ':')
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

  // Parse an attribute value (single- or double-quoted)
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

  // Top-level: optional XML declaration, optional DOCTYPE (rejected), root element
  function parseDocument() {
    skipWs();
    // XML declaration <?xml version="1.0" ... ?>
    if (input.startsWith("<?xml", pos)) {
      var declEnd = input.indexOf("?>", pos);
      if (declEnd < 0) throw _err("unterminated XML declaration", "xml/bad-decl");
      pos = declEnd + 2;
    }
    skipWs();
    // DOCTYPE — rejected by default (XXE / billion-laughs vector)
    if (input.startsWith("<!DOCTYPE", pos)) {
      if (!allowDoctype) {
        throw _err("DOCTYPE declarations are forbidden (XXE protection)", "xml/doctype");
      }
      // If allowed (operator opt-in), skip past the DOCTYPE without parsing internal subset
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

    // Comments / processing instructions before root
    while (input.startsWith("<!--", pos) || input.startsWith("<?", pos)) {
      if (input.startsWith("<!--", pos)) {
        var commentEnd = input.indexOf("-->", pos);
        if (commentEnd < 0) throw _err("unterminated comment", "xml/bad-comment");
        pos = commentEnd + 3;
      } else {
        // Processing instruction
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
      // Trailing comments / whitespace OK; otherwise reject extra content
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
    // Null-prototype accumulator keyed by attacker-influenced attribute
    // names — no inherited Object member can shadow a missing key, and the
    // duplicate-attribute check below can't be fooled by an inherited
    // function (CWE-1321). Forbidden names are already rejected in
    // parseName.
    var attrs = Object.create(null);
    var attrCount = 0;

    while (pos < len) {
      // Look for attribute, '/>', or '>'
      var c = input.charAt(pos);
      if (c === "/") { pos += 1; expectChar(">"); return _wrap(name, attrs, []); }
      if (c === ">") { pos += 1; break; }
      if (c === " " || c === "\t" || c === "\n" || c === "\r") { pos += 1; continue; }

      // Attribute
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

    // Children + text
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
      // Text
      var textStart = pos;
      while (pos < len && input.charAt(pos) !== "<") pos += 1;
      var rawText = input.substring(textStart, pos);
      if (rawText.length > 0) {
        children.push({ kind: "text", value: decodeEntities(rawText) });
      }
    }
    throw _err("unexpected end of input inside <" + name + ">", "xml/truncated");
  }

  // Wrap parsed element into the JS-object shape.
  function _wrap(name, attrs, children) {
    var elementChildren = children.filter(function (c) { return c.kind === "element"; });
    var textParts = children.filter(function (c) { return c.kind === "text"; }).map(function (c) { return c.value; });
    var hasAttrs = Object.keys(attrs).length > 0;

    // Self-closing or empty element with no attrs → empty string
    if (children.length === 0 && !hasAttrs) {
      return _make(name, "");
    }
    if (elementChildren.length === 0 && !hasAttrs) {
      // Pure-text element → string
      return _make(name, textParts.join("").trim() === "" ? textParts.join("") : textParts.join(""));
    }
    // Mixed / attributed element → object. Both accumulators carry a null
    // prototype: `grouped` is keyed by attacker-influenced child element
    // names and `obj` receives them via Object.assign, so neither may
    // expose an inherited Object member or be prototype-poisoned by a
    // computed-member write (CWE-1321). Forbidden child names were already
    // rejected in parseName.
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
    var combinedText = textParts.join("").replace(/\s+/g, " ").trim();
    if (combinedText.length > 0) obj["#text"] = combinedText;
    return _make(name, obj);
  }

  function _make(name, value) {
    // Null-prototype wrapper keyed by the element name (parser-controlled,
    // attacker-influenced). `out[name] = value` with a forbidden name
    // would otherwise reassign the wrapper's prototype when value is an
    // object; the name is already rejected in parseName and the null
    // prototype removes the inherited-member surface entirely (CWE-1321).
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
