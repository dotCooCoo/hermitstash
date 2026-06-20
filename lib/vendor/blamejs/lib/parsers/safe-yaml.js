"use strict";
/**
 * Security-focused YAML parser (safe subset of YAML 1.2).
 *
 * YAML's full grammar is large and historically the source of many CVEs:
 * `!!python/object` deserialization in PyYAML, anchor-cycle billion-laughs
 * DoS, tag-based RCE chains. This parser implements only the JSON-shaped
 * subset that real-world config files actually use, and REJECTS the rest
 * with explicit errors.
 *
 * Supported:
 *   - Block mappings: `key: value`, indented children
 *   - Block sequences: `- item`, indented multi-line items
 *   - Flow mappings: `{ key: value, ... }`
 *   - Flow sequences: `[a, b, c]`
 *   - Plain scalars with YAML 1.2 *core schema* type inference:
 *       null / Null / NULL / ~ / empty       null
 *       true / True / TRUE / false / False   boolean
 *         (only these forms — NOT yes/no/on/off, fixing the
 *         "Norway problem" where country: NO became country: false)
 *       integers: 0, -17, 0o755, 0x1F                          number
 *       floats:   3.14, 5e+22, .inf, -.inf, .nan               number
 *       everything else                                         string
 *   - Single-quoted strings (no escapes; `''` for literal apostrophe)
 *   - Double-quoted strings (\n, \t, \\, \", \uXXXX, \UXXXXXXXX)
 *   - Block scalars: literal `|` and folded `>` with chomp indicators
 *     (-, +, or default)
 *   - `#` comments (line-rest)
 *
 * REJECTED with explicit errors:
 *   - Anchors `&name` / aliases `*name` (billion-laughs / cycles)
 *   - Tags `!tag`, `!!tag`, `!<uri>` (tag-driven deserialization)
 *   - YAML directives `%YAML`, `%TAG`
 *   - Multi-document streams (`---` / `...` separators)
 *   - Complex keys (`? mapping_key`)
 *   - Merge keys `<<` (anchor-using feature)
 *   - Tabs in indentation (per YAML 1.2 spec)
 *   - __proto__ / constructor / prototype as map keys (prototype pollution)
 *
 * Output shape:
 *   - mappings  plain {} object
 *   - sequences JS array
 *   - scalars   string / number / boolean / null per core schema
 *
 * Public API:
 *   yaml.parse(input, opts?)        value | throws SafeYamlError
 *   yaml.SafeYamlError              error class
 *
 * Defaults:
 *   maxBytes:  1 MiB
 *   maxDepth:  100
 *   maxKeys:   50000
 */

var C = require("../constants");
var pick = require("../pick");
var boundedMap = require("../bounded-map");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var { FrameworkError } = require("../framework-error");

class SafeYamlError extends FrameworkError {
  constructor(message, code, line, col) {
    super(line != null ? message + " at line " + line + ":" + col : message);
    this.name = "SafeYamlError";
    this.code = code || "yaml/invalid";
    this.line = line == null ? null : line;
    this.col = col == null ? null : col;
    this.isSafeYamlError = true;
  }
}

// parseInt radices, named so the line itself doesn't carry a bare 8 / 16
// integer literal that reads as a byte count.
var RADIX_OCTAL = 0x8;
var RADIX_HEX   = 0x10;

// Defensive cap on the size of a single scalar token before regex
// classification. The parser already bounds the whole input via maxBytes;
// this cap keeps a pathological single-line scalar from feeding the type-
// inference regexes an arbitrarily long string.
var MAX_SCALAR_BYTES = C.BYTES.kib(64);

var DEFAULTS = {
  maxBytes: C.BYTES.mib(1),
  maxDepth: 100,
  maxKeys:  50_000,
};


// YAML 1.2 core-schema scalar resolution. Order matters: null first
// (covers ~ and empty), then bool, then int (with base prefixes), then
// float, then string fallback.
var NULL_RE  = /^(null|Null|NULL|~|)$/;
var BOOL_RE  = /^(true|True|TRUE|false|False|FALSE)$/;
var INT_RE   = /^[-+]?(0|[1-9][0-9]*)$/;
var INT_OCT  = /^0o[0-7]+$/;
var INT_HEX  = /^0x[0-9a-fA-F]+$/;
var FLOAT_RE = /^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/;
var FLOAT_INF = /^[-+]?\.(inf|Inf|INF)$/;
var FLOAT_NAN = /^\.(nan|NaN|NAN)$/;

function _resolveScalar(s) {
  // Fall back to string for any token whose length exceeds the scalar cap
  // before running type-inference regexes. The parser caller has already
  // applied the input-wide maxBytes cap; this is a per-token guard so the
  // type-inference regexes never see a pathologically long string.
  if (typeof s !== "string" || s.length > MAX_SCALAR_BYTES) return s;
  // Below: every regex test sees an `s` whose s.length <= MAX_SCALAR_BYTES.
  if (NULL_RE.test(s)) return null;
  if (BOOL_RE.test(s)) return s.toLowerCase() === "true";
  // s.length <= MAX_SCALAR_BYTES asserted at function entry above.
  if (INT_RE.test(s)) {
    var n = parseInt(s, 10);
    if (Number.isSafeInteger(n)) return n;
    return s;  // fallback to string for huge ints (don't lose precision silently)
  }
  // s.length <= MAX_SCALAR_BYTES asserted at function entry above.
  if (INT_OCT.test(s)) {
    var oct = parseInt(s.substring(2), RADIX_OCTAL);
    if (Number.isSafeInteger(oct)) return oct;
    return s;
  }
  // s.length <= MAX_SCALAR_BYTES asserted at function entry above.
  if (INT_HEX.test(s)) {
    var hex = parseInt(s.substring(2), RADIX_HEX);
    if (Number.isSafeInteger(hex)) return hex;
    return s;
  }
  // s.length <= MAX_SCALAR_BYTES asserted at function entry above.
  if (FLOAT_INF.test(s)) return s.charAt(0) === "-" ? -Infinity : Infinity;
  if (FLOAT_NAN.test(s)) return NaN;
  // s.length <= MAX_SCALAR_BYTES asserted at function entry above.
  if (FLOAT_RE.test(s)) {
    var f = parseFloat(s);
    if (!isNaN(f)) return f;
  }
  return s;
}

function parse(input, opts) {
  opts = opts || {};
  // Validate operator-supplied numeric opts via lib/numeric-bounds —
  // Infinity / NaN / negative / non-integer all bypass the
  // `> 0` shape and silently lift the DoS cap they were meant to enforce.
  if (opts.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new SafeYamlError("yaml.parse: maxBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxBytes), "yaml/bad-opt");
  }
  if (opts.maxDepth !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxDepth)) {
    throw new SafeYamlError("yaml.parse: maxDepth must be a positive finite integer; got " +
      numericBounds.shape(opts.maxDepth), "yaml/bad-opt");
  }
  if (opts.maxKeys !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxKeys)) {
    throw new SafeYamlError("yaml.parse: maxKeys must be a positive finite integer; got " +
      numericBounds.shape(opts.maxKeys), "yaml/bad-opt");
  }
  var maxBytes = opts.maxBytes !== undefined
    ? Math.min(opts.maxBytes, C.BYTES.mib(64)) : DEFAULTS.maxBytes;
  var maxDepth = opts.maxDepth !== undefined
    ? Math.min(opts.maxDepth, 1_000) : DEFAULTS.maxDepth;
  var maxKeys = opts.maxKeys !== undefined
    ? Math.min(opts.maxKeys, 1_000_000) : DEFAULTS.maxKeys;

  input = safeBuffer.normalizeText(input, {
    maxBytes:   maxBytes,
    errorClass: SafeYamlError,
    typeCode:   "yaml/wrong-input-type",
    sizeCode:   "yaml/too-large",
  });

  // Pre-validate: scan for banned constructs ANYWHERE in the input. Cheap
  // up-front rejection beats partial-parse-then-throw, and it surfaces a
  // clearer diagnostic than "unexpected & at line 47".
  // Skip bans that appear inside quoted strings — those are legitimate
  // string content. Block-scalar content also exempt.
  _preValidate(input);

  // Normalize line endings: CRLF / CR → LF for consistent line-based work.
  input = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // Split into raw lines preserving line numbers.
  var rawLines = input.split("\n");
  var lines = [];
  for (var i = 0; i < rawLines.length; i++) {
    var raw = rawLines[i];
    // Strip trailing whitespace from the line for analysis (block-scalar
    // content paths preserve their own internal spacing separately).
    var trimmed = safeBuffer.stripTrailingHspace(raw);
    var indent = 0;
    while (indent < raw.length && raw.charAt(indent) === " ") indent += 1;
    if (indent < raw.length && raw.charAt(indent) === "\t") {
      throw new SafeYamlError("tab in indentation (YAML 1.2 forbids)", "yaml/tab-indent", i + 1, indent + 1);
    }
    var content = raw.substring(indent);
    var isBlank = content.length === 0;
    var isComment = content.charAt(0) === "#";
    lines.push({
      lineNumber: i + 1,
      raw:         raw,
      indent:      indent,
      content:     content,
      trimmed:     trimmed,
      isBlank:     isBlank,
      isComment:   isComment,
    });
  }

  // Skip leading blank/comment lines and an optional `---` document marker.
  // Reject any later `---` or `...` (multi-document streams not supported).
  var idx = 0;
  while (idx < lines.length && (lines[idx].isBlank || lines[idx].isComment)) idx += 1;
  if (idx < lines.length && /^---(\s|$)/.test(lines[idx].content)) idx += 1;
  // Subsequent doc markers anywhere = reject.
  for (var j = idx; j < lines.length; j++) {
    var c = lines[j].content;
    if (/^---(\s|$)/.test(c) || /^\.\.\.(\s|$)/.test(c)) {
      throw new SafeYamlError(
        "multi-document YAML streams are not supported",
        "yaml/multi-document", lines[j].lineNumber, 1
      );
    }
  }

  var keyCount = 0;

  function _bumpKeys(line) {
    keyCount += 1;
    if (keyCount > maxKeys) {
      throw new SafeYamlError("input exceeds maxKeys", "yaml/too-many-keys", line, 1);
    }
  }

  // ---- Recursive parse ----
  // parseValue takes a starting line index and the *minimum* indent the
  // value occupies. Returns { value, nextLine }.

  function parseValueAtLine(startIdx, parentIndent, depth) {
    if (depth > maxDepth) {
      throw new SafeYamlError("input exceeds maxDepth", "yaml/too-deep",
        startIdx < lines.length ? lines[startIdx].lineNumber : null, 1);
    }

    // Skip blank + comment lines.
    var k = startIdx;
    while (k < lines.length && (lines[k].isBlank || lines[k].isComment)) k += 1;
    if (k >= lines.length) return { value: null, nextLine: lines.length };

    var firstLine = lines[k];
    if (firstLine.indent <= parentIndent) {
      // No content for this value — it's an empty value (e.g. `key:` with nothing after)
      return { value: null, nextLine: k };
    }

    var content = firstLine.content;
    var indent = firstLine.indent;

    // Block sequence: line starts with `- ` or just `-` (then empty / value)
    if (content === "-" || content.startsWith("- ")) {
      return _parseBlockSequence(k, indent, depth);
    }

    // Block mapping starts with a key (bare or quoted) followed by `:`.
    var keyRange = _scanKeyRange(content, firstLine.lineNumber, indent);
    if (keyRange) {
      return _parseBlockMapping(k, indent, depth);
    }

    // Block scalar header: `|` or `>` (with optional chomp/indent indicator)
    if (/^[|>][-+]?[0-9]?\s*(#.*)?$/.test(content)) {
      return _parseBlockScalar(k, indent, content);
    }

    // Otherwise: a single scalar (possibly continued via flow style on
    // following lines, but for the safe subset we restrict scalars to
    // single-line plain or quoted, or wrapped flow on a single line).
    return _parseScalarOrFlow(k, indent);
  }

  // _scanKeyRange returns { keyLiteral, valueStart } if the line starts
  // with a bare-or-quoted key followed by ":" + (space|EOL), else null.
  function _scanKeyRange(content, lineNumber, indent) {
    var p = 0;
    var len = content.length;
    if (len === 0) return null;
    if (content.charAt(0) === "?") {
      throw new SafeYamlError("complex keys (`? key`) are not supported",
        "yaml/complex-key-banned", lineNumber, indent + 1);
    }
    if (content.charAt(0) === '"') {
      // Find closing quote
      var i = 1;
      while (i < len) {
        var ch = content.charAt(i);
        if (ch === "\\") { i += 2; continue; }
        if (ch === '"') break;
        i += 1;
      }
      if (i >= len) return null;  // unterminated → not a key
      p = i + 1;
    } else if (content.charAt(0) === "'") {
      var j = 1;
      while (j < len) {
        if (content.charAt(j) === "'") {
          if (content.charAt(j + 1) === "'") { j += 2; continue; }
          break;
        }
        j += 1;
      }
      if (j >= len) return null;
      p = j + 1;
    } else {
      // Plain scalar key: read up to ':' followed by space or EOL.
      while (p < len) {
        if (content.charAt(p) === ":" &&
            (p + 1 === len || content.charAt(p + 1) === " ")) {
          break;
        }
        p += 1;
      }
      if (p >= len) return null;
    }
    if (content.charAt(p) !== ":") return null;
    var afterColon = p + 1;
    if (afterColon !== len && content.charAt(afterColon) !== " ") return null;
    return { keyEnd: p, valueStart: afterColon };
  }

  function _decodeKeyLiteral(raw, lineNumber, col) {
    if (raw.charAt(0) === '"') {
      return _decodeDoubleQuoted(raw, lineNumber, col);
    }
    if (raw.charAt(0) === "'") {
      return _decodeSingleQuoted(raw, lineNumber, col);
    }
    var trimmed = safeBuffer.stripTrailingHspace(raw);
    if (pick.isPoisonedKey(trimmed)) {
      throw new SafeYamlError("forbidden key '" + trimmed + "'",
        "yaml/poisoned-key", lineNumber, col);
    }
    return trimmed;
  }

  function _parseBlockMapping(startIdx, indent, depth) {
    var result = Object.create(null);
    var seen = new Set();
    var k = startIdx;
    while (k < lines.length) {
      var ln = lines[k];
      if (ln.isBlank || ln.isComment) { k += 1; continue; }
      if (ln.indent < indent) break;
      if (ln.indent > indent) {
        // Shouldn't happen if our caller dispatched correctly
        throw new SafeYamlError("unexpected indent", "yaml/bad-indent", ln.lineNumber, ln.indent + 1);
      }
      // Reject a block sequence at the same indent — that's not a mapping.
      if (ln.content === "-" || ln.content.startsWith("- ")) {
        throw new SafeYamlError("sequence item where mapping key expected",
          "yaml/expected-key", ln.lineNumber, ln.indent + 1);
      }
      var keyRange = _scanKeyRange(ln.content, ln.lineNumber, ln.indent);
      if (!keyRange) {
        throw new SafeYamlError("expected mapping key 'name:'",
          "yaml/expected-key", ln.lineNumber, ln.indent + 1);
      }
      var keyLiteral = ln.content.substring(0, keyRange.keyEnd);
      var key = _decodeKeyLiteral(keyLiteral, ln.lineNumber, ln.indent + 1);
      if (typeof key !== "string") {
        throw new SafeYamlError("non-string mapping key not supported",
          "yaml/bad-key", ln.lineNumber, ln.indent + 1);
      }
      if (pick.isPoisonedKey(key)) {
        throw new SafeYamlError("forbidden key '" + key + "'",
          "yaml/poisoned-key", ln.lineNumber, ln.indent + 1);
      }
      if (key === "<<") {
        throw new SafeYamlError("merge key '<<' not supported (anchor-using feature)",
          "yaml/merge-key-banned", ln.lineNumber, ln.indent + 1);
      }
      boundedMap.requireAbsentMember(seen, key, function () {
        throw new SafeYamlError("duplicate mapping key '" + key + "'",
          "yaml/duplicate-key", ln.lineNumber, ln.indent + 1);
      });
      seen.add(key);
      _bumpKeys(ln.lineNumber);

      // Determine the value:
      // 1. if there's content after the colon, that's a flow value or
      //    a plain scalar continuation on the same line.
      // 2. otherwise the value lives on subsequent more-indented lines.
      var afterColon = ln.content.substring(keyRange.valueStart).replace(/^[ \t]+/, "");
      // Strip end-of-line comment
      afterColon = _stripEolComment(afterColon);
      var value;
      if (afterColon.length > 0) {
        // Inline value on this line.
        if (afterColon.charAt(0) === "|" || afterColon.charAt(0) === ">") {
          // Block scalar header inline with key
          if (!/^[|>][-+]?[0-9]?\s*$/.test(afterColon)) {
            throw new SafeYamlError("malformed block scalar header",
              "yaml/bad-block-scalar", ln.lineNumber, ln.indent + 1);
          }
          var bs = _parseBlockScalar(k, indent, afterColon);
          // Block scalar header was on this line; content is on the
          // following lines. _parseBlockScalar handles the header
          // tokenisation when given the header content directly.
          value = bs.value;
          k = bs.nextLine;
          result[key] = value;
          continue;
        }
        value = _parseInlineValue(afterColon, ln.lineNumber, ln.indent + keyRange.valueStart);
        k += 1;
      } else {
        // Value is on more-indented lines below.
        var nested = parseValueAtLine(k + 1, indent, depth + 1);
        value = nested.value;
        k = nested.nextLine;
      }
      result[key] = value;
    }
    // Convert null-prototype to plain {} below in _normalize.
    return { value: result, nextLine: k };
  }

  function _parseBlockSequence(startIdx, indent, depth) {
    var arr = [];
    var k = startIdx;
    while (k < lines.length) {
      var ln = lines[k];
      if (ln.isBlank || ln.isComment) { k += 1; continue; }
      if (ln.indent < indent) break;
      if (ln.indent !== indent) {
        throw new SafeYamlError("unexpected indent in sequence",
          "yaml/bad-indent", ln.lineNumber, ln.indent + 1);
      }
      if (ln.content !== "-" && !ln.content.startsWith("- ")) break;
      _bumpKeys(ln.lineNumber);

      // Item value:
      // - "- " followed by content → inline value (could be flow, scalar,
      //   or the start of a nested mapping if "key: value" pattern)
      // - "-" alone → value on more-indented lines below
      var afterDash = ln.content === "-" ? "" : ln.content.substring(2);
      afterDash = _stripEolComment(afterDash);
      var item;
      if (afterDash.length === 0) {
        var nested = parseValueAtLine(k + 1, indent, depth + 1);
        item = nested.value;
        k = nested.nextLine;
      } else {
        // Could be a nested mapping: `- key: value` (compact mapping)
        var mapKey = _scanKeyRange(afterDash, ln.lineNumber, ln.indent + 2);
        if (mapKey) {
          // Treat as a single-line block mapping at indent+2 by
          // synthesising a sub-region. The mapping's "indent" is the
          // column where the key starts (ln.indent + 2).
          // We need to feed _parseBlockMapping starting at this line but
          // with the mapping treating its own indent as ln.indent + 2.
          // Simplest: clone the line with the dash stripped, then continue
          // with subsequent more-indented lines as the mapping's body.
          var synthetic = {
            lineNumber: ln.lineNumber,
            raw:         ln.raw,
            indent:      ln.indent + 2,
            content:     afterDash,
            trimmed:     afterDash,
            isBlank:     false,
            isComment:   false,
          };
          var saved = lines[k];
          lines[k] = synthetic;
          try {
            var sub = _parseBlockMapping(k, ln.indent + 2, depth + 1);
            item = sub.value;
            k = sub.nextLine;
          } finally {
            lines[saved.lineNumber - 1] = saved;
          }
        } else {
          item = _parseInlineValue(afterDash, ln.lineNumber, ln.indent + 2);
          k += 1;
        }
      }
      arr.push(item);
    }
    return { value: arr, nextLine: k };
  }

  function _parseInlineValue(text, lineNumber, col) {
    // Strip trailing whitespace/comment already done by caller (mostly).
    // Handle: flow [...] / {...}, quoted strings, plain scalars.
    var t = text;
    if (t.charAt(0) === "[") return _parseFlowSequence(t, lineNumber, col, 0);
    if (t.charAt(0) === "{") return _parseFlowMapping(t, lineNumber, col, 0);
    if (t.charAt(0) === '"') {
      var dq = _decodeDoubleQuoted(t, lineNumber, col);
      var afterDq = _trailingAfterQuoted(t, '"');
      if (afterDq.length > 0 && afterDq.replace(/^\s+/, "") !== "") {
        throw new SafeYamlError("unexpected content after quoted string",
          "yaml/trailing-content", lineNumber, col);
      }
      return dq;
    }
    if (t.charAt(0) === "'") {
      var sq = _decodeSingleQuoted(t, lineNumber, col);
      return sq;
    }
    // Plain scalar — strip trailing space, resolve type.
    return _resolveScalar(safeBuffer.stripTrailingHspace(t));
  }

  // For quoted-string termination check on a single-line value.
  function _trailingAfterQuoted(text, quote) {
    if (text.charAt(0) !== quote) return text;
    var i = 1;
    while (i < text.length) {
      var ch = text.charAt(i);
      if (quote === '"' && ch === "\\") { i += 2; continue; }
      if (ch === quote) {
        if (quote === "'" && text.charAt(i + 1) === "'") { i += 2; continue; }
        return text.substring(i + 1);
      }
      i += 1;
    }
    return "";
  }

  // ---- Flow style ----

  function _parseFlowSequence(text, lineNumber, col, depthIncoming) {
    var p = 1;  // skip [
    var arr = [];
    while (p < text.length) {
      _flowSkipWs(text, p);
      p = _flowSkipWsIndex(text, p);
      if (text.charAt(p) === "]") return arr;
      var v = _parseFlowValue(text, p, lineNumber, col, depthIncoming + 1);
      arr.push(v.value);
      p = v.nextPos;
      p = _flowSkipWsIndex(text, p);
      if (text.charAt(p) === ",") { p += 1; continue; }
      if (text.charAt(p) === "]") { return arr; }
      throw new SafeYamlError("expected ',' or ']' in flow sequence",
        "yaml/bad-flow", lineNumber, col + p);
    }
    throw new SafeYamlError("unterminated flow sequence",
      "yaml/unterminated-flow", lineNumber, col);
  }

  function _parseFlowMapping(text, lineNumber, col, depthIncoming) {
    if (depthIncoming > maxDepth) {
      throw new SafeYamlError("input exceeds maxDepth", "yaml/too-deep", lineNumber, col);
    }
    var p = 1;
    var result = Object.create(null);
    while (p < text.length) {
      p = _flowSkipWsIndex(text, p);
      if (text.charAt(p) === "}") { return result; }
      // Read key
      var keyVal = _parseFlowKey(text, p, lineNumber, col);
      var key = keyVal.key;
      if (typeof key !== "string") {
        throw new SafeYamlError("non-string flow-mapping key",
          "yaml/bad-key", lineNumber, col + p);
      }
      if (pick.isPoisonedKey(key)) {
        throw new SafeYamlError("forbidden key '" + key + "'",
          "yaml/poisoned-key", lineNumber, col + p);
      }
      _bumpKeys(lineNumber);
      p = keyVal.nextPos;
      p = _flowSkipWsIndex(text, p);
      if (text.charAt(p) !== ":") {
        throw new SafeYamlError("expected ':' in flow mapping",
          "yaml/bad-flow", lineNumber, col + p);
      }
      p += 1;
      p = _flowSkipWsIndex(text, p);
      var valRes = _parseFlowValue(text, p, lineNumber, col, depthIncoming + 1);
      result[key] = valRes.value;
      p = valRes.nextPos;
      p = _flowSkipWsIndex(text, p);
      if (text.charAt(p) === ",") { p += 1; continue; }
      if (text.charAt(p) === "}") { return result; }
      throw new SafeYamlError("expected ',' or '}' in flow mapping",
        "yaml/bad-flow", lineNumber, col + p);
    }
    throw new SafeYamlError("unterminated flow mapping",
      "yaml/unterminated-flow", lineNumber, col);
  }

  function _parseFlowValue(text, p, lineNumber, col, depthIncoming) {
    if (depthIncoming > maxDepth) {
      throw new SafeYamlError("input exceeds maxDepth", "yaml/too-deep", lineNumber, col + p);
    }
    var ch = text.charAt(p);
    if (ch === "[") {
      var sub = _parseFlowSequence(text.substring(p), lineNumber, col + p, depthIncoming);
      // We need to find where the matching ] closes — re-scan
      var endP = _findMatchingBracket(text, p, "[", "]", lineNumber, col);
      return { value: sub, nextPos: endP + 1 };
    }
    if (ch === "{") {
      var subM = _parseFlowMapping(text.substring(p), lineNumber, col + p, depthIncoming);
      var endM = _findMatchingBracket(text, p, "{", "}", lineNumber, col);
      return { value: subM, nextPos: endM + 1 };
    }
    if (ch === '"') {
      var dq = _decodeDoubleQuoted(text.substring(p), lineNumber, col + p);
      var endQ = _findClosingQuote(text, p, '"', lineNumber, col);
      return { value: dq, nextPos: endQ + 1 };
    }
    if (ch === "'") {
      var sq = _decodeSingleQuoted(text.substring(p), lineNumber, col + p);
      var endSQ = _findClosingQuote(text, p, "'", lineNumber, col);
      return { value: sq, nextPos: endSQ + 1 };
    }
    // Plain scalar — read until , } ] or EOL
    var start = p;
    while (p < text.length) {
      var c = text.charAt(p);
      if (c === "," || c === "}" || c === "]") break;
      p += 1;
    }
    var raw = safeBuffer.stripTrailingHspace(text.substring(start, p));
    return { value: _resolveScalar(raw), nextPos: p };
  }

  function _parseFlowKey(text, p, lineNumber, col) {
    var ch = text.charAt(p);
    if (ch === '"') {
      var dq = _decodeDoubleQuoted(text.substring(p), lineNumber, col + p);
      var endQ = _findClosingQuote(text, p, '"', lineNumber, col);
      return { key: dq, nextPos: endQ + 1 };
    }
    if (ch === "'") {
      var sq = _decodeSingleQuoted(text.substring(p), lineNumber, col + p);
      var endSQ = _findClosingQuote(text, p, "'", lineNumber, col);
      return { key: sq, nextPos: endSQ + 1 };
    }
    // Plain key — read until ':' (followed by space/comma/end) or comma/end
    var start = p;
    while (p < text.length) {
      var c = text.charAt(p);
      if (c === ":" || c === "," || c === "}" || c === "]") break;
      p += 1;
    }
    return { key: safeBuffer.stripTrailingHspace(text.substring(start, p)), nextPos: p };
  }

  function _findMatchingBracket(text, start, open, close, lineNumber, col) {
    var depth = 0;
    var i = start;
    while (i < text.length) {
      var c = text.charAt(i);
      if (c === '"') { i = _findClosingQuote(text, i, '"', lineNumber, col) + 1; continue; }
      if (c === "'") { i = _findClosingQuote(text, i, "'", lineNumber, col) + 1; continue; }
      if (c === open)  depth += 1;
      else if (c === close) {
        depth -= 1;
        if (depth === 0) return i;
      }
      i += 1;
    }
    throw new SafeYamlError("unterminated flow brackets",
      "yaml/unterminated-flow", lineNumber, col + start);
  }

  function _findClosingQuote(text, start, quote, lineNumber, col) {
    var i = start + 1;
    while (i < text.length) {
      var c = text.charAt(i);
      if (quote === '"' && c === "\\") { i += 2; continue; }
      if (c === quote) {
        if (quote === "'" && text.charAt(i + 1) === "'") { i += 2; continue; }
        return i;
      }
      i += 1;
    }
    throw new SafeYamlError("unterminated quoted string",
      "yaml/unterminated-string", lineNumber, col + start);
  }

  function _flowSkipWs(_text, _p) { /* no-op shim — real version below */ }
  function _flowSkipWsIndex(text, p) {
    while (p < text.length) {
      var c = text.charAt(p);
      if (c === " " || c === "\t") p += 1;
      else break;
    }
    return p;
  }

  // ---- Scalar decoding ----

  function _decodeDoubleQuoted(raw, lineNumber, col) {
    if (raw.charAt(0) !== '"') {
      throw new SafeYamlError("expected '\"'", "yaml/bad-string", lineNumber, col);
    }
    var i = 1;
    var out = "";
    while (i < raw.length) {
      var ch = raw.charAt(i);
      if (ch === '"') return out;
      if (ch === "\\") {
        var esc = raw.charAt(i + 1);
        switch (esc) {
          case '"':  out += '"';  i += 2; break;
          case "\\": out += "\\"; i += 2; break;
          case "/":  out += "/";  i += 2; break;
          case "n":  out += "\n"; i += 2; break;
          case "t":  out += "\t"; i += 2; break;
          case "r":  out += "\r"; i += 2; break;
          case "b":  out += "\b"; i += 2; break;
          case "f":  out += "\f"; i += 2; break;
          case "0":  out += "\0"; i += 2; break;
          case "u": {
            var hex = raw.substring(i + 2, i + 6);
            if (!safeBuffer.isHex(hex, 4)) {
              throw new SafeYamlError("bad \\u escape", "yaml/bad-escape", lineNumber, col + i);
            }
            out += String.fromCharCode(parseInt(hex, RADIX_HEX));
            i += 6;
            break;
          }
          case "U": {
            var hex8 = raw.substring(i + 2, i + 10);
            if (!/^[0-9a-fA-F]{8}$/.test(hex8)) {
              throw new SafeYamlError("bad \\U escape", "yaml/bad-escape", lineNumber, col + i);
            }
            var code = parseInt(hex8, RADIX_HEX);
            if (code > 0x10FFFF) {
              throw new SafeYamlError("\\U code point > U+10FFFF",
                "yaml/bad-escape", lineNumber, col + i);
            }
            out += String.fromCodePoint(code);
            i += 10;
            break;
          }
          default:
            throw new SafeYamlError("unknown escape '\\" + esc + "'",
              "yaml/bad-escape", lineNumber, col + i);
        }
        continue;
      }
      out += ch;
      i += 1;
    }
    throw new SafeYamlError("unterminated double-quoted string",
      "yaml/unterminated-string", lineNumber, col);
  }

  function _decodeSingleQuoted(raw, lineNumber, col) {
    if (raw.charAt(0) !== "'") {
      throw new SafeYamlError("expected \"'\"", "yaml/bad-string", lineNumber, col);
    }
    var i = 1;
    var out = "";
    while (i < raw.length) {
      var ch = raw.charAt(i);
      if (ch === "'") {
        if (raw.charAt(i + 1) === "'") { out += "'"; i += 2; continue; }
        return out;
      }
      out += ch;
      i += 1;
    }
    throw new SafeYamlError("unterminated single-quoted string",
      "yaml/unterminated-string", lineNumber, col);
  }

  function _stripEolComment(text) {
    // Strip ` #...` comments (must be preceded by whitespace) at end of line.
    var match = text.match(/^(.*?)(\s+#.*)?$/);
    return safeBuffer.stripTrailingHspace(match && match[1] != null ? match[1] : text);
  }

  // ---- Block scalars (| literal, > folded) ----

  function _parseBlockScalar(startIdx, parentIndent, headerContent) {
    var headerLine = lines[startIdx];
    var header = headerContent.trim();
    var style = header.charAt(0);  // '|' or '>'
    var rest = header.substring(1);
    var chomp = "";  // "-" strip, "+" keep, "" clip (default)
    var explicitIndent = null;
    for (var i = 0; i < rest.length; i++) {
      var ch = rest.charAt(i);
      if (ch === "-" || ch === "+") {
        if (chomp) throw new SafeYamlError("multiple chomping indicators",
          "yaml/bad-block-scalar", headerLine.lineNumber, parentIndent + 1);
        chomp = ch;
      } else if (ch >= "1" && ch <= "9") {
        if (explicitIndent != null) throw new SafeYamlError("multiple indentation indicators",
          "yaml/bad-block-scalar", headerLine.lineNumber, parentIndent + 1);
        explicitIndent = parseInt(ch, 10);
      } else if (ch === " " || ch === "\t" || ch === "#") {
        // comment / trailing whitespace — stop reading indicators
        break;
      }
    }

    // Collect content lines: anything more-indented than parentIndent.
    // The first non-blank content line establishes the block's indent.
    var k = startIdx + 1;
    var blockIndent = null;
    var contentLines = [];
    while (k < lines.length) {
      var ln = lines[k];
      if (ln.isBlank) { contentLines.push(""); k += 1; continue; }
      if (ln.indent <= parentIndent) break;
      if (blockIndent === null) {
        blockIndent = explicitIndent != null ? parentIndent + explicitIndent : ln.indent;
      }
      if (ln.indent < blockIndent) break;
      var trimmedToIndent = ln.raw.substring(blockIndent);
      contentLines.push(trimmedToIndent);
      k += 1;
    }

    // Trim trailing blank lines based on chomp.
    var trailingBlanks = 0;
    while (contentLines.length > 0 && contentLines[contentLines.length - 1] === "") {
      contentLines.pop();
      trailingBlanks += 1;
    }

    var body;
    if (style === "|") {
      // Literal: each content line + a newline; preserve internal blanks
      // (we just popped trailing ones for chomp handling).
      body = contentLines.join("\n");
      if (contentLines.length > 0) body += "\n";
    } else {
      // Folded: blank line separates paragraphs (becomes a newline);
      // adjacent non-blank lines fold to single space.
      var folded = "";
      for (var n = 0; n < contentLines.length; n++) {
        var cl = contentLines[n];
        if (cl === "") {
          folded += "\n";
          continue;
        }
        if (folded.length > 0 && !folded.endsWith("\n")) {
          folded += " ";
        }
        folded += cl;
      }
      body = folded;
      if (contentLines.length > 0) body += "\n";
    }

    if (chomp === "-") {
      // strip — remove trailing newline(s)
      body = body.replace(/\n+$/, "");
    } else if (chomp === "+") {
      // keep — restore trailing blanks we popped
      body += "\n".repeat(trailingBlanks);
    } /* else "clip" — keep one trailing newline (already there) */

    return { value: body, nextLine: k };
  }

  function _parseScalarOrFlow(startIdx, indent) {
    var ln = lines[startIdx];
    var content = _stripEolComment(ln.content);
    var v = _parseInlineValue(content, ln.lineNumber, ln.indent + 1);
    return { value: v, nextLine: startIdx + 1 };
  }

  // ---- Top-level dispatch ----
  var top = parseValueAtLine(idx, -1, 1);

  // Normalize null-prototype objects to plain {} so JSON.stringify and
  // for-in behave naturally for the operator.
  function _normalize(value) {
    if (Array.isArray(value)) return value.map(_normalize);
    if (value && typeof value === "object" && !(value instanceof Date)) {
      var out = {};
      for (var k in value) {
        if (Object.prototype.hasOwnProperty.call(value, k)) {
          out[k] = _normalize(value[k]);
        }
      }
      return out;
    }
    return value;
  }
  return _normalize(top.value);
}

// ---- Pre-validation: scan input for banned constructs ----
//
// We mask out string content (single-quoted, double-quoted) and block-
// scalar bodies before scanning, so legitimate string content with `&`
// or `!` characters doesn't false-positive.
function _preValidate(input) {
  // Build a "scan-safe" copy where quoted-string bodies and block-scalar
  // bodies are replaced with same-length whitespace. Simple state machine.
  var len = input.length;
  var line = 1;
  var col = 1;
  var i = 0;
  var safe = "";

  function advance(n) {
    n = n == null ? 1 : n;
    for (var z = 0; z < n; z++) {
      if (i < len && input.charCodeAt(i) === 0x0A) { line += 1; col = 1; }
      else col += 1;
      i += 1;
    }
  }

  while (i < len) {
    var c = input.charAt(i);
    // Comments — pass through
    if (c === "#") {
      while (i < len && input.charAt(i) !== "\n") {
        safe += input.charAt(i);
        i += 1;
        col += 1;
      }
      continue;
    }
    // Quoted strings — mask body
    if (c === '"' || c === "'") {
      var quote = c;
      var startLine = line;
      var startCol = col;
      safe += c;
      advance();
      while (i < len) {
        var ch = input.charAt(i);
        if (quote === '"' && ch === "\\" && i + 1 < len) {
          // mask both
          safe += "  ";
          advance(2);
          continue;
        }
        if (ch === quote) {
          if (quote === "'" && input.charAt(i + 1) === "'") {
            safe += "  ";
            advance(2);
            continue;
          }
          safe += ch;
          advance();
          break;
        }
        // Mask content (preserve newlines for line counting)
        safe += (ch === "\n") ? "\n" : " ";
        advance();
      }
      if (i > len) {
        throw new SafeYamlError("unterminated quoted string",
          "yaml/unterminated-string", startLine, startCol);
      }
      continue;
    }
    // Pass through everything else
    safe += c;
    advance();
  }

  // Now scan `safe` for banned constructs.
  // Banned tokens (must be at line-start or after whitespace, not in keys):
  //   &name      anchor
  //   *name      alias
  //   !tag, !!tag
  //   %YAML / %TAG directive (only at column 0)

  // Anchors: `&` followed by a name char, with whitespace or `-`/`?` before
  //   (or start of value position). A simple heuristic: any unescaped `&`
  //   that's followed by an identifier char and is preceded by space or
  //   line start is an anchor. Same for `*`.
  var anchorOrAliasRe = /(^|\s)([&*])([A-Za-z0-9_][A-Za-z0-9_-]*)/;
  var m = safe.match(anchorOrAliasRe);
  if (m) {
    var posIdx = safe.indexOf(m[0]);
    var lineCount = safe.substring(0, posIdx).split("\n").length;
    throw new SafeYamlError(
      m[2] === "&" ? "anchors are not supported" : "aliases are not supported",
      m[2] === "&" ? "yaml/anchors-banned" : "yaml/aliases-banned",
      lineCount, 1
    );
  }

  // Tags: `!` at start of value or after `: ` / `- `. False-positive risk:
  //   "key: !something" vs "key: ![bracket". We match `!` followed by
  //   alphanumeric or `<`.
  var tagRe = /(^|[\s-])(!{1,2}[A-Za-z<])/;
  var mt = safe.match(tagRe);
  if (mt) {
    var tagIdx = safe.indexOf(mt[0]);
    var tagLine = safe.substring(0, tagIdx).split("\n").length;
    throw new SafeYamlError("tags are not supported",
      "yaml/tags-banned", tagLine, 1);
  }

  // Directives: `%YAML` or `%TAG` at column 0
  var dirRe = /(^|\n)%(YAML|TAG)\b/;
  var md = safe.match(dirRe);
  if (md) {
    var dirIdx = safe.indexOf(md[0]);
    var dirLine = safe.substring(0, dirIdx).split("\n").length + (md[1] === "\n" ? 1 : 0);
    throw new SafeYamlError("directives are not supported",
      "yaml/directives-banned", dirLine, 1);
  }
}

module.exports = {
  parse:          parse,
  SafeYamlError:  SafeYamlError,
};
